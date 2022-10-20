/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "EffectHalHidl"
//#define LOG_NDEBUG 0

#include <android/hidl/manager/1.0/IServiceManager.h>
#include <android-base/stringprintf.h>
#include <common/all-versions/VersionUtils.h>
#include <cutils/native_handle.h>
#include <cutils/properties.h>
#include <hwbinder/IPCThreadState.h>
#include <media/EffectsFactoryApi.h>
#include <mediautils/SchedulingPolicyService.h>
#include <mediautils/TimeCheck.h>
#include <system/audio_effects/effect_spatializer.h>
#include <utils/Log.h>

#include <util/EffectUtils.h>

#include "EffectBufferHalHidl.h"
#include "EffectHalHidl.h"

using ::android::hardware::audio::common::utils::EnumBitfield;
using ::android::hardware::audio::effect::CPP_VERSION::implementation::EffectUtils;
using ::android::hardware::hidl_vec;
using ::android::hardware::MQDescriptorSync;
using ::android::hardware::Return;

namespace android {
namespace effect {

using namespace ::android::hardware::audio::common::CPP_VERSION;
using namespace ::android::hardware::audio::effect::CPP_VERSION;

#define TIME_CHECK() auto timeCheck = \
        mediautils::makeTimeCheckStatsForClassMethod(getClassName(), __func__)

EffectHalHidl::EffectHalHidl(const sp<IEffect>& effect, uint64_t effectId)
        : EffectConversionHelperHidl("EffectHalHidl"),
          mEffect(effect), mEffectId(effectId), mBuffersChanged(true), mEfGroup(nullptr) {
    effect_descriptor_t halDescriptor{};
    if (EffectHalHidl::getDescriptor(&halDescriptor) == NO_ERROR) {
        mIsInput = (halDescriptor.flags & EFFECT_FLAG_TYPE_PRE_PROC) == EFFECT_FLAG_TYPE_PRE_PROC;
        const bool isSpatializer =
                memcmp(&halDescriptor.type, FX_IID_SPATIALIZER, sizeof(effect_uuid_t)) == 0;
        if (isSpatializer) {
            constexpr int32_t kRTPriorityMin = 1;
            constexpr int32_t kRTPriorityMax = 3;
            const int32_t priorityBoost = property_get_int32("audio.spatializer.priority", 1);
            if (priorityBoost >= kRTPriorityMin && priorityBoost <= kRTPriorityMax) {
                ALOGD("%s: audio.spatializer.priority %d on effect %lld",
                         __func__, priorityBoost, (long long)effectId);
                mHalThreadPriority = priorityBoost;
            }
        }
    }
}

EffectHalHidl::~EffectHalHidl() {
    if (mEffect != 0) {
        close();
        mEffect.clear();
        hardware::IPCThreadState::self()->flushCommands();
    }
    if (mEfGroup) {
        EventFlag::deleteEventFlag(&mEfGroup);
    }
}

status_t EffectHalHidl::setInBuffer(const sp<EffectBufferHalInterface>& buffer) {
    TIME_CHECK();

    if (!mBuffersChanged) {
        if (buffer.get() == nullptr || mInBuffer.get() == nullptr) {
            mBuffersChanged = buffer.get() != mInBuffer.get();
        } else {
            mBuffersChanged = buffer->audioBuffer() != mInBuffer->audioBuffer();
        }
    }
    mInBuffer = buffer;
    return OK;
}

status_t EffectHalHidl::setOutBuffer(const sp<EffectBufferHalInterface>& buffer) {
    TIME_CHECK();

    if (!mBuffersChanged) {
        if (buffer.get() == nullptr || mOutBuffer.get() == nullptr) {
            mBuffersChanged = buffer.get() != mOutBuffer.get();
        } else {
            mBuffersChanged = buffer->audioBuffer() != mOutBuffer->audioBuffer();
        }
    }
    mOutBuffer = buffer;
    return OK;
}

status_t EffectHalHidl::process() {
    // TIME_CHECK();  // TODO(b/238654698) reenable only when optimized.

    return processImpl(static_cast<uint32_t>(MessageQueueFlagBits::REQUEST_PROCESS));
}

status_t EffectHalHidl::processReverse() {
    // TIME_CHECK();  // TODO(b/238654698) reenable only when optimized.

    return processImpl(static_cast<uint32_t>(MessageQueueFlagBits::REQUEST_PROCESS_REVERSE));
}

status_t EffectHalHidl::prepareForProcessing() {
    std::unique_ptr<StatusMQ> tempStatusMQ;
    Result retval;
    Return<void> ret = mEffect->prepareForProcessing(
            [&](Result r, const MQDescriptorSync<Result>& statusMQ) {
                retval = r;
                if (retval == Result::OK) {
                    tempStatusMQ.reset(new StatusMQ(statusMQ));
                    if (tempStatusMQ->isValid() && tempStatusMQ->getEventFlagWord()) {
                        EventFlag::createEventFlag(tempStatusMQ->getEventFlagWord(), &mEfGroup);
                    }
                }
            });
    if (!ret.isOk() || retval != Result::OK) {
        return ret.isOk() ? analyzeResult(retval) : FAILED_TRANSACTION;
    }
    if (!tempStatusMQ || !tempStatusMQ->isValid() || !mEfGroup) {
        ALOGE_IF(!tempStatusMQ, "Failed to obtain status message queue for effects");
        ALOGE_IF(tempStatusMQ && !tempStatusMQ->isValid(),
                "Status message queue for effects is invalid");
        ALOGE_IF(!mEfGroup, "Event flag creation for effects failed");
        return NO_INIT;
    }

    (void)checkHalThreadPriority();
    mStatusMQ = std::move(tempStatusMQ);
    return OK;
}

bool EffectHalHidl::needToResetBuffers() {
    if (mBuffersChanged) return true;
    bool inBufferFrameCountUpdated = mInBuffer->checkFrameCountChange();
    bool outBufferFrameCountUpdated = mOutBuffer->checkFrameCountChange();
    return inBufferFrameCountUpdated || outBufferFrameCountUpdated;
}

status_t EffectHalHidl::processImpl(uint32_t mqFlag) {
    if (mEffect == 0 || mInBuffer == 0 || mOutBuffer == 0) return NO_INIT;
    status_t status;
    if (!mStatusMQ && (status = prepareForProcessing()) != OK) {
        return status;
    }
    if (needToResetBuffers() && (status = setProcessBuffers()) != OK) {
        return status;
    }
    // The data is already in the buffers, just need to flush it and wake up the server side.
    std::atomic_thread_fence(std::memory_order_release);
    mEfGroup->wake(mqFlag);
    uint32_t efState = 0;
retry:
    status_t ret = mEfGroup->wait(
            static_cast<uint32_t>(MessageQueueFlagBits::DONE_PROCESSING), &efState);
    if (efState & static_cast<uint32_t>(MessageQueueFlagBits::DONE_PROCESSING)) {
        Result retval = Result::NOT_INITIALIZED;
        mStatusMQ->read(&retval);
        if (retval == Result::OK || retval == Result::INVALID_STATE) {
            // Sync back the changed contents of the buffer.
            std::atomic_thread_fence(std::memory_order_acquire);
        }
        return analyzeResult(retval);
    }
    if (ret == -EAGAIN || ret == -EINTR) {
        // Spurious wakeup. This normally retries no more than once.
        goto retry;
    }
    return ret;
}

status_t EffectHalHidl::setProcessBuffers() {
    Return<Result> ret = mEffect->setProcessBuffers(
            static_cast<EffectBufferHalHidl*>(mInBuffer.get())->hidlBuffer(),
            static_cast<EffectBufferHalHidl*>(mOutBuffer.get())->hidlBuffer());
    if (ret.isOk() && ret == Result::OK) {
        mBuffersChanged = false;
        return OK;
    }
    return ret.isOk() ? analyzeResult(ret) : FAILED_TRANSACTION;
}

status_t EffectHalHidl::command(uint32_t cmdCode, uint32_t cmdSize, void *pCmdData,
        uint32_t *replySize, void *pReplyData) {
    TIME_CHECK();

    if (mEffect == 0) return NO_INIT;

    // Special cases.
    if (cmdCode == EFFECT_CMD_SET_CONFIG || cmdCode == EFFECT_CMD_SET_CONFIG_REVERSE) {
        return setConfigImpl(cmdCode, cmdSize, pCmdData, replySize, pReplyData);
    } else if (cmdCode == EFFECT_CMD_GET_CONFIG || cmdCode == EFFECT_CMD_GET_CONFIG_REVERSE) {
        return getConfigImpl(cmdCode, replySize, pReplyData);
    }

    // Common case.
    hidl_vec<uint8_t> hidlData;
    if (pCmdData != nullptr && cmdSize > 0) {
        hidlData.setToExternal(reinterpret_cast<uint8_t*>(pCmdData), cmdSize);
    }
    status_t status;
    uint32_t replySizeStub = 0;
    if (replySize == nullptr || pReplyData == nullptr) replySize = &replySizeStub;
    Return<void> ret = mEffect->command(cmdCode, hidlData, *replySize,
            [&](int32_t s, const hidl_vec<uint8_t>& result) {
                status = s;
                if (status == 0) {
                    if (*replySize > result.size()) *replySize = result.size();
                    if (pReplyData != nullptr && *replySize > 0) {
                        memcpy(pReplyData, &result[0], *replySize);
                    }
                }
            });
    return ret.isOk() ? status : FAILED_TRANSACTION;
}

status_t EffectHalHidl::getDescriptor(effect_descriptor_t *pDescriptor) {
    TIME_CHECK();

    if (mEffect == 0) return NO_INIT;
    Result retval = Result::NOT_INITIALIZED;
    Return<void> ret = mEffect->getDescriptor(
            [&](Result r, const EffectDescriptor& result) {
                retval = r;
                if (retval == Result::OK) {
                    EffectUtils::effectDescriptorToHal(result, pDescriptor);
                }
            });
    return ret.isOk() ? analyzeResult(retval) : FAILED_TRANSACTION;
}

status_t EffectHalHidl::close() {
    TIME_CHECK();

    if (mEffect == 0) return NO_INIT;
    Return<Result> ret = mEffect->close();
    return ret.isOk() ? analyzeResult(ret) : FAILED_TRANSACTION;
}

status_t EffectHalHidl::dump(int fd) {
    TIME_CHECK();

    if (mEffect == 0) return NO_INIT;
    native_handle_t* hidlHandle = native_handle_create(1, 0);
    hidlHandle->data[0] = fd;
    Return<void> ret = mEffect->debug(hidlHandle, {} /* options */);
    native_handle_delete(hidlHandle);

    // TODO(b/111997867, b/177271958)  Workaround - remove when fixed.
    // A Binder transmitted fd may not close immediately due to a race condition b/111997867
    // when the remote binder thread removes the last refcount to the fd blocks in the
    // kernel for binder activity. We send a Binder ping() command to unblock the thread
    // and complete the fd close / release.
    //
    // See DeviceHalHidl::dump(), EffectHalHidl::dump(), StreamHalHidl::dump(),
    //     EffectsFactoryHalHidl::dumpEffects().

    (void)mEffect->ping(); // synchronous Binder call

    return ret.isOk() ? OK : FAILED_TRANSACTION;
}

status_t EffectHalHidl::getConfigImpl(
        uint32_t cmdCode, uint32_t *replySize, void *pReplyData) {
    if (replySize == NULL || *replySize != sizeof(effect_config_t) || pReplyData == NULL) {
        return BAD_VALUE;
    }
    status_t result = FAILED_TRANSACTION;
    Return<void> ret;
    if (cmdCode == EFFECT_CMD_GET_CONFIG) {
        ret = mEffect->getConfig([&] (Result r, const EffectConfig &hidlConfig) {
            result = analyzeResult(r);
            if (r == Result::OK) {
                EffectUtils::effectConfigToHal(
                        hidlConfig, static_cast<effect_config_t*>(pReplyData));
            }
        });
    } else {
        ret = mEffect->getConfigReverse([&] (Result r, const EffectConfig &hidlConfig) {
            result = analyzeResult(r);
            if (r == Result::OK) {
                EffectUtils::effectConfigToHal(
                        hidlConfig, static_cast<effect_config_t*>(pReplyData));
            }
        });
    }
    if (!ret.isOk()) {
        result = FAILED_TRANSACTION;
    }
    return result;
}

status_t EffectHalHidl::setConfigImpl(
        uint32_t cmdCode, uint32_t cmdSize, void *pCmdData, uint32_t *replySize, void *pReplyData) {
    if (pCmdData == NULL || cmdSize != sizeof(effect_config_t) ||
            replySize == NULL || *replySize != sizeof(int32_t) || pReplyData == NULL) {
        return BAD_VALUE;
    }
    const effect_config_t *halConfig = static_cast<effect_config_t*>(pCmdData);
    if (halConfig->inputCfg.bufferProvider.getBuffer != NULL ||
            halConfig->inputCfg.bufferProvider.releaseBuffer != NULL ||
            halConfig->outputCfg.bufferProvider.getBuffer != NULL ||
            halConfig->outputCfg.bufferProvider.releaseBuffer != NULL) {
        ALOGE("Buffer provider callbacks are not supported");
    }
    EffectConfig hidlConfig;
    EffectUtils::effectConfigFromHal(*halConfig, mIsInput, &hidlConfig);
    Return<Result> ret = cmdCode == EFFECT_CMD_SET_CONFIG ?
            mEffect->setConfig(hidlConfig, nullptr, nullptr) :
            mEffect->setConfigReverse(hidlConfig, nullptr, nullptr);
    status_t result = FAILED_TRANSACTION;
    if (ret.isOk()) {
        result = analyzeResult(ret);
        *static_cast<int32_t*>(pReplyData) = result;
    }
    return result;
}

status_t EffectHalHidl::getHalPid(pid_t *pid) const {
    using ::android::hidl::base::V1_0::DebugInfo;
    using ::android::hidl::manager::V1_0::IServiceManager;
    DebugInfo debugInfo;
    const auto ret = mEffect->getDebugInfo([&] (const auto &info) {
        debugInfo = info;
    });
    if (!ret.isOk()) {
        ALOGW("%s: cannot get effect debug info", __func__);
        return INVALID_OPERATION;
    }
    if (debugInfo.pid != (int)IServiceManager::PidConstant::NO_PID) {
        *pid = debugInfo.pid;
        return NO_ERROR;
    }
    ALOGW("%s: effect debug info does not contain pid", __func__);
    return NAME_NOT_FOUND;
}

status_t EffectHalHidl::getHalWorkerTid(pid_t *tid) {
    int32_t reply = -1;
    uint32_t replySize = sizeof(reply);
    const status_t status =
            command('gtid', 0 /* cmdSize */, nullptr /* pCmdData */, &replySize, &reply);
    if (status == OK) {
        *tid = (pid_t)reply;
    } else {
        ALOGW("%s: failed with status:%d", __func__, status);
    }
    return status;
}

bool EffectHalHidl::requestHalThreadPriority(pid_t threadPid, pid_t threadId) {
    if (mHalThreadPriority == kRTPriorityDisabled) {
        return true;
    }
    const int err = requestPriority(
            threadPid, threadId,
            mHalThreadPriority, false /*isForApp*/, true /*asynchronous*/);
    ALOGW_IF(err, "%s: failed to set RT priority %d for pid %d tid %d; error %d",
            __func__, mHalThreadPriority, threadPid, threadId, err);
    // Audio will still work, but may be more susceptible to glitches.
    return err == 0;
}

status_t EffectHalHidl::checkHalThreadPriority() {
    if (mHalThreadPriority == kRTPriorityDisabled) return OK;
    if (mHalThreadPriority < kRTPriorityMin
            || mHalThreadPriority > kRTPriorityMax) return BAD_VALUE;

    pid_t halPid, halWorkerTid;
    const status_t status = getHalPid(&halPid) ?: getHalWorkerTid(&halWorkerTid);
    const bool success = status == OK && requestHalThreadPriority(halPid, halWorkerTid);
    ALOGD("%s: effectId %lld RT priority(%d) request %s%s",
            __func__, (long long)mEffectId, mHalThreadPriority,
            success ? "succeeded" : "failed",
            status == OK
                    ? base::StringPrintf(" for pid:%d tid:%d", halPid, halWorkerTid).c_str()
                    : " (pid / tid cannot be read)");
    return success ? OK : status != OK ? status : INVALID_OPERATION /* request failed */;
}

} // namespace effect
} // namespace android
