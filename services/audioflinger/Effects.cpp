/*
**
** Copyright 2012, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/


#define LOG_TAG "AudioFlinger"
//#define LOG_NDEBUG 0

#include "Effects.h"

#include "Client.h"
#include "EffectConfiguration.h"

#include <afutils/DumpTryLock.h>
#include <audio_utils/channels.h>
#include <audio_utils/primitives.h>
#include <media/AudioCommonTypes.h>
#include <media/AudioContainers.h>
#include <media/AudioDeviceTypeAddr.h>
#include <media/AudioEffect.h>
#include <media/ShmemCompat.h>
#include <media/TypeConverter.h>
#include <media/audiohal/EffectHalInterface.h>
#include <media/audiohal/EffectsFactoryHalInterface.h>
#include <mediautils/MethodStatistics.h>
#include <mediautils/ServiceUtilities.h>
#include <mediautils/TimeCheck.h>
#include <system/audio_effects/effect_aec.h>
#include <system/audio_effects/effect_downmix.h>
#include <system/audio_effects/effect_dynamicsprocessing.h>
#include <system/audio_effects/effect_hapticgenerator.h>
#include <system/audio_effects/effect_ns.h>
#include <system/audio_effects/effect_spatializer.h>
#include <system/audio_effects/effect_visualizer.h>
#include <utils/Log.h>

#include <algorithm>

// ----------------------------------------------------------------------------

// Note: the following macro is used for extremely verbose logging message.  In
// order to run with ALOG_ASSERT turned on, we need to have LOG_NDEBUG set to
// 0; but one side effect of this is to turn all LOGV's as well.  Some messages
// are so verbose that we want to suppress them even when we have ALOG_ASSERT
// turned on.  Do not uncomment the #def below unless you really know what you
// are doing and want to see all of the extremely verbose messages.
//#define VERY_VERY_VERBOSE_LOGGING
#ifdef VERY_VERY_VERBOSE_LOGGING
#define ALOGVV ALOGV
#else
#define ALOGVV(a...) do { } while(0)
#endif

#define DEFAULT_OUTPUT_SAMPLE_RATE 48000

namespace android {

using aidl_utils::statusTFromBinderStatus;
using audioflinger::EffectConfiguration;
using binder::Status;

namespace {

// Append a POD value into a vector of bytes.
template<typename T>
void appendToBuffer(const T& value, std::vector<uint8_t>* buffer) {
    const uint8_t* ar(reinterpret_cast<const uint8_t*>(&value));
    buffer->insert(buffer->end(), ar, ar + sizeof(T));
}

// Write a POD value into a vector of bytes (clears the previous buffer
// content).
template<typename T>
void writeToBuffer(const T& value, std::vector<uint8_t>* buffer) {
    buffer->clear();
    appendToBuffer(value, buffer);
}

}  // namespace

// ----------------------------------------------------------------------------
//  EffectBase implementation
// ----------------------------------------------------------------------------

#undef LOG_TAG
#define LOG_TAG "EffectBase"

EffectBase::EffectBase(const sp<EffectCallbackInterface>& callback,
                                        effect_descriptor_t *desc,
                                        int id,
                                        audio_session_t sessionId,
                                        bool pinned)
    : mPinned(pinned),
      mCallback(callback), mId(id), mSessionId(sessionId),
      mDescriptor(*desc)
{
}

// must be called with EffectModule::mutex() held
status_t EffectBase::setEnabled_l(bool enabled)
{

    ALOGV("setEnabled %p enabled %d", this, enabled);

    if (enabled != isEnabled()) {
        switch (mState) {
        // going from disabled to enabled
        case IDLE:
            mState = STARTING;
            break;
        case STOPPED:
            mState = RESTART;
            break;
        case STOPPING:
            mState = ACTIVE;
            break;

        // going from enabled to disabled
        case RESTART:
            mState = STOPPED;
            break;
        case STARTING:
            mState = IDLE;
            break;
        case ACTIVE:
            mState = STOPPING;
            break;
        case DESTROYED:
            return NO_ERROR; // simply ignore as we are being destroyed
        }
        for (size_t i = 1; i < mHandles.size(); i++) {
            IAfEffectHandle *h = mHandles[i];
            if (h != NULL && !h->disconnected()) {
                h->setEnabled(enabled);
            }
        }
    }
    return NO_ERROR;
}

status_t EffectBase::setEnabled(bool enabled, bool fromHandle)
{
    status_t status;
    {
        audio_utils::lock_guard _l(mutex());
        status = setEnabled_l(enabled);
    }
    if (fromHandle) {
        if (enabled) {
            if (status != NO_ERROR) {
                getCallback()->checkSuspendOnEffectEnabled(this, false, false /*threadLocked*/);
            } else {
                getCallback()->onEffectEnable(this);
            }
        } else {
            getCallback()->onEffectDisable(this);
        }
    }
    return status;
}

bool EffectBase::isEnabled() const
{
    switch (mState) {
    case RESTART:
    case STARTING:
    case ACTIVE:
        return true;
    case IDLE:
    case STOPPING:
    case STOPPED:
    case DESTROYED:
    default:
        return false;
    }
}

void EffectBase::setSuspended(bool suspended)
{
    audio_utils::lock_guard _l(mutex());
    mSuspended = suspended;
}

bool EffectBase::suspended() const
{
    audio_utils::lock_guard _l(mutex());
    return mSuspended;
}

status_t EffectBase::addHandle(IAfEffectHandle *handle)
{
    status_t status;

    audio_utils::lock_guard _l(mutex());
    int priority = handle->priority();
    size_t size = mHandles.size();
    IAfEffectHandle *controlHandle = nullptr;
    size_t i;
    for (i = 0; i < size; i++) {
        IAfEffectHandle *h = mHandles[i];
        if (h == NULL || h->disconnected()) {
            continue;
        }
        // first non destroyed handle is considered in control
        if (controlHandle == NULL) {
            controlHandle = h;
        }
        if (h->priority() <= priority) {
            break;
        }
    }
    // if inserted in first place, move effect control from previous owner to this handle
    if (i == 0) {
        bool enabled = false;
        if (controlHandle != NULL) {
            enabled = controlHandle->enabled();
            controlHandle->setControl(false/*hasControl*/, true /*signal*/, enabled /*enabled*/);
        }
        handle->setControl(true /*hasControl*/, false /*signal*/, enabled /*enabled*/);
        status = NO_ERROR;
    } else {
        status = ALREADY_EXISTS;
    }
    ALOGV("addHandle() %p added handle %p in position %zu", this, handle, i);
    mHandles.insertAt(handle, i);
    return status;
}

status_t EffectBase::updatePolicyState()
{
    status_t status = NO_ERROR;
    bool doRegister = false;
    bool registered = false;
    bool doEnable = false;
    bool enabled = false;
    audio_io_handle_t io = AUDIO_IO_HANDLE_NONE;
    product_strategy_t strategy = PRODUCT_STRATEGY_NONE;

    {
        audio_utils::lock_guard _l(mutex());

        if ((isInternal_l() && !mPolicyRegistered)
                || !getCallback()->isAudioPolicyReady()) {
            return NO_ERROR;
        }

        // register effect when first handle is attached and unregister when last handle is removed
        if (mPolicyRegistered != mHandles.size() > 0) {
            doRegister = true;
            mPolicyRegistered = mHandles.size() > 0;
            if (mPolicyRegistered) {
                const auto callback = getCallback();
                io = callback->io();
                strategy = callback->strategy();
            }
        }
        // enable effect when registered according to enable state requested by controlling handle
        if (mHandles.size() > 0) {
            IAfEffectHandle *handle = controlHandle_l();
            if (handle != nullptr && mPolicyEnabled != handle->enabled()) {
                doEnable = true;
                mPolicyEnabled = handle->enabled();
            }
        }
        registered = mPolicyRegistered;
        enabled = mPolicyEnabled;
        // The simultaneous release of two EffectHandles with the same EffectModule
        // may cause us to call this method at the same time.
        // This may deadlock under some circumstances (b/180941720).  Avoid this.
        if (!doRegister && !(registered && doEnable)) {
            return NO_ERROR;
        }
    }
    policyMutex().lock();
    ALOGV("%s name %s id %d session %d doRegister %d registered %d doEnable %d enabled %d",
        __func__, mDescriptor.name, mId, mSessionId, doRegister, registered, doEnable, enabled);
    if (doRegister) {
        if (registered) {
            status = AudioSystem::registerEffect(
                &mDescriptor,
                io,
                strategy,
                mSessionId,
                mId);
        } else {
            status = AudioSystem::unregisterEffect(mId);
        }
    }
    if (registered && doEnable) {
        status = AudioSystem::setEffectEnabled(mId, enabled);
    }
    policyMutex().unlock();

    return status;
}


ssize_t EffectBase::removeHandle(IAfEffectHandle *handle)
{
    audio_utils::lock_guard _l(mutex());
    return removeHandle_l(handle);
}

ssize_t EffectBase::removeHandle_l(IAfEffectHandle *handle)
{
    size_t size = mHandles.size();
    size_t i;
    for (i = 0; i < size; i++) {
        if (mHandles[i] == handle) {
            break;
        }
    }
    if (i == size) {
        ALOGW("%s %p handle not found %p", __FUNCTION__, this, handle);
        return BAD_VALUE;
    }
    ALOGV("removeHandle_l() %p removed handle %p in position %zu", this, handle, i);

    mHandles.removeAt(i);
    // if removed from first place, move effect control from this handle to next in line
    if (i == 0) {
        IAfEffectHandle *h = controlHandle_l();
        if (h != NULL) {
            h->setControl(true /*hasControl*/, true /*signal*/ , handle->enabled() /*enabled*/);
        }
    }

    // Prevent calls to process() and other functions on effect interface from now on.
    // The effect engine will be released by the destructor when the last strong reference on
    // this object is released which can happen after next process is called.
    if (mHandles.size() == 0 && !mPinned) {
        mState = DESTROYED;
    }

    return mHandles.size();
}

// must be called with EffectModule::mutex() held
IAfEffectHandle *EffectBase::controlHandle_l()
{
    // the first valid handle in the list has control over the module
    for (size_t i = 0; i < mHandles.size(); i++) {
        IAfEffectHandle *h = mHandles[i];
        if (h != NULL && !h->disconnected()) {
            return h;
        }
    }

    return NULL;
}

// unsafe method called when the effect parent thread has been destroyed
ssize_t EffectBase::disconnectHandle(IAfEffectHandle *handle, bool unpinIfLast)
{
    const auto callback = getCallback();
    ALOGV("disconnect() %p handle %p", this, handle);
    if (callback->disconnectEffectHandle(handle, unpinIfLast)) {
        return mHandles.size();
    }

    audio_utils::lock_guard _l(mutex());
    ssize_t numHandles = removeHandle_l(handle);
    if ((numHandles == 0) && (!mPinned || unpinIfLast)) {
        mutex().unlock();
        callback->updateOrphanEffectChains(this);
        mutex().lock();
    }
    return numHandles;
}

bool EffectBase::purgeHandles()
{
    bool enabled = false;
    audio_utils::lock_guard _l(mutex());
    IAfEffectHandle *handle = controlHandle_l();
    if (handle != NULL) {
        enabled = handle->enabled();
    }
    mHandles.clear();
    return enabled;
}

void EffectBase::checkSuspendOnEffectEnabled(bool enabled, bool threadLocked) {
    getCallback()->checkSuspendOnEffectEnabled(this, enabled, threadLocked);
}

static String8 effectFlagsToString(uint32_t flags) {
    String8 s;

    s.append("conn. mode: ");
    switch (flags & EFFECT_FLAG_TYPE_MASK) {
    case EFFECT_FLAG_TYPE_INSERT: s.append("insert"); break;
    case EFFECT_FLAG_TYPE_AUXILIARY: s.append("auxiliary"); break;
    case EFFECT_FLAG_TYPE_REPLACE: s.append("replace"); break;
    case EFFECT_FLAG_TYPE_PRE_PROC: s.append("preproc"); break;
    case EFFECT_FLAG_TYPE_POST_PROC: s.append("postproc"); break;
    default: s.append("unknown/reserved"); break;
    }
    s.append(", ");

    s.append("insert pref: ");
    switch (flags & EFFECT_FLAG_INSERT_MASK) {
    case EFFECT_FLAG_INSERT_ANY: s.append("any"); break;
    case EFFECT_FLAG_INSERT_FIRST: s.append("first"); break;
    case EFFECT_FLAG_INSERT_LAST: s.append("last"); break;
    case EFFECT_FLAG_INSERT_EXCLUSIVE: s.append("exclusive"); break;
    default: s.append("unknown/reserved"); break;
    }
    s.append(", ");

    s.append("volume mgmt: ");
    switch (flags & EFFECT_FLAG_VOLUME_MASK) {
    case EFFECT_FLAG_VOLUME_NONE: s.append("none"); break;
    case EFFECT_FLAG_VOLUME_CTRL: s.append("implements control"); break;
    case EFFECT_FLAG_VOLUME_IND: s.append("requires indication"); break;
    case EFFECT_FLAG_VOLUME_MONITOR: s.append("monitors volume"); break;
    default: s.append("unknown/reserved"); break;
    }
    s.append(", ");

    uint32_t devind = flags & EFFECT_FLAG_DEVICE_MASK;
    if (devind) {
        s.append("device indication: ");
        switch (devind) {
        case EFFECT_FLAG_DEVICE_IND: s.append("requires updates"); break;
        default: s.append("unknown/reserved"); break;
        }
        s.append(", ");
    }

    s.append("input mode: ");
    switch (flags & EFFECT_FLAG_INPUT_MASK) {
    case EFFECT_FLAG_INPUT_DIRECT: s.append("direct"); break;
    case EFFECT_FLAG_INPUT_PROVIDER: s.append("provider"); break;
    case EFFECT_FLAG_INPUT_BOTH: s.append("direct+provider"); break;
    default: s.append("not set"); break;
    }
    s.append(", ");

    s.append("output mode: ");
    switch (flags & EFFECT_FLAG_OUTPUT_MASK) {
    case EFFECT_FLAG_OUTPUT_DIRECT: s.append("direct"); break;
    case EFFECT_FLAG_OUTPUT_PROVIDER: s.append("provider"); break;
    case EFFECT_FLAG_OUTPUT_BOTH: s.append("direct+provider"); break;
    default: s.append("not set"); break;
    }
    s.append(", ");

    uint32_t accel = flags & EFFECT_FLAG_HW_ACC_MASK;
    if (accel) {
        s.append("hardware acceleration: ");
        switch (accel) {
        case EFFECT_FLAG_HW_ACC_SIMPLE: s.append("non-tunneled"); break;
        case EFFECT_FLAG_HW_ACC_TUNNEL: s.append("tunneled"); break;
        default: s.append("unknown/reserved"); break;
        }
        s.append(", ");
    }

    uint32_t modeind = flags & EFFECT_FLAG_AUDIO_MODE_MASK;
    if (modeind) {
        s.append("mode indication: ");
        switch (modeind) {
        case EFFECT_FLAG_AUDIO_MODE_IND: s.append("required"); break;
        default: s.append("unknown/reserved"); break;
        }
        s.append(", ");
    }

    uint32_t srcind = flags & EFFECT_FLAG_AUDIO_SOURCE_MASK;
    if (srcind) {
        s.append("source indication: ");
        switch (srcind) {
        case EFFECT_FLAG_AUDIO_SOURCE_IND: s.append("required"); break;
        default: s.append("unknown/reserved"); break;
        }
        s.append(", ");
    }

    if (flags & EFFECT_FLAG_OFFLOAD_MASK) {
        s.append("offloadable, ");
    }

    int len = s.length();
    if (s.length() > 2) {
        (void) s.lockBuffer(len);
        s.unlockBuffer(len - 2);
    }
    return s;
}

void EffectBase::dump(int fd, const Vector<String16>& args __unused) const
NO_THREAD_SAFETY_ANALYSIS // conditional try lock
{
    String8 result;

    result.appendFormat("\tEffect ID %d:\n", mId);

    const bool locked = afutils::dumpTryLock(mutex());
    // failed to lock - AudioFlinger is probably deadlocked
    if (!locked) {
        result.append("\t\tCould not lock Fx mutex:\n");
    }
    bool isInternal = isInternal_l();
    result.append("\t\tSession State Registered Internal Enabled Suspended:\n");
    result.appendFormat("\t\t%05d   %03d   %s          %s        %s       %s\n",
            mSessionId, mState, mPolicyRegistered ? "y" : "n", isInternal ? "y" : "n",
            ((isInternal && isEnabled()) || (!isInternal && mPolicyEnabled)) ? "y" : "n",
            mSuspended ? "y" : "n");

    result.append("\t\tDescriptor:\n");
    char uuidStr[64];
    AudioEffect::guidToString(&mDescriptor.uuid, uuidStr, sizeof(uuidStr));
    result.appendFormat("\t\t- UUID: %s\n", uuidStr);
    AudioEffect::guidToString(&mDescriptor.type, uuidStr, sizeof(uuidStr));
    result.appendFormat("\t\t- TYPE: %s\n", uuidStr);
    result.appendFormat("\t\t- apiVersion: %08X\n\t\t- flags: %08X (%s)\n",
            mDescriptor.apiVersion,
            mDescriptor.flags,
            effectFlagsToString(mDescriptor.flags).c_str());
    result.appendFormat("\t\t- name: %s\n",
            mDescriptor.name);

    result.appendFormat("\t\t- implementor: %s\n",
            mDescriptor.implementor);

    result.appendFormat("\t\t%zu Clients:\n", mHandles.size());
    result.append("\t\t\t  Pid Priority Ctrl Locked client server\n");
    char buffer[256];
    for (size_t i = 0; i < mHandles.size(); ++i) {
        IAfEffectHandle *handle = mHandles[i];
        if (handle != NULL && !handle->disconnected()) {
            handle->dumpToBuffer(buffer, sizeof(buffer));
            result.append(buffer);
        }
    }
    if (locked) {
        mutex().unlock();
    }

    write(fd, result.c_str(), result.length());
}

// ----------------------------------------------------------------------------
//  EffectModule implementation
// ----------------------------------------------------------------------------

#undef LOG_TAG
#define LOG_TAG "EffectModule"

EffectModule::EffectModule(const sp<EffectCallbackInterface>& callback,
                                         effect_descriptor_t *desc,
                                         int id,
                                         audio_session_t sessionId,
                                         bool pinned,
                                         audio_port_handle_t deviceId)
    : EffectBase(callback, desc, id, sessionId, pinned),
      // clear mConfig to ensure consistent initial value of buffer framecount
      // in case buffers are associated by setInBuffer() or setOutBuffer()
      // prior to configure_l().
      mConfig{{}, {}},
      mStatus(NO_INIT),
      mMaxDisableWaitCnt(1), // set by configure_l(), should be >= 1
      mDisableWaitCnt(0),    // set by process() and updateState()
      mOffloaded(false),
      mIsOutput(false)
      , mSupportsFloat(false)
{
    ALOGV("Constructor %p pinned %d", this, pinned);
    int lStatus;

    // create effect engine from effect factory
    mStatus = callback->createEffectHal(
            &desc->uuid, sessionId, deviceId, &mEffectInterface);
    if (mStatus != NO_ERROR) {
        return;
    }
    lStatus = init_l();
    if (lStatus < 0) {
        mStatus = lStatus;
        goto Error;
    }

    setOffloaded_l(callback->isOffload(), callback->io());
    ALOGV("Constructor success name %s, Interface %p", mDescriptor.name, mEffectInterface.get());

    return;
Error:
    mEffectInterface.clear();
    ALOGV("Constructor Error %d", mStatus);
}

EffectModule::~EffectModule()
{
    ALOGV("Destructor %p", this);
    if (mEffectInterface != 0) {
        char uuidStr[64];
        AudioEffect::guidToString(&mDescriptor.uuid, uuidStr, sizeof(uuidStr));
        ALOGW("EffectModule %p destructor called with unreleased interface, effect %s",
                this, uuidStr);
        release_l();
    }

}

bool EffectModule::updateState_l() {
    audio_utils::lock_guard _l(mutex());

    bool started = false;
    switch (mState) {
    case RESTART:
        reset_l();
        FALLTHROUGH_INTENDED;

    case STARTING:
        // clear auxiliary effect input buffer for next accumulation
        if ((mDescriptor.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_AUXILIARY) {
            memset(mConfig.inputCfg.buffer.raw,
                   0,
                   mConfig.inputCfg.buffer.frameCount*sizeof(int32_t));
        }
        if (start_ll() == NO_ERROR) {
            mState = ACTIVE;
            started = true;
        } else {
            mState = IDLE;
        }
        break;
    case STOPPING:
        // volume control for offload and direct threads must take effect immediately.
        if (stop_ll() == NO_ERROR
            && !(isVolumeControl() && isOffloadedOrDirect_l())) {
            mDisableWaitCnt = mMaxDisableWaitCnt;
        } else {
            mDisableWaitCnt = 1; // will cause immediate transition to IDLE
        }
        mState = STOPPED;
        break;
    case STOPPED:
        // mDisableWaitCnt is forced to 1 by process() when the engine indicates the end of the
        // turn off sequence.
        if (--mDisableWaitCnt == 0) {
            reset_l();
            mState = IDLE;
        }
        break;
    case ACTIVE:
        for (size_t i = 0; i < mHandles.size(); i++) {
            if (!mHandles[i]->disconnected()) {
                mHandles[i]->framesProcessed(mConfig.inputCfg.buffer.frameCount);
            }
        }
        break;
    default: //IDLE , ACTIVE, DESTROYED
        break;
    }

    return started;
}

void EffectModule::process()
{
    audio_utils::lock_guard _l(mutex());

    if (mState == DESTROYED || mEffectInterface == 0 || mInBuffer == 0 || mOutBuffer == 0) {
        return;
    }

    const uint32_t inChannelCount =
            audio_channel_count_from_out_mask(mConfig.inputCfg.channels);
    const uint32_t outChannelCount =
            audio_channel_count_from_out_mask(mConfig.outputCfg.channels);
    const bool auxType =
            (mDescriptor.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_AUXILIARY;

    // safeInputOutputSampleCount is 0 if the channel count between input and output
    // buffers do not match. This prevents automatic accumulation or copying between the
    // input and output effect buffers without an intermediary effect process.
    // TODO: consider implementing channel conversion.
    const size_t safeInputOutputSampleCount =
            mInChannelCountRequested != mOutChannelCountRequested ? 0
                    : mOutChannelCountRequested * std::min(
                            mConfig.inputCfg.buffer.frameCount,
                            mConfig.outputCfg.buffer.frameCount);
    const auto accumulateInputToOutput = [this, safeInputOutputSampleCount]() {
        accumulate_float(
                mConfig.outputCfg.buffer.f32,
                mConfig.inputCfg.buffer.f32,
                safeInputOutputSampleCount);
    };
    const auto copyInputToOutput = [this, safeInputOutputSampleCount]() {
        memcpy(
                mConfig.outputCfg.buffer.f32,
                mConfig.inputCfg.buffer.f32,
                safeInputOutputSampleCount * sizeof(*mConfig.outputCfg.buffer.f32));
    };

    if (isProcessEnabled()) {
        int ret;
        if (isProcessImplemented()) {
            if (auxType) {
                // We overwrite the aux input buffer here and clear after processing.
                // aux input is always mono.

                if (!mSupportsFloat) {
                    memcpy_to_i16_from_float(
                            mConfig.inputCfg.buffer.s16,
                            mConfig.inputCfg.buffer.f32,
                            mConfig.inputCfg.buffer.frameCount);
                }
            }
            sp<EffectBufferHalInterface> inBuffer = mInBuffer;
            sp<EffectBufferHalInterface> outBuffer = mOutBuffer;

            if (!auxType && mInChannelCountRequested != inChannelCount) {
                adjust_channels(
                        inBuffer->audioBuffer()->f32, mInChannelCountRequested,
                        mInConversionBuffer->audioBuffer()->f32, inChannelCount,
                        sizeof(float),
                        sizeof(float)
                        * mInChannelCountRequested * mConfig.inputCfg.buffer.frameCount);
                inBuffer = mInConversionBuffer;
            }
            if (mConfig.outputCfg.accessMode == EFFECT_BUFFER_ACCESS_ACCUMULATE
                    && mOutChannelCountRequested != outChannelCount) {
                adjust_selected_channels(
                        outBuffer->audioBuffer()->f32, mOutChannelCountRequested,
                        mOutConversionBuffer->audioBuffer()->f32, outChannelCount,
                        sizeof(float),
                        sizeof(float)
                        * mOutChannelCountRequested * mConfig.outputCfg.buffer.frameCount);
                outBuffer = mOutConversionBuffer;
            }
            if (!mSupportsFloat) { // convert input to int16_t as effect doesn't support float.
                if (!auxType) {
                    if (mInConversionBuffer == nullptr) {
                        ALOGW("%s: mInConversionBuffer is null, bypassing", __func__);
                        goto data_bypass;
                    }
                    memcpy_to_i16_from_float(
                            mInConversionBuffer->audioBuffer()->s16,
                            inBuffer->audioBuffer()->f32,
                            inChannelCount * mConfig.inputCfg.buffer.frameCount);
                    inBuffer = mInConversionBuffer;
                }
                if (mConfig.outputCfg.accessMode == EFFECT_BUFFER_ACCESS_ACCUMULATE) {
                    if (mOutConversionBuffer == nullptr) {
                        ALOGW("%s: mOutConversionBuffer is null, bypassing", __func__);
                        goto data_bypass;
                    }
                    memcpy_to_i16_from_float(
                            mOutConversionBuffer->audioBuffer()->s16,
                            outBuffer->audioBuffer()->f32,
                            outChannelCount * mConfig.outputCfg.buffer.frameCount);
                    outBuffer = mOutConversionBuffer;
                }
            }
            ret = mEffectInterface->process();
            if (!mSupportsFloat) { // convert output int16_t back to float.
                sp<EffectBufferHalInterface> target =
                        mOutChannelCountRequested != outChannelCount
                        ? mOutConversionBuffer : mOutBuffer;

                memcpy_to_float_from_i16(
                        target->audioBuffer()->f32,
                        mOutConversionBuffer->audioBuffer()->s16,
                        outChannelCount * mConfig.outputCfg.buffer.frameCount);
            }
            if (mOutChannelCountRequested != outChannelCount) {
                adjust_selected_channels(mOutConversionBuffer->audioBuffer()->f32, outChannelCount,
                        mOutBuffer->audioBuffer()->f32, mOutChannelCountRequested,
                        sizeof(float),
                        sizeof(float) * outChannelCount * mConfig.outputCfg.buffer.frameCount);
            }
        } else {
            data_bypass:
            if (!auxType  /* aux effects do not require data bypass */
                    && mConfig.inputCfg.buffer.raw != mConfig.outputCfg.buffer.raw) {
                if (mConfig.outputCfg.accessMode == EFFECT_BUFFER_ACCESS_ACCUMULATE) {
                    accumulateInputToOutput();
                } else {
                    copyInputToOutput();
                }
            }
            ret = -ENODATA;
        }

        // force transition to IDLE state when engine is ready
        if (mState == STOPPED && ret == -ENODATA) {
            mDisableWaitCnt = 1;
        }

        // clear auxiliary effect input buffer for next accumulation
        if (auxType) {
            const size_t size =
                    mConfig.inputCfg.buffer.frameCount * inChannelCount * sizeof(float);
            memset(mConfig.inputCfg.buffer.raw, 0, size);
        }
    } else if ((mDescriptor.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_INSERT &&
                // mInBuffer->audioBuffer()->raw != mOutBuffer->audioBuffer()->raw
                mConfig.inputCfg.buffer.raw != mConfig.outputCfg.buffer.raw) {
        // If an insert effect is idle and input buffer is different from output buffer,
        // accumulate input onto output
        if (getCallback()->activeTrackCnt() != 0) {
            // similar handling with data_bypass above.
            if (mConfig.outputCfg.accessMode == EFFECT_BUFFER_ACCESS_ACCUMULATE) {
                accumulateInputToOutput();
            } else { // EFFECT_BUFFER_ACCESS_WRITE
                copyInputToOutput();
            }
        }
    }
}

void EffectModule::reset_l()
{
    if (mStatus != NO_ERROR || mEffectInterface == 0) {
        return;
    }

    int reply = 0;
    uint32_t replySize = sizeof(reply);
    mEffectInterface->command(EFFECT_CMD_RESET, 0, NULL, &replySize, &reply);
}

status_t EffectModule::configure_l()
{
    ALOGVV("%s started", __func__);
    status_t status;
    uint32_t size;
    audio_channel_mask_t channelMask;
    sp<EffectCallbackInterface> callback;

    if (mEffectInterface == 0) {
        status = NO_INIT;
        goto exit;
    }

    // TODO: handle configuration of effects replacing track process
    // TODO: handle configuration of input (record) SW effects above the HAL,
    // similar to output EFFECT_FLAG_TYPE_INSERT/REPLACE,
    // in which case input channel masks should be used here.
    callback = getCallback();
    channelMask = callback->inChannelMask(mId);
    mConfig.inputCfg.channels = channelMask;
    mConfig.outputCfg.channels = callback->outChannelMask();

    if ((mDescriptor.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_AUXILIARY) {
        if (mConfig.inputCfg.channels != AUDIO_CHANNEL_OUT_MONO) {
            mConfig.inputCfg.channels = AUDIO_CHANNEL_OUT_MONO;
            ALOGV("Overriding auxiliary effect input channels %#x as MONO",
                    mConfig.inputCfg.channels);
        }
    }
    if (isHapticGenerator()) {
        audio_channel_mask_t hapticChannelMask = callback->hapticChannelMask();
        mConfig.inputCfg.channels |= hapticChannelMask;
        mConfig.outputCfg.channels |= hapticChannelMask;
    }
    mInChannelCountRequested =
            audio_channel_count_from_out_mask(mConfig.inputCfg.channels);
    mOutChannelCountRequested =
            audio_channel_count_from_out_mask(mConfig.outputCfg.channels);

    mConfig.inputCfg.format = AUDIO_FORMAT_PCM_FLOAT;
    mConfig.outputCfg.format = AUDIO_FORMAT_PCM_FLOAT;

    // Don't use sample rate for thread if effect isn't offloadable.
    if (callback->isOffloadOrDirect() && !isOffloaded_l()) {
        mConfig.inputCfg.samplingRate = DEFAULT_OUTPUT_SAMPLE_RATE;
        ALOGV("Overriding effect input as 48kHz");
    } else {
        mConfig.inputCfg.samplingRate = callback->sampleRate();
    }
    mConfig.outputCfg.samplingRate = mConfig.inputCfg.samplingRate;
    mConfig.inputCfg.bufferProvider.cookie = NULL;
    mConfig.inputCfg.bufferProvider.getBuffer = NULL;
    mConfig.inputCfg.bufferProvider.releaseBuffer = NULL;
    mConfig.outputCfg.bufferProvider.cookie = NULL;
    mConfig.outputCfg.bufferProvider.getBuffer = NULL;
    mConfig.outputCfg.bufferProvider.releaseBuffer = NULL;
    mConfig.inputCfg.accessMode = EFFECT_BUFFER_ACCESS_READ;
    // Insert effect:
    // - in global sessions (e.g AUDIO_SESSION_OUTPUT_MIX),
    // always overwrites output buffer: input buffer == output buffer
    // - in other sessions:
    //      last effect in the chain accumulates in output buffer: input buffer != output buffer
    //      other effect: overwrites output buffer: input buffer == output buffer
    // Auxiliary effect:
    //      accumulates in output buffer: input buffer != output buffer
    // Therefore: accumulate <=> input buffer != output buffer
    mConfig.outputCfg.accessMode = requiredEffectBufferAccessMode();
    mConfig.inputCfg.mask = EFFECT_CONFIG_ALL;
    mConfig.outputCfg.mask = EFFECT_CONFIG_ALL;
    mConfig.inputCfg.buffer.frameCount = callback->frameCount();
    mConfig.outputCfg.buffer.frameCount = mConfig.inputCfg.buffer.frameCount;
    mIsOutput = callback->isOutput();

    ALOGV("%s %p chain %p buffer %p framecount %zu", __func__, this,
          callback->chain().promote().get(), mConfig.inputCfg.buffer.raw,
          mConfig.inputCfg.buffer.frameCount);

    status_t cmdStatus;
    size = sizeof(int);
    status = mEffectInterface->command(EFFECT_CMD_SET_CONFIG,
                                       sizeof(mConfig),
                                       &mConfig,
                                       &size,
                                       &cmdStatus);
    if (status == NO_ERROR) {
        status = cmdStatus;
    }

    if (status != NO_ERROR &&
            EffectConfiguration::isHidl() && // only HIDL effects support channel conversion
            mIsOutput &&
            (mConfig.inputCfg.channels != AUDIO_CHANNEL_OUT_STEREO
                    || mConfig.outputCfg.channels != AUDIO_CHANNEL_OUT_STEREO)) {
        // Older effects may require exact STEREO position mask.
        if (mConfig.inputCfg.channels != AUDIO_CHANNEL_OUT_STEREO
                && (mDescriptor.flags & EFFECT_FLAG_TYPE_MASK) != EFFECT_FLAG_TYPE_AUXILIARY) {
            ALOGV("Overriding effect input channels %#x as STEREO", mConfig.inputCfg.channels);
            mConfig.inputCfg.channels = AUDIO_CHANNEL_OUT_STEREO;
        }
        if (mConfig.outputCfg.channels != AUDIO_CHANNEL_OUT_STEREO) {
            ALOGV("Overriding effect output channels %#x as STEREO", mConfig.outputCfg.channels);
            mConfig.outputCfg.channels = AUDIO_CHANNEL_OUT_STEREO;
        }
        size = sizeof(int);
        status = mEffectInterface->command(EFFECT_CMD_SET_CONFIG,
                                           sizeof(mConfig),
                                           &mConfig,
                                           &size,
                                           &cmdStatus);
        if (status == NO_ERROR) {
            status = cmdStatus;
        }
    }

    if (status == NO_ERROR) {
        mSupportsFloat = true;
    }

    // only HIDL effects support integer conversion.
    if (status != NO_ERROR && EffectConfiguration::isHidl()) {
        ALOGV("EFFECT_CMD_SET_CONFIG failed with float format, retry with int16_t.");
        mConfig.inputCfg.format = AUDIO_FORMAT_PCM_16_BIT;
        mConfig.outputCfg.format = AUDIO_FORMAT_PCM_16_BIT;
        size = sizeof(int);
        status = mEffectInterface->command(EFFECT_CMD_SET_CONFIG,
                                           sizeof(mConfig),
                                           &mConfig,
                                           &size,
                                           &cmdStatus);
        if (status == NO_ERROR) {
            status = cmdStatus;
        }
        if (status == NO_ERROR) {
            mSupportsFloat = false;
            ALOGVV("config worked with 16 bit");
        } else {
            ALOGE("%s failed %d with int16_t (as well as float)", __func__, status);
        }
    }

    if (status == NO_ERROR) {
        // Establish Buffer strategy
        setInBuffer(mInBuffer);
        setOutBuffer(mOutBuffer);

        // Update visualizer latency
        if (memcmp(&mDescriptor.type, SL_IID_VISUALIZATION, sizeof(effect_uuid_t)) == 0) {
            uint32_t buf32[sizeof(effect_param_t) / sizeof(uint32_t) + 2];
            effect_param_t *p = (effect_param_t *)buf32;

            p->psize = sizeof(uint32_t);
            p->vsize = sizeof(uint32_t);
            size = sizeof(int);
            *(int32_t *)p->data = VISUALIZER_PARAM_LATENCY;

            uint32_t latency = callback->latency();

            *((int32_t *)p->data + 1)= latency;
            mEffectInterface->command(EFFECT_CMD_SET_PARAM,
                    sizeof(effect_param_t) + 8,
                    &buf32,
                    &size,
                    &cmdStatus);
        }
    }

    // mConfig.outputCfg.buffer.frameCount cannot be zero.
    mMaxDisableWaitCnt = (uint32_t)std::max(
            (uint64_t)1, // mMaxDisableWaitCnt must be greater than zero.
            (uint64_t)mConfig.outputCfg.buffer.frameCount == 0 ? 1
                : (MAX_DISABLE_TIME_MS * mConfig.outputCfg.samplingRate
                / ((uint64_t)1000 * mConfig.outputCfg.buffer.frameCount)));

exit:
    // TODO: consider clearing mConfig on error.
    mStatus = status;
    ALOGVV("%s ended", __func__);
    return status;
}

status_t EffectModule::init_l()
{
    audio_utils::lock_guard _l(mutex());
    if (mEffectInterface == 0) {
        return NO_INIT;
    }
    status_t cmdStatus;
    uint32_t size = sizeof(status_t);
    status_t status = mEffectInterface->command(EFFECT_CMD_INIT,
                                                0,
                                                NULL,
                                                &size,
                                                &cmdStatus);
    if (status == 0) {
        status = cmdStatus;
    }
    return status;
}

void EffectModule::addEffectToHal_l()
{
    if ((mDescriptor.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_PRE_PROC ||
         (mDescriptor.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_POST_PROC) {
        if (mCurrentHalStream == getCallback()->io()) {
            return;
        }

        (void)getCallback()->addEffectToHal(mEffectInterface);
        mCurrentHalStream = getCallback()->io();
    }
}

// start_l() must be called with EffectChain::mutex() held
status_t EffectModule::start_l()
{
    status_t status;
    {
        audio_utils::lock_guard _l(mutex());
        status = start_ll();
    }
    if (status == NO_ERROR) {
        getCallback()->resetVolume_l();
    }
    return status;
}

status_t EffectModule::start_ll()
{
    if (mEffectInterface == 0) {
        return NO_INIT;
    }
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    status_t cmdStatus;
    uint32_t size = sizeof(status_t);
    status_t status = mEffectInterface->command(EFFECT_CMD_ENABLE,
                                                0,
                                                NULL,
                                                &size,
                                                &cmdStatus);
    if (status == 0) {
        status = cmdStatus;
    }
    if (status == 0) {
        addEffectToHal_l();
    }
    return status;
}

status_t EffectModule::stop_l()
{
    audio_utils::lock_guard _l(mutex());
    return stop_ll();
}

status_t EffectModule::stop_ll()
{
    if (mEffectInterface == 0) {
        return NO_INIT;
    }
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    status_t cmdStatus = NO_ERROR;
    uint32_t size = sizeof(status_t);

    if (isVolumeControl() && isOffloadedOrDirect_l()) {
        // We have the EffectChain and EffectModule lock, permit a reentrant call to setVolume:
        // resetVolume_l --> setVolume_l --> EffectModule::setVolume
        mSetVolumeReentrantTid = gettid();
        getCallback()->resetVolume_l();
        mSetVolumeReentrantTid = INVALID_PID;
    }

    status_t status = mEffectInterface->command(EFFECT_CMD_DISABLE,
                                                0,
                                                NULL,
                                                &size,
                                                &cmdStatus);
    if (status == NO_ERROR) {
        status = cmdStatus;
    }
    if (status == NO_ERROR) {
        status = removeEffectFromHal_l();
    }
    return status;
}

// must be called with EffectChain::mutex() held
void EffectModule::release_l()
{
    if (mEffectInterface != 0) {
        removeEffectFromHal_l();
        // release effect engine
        mEffectInterface->close();
        mEffectInterface.clear();
    }
}

status_t EffectModule::removeEffectFromHal_l()
{
    if ((mDescriptor.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_PRE_PROC ||
             (mDescriptor.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_POST_PROC) {
        if (mCurrentHalStream != getCallback()->io()) {
            return (mCurrentHalStream == AUDIO_IO_HANDLE_NONE) ? NO_ERROR : INVALID_OPERATION;
        }
        getCallback()->removeEffectFromHal(mEffectInterface);
        mCurrentHalStream = AUDIO_IO_HANDLE_NONE;
    }
    return NO_ERROR;
}

// round up delta valid if value and divisor are positive.
template <typename T>
static T roundUpDelta(const T &value, const T &divisor) {
    T remainder = value % divisor;
    return remainder == 0 ? 0 : divisor - remainder;
}

status_t EffectModule::command(int32_t cmdCode,
                     const std::vector<uint8_t>& cmdData,
                     int32_t maxReplySize,
                     std::vector<uint8_t>* reply)
{
    audio_utils::lock_guard _l(mutex());
    ALOGVV("%s, cmdCode: %d, mEffectInterface: %p", __func__, cmdCode, mEffectInterface.get());

    if (mState == DESTROYED || mEffectInterface == 0) {
        return NO_INIT;
    }
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    if (maxReplySize < 0 || maxReplySize > EFFECT_PARAM_SIZE_MAX) {
        return -EINVAL;
    }
    size_t cmdSize = cmdData.size();
    const effect_param_t* param = cmdSize >= sizeof(effect_param_t)
                                  ? reinterpret_cast<const effect_param_t*>(cmdData.data())
                                  : nullptr;
    if (cmdCode == EFFECT_CMD_GET_PARAM &&
            (param == nullptr || param->psize > cmdSize - sizeof(effect_param_t))) {
        android_errorWriteLog(0x534e4554, "32438594");
        android_errorWriteLog(0x534e4554, "33003822");
        return -EINVAL;
    }
    if (cmdCode == EFFECT_CMD_GET_PARAM &&
            (maxReplySize < static_cast<signed>(sizeof(effect_param_t)) ||
                   param->psize > maxReplySize - sizeof(effect_param_t))) {
        android_errorWriteLog(0x534e4554, "29251553");
        return -EINVAL;
    }
    if (cmdCode == EFFECT_CMD_GET_PARAM &&
            (static_cast<signed>(sizeof(effect_param_t)) > maxReplySize
                    || param->psize > maxReplySize - sizeof(effect_param_t)
                    || param->vsize > maxReplySize - sizeof(effect_param_t)
                            - param->psize
                    || roundUpDelta(param->psize, (uint32_t) sizeof(int)) >
                            maxReplySize
                                    - sizeof(effect_param_t)
                                    - param->psize
                                    - param->vsize)) {
        ALOGV("\tLVM_ERROR : EFFECT_CMD_GET_PARAM: reply size inconsistent");
                     android_errorWriteLog(0x534e4554, "32705438");
        return -EINVAL;
    }
    if ((cmdCode == EFFECT_CMD_SET_PARAM
            || cmdCode == EFFECT_CMD_SET_PARAM_DEFERRED)
            &&  // DEFERRED not generally used
                    (param == nullptr
                            || param->psize > cmdSize - sizeof(effect_param_t)
                            || param->vsize > cmdSize - sizeof(effect_param_t)
                                    - param->psize
                            || roundUpDelta(param->psize,
                                            (uint32_t) sizeof(int)) >
                                    cmdSize
                                            - sizeof(effect_param_t)
                                            - param->psize
                                            - param->vsize)) {
        android_errorWriteLog(0x534e4554, "30204301");
        return -EINVAL;
    }
    uint32_t replySize = maxReplySize;
    reply->resize(replySize);
    status_t status = mEffectInterface->command(cmdCode,
                                                cmdSize,
                                                const_cast<uint8_t*>(cmdData.data()),
                                                &replySize,
                                                reply->data());
    reply->resize(status == NO_ERROR ? replySize : 0);
    if (cmdCode != EFFECT_CMD_GET_PARAM && status == NO_ERROR) {
        for (size_t i = 1; i < mHandles.size(); i++) {
            IAfEffectHandle *h = mHandles[i];
            if (h != NULL && !h->disconnected()) {
                h->commandExecuted(cmdCode, cmdData, *reply);
            }
        }
    }
    return status;
}

bool EffectModule::isProcessEnabled() const
{
    if (mStatus != NO_ERROR) {
        return false;
    }

    switch (mState) {
    case RESTART:
    case ACTIVE:
    case STOPPING:
    case STOPPED:
        return true;
    case IDLE:
    case STARTING:
    case DESTROYED:
    default:
        return false;
    }
}

bool EffectModule::isOffloadedOrDirect_l() const
{
    return getCallback()->isOffloadOrDirect();
}

bool EffectModule::isVolumeControlEnabled_l() const
{
    return (isVolumeControl() && (isOffloadedOrDirect_l() ? isEnabled() : isProcessEnabled()));
}

void EffectModule::setInBuffer(const sp<EffectBufferHalInterface>& buffer) {
    ALOGVV("setInBuffer %p",(&buffer));

    // mConfig.inputCfg.buffer.frameCount may be zero if configure_l() is not called yet.
    if (buffer != 0) {
        mConfig.inputCfg.buffer.raw = buffer->audioBuffer()->raw;
        buffer->setFrameCount(mConfig.inputCfg.buffer.frameCount);
    } else {
        mConfig.inputCfg.buffer.raw = NULL;
    }
    mInBuffer = buffer;
    mEffectInterface->setInBuffer(buffer);

    // aux effects do in place conversion to float - we don't allocate mInConversionBuffer.
    // Theoretically insert effects can also do in-place conversions (destroying
    // the original buffer) when the output buffer is identical to the input buffer,
    // but we don't optimize for it here.
    const bool auxType = (mDescriptor.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_AUXILIARY;
    const uint32_t inChannelCount =
            audio_channel_count_from_out_mask(mConfig.inputCfg.channels);
    const bool formatMismatch = !mSupportsFloat || mInChannelCountRequested != inChannelCount;
    if (!auxType && formatMismatch && mInBuffer != nullptr) {
        // we need to translate - create hidl shared buffer and intercept
        const size_t inFrameCount = mConfig.inputCfg.buffer.frameCount;
        // Use FCC_2 in case mInChannelCountRequested is mono and the effect is stereo.
        const uint32_t inChannels = std::max((uint32_t)FCC_2, mInChannelCountRequested);
        const size_t size = inChannels * inFrameCount * std::max(sizeof(int16_t), sizeof(float));

        ALOGV("%s: setInBuffer updating for inChannels:%d inFrameCount:%zu total size:%zu",
                __func__, inChannels, inFrameCount, size);

        if (size > 0 && (mInConversionBuffer == nullptr
                || size > mInConversionBuffer->getSize())) {
            mInConversionBuffer.clear();
            ALOGV("%s: allocating mInConversionBuffer %zu", __func__, size);
            (void)getCallback()->allocateHalBuffer(size, &mInConversionBuffer);
        }
        if (mInConversionBuffer != nullptr) {
            mInConversionBuffer->setFrameCount(inFrameCount);
            mEffectInterface->setInBuffer(mInConversionBuffer);
        } else if (size > 0) {
            ALOGE("%s cannot create mInConversionBuffer", __func__);
        }
    }
}

void EffectModule::setOutBuffer(const sp<EffectBufferHalInterface>& buffer) {
    ALOGVV("setOutBuffer %p",(&buffer));

    // mConfig.outputCfg.buffer.frameCount may be zero if configure_l() is not called yet.
    if (buffer != 0) {
        mConfig.outputCfg.buffer.raw = buffer->audioBuffer()->raw;
        buffer->setFrameCount(mConfig.outputCfg.buffer.frameCount);
    } else {
        mConfig.outputCfg.buffer.raw = NULL;
    }
    mOutBuffer = buffer;
    mEffectInterface->setOutBuffer(buffer);

    // Note: Any effect that does not accumulate does not need mOutConversionBuffer and
    // can do in-place conversion from int16_t to float.  We don't optimize here.
    const uint32_t outChannelCount =
            audio_channel_count_from_out_mask(mConfig.outputCfg.channels);
    const bool formatMismatch = !mSupportsFloat || mOutChannelCountRequested != outChannelCount;
    if (formatMismatch && mOutBuffer != nullptr) {
        const size_t outFrameCount = mConfig.outputCfg.buffer.frameCount;
        // Use FCC_2 in case mOutChannelCountRequested is mono and the effect is stereo.
        const uint32_t outChannels = std::max((uint32_t)FCC_2, mOutChannelCountRequested);
        const size_t size = outChannels * outFrameCount * std::max(sizeof(int16_t), sizeof(float));

        ALOGV("%s: setOutBuffer updating for outChannels:%d outFrameCount:%zu total size:%zu",
                __func__, outChannels, outFrameCount, size);

        if (size > 0 && (mOutConversionBuffer == nullptr
                || size > mOutConversionBuffer->getSize())) {
            mOutConversionBuffer.clear();
            ALOGV("%s: allocating mOutConversionBuffer %zu", __func__, size);
            (void)getCallback()->allocateHalBuffer(size, &mOutConversionBuffer);
        }
        if (mOutConversionBuffer != nullptr) {
            mOutConversionBuffer->setFrameCount(outFrameCount);
            mEffectInterface->setOutBuffer(mOutConversionBuffer);
        } else if (size > 0) {
            ALOGE("%s cannot create mOutConversionBuffer", __func__);
        }
    }
}

status_t EffectModule::setVolume(uint32_t* left, uint32_t* right, bool controller) {
    AutoLockReentrant _l(mutex(), mSetVolumeReentrantTid);
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    status_t status = NO_ERROR;
    // Send volume indication if EFFECT_FLAG_VOLUME_IND is set and read back altered volume
    // if controller flag is set (Note that controller == TRUE => EFFECT_FLAG_VOLUME_CTRL set)
    if (isProcessEnabled() &&
            ((mDescriptor.flags & EFFECT_FLAG_VOLUME_MASK) == EFFECT_FLAG_VOLUME_CTRL ||
             (mDescriptor.flags & EFFECT_FLAG_VOLUME_MASK) == EFFECT_FLAG_VOLUME_IND ||
             (mDescriptor.flags & EFFECT_FLAG_VOLUME_MASK) == EFFECT_FLAG_VOLUME_MONITOR)) {
        status = setVolumeInternal(left, right, controller);
    }
    return status;
}

status_t EffectModule::setVolumeInternal(
        uint32_t *left, uint32_t *right, bool controller) {
    uint32_t volume[2] = {*left, *right};
    uint32_t *pVolume = controller ? volume : nullptr;
    uint32_t size = sizeof(volume);
    status_t status = mEffectInterface->command(EFFECT_CMD_SET_VOLUME,
                                                size,
                                                volume,
                                                &size,
                                                pVolume);
    if (controller && status == NO_ERROR && size == sizeof(volume)) {
        *left = volume[0];
        *right = volume[1];
    }
    return status;
}

void EffectChain::setVolumeForOutput_l(uint32_t left, uint32_t right)
{
    // for offload or direct thread, if the effect chain has non-offloadable
    // effect and any effect module within the chain has volume control, then
    // volume control is delegated to effect, otherwise, set volume to hal.
    if (mEffectCallback->isOffloadOrDirect() &&
        !(isNonOffloadableEnabled_l() && hasVolumeControlEnabled_l())) {
        float vol_l = (float)left / (1 << 24);
        float vol_r = (float)right / (1 << 24);
        mEffectCallback->setVolumeForOutput(vol_l, vol_r);
    }
}

status_t EffectModule::sendSetAudioDevicesCommand(
        const AudioDeviceTypeAddrVector &devices, uint32_t cmdCode)
{
    audio_devices_t deviceType = deviceTypesToBitMask(getAudioDeviceTypes(devices));
    if (deviceType == AUDIO_DEVICE_NONE) {
        return NO_ERROR;
    }

    audio_utils::lock_guard _l(mutex());
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    status_t status = NO_ERROR;
    if ((mDescriptor.flags & EFFECT_FLAG_DEVICE_MASK) == EFFECT_FLAG_DEVICE_IND) {
        status_t cmdStatus;
        uint32_t size = sizeof(status_t);
        // FIXME: use audio device types and addresses when the hal interface is ready.
        status = mEffectInterface->command(cmdCode,
                                           sizeof(uint32_t),
                                           &deviceType,
                                           &size,
                                           &cmdStatus);
    }
    return status;
}

status_t EffectModule::setDevices(const AudioDeviceTypeAddrVector &devices)
{
    return sendSetAudioDevicesCommand(devices, EFFECT_CMD_SET_DEVICE);
}

status_t EffectModule::setInputDevice(const AudioDeviceTypeAddr &device)
{
    return sendSetAudioDevicesCommand({device}, EFFECT_CMD_SET_INPUT_DEVICE);
}

status_t EffectModule::setMode(audio_mode_t mode)
{
    audio_utils::lock_guard _l(mutex());
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    status_t status = NO_ERROR;
    if ((mDescriptor.flags & EFFECT_FLAG_AUDIO_MODE_MASK) == EFFECT_FLAG_AUDIO_MODE_IND) {
        status_t cmdStatus;
        uint32_t size = sizeof(status_t);
        status = mEffectInterface->command(EFFECT_CMD_SET_AUDIO_MODE,
                                           sizeof(audio_mode_t),
                                           &mode,
                                           &size,
                                           &cmdStatus);
        if (status == NO_ERROR) {
            status = cmdStatus;
        }
    }
    return status;
}

status_t EffectModule::setAudioSource(audio_source_t source)
{
    audio_utils::lock_guard _l(mutex());
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    status_t status = NO_ERROR;
    if ((mDescriptor.flags & EFFECT_FLAG_AUDIO_SOURCE_MASK) == EFFECT_FLAG_AUDIO_SOURCE_IND) {
        uint32_t size = 0;
        status = mEffectInterface->command(EFFECT_CMD_SET_AUDIO_SOURCE,
                                           sizeof(audio_source_t),
                                           &source,
                                           &size,
                                           NULL);
    }
    return status;
}

status_t EffectModule::setOffloaded_l(bool offloaded, audio_io_handle_t io)
{
    audio_utils::lock_guard _l(mutex());
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    status_t status = NO_ERROR;
    if ((mDescriptor.flags & EFFECT_FLAG_OFFLOAD_SUPPORTED) != 0) {
        status_t cmdStatus;
        uint32_t size = sizeof(status_t);
        effect_offload_param_t cmd;

        cmd.isOffload = offloaded;
        cmd.ioHandle = io;
        status = mEffectInterface->command(EFFECT_CMD_OFFLOAD,
                                           sizeof(effect_offload_param_t),
                                           &cmd,
                                           &size,
                                           &cmdStatus);
        if (status == NO_ERROR) {
            status = cmdStatus;
        }
        mOffloaded = (status == NO_ERROR) ? offloaded : false;
    } else {
        if (offloaded) {
            status = INVALID_OPERATION;
        }
        mOffloaded = false;
    }
    ALOGV("%s offloaded %d io %d status %d", __func__, offloaded, io, status);
    return status;
}

bool EffectModule::isOffloaded_l() const
{
    audio_utils::lock_guard _l(mutex());
    return mOffloaded;
}

/*static*/
bool IAfEffectModule::isHapticGenerator(const effect_uuid_t *type) {
    return memcmp(type, FX_IID_HAPTICGENERATOR, sizeof(effect_uuid_t)) == 0;
}

bool EffectModule::isHapticGenerator() const {
    return IAfEffectModule::isHapticGenerator(&mDescriptor.type);
}

/*static*/
bool IAfEffectModule::isSpatializer(const effect_uuid_t *type) {
    return memcmp(type, FX_IID_SPATIALIZER, sizeof(effect_uuid_t)) == 0;
}

bool EffectModule::isSpatializer() const {
    return IAfEffectModule::isSpatializer(&mDescriptor.type);
}

status_t EffectModule::setHapticScale_l(int id, os::HapticScale hapticScale) {
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    if (!isHapticGenerator()) {
        ALOGW("Should not set haptic intensity for effects that are not HapticGenerator");
        return INVALID_OPERATION;
    }

    std::vector<uint8_t> request(sizeof(effect_param_t) + 3 * sizeof(uint32_t));
    effect_param_t *param = (effect_param_t*) request.data();
    param->psize = sizeof(int32_t);
    param->vsize = sizeof(int32_t) * 2;
    *(int32_t*)param->data = HG_PARAM_HAPTIC_INTENSITY;
    *((int32_t*)param->data + 1) = id;
    *((int32_t*)param->data + 2) = static_cast<int32_t>(hapticScale.getLevel());
    std::vector<uint8_t> response;
    status_t status = command(EFFECT_CMD_SET_PARAM, request, sizeof(int32_t), &response);
    if (status == NO_ERROR) {
        LOG_ALWAYS_FATAL_IF(response.size() != 4);
        status = *reinterpret_cast<const status_t*>(response.data());
    }
    return status;
}

status_t EffectModule::setVibratorInfo_l(const media::AudioVibratorInfo& vibratorInfo) {
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    if (!isHapticGenerator()) {
        ALOGW("Should not set vibrator info for effects that are not HapticGenerator");
        return INVALID_OPERATION;
    }

    const size_t paramCount = 3;
    std::vector<uint8_t> request(
            sizeof(effect_param_t) + sizeof(int32_t) + paramCount * sizeof(float));
    effect_param_t *param = (effect_param_t*) request.data();
    param->psize = sizeof(int32_t);
    param->vsize = paramCount * sizeof(float);
    *(int32_t*)param->data = HG_PARAM_VIBRATOR_INFO;
    float* vibratorInfoPtr = reinterpret_cast<float*>(param->data + sizeof(int32_t));
    vibratorInfoPtr[0] = vibratorInfo.resonantFrequency;
    vibratorInfoPtr[1] = vibratorInfo.qFactor;
    vibratorInfoPtr[2] = vibratorInfo.maxAmplitude;
    std::vector<uint8_t> response;
    status_t status = command(EFFECT_CMD_SET_PARAM, request, sizeof(int32_t), &response);
    if (status == NO_ERROR) {
        LOG_ALWAYS_FATAL_IF(response.size() != sizeof(status_t));
        status = *reinterpret_cast<const status_t*>(response.data());
    }
    return status;
}

status_t EffectModule::getConfigs_l(audio_config_base_t* inputCfg, audio_config_base_t* outputCfg,
                                    bool* isOutput) const {
    audio_utils::lock_guard _l(mutex());
    if (mConfig.inputCfg.mask == 0 || mConfig.outputCfg.mask == 0) {
        return NO_INIT;
    }
    inputCfg->sample_rate = mConfig.inputCfg.samplingRate;
    inputCfg->channel_mask = static_cast<audio_channel_mask_t>(mConfig.inputCfg.channels);
    inputCfg->format = static_cast<audio_format_t>(mConfig.inputCfg.format);
    outputCfg->sample_rate = mConfig.outputCfg.samplingRate;
    outputCfg->channel_mask = static_cast<audio_channel_mask_t>(mConfig.outputCfg.channels);
    outputCfg->format = static_cast<audio_format_t>(mConfig.outputCfg.format);
    *isOutput = mIsOutput;
    return NO_ERROR;
}

status_t EffectModule::sendMetadata_ll(const std::vector<playback_track_metadata_v7_t>& metadata) {
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    // TODO b/307368176: send all metadata to effects if requested by the implementation.
    // For now only send channel mask to Spatializer.
    if (!isSpatializer()) {
        return INVALID_OPERATION;
    }

    std::vector<uint8_t> request(
            sizeof(effect_param_t) + sizeof(int32_t) + metadata.size() * sizeof(uint32_t));
    effect_param_t *param = (effect_param_t*) request.data();
    param->psize = sizeof(int32_t);
    param->vsize = metadata.size() * sizeof(uint32_t);
    *(int32_t*)param->data = SPATIALIZER_PARAM_INPUT_CHANNEL_MASK;
    uint32_t* channelMasks = reinterpret_cast<uint32_t*>(param->data + sizeof(int32_t));
    for (auto m : metadata) {
        *channelMasks++ = m.channel_mask;
    }
    std::vector<uint8_t> response;
    status_t status = command(EFFECT_CMD_SET_PARAM, request, sizeof(int32_t), &response);
    if (status == NO_ERROR) {
        LOG_ALWAYS_FATAL_IF(response.size() != sizeof(status_t));
        status = *reinterpret_cast<const status_t*>(response.data());
    }
    return status;
}

static std::string dumpInOutBuffer(bool isInput, const sp<EffectBufferHalInterface> &buffer) {
    std::stringstream ss;

    if (buffer == nullptr) {
        return "nullptr"; // make different than below
    } else if (buffer->externalData() != nullptr) {
        ss << (isInput ? buffer->externalData() : buffer->audioBuffer()->raw)
                << " -> "
                << (isInput ? buffer->audioBuffer()->raw : buffer->externalData());
    } else {
        ss << buffer->audioBuffer()->raw;
    }
    return ss.str();
}

void EffectModule::dump(int fd, const Vector<String16>& args) const
NO_THREAD_SAFETY_ANALYSIS  // conditional try lock
{
    EffectBase::dump(fd, args);

    String8 result;
    const bool locked = afutils::dumpTryLock(mutex());

    result.append("\t\tStatus Engine:\n");
    result.appendFormat("\t\t%03d    %p\n",
            mStatus, mEffectInterface.get());

    result.appendFormat("\t\t- data: %s\n", mSupportsFloat ? "float" : "int16");

    result.append("\t\t- Input configuration:\n");
    result.append("\t\t\tBuffer     Frames  Smp rate Channels Format\n");
    result.appendFormat("\t\t\t%p %05zu   %05d    %08x %6d (%s)\n",
            mConfig.inputCfg.buffer.raw,
            mConfig.inputCfg.buffer.frameCount,
            mConfig.inputCfg.samplingRate,
            mConfig.inputCfg.channels,
            mConfig.inputCfg.format,
            toString(static_cast<audio_format_t>(mConfig.inputCfg.format)).c_str());

    result.append("\t\t- Output configuration:\n");
    result.append("\t\t\tBuffer     Frames  Smp rate Channels Format\n");
    result.appendFormat("\t\t\t%p %05zu   %05d    %08x %6d (%s)\n",
            mConfig.outputCfg.buffer.raw,
            mConfig.outputCfg.buffer.frameCount,
            mConfig.outputCfg.samplingRate,
            mConfig.outputCfg.channels,
            mConfig.outputCfg.format,
            toString(static_cast<audio_format_t>(mConfig.outputCfg.format)).c_str());

    result.appendFormat("\t\t- HAL buffers:\n"
            "\t\t\tIn(%s) InConversion(%s) Out(%s) OutConversion(%s)\n",
            dumpInOutBuffer(true /* isInput */, mInBuffer).c_str(),
            dumpInOutBuffer(true /* isInput */, mInConversionBuffer).c_str(),
            dumpInOutBuffer(false /* isInput */, mOutBuffer).c_str(),
            dumpInOutBuffer(false /* isInput */, mOutConversionBuffer).c_str());

    write(fd, result.c_str(), result.length());

    if (mEffectInterface != 0) {
        dprintf(fd, "\tEffect ID %d HAL dump:\n", mId);
        (void)mEffectInterface->dump(fd);
    }

    if (locked) {
        mutex().unlock();
    }
}

// ----------------------------------------------------------------------------
//  EffectHandle implementation
// ----------------------------------------------------------------------------

#undef LOG_TAG
#define LOG_TAG "EffectHandle"

/* static */
sp<IAfEffectHandle> IAfEffectHandle::create(
        const sp<IAfEffectBase>& effect,
        const sp<Client>& client,
        const sp<media::IEffectClient>& effectClient,
        int32_t priority, bool notifyFramesProcessed)
{
    return sp<EffectHandle>::make(
            effect, client, effectClient, priority, notifyFramesProcessed);
}

EffectHandle::EffectHandle(const sp<IAfEffectBase>& effect,
                                         const sp<Client>& client,
                                         const sp<media::IEffectClient>& effectClient,
                                         int32_t priority, bool notifyFramesProcessed)
    : BnEffect(),
    mEffect(effect), mEffectClient(effectClient), mClient(client), mCblk(NULL),
    mPriority(priority), mHasControl(false), mEnabled(false), mDisconnected(false),
    mNotifyFramesProcessed(notifyFramesProcessed)
{
    ALOGV("constructor %p client %p", this, client.get());
    setMinSchedulerPolicy(SCHED_NORMAL, ANDROID_PRIORITY_AUDIO);

    if (client == 0) {
        return;
    }
    int bufOffset = ((sizeof(effect_param_cblk_t) - 1) / sizeof(int) + 1) * sizeof(int);
    mCblkMemory = client->allocator().allocate(mediautils::NamedAllocRequest{
            {static_cast<size_t>(EFFECT_PARAM_BUFFER_SIZE + bufOffset)},
            std::string("Effect ID: ")
                    .append(std::to_string(effect->id()))
                    .append(" Session ID: ")
                    .append(std::to_string(static_cast<int>(effect->sessionId())))
                    .append(" \n")
            });
    if (mCblkMemory == 0 ||
            (mCblk = static_cast<effect_param_cblk_t *>(mCblkMemory->unsecurePointer())) == NULL) {
        ALOGE("not enough memory for Effect size=%zu", EFFECT_PARAM_BUFFER_SIZE +
                sizeof(effect_param_cblk_t));
        mCblkMemory.clear();
        return;
    }
    new(mCblk) effect_param_cblk_t();
    mBuffer = (uint8_t *)mCblk + bufOffset;
}

EffectHandle::~EffectHandle()
{
    ALOGV("Destructor %p", this);
    disconnect(false);
}

// Creates an association between Binder code to name for IEffect.
#define IEFFECT_BINDER_METHOD_MACRO_LIST \
BINDER_METHOD_ENTRY(enable) \
BINDER_METHOD_ENTRY(disable) \
BINDER_METHOD_ENTRY(command) \
BINDER_METHOD_ENTRY(disconnect) \
BINDER_METHOD_ENTRY(getCblk) \
BINDER_METHOD_ENTRY(getConfig) \

// singleton for Binder Method Statistics for IEffect
mediautils::MethodStatistics<int>& getIEffectStatistics() {
    using Code = int;

#pragma push_macro("BINDER_METHOD_ENTRY")
#undef BINDER_METHOD_ENTRY
#define BINDER_METHOD_ENTRY(ENTRY) \
        {(Code)media::BnEffect::TRANSACTION_##ENTRY, #ENTRY},

    static mediautils::MethodStatistics<Code> methodStatistics{
        IEFFECT_BINDER_METHOD_MACRO_LIST
        METHOD_STATISTICS_BINDER_CODE_NAMES(Code)
    };
#pragma pop_macro("BINDER_METHOD_ENTRY")

    return methodStatistics;
}

status_t EffectHandle::onTransact(
        uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
    const std::string methodName = getIEffectStatistics().getMethodForCode(code);
    mediautils::TimeCheck check(
            std::string("IEffect::").append(methodName),
            [code](bool timeout, float elapsedMs) {
        if (timeout) {
            ; // we don't timeout right now on the effect interface.
        } else {
            getIEffectStatistics().event(code, elapsedMs);
        }
    }, {} /* timeoutDuration */, {} /* secondChanceDuration */, false /* crashOnTimeout */);
    return BnEffect::onTransact(code, data, reply, flags);
}

status_t EffectHandle::initCheck() const
{
    return mClient == 0 || mCblkMemory != 0 ? OK : NO_MEMORY;
}

#define RETURN(code) \
  *_aidl_return = (code); \
  return Status::ok();

#define VALUE_OR_RETURN_STATUS_AS_OUT(exp)              \
    ({                                                  \
        auto _tmp = (exp);                              \
        if (!_tmp.ok()) { RETURN(_tmp.error()); }       \
        std::move(_tmp.value());                        \
    })

Status EffectHandle::enable(int32_t* _aidl_return)
{
    audio_utils::lock_guard _l(mutex());
    ALOGV("enable %p", this);
    sp<IAfEffectBase> effect = mEffect.promote();
    if (effect == 0 || mDisconnected) {
        RETURN(DEAD_OBJECT);
    }
    if (!mHasControl) {
        RETURN(INVALID_OPERATION);
    }

    if (mEnabled) {
        RETURN(NO_ERROR);
    }

    mEnabled = true;

    status_t status = effect->updatePolicyState();
    if (status != NO_ERROR) {
        mEnabled = false;
        RETURN(status);
    }

    effect->checkSuspendOnEffectEnabled(true, false /*threadLocked*/);

    // checkSuspendOnEffectEnabled() can suspend this same effect when enabled
    if (effect->suspended()) {
        RETURN(NO_ERROR);
    }

    status = effect->setEnabled(true, true /*fromHandle*/);
    if (status != NO_ERROR) {
        mEnabled = false;
    }
    RETURN(status);
}

Status EffectHandle::disable(int32_t* _aidl_return)
{
    ALOGV("disable %p", this);
    audio_utils::lock_guard _l(mutex());
    sp<IAfEffectBase> effect = mEffect.promote();
    if (effect == 0 || mDisconnected) {
        RETURN(DEAD_OBJECT);
    }
    if (!mHasControl) {
        RETURN(INVALID_OPERATION);
    }

    if (!mEnabled) {
        RETURN(NO_ERROR);
    }
    mEnabled = false;

    effect->updatePolicyState();

    if (effect->suspended()) {
        RETURN(NO_ERROR);
    }

    status_t status = effect->setEnabled(false, true /*fromHandle*/);
    RETURN(status);
}

Status EffectHandle::disconnect()
{
    ALOGV("%s %p", __FUNCTION__, this);
    disconnect(true);
    return Status::ok();
}

void EffectHandle::disconnect(bool unpinIfLast)
{
    audio_utils::lock_guard _l(mutex());
    ALOGV("disconnect(%s) %p", unpinIfLast ? "true" : "false", this);
    if (mDisconnected) {
        if (unpinIfLast) {
            android_errorWriteLog(0x534e4554, "32707507");
        }
        return;
    }
    mDisconnected = true;
    {
        sp<IAfEffectBase> effect = mEffect.promote();
        if (effect != 0) {
            if (effect->disconnectHandle(this, unpinIfLast) > 0) {
                ALOGW("%s Effect handle %p disconnected after thread destruction",
                    __func__, this);
            }
            effect->updatePolicyState();
        }
    }

    if (mClient != 0) {
        if (mCblk != NULL) {
            // unlike ~TrackBase(), mCblk is never a local new, so don't delete
            mCblk->~effect_param_cblk_t();   // destroy our shared-structure.
        }
        mCblkMemory.clear();    // free the shared memory before releasing the heap it belongs to
        // Client destructor must run with AudioFlinger client mutex locked
        audio_utils::lock_guard _l2(mClient->afClientCallback()->clientMutex());
        mClient.clear();
    }
}

Status EffectHandle::getCblk(media::SharedFileRegion* _aidl_return) {
    LOG_ALWAYS_FATAL_IF(!convertIMemoryToSharedFileRegion(mCblkMemory, _aidl_return));
    return Status::ok();
}

Status EffectHandle::getConfig(
        media::EffectConfig* _config, int32_t* _aidl_return) {
    audio_utils::lock_guard _l(mutex());
    sp<IAfEffectBase> effect = mEffect.promote();
    if (effect == nullptr || mDisconnected) {
        RETURN(DEAD_OBJECT);
    }
    sp<IAfEffectModule> effectModule = effect->asEffectModule();
    if (effectModule == nullptr) {
        RETURN(INVALID_OPERATION);
    }
    audio_config_base_t inputCfg = AUDIO_CONFIG_BASE_INITIALIZER;
    audio_config_base_t outputCfg = AUDIO_CONFIG_BASE_INITIALIZER;
    bool isOutput;
    status_t status = effectModule->getConfigs_l(&inputCfg, &outputCfg, &isOutput);
    if (status == NO_ERROR) {
        constexpr bool isInput = false; // effects always use 'OUT' channel masks.
        _config->inputCfg = VALUE_OR_RETURN_STATUS_AS_OUT(
                legacy2aidl_audio_config_base_t_AudioConfigBase(inputCfg, isInput));
        _config->outputCfg = VALUE_OR_RETURN_STATUS_AS_OUT(
                legacy2aidl_audio_config_base_t_AudioConfigBase(outputCfg, isInput));
        _config->isOnInputStream = !isOutput;
    }
    RETURN(status);
}

Status EffectHandle::command(int32_t cmdCode,
                       const std::vector<uint8_t>& cmdData,
                       int32_t maxResponseSize,
                       std::vector<uint8_t>* response,
                       int32_t* _aidl_return)
{
    ALOGVV("command(), cmdCode: %d, mHasControl: %d, mEffect: %p",
            cmdCode, mHasControl, mEffect.unsafe_get());

    // reject commands reserved for internal use by audio framework if coming from outside
    // of audioserver
    switch(cmdCode) {
        case EFFECT_CMD_ENABLE:
        case EFFECT_CMD_DISABLE:
        case EFFECT_CMD_SET_PARAM:
        case EFFECT_CMD_SET_PARAM_DEFERRED:
        case EFFECT_CMD_SET_PARAM_COMMIT:
        case EFFECT_CMD_GET_PARAM:
            break;
        default:
            if (cmdCode >= EFFECT_CMD_FIRST_PROPRIETARY) {
                break;
            }
            android_errorWriteLog(0x534e4554, "62019992");
            RETURN(BAD_VALUE);
    }

    if (cmdCode == EFFECT_CMD_ENABLE) {
        if (maxResponseSize < static_cast<signed>(sizeof(int))) {
            android_errorWriteLog(0x534e4554, "32095713");
            RETURN(BAD_VALUE);
        }
        writeToBuffer(NO_ERROR, response);
        return enable(_aidl_return);
    } else if (cmdCode == EFFECT_CMD_DISABLE) {
        if (maxResponseSize < static_cast<signed>(sizeof(int))) {
            android_errorWriteLog(0x534e4554, "32095713");
            RETURN(BAD_VALUE);
        }
        writeToBuffer(NO_ERROR, response);
        return disable(_aidl_return);
    }

    audio_utils::lock_guard _l(mutex());
    sp<IAfEffectBase> effect = mEffect.promote();
    if (effect == 0 || mDisconnected) {
        RETURN(DEAD_OBJECT);
    }
    // only get parameter command is permitted for applications not controlling the effect
    if (!mHasControl && cmdCode != EFFECT_CMD_GET_PARAM) {
        RETURN(INVALID_OPERATION);
    }

    // handle commands that are not forwarded transparently to effect engine
    if (cmdCode == EFFECT_CMD_SET_PARAM_COMMIT) {
        if (mClient == 0) {
            RETURN(INVALID_OPERATION);
        }

        if (maxResponseSize < (signed)sizeof(int)) {
            android_errorWriteLog(0x534e4554, "32095713");
            RETURN(BAD_VALUE);
        }
        writeToBuffer(NO_ERROR, response);

        // No need to trylock() here as this function is executed in the binder thread serving a
        // particular client process:  no risk to block the whole media server process or mixer
        // threads if we are stuck here
        Mutex::Autolock _l2(mCblk->lock);
        // keep local copy of index in case of client corruption b/32220769
        const uint32_t clientIndex = mCblk->clientIndex;
        const uint32_t serverIndex = mCblk->serverIndex;
        if (clientIndex > EFFECT_PARAM_BUFFER_SIZE ||
            serverIndex > EFFECT_PARAM_BUFFER_SIZE) {
            mCblk->serverIndex = 0;
            mCblk->clientIndex = 0;
            RETURN(BAD_VALUE);
        }
        status_t status = NO_ERROR;
        std::vector<uint8_t> param;
        for (uint32_t index = serverIndex; index < clientIndex;) {
            int *p = (int *)(mBuffer + index);
            const int size = *p++;
            if (size < 0
                    || size > EFFECT_PARAM_BUFFER_SIZE
                    || ((uint8_t *)p + size) > mBuffer + clientIndex) {
                ALOGW("command(): invalid parameter block size");
                status = BAD_VALUE;
                break;
            }

            std::copy(reinterpret_cast<const uint8_t*>(p),
                      reinterpret_cast<const uint8_t*>(p) + size,
                      std::back_inserter(param));

            std::vector<uint8_t> replyBuffer;
            status_t ret = effect->command(EFFECT_CMD_SET_PARAM,
                                            param,
                                            sizeof(int),
                                            &replyBuffer);
            int reply = *reinterpret_cast<const int*>(replyBuffer.data());

            // verify shared memory: server index shouldn't change; client index can't go back.
            if (serverIndex != mCblk->serverIndex
                    || clientIndex > mCblk->clientIndex) {
                android_errorWriteLog(0x534e4554, "32220769");
                status = BAD_VALUE;
                break;
            }

            // stop at first error encountered
            if (ret != NO_ERROR) {
                status = ret;
                writeToBuffer(reply, response);
                break;
            } else if (reply != NO_ERROR) {
                writeToBuffer(reply, response);
                break;
            }
            index += size;
        }
        mCblk->serverIndex = 0;
        mCblk->clientIndex = 0;
        RETURN(status);
    }

    status_t status = effect->command(cmdCode,
                                      cmdData,
                                      maxResponseSize,
                                      response);
    RETURN(status);
}

void EffectHandle::setControl(bool hasControl, bool signal, bool enabled)
{
    ALOGV("setControl %p control %d", this, hasControl);

    mHasControl = hasControl;
    mEnabled = enabled;

    if (signal && mEffectClient != 0) {
        mEffectClient->controlStatusChanged(hasControl);
    }
}

void EffectHandle::commandExecuted(uint32_t cmdCode,
                         const std::vector<uint8_t>& cmdData,
                         const std::vector<uint8_t>& replyData)
{
    if (mEffectClient != 0) {
        mEffectClient->commandExecuted(cmdCode, cmdData, replyData);
    }
}



void EffectHandle::setEnabled(bool enabled)
{
    if (mEffectClient != 0) {
        mEffectClient->enableStatusChanged(enabled);
    }
}

void EffectHandle::framesProcessed(int32_t frames) const
{
    if (mEffectClient != 0 && mNotifyFramesProcessed) {
        mEffectClient->framesProcessed(frames);
    }
}

void EffectHandle::dumpToBuffer(char* buffer, size_t size) const
NO_THREAD_SAFETY_ANALYSIS  // conditional try lock
{
    const bool locked = mCblk != nullptr && afutils::dumpTryLock(mCblk->lock);

    snprintf(buffer, size, "\t\t\t%5d    %5d  %3s    %3s  %5u  %5u\n",
            (mClient == 0) ? getpid() : mClient->pid(),
            mPriority,
            mHasControl ? "yes" : "no",
            locked ? "yes" : "no",
            mCblk ? mCblk->clientIndex : 0,
            mCblk ? mCblk->serverIndex : 0
            );

    if (locked) {
        mCblk->lock.unlock();
    }
}

#undef LOG_TAG
#define LOG_TAG "EffectChain"

/* static */
sp<IAfEffectChain> IAfEffectChain::create(
        const sp<IAfThreadBase>& thread,
        audio_session_t sessionId)
{
    return sp<EffectChain>::make(thread, sessionId);
}

EffectChain::EffectChain(const sp<IAfThreadBase>& thread,
                                       audio_session_t sessionId)
    : mSessionId(sessionId), mActiveTrackCnt(0), mTrackCnt(0), mTailBufferCount(0),
      mLeftVolume(UINT_MAX), mRightVolume(UINT_MAX),
      mNewLeftVolume(UINT_MAX), mNewRightVolume(UINT_MAX),
      mEffectCallback(new EffectCallback(wp<EffectChain>(this), thread))
{
    mStrategy = thread->getStrategyForStream(AUDIO_STREAM_MUSIC);
    mMaxTailBuffers = ((kProcessTailDurationMs * thread->sampleRate()) / 1000) /
                                    thread->frameCount();
}

// getEffectFromDesc_l() must be called with IAfThreadBase::mutex() held
sp<IAfEffectModule> EffectChain::getEffectFromDesc_l(
        effect_descriptor_t *descriptor) const
{
    size_t size = mEffects.size();

    for (size_t i = 0; i < size; i++) {
        if (memcmp(&mEffects[i]->desc().uuid, &descriptor->uuid, sizeof(effect_uuid_t)) == 0) {
            return mEffects[i];
        }
    }
    return 0;
}

// getEffectFromId_l() must be called with IAfThreadBase::mutex() held
sp<IAfEffectModule> EffectChain::getEffectFromId_l(int id) const
{
    size_t size = mEffects.size();

    for (size_t i = 0; i < size; i++) {
        // by convention, return first effect if id provided is 0 (0 is never a valid id)
        if (id == 0 || mEffects[i]->id() == id) {
            return mEffects[i];
        }
    }
    return 0;
}

// getEffectFromType_l() must be called with IAfThreadBase::mutex() held
sp<IAfEffectModule> EffectChain::getEffectFromType_l(
        const effect_uuid_t *type) const
{
    size_t size = mEffects.size();

    for (size_t i = 0; i < size; i++) {
        if (memcmp(&mEffects[i]->desc().type, type, sizeof(effect_uuid_t)) == 0) {
            return mEffects[i];
        }
    }
    return 0;
}

std::vector<int> EffectChain::getEffectIds_l() const
{
    std::vector<int> ids;
    audio_utils::lock_guard _l(mutex());
    for (size_t i = 0; i < mEffects.size(); i++) {
        ids.push_back(mEffects[i]->id());
    }
    return ids;
}

void EffectChain::clearInputBuffer()
{
    audio_utils::lock_guard _l(mutex());
    clearInputBuffer_l();
}

// Must be called with EffectChain::mutex() locked
void EffectChain::clearInputBuffer_l()
{
    if (mInBuffer == NULL) {
        return;
    }
    const size_t frameSize = audio_bytes_per_sample(AUDIO_FORMAT_PCM_FLOAT)
            * mEffectCallback->inChannelCount(mEffects[0]->id());

    memset(mInBuffer->audioBuffer()->raw, 0, mEffectCallback->frameCount() * frameSize);
    mInBuffer->commit();
}

// Must be called with EffectChain::mutex() locked
void EffectChain::process_l() {
    // never process effects when:
    // - on an OFFLOAD thread
    // - no more tracks are on the session and the effect tail has been rendered
    bool doProcess = !mEffectCallback->isOffloadOrMmap();
    if (!audio_is_global_session(mSessionId)) {
        bool tracksOnSession = (trackCnt() != 0);

        if (!tracksOnSession && mTailBufferCount == 0) {
            doProcess = false;
        }

        if (activeTrackCnt() == 0) {
            // if no track is active and the effect tail has not been rendered,
            // the input buffer must be cleared here as the mixer process will not do it
            if (tracksOnSession || mTailBufferCount > 0) {
                clearInputBuffer_l();
                if (mTailBufferCount > 0) {
                    mTailBufferCount--;
                }
            }
        }
    }

    size_t size = mEffects.size();
    if (doProcess) {
        // Only the input and output buffers of the chain can be external,
        // and 'update' / 'commit' do nothing for allocated buffers, thus
        // it's not needed to consider any other buffers here.
        mInBuffer->update();
        if (mInBuffer->audioBuffer()->raw != mOutBuffer->audioBuffer()->raw) {
            mOutBuffer->update();
        }
        for (size_t i = 0; i < size; i++) {
            mEffects[i]->process();
        }
        mInBuffer->commit();
        if (mInBuffer->audioBuffer()->raw != mOutBuffer->audioBuffer()->raw) {
            mOutBuffer->commit();
        }
    }
    bool doResetVolume = false;
    for (size_t i = 0; i < size; i++) {
        doResetVolume = mEffects[i]->updateState_l() || doResetVolume;
    }
    if (doResetVolume) {
        resetVolume_l();
    }
}

// createEffect_l() must be called with IAfThreadBase::mutex() held
status_t EffectChain::createEffect_l(sp<IAfEffectModule>& effect,
                                                   effect_descriptor_t *desc,
                                                   int id,
                                                   audio_session_t sessionId,
                                                   bool pinned)
{
    audio_utils::lock_guard _l(mutex());
    effect = new EffectModule(mEffectCallback, desc, id, sessionId, pinned, AUDIO_PORT_HANDLE_NONE);
    status_t lStatus = effect->status();
    if (lStatus == NO_ERROR) {
        lStatus = addEffect_ll(effect);
    }
    if (lStatus != NO_ERROR) {
        effect.clear();
    }
    return lStatus;
}

// addEffect_l() must be called with IAfThreadBase::mutex() held
status_t EffectChain::addEffect_l(const sp<IAfEffectModule>& effect)
{
    audio_utils::lock_guard _l(mutex());
    return addEffect_ll(effect);
}
// addEffect_l() must be called with IAfThreadBase::mutex() and EffectChain::mutex() held
status_t EffectChain::addEffect_ll(const sp<IAfEffectModule>& effect)
{
    effect->setCallback(mEffectCallback);

    effect_descriptor_t desc = effect->desc();
    if ((desc.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_AUXILIARY) {
        // Auxiliary effects are inserted at the beginning of mEffects vector as
        // they are processed first and accumulated in chain input buffer
        mEffects.insertAt(effect, 0);

        // the input buffer for auxiliary effect contains mono samples in
        // 32 bit format. This is to avoid saturation in AudoMixer
        // accumulation stage. Saturation is done in EffectModule::process() before
        // calling the process in effect engine
        size_t numSamples = mEffectCallback->frameCount();
        sp<EffectBufferHalInterface> halBuffer;

        status_t result = mEffectCallback->allocateHalBuffer(
                numSamples * sizeof(float), &halBuffer);
        if (result != OK) return result;

        effect->configure_l();

        effect->setInBuffer(halBuffer);
        // auxiliary effects output samples to chain input buffer for further processing
        // by insert effects
        effect->setOutBuffer(mInBuffer);
    } else {
        ssize_t idx_insert = getInsertIndex_ll(desc);
        if (idx_insert < 0) {
            return INVALID_OPERATION;
        }

        size_t previousSize = mEffects.size();
        mEffects.insertAt(effect, idx_insert);

        effect->configure_l();

        // - By default:
        //   All effects read samples from chain input buffer.
        //   The last effect in the chain, writes samples to chain output buffer,
        //   otherwise to chain input buffer
        // - In the OUTPUT_STAGE chain of a spatializer mixer thread:
        //   The spatializer effect (first effect) reads samples from the input buffer
        //   and writes samples to the output buffer.
        //   All other effects read and writes samples to the output buffer
        if (mEffectCallback->isSpatializer()
                && mSessionId == AUDIO_SESSION_OUTPUT_STAGE) {
            effect->setOutBuffer(mOutBuffer);
            if (idx_insert == 0) {
                if (previousSize != 0) {
                    mEffects[1]->configure_l();
                    mEffects[1]->setInBuffer(mOutBuffer);
                    mEffects[1]->updateAccessMode_l();  // reconfig if needed.
                }
                effect->setInBuffer(mInBuffer);
            } else {
                effect->setInBuffer(mOutBuffer);
            }
        } else {
            effect->setInBuffer(mInBuffer);
            if (idx_insert == static_cast<ssize_t>(previousSize)) {
                if (idx_insert != 0) {
                    mEffects[idx_insert-1]->configure_l();
                    mEffects[idx_insert-1]->setOutBuffer(mInBuffer);
                    mEffects[idx_insert - 1]->updateAccessMode_l();  // reconfig if needed.
                }
                effect->setOutBuffer(mOutBuffer);
            } else {
                effect->setOutBuffer(mInBuffer);
            }
        }
        ALOGV("%s effect %p, added in chain %p at rank %zu",
                __func__, effect.get(), this, idx_insert);
    }
    effect->configure_l();

    return NO_ERROR;
}

std::optional<size_t> EffectChain::findVolumeControl_l(size_t from, size_t to) const {
    for (size_t i = std::min(to, mEffects.size()); i > from; i--) {
        if (mEffects[i - 1]->isVolumeControlEnabled_l()) {
            return i - 1;
        }
    }
    return std::nullopt;
}

ssize_t EffectChain::getInsertIndex_ll(const effect_descriptor_t& desc) {
    // Insert effects are inserted at the end of mEffects vector as they are processed
    //  after track and auxiliary effects.
    // Insert effect order as a function of indicated preference:
    //  if EFFECT_FLAG_INSERT_EXCLUSIVE, insert in first position or reject if
    //  another effect is present
    //  else if EFFECT_FLAG_INSERT_FIRST, insert in first position or after the
    //  last effect claiming first position
    //  else if EFFECT_FLAG_INSERT_LAST, insert in last position or before the
    //  first effect claiming last position
    //  else if EFFECT_FLAG_INSERT_ANY insert after first or before last
    // Reject insertion if an effect with EFFECT_FLAG_INSERT_EXCLUSIVE is
    // already present
    // Spatializer or Downmixer effects are inserted in first position because
    // they adapt the channel count for all other effects in the chain
    if (IAfEffectModule::isSpatializer(&desc.type)
            || (memcmp(&desc.type, EFFECT_UIID_DOWNMIX, sizeof(effect_uuid_t)) == 0)) {
        return 0;
    }

    size_t size = mEffects.size();
    uint32_t insertPref = desc.flags & EFFECT_FLAG_INSERT_MASK;
    ssize_t idx_insert;
    ssize_t idx_insert_first = -1;
    ssize_t idx_insert_last = -1;

    idx_insert = size;
    for (size_t i = 0; i < size; i++) {
        effect_descriptor_t d = mEffects[i]->desc();
        uint32_t iMode = d.flags & EFFECT_FLAG_TYPE_MASK;
        uint32_t iPref = d.flags & EFFECT_FLAG_INSERT_MASK;
        if (iMode == EFFECT_FLAG_TYPE_INSERT) {
            // check invalid effect chaining combinations
            if (insertPref == EFFECT_FLAG_INSERT_EXCLUSIVE ||
                iPref == EFFECT_FLAG_INSERT_EXCLUSIVE) {
                ALOGW("%s could not insert effect %s: exclusive conflict with %s",
                        __func__, desc.name, d.name);
                return -1;
            }
            // remember position of first insert effect and by default
            // select this as insert position for new effect
            if (idx_insert == static_cast<ssize_t>(size)) {
                idx_insert = i;
            }
            // remember position of last insert effect claiming
            // first position
            if (iPref == EFFECT_FLAG_INSERT_FIRST) {
                idx_insert_first = i;
            }
            // remember position of first insert effect claiming
            // last position
            if (iPref == EFFECT_FLAG_INSERT_LAST &&
                idx_insert_last == -1) {
                idx_insert_last = i;
            }
        }
    }

    // modify idx_insert from first position if needed
    if (insertPref == EFFECT_FLAG_INSERT_LAST) {
        if (idx_insert_last != -1) {
            idx_insert = idx_insert_last;
        } else {
            idx_insert = size;
        }
    } else {
        if (idx_insert_first != -1) {
            idx_insert = idx_insert_first + 1;
        }
    }
    return idx_insert;
}

// removeEffect_l() must be called with IAfThreadBase::mutex() held
size_t EffectChain::removeEffect_l(const sp<IAfEffectModule>& effect,
                                                 bool release)
{
    audio_utils::lock_guard _l(mutex());
    size_t size = mEffects.size();
    uint32_t type = effect->desc().flags & EFFECT_FLAG_TYPE_MASK;

    for (size_t i = 0; i < size; i++) {
        if (effect == mEffects[i]) {
            // calling stop here will remove pre-processing effect from the audio HAL.
            // This is safe as we hold the EffectChain mutex which guarantees that we are not in
            // the middle of a read from audio HAL
            if (mEffects[i]->state() == EffectModule::ACTIVE ||
                    mEffects[i]->state() == EffectModule::STOPPING) {
                mEffects[i]->stop_l();
            }
            if (release) {
                mEffects[i]->release_l();
            }

            if (type != EFFECT_FLAG_TYPE_AUXILIARY) {
                if (i == size - 1 && i != 0) {
                    mEffects[i - 1]->configure_l();
                    mEffects[i - 1]->setOutBuffer(mOutBuffer);
                    mEffects[i - 1]->updateAccessMode_l();      // reconfig if needed.
                }
            }
            mEffects.removeAt(i);

            // make sure the input buffer configuration for the new first effect in the chain
            // is updated if needed (can switch from HAL channel mask to mixer channel mask)
            if (type != EFFECT_FLAG_TYPE_AUXILIARY // TODO(b/284522658) breaks for aux FX, why?
                    && i == 0 && size > 1) {
                mEffects[0]->configure_l();
                mEffects[0]->setInBuffer(mInBuffer);
                mEffects[0]->updateAccessMode_l();      // reconfig if needed.
            }

            ALOGV("removeEffect_l() effect %p, removed from chain %p at rank %zu", effect.get(),
                    this, i);
            break;
        }
    }

    return mEffects.size();
}

// setDevices_l() must be called with IAfThreadBase::mutex() held
void EffectChain::setDevices_l(const AudioDeviceTypeAddrVector &devices)
{
    size_t size = mEffects.size();
    for (size_t i = 0; i < size; i++) {
        mEffects[i]->setDevices(devices);
    }
}

// setInputDevice_l() must be called with IAfThreadBase::mutex() held
void EffectChain::setInputDevice_l(const AudioDeviceTypeAddr &device)
{
    size_t size = mEffects.size();
    for (size_t i = 0; i < size; i++) {
        mEffects[i]->setInputDevice(device);
    }
}

// setMode_l() must be called with IAfThreadBase::mutex() held
void EffectChain::setMode_l(audio_mode_t mode)
{
    size_t size = mEffects.size();
    for (size_t i = 0; i < size; i++) {
        mEffects[i]->setMode(mode);
    }
}

// setAudioSource_l() must be called with IAfThreadBase::mutex() held
void EffectChain::setAudioSource_l(audio_source_t source)
{
    size_t size = mEffects.size();
    for (size_t i = 0; i < size; i++) {
        mEffects[i]->setAudioSource(source);
    }
}

bool EffectChain::hasVolumeControlEnabled_l() const {
    for (const auto &effect : mEffects) {
        if (effect->isVolumeControlEnabled_l()) return true;
    }
    return false;
}

// setVolume() must be called without EffectChain::mutex()
bool EffectChain::setVolume(uint32_t* left, uint32_t* right, bool force) {
    audio_utils::lock_guard _l(mutex());
    return setVolume_l(left, right, force);
}

// setVolume_l() must be called with EffectChain::mutex() held
bool EffectChain::setVolume_l(uint32_t* left, uint32_t* right, bool force) {
    uint32_t newLeft = *left;
    uint32_t newRight = *right;
    const size_t size = mEffects.size();

    // first update volume controller
    const auto volumeControlIndex = findVolumeControl_l(0, size);
    const int ctrlIdx = volumeControlIndex.value_or(-1);
    const sp<IAfEffectModule> volumeControlEffect =
            volumeControlIndex.has_value() ? mEffects[ctrlIdx] : nullptr;
    const sp<IAfEffectModule> cachedVolumeControlEffect = mVolumeControlEffect.promote();

    if (!force && volumeControlEffect == cachedVolumeControlEffect &&
            *left == mLeftVolume && *right == mRightVolume) {
        if (volumeControlIndex.has_value()) {
            *left = mNewLeftVolume;
            *right = mNewRightVolume;
        }
        return volumeControlIndex.has_value();
    }

    if (volumeControlEffect != cachedVolumeControlEffect) {
        // The volume control effect is a new one. Set the old one as full volume. Set the new onw
        // as zero for safe ramping.
        if (cachedVolumeControlEffect != nullptr) {
            uint32_t leftMax = 1 << 24;
            uint32_t rightMax = 1 << 24;
            cachedVolumeControlEffect->setVolume(&leftMax, &rightMax, true /*controller*/);
        }
        if (volumeControlEffect != nullptr) {
            uint32_t leftZero = 0;
            uint32_t rightZero = 0;
            volumeControlEffect->setVolume(&leftZero, &rightZero, true /*controller*/);
        }
        mVolumeControlEffect = volumeControlEffect;
    }
    mLeftVolume = newLeft;
    mRightVolume = newRight;

    // second get volume update from volume controller
    if (ctrlIdx >= 0) {
        mEffects[ctrlIdx]->setVolume(&newLeft, &newRight, true);
        mNewLeftVolume = newLeft;
        mNewRightVolume = newRight;
    }
    // then indicate volume to all other effects in chain.
    // Pass altered volume to effects before volume controller
    // and requested volume to effects after controller or with volume monitor flag
    uint32_t lVol = newLeft;
    uint32_t rVol = newRight;

    for (size_t i = 0; i < size; i++) {
        if ((int)i == ctrlIdx) {
            continue;
        }
        // this also works for ctrlIdx == -1 when there is no volume controller
        if ((int)i > ctrlIdx) {
            lVol = *left;
            rVol = *right;
        }
        // Pass requested volume directly if this is volume monitor module
        if (mEffects[i]->isVolumeMonitor()) {
            mEffects[i]->setVolume(left, right, false);
        } else {
            mEffects[i]->setVolume(&lVol, &rVol, false);
        }
    }
    *left = newLeft;
    *right = newRight;

    setVolumeForOutput_l(*left, *right);

    return volumeControlIndex.has_value();
}

// resetVolume_l() must be called with EffectChain::mutex() held
void EffectChain::resetVolume_l()
{
    if ((mLeftVolume != UINT_MAX) && (mRightVolume != UINT_MAX)) {
        uint32_t left = mLeftVolume;
        uint32_t right = mRightVolume;
        (void)setVolume_l(&left, &right, true);
    }
}

// containsHapticGeneratingEffect_l must be called with
// IAfThreadBase::mutex() or EffectChain::mutex() held
bool EffectChain::containsHapticGeneratingEffect_l()
{
    for (size_t i = 0; i < mEffects.size(); ++i) {
        if (mEffects[i]->isHapticGenerator()) {
            return true;
        }
    }
    return false;
}

void EffectChain::setHapticScale_l(int id, os::HapticScale hapticScale)
{
    audio_utils::lock_guard _l(mutex());
    for (size_t i = 0; i < mEffects.size(); ++i) {
        mEffects[i]->setHapticScale_l(id, hapticScale);
    }
}

void EffectChain::syncHalEffectsState_l()
{
    audio_utils::lock_guard _l(mutex());
    for (size_t i = 0; i < mEffects.size(); i++) {
        if (mEffects[i]->state() == EffectModule::ACTIVE ||
                mEffects[i]->state() == EffectModule::STOPPING) {
            mEffects[i]->addEffectToHal_l();
        }
    }
}

void EffectChain::dump(int fd, const Vector<String16>& args) const
NO_THREAD_SAFETY_ANALYSIS  // conditional try lock
{
    String8 result;

    const size_t numEffects = mEffects.size();
    result.appendFormat("    %zu effects for session %d\n", numEffects, mSessionId);

    if (numEffects) {
        const bool locked = afutils::dumpTryLock(mutex());
        // failed to lock - AudioFlinger is probably deadlocked
        if (!locked) {
            result.append("\tCould not lock mutex:\n");
        }

        const std::string inBufferStr = dumpInOutBuffer(true /* isInput */, mInBuffer);
        const std::string outBufferStr = dumpInOutBuffer(false /* isInput */, mOutBuffer);
        result.appendFormat("\t%-*s%-*s   Active tracks:\n",
                (int)inBufferStr.size(), "In buffer    ",
                (int)outBufferStr.size(), "Out buffer      ");
        result.appendFormat("\t%s   %s   %d\n",
                inBufferStr.c_str(), outBufferStr.c_str(), mActiveTrackCnt);
        write(fd, result.c_str(), result.size());

        for (size_t i = 0; i < numEffects; ++i) {
            sp<IAfEffectModule> effect = mEffects[i];
            if (effect != 0) {
                effect->dump(fd, args);
            }
        }

        if (locked) {
            mutex().unlock();
        }
    } else {
        write(fd, result.c_str(), result.size());
    }
}

// must be called with IAfThreadBase::mutex() held
void EffectChain::setEffectSuspended_l(
        const effect_uuid_t *type, bool suspend)
{
    sp<SuspendedEffectDesc> desc;
    // use effect type UUID timelow as key as there is no real risk of identical
    // timeLow fields among effect type UUIDs.
    ssize_t index = mSuspendedEffects.indexOfKey(type->timeLow);
    if (suspend) {
        if (index >= 0) {
            desc = mSuspendedEffects.valueAt(index);
        } else {
            desc = new SuspendedEffectDesc();
            desc->mType = *type;
            mSuspendedEffects.add(type->timeLow, desc);
            ALOGV("setEffectSuspended_l() add entry for %08x", type->timeLow);
        }

        if (desc->mRefCount++ == 0) {
            sp<IAfEffectModule> effect = getEffectIfEnabled_l(type);
            if (effect != 0) {
                desc->mEffect = effect;
                effect->setSuspended(true);
                effect->setEnabled(false, false /*fromHandle*/);
            }
        }
    } else {
        if (index < 0) {
            return;
        }
        desc = mSuspendedEffects.valueAt(index);
        if (desc->mRefCount <= 0) {
            ALOGW("setEffectSuspended_l() restore refcount should not be 0 %d", desc->mRefCount);
            desc->mRefCount = 0;
            return;
        }
        if (--desc->mRefCount == 0) {
            ALOGV("setEffectSuspended_l() remove entry for %08x", mSuspendedEffects.keyAt(index));
            if (desc->mEffect != 0) {
                sp<IAfEffectModule> effect = desc->mEffect.promote();
                if (effect != 0) {
                    effect->setSuspended(false);
                    effect->mutex().lock();
                    IAfEffectHandle *handle = effect->controlHandle_l();
                    if (handle != NULL && !handle->disconnected()) {
                        effect->setEnabled_l(handle->enabled());
                    }
                    effect->mutex().unlock();
                }
                desc->mEffect.clear();
            }
            mSuspendedEffects.removeItemsAt(index);
        }
    }
}

// must be called with IAfThreadBase::mutex() held
void EffectChain::setEffectSuspendedAll_l(bool suspend)
{
    sp<SuspendedEffectDesc> desc;

    ssize_t index = mSuspendedEffects.indexOfKey((int)kKeyForSuspendAll);
    if (suspend) {
        if (index >= 0) {
            desc = mSuspendedEffects.valueAt(index);
        } else {
            desc = new SuspendedEffectDesc();
            mSuspendedEffects.add((int)kKeyForSuspendAll, desc);
            ALOGV("setEffectSuspendedAll_l() add entry for 0");
        }
        if (desc->mRefCount++ == 0) {
            Vector< sp<IAfEffectModule> > effects;
            getSuspendEligibleEffects_l(effects);
            for (size_t i = 0; i < effects.size(); i++) {
                setEffectSuspended_l(&effects[i]->desc().type, true);
            }
        }
    } else {
        if (index < 0) {
            return;
        }
        desc = mSuspendedEffects.valueAt(index);
        if (desc->mRefCount <= 0) {
            ALOGW("setEffectSuspendedAll_l() restore refcount should not be 0 %d", desc->mRefCount);
            desc->mRefCount = 1;
        }
        if (--desc->mRefCount == 0) {
            Vector<const effect_uuid_t *> types;
            for (size_t i = 0; i < mSuspendedEffects.size(); i++) {
                if (mSuspendedEffects.keyAt(i) == (int)kKeyForSuspendAll) {
                    continue;
                }
                types.add(&mSuspendedEffects.valueAt(i)->mType);
            }
            for (size_t i = 0; i < types.size(); i++) {
                setEffectSuspended_l(types[i], false);
            }
            ALOGV("setEffectSuspendedAll_l() remove entry for %08x",
                    mSuspendedEffects.keyAt(index));
            mSuspendedEffects.removeItem((int)kKeyForSuspendAll);
        }
    }
}


// The volume effect is used for automated tests only
#ifndef OPENSL_ES_H_
static const effect_uuid_t SL_IID_VOLUME_ = { 0x09e8ede0, 0xddde, 0x11db, 0xb4f6,
                                            { 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b } };
const effect_uuid_t * const SL_IID_VOLUME = &SL_IID_VOLUME_;
#endif //OPENSL_ES_H_

/* static */
bool EffectChain::isEffectEligibleForBtNrecSuspend_l(const effect_uuid_t* type) {
    // Only NS and AEC are suspended when BtNRec is off
    if ((memcmp(type, FX_IID_AEC, sizeof(effect_uuid_t)) == 0) ||
        (memcmp(type, FX_IID_NS, sizeof(effect_uuid_t)) == 0)) {
        return true;
    }
    return false;
}

bool EffectChain::isEffectEligibleForSuspend_l(const effect_descriptor_t& desc)
{
    // auxiliary effects and visualizer are never suspended on output mix
    if ((mSessionId == AUDIO_SESSION_OUTPUT_MIX) &&
        (((desc.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_AUXILIARY) ||
         (memcmp(&desc.type, SL_IID_VISUALIZATION, sizeof(effect_uuid_t)) == 0) ||
         (memcmp(&desc.type, SL_IID_VOLUME, sizeof(effect_uuid_t)) == 0) ||
         (memcmp(&desc.type, SL_IID_DYNAMICSPROCESSING, sizeof(effect_uuid_t)) == 0))) {
        return false;
    }
    return true;
}

void EffectChain::getSuspendEligibleEffects_l(
        Vector< sp<IAfEffectModule> > &effects)
{
    effects.clear();
    for (size_t i = 0; i < mEffects.size(); i++) {
        if (isEffectEligibleForSuspend_l(mEffects[i]->desc())) {
            effects.add(mEffects[i]);
        }
    }
}

sp<IAfEffectModule> EffectChain::getEffectIfEnabled_l(const effect_uuid_t *type)
{
    sp<IAfEffectModule> effect = getEffectFromType_l(type);
    return effect != 0 && effect->isEnabled() ? effect : 0;
}

void EffectChain::checkSuspendOnEffectEnabled_l(const sp<IAfEffectModule>& effect, bool enabled) {
    ssize_t index = mSuspendedEffects.indexOfKey(effect->desc().type.timeLow);
    if (enabled) {
        if (index < 0) {
            // if the effect is not suspend check if all effects are suspended
            index = mSuspendedEffects.indexOfKey((int)kKeyForSuspendAll);
            if (index < 0) {
                return;
            }
            if (!isEffectEligibleForSuspend_l(effect->desc())) {
                return;
            }
            setEffectSuspended_l(&effect->desc().type, enabled);
            index = mSuspendedEffects.indexOfKey(effect->desc().type.timeLow);
            if (index < 0) {
                ALOGW("%s Fx should be suspended here!", __func__);
                return;
            }
        }
        ALOGV("%s enable suspending fx %08x", __func__, effect->desc().type.timeLow);
        sp<SuspendedEffectDesc> desc = mSuspendedEffects.valueAt(index);
        // if effect is requested to suspended but was not yet enabled, suspend it now.
        if (desc->mEffect == 0) {
            desc->mEffect = effect;
            effect->setEnabled(false, false /*fromHandle*/);
            effect->setSuspended(true);
        }
    } else {
        if (index < 0) {
            return;
        }
        ALOGV("%s disable restoring fx %08x", __func__, effect->desc().type.timeLow);
        sp<SuspendedEffectDesc> desc = mSuspendedEffects.valueAt(index);
        desc->mEffect.clear();
        effect->setSuspended(false);
    }
}

bool EffectChain::isNonOffloadableEnabled() const
{
    audio_utils::lock_guard _l(mutex());
    return isNonOffloadableEnabled_l();
}

bool EffectChain::isNonOffloadableEnabled_l() const
{
    size_t size = mEffects.size();
    for (size_t i = 0; i < size; i++) {
        if (mEffects[i]->isEnabled() && !mEffects[i]->isOffloadable()) {
            return true;
        }
    }
    return false;
}

void EffectChain::setThread(const sp<IAfThreadBase>& thread)
{
    audio_utils::lock_guard _l(mutex());
    mEffectCallback->setThread(thread);
}

void EffectChain::checkOutputFlagCompatibility(audio_output_flags_t *flags) const
{
    if ((*flags & AUDIO_OUTPUT_FLAG_RAW) != 0 && !isRawCompatible()) {
        *flags = (audio_output_flags_t)(*flags & ~AUDIO_OUTPUT_FLAG_RAW);
    }
    if ((*flags & AUDIO_OUTPUT_FLAG_FAST) != 0 && !isFastCompatible()) {
        *flags = (audio_output_flags_t)(*flags & ~AUDIO_OUTPUT_FLAG_FAST);
    }
    if ((*flags & AUDIO_OUTPUT_FLAG_BIT_PERFECT) != 0 && !isBitPerfectCompatible()) {
        *flags = (audio_output_flags_t)(*flags & ~AUDIO_OUTPUT_FLAG_BIT_PERFECT);
    }
}

void EffectChain::checkInputFlagCompatibility(audio_input_flags_t *flags) const
{
    if ((*flags & AUDIO_INPUT_FLAG_RAW) != 0 && !isRawCompatible()) {
        *flags = (audio_input_flags_t)(*flags & ~AUDIO_INPUT_FLAG_RAW);
    }
    if ((*flags & AUDIO_INPUT_FLAG_FAST) != 0 && !isFastCompatible()) {
        *flags = (audio_input_flags_t)(*flags & ~AUDIO_INPUT_FLAG_FAST);
    }
}

bool EffectChain::isRawCompatible() const
{
    audio_utils::lock_guard _l(mutex());
    for (const auto &effect : mEffects) {
        if (effect->isProcessImplemented()) {
            return false;
        }
    }
    // Allow effects without processing.
    return true;
}

bool EffectChain::isFastCompatible() const
{
    audio_utils::lock_guard _l(mutex());
    for (const auto &effect : mEffects) {
        if (effect->isProcessImplemented()
                && effect->isImplementationSoftware()) {
            return false;
        }
    }
    // Allow effects without processing or hw accelerated effects.
    return true;
}

bool EffectChain::isBitPerfectCompatible() const {
    audio_utils::lock_guard _l(mutex());
    for (const auto &effect : mEffects) {
        if (effect->isProcessImplemented()
                && effect->isImplementationSoftware()) {
            return false;
        }
    }
    // Allow effects without processing or hw accelerated effects.
    return true;
}

// isCompatibleWithThread_l() must be called with thread->mutex() held
bool EffectChain::isCompatibleWithThread_l(const sp<IAfThreadBase>& thread) const
{
    audio_utils::lock_guard _l(mutex());
    for (size_t i = 0; i < mEffects.size(); i++) {
        if (thread->checkEffectCompatibility_l(&(mEffects[i]->desc()), mSessionId) != NO_ERROR) {
            return false;
        }
    }
    return true;
}

// sendMetadata_l() must be called with thread->mutex() held
void EffectChain::sendMetadata_l(const std::vector<playback_track_metadata_v7_t>& allMetadata,
        const std::optional<const std::vector<playback_track_metadata_v7_t>> spatializedMetadata) {
    audio_utils::lock_guard _l(mutex());
    for (const auto& effect : mEffects) {
        if (spatializedMetadata.has_value()
                && IAfEffectModule::isSpatializer(&effect->desc().type)) {
            effect->sendMetadata_ll(spatializedMetadata.value());
        } else {
            effect->sendMetadata_ll(allMetadata);
        }
    }
}

// EffectCallbackInterface implementation
status_t EffectChain::EffectCallback::createEffectHal(
        const effect_uuid_t *pEffectUuid, int32_t sessionId, int32_t deviceId,
        sp<EffectHalInterface> *effect) {
    status_t status = NO_INIT;
    const sp<EffectsFactoryHalInterface> effectsFactory =
            EffectConfiguration::getEffectsFactoryHal();
    if (effectsFactory != 0) {
        status = effectsFactory->createEffect(pEffectUuid, sessionId, io(), deviceId, effect);
    }
    return status;
}

bool EffectChain::EffectCallback::updateOrphanEffectChains(
        const sp<IAfEffectBase>& effect) {
    // in EffectChain context, an EffectBase is always from an EffectModule so static cast is safe
    return mAfThreadCallback->updateOrphanEffectChains(effect->asEffectModule());
}

status_t EffectChain::EffectCallback::allocateHalBuffer(
        size_t size, sp<EffectBufferHalInterface>* buffer) {
    return mAfThreadCallback->getEffectsFactoryHal()->allocateBuffer(size, buffer);
}

status_t EffectChain::EffectCallback::addEffectToHal(
        const sp<EffectHalInterface>& effect) {
    status_t result = NO_INIT;
    const sp<IAfThreadBase> t = thread().promote();
    if (t == nullptr) {
        return result;
    }
    sp <StreamHalInterface> st = t->stream();
    if (st == nullptr) {
        return result;
    }
    result = st->addEffect(effect);
    ALOGE_IF(result != OK, "Error when adding effect: %d", result);
    return result;
}

status_t EffectChain::EffectCallback::removeEffectFromHal(
        const sp<EffectHalInterface>& effect) {
    status_t result = NO_INIT;
    const sp<IAfThreadBase> t = thread().promote();
    if (t == nullptr) {
        return result;
    }
    sp <StreamHalInterface> st = t->stream();
    if (st == nullptr) {
        return result;
    }
    result = st->removeEffect(effect);
    ALOGE_IF(result != OK, "Error when removing effect: %d", result);
    return result;
}

audio_io_handle_t EffectChain::EffectCallback::io() const {
    const sp<IAfThreadBase> t = thread().promote();
    if (t == nullptr) {
        return AUDIO_IO_HANDLE_NONE;
    }
    return t->id();
}

bool EffectChain::EffectCallback::isOutput() const {
    const sp<IAfThreadBase> t = thread().promote();
    if (t == nullptr) {
        return true;
    }
    return t->isOutput();
}

bool EffectChain::EffectCallback::isOffload() const {
    return mThreadType == IAfThreadBase::OFFLOAD;
}

bool EffectChain::EffectCallback::isOffloadOrDirect() const {
    return mThreadType == IAfThreadBase::OFFLOAD
            || mThreadType == IAfThreadBase::DIRECT;
}

bool EffectChain::EffectCallback::isOffloadOrMmap() const {
    switch (mThreadType) {
    case IAfThreadBase::OFFLOAD:
    case IAfThreadBase::MMAP_PLAYBACK:
    case IAfThreadBase::MMAP_CAPTURE:
        return true;
    default:
        return false;
    }
}

bool EffectChain::EffectCallback::isSpatializer() const {
    return mThreadType == IAfThreadBase::SPATIALIZER;
}

uint32_t EffectChain::EffectCallback::sampleRate() const {
    const sp<IAfThreadBase> t = thread().promote();
    if (t == nullptr) {
        return 0;
    }
    return t->sampleRate();
}

audio_channel_mask_t EffectChain::EffectCallback::inChannelMask(int id) const
NO_THREAD_SAFETY_ANALYSIS
// calling function 'hasAudioSession_l' requires holding mutex 'ThreadBase_Mutex' exclusively
{
    const sp<IAfThreadBase> t = thread().promote();
    if (t == nullptr) {
        return AUDIO_CHANNEL_NONE;
    }
    sp<IAfEffectChain> c = chain().promote();
    if (c == nullptr) {
        return AUDIO_CHANNEL_NONE;
    }

    if (mThreadType == IAfThreadBase::SPATIALIZER) {
        if (c->sessionId() == AUDIO_SESSION_OUTPUT_STAGE) {
            if (c->isFirstEffect(id)) {
                return t->mixerChannelMask();
            } else {
                return t->channelMask();
            }
        } else if (!audio_is_global_session(c->sessionId())) {
            if ((t->hasAudioSession_l(c->sessionId())
                    & IAfThreadBase::SPATIALIZED_SESSION) != 0) {
                return t->mixerChannelMask();
            } else {
                return t->channelMask();
            }
        } else {
            return t->channelMask();
        }
    } else {
        return t->channelMask();
    }
}

uint32_t EffectChain::EffectCallback::inChannelCount(int id) const {
    return audio_channel_count_from_out_mask(inChannelMask(id));
}

audio_channel_mask_t EffectChain::EffectCallback::outChannelMask() const
NO_THREAD_SAFETY_ANALYSIS
// calling function 'hasAudioSession_l' requires holding mutex 'ThreadBase_Mutex' exclusively
{
    const sp<IAfThreadBase> t = thread().promote();
    if (t == nullptr) {
        return AUDIO_CHANNEL_NONE;
    }
    sp<IAfEffectChain> c = chain().promote();
    if (c == nullptr) {
        return AUDIO_CHANNEL_NONE;
    }

    if (mThreadType == IAfThreadBase::SPATIALIZER) {
        if (!audio_is_global_session(c->sessionId())) {
            if ((t->hasAudioSession_l(c->sessionId())
                    & IAfThreadBase::SPATIALIZED_SESSION) != 0) {
                return t->mixerChannelMask();
            } else {
                return t->channelMask();
            }
        } else {
            return t->channelMask();
        }
    } else {
        return t->channelMask();
    }
}

uint32_t EffectChain::EffectCallback::outChannelCount() const {
    return audio_channel_count_from_out_mask(outChannelMask());
}

audio_channel_mask_t EffectChain::EffectCallback::hapticChannelMask() const {
    const sp<IAfThreadBase> t = thread().promote();
    if (t == nullptr) {
        return AUDIO_CHANNEL_NONE;
    }
    return t->hapticChannelMask();
}

size_t EffectChain::EffectCallback::frameCount() const {
    const sp<IAfThreadBase> t = thread().promote();
    if (t == nullptr) {
        return 0;
    }
    return t->frameCount();
}

uint32_t EffectChain::EffectCallback::latency() const
NO_THREAD_SAFETY_ANALYSIS  // latency_l() access
{
    const sp<IAfThreadBase> t = thread().promote();
    if (t == nullptr) {
        return 0;
    }
    // TODO(b/275956781) - this requires the thread lock.
    return t->latency_l();
}

void EffectChain::EffectCallback::setVolumeForOutput(float left, float right) const
NO_THREAD_SAFETY_ANALYSIS  // setVolumeForOutput_l() access
{
    const sp<IAfThreadBase> t = thread().promote();
    if (t == nullptr) {
        return;
    }
    t->setVolumeForOutput_l(left, right);
}

void EffectChain::EffectCallback::checkSuspendOnEffectEnabled(const sp<IAfEffectBase>& effect,
                                                              bool enabled, bool threadLocked)
        NO_THREAD_SAFETY_ANALYSIS {
    const sp<IAfThreadBase> t = thread().promote();
    if (t == nullptr) {
        return;
    }
    t->checkSuspendOnEffectEnabled(enabled, effect->sessionId(), threadLocked);

    sp<IAfEffectChain> c = chain().promote();
    if (c == nullptr) {
        return;
    }
    // in EffectChain context, an EffectBase is always from an EffectModule so static cast is safe
    c->checkSuspendOnEffectEnabled_l(effect->asEffectModule(), enabled);
}

void EffectChain::EffectCallback::onEffectEnable(const sp<IAfEffectBase>& effect) {
    const sp<IAfThreadBase> t = thread().promote();
    if (t == nullptr) {
        return;
    }
    // in EffectChain context, an EffectBase is always from an EffectModule so static cast is safe
    t->onEffectEnable(effect->asEffectModule());
}

void EffectChain::EffectCallback::onEffectDisable(const sp<IAfEffectBase>& effect) {
    checkSuspendOnEffectEnabled(effect, false, false /*threadLocked*/);

    const sp<IAfThreadBase> t = thread().promote();
    if (t == nullptr) {
        return;
    }
    t->onEffectDisable();
}

bool EffectChain::EffectCallback::disconnectEffectHandle(IAfEffectHandle *handle,
                                                      bool unpinIfLast) {
    const sp<IAfThreadBase> t = thread().promote();
    if (t == nullptr) {
        return false;
    }
    t->disconnectEffectHandle(handle, unpinIfLast);
    return true;
}

void EffectChain::EffectCallback::resetVolume_l() {
    sp<IAfEffectChain> c = chain().promote();
    if (c == nullptr) {
        return;
    }
    c->resetVolume_l();

}

product_strategy_t EffectChain::EffectCallback::strategy() const {
    sp<IAfEffectChain> c = chain().promote();
    if (c == nullptr) {
        return PRODUCT_STRATEGY_NONE;
    }
    return c->strategy();
}

int32_t EffectChain::EffectCallback::activeTrackCnt() const {
    sp<IAfEffectChain> c = chain().promote();
    if (c == nullptr) {
        return 0;
    }
    return c->activeTrackCnt();
}


#undef LOG_TAG
#define LOG_TAG "DeviceEffectProxy"

/* static */
sp<IAfDeviceEffectProxy> IAfDeviceEffectProxy::create(
        const AudioDeviceTypeAddr& device,
        const sp<DeviceEffectManagerCallback>& callback,
        effect_descriptor_t *desc, int id, bool notifyFramesProcessed)
{
    return sp<DeviceEffectProxy>::make(device,
            callback,
            desc, id, notifyFramesProcessed);
}

status_t DeviceEffectProxy::setEnabled(bool enabled, bool fromHandle)
{
    status_t status = EffectBase::setEnabled(enabled, fromHandle);
    audio_utils::lock_guard _l(proxyMutex());
    if (status == NO_ERROR) {
        for (auto& handle : mEffectHandles) {
            Status bs;
            if (enabled) {
                bs = handle.second->asIEffect()->enable(&status);
            } else {
                bs = handle.second->asIEffect()->disable(&status);
            }
            if (!bs.isOk()) {
              status = statusTFromBinderStatus(bs);
            }
        }
    }
    ALOGV("%s enable %d status %d", __func__, enabled, status);
    return status;
}

status_t DeviceEffectProxy::init_l(
        const std::map <audio_patch_handle_t, IAfPatchPanel::Patch>& patches) {
//For all audio patches
//If src or sink device match
//If the effect is HW accelerated
//	if no corresponding effect module
//		Create EffectModule: mHalEffect
//Create and attach EffectHandle
//If the effect is not HW accelerated and the patch sink or src is a mixer port
//	Create Effect on patch input or output thread on session -1
//Add EffectHandle to EffectHandle map of Effect Proxy:
    ALOGV("%s device type %d address %s", __func__,  mDevice.mType, mDevice.getAddress());
    status_t status = NO_ERROR;
    for (auto &patch : patches) {
        status = onCreatePatch(patch.first, patch.second);
        ALOGV("%s onCreatePatch status %d", __func__, status);
        if (status == BAD_VALUE) {
            return status;
        }
    }
    return status;
}

status_t DeviceEffectProxy::onUpdatePatch(audio_patch_handle_t oldPatchHandle,
        audio_patch_handle_t newPatchHandle,
        const IAfPatchPanel::Patch& /* patch */) {
    status_t status = NAME_NOT_FOUND;
    ALOGV("%s", __func__);
    audio_utils::lock_guard _l(proxyMutex());
    if (mEffectHandles.find(oldPatchHandle) != mEffectHandles.end()) {
        ALOGV("%s replacing effect from handle %d to handle %d", __func__, oldPatchHandle,
                newPatchHandle);
        sp<IAfEffectHandle> effect = mEffectHandles.at(oldPatchHandle);
        mEffectHandles.erase(oldPatchHandle);
        mEffectHandles.emplace(newPatchHandle, effect);
        status = NO_ERROR;
    }
    return status;
}

status_t DeviceEffectProxy::onCreatePatch(
        audio_patch_handle_t patchHandle, const IAfPatchPanel::Patch& patch) {
    status_t status = NAME_NOT_FOUND;
    sp<IAfEffectHandle> handle;
    // only consider source[0] as this is the only "true" source of a patch
    status = checkPort(patch, &patch.mAudioPatch.sources[0], &handle);
    ALOGV("%s source checkPort status %d", __func__, status);
    for (uint32_t i = 0; i < patch.mAudioPatch.num_sinks && status == NAME_NOT_FOUND; i++) {
        status = checkPort(patch, &patch.mAudioPatch.sinks[i], &handle);
        ALOGV("%s sink %d checkPort status %d", __func__, i, status);
    }
    if (status == NO_ERROR || status == ALREADY_EXISTS) {
        audio_utils::lock_guard _l(proxyMutex());
        size_t erasedHandle = mEffectHandles.erase(patchHandle);
        ALOGV("%s %s effecthandle %p for patch %d",
                __func__, (erasedHandle == 0 ? "adding" : "replacing"), handle.get(), patchHandle);
        mEffectHandles.emplace(patchHandle, handle);
    }
    ALOGW_IF(status == BAD_VALUE,
            "%s cannot attach effect %s on patch %d", __func__, mDescriptor.name, patchHandle);

    return status;
}

status_t DeviceEffectProxy::checkPort(const IAfPatchPanel::Patch& patch,
        const struct audio_port_config *port, sp<IAfEffectHandle> *handle)
NO_THREAD_SAFETY_ANALYSIS
// calling function 'createEffect_l' requires holding mutex 'AudioFlinger_Mutex' exclusively
{

    ALOGV("%s type %d device type %d address %s device ID %d patch.isSoftware() %d",
            __func__, port->type, port->ext.device.type,
            port->ext.device.address, port->id, patch.isSoftware());
    if (port->type != AUDIO_PORT_TYPE_DEVICE || port->ext.device.type != mDevice.mType ||
        port->ext.device.address != mDevice.address()) {
        return NAME_NOT_FOUND;
    }
    if (((mDescriptor.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_POST_PROC) &&
        (audio_port_config_has_input_direction(port))) {
        ALOGI("%s don't create postprocessing effect on record port", __func__);
        return NAME_NOT_FOUND;
    }
    if (((mDescriptor.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_PRE_PROC) &&
        (!audio_port_config_has_input_direction(port))) {
        ALOGI("%s don't create preprocessing effect on playback port", __func__);
        return NAME_NOT_FOUND;
    }
    status_t status = NAME_NOT_FOUND;

    if (mDescriptor.flags & EFFECT_FLAG_HW_ACC_TUNNEL) {
        audio_utils::lock_guard _l(proxyMutex());
        if (mHalEffect != nullptr && mDevicePort.id == port->id) {
            ALOGV("%s reusing HAL effect", __func__);
        } else {
            mDevicePort = *port;
            mHalEffect = new EffectModule(mMyCallback,
                                      const_cast<effect_descriptor_t *>(&mDescriptor),
                                      mMyCallback->newEffectId(), AUDIO_SESSION_DEVICE,
                                      false /* pinned */, port->id);
            if (audio_is_input_device(mDevice.mType)) {
                mHalEffect->setInputDevice(mDevice);
            } else {
                mHalEffect->setDevices({mDevice});
            }
            mHalEffect->configure_l();
        }
        *handle = new EffectHandle(mHalEffect, nullptr, nullptr, 0 /*priority*/,
                                   mNotifyFramesProcessed);
        status = (*handle)->initCheck();
        if (status == OK) {
            status = mHalEffect->addHandle((*handle).get());
        } else {
            mHalEffect.clear();
            mDevicePort.id = AUDIO_PORT_HANDLE_NONE;
        }
    } else if (patch.isSoftware() || patch.thread().promote() != nullptr) {
        sp<IAfThreadBase> thread;
        if (audio_port_config_has_input_direction(port)) {
            if (patch.isSoftware()) {
                thread = patch.mRecord.thread();
            } else {
                thread = patch.thread().promote();
            }
        } else {
            if (patch.isSoftware()) {
                thread = patch.mPlayback.thread();
            } else {
                thread = patch.thread().promote();
            }
        }
        int enabled;
        *handle = thread->createEffect_l(nullptr, nullptr, 0, AUDIO_SESSION_DEVICE,
                                         const_cast<effect_descriptor_t *>(&mDescriptor),
                                         &enabled, &status, false, false /*probe*/,
                                         mNotifyFramesProcessed);
        ALOGV("%s thread->createEffect_l status %d", __func__, status);
    } else {
        status = BAD_VALUE;
    }

    if (status == NO_ERROR || status == ALREADY_EXISTS) {
        Status bs;
        if (isEnabled()) {
            bs = (*handle)->asIEffect()->enable(&status);
        } else {
            bs = (*handle)->asIEffect()->disable(&status);
        }
        if (!bs.isOk()) {
            status = statusTFromBinderStatus(bs);
        }
    }
    return status;
}

void DeviceEffectProxy::onReleasePatch(audio_patch_handle_t patchHandle) {
    sp<IAfEffectHandle> effect;
    {
        audio_utils::lock_guard _l(proxyMutex());
        if (mEffectHandles.find(patchHandle) != mEffectHandles.end()) {
            effect = mEffectHandles.at(patchHandle);
            mEffectHandles.erase(patchHandle);
        }
    }
}


size_t DeviceEffectProxy::removeEffect(const sp<IAfEffectModule>& effect)
{
    audio_utils::lock_guard _l(proxyMutex());
    if (effect == mHalEffect) {
        mHalEffect->release_l();
        mHalEffect.clear();
        mDevicePort.id = AUDIO_PORT_HANDLE_NONE;
    }
    return mHalEffect == nullptr ? 0 : 1;
}

status_t DeviceEffectProxy::addEffectToHal(
        const sp<EffectHalInterface>& effect) {
    if (mHalEffect == nullptr) {
        return NO_INIT;
    }
    return mManagerCallback->addEffectToHal(&mDevicePort, effect);
}

status_t DeviceEffectProxy::removeEffectFromHal(
        const sp<EffectHalInterface>& effect) {
    if (mHalEffect == nullptr) {
        return NO_INIT;
    }
    return mManagerCallback->removeEffectFromHal(&mDevicePort, effect);
}

status_t DeviceEffectProxy::command(
        int32_t cmdCode, const std::vector<uint8_t>& cmdData, int32_t maxReplySize,
        std::vector<uint8_t>* reply) {
    audio_utils::lock_guard _l(proxyMutex());
    status_t status = EffectBase::command(cmdCode, cmdData, maxReplySize, reply);
    if (status == NO_ERROR) {
        for (auto& handle : mEffectHandles) {
            sp<IAfEffectBase> effect = handle.second->effect().promote();
            if (effect != nullptr) {
                status = effect->command(cmdCode, cmdData, maxReplySize, reply);
            }
        }
    }
    ALOGV("%s status %d", __func__, status);
    return status;
}

bool DeviceEffectProxy::isOutput() const {
    if (mDevicePort.id != AUDIO_PORT_HANDLE_NONE) {
        return mDevicePort.role == AUDIO_PORT_ROLE_SINK;
    }
    return true;
}

uint32_t DeviceEffectProxy::sampleRate() const {
    if (mDevicePort.id != AUDIO_PORT_HANDLE_NONE &&
            (mDevicePort.config_mask & AUDIO_PORT_CONFIG_SAMPLE_RATE) != 0) {
        return mDevicePort.sample_rate;
    }
    return DEFAULT_OUTPUT_SAMPLE_RATE;
}

audio_channel_mask_t DeviceEffectProxy::channelMask() const {
    if (mDevicePort.id != AUDIO_PORT_HANDLE_NONE &&
            (mDevicePort.config_mask & AUDIO_PORT_CONFIG_CHANNEL_MASK) != 0) {
        return mDevicePort.channel_mask;
    }
    return AUDIO_CHANNEL_OUT_STEREO;
}

uint32_t DeviceEffectProxy::channelCount() const {
    if (isOutput()) {
        return audio_channel_count_from_out_mask(channelMask());
    }
    return audio_channel_count_from_in_mask(channelMask());
}

void DeviceEffectProxy::dump2(int fd, int spaces) const
NO_THREAD_SAFETY_ANALYSIS  // conditional try lock
{
    const Vector<String16> args;
    EffectBase::dump(fd, args);

    const bool locked = afutils::dumpTryLock(proxyMutex());
    if (!locked) {
        String8 result("DeviceEffectProxy may be deadlocked\n");
        write(fd, result.c_str(), result.size());
    }

    String8 outStr;
    if (mHalEffect != nullptr) {
        outStr.appendFormat("%*sHAL Effect Id: %d\n", spaces, "", mHalEffect->id());
    } else {
        outStr.appendFormat("%*sNO HAL Effect\n", spaces, "");
    }
    write(fd, outStr.c_str(), outStr.size());
    outStr.clear();

    outStr.appendFormat("%*sSub Effects:\n", spaces, "");
    write(fd, outStr.c_str(), outStr.size());
    outStr.clear();

    for (const auto& iter : mEffectHandles) {
        outStr.appendFormat("%*sEffect for patch handle %d:\n", spaces + 2, "", iter.first);
        write(fd, outStr.c_str(), outStr.size());
        outStr.clear();
        sp<IAfEffectBase> effect = iter.second->effect().promote();
        if (effect != nullptr) {
            effect->dump(fd, args);
        }
    }

    if (locked) {
        proxyMutex().unlock();
    }
}

#undef LOG_TAG
#define LOG_TAG "DeviceEffectProxy::ProxyCallback"

int DeviceEffectProxy::ProxyCallback::newEffectId() {
    return mManagerCallback->newEffectId();
}


bool DeviceEffectProxy::ProxyCallback::disconnectEffectHandle(
        IAfEffectHandle *handle, bool unpinIfLast) {
    sp<IAfEffectBase> effectBase = handle->effect().promote();
    if (effectBase == nullptr) {
        return false;
    }

    sp<IAfEffectModule> effect = effectBase->asEffectModule();
    if (effect == nullptr) {
        return false;
    }

    // restore suspended effects if the disconnected handle was enabled and the last one.
    bool remove = (effect->removeHandle(handle) == 0) && (!effect->isPinned() || unpinIfLast);
    if (remove) {
        sp<DeviceEffectProxy> proxy = mProxy.promote();
        if (proxy != nullptr) {
            proxy->removeEffect(effect);
        }
        if (handle->enabled()) {
            effectBase->checkSuspendOnEffectEnabled(false, false /*threadLocked*/);
        }
    }
    return true;
}

status_t DeviceEffectProxy::ProxyCallback::createEffectHal(
        const effect_uuid_t *pEffectUuid, int32_t sessionId, int32_t deviceId,
        sp<EffectHalInterface> *effect) {
    return mManagerCallback->createEffectHal(pEffectUuid, sessionId, deviceId, effect);
}

status_t DeviceEffectProxy::ProxyCallback::addEffectToHal(
        const sp<EffectHalInterface>& effect) {
    sp<DeviceEffectProxy> proxy = mProxy.promote();
    if (proxy == nullptr) {
        return NO_INIT;
    }
    return proxy->addEffectToHal(effect);
}

status_t DeviceEffectProxy::ProxyCallback::removeEffectFromHal(
        const sp<EffectHalInterface>& effect) {
    sp<DeviceEffectProxy> proxy = mProxy.promote();
    if (proxy == nullptr) {
        return NO_INIT;
    }
    return proxy->removeEffectFromHal(effect);
}

bool DeviceEffectProxy::ProxyCallback::isOutput() const {
    sp<DeviceEffectProxy> proxy = mProxy.promote();
    if (proxy == nullptr) {
        return true;
    }
    return proxy->isOutput();
}

uint32_t DeviceEffectProxy::ProxyCallback::sampleRate() const {
    sp<DeviceEffectProxy> proxy = mProxy.promote();
    if (proxy == nullptr) {
        return DEFAULT_OUTPUT_SAMPLE_RATE;
    }
    return proxy->sampleRate();
}

audio_channel_mask_t DeviceEffectProxy::ProxyCallback::inChannelMask(
        int id __unused) const {
    sp<DeviceEffectProxy> proxy = mProxy.promote();
    if (proxy == nullptr) {
        return AUDIO_CHANNEL_OUT_STEREO;
    }
    return proxy->channelMask();
}

uint32_t DeviceEffectProxy::ProxyCallback::inChannelCount(int id __unused) const {
    sp<DeviceEffectProxy> proxy = mProxy.promote();
    if (proxy == nullptr) {
        return 2;
    }
    return proxy->channelCount();
}

audio_channel_mask_t DeviceEffectProxy::ProxyCallback::outChannelMask() const {
    sp<DeviceEffectProxy> proxy = mProxy.promote();
    if (proxy == nullptr) {
        return AUDIO_CHANNEL_OUT_STEREO;
    }
    return proxy->channelMask();
}

uint32_t DeviceEffectProxy::ProxyCallback::outChannelCount() const {
    sp<DeviceEffectProxy> proxy = mProxy.promote();
    if (proxy == nullptr) {
        return 2;
    }
    return proxy->channelCount();
}

void DeviceEffectProxy::ProxyCallback::onEffectEnable(
        const sp<IAfEffectBase>& effectBase) {
    sp<IAfEffectModule> effect = effectBase->asEffectModule();
    if (effect == nullptr) {
        return;
    }
    effect->start_l();
}

void DeviceEffectProxy::ProxyCallback::onEffectDisable(
        const sp<IAfEffectBase>& effectBase) {
    sp<IAfEffectModule> effect = effectBase->asEffectModule();
    if (effect == nullptr) {
        return;
    }
    effect->stop_l();
}

} // namespace android
