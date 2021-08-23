/*
**
** Copyright 2021, The Android Open Source Project
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


#define LOG_TAG "Spatializer"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <limits.h>
#include <stdint.h>
#include <sys/types.h>

#include <android/content/AttributionSourceState.h>
#include <audio_utils/fixedfft.h>
#include <cutils/bitops.h>
#include <media/ShmemCompat.h>
#include <media/audiohal/EffectsFactoryHalInterface.h>
#include <mediautils/ServiceUtilities.h>
#include <utils/Thread.h>

#include "Spatializer.h"

namespace android {

using aidl_utils::statusTFromBinderStatus;
using aidl_utils::binderStatusFromStatusT;
using android::content::AttributionSourceState;
using binder::Status;
using media::SpatializationLevel;
using media::SpatializerHeadTrackingMode;

#define VALUE_OR_RETURN_BINDER_STATUS(x) \
    ({ auto _tmp = (x); \
       if (!_tmp.ok()) return aidl_utils::binderStatusFromStatusT(_tmp.error()); \
       std::move(_tmp.value()); })

#define RETURN_IF_BINDER_ERROR(x)      \
    {                                  \
        binder::Status _tmp = (x);     \
        if (!_tmp.isOk()) return _tmp; \
    }

// ---------------------------------------------------------------------------

sp<Spatializer> Spatializer::create(SpatializerPolicyCallback *callback) {
    sp<Spatializer> spatializer;

    sp<EffectsFactoryHalInterface> effectsFactoryHal = EffectsFactoryHalInterface::create();
    if (effectsFactoryHal == nullptr) {
        ALOGW("%s failed to create effect factory interface", __func__);
        return spatializer;
    }

    std::vector<effect_descriptor_t> descriptors;
    status_t status =
            effectsFactoryHal->getDescriptors(FX_IID_SPATIALIZER, &descriptors);
    if (status != NO_ERROR) {
        ALOGW("%s failed to get spatializer descriptor, error %d", __func__, status);
        return spatializer;
    }
    ALOG_ASSERT(!descriptors.empty(),
            "%s getDescriptors() returned no error but empty list", __func__);

    //TODO: get supported spatialization modes from FX engine or descriptor

    sp<EffectHalInterface> effect;
    status = effectsFactoryHal->createEffect(&descriptors[0].uuid, AUDIO_SESSION_OUTPUT_STAGE,
            AUDIO_IO_HANDLE_NONE, AUDIO_PORT_HANDLE_NONE, &effect);
    ALOGI("%s FX create status %d effect %p", __func__, status, effect.get());

    if (status == NO_ERROR && effect != nullptr) {
        spatializer = new Spatializer(descriptors[0], callback);
        // TODO: Read supported config from engine
        audio_config_base_t config = AUDIO_CONFIG_BASE_INITIALIZER;
        config.channel_mask = AUDIO_CHANNEL_OUT_5POINT1;
        spatializer->setAudioInConfig(config);
    }

    return spatializer;
}

Spatializer::Spatializer(effect_descriptor_t engineDescriptor,
                                   SpatializerPolicyCallback *callback)
    : mEngineDescriptor(engineDescriptor), mPolicyCallback(callback) {
    ALOGV("%s", __func__);
}

Spatializer::~Spatializer() {
    ALOGV("%s", __func__);
}

status_t Spatializer::registerCallback(
        const sp<media::INativeSpatializerCallback>& callback) {
    Mutex::Autolock _l(mLock);
    if (callback == nullptr) {
        return BAD_VALUE;
    }

    sp<IBinder> binder = IInterface::asBinder(callback);
    status_t status = binder->linkToDeath(this);
    if (status == NO_ERROR) {
        mSpatializerCallback = callback;
    }
    ALOGV("%s status %d", __func__, status);
    return status;
}

// IBinder::DeathRecipient
void Spatializer::binderDied(__unused const wp<IBinder> &who) {
    {
        Mutex::Autolock _l(mLock);
        mLevel = SpatializationLevel::NONE;
        mSpatializerCallback.clear();
    }
    ALOGV("%s", __func__);
    mPolicyCallback->onCheckSpatializer();
}

// ISpatializer
Status Spatializer::getSupportedLevels(std::vector<SpatializationLevel> *levels) {
    ALOGV("%s", __func__);
    if (levels == nullptr) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    //TODO: get this from engine
    levels->push_back(SpatializationLevel::NONE);
    levels->push_back(SpatializationLevel::SPATIALIZER_MULTICHANNEL);
    return Status::ok();
}

Status Spatializer::setLevel(media::SpatializationLevel level) {
    ALOGV("%s level %d", __func__, (int)level);
    if (level != SpatializationLevel::NONE
            && level != SpatializationLevel::SPATIALIZER_MULTICHANNEL) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    sp<media::INativeSpatializerCallback> callback;
    bool levelChanged = false;
    {
        Mutex::Autolock _l(mLock);
        levelChanged = mLevel != level;
        mLevel = level;
        callback = mSpatializerCallback;
    }

    if (levelChanged) {
        mPolicyCallback->onCheckSpatializer();
        if (callback != nullptr) {
            callback->onLevelChanged(level);
        }
    }
    return Status::ok();
}

Status Spatializer::getLevel(media::SpatializationLevel *level) {
    if (level == nullptr) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    Mutex::Autolock _l(mLock);
    *level = mLevel;
    ALOGV("%s level %d", __func__, (int)*level);
    return Status::ok();
}

Status Spatializer::getSupportedHeadTrackingModes(
        std::vector<media::SpatializerHeadTrackingMode>* modes) {
    ALOGV("%s", __func__);
    if (modes == nullptr) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    //TODO: get this from:
    // - The engine capabilities
    // - If a head tracking sensor is registered and linked to a connected audio device
    // - if we have indications on the screen orientation
    modes->push_back(SpatializerHeadTrackingMode::RELATIVE_WORLD);
    return Status::ok();
}

Status Spatializer::setDesiredHeadTrackingMode(media::SpatializerHeadTrackingMode mode) {
    ALOGV("%s level %d", __func__, (int)mode);
    if (mode != SpatializerHeadTrackingMode::DISABLED
            && mode != SpatializerHeadTrackingMode::RELATIVE_WORLD) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    {
        Mutex::Autolock _l(mLock);
        mHeadTrackingMode = mode;
    }
    return Status::ok();
}

Status Spatializer::getActualHeadTrackingMode(media::SpatializerHeadTrackingMode *mode) {
    if (mode == nullptr) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    Mutex::Autolock _l(mLock);
    *mode = mHeadTrackingMode;
    ALOGV("%s mode %d", __func__, (int)*mode);
    return Status::ok();
}

Status Spatializer::recenterHeadTracker() {
    return Status::ok();
}

Status Spatializer::setGlobalTransform(const std::vector<float>& screenToStage) {
    Mutex::Autolock _l(mLock);
    mScreenToStageTransform = screenToStage;
    ALOGV("%s", __func__);
    return Status::ok();
}

Status Spatializer::release() {
    ALOGV("%s", __func__);
    bool levelChanged = false;
    {
        Mutex::Autolock _l(mLock);
        if (mSpatializerCallback == nullptr) {
            return binderStatusFromStatusT(INVALID_OPERATION);
        }

        sp<IBinder> binder = IInterface::asBinder(mSpatializerCallback);
        binder->unlinkToDeath(this);
        mSpatializerCallback.clear();

        levelChanged = mLevel != SpatializationLevel::NONE;
        mLevel = SpatializationLevel::NONE;
    }

    if (levelChanged) {
        mPolicyCallback->onCheckSpatializer();
    }
    return Status::ok();
}

status_t Spatializer::attachOutput(audio_io_handle_t output) {
    Mutex::Autolock _l(mLock);
    ALOGV("%s output %d mOutput %d", __func__, (int)output, (int)mOutput);
    if (mOutput != AUDIO_IO_HANDLE_NONE) {
        LOG_ALWAYS_FATAL_IF(mEngine != nullptr, "%s output set without FX engine", __func__);
        // remove FX instance
        mEngine->setEnabled(false);
        mEngine.clear();
    }
    // create FX instance on output
    AttributionSourceState attributionSource = AttributionSourceState();
    mEngine = new AudioEffect(attributionSource);
    mEngine->set(nullptr, &mEngineDescriptor.uuid, 0, Spatializer::engineCallback /* cbf */,
                 this /* user */, AUDIO_SESSION_OUTPUT_STAGE, output, {} /* device */,
                 false /* probe */, true /* notifyFramesProcessed */);
    status_t status = mEngine->initCheck();
    ALOGV("%s mEngine create status %d", __func__, (int)status);
    if (status != NO_ERROR) {
        return status;
    }
    mEngine->setEnabled(true);
    mOutput = output;
    return NO_ERROR;
}

audio_io_handle_t Spatializer::detachOutput() {
    Mutex::Autolock _l(mLock);
    ALOGV("%s mOutput %d", __func__, (int)mOutput);
    if (mOutput == AUDIO_IO_HANDLE_NONE) {
        return AUDIO_IO_HANDLE_NONE;
    }
    // remove FX instance
    mEngine->setEnabled(false);
    mEngine.clear();
    audio_io_handle_t output = mOutput;
    mOutput = AUDIO_IO_HANDLE_NONE;
    return output;
}

void Spatializer::engineCallback(int32_t event, void *user, void *info) {

    if (user == nullptr) {
        return;
    }
    const Spatializer * const me = reinterpret_cast<Spatializer *>(user);
    switch (event) {
        case AudioEffect::EVENT_FRAMES_PROCESSED: {
            int frames = info == nullptr ? 0 : *(int *)info;
            ALOGD("%s frames processed %d for me %p", __func__, frames, me);
            } break;
        default:
            ALOGD("%s event %d", __func__, event);
            break;
    }
}

// ---------------------------------------------------------------------------

Spatializer::EffectClient::EffectClient(const sp<media::IEffectClient>& effectClient,
             Spatializer& parent)
             : BnEffect(),
             mEffectClient(effectClient), mParent(parent) {
}

Spatializer::EffectClient::~EffectClient() {
}

// IEffect

#define RETURN(code) \
  *_aidl_return = (code); \
  return Status::ok();

// Write a POD value into a vector of bytes (clears the previous buffer
// content).
template<typename T>
void writeToBuffer(const T& value, std::vector<uint8_t>* buffer) {
    buffer->clear();
    appendToBuffer(value, buffer);
}

Status Spatializer::EffectClient::enable(int32_t* _aidl_return) {
    RETURN(OK);
}

Status Spatializer::EffectClient::disable(int32_t* _aidl_return) {
    RETURN(OK);
}

Status Spatializer::EffectClient::command(int32_t cmdCode,
                                const std::vector<uint8_t>& cmdData __unused,
                                int32_t maxResponseSize __unused,
                                std::vector<uint8_t>* response __unused,
                                int32_t* _aidl_return) {

    // reject commands reserved for internal use by audio framework if coming from outside
    // of audioserver
    switch(cmdCode) {
        case EFFECT_CMD_ENABLE:
        case EFFECT_CMD_DISABLE:
        case EFFECT_CMD_SET_PARAM_DEFERRED:
        case EFFECT_CMD_SET_PARAM_COMMIT:
            RETURN(BAD_VALUE);
        case EFFECT_CMD_SET_PARAM:
        case EFFECT_CMD_GET_PARAM:
            break;
        default:
            if (cmdCode >= EFFECT_CMD_FIRST_PROPRIETARY) {
                break;
            }
            android_errorWriteLog(0x534e4554, "62019992");
            RETURN(BAD_VALUE);
    }
    (void)mParent;
    RETURN(OK);
}

Status Spatializer::EffectClient::disconnect() {
    mDisconnected = true;
    return Status::ok();
}

Status Spatializer::EffectClient::getCblk(media::SharedFileRegion* _aidl_return) {
    LOG_ALWAYS_FATAL_IF(!convertIMemoryToSharedFileRegion(mCblkMemory, _aidl_return));
    return Status::ok();
}

} // namespace android
