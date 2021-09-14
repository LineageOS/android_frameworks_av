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
#include <android/sensor.h>
#include <audio_utils/fixedfft.h>
#include <cutils/bitops.h>
#include <hardware/sensors.h>
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
using media::HeadTrackingMode;
using media::Pose3f;
using media::SpatializationLevel;
using media::SpatializationMode;
using media::SpatializerHeadTrackingMode;
using media::SensorPoseProvider;


using namespace std::chrono_literals;

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
        if (spatializer->loadEngineConfiguration(effect) != NO_ERROR) {
            spatializer.clear();
        }
    }

    return spatializer;
}

Spatializer::Spatializer(effect_descriptor_t engineDescriptor, SpatializerPolicyCallback* callback)
    : mEngineDescriptor(engineDescriptor),
      mPolicyCallback(callback) {
    ALOGV("%s", __func__);
}

Spatializer::~Spatializer() {
    ALOGV("%s", __func__);
}

status_t Spatializer::loadEngineConfiguration(sp<EffectHalInterface> effect) {
    ALOGV("%s", __func__);

    std::vector<bool> supportsHeadTracking;
    status_t status = getHalParameter<false>(effect, SPATIALIZER_PARAM_HEADTRACKING_SUPPORTED,
                                         &supportsHeadTracking);
    if (status != NO_ERROR) {
        return status;
    }
    mSupportsHeadTracking = supportsHeadTracking[0];

    status = getHalParameter<true>(effect, SPATIALIZER_PARAM_SUPPORTED_LEVELS, &mLevels);
    if (status != NO_ERROR) {
        return status;
    }
    status = getHalParameter<true>(effect, SPATIALIZER_PARAM_SUPPORTED_SPATIALIZATION_MODES,
                                &mSpatializationModes);
    if (status != NO_ERROR) {
        return status;
    }
    status = getHalParameter<true>(effect, SPATIALIZER_PARAM_SUPPORTED_CHANNEL_MASKS,
                                 &mChannelMasks);
    if (status != NO_ERROR) {
        return status;
    }
    return NO_ERROR;
}

/** Gets the channel mask, sampling rate and format set for the spatializer input. */
audio_config_base_t Spatializer::getAudioInConfig() const {
    std::lock_guard lock(mLock);
    audio_config_base_t config = AUDIO_CONFIG_BASE_INITIALIZER;
    // For now use highest supported channel count
    uint32_t maxCount = 0;
    for ( auto mask : mChannelMasks) {
        if (audio_channel_count_from_out_mask(mask) > maxCount) {
            config.channel_mask = mask;
        }
    }
    return config;
}

status_t Spatializer::registerCallback(
        const sp<media::INativeSpatializerCallback>& callback) {
    std::lock_guard lock(mLock);
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
        std::lock_guard lock(mLock);
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
    levels->push_back(SpatializationLevel::NONE);
    levels->insert(levels->end(), mLevels.begin(), mLevels.end());
    return Status::ok();
}

Status Spatializer::setLevel(SpatializationLevel level) {
    ALOGV("%s level %d", __func__, (int)level);
    if (level != SpatializationLevel::NONE
            && std::find(mLevels.begin(), mLevels.end(), level) == mLevels.end()) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    sp<media::INativeSpatializerCallback> callback;
    bool levelChanged = false;
    {
        std::lock_guard lock(mLock);
        levelChanged = mLevel != level;
        mLevel = level;
        callback = mSpatializerCallback;

        if (levelChanged && mEngine != nullptr) {
            setEffectParameter_l(SPATIALIZER_PARAM_LEVEL, std::vector<SpatializationLevel>{level});
        }
    }

    if (levelChanged) {
        mPolicyCallback->onCheckSpatializer();
        if (callback != nullptr) {
            callback->onLevelChanged(level);
        }
    }
    return Status::ok();
}

Status Spatializer::getLevel(SpatializationLevel *level) {
    if (level == nullptr) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    std::lock_guard lock(mLock);
    *level = mLevel;
    ALOGV("%s level %d", __func__, (int)*level);
    return Status::ok();
}

Status Spatializer::getSupportedHeadTrackingModes(
        std::vector<SpatializerHeadTrackingMode>* modes) {
    std::lock_guard lock(mLock);
    ALOGV("%s", __func__);
    if (modes == nullptr) {
        return binderStatusFromStatusT(BAD_VALUE);
    }

    modes->push_back(SpatializerHeadTrackingMode::DISABLED);
    if (mSupportsHeadTracking) {
        if (mHeadSensor != nullptr) {
            modes->push_back(SpatializerHeadTrackingMode::RELATIVE_WORLD);
            if (mScreenSensor != nullptr) {
                modes->push_back(SpatializerHeadTrackingMode::RELATIVE_SCREEN);
            }
        }
    }
    return Status::ok();
}

Status Spatializer::setDesiredHeadTrackingMode(SpatializerHeadTrackingMode mode) {
    ALOGV("%s mode %d", __func__, (int)mode);

    if (!mSupportsHeadTracking) {
        return binderStatusFromStatusT(INVALID_OPERATION);
    }
    std::lock_guard lock(mLock);
    switch (mode) {
        case SpatializerHeadTrackingMode::OTHER:
            return binderStatusFromStatusT(BAD_VALUE);
        case SpatializerHeadTrackingMode::DISABLED:
            mDesiredHeadTrackingMode = HeadTrackingMode::STATIC;
            break;
        case SpatializerHeadTrackingMode::RELATIVE_WORLD:
            mDesiredHeadTrackingMode = HeadTrackingMode::WORLD_RELATIVE;
            break;
        case SpatializerHeadTrackingMode::RELATIVE_SCREEN:
            mDesiredHeadTrackingMode = HeadTrackingMode::SCREEN_RELATIVE;
            break;
    }

    if (mPoseController != nullptr) {
        mPoseController->setDesiredMode(mDesiredHeadTrackingMode);
    }

    return Status::ok();
}

Status Spatializer::getActualHeadTrackingMode(SpatializerHeadTrackingMode *mode) {
    if (mode == nullptr) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    std::lock_guard lock(mLock);
    *mode = mActualHeadTrackingMode;
    ALOGV("%s mode %d", __func__, (int)*mode);
    return Status::ok();
}

Status Spatializer::recenterHeadTracker() {
    std::lock_guard lock(mLock);
    if (mPoseController != nullptr) {
        mPoseController->recenter();
    }
    return Status::ok();
}

Status Spatializer::setGlobalTransform(const std::vector<float>& screenToStage) {
    ALOGV("%s", __func__);
    std::optional<Pose3f> maybePose = Pose3f::fromVector(screenToStage);
    if (!maybePose.has_value()) {
        ALOGW("Invalid screenToStage vector.");
        return binderStatusFromStatusT(BAD_VALUE);
    }
    std::lock_guard lock(mLock);
    if (mPoseController != nullptr) {
        mPoseController->setScreenToStagePose(maybePose.value());
    }
    return Status::ok();
}

Status Spatializer::release() {
    ALOGV("%s", __func__);
    bool levelChanged = false;
    {
        std::lock_guard lock(mLock);
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

Status Spatializer::setHeadSensor(int sensorHandle) {
    ALOGV("%s sensorHandle %d", __func__, sensorHandle);
    std::lock_guard lock(mLock);
    if (sensorHandle == ASENSOR_INVALID) {
        mHeadSensor = nullptr;
    } else {
        mHeadSensor = VALUE_OR_RETURN_BINDER_STATUS(getSensorFromHandle(sensorHandle));
    }
    if (mPoseController != nullptr) {
        mPoseController->setHeadSensor(mHeadSensor);
    }
    return Status::ok();
}

Status Spatializer::setScreenSensor(int sensorHandle) {
    ALOGV("%s sensorHandle %d", __func__, sensorHandle);
    std::lock_guard lock(mLock);
    if (sensorHandle == ASENSOR_INVALID) {
        mScreenSensor = nullptr;
    } else {
        mScreenSensor = VALUE_OR_RETURN_BINDER_STATUS(getSensorFromHandle(sensorHandle));
    }
    if (mPoseController != nullptr) {
        mPoseController->setScreenSensor(mScreenSensor);
    }
    return Status::ok();
}

Status Spatializer::setDisplayOrientation(float physicalToLogicalAngle) {
    ALOGV("%s physicalToLogicalAngle %f", __func__, physicalToLogicalAngle);
    std::lock_guard lock(mLock);
    mDisplayOrientation = physicalToLogicalAngle;
    if (mPoseController != nullptr) {
        mPoseController->setDisplayOrientation(mDisplayOrientation);
    }
    return Status::ok();
}

Status Spatializer::setHingeAngle(float hingeAngle) {
    std::lock_guard lock(mLock);
    ALOGV("%s hingeAngle %f", __func__, hingeAngle);
    if (mEngine != nullptr) {
        setEffectParameter_l(SPATIALIZER_PARAM_HINGE_ANGLE, std::vector<float>{hingeAngle});
    }
    return Status::ok();
}

Status Spatializer::getSupportedModes(std::vector<SpatializationMode> *modes) {
    ALOGV("%s", __func__);
    if (modes == nullptr) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    *modes = mSpatializationModes;
    return Status::ok();
}

// SpatializerPoseController::Listener
void Spatializer::onHeadToStagePose(const Pose3f& headToStage) {
    ALOGV("%s", __func__);
    sp<media::INativeSpatializerCallback> callback;
    auto vec = headToStage.toVector();
    {
        std::lock_guard lock(mLock);
        callback = mSpatializerCallback;
        if (mEngine != nullptr) {
            setEffectParameter_l(SPATIALIZER_PARAM_HEAD_TO_STAGE, vec);
        }
    }

    if (callback != nullptr) {
        callback->onHeadToSoundStagePoseUpdated(vec);
    }
}

void Spatializer::onActualModeChange(HeadTrackingMode mode) {
    ALOGV("onActualModeChange(%d)", (int) mode);
    sp<media::INativeSpatializerCallback> callback;
    SpatializerHeadTrackingMode spatializerMode;
    {
        std::lock_guard lock(mLock);
        if (!mSupportsHeadTracking) {
            spatializerMode = SpatializerHeadTrackingMode::DISABLED;
        } else {
            switch (mode) {
                case HeadTrackingMode::STATIC:
                    spatializerMode = SpatializerHeadTrackingMode::DISABLED;
                    break;
                case HeadTrackingMode::WORLD_RELATIVE:
                    spatializerMode = SpatializerHeadTrackingMode::RELATIVE_WORLD;
                    break;
                case HeadTrackingMode::SCREEN_RELATIVE:
                    spatializerMode = SpatializerHeadTrackingMode::RELATIVE_SCREEN;
                    break;
                default:
                    LOG_ALWAYS_FATAL("Unknown mode: %d", mode);
            }
        }
        mActualHeadTrackingMode = spatializerMode;
        callback = mSpatializerCallback;
    }
    if (callback != nullptr) {
        callback->onHeadTrackingModeChanged(spatializerMode);
    }
}

/* static */
ConversionResult<ASensorRef> Spatializer::getSensorFromHandle(int handle) {
    ASensorManager* sensorManager =
            ASensorManager_getInstanceForPackage("headtracker");
    if (!sensorManager) {
        ALOGE("Failed to get a sensor manager");
        return base::unexpected(NO_INIT);
    }
    ASensorList sensorList;
    int numSensors = ASensorManager_getSensorList(sensorManager, &sensorList);
    for (int i = 0; i < numSensors; ++i) {
        if (ASensor_getHandle(sensorList[i]) == handle) {
            return sensorList[i];
        }
    }
    return base::unexpected(BAD_VALUE);
}

status_t Spatializer::attachOutput(audio_io_handle_t output) {
    std::shared_ptr<SpatializerPoseController> poseController;
    {
        std::lock_guard lock(mLock);
        ALOGV("%s output %d mOutput %d", __func__, (int)output, (int)mOutput);
        if (mOutput != AUDIO_IO_HANDLE_NONE) {
            LOG_ALWAYS_FATAL_IF(mEngine == nullptr, "%s output set without FX engine", __func__);
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

        setEffectParameter_l(SPATIALIZER_PARAM_LEVEL,
                             std::vector<SpatializationLevel>{mLevel});
        setEffectParameter_l(SPATIALIZER_PARAM_HEADTRACKING_MODE,
                             std::vector<SpatializerHeadTrackingMode>{mActualHeadTrackingMode});

        mEngine->setEnabled(true);
        mOutput = output;

        mPoseController = std::make_shared<SpatializerPoseController>(
                static_cast<SpatializerPoseController::Listener*>(this), 10ms, 50ms);
        LOG_ALWAYS_FATAL_IF(mPoseController == nullptr,
                            "%s could not allocate pose controller", __func__);

        mPoseController->setDesiredMode(mDesiredHeadTrackingMode);
        mPoseController->setHeadSensor(mHeadSensor);
        mPoseController->setScreenSensor(mScreenSensor);
        mPoseController->setDisplayOrientation(mDisplayOrientation);
        poseController = mPoseController;
    }
    poseController->waitUntilCalculated();
    return NO_ERROR;
}

audio_io_handle_t Spatializer::detachOutput() {
    std::lock_guard lock(mLock);
    ALOGV("%s mOutput %d", __func__, (int)mOutput);
    audio_io_handle_t output = AUDIO_IO_HANDLE_NONE;
    if (mOutput == AUDIO_IO_HANDLE_NONE) {
        return output;
    }
    // remove FX instance
    mEngine->setEnabled(false);
    mEngine.clear();
    output = mOutput;
    mOutput = AUDIO_IO_HANDLE_NONE;
    mPoseController.reset();
    return output;
}

void Spatializer::calculateHeadPose() {
    ALOGV("%s", __func__);
    std::lock_guard lock(mLock);
    if (mPoseController != nullptr) {
        mPoseController->calculateAsync();
    }
}

void Spatializer::engineCallback(int32_t event, void *user, void *info) {
    if (user == nullptr) {
        return;
    }
    Spatializer* const me = reinterpret_cast<Spatializer *>(user);
    switch (event) {
        case AudioEffect::EVENT_FRAMES_PROCESSED: {
            int frames = info == nullptr ? 0 : *(int*)info;
            ALOGD("%s frames processed %d for me %p", __func__, frames, me);
            if (frames > 0) {
                me->calculateHeadPose();
            }
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
