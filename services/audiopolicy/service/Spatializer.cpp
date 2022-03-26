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
#include <hardware/sensors.h>
#include <media/audiohal/EffectsFactoryHalInterface.h>
#include <media/stagefright/foundation/AHandler.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/ShmemCompat.h>
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

// ---------------------------------------------------------------------------

class Spatializer::EngineCallbackHandler : public AHandler {
public:
    EngineCallbackHandler(wp<Spatializer> spatializer)
            : mSpatializer(spatializer) {
    }

    enum {
        // Device state callbacks
        kWhatOnFramesProcessed,    // AudioEffect::EVENT_FRAMES_PROCESSED
        kWhatOnHeadToStagePose,    // SpatializerPoseController::Listener::onHeadToStagePose
        kWhatOnActualModeChange,   // SpatializerPoseController::Listener::onActualModeChange
    };
    static constexpr const char *kNumFramesKey = "numFrames";
    static constexpr const char *kModeKey = "mode";
    static constexpr const char *kTranslation0Key = "translation0";
    static constexpr const char *kTranslation1Key = "translation1";
    static constexpr const char *kTranslation2Key = "translation2";
    static constexpr const char *kRotation0Key = "rotation0";
    static constexpr const char *kRotation1Key = "rotation1";
    static constexpr const char *kRotation2Key = "rotation2";

    void onMessageReceived(const sp<AMessage> &msg) override {
        switch (msg->what()) {
            case kWhatOnFramesProcessed: {
                sp<Spatializer> spatializer = mSpatializer.promote();
                if (spatializer == nullptr) {
                    ALOGW("%s: Cannot promote spatializer", __func__);
                    return;
                }
                int numFrames;
                if (!msg->findInt32(kNumFramesKey, &numFrames)) {
                    ALOGE("%s: Cannot find num frames!", __func__);
                    return;
                }
                if (numFrames > 0) {
                    spatializer->calculateHeadPose();
                }
                } break;
            case kWhatOnHeadToStagePose: {
                sp<Spatializer> spatializer = mSpatializer.promote();
                if (spatializer == nullptr) {
                    ALOGW("%s: Cannot promote spatializer", __func__);
                    return;
                }
                std::vector<float> headToStage(sHeadPoseKeys.size());
                for (size_t i = 0 ; i < sHeadPoseKeys.size(); i++) {
                    if (!msg->findFloat(sHeadPoseKeys[i], &headToStage[i])) {
                        ALOGE("%s: Cannot find kTranslation0Key!", __func__);
                        return;
                    }
                }
                spatializer->onHeadToStagePoseMsg(headToStage);
                } break;
            case kWhatOnActualModeChange: {
                sp<Spatializer> spatializer = mSpatializer.promote();
                if (spatializer == nullptr) {
                    ALOGW("%s: Cannot promote spatializer", __func__);
                    return;
                }
                int mode;
                if (!msg->findInt32(EngineCallbackHandler::kModeKey, &mode)) {
                    ALOGE("%s: Cannot find actualMode!", __func__);
                    return;
                }
                spatializer->onActualModeChangeMsg(static_cast<HeadTrackingMode>(mode));
                } break;
            default:
                LOG_ALWAYS_FATAL("Invalid callback message %d", msg->what());
        }
    }
private:
    wp<Spatializer> mSpatializer;
};

const std::vector<const char *> Spatializer::sHeadPoseKeys = {
    Spatializer::EngineCallbackHandler::kTranslation0Key,
    Spatializer::EngineCallbackHandler::kTranslation1Key,
    Spatializer::EngineCallbackHandler::kTranslation2Key,
    Spatializer::EngineCallbackHandler::kRotation0Key,
    Spatializer::EngineCallbackHandler::kRotation1Key,
    Spatializer::EngineCallbackHandler::kRotation2Key,
};

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

void Spatializer::onFirstRef() {
    mLooper = new ALooper;
    mLooper->setName("Spatializer-looper");
    mLooper->start(
            /*runOnCallingThread*/false,
            /*canCallJava*/       false,
            PRIORITY_AUDIO);

    mHandler = new EngineCallbackHandler(this);
    mLooper->registerHandler(mHandler);
}

Spatializer::~Spatializer() {
    ALOGV("%s", __func__);
    if (mLooper != nullptr) {
        mLooper->stop();
        mLooper->unregisterHandler(mHandler->id());
    }
    mLooper.clear();
    mHandler.clear();
}

status_t Spatializer::loadEngineConfiguration(sp<EffectHalInterface> effect) {
    ALOGV("%s", __func__);

    std::vector<bool> supportsHeadTracking;
    status_t status = getHalParameter<false>(effect, SPATIALIZER_PARAM_HEADTRACKING_SUPPORTED,
                                         &supportsHeadTracking);
    if (status != NO_ERROR) {
        return status;
    }
// Disable head tracking until head sensor activity is properly controlled.
//    mSupportsHeadTracking = supportsHeadTracking[0];
    mSupportsHeadTracking = false;

    status = getHalParameter<true>(effect, SPATIALIZER_PARAM_SUPPORTED_LEVELS, &mLevels);
    if (status != NO_ERROR) {
        return status;
    }
    status = getHalParameter<true>(effect, SPATIALIZER_PARAM_SUPPORTED_SPATIALIZATION_MODES,
                                &mSpatializationModes);
    if (status != NO_ERROR) {
        return status;
    }
    return getHalParameter<true>(effect, SPATIALIZER_PARAM_SUPPORTED_CHANNEL_MASKS,
                                 &mChannelMasks);
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

Status Spatializer::isHeadTrackingSupported(bool *supports) {
    ALOGV("%s mSupportsHeadTracking %d", __func__, mSupportsHeadTracking);
    if (supports == nullptr) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    std::lock_guard lock(mLock);
    *supports = mSupportsHeadTracking;
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
        if (mHeadSensor != SpatializerPoseController::INVALID_SENSOR) {
            modes->push_back(SpatializerHeadTrackingMode::RELATIVE_WORLD);
            if (mScreenSensor != SpatializerPoseController::INVALID_SENSOR) {
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
    if (!mSupportsHeadTracking) {
        return binderStatusFromStatusT(INVALID_OPERATION);
    }
    std::lock_guard lock(mLock);
    if (mPoseController != nullptr) {
        mPoseController->recenter();
    }
    return Status::ok();
}

Status Spatializer::setGlobalTransform(const std::vector<float>& screenToStage) {
    ALOGV("%s", __func__);
    if (!mSupportsHeadTracking) {
        return binderStatusFromStatusT(INVALID_OPERATION);
    }
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
    if (!mSupportsHeadTracking) {
        return binderStatusFromStatusT(INVALID_OPERATION);
    }
    std::lock_guard lock(mLock);
    mHeadSensor = sensorHandle;
    if (mPoseController != nullptr) {
        mPoseController->setHeadSensor(mHeadSensor);
    }
    return Status::ok();
}

Status Spatializer::setScreenSensor(int sensorHandle) {
    ALOGV("%s sensorHandle %d", __func__, sensorHandle);
    if (!mSupportsHeadTracking) {
        return binderStatusFromStatusT(INVALID_OPERATION);
    }
    std::lock_guard lock(mLock);
    mScreenSensor = sensorHandle;
    if (mPoseController != nullptr) {
        mPoseController->setScreenSensor(mScreenSensor);
    }
    return Status::ok();
}

Status Spatializer::setDisplayOrientation(float physicalToLogicalAngle) {
    ALOGV("%s physicalToLogicalAngle %f", __func__, physicalToLogicalAngle);
    if (!mSupportsHeadTracking) {
        return binderStatusFromStatusT(INVALID_OPERATION);
    }
    std::lock_guard lock(mLock);
    mDisplayOrientation = physicalToLogicalAngle;
    if (mPoseController != nullptr) {
        mPoseController->setDisplayOrientation(mDisplayOrientation);
    }
    if (mEngine != nullptr) {
        setEffectParameter_l(
            SPATIALIZER_PARAM_DISPLAY_ORIENTATION, std::vector<float>{physicalToLogicalAngle});
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

Status Spatializer::registerHeadTrackingCallback(
        const sp<media::ISpatializerHeadTrackingCallback>& callback) {
    ALOGV("%s callback %p", __func__, callback.get());
    std::lock_guard lock(mLock);
    if (!mSupportsHeadTracking) {
        return binderStatusFromStatusT(INVALID_OPERATION);
    }
    mHeadTrackingCallback = callback;
    return Status::ok();
}

Status Spatializer::setParameter(int key, const std::vector<unsigned char>& value) {
    ALOGV("%s key %d", __func__, key);
    std::lock_guard lock(mLock);
    status_t status = INVALID_OPERATION;
    if (mEngine != nullptr) {
        status = setEffectParameter_l(key, value);
    }
    return binderStatusFromStatusT(status);
}

Status Spatializer::getParameter(int key, std::vector<unsigned char> *value) {
    ALOGV("%s key %d value size %d", __func__, key,
          (value != nullptr ? (int)value->size() : -1));
    if (value == nullptr) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    std::lock_guard lock(mLock);
    status_t status = INVALID_OPERATION;
    if (mEngine != nullptr) {
        ALOGV("%s key %d mEngine %p", __func__, key, mEngine.get());
        status = getEffectParameter_l(key, value);
    }
    return binderStatusFromStatusT(status);
}

Status Spatializer::getOutput(int *output) {
    ALOGV("%s", __func__);
    if (output == nullptr) {
        binderStatusFromStatusT(BAD_VALUE);
    }
    std::lock_guard lock(mLock);
    *output = VALUE_OR_RETURN_BINDER_STATUS(legacy2aidl_audio_io_handle_t_int32_t(mOutput));
    ALOGV("%s got output %d", __func__, *output);
    return Status::ok();
}

// SpatializerPoseController::Listener
void Spatializer::onHeadToStagePose(const Pose3f& headToStage) {
    ALOGV("%s", __func__);
    LOG_ALWAYS_FATAL_IF(!mSupportsHeadTracking,
            "onHeadToStagePose() called with no head tracking support!");

    auto vec = headToStage.toVector();
    LOG_ALWAYS_FATAL_IF(vec.size() != sHeadPoseKeys.size(),
            "%s invalid head to stage vector size %zu", __func__, vec.size());

    sp<AMessage> msg =
            new AMessage(EngineCallbackHandler::kWhatOnHeadToStagePose, mHandler);
    for (size_t i = 0 ; i < sHeadPoseKeys.size(); i++) {
        msg->setFloat(sHeadPoseKeys[i], vec[i]);
    }
    msg->post();
}

void Spatializer::onHeadToStagePoseMsg(const std::vector<float>& headToStage) {
    ALOGV("%s", __func__);
    sp<media::ISpatializerHeadTrackingCallback> callback;
    {
        std::lock_guard lock(mLock);
        callback = mHeadTrackingCallback;
        if (mEngine != nullptr) {
            setEffectParameter_l(SPATIALIZER_PARAM_HEAD_TO_STAGE, headToStage);
        }
    }

    if (callback != nullptr) {
        callback->onHeadToSoundStagePoseUpdated(headToStage);
    }
}

void Spatializer::onActualModeChange(HeadTrackingMode mode) {
    ALOGV("%s(%d)", __func__, (int)mode);
    sp<AMessage> msg =
            new AMessage(EngineCallbackHandler::kWhatOnActualModeChange, mHandler);
    msg->setInt32(EngineCallbackHandler::kModeKey, static_cast<int>(mode));
    msg->post();
}

void Spatializer::onActualModeChangeMsg(HeadTrackingMode mode) {
    ALOGV("%s(%d)", __func__, (int) mode);
    sp<media::ISpatializerHeadTrackingCallback> callback;
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
        callback = mHeadTrackingCallback;
    }
    if (callback != nullptr) {
        callback->onHeadTrackingModeChanged(spatializerMode);
    }
}

status_t Spatializer::attachOutput(audio_io_handle_t output) {
    std::shared_ptr<SpatializerPoseController> poseController;
    bool outputChanged = false;
    sp<media::INativeSpatializerCallback> callback;

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
        outputChanged = mOutput != output;
        mOutput = output;

        if (mSupportsHeadTracking) {
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
        callback = mSpatializerCallback;
    }
    if (poseController != nullptr) {
        poseController->waitUntilCalculated();
    }

    if (outputChanged && callback != nullptr) {
        callback->onOutputChanged(output);
    }

    return NO_ERROR;
}

audio_io_handle_t Spatializer::detachOutput() {
    audio_io_handle_t output = AUDIO_IO_HANDLE_NONE;
    sp<media::INativeSpatializerCallback> callback;

    {
        std::lock_guard lock(mLock);
        ALOGV("%s mOutput %d", __func__, (int)mOutput);
        if (mOutput == AUDIO_IO_HANDLE_NONE) {
            return output;
        }
        // remove FX instance
        mEngine->setEnabled(false);
        mEngine.clear();
        output = mOutput;
        mOutput = AUDIO_IO_HANDLE_NONE;
        mPoseController.reset();

        callback = mSpatializerCallback;
    }

    if (callback != nullptr) {
        callback->onOutputChanged(AUDIO_IO_HANDLE_NONE);
    }
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
            // ALOGD("%s frames processed %d for me %p", __func__, frames, me);
            me->postFramesProcessedMsg(frames);
        } break;
        default:
            ALOGD("%s event %d", __func__, event);
            break;
    }
}

void Spatializer::postFramesProcessedMsg(int frames) {
    sp<AMessage> msg =
            new AMessage(EngineCallbackHandler::kWhatOnFramesProcessed, mHandler);
    msg->setInt32(EngineCallbackHandler::kNumFramesKey, frames);
    msg->post();
}

} // namespace android
