/*
 * Copyright (C) 2021 The Android Open Source Project
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

#ifndef ANDROID_MEDIA_SPATIALIZER_H
#define ANDROID_MEDIA_SPATIALIZER_H

#include <android/media/BnEffect.h>
#include <android/media/BnSpatializer.h>
#include <android/media/HeadTrackingMode.h>
#include <android/media/SpatializationLevel.h>

#include <media/AudioEffect.h>
#include <system/audio_effects/effect_virtualizer_stage.h>


namespace android {


// ----------------------------------------------------------------------------

/**
 * A callback interface from the Spatializer object or its parent AudioPolicyService.
 * This is implemented by the audio policy service hosting the Spatializer to perform
 * actions needed when a state change inside the Spatializer requires some audio system
 * changes that cannot be performed by the Spatializer. For instance opening or closing a
 * spatializer output stream when the spatializer is enabled or disabled
 */
class SpatializerPolicyCallback {
public:
    /** Called when a stage change occurs that requires the parent audio policy service to take
     * some action.
     */
    virtual void onCheckSpatializer() = 0;

    virtual ~SpatializerPolicyCallback() = default;
};
/**
 * The Spatializer class implements all functional controlling the multichannel spatializer
 * with head tracking implementation in the native audio service: audio policy and audio flinger.
 * It presents an AIDL interface available to the java audio service to discover the availability
 * of the feature and options, control its state and register an active head tracking sensor.
 * It maintains the current state of the platform spatializer and applies the stored parameters
 * when the spatializer engine is created and enabled.
 * Based on the requested spatializer level, it will request the creation of a specialized output
 * mixer to the audio policy service which will in turn notify the Spatializer of the output
 * stream on which a spatializer engine should be created, configured and enabled.
 * The spatializer also hosts the head tracking management logic. This logic receives the
 * desired head tracking mode and selected head tracking sensor, registers a sensor event listener
 * and derives the compounded head pose information to the spatializer engine.
 *
 * Workflow:
 * - Initialization: when the audio policy service starts, it checks if a spatializer effect
 * engine exists and if the audio policy manager reports a dedicated spatializer output profile.
 * If both conditions are met, a Spatializer object is created
 * - Capabilities discovery: AudioService will call AudioSystem::canBeSpatialized() and if true,
 * acquire an ISpatializer interface with AudioSystem::getSpatializer(). This interface
 * will be used to query the implementation capabilities and configure the spatializer.
 * - Enabling: when ISpatializer::setLevel() sets a level different from NONE the spatializer
 * is considered enabled. The audio policy callback onCheckSpatializer() is called. This
 * triggers a request to audio policy manager to open a spatialization output stream and a
 * spatializer mixer is created in audio flinger. When an output is returned by audio policy
 * manager, Spatializer::attachOutput() is called which creates and enables the spatializer
 * stage engine on the specified output.
 * - Disabling: when the spatialization level is set to NONE, the spatializer is considered
 * disabled. The audio policy callback onCheckSpatializer() is called. This triggers a call
 * to Spatializer::detachOutput() and the spatializer engine is released. Then a request is
 * made to audio policy manager to release and close the spatializer output stream and the
 * spatializer mixer thread is destroyed.
 */
class Spatializer : public media::BnSpatializer, public IBinder::DeathRecipient {
public:

    static sp<Spatializer> create(SpatializerPolicyCallback *callback);

           ~Spatializer() override;

    /** ISpatializer, see ISpatializer.aidl */
    binder::Status release() override;
    binder::Status getSupportedLevels(std::vector<media::SpatializationLevel>* levels) override;
    binder::Status setLevel(media::SpatializationLevel level) override;
    binder::Status getLevel(media::SpatializationLevel *level) override;
    binder::Status getSupportedHeadTrackingModes(
            std::vector<media::HeadTrackingMode>* modes) override;
    binder::Status setDesiredHeadTrackingMode(media::HeadTrackingMode mode) override;
    binder::Status getActualHeadTrackingMode(media::HeadTrackingMode *mode) override;
    binder::Status recenterHeadtracker() override;
    binder::Status setGlobalTransform(const std::vector<float>& screenToStage) override;

    /** IBinder::DeathRecipient. Listen to the death of the INativeSpatializerCallback. */
    virtual void binderDied(const wp<IBinder>& who);

    /** Registers a INativeSpatializerCallback when a client is attached to this Spatializer
     * by audio policy service.
     */
    status_t registerCallback(const sp<media::INativeSpatializerCallback>& callback);

    /** Level getter for use by local classes. */
    media::SpatializationLevel getLevel() const { Mutex::Autolock _l(mLock); return mLevel; }

    /** Called by audio policy service when the special output mixer dedicated to spatialization
     * is opened and the spatializer engine must be created.
     */
    status_t attachOutput(audio_io_handle_t output);
    /** Called by audio policy service when the special output mixer dedicated to spatialization
     * is closed and the spatializer engine must be release.
     */
    audio_io_handle_t detachOutput();
    /** Returns the output stream the spatializer is attached to. */
    audio_io_handle_t getOutput() const { Mutex::Autolock _l(mLock); return mOutput; }

    /** Sets the channel mask, sampling rate and format for the spatializer input. */
    void setAudioInConfig(const audio_config_base_t& config) {
        Mutex::Autolock _l(mLock);
        mAudioInConfig = config;
    }

    /** Gets the channel mask, sampling rate and format set for the spatializer input. */
    audio_config_base_t getAudioInConfig() const {
        Mutex::Autolock _l(mLock);
        return mAudioInConfig;
    }

    /** An implementation of an IEffect interface that can be used to pass advanced parameters to
     * the spatializer engine. All APis are noop (i.e. the interface cannot be used to control
     * the effect) except for passing parameters via the command() API. */
    class EffectClient: public android::media::BnEffect {
    public:

        EffectClient(const sp<media::IEffectClient>& effectClient,
                     Spatializer& parent);
        virtual ~EffectClient();

        // IEffect
        android::binder::Status enable(int32_t* _aidl_return) override;
        android::binder::Status disable(int32_t* _aidl_return) override;
        android::binder::Status command(int32_t cmdCode,
                                        const std::vector<uint8_t>& cmdData,
                                        int32_t maxResponseSize,
                                        std::vector<uint8_t>* response,
                                        int32_t* _aidl_return) override;
        android::binder::Status disconnect() override;
        android::binder::Status getCblk(media::SharedFileRegion* _aidl_return) override;

    private:
        const sp<media::IEffectClient> mEffectClient;
        sp<IMemory> mCblkMemory;
        const Spatializer& mParent;
        bool mDisconnected = false;
    };

private:

    Spatializer(effect_descriptor_t engineDescriptor,
                     SpatializerPolicyCallback *callback);


    static void engineCallback(int32_t event, void* user, void *info);

    /** Effect engine descriptor */
    const effect_descriptor_t mEngineDescriptor;
    /** Callback interface to parent audio policy service */
    SpatializerPolicyCallback* mPolicyCallback;

    /** Mutex protecting internal state */
    mutable Mutex mLock;

    /** Client AudioEffect for the engine */
    sp<AudioEffect> mEngine GUARDED_BY(mLock);
    /** Output stream the spatializer mixer thread is attached to */
    audio_io_handle_t mOutput GUARDED_BY(mLock) = AUDIO_IO_HANDLE_NONE;
    /** Virtualizer engine input configuration */
    audio_config_base_t mAudioInConfig GUARDED_BY(mLock) = AUDIO_CONFIG_BASE_INITIALIZER;

    /** Callback interface to the client (AudioService) controlling this`Spatializer */
    sp<media::INativeSpatializerCallback> mSpatializerCallback GUARDED_BY(mLock);

    /** Requested spatialization level */
    media::SpatializationLevel mLevel GUARDED_BY(mLock) = media::SpatializationLevel::NONE;
    /** Requested head tracking mode */
    media::HeadTrackingMode mHeadTrackingMode GUARDED_BY(mLock)
            = media::HeadTrackingMode::DISABLED;
    /** Configured screen to stage transform */
    std::vector<float> mScreenToStageTransform GUARDED_BY(mLock);

    /** Extended IEffect interface is one has been created */
    sp<EffectClient> mEffectClient GUARDED_BY(mLock);
};


}; // namespace android

#endif // ANDROID_MEDIA_SPATIALIZER_H
