/*
 * Copyright (C) 2014 The Android Open Source Project
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

#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <future>

#include <android-base/thread_annotations.h>
#include <audio_utils/mutex.h>
#include <cutils/misc.h>
#include <media/AudioEffect.h>
#include <media/audiohal/EffectsFactoryHalInterface.h>
#include <system/audio.h>
#include <utils/Vector.h>
#include <utils/SortedVector.h>

namespace android {

// ----------------------------------------------------------------------------

/**
 * AudioPolicyEffects class.
 *
 * This class manages all effects attached to input and output streams in AudioPolicyService.
 * The effect configurations can be queried in several ways:
 *
 * With HIDL HAL, the configuration file `audio_effects.xml` will be loaded by libAudioHal. If this
 * file does not exist, AudioPolicyEffects class will fallback to load configuration from
 * `/vendor/etc/audio_effects.conf` (AUDIO_EFFECT_VENDOR_CONFIG_FILE). If this file also does not
 * exist, the configuration will be loaded from the file `/system/etc/audio_effects.conf`.
 *
 * With AIDL HAL, the configuration will be queried with the method `IFactory::queryProcessing()`.
 */
class AudioPolicyEffects : public RefBase
{

public:

    // The constructor will parse audio_effects.conf
    // First it will look whether vendor specific file exists,
    // otherwise it will parse the system default file.
    explicit AudioPolicyEffects(const sp<EffectsFactoryHalInterface>& effectsFactoryHal);

    // NOTE: methods on AudioPolicyEffects should never be called with the AudioPolicyService
    // main mutex (mMutex) held as they will indirectly call back into AudioPolicyService when
    // managing audio effects.

    // Return a list of effect descriptors for default input effects
    // associated with audioSession
    status_t queryDefaultInputEffects(audio_session_t audioSession,
                             effect_descriptor_t *descriptors,
                             uint32_t* count) EXCLUDES_AudioPolicyEffects_Mutex;

    // Add all input effects associated with this input
    // Effects are attached depending on the audio_source_t
    status_t addInputEffects(audio_io_handle_t input,
                             audio_source_t inputSource,
                             audio_session_t audioSession) EXCLUDES_AudioPolicyEffects_Mutex;

    // Add all input effects associated to this input
    status_t releaseInputEffects(audio_io_handle_t input,
                                 audio_session_t audioSession) EXCLUDES_AudioPolicyEffects_Mutex;

    // Return a list of effect descriptors for default output effects
    // associated with audioSession
    status_t queryDefaultOutputSessionEffects(audio_session_t audioSession,
                             effect_descriptor_t *descriptors,
                             uint32_t* count) EXCLUDES_AudioPolicyEffects_Mutex;

    // Add all output effects associated to this output
    // Effects are attached depending on the audio_stream_type_t
    status_t addOutputSessionEffects(audio_io_handle_t output,
                             audio_stream_type_t stream,
                             audio_session_t audioSession) EXCLUDES_AudioPolicyEffects_Mutex;

    // release all output effects associated with this output stream and audiosession
    status_t releaseOutputSessionEffects(audio_io_handle_t output,
                             audio_stream_type_t stream,
                             audio_session_t audioSession) EXCLUDES_AudioPolicyEffects_Mutex;

    // Add the effect to the list of default effects for sources of type |source|.
    status_t addSourceDefaultEffect(const effect_uuid_t *type,
                                    const String16& opPackageName,
                                    const effect_uuid_t *uuid,
                                    int32_t priority,
                                    audio_source_t source,
                                    audio_unique_id_t* id) EXCLUDES_AudioPolicyEffects_Mutex;

    // Add the effect to the list of default effects for streams of a given usage.
    status_t addStreamDefaultEffect(const effect_uuid_t *type,
                                    const String16& opPackageName,
                                    const effect_uuid_t *uuid,
                                    int32_t priority,
                                    audio_usage_t usage,
                                    audio_unique_id_t* id) EXCLUDES_AudioPolicyEffects_Mutex;

    // Remove the default source effect from wherever it's attached.
    status_t removeSourceDefaultEffect(audio_unique_id_t id) EXCLUDES_AudioPolicyEffects_Mutex;

    // Remove the default stream effect from wherever it's attached.
    status_t removeStreamDefaultEffect(audio_unique_id_t id) EXCLUDES_AudioPolicyEffects_Mutex;

    // Initializes the Effects (AudioSystem must be ready as this creates audio client objects).
    void initDefaultDeviceEffects() EXCLUDES(mDeviceEffectsMutex) EXCLUDES_EffectHandle_Mutex;

private:

    // class to store the description of an effects and its parameters
    // as defined in audio_effects.conf
    class EffectDesc {
    public:
        EffectDesc(std::string_view name,
                   const effect_uuid_t& typeUuid,
                   const String16& opPackageName,
                   const effect_uuid_t& uuid,
                   uint32_t priority,
                   audio_unique_id_t id) :
                        mName(name),
                        mTypeUuid(typeUuid),
                        mOpPackageName(opPackageName),
                        mUuid(uuid),
                        mPriority(priority),
                        mId(id) { }
        // Modern EffectDesc usage:
        EffectDesc(std::string_view name, const effect_uuid_t& uuid) :
                        EffectDesc(name,
                                   *EFFECT_UUID_NULL,
                                   String16(""),
                                   uuid,
                                   0,
                                   AUDIO_UNIQUE_ID_ALLOCATE) { }
        EffectDesc(const EffectDesc& orig) :
                        mName(orig.mName),
                        mTypeUuid(orig.mTypeUuid),
                        mOpPackageName(orig.mOpPackageName),
                        mUuid(orig.mUuid),
                        mPriority(orig.mPriority),
                        mId(orig.mId),
                        mParams(orig.mParams) { }

        const std::string mName;
        const effect_uuid_t mTypeUuid;
        const String16 mOpPackageName;
        const effect_uuid_t mUuid;
        const int32_t mPriority;
        const audio_unique_id_t mId;
        std::vector<std::shared_ptr<const effect_param_t>> mParams;
    };

    using EffectDescVector = std::vector<std::shared_ptr<EffectDesc>>;

    class EffectVector {
    public:
        explicit EffectVector(audio_session_t session) : mSessionId(session) {}

        // Enable or disable all effects in effect vector
        void setProcessorEnabled(bool enabled);

        const audio_session_t mSessionId;
        // AudioPolicyManager keeps mMutex, no need for lock on reference count here
        int mRefCount = 0;
        std::vector<sp<AudioEffect>> mEffects;
    };

    /**
     * @brief The DeviceEffects class stores the effects associated to a given Device Port.
     */
    class DeviceEffects {
    public:
        DeviceEffects(std::unique_ptr<EffectDescVector> effectDescriptors,
                               audio_devices_t device, std::string_view address) :
            mEffectDescriptors(std::move(effectDescriptors)),
            mDeviceType(device), mDeviceAddress(address) {}

        std::vector<sp<AudioEffect>> mEffects;
        audio_devices_t getDeviceType() const { return mDeviceType; }
        std::string getDeviceAddress() const { return mDeviceAddress; }
        const std::unique_ptr<EffectDescVector> mEffectDescriptors;

    private:
        const audio_devices_t mDeviceType;
        const std::string mDeviceAddress;

    };

    status_t loadAudioEffectConfig_ll(const sp<EffectsFactoryHalInterface>& effectsFactoryHal)
            REQUIRES(mMutex, mDeviceEffectsMutex);

    // Legacy: Begin methods below.
    // Parse audio_effects.conf - called from constructor.
    status_t loadAudioEffectConfigLegacy_l(const char* path) REQUIRES(mMutex);

    // Legacy: Load all automatic effect configurations
    status_t loadInputEffectConfigurations_l(cnode* root,
            const EffectDescVector& effects) REQUIRES(mMutex);
    status_t loadStreamEffectConfigurations_l(cnode* root,
            const EffectDescVector& effects) REQUIRES(mMutex);

    // Legacy: static methods below.

    static audio_source_t inputSourceNameToEnum(const char *name);

    static audio_stream_type_t streamNameToEnum(const char* name);

    // Load all effects descriptors in configuration file
    static EffectDescVector loadEffects(cnode* root);
    static std::shared_ptr<AudioPolicyEffects::EffectDesc> loadEffect(cnode* root);
    static std::shared_ptr<EffectDescVector> loadEffectConfig(cnode* root,
            const EffectDescVector& effects);

    // Load all automatic effect parameters
    static void loadEffectParameters(
            cnode* root, std::vector<std::shared_ptr<const effect_param_t>>& params);

    // loadEffectParameter returns a shared_ptr instead of a unique_ptr as there may
    // be multiple references to the same effect parameter.
    static std::shared_ptr<const effect_param_t> loadEffectParameter(cnode* root);
    static size_t readParamValue(cnode* node,
                          char **param,
                          size_t *curSize,
                          size_t *totSize);
    static size_t growParamSize(char** param,
                         size_t size,
                         size_t *curSize,
                         size_t *totSize);

    // Legacy: End methods above.

    // Note: The association of Effects to audio source, session, or stream
    // is done through std::map instead of std::unordered_map.  This gives
    // better reproducibility of issues, since map is ordered and more predictable
    // in enumeration.

    // protects access to mInputSources, mInputSessions, mOutputStreams, mOutputSessions
    // never hold AudioPolicyService::mMutex when calling AudioPolicyEffects methods as
    // those can call back into AudioPolicyService methods and try to acquire the mutex
    mutable audio_utils::mutex mMutex{audio_utils::MutexOrder::kAudioPolicyEffects_Mutex};
    // Automatic input effects are configured per audio_source_t
    std::map<audio_source_t, std::shared_ptr<EffectDescVector>> mInputSources
            GUARDED_BY(mMutex);
    // Automatic input effects are unique for an audio_session_t.
    std::map<audio_session_t, std::shared_ptr<EffectVector>> mInputSessions
            GUARDED_BY(mMutex);

    // Automatic output effects are organized per audio_stream_type_t
    std::map<audio_stream_type_t, std::shared_ptr<EffectDescVector>> mOutputStreams
            GUARDED_BY(mMutex);
    // Automatic output effects are unique for an audio_session_t.
    std::map<audio_session_t, std::shared_ptr<EffectVector>> mOutputSessions
            GUARDED_BY(mMutex);

    /**
     * @brief mDeviceEffects map of device effects indexed by the device address
     */

    // mDeviceEffects is never accessed through AudioPolicyEffects methods.
    // We keep a separate mutex here to catch future methods attempting to access this variable.
    std::mutex mDeviceEffectsMutex;
    std::map<std::string, std::unique_ptr<DeviceEffects>> mDeviceEffects
            GUARDED_BY(mDeviceEffectsMutex);
};

} // namespace android
