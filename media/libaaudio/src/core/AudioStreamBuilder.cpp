/*
 * Copyright 2015 The Android Open Source Project
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

#define LOG_TAG "AudioStreamBuilder"
//#define LOG_NDEBUG 0

#include "AudioStreamBuilder.h"

// go/keep-sorted start
#include <aaudio/AAudio.h>
#include <aaudio/AAudioTesting.h>
#include <android/media/audio/common/AudioMMapPolicy.h>
#include <android/media/audio/common/AudioMMapPolicyInfo.h>
#include <android/media/audio/common/AudioMMapPolicyType.h>
#include <android_media_audio.h>
#include <binding/AAudioBinderClient.h>
#include <client/AudioStreamInternalCapture.h>
#include <client/AudioStreamInternalPlay.h>
#include <core/AudioStream.h>
#include <legacy/AudioStreamRecord.h>
#include <legacy/AudioStreamTrack.h>
#include <media/AudioSystem.h>
#include <system/aaudio/AAudio.h>
#include <utility/AAudioUtilities.h>
#include <utility/AudioGlobal.h>
#include <utils/Log.h>
// go/keep-sorted end

// go/keep-sorted start
#include <new>
#include <numeric>
#include <stdint.h>
#include <vector>
// go/keep-sorted end

using namespace aaudio;

using android::media::audio::common::AudioMMapPolicy;
using android::media::audio::common::AudioMMapPolicyInfo;
using android::media::audio::common::AudioMMapPolicyType;

#define AAUDIO_MMAP_POLICY_DEFAULT             AAUDIO_POLICY_NEVER
#define AAUDIO_MMAP_EXCLUSIVE_POLICY_DEFAULT   AAUDIO_POLICY_NEVER
#define AAUDIO_MMAP_POLICY_DEFAULT_AIDL        AudioMMapPolicy::NEVER
#define AAUDIO_MMAP_EXCLUSIVE_POLICY_DEFAULT_AIDL AudioMMapPolicy::NEVER

/*
 * AudioStreamBuilder
 */
static aaudio_result_t builder_createStream(aaudio_direction_t direction,
                                            aaudio_sharing_mode_t /*sharingMode*/,
                                            bool tryMMap,
                                            android::sp<AudioStream> &stream) {
    aaudio_result_t result = AAUDIO_OK;

    switch (direction) {

        case AAUDIO_DIRECTION_INPUT:
            if (tryMMap) {
                stream = new AudioStreamInternalCapture(AAudioBinderClient::getInstance(),
                                                                 false);
            } else {
                stream = new AudioStreamRecord();
            }
            break;

        case AAUDIO_DIRECTION_OUTPUT:
            if (tryMMap) {
                stream = new AudioStreamInternalPlay(AAudioBinderClient::getInstance(),
                                                              false);
            } else {
                stream = new AudioStreamTrack();
            }
            break;

        default:
            ALOGE("%s() bad direction = %d", __func__, direction);
            result = AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }
    return result;
}

AudioStreamBuilder* AudioStreamBuilder::setRoutingChangedCallbackProc(
        AAudioStream_routingChangedCallback proc) {
    if (!android_media_audio_partial_flush_for_pcm_offload()) {
        ALOGI("%s, ignored as the feature flag is not enabled.", __func__);
        return this;
    }
    mRoutingChangedCallbackProc = proc;
    return this;
}

AudioStreamBuilder* AudioStreamBuilder::setRoutingChangedCallbackUserData(void *userData) {
    if (!android_media_audio_partial_flush_for_pcm_offload()) {
        ALOGI("%s, ignored as the feature flag is not enabled.", __func__);
        return this;
    }
    mRoutingChangedCallbackUserData = userData;
    return this;
}

// Try to open using MMAP path if that is allowed.
// Fall back to Legacy path if MMAP not available.
// Exact behavior is controlled by MMapPolicy.
aaudio_result_t AudioStreamBuilder::build(AudioStream** streamPtr) {

    if (streamPtr == nullptr) {
        ALOGE("%s() streamPtr is null", __func__);
        return AAUDIO_ERROR_NULL;
    }
    *streamPtr = nullptr;

    logParameters();

    aaudio_result_t result = validate();
    if (result != AAUDIO_OK) {
        return result;
    }

    std::vector<AudioMMapPolicyInfo> policyInfos;
    aaudio_policy_t mmapPolicy = AudioGlobal_getMMapPolicy();
    ALOGD("%s, global mmap policy is %d", __func__, mmapPolicy);
    if (status_t status = android::AudioSystem::getMmapPolicyInfos(
            AudioMMapPolicyType::DEFAULT, &policyInfos); status == NO_ERROR) {
        aaudio_policy_t systemMmapPolicy = AAudio_getAAudioPolicy(
                policyInfos, AAUDIO_MMAP_POLICY_DEFAULT_AIDL);
        ALOGD("%s, system mmap policy is %d", __func__, systemMmapPolicy);
        if (mmapPolicy == AAUDIO_POLICY_ALWAYS && systemMmapPolicy == AAUDIO_POLICY_NEVER) {
            // No need to try as AAudioService is not created and the client only wants MMAP path.
            return AAUDIO_ERROR_NO_SERVICE;
        }
        // Use system property for mmap policy if
        //    1. The API setting does not specify mmap policy or
        //    2. The system property specifies MMAP policy as never. In this case, AAudioService
        //       will not be started, no need to try mmap path.
        if (mmapPolicy == AAUDIO_UNSPECIFIED || systemMmapPolicy == AAUDIO_POLICY_NEVER) {
            mmapPolicy = systemMmapPolicy;
        }
    } else {
        ALOGD("%s, failed to query system mmap policy, error=%d", __func__, status);
        // If it fails querying mmap policy info, it is highly possible that the AAudioService is
        // not created. In this case, we don't try mmap path.
        if (mmapPolicy == AAUDIO_POLICY_ALWAYS) {
            return AAUDIO_ERROR_NO_SERVICE;
        }
        mmapPolicy = AAUDIO_POLICY_NEVER;
    }
    // If still not specified then use the default.
    if (mmapPolicy == AAUDIO_UNSPECIFIED) {
        mmapPolicy = AAUDIO_MMAP_POLICY_DEFAULT;
    }
    ALOGD("%s, final mmap policy is %d", __func__, mmapPolicy);

    policyInfos.clear();
    aaudio_policy_t mmapExclusivePolicy = AAUDIO_UNSPECIFIED;
    if (status_t status = android::AudioSystem::getMmapPolicyInfos(
            AudioMMapPolicyType::EXCLUSIVE, &policyInfos); status == NO_ERROR) {
        mmapExclusivePolicy = AAudio_getAAudioPolicy(
                policyInfos, AAUDIO_MMAP_EXCLUSIVE_POLICY_DEFAULT_AIDL);
        ALOGD("%s, system mmap exclusive policy is %d", __func__, mmapExclusivePolicy);
    } else {
        ALOGD("%s, failed to query mmap exclusive policy, error=%d", __func__, status);
    }
    if (mmapExclusivePolicy == AAUDIO_UNSPECIFIED) {
        mmapExclusivePolicy = AAUDIO_MMAP_EXCLUSIVE_POLICY_DEFAULT;
    }
    ALOGD("%s, final mmap exclusive policy is %d", __func__, mmapExclusivePolicy);

    aaudio_sharing_mode_t sharingMode = getSharingMode();
    if ((sharingMode == AAUDIO_SHARING_MODE_EXCLUSIVE)
        && (mmapExclusivePolicy == AAUDIO_POLICY_NEVER)) {
        ALOGD("%s() EXCLUSIVE sharing mode not supported. Use SHARED.", __func__);
        sharingMode = AAUDIO_SHARING_MODE_SHARED;
        setSharingMode(sharingMode);
    }

    bool allowMMap = mmapPolicy != AAUDIO_POLICY_NEVER;
    bool allowLegacy = mmapPolicy != AAUDIO_POLICY_ALWAYS;

    // TODO Support other performance settings in MMAP mode.
    // Disable MMAP if low latency or power saving offloaded is not requested.
    if (getPerformanceMode() != AAUDIO_PERFORMANCE_MODE_LOW_LATENCY &&
        getPerformanceMode() != AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED) {
        ALOGD("%s() MMAP not used because AAUDIO_PERFORMANCE_MODE_LOW_LATENCY or "
              "AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED not requested.",
              __func__);
        allowMMap = false;
    }
    if (!audio_is_linear_pcm(getFormat())) {
        ALOGD("%s() MMAP not used because the requested format(%#x) is not pcm",
              __func__, getFormat());
        allowMMap = false;
    }

    // SessionID and Effects are only supported in legacy mode and mmap offload mode.
    if (getSessionId() != AAUDIO_SESSION_ID_NONE &&
        getPerformanceMode() != AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED) {
        ALOGD("%s() MMAP not used because sessionId specified.", __func__);
        allowMMap = false;
    }

    if (getFormat() == AUDIO_FORMAT_IEC61937) {
        ALOGD("%s IEC61937 format is selected, do not allow MMAP in this case.", __func__);
        allowMMap = false;
    }

    if (!allowMMap && !allowLegacy) {
        ALOGE("%s() no backend available: neither MMAP nor legacy path are allowed", __func__);
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }

    setPrivacySensitive(false);
    if (mPrivacySensitiveReq == PRIVACY_SENSITIVE_DEFAULT) {
        // When not explicitly requested, set privacy sensitive mode according to input preset:
        // communication and camcorder captures are considered privacy sensitive by default.
        aaudio_input_preset_t preset = getInputPreset();
        if (preset == AAUDIO_INPUT_PRESET_CAMCORDER
                || preset == AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION) {
            setPrivacySensitive(true);
        }
    } else if (mPrivacySensitiveReq == PRIVACY_SENSITIVE_ENABLED) {
        setPrivacySensitive(true);
    }

    android::sp<AudioStream> audioStream;
    result = builder_createStream(getDirection(), sharingMode, allowMMap, audioStream);
    if (result == AAUDIO_OK) {
        // Open the stream using the parameters from the builder.
        result = audioStream->open(*this);
        if (result != AAUDIO_OK) {
            bool isMMap = audioStream->isMMap();
            if (isMMap && allowLegacy) {
                ALOGV("%s() MMAP stream did not open so try Legacy path", __func__);
                // If MMAP stream failed to open then TRY using a legacy stream.
                result = builder_createStream(getDirection(), sharingMode,
                                              false, audioStream);
                if (result == AAUDIO_OK) {
                    result = audioStream->open(*this);
                }
            }
        }
        if (result == AAUDIO_OK) {
            audioStream->registerPlayerBase();
            audioStream->logOpenActual();
            *streamPtr = startUsingStream(audioStream);
        } // else audioStream will go out of scope and be deleted
    }

    return result;
}

AudioStream *AudioStreamBuilder::startUsingStream(android::sp<AudioStream> &audioStream) {
    // Increment the smart pointer so it will not get deleted when
    // we pass it to the C caller and it goes out of scope.
    // The C code cannot hold a smart pointer so we increment the reference
    // count to indicate that the C app owns a reference.
    audioStream->incStrong(nullptr);
    return audioStream.get();
}

void AudioStreamBuilder::stopUsingStream(AudioStream *stream) {
    // Undo the effect of startUsingStream()
    android::sp<AudioStream> spAudioStream(stream);
    ALOGV("%s() strongCount = %d", __func__, spAudioStream->getStrongCount());
    spAudioStream->decStrong(nullptr);
}

aaudio_result_t AudioStreamBuilder::addTag(const char* tag) {
    const std::string tagStr(tag);
    mTags.insert(tagStr);
    // The tags will be joined with `;` and ended with null terminator when sending to the HAL.
    const int tagsLength = std::accumulate(
            mTags.begin(), mTags.end(), 0, [](int v, const std::string& s) { return v + s.size(); })
            + mTags.size();
    if (tagsLength <= AUDIO_ATTRIBUTES_TAGS_MAX_SIZE) {
        return AAUDIO_OK;
    }
    mTags.erase(tagStr);
    return AAUDIO_ERROR_OUT_OF_RANGE;
}

void AudioStreamBuilder::clearTags() {
    mTags.clear();
}

static const char *AAudio_convertSharingModeToShortText(aaudio_sharing_mode_t sharingMode) {
    switch (sharingMode) {
        case AAUDIO_SHARING_MODE_EXCLUSIVE:
            return "EX";
        case AAUDIO_SHARING_MODE_SHARED:
            return "SH";
        default:
            return "?!";
    }
}

static const char *AAudio_convertDirectionToText(aaudio_direction_t direction) {
    switch (direction) {
        case AAUDIO_DIRECTION_OUTPUT:
            return "OUTPUT";
        case AAUDIO_DIRECTION_INPUT:
            return "INPUT";
        default:
            return "?!";
    }
}

void AudioStreamBuilder::logParameters() const {
    // This is very helpful for debugging in the future. Please leave it in.
    ALOGI("rate   = %6d, channels  = %d, channelMask = %#x, format   = %#x, sharing = %s, dir = %s",
          getSampleRate(), getSamplesPerFrame(), getChannelMask(), getFormat(),
          AAudio_convertSharingModeToShortText(getSharingMode()),
          AAudio_convertDirectionToText(getDirection()));
    ALOGI("devices = %s, sessionId = %d, perfMode = %d, callback: %s with frames = %d",
          android::toString(getDeviceIds()).c_str(),
          getSessionId(),
          getPerformanceMode(),
          ((getPartialDataCallbackProc() != nullptr) ? "ON_P"
                                                     : (getDataCallbackProc() != nullptr) ? "ON"
                                                                                          : "OFF"),
          mFramesPerDataCallback);
    ALOGI("usage  = %6d, contentType = %d, inputPreset = %d, allowedCapturePolicy = %d",
          getUsage(), getContentType(), getInputPreset(), getAllowedCapturePolicy());
    ALOGI("privacy sensitive = %s, opPackageName = %s, attributionTag = %s",
          isPrivacySensitive() ? "true" : "false",
          !getOpPackageName().has_value() ? "(null)" : getOpPackageName().value().c_str(),
          !getAttributionTag().has_value() ? "(null)" : getAttributionTag().value().c_str());
}
