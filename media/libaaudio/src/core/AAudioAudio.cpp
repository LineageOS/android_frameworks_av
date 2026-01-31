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

#define LOG_TAG "AAudio"
//#define LOG_NDEBUG 0

// go/keep-sorted start
#include <aaudio/AAudio.h>
#include <aaudio/AAudioTesting.h>
#include <binding/AAudioCommon.h>
#include <client/AudioStreamInternal.h>
#include <com_android_media_audioserver.h>
#include <core/AudioStream.h>
#include <core/AudioStreamBuilder.h>
#include <system/aaudio/AAudio.h>
#include <system/audio.h>
#include <utility/AudioClock.h>
#include <utility/AudioGlobal.h>
#include <utils/Log.h>
// go/keep-sorted end

// go/keep-sorted start
#include <inttypes.h>
#include <mutex>
#include <pthread.h>
#include <time.h>
// go/keep-sorted end

using namespace aaudio;

// Macros for common code that includes a return.
// TODO Consider using do{}while(0) construct. I tried but it hung AndroidStudio
#define CONVERT_BUILDER_HANDLE_OR_RETURN() \
    convertAAudioBuilderToStreamBuilder(builder);

#define COMMON_GET_FROM_BUILDER_OR_RETURN(resultPtr) \
    CONVERT_BUILDER_HANDLE_OR_RETURN() \
    if ((resultPtr) == nullptr) { \
        return AAUDIO_ERROR_NULL; \
    }

AAUDIO_API const char * AAudio_convertResultToText(aaudio_result_t returnCode) {
    return AudioGlobal_convertResultToText(returnCode);
}

AAUDIO_API const char * AAudio_convertStreamStateToText(aaudio_stream_state_t state) {
    return AudioGlobal_convertStreamStateToText(state);
}

AAUDIO_API aaudio_policy_t AAudio_getPlatformMMapPolicy(
        AAudio_DeviceType device, aaudio_direction_t direction) {
    return AudioGlobal_getPlatformMMapPolicy(device, direction);
}

AAUDIO_API aaudio_policy_t AAudio_getPlatformMMapExclusivePolicy(
        AAudio_DeviceType device, aaudio_direction_t direction) {
    return AudioGlobal_getPlatformMMapExclusivePolicy(device, direction);
}

static AudioStream *convertAAudioStreamToAudioStream(AAudioStream* stream)
{
    return (AudioStream*) stream;
}

static AudioStreamBuilder *convertAAudioBuilderToStreamBuilder(AAudioStreamBuilder* builder)
{
    return (AudioStreamBuilder*) builder;
}

AAUDIO_API AAudio_FlushFromFrameSupport AAudio_getFlushFromFrameSupport(
        const AAudioStreamBuilder* builder) {
    const AudioStreamBuilder* streamBuilder = reinterpret_cast<const AudioStreamBuilder*>(builder);
    return AudioStream::getFlushFromFrameSupport(*streamBuilder);
}

AAUDIO_API aaudio_result_t AAudio_createStreamBuilder(AAudioStreamBuilder** builder)
{
    AudioStreamBuilder *audioStreamBuilder =  new(std::nothrow) AudioStreamBuilder();
    if (audioStreamBuilder == nullptr) {
        return AAUDIO_ERROR_NO_MEMORY;
    }
    *builder = (AAudioStreamBuilder*) audioStreamBuilder;
    return AAUDIO_OK;
}

AAUDIO_API void AAudioStreamBuilder_setPerformanceMode(AAudioStreamBuilder* builder,
                                                       aaudio_performance_mode_t mode)
{
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setPerformanceMode(mode);
}

AAUDIO_API void AAudioStreamBuilder_setDeviceId(AAudioStreamBuilder* builder,
                                                int32_t deviceId)
{
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    android::DeviceIdVector deviceIds;
    if (deviceId != AAUDIO_UNSPECIFIED) {
        deviceIds.push_back(deviceId);
    }
    streamBuilder->setDeviceIds(deviceIds);
}

AAUDIO_API void AAudioStreamBuilder_setPackageName(AAudioStreamBuilder* builder,
                                                   const char* packageName)
{
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    std::optional<std::string> optionalPackageName;
    if (packageName != nullptr) {
      optionalPackageName = std::string(packageName);
    }
    // Only system apps can read the op package name. For regular apps the
    // regular package name is a sufficient replacement
    streamBuilder->setOpPackageName(optionalPackageName);
}

AAUDIO_API void AAudioStreamBuilder_setAttributionTag(AAudioStreamBuilder* builder,
                                                      const char* attributionTag)
{
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    std::optional<std::string> optionalAttrTag;
    if (attributionTag != nullptr) {
      optionalAttrTag = std::string(attributionTag);
    }
    streamBuilder->setAttributionTag(optionalAttrTag);
}

AAUDIO_API void AAudioStreamBuilder_setSampleRate(AAudioStreamBuilder* builder,
                                              int32_t sampleRate)
{
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setSampleRate(sampleRate);
}

AAUDIO_API void AAudioStreamBuilder_setChannelCount(AAudioStreamBuilder* builder,
                                                    int32_t channelCount)
{
    AAudioStreamBuilder_setSamplesPerFrame(builder, channelCount);
}

AAUDIO_API void AAudioStreamBuilder_setSamplesPerFrame(AAudioStreamBuilder* builder,
                                                       int32_t samplesPerFrame)
{
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    const aaudio_channel_mask_t channelMask = AAudioConvert_channelCountToMask(samplesPerFrame);
    streamBuilder->setChannelMask(channelMask);
}

AAUDIO_API void AAudioStreamBuilder_setDirection(AAudioStreamBuilder* builder,
                                             aaudio_direction_t direction)
{
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setDirection(direction);
}

AAUDIO_API void AAudioStreamBuilder_setFormat(AAudioStreamBuilder* builder,
                                                   aaudio_format_t format)
{
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    // Use audio_format_t everywhere internally.
    const audio_format_t internalFormat = AAudioConvert_aaudioToAndroidDataFormat(format);
    streamBuilder->setFormat(internalFormat);
}

AAUDIO_API void AAudioStreamBuilder_setSharingMode(AAudioStreamBuilder* builder,
                                                        aaudio_sharing_mode_t sharingMode)
{
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setSharingMode(sharingMode);
}

AAUDIO_API void AAudioStreamBuilder_setUsage(AAudioStreamBuilder* builder,
                                             aaudio_usage_t usage) {
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setUsage(usage);
}

AAUDIO_API void AAudioStreamBuilder_setContentType(AAudioStreamBuilder* builder,
                                                   aaudio_content_type_t contentType) {
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setContentType(contentType);
}

AAUDIO_API aaudio_result_t AAudioStreamBuilder_addTag(AAudioStreamBuilder* builder,
                                                      const char* tags) {
    if (tags == nullptr) {
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    return streamBuilder->addTag(tags);
}

AAUDIO_API void AAudioStreamBuilder_clearTags(AAudioStreamBuilder* builder) {
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->clearTags();
}

AAUDIO_API void AAudioStreamBuilder_setSpatializationBehavior(AAudioStreamBuilder* builder,
        aaudio_spatialization_behavior_t spatializationBehavior) {
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setSpatializationBehavior(spatializationBehavior);
}

AAUDIO_API void AAudioStreamBuilder_setIsContentSpatialized(AAudioStreamBuilder* builder,
                                                            bool isSpatialized) {
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setIsContentSpatialized(isSpatialized);
}

AAUDIO_API void AAudioStreamBuilder_setInputPreset(AAudioStreamBuilder* builder,
                                                   aaudio_input_preset_t inputPreset) {
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setInputPreset(inputPreset);
}

AAUDIO_API void AAudioStreamBuilder_setPrivacySensitive(AAudioStreamBuilder* builder,
                                                   bool privacySensitive) {
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setPrivacySensitiveRequest(privacySensitive);
}

AAUDIO_API void AAudioStreamBuilder_setBufferCapacityInFrames(AAudioStreamBuilder* builder,
                                                              int32_t frames)
{
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setBufferCapacity(frames);
}

AAUDIO_API void AAudioStreamBuilder_setAllowedCapturePolicy(
        AAudioStreamBuilder* builder, aaudio_allowed_capture_policy_t policy) {
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setAllowedCapturePolicy(policy);
}

AAUDIO_API void AAudioStreamBuilder_setSessionId(AAudioStreamBuilder* builder,
                                                 aaudio_session_id_t sessionId)
{
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setSessionId(sessionId);
}

AAUDIO_API void AAudioStreamBuilder_setDataCallback(AAudioStreamBuilder* builder,
                                                    AAudioStream_dataCallback callback,
                                                    void *userData)
{
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setDataCallbackProc(callback);
    streamBuilder->setDataCallbackUserData(userData);
}

AAUDIO_API aaudio_result_t AAudioStreamBuilder_setPartialDataCallback(
        AAudioStreamBuilder* builder,
        AAudioStream_partialDataCallback callback,
        void *userData)
{
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setPartialDataCallbackProc(callback)
                 ->setDataCallbackUserData(userData);
    return AAUDIO_OK;
}

AAUDIO_API void AAudioStreamBuilder_setErrorCallback(AAudioStreamBuilder* builder,
                                                 AAudioStream_errorCallback callback,
                                                 void *userData)
{
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setErrorCallbackProc(callback);
    streamBuilder->setErrorCallbackUserData(userData);
}

AAUDIO_API void AAudioStreamBuilder_setPresentationEndCallback(AAudioStreamBuilder* builder,
        AAudioStream_presentationEndCallback callback, void* userData) {
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    if (streamBuilder == nullptr) {
        return;
    }
    streamBuilder->setPresentationEndCallbackProc(callback)
                 ->setPresentationEndCallbackUserData(userData);
}

AAUDIO_API void AAudioStreamBuilder_setRoutingChangedCallback(
        AAudioStreamBuilder* builder,
        AAudioStream_routingChangedCallback callback,
        void* userData) {
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setRoutingChangedCallbackProc(callback)
                 ->setRoutingChangedCallbackUserData(userData);
}

AAUDIO_API void AAudioStreamBuilder_setFramesPerDataCallback(AAudioStreamBuilder* builder,
                                                int32_t frames)
{
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setFramesPerDataCallback(frames);
}

AAUDIO_API void AAudioStreamBuilder_setChannelMask(AAudioStreamBuilder* builder,
                                                   aaudio_channel_mask_t channelMask)
{
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    streamBuilder->setChannelMask(channelMask);
}

AAUDIO_API aaudio_result_t  AAudioStreamBuilder_openStream(AAudioStreamBuilder* builder,
                                                     AAudioStream** streamPtr)
{
    AudioStream *audioStream = nullptr;
    aaudio_stream_id_t id = 0;
    // Please leave these logs because they are very helpful when debugging.
    ALOGI("%s() called ----------------------------------------", __func__);
    AudioStreamBuilder *streamBuilder = COMMON_GET_FROM_BUILDER_OR_RETURN(streamPtr);
    aaudio_result_t result = streamBuilder->build(&audioStream);
    if (result == AAUDIO_OK) {
        *streamPtr = (AAudioStream*) audioStream;
        id = audioStream->getId();
        ALOGI("%s() got %s, devIds = [%s], perf = %s, burst = %d",
              __func__,
              (audioStream->isMMap() ? "MMAP" : "Legacy"),
              android::toString(audioStream->getDeviceIds()).c_str(),
              AudioGlobal_convertPerformanceModeToShortText(audioStream->getPerformanceMode()),
              audioStream->getFramesPerBurst()
              );
    } else {
        *streamPtr = nullptr;
    }
    ALOGI("%s() returns %d = %s for s#%u ----------------",
          __func__, result, AAudio_convertResultToText(result), id);
    return result;
}

AAUDIO_API aaudio_result_t  AAudioStreamBuilder_delete(AAudioStreamBuilder* builder)
{
    AudioStreamBuilder *streamBuilder = convertAAudioBuilderToStreamBuilder(builder);
    if (streamBuilder != nullptr) {
        delete streamBuilder;
        return AAUDIO_OK;
    }
    return AAUDIO_ERROR_NULL;
}

AAUDIO_API aaudio_result_t  AAudioStream_release(AAudioStream* stream) {
    aaudio_result_t result = AAUDIO_ERROR_NULL;
    AudioStream* audioStream = convertAAudioStreamToAudioStream(stream);
    if (audioStream != nullptr) {
        aaudio_stream_id_t id = audioStream->getId();
        ALOGD("%s(s#%u) called ---------------", __func__, id);
        result = audioStream->safeRelease();
        // safeRelease() will only fail if called illegally, for example, from a callback.
        // That would result in the release of an active stream, which would cause a crash.
        if (result != AAUDIO_OK) {
            ALOGW("%s(s#%u) failed. Release it from another thread.",
                  __func__, id);
        }
        ALOGD("%s(s#%u) returned %d %s ---------", __func__,
                id, result, AAudio_convertResultToText(result));
    }
    return result;
}

AAUDIO_API aaudio_result_t  AAudioStream_close(AAudioStream* stream) {
    aaudio_result_t result = AAUDIO_ERROR_NULL;
    AudioStream* audioStream = convertAAudioStreamToAudioStream(stream);
    if (audioStream != nullptr) {
        aaudio_stream_id_t id = audioStream->getId();
        ALOGD("%s(s#%u) called ---------------", __func__, id);
        result = audioStream->safeReleaseClose();
        // safeReleaseClose will only fail if called illegally, for example, from a callback.
        // That would result in deleting an active stream, which would cause a crash.
        if (result != AAUDIO_OK) {
            ALOGW("%s(s#%u) failed. Close it from another thread.",
                  __func__, id);
        } else {
            audioStream->unregisterPlayerBase();
            // Allow the stream to be deleted.
            AudioStreamBuilder::stopUsingStream(audioStream);
        }
        ALOGD("%s(s#%u) returned %d ---------", __func__, id, result);
    }
    return result;
}

AAUDIO_API aaudio_result_t  AAudioStream_requestStart(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    aaudio_stream_id_t id = audioStream->getId();
    ALOGD("%s(s#%u) called --------------", __func__, id);
    aaudio_result_t result = audioStream->systemStart();
    ALOGD("%s(s#%u) returned %d ---------", __func__, id, result);
    return result;
}

AAUDIO_API aaudio_result_t  AAudioStream_requestPause(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    ALOGD("%s(s#%u) called", __func__, audioStream->getId());
    return audioStream->systemPause();
}

AAUDIO_API aaudio_result_t  AAudioStream_requestFlush(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    ALOGD("%s(s#%u) called", __func__, audioStream->getId());
    return audioStream->safeFlush();
}

AAUDIO_API aaudio_result_t  AAudioStream_requestStop(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    ALOGD("%s(s#%u) called", __func__, audioStream->getId());
    return audioStream->systemStopFromApp();
}

AAUDIO_API aaudio_result_t AAudioStream_waitForStateChange(AAudioStream* stream,
                                            aaudio_stream_state_t inputState,
                                            aaudio_stream_state_t *nextState,
                                            int64_t timeoutNanoseconds)
{

    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    android::sp<AudioStream> spAudioStream(audioStream);
    return spAudioStream->waitForStateChange(inputState, nextState, timeoutNanoseconds);
}

// ============================================================
// Stream - non-blocking I/O
// ============================================================

AAUDIO_API aaudio_result_t AAudioStream_read(AAudioStream* stream,
                               void *buffer,
                               int32_t numFrames,
                               int64_t timeoutNanoseconds)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    if (buffer == nullptr) {
        return AAUDIO_ERROR_NULL;
    }
    if (numFrames < 0) {
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    } else if (numFrames == 0) {
        return 0;
    }

    aaudio_result_t result = audioStream->read(buffer, numFrames, timeoutNanoseconds);

    return result;
}

AAUDIO_API aaudio_result_t AAudioStream_write(AAudioStream* stream,
                               const void *buffer,
                               int32_t numFrames,
                               int64_t timeoutNanoseconds)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    if (buffer == nullptr) {
        return AAUDIO_ERROR_NULL;
    }

    // Don't allow writes when playing with a callback.
    if (audioStream->isDataCallbackActive()) {
        // A developer requested this warning because it would have saved lots of debugging.
        ALOGW("%s() - Cannot write to a callback stream when running.", __func__);
        return AAUDIO_ERROR_INVALID_STATE;
    }

    if (numFrames < 0) {
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    } else if (numFrames == 0) {
        return 0;
    }

    aaudio_result_t result = audioStream->write(buffer, numFrames, timeoutNanoseconds);

    return result;
}

// ============================================================
// Stream - queries
// ============================================================

AAUDIO_API int32_t AAudioStream_getSampleRate(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getSampleRate();
}

AAUDIO_API int32_t AAudioStream_getHardwareSampleRate(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getHardwareSampleRate();
}

AAUDIO_API int32_t AAudioStream_getChannelCount(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getSamplesPerFrame();
}

AAUDIO_API int32_t AAudioStream_getHardwareChannelCount(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getHardwareSamplesPerFrame();
}

AAUDIO_API int32_t AAudioStream_getSamplesPerFrame(AAudioStream* stream)
{
    return AAudioStream_getChannelCount(stream);
}

AAUDIO_API aaudio_stream_state_t AAudioStream_getState(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getStateExternal();
}

AAUDIO_API aaudio_format_t AAudioStream_getFormat(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    // Use audio_format_t internally.
    audio_format_t internalFormat = audioStream->getFormat();
    return AAudioConvert_androidToAAudioDataFormat(internalFormat);
}

AAUDIO_API aaudio_format_t AAudioStream_getHardwareFormat(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    // Use audio_format_t internally.
    audio_format_t internalFormat = audioStream->getHardwareFormat();
    return AAudioConvert_androidToNearestAAudioDataFormat(internalFormat);
}

AAUDIO_API aaudio_result_t AAudioStream_setBufferSizeInFrames(AAudioStream* stream,
                                                int32_t requestedFrames)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->setBufferSize(requestedFrames);
}

AAUDIO_API int32_t AAudioStream_getBufferSizeInFrames(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getBufferSize();
}

AAUDIO_API aaudio_direction_t AAudioStream_getDirection(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getDirection();
}

AAUDIO_API int32_t AAudioStream_getFramesPerBurst(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getFramesPerBurst();
}

AAUDIO_API int32_t AAudioStream_getFramesPerDataCallback(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getFramesPerDataCallback();
}

AAUDIO_API int32_t AAudioStream_getBufferCapacityInFrames(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getBufferCapacity();
}

AAUDIO_API int32_t AAudioStream_getXRunCount(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getXRunCount();
}

AAUDIO_API aaudio_performance_mode_t AAudioStream_getPerformanceMode(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getPerformanceMode();
}

AAUDIO_API int32_t AAudioStream_getDeviceId(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    auto deviceIds = audioStream->getDeviceIds();
    if (deviceIds.empty()) {
        return AAUDIO_UNSPECIFIED;
    }
    return deviceIds[0];
}

AAUDIO_API aaudio_result_t AAudioStream_getDeviceIds(AAudioStream* stream, int32_t* ids,
                                                     int32_t* numIds)
{
    if (numIds == nullptr) {
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    auto deviceIds = audioStream->getDeviceIds();
    if (*numIds < deviceIds.size()) {
        *numIds = deviceIds.size();
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }
    if (ids == nullptr) {
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }
    for (int i = 0; i < deviceIds.size(); i++) {
        ids[i] = deviceIds[i];
    }
    *numIds = deviceIds.size();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_sharing_mode_t AAudioStream_getSharingMode(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getSharingMode();
}

AAUDIO_API aaudio_usage_t AAudioStream_getUsage(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getUsage();
}

AAUDIO_API aaudio_content_type_t AAudioStream_getContentType(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getContentType();
}

AAUDIO_API int32_t AAudioStream_obtainTags(AAudioStream* stream, char*** tags)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    auto aaTags = audioStream->getTags();
    if (aaTags.empty()) {
        *tags = nullptr;
        return 0;
    }
    *tags = new char*[aaTags.size()];
    if (*tags == nullptr) {
        return AAUDIO_ERROR_NO_MEMORY;
    }
    auto it = aaTags.begin();
    for (int i = 0; it != aaTags.end(); i++, it++) {
        (*tags)[i] = new char[AUDIO_ATTRIBUTES_TAGS_MAX_SIZE];
        if ((*tags)[i] == nullptr) {
            for (int j = 0; j < i; ++j) {
                delete[] (*tags)[i];
            }
            delete[] (*tags);
            return AAUDIO_ERROR_NO_MEMORY;
        }
        strcpy((*tags)[i], it->c_str());
    }
    return aaTags.size();
}

AAUDIO_API void AAudioStream_destroyTags(AAudioStream* stream, char** tags) {
    if (tags == nullptr) {
        return;
    }
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    const int tagsNum = audioStream->getTags().size();
    for (int i = 0; i < tagsNum; ++i) {
        delete[] tags[i];
    }
    delete[] tags;
}

AAUDIO_API aaudio_spatialization_behavior_t AAudioStream_getSpatializationBehavior(
        AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getSpatializationBehavior();
}

AAUDIO_API bool AAudioStream_isContentSpatialized(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->isContentSpatialized();
}

AAUDIO_API aaudio_input_preset_t AAudioStream_getInputPreset(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getInputPreset();
}

AAUDIO_API aaudio_allowed_capture_policy_t AAudioStream_getAllowedCapturePolicy(
        AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getAllowedCapturePolicy();
}

AAUDIO_API int32_t AAudioStream_getSessionId(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getSessionId();
}

AAUDIO_API int64_t AAudioStream_getFramesWritten(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getFramesWritten() * audioStream->getSampleRate() /
            audioStream->getDeviceSampleRate();
}

AAUDIO_API int64_t AAudioStream_getFramesRead(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getFramesRead() * audioStream->getSampleRate() /
            audioStream->getDeviceSampleRate();
}

AAUDIO_API aaudio_result_t AAudioStream_getTimestamp(AAudioStream* stream,
                                      clockid_t clockid,
                                      int64_t *framePosition,
                                      int64_t *timeNanoseconds)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    if (framePosition == nullptr || timeNanoseconds == nullptr) {
        return AAUDIO_ERROR_NULL;
    } else if (clockid != CLOCK_MONOTONIC && clockid != CLOCK_BOOTTIME) {
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }

    return audioStream->getTimestamp(clockid, framePosition, timeNanoseconds);
}

AAUDIO_API aaudio_policy_t AAudio_getMMapPolicy() {
    return AudioGlobal_getMMapPolicy();
}

AAUDIO_API aaudio_result_t AAudio_setMMapPolicy(aaudio_policy_t policy) {
    ALOGD("%s(%d)", __func__, policy);
    return AudioGlobal_setMMapPolicy(policy);
}

AAUDIO_API bool AAudioStream_isMMapUsed(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->isMMap();
}

AAUDIO_API bool AAudioStream_isPrivacySensitive(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->isPrivacySensitive();
}

AAUDIO_API aaudio_channel_mask_t AAudioStream_getChannelMask(AAudioStream* stream)
{
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    const aaudio_channel_mask_t channelMask = audioStream->getChannelMask();
    // Do not return channel index masks as they are not public.
    return AAudio_isChannelIndexMask(channelMask) ? AAUDIO_UNSPECIFIED : channelMask;
}

AAUDIO_API aaudio_result_t AAudioStream_setOffloadDelayPadding(
        AAudioStream* stream, int32_t delayInFrames, int32_t paddingInFrames) {
    if (delayInFrames < 0 || paddingInFrames < 0) {
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->setOffloadDelayPadding(delayInFrames, paddingInFrames);
}

AAUDIO_API int32_t AAudioStream_getOffloadDelay(AAudioStream* stream) {
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getOffloadDelay();
}

AAUDIO_API int32_t AAudioStream_getOffloadPadding(AAudioStream* stream) {
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getOffloadPadding();
}

AAUDIO_API aaudio_result_t AAudioStream_setOffloadEndOfStream(AAudioStream* stream) {
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->setOffloadEndOfStream();
}

AAUDIO_API aaudio_result_t AAudioStream_flushFromFrame(
        AAudioStream* stream, AAudio_FlushFromAccuracy accuracy, int64_t* inOutPosition) {
    AudioStream *audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->flushFromFrame(accuracy, inOutPosition);
}

AAUDIO_API aaudio_result_t AAudioStream_setPlaybackParameters(
        AAudioStream* stream, const AAudioPlaybackParameters* parameters) {
    AudioStream* audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->setPlaybackParameters(parameters);
}

AAUDIO_API aaudio_result_t AAudioStream_getPlaybackParameters(
        AAudioStream* stream, AAudioPlaybackParameters* outParameters) {
    AudioStream* audioStream = convertAAudioStreamToAudioStream(stream);
    return audioStream->getPlaybackParameters(outParameters);
}
