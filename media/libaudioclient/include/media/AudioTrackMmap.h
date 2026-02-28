/*
 * Copyright (C) 2026 The Android Open Source Project
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

#include <client/AudioStreamInternalPlay.h>
#include <media/AudioContainers.h>
#include <media/AudioTrack.h>

#include <deque>
#include <variant>

namespace android {

class AudioTrackMmap : public AudioTrack {
public:
    explicit AudioTrackMmap(SetParams&& params);
    ~AudioTrackMmap() override;

    uint32_t getSampleRate() const final;
    status_t start() final;
    void stop() final;
    void pause() final;
    void flush() final;
    status_t setVolume(float left, float right) final;
    ssize_t getBufferSizeInFrames() final;
    ssize_t setBufferSizeInFrames(size_t size) final;
    status_t setSampleRate(uint32_t sampleRate) final;
    const AudioPlaybackRate& getPlaybackRate() final;
    status_t setPlaybackRate(const AudioPlaybackRate &playbackRate) final;
    status_t setMarkerPosition(uint32_t marker) final;
    status_t getMarkerPosition(uint32_t *marker) const final;
    status_t setPositionUpdatePeriod(uint32_t updatePeriod) final;
    status_t getPositionUpdatePeriod(uint32_t *updatePeriod) const final;
    int64_t getWrittenFramesCount() const final;
    status_t setPosition(uint32_t position) final;
    status_t getPosition(uint32_t *position) final;
    uint32_t latency() final;
    uint32_t getUnderrunCount() const final;
    audio_output_flags_t getFlags() const final;
    status_t getTimestamp(AudioTimestamp& timestamp) final;
    status_t setLoop(uint32_t loopStart, uint32_t loopEnd, int loopCount) final;
    status_t reload() final;
    status_t setAuxEffectSendLevel(float level) final;
    status_t attachAuxEffect(int effectId) final;
    status_t setOutputDevice(audio_port_handle_t deviceId) final;
    DeviceIdVector getRoutedDeviceIds() final;
    media::VolumeShaper::Status applyVolumeShaper(
            const sp<media::VolumeShaper::Configuration>& configuration,
            const sp<media::VolumeShaper::Operation>& operation) final;
    sp<media::VolumeShaper::State> getVolumeShaperState(int id) final;
    status_t selectPresentation(int presentationId, int programId) final;
    status_t setParameters(const String8& keyValuePairs) final;
    status_t setAudioDescriptionMixLevel(float leveldB) final;
    status_t getAudioDescriptionMixLevel(float* leveldB) const final;
    status_t setDualMonoMode(audio_dual_mono_mode_t mode) final;
    status_t getDualMonoMode(audio_dual_mono_mode_t* mode) const final;
    ssize_t getStartThresholdInFrames() const final;
    ssize_t setStartThresholdInFrames(size_t startThresholdInFrames) final;
    ssize_t write(const void* buffer, size_t size, bool blocking = true) final;
    uint32_t getUnderrunFrames() const final;

    static int32_t aaudioPartialDataCallback(
            AAudioStream* stream, void* userData, void* audioData, int32_t numFrames);
    static void aaudioPresentationEndCallback(AAudioStream* stream, void* userData);

protected:
    status_t createTrack_l() final;
    nsecs_t processAudioBuffer() final;
    void stopAndJoinCallbacks() final;

private:
    status_t validateParameters();
    int32_t aaudioPartialDataCallbackImpl(int32_t numFrames);
    void aaudioPresentationEndCallbackImpl();

    sp<aaudio::AudioStreamInternalPlay> mStream;
    int64_t mFramesWrittenOffset GUARDED_BY(mLock){0};
    int64_t mFramesReadOffset GUARDED_BY(mLock){0};
    int64_t mLastReportedPosition GUARDED_BY(mLock){0};

    enum CallbackEventCode {
        EVENT_MORE_DATA_AVAILABLE,
        EVENT_STREAM_END,
        EVENT_ROUTED_DEVICE_CHANGED,
    };

    struct CallbackEvent {
        CallbackEventCode mEvent [[clang::require_explicit_initialization]];
        std::variant<int32_t, DeviceIdVector> mParams = 0;
    };

    std::mutex mMmapCbMutex;
    std::condition_variable mMmapCbCond;
    std::deque<CallbackEvent> mCbEvents GUARDED_BY(mMmapCbMutex);
};

} // namespace android
