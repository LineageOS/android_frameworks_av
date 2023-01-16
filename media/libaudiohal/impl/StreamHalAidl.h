/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <memory>
#include <string_view>

#include <aidl/android/hardware/audio/core/BpStreamCommon.h>
#include <aidl/android/hardware/audio/core/BpStreamIn.h>
#include <aidl/android/hardware/audio/core/BpStreamOut.h>
#include <fmq/AidlMessageQueue.h>
#include <media/audiohal/EffectHalInterface.h>
#include <media/audiohal/StreamHalInterface.h>
#include <mediautils/Synchronization.h>

#include "ConversionHelperAidl.h"
#include "StreamPowerLog.h"

namespace android {

class DeviceHalAidl;

class StreamHalAidl : public virtual StreamHalInterface, public ConversionHelperAidl {
  public:
    // Return size of input/output buffer in bytes for this stream - eg. 4800.
    status_t getBufferSize(size_t *size) override;

    // Return the base configuration of the stream:
    //   - channel mask;
    //   - format - e.g. AUDIO_FORMAT_PCM_16_BIT;
    //   - sampling rate in Hz - eg. 44100.
    status_t getAudioProperties(audio_config_base_t *configBase) override;

    // Set audio stream parameters.
    status_t setParameters(const String8& kvPairs) override;

    // Get audio stream parameters.
    status_t getParameters(const String8& keys, String8 *values) override;

    // Return the frame size (number of bytes per sample) of a stream.
    status_t getFrameSize(size_t *size) override;

    // Add or remove the effect on the stream.
    status_t addEffect(sp<EffectHalInterface> effect) override;
    status_t removeEffect(sp<EffectHalInterface> effect) override;

    // Put the audio hardware input/output into standby mode.
    status_t standby() override;

    status_t dump(int fd, const Vector<String16>& args) override;

    // Start a stream operating in mmap mode.
    status_t start() override;

    // Stop a stream operating in mmap mode.
    status_t stop() override;

    // Retrieve information on the data buffer in mmap mode.
    status_t createMmapBuffer(int32_t minSizeFrames,
            struct audio_mmap_buffer_info *info) override;

    // Get current read/write position in the mmap buffer
    status_t getMmapPosition(struct audio_mmap_position *position) override;

    // Set the priority of the thread that interacts with the HAL
    // (must match the priority of the audioflinger's thread that calls 'read' / 'write')
    status_t setHalThreadPriority(int priority) override;

    status_t legacyCreateAudioPatch(const struct audio_port_config& port,
            std::optional<audio_source_t> source,
            audio_devices_t type) override;

    status_t legacyReleaseAudioPatch() override;

  protected:
    typedef AidlMessageQueue<::aidl::android::hardware::audio::core::StreamDescriptor::Command,
          ::aidl::android::hardware::common::fmq::SynchronizedReadWrite> CommandMQ;
    typedef AidlMessageQueue<::aidl::android::hardware::audio::core::StreamDescriptor::Reply,
            ::aidl::android::hardware::common::fmq::SynchronizedReadWrite> ReplyMQ;
    typedef AidlMessageQueue<int8_t,
            ::aidl::android::hardware::common::fmq::SynchronizedReadWrite> DataMQ;

    template<class T>
    static std::shared_ptr<::aidl::android::hardware::audio::core::IStreamCommon> getStreamCommon(
            const std::shared_ptr<T>& stream);

    // Subclasses can not be constructed directly by clients.
    StreamHalAidl(std::string_view className,
            bool isInput,
            const ::aidl::android::hardware::audio::core::StreamDescriptor& descriptor,
            const std::shared_ptr<::aidl::android::hardware::audio::core::IStreamCommon>& stream);

    ~StreamHalAidl() override;

    status_t getHalPid(pid_t *pid);

    bool requestHalThreadPriority(pid_t threadPid, pid_t threadId);

    const bool mIsInput;
    const size_t mFrameSizeBytes;
    const size_t mBufferSizeFrames;
    const std::unique_ptr<CommandMQ> mCommandMQ;
    const std::unique_ptr<ReplyMQ> mReplyMQ;
    const std::unique_ptr<DataMQ> mDataMQ;
    // mStreamPowerLog is used for audio signal power logging.
    StreamPowerLog mStreamPowerLog;

  private:
    static std::unique_ptr<DataMQ> maybeCreateDataMQ(
            const ::aidl::android::hardware::audio::core::StreamDescriptor& descriptor) {
        using Tag = ::aidl::android::hardware::audio::core::StreamDescriptor::AudioBuffer::Tag;
        if (descriptor.audio.getTag() == Tag::fmq) {
            return std::make_unique<DataMQ>(descriptor.audio.get<Tag::fmq>());
        }
        return nullptr;
    }

    const int HAL_THREAD_PRIORITY_DEFAULT = -1;
    const std::shared_ptr<::aidl::android::hardware::audio::core::IStreamCommon> mStream;
    int mHalThreadPriority = HAL_THREAD_PRIORITY_DEFAULT;
};

class StreamOutHalAidl : public StreamOutHalInterface, public StreamHalAidl {
  public:
    // Return the audio hardware driver estimated latency in milliseconds.
    status_t getLatency(uint32_t *latency) override;

    // Use this method in situations where audio mixing is done in the hardware.
    status_t setVolume(float left, float right) override;

    // Selects the audio presentation (if available).
    status_t selectPresentation(int presentationId, int programId) override;

    // Write audio buffer to driver.
    status_t write(const void *buffer, size_t bytes, size_t *written) override;

    // Return the number of audio frames written by the audio dsp to DAC since
    // the output has exited standby.
    status_t getRenderPosition(uint32_t *dspFrames) override;

    // Get the local time at which the next write to the audio driver will be presented.
    status_t getNextWriteTimestamp(int64_t *timestamp) override;

    // Set the callback for notifying completion of non-blocking write and drain.
    status_t setCallback(wp<StreamOutHalInterfaceCallback> callback) override;

    // Returns whether pause and resume operations are supported.
    status_t supportsPauseAndResume(bool *supportsPause, bool *supportsResume) override;

    // Notifies to the audio driver to resume playback following a pause.
    status_t pause() override;

    // Notifies to the audio driver to resume playback following a pause.
    status_t resume() override;

    // Returns whether drain operation is supported.
    status_t supportsDrain(bool *supportsDrain) override;

    // Requests notification when data buffered by the driver/hardware has been played.
    status_t drain(bool earlyNotify) override;

    // Notifies to the audio driver to flush the queued data.
    status_t flush() override;

    // Return a recent count of the number of audio frames presented to an external observer.
    status_t getPresentationPosition(uint64_t *frames, struct timespec *timestamp) override;

    // Called when the metadata of the stream's source has been changed.
    status_t updateSourceMetadata(const SourceMetadata& sourceMetadata) override;

    // Returns the Dual Mono mode presentation setting.
    status_t getDualMonoMode(audio_dual_mono_mode_t* mode) override;

    // Sets the Dual Mono mode presentation on the output device.
    status_t setDualMonoMode(audio_dual_mono_mode_t mode) override;

    // Returns the Audio Description Mix level in dB.
    status_t getAudioDescriptionMixLevel(float* leveldB) override;

    // Sets the Audio Description Mix level in dB.
    status_t setAudioDescriptionMixLevel(float leveldB) override;

    // Retrieves current playback rate parameters.
    status_t getPlaybackRateParameters(audio_playback_rate_t* playbackRate) override;

    // Sets the playback rate parameters that control playback behavior.
    status_t setPlaybackRateParameters(const audio_playback_rate_t& playbackRate) override;

    status_t setEventCallback(const sp<StreamOutHalInterfaceEventCallback>& callback) override;

    status_t setLatencyMode(audio_latency_mode_t mode) override;
    status_t getRecommendedLatencyModes(std::vector<audio_latency_mode_t> *modes) override;
    status_t setLatencyModeCallback(
            const sp<StreamOutHalInterfaceLatencyModeCallback>& callback) override;

    void onRecommendedLatencyModeChanged(const std::vector<audio_latency_mode_t>& modes);

    status_t exit() override;

    void onCodecFormatChanged(const std::basic_string<uint8_t>& metadataBs);

    // Methods used by StreamOutCallback ().
    // FIXME: Consider the required visibility.
    void onWriteReady();
    void onDrainReady();
    void onError();

  private:
    friend class sp<StreamOutHalAidl>;

    mediautils::atomic_wp<StreamOutHalInterfaceCallback> mCallback;
    mediautils::atomic_wp<StreamOutHalInterfaceEventCallback> mEventCallback;
    mediautils::atomic_wp<StreamOutHalInterfaceLatencyModeCallback> mLatencyModeCallback;

    const std::shared_ptr<::aidl::android::hardware::audio::core::IStreamOut> mStream;

    // Can not be constructed directly by clients.
    StreamOutHalAidl(
            const ::aidl::android::hardware::audio::core::StreamDescriptor& descriptor,
            const std::shared_ptr<::aidl::android::hardware::audio::core::IStreamOut>& stream);

    ~StreamOutHalAidl() override = default;
};

class StreamInHalAidl : public StreamInHalInterface, public StreamHalAidl {
  public:
    // Set the input gain for the audio driver.
    status_t setGain(float gain) override;

    // Read audio buffer in from driver.
    status_t read(void *buffer, size_t bytes, size_t *read) override;

    // Return the amount of input frames lost in the audio driver.
    status_t getInputFramesLost(uint32_t *framesLost) override;

    // Return a recent count of the number of audio frames received and
    // the clock time associated with that frame count.
    status_t getCapturePosition(int64_t *frames, int64_t *time) override;

    // Get active microphones
    status_t getActiveMicrophones(std::vector<media::MicrophoneInfo> *microphones) override;

    // Set microphone direction (for processing)
    status_t setPreferredMicrophoneDirection(
                            audio_microphone_direction_t direction) override;

    // Set microphone zoom (for processing)
    status_t setPreferredMicrophoneFieldDimension(float zoom) override;

    // Called when the metadata of the stream's sink has been changed.
    status_t updateSinkMetadata(const SinkMetadata& sinkMetadata) override;

  private:
    friend class sp<StreamInHalAidl>;

    const std::shared_ptr<::aidl::android::hardware::audio::core::IStreamIn> mStream;

    // Can not be constructed directly by clients.
    StreamInHalAidl(
            const ::aidl::android::hardware::audio::core::StreamDescriptor& descriptor,
            const std::shared_ptr<::aidl::android::hardware::audio::core::IStreamIn>& stream);

    ~StreamInHalAidl() override = default;
};

} // namespace android
