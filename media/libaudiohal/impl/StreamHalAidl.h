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

#include <atomic>
#include <memory>
#include <mutex>
#include <string_view>

#include <aidl/android/hardware/audio/common/AudioOffloadMetadata.h>
#include <aidl/android/hardware/audio/core/BpStreamCommon.h>
#include <aidl/android/hardware/audio/core/BpStreamIn.h>
#include <aidl/android/hardware/audio/core/BpStreamOut.h>
#include <aidl/android/hardware/audio/core/MmapBufferDescriptor.h>
#include <aidl/android/media/audio/IHalAdapterVendorExtension.h>
#include <fmq/AidlMessageQueue.h>
#include <media/audiohal/EffectHalInterface.h>
#include <media/audiohal/StreamHalInterface.h>
#include <media/AidlConversionUtil.h>
#include <media/AudioParameter.h>

#include "ConversionHelperAidl.h"
#include "StreamPowerLog.h"

using ::aidl::android::hardware::audio::common::AudioOffloadMetadata;
using ::aidl::android::hardware::audio::core::MmapBufferDescriptor;

namespace android {

class StreamContextAidl {
  public:
    typedef AidlMessageQueue<::aidl::android::hardware::audio::core::StreamDescriptor::Command,
          ::aidl::android::hardware::common::fmq::SynchronizedReadWrite> CommandMQ;
    typedef AidlMessageQueue<::aidl::android::hardware::audio::core::StreamDescriptor::Reply,
            ::aidl::android::hardware::common::fmq::SynchronizedReadWrite> ReplyMQ;
    typedef AidlMessageQueue<int8_t,
            ::aidl::android::hardware::common::fmq::SynchronizedReadWrite> DataMQ;

    StreamContextAidl(
            ::aidl::android::hardware::audio::core::StreamDescriptor& descriptor,
            bool isAsynchronous)
        : mFrameSizeBytes(descriptor.frameSizeBytes),
          mCommandMQ(new CommandMQ(descriptor.command)),
          mReplyMQ(new ReplyMQ(descriptor.reply)),
          mBufferSizeFrames(descriptor.bufferSizeFrames),
          mDataMQ(maybeCreateDataMQ(descriptor)),
          mIsAsynchronous(isAsynchronous),
          mIsMmapped(isMmapped(descriptor)),
          mMmapBufferDescriptor(maybeGetMmapBuffer(descriptor)) {}
    StreamContextAidl(StreamContextAidl&& other) :
            mFrameSizeBytes(other.mFrameSizeBytes),
            mCommandMQ(std::move(other.mCommandMQ)),
            mReplyMQ(std::move(other.mReplyMQ)),
            mBufferSizeFrames(other.mBufferSizeFrames),
            mDataMQ(std::move(other.mDataMQ)),
            mIsAsynchronous(other.mIsAsynchronous),
            mIsMmapped(other.mIsMmapped),
            mMmapBufferDescriptor(std::move(other.mMmapBufferDescriptor)) {}
    StreamContextAidl& operator=(StreamContextAidl&& other) {
        mFrameSizeBytes = other.mFrameSizeBytes;
        mCommandMQ = std::move(other.mCommandMQ);
        mReplyMQ = std::move(other.mReplyMQ);
        mBufferSizeFrames = other.mBufferSizeFrames;
        mDataMQ = std::move(other.mDataMQ);
        mIsAsynchronous = other.mIsAsynchronous;
        mIsMmapped = other.mIsMmapped;
        mMmapBufferDescriptor = std::move(other.mMmapBufferDescriptor);
        return *this;
    }
    bool isValid() const {
        return mFrameSizeBytes != 0 &&
                mCommandMQ != nullptr && mCommandMQ->isValid() &&
                mReplyMQ != nullptr && mReplyMQ->isValid() &&
                (mDataMQ == nullptr || (
                        mDataMQ->isValid() &&
                        mDataMQ->getQuantumCount() * mDataMQ->getQuantumSize() >=
                        mFrameSizeBytes * mBufferSizeFrames)) &&
                (!mIsMmapped || mMmapBufferDescriptor.sharedMemory.fd.get() >= 0);
    }
    size_t getBufferSizeBytes() const { return mFrameSizeBytes * mBufferSizeFrames; }
    size_t getBufferSizeFrames() const { return mBufferSizeFrames; }
    CommandMQ* getCommandMQ() const { return mCommandMQ.get(); }
    DataMQ* getDataMQ() const { return mDataMQ.get(); }
    size_t getFrameSizeBytes() const { return mFrameSizeBytes; }
    ReplyMQ* getReplyMQ() const { return mReplyMQ.get(); }
    bool isAsynchronous() const { return mIsAsynchronous; }
    bool isMmapped() const { return mIsMmapped; }
    const MmapBufferDescriptor& getMmapBufferDescriptor() const { return mMmapBufferDescriptor; }

  private:
    static std::unique_ptr<DataMQ> maybeCreateDataMQ(
            const ::aidl::android::hardware::audio::core::StreamDescriptor& descriptor) {
        using Tag = ::aidl::android::hardware::audio::core::StreamDescriptor::AudioBuffer::Tag;
        if (descriptor.audio.getTag() == Tag::fmq) {
            return std::make_unique<DataMQ>(descriptor.audio.get<Tag::fmq>());
        }
        return nullptr;
    }
    static bool isMmapped(
            const ::aidl::android::hardware::audio::core::StreamDescriptor& descriptor) {
        using Tag = ::aidl::android::hardware::audio::core::StreamDescriptor::AudioBuffer::Tag;
        return descriptor.audio.getTag() == Tag::mmap;
    }
    static MmapBufferDescriptor maybeGetMmapBuffer(
            ::aidl::android::hardware::audio::core::StreamDescriptor& descriptor) {
        using Tag = ::aidl::android::hardware::audio::core::StreamDescriptor::AudioBuffer::Tag;
        if (descriptor.audio.getTag() == Tag::mmap) {
            return std::move(descriptor.audio.get<Tag::mmap>());
        }
        return {};
    }

    size_t mFrameSizeBytes;
    std::unique_ptr<CommandMQ> mCommandMQ;
    std::unique_ptr<ReplyMQ> mReplyMQ;
    size_t mBufferSizeFrames;
    std::unique_ptr<DataMQ> mDataMQ;
    bool mIsAsynchronous;
    bool mIsMmapped;
    MmapBufferDescriptor mMmapBufferDescriptor;
};

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
    // For tests.
    friend class sp<StreamHalAidl>;

    template<class T>
    static std::shared_ptr<::aidl::android::hardware::audio::core::IStreamCommon> getStreamCommon(
            const std::shared_ptr<T>& stream);

    // Subclasses can not be constructed directly by clients.
    StreamHalAidl(std::string_view className,
            bool isInput,
            const audio_config& config,
            int32_t nominalLatency,
            StreamContextAidl&& context,
            const std::shared_ptr<::aidl::android::hardware::audio::core::IStreamCommon>& stream,
            const std::shared_ptr<::aidl::android::media::audio::IHalAdapterVendorExtension>& vext);

    ~StreamHalAidl() override;

    status_t getLatency(uint32_t *latency);

    status_t getObservablePosition(int64_t *frames, int64_t *timestamp);

    status_t getHardwarePosition(int64_t *frames, int64_t *timestamp);

    status_t getXruns(int32_t *frames);

    status_t transfer(void *buffer, size_t bytes, size_t *transferred);

    status_t pause(
            ::aidl::android::hardware::audio::core::StreamDescriptor::Reply* reply = nullptr);

    status_t resume(
            ::aidl::android::hardware::audio::core::StreamDescriptor::Reply* reply = nullptr);

    status_t drain(bool earlyNotify,
            ::aidl::android::hardware::audio::core::StreamDescriptor::Reply* reply = nullptr);

    status_t flush(
            ::aidl::android::hardware::audio::core::StreamDescriptor::Reply* reply = nullptr);

    status_t exit();

    const bool mIsInput;
    const audio_config_base_t mConfig;
    const StreamContextAidl mContext;

  private:
    static audio_config_base_t configToBase(const audio_config& config) {
        audio_config_base_t result = AUDIO_CONFIG_BASE_INITIALIZER;
        result.sample_rate = config.sample_rate;
        result.channel_mask = config.channel_mask;
        result.format = config.format;
        return result;
    }
    ::aidl::android::hardware::audio::core::StreamDescriptor::State getState() {
        std::lock_guard l(mLock);
        return mLastReply.state;
    }
    status_t sendCommand(
            const ::aidl::android::hardware::audio::core::StreamDescriptor::Command &command,
            ::aidl::android::hardware::audio::core::StreamDescriptor::Reply* reply = nullptr,
            bool safeFromNonWorkerThread = false);
    status_t updateCountersIfNeeded(
            ::aidl::android::hardware::audio::core::StreamDescriptor::Reply* reply = nullptr);

    const std::shared_ptr<::aidl::android::hardware::audio::core::IStreamCommon> mStream;
    const std::shared_ptr<::aidl::android::media::audio::IHalAdapterVendorExtension> mVendorExt;
    std::mutex mLock;
    ::aidl::android::hardware::audio::core::StreamDescriptor::Reply mLastReply GUARDED_BY(mLock);
    // mStreamPowerLog is used for audio signal power logging.
    StreamPowerLog mStreamPowerLog;
    std::atomic<pid_t> mWorkerTid = -1;
};

class CallbackBroker;

class StreamOutHalAidl : public StreamOutHalInterface, public StreamHalAidl {
  public:
    // Extract the output stream parameters and set by AIDL APIs.
    status_t setParameters(const String8& kvPairs) override;

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

    status_t exit() override;

  private:
    friend class sp<StreamOutHalAidl>;

    static ConversionResult<::aidl::android::hardware::audio::common::SourceMetadata>
    legacy2aidl_SourceMetadata(const StreamOutHalInterface::SourceMetadata& legacy);

    const std::shared_ptr<::aidl::android::hardware::audio::core::IStreamOut> mStream;
    const wp<CallbackBroker> mCallbackBroker;

    AudioOffloadMetadata mOffloadMetadata;

    // Can not be constructed directly by clients.
    StreamOutHalAidl(
            const audio_config& config, StreamContextAidl&& context, int32_t nominalLatency,
            const std::shared_ptr<::aidl::android::hardware::audio::core::IStreamOut>& stream,
            const std::shared_ptr<::aidl::android::media::audio::IHalAdapterVendorExtension>& vext,
            const sp<CallbackBroker>& callbackBroker);

    ~StreamOutHalAidl() override;

    // Filter and update the offload metadata. The parameters which are related to the offload
    // metadata will be removed after filtering.
    status_t filterAndUpdateOffloadMetadata(AudioParameter &parameters);
};

class MicrophoneInfoProvider;

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
    status_t getActiveMicrophones(std::vector<media::MicrophoneInfoFw> *microphones) override;

    // Set microphone direction (for processing)
    status_t setPreferredMicrophoneDirection(
                            audio_microphone_direction_t direction) override;

    // Set microphone zoom (for processing)
    status_t setPreferredMicrophoneFieldDimension(float zoom) override;

    // Called when the metadata of the stream's sink has been changed.
    status_t updateSinkMetadata(const SinkMetadata& sinkMetadata) override;

  private:
    friend class sp<StreamInHalAidl>;

    static ConversionResult<::aidl::android::hardware::audio::common::SinkMetadata>
    legacy2aidl_SinkMetadata(const StreamInHalInterface::SinkMetadata& legacy);

    const std::shared_ptr<::aidl::android::hardware::audio::core::IStreamIn> mStream;
    const wp<MicrophoneInfoProvider> mMicInfoProvider;

    // Can not be constructed directly by clients.
    StreamInHalAidl(
            const audio_config& config, StreamContextAidl&& context, int32_t nominalLatency,
            const std::shared_ptr<::aidl::android::hardware::audio::core::IStreamIn>& stream,
            const std::shared_ptr<::aidl::android::media::audio::IHalAdapterVendorExtension>& vext,
            const sp<MicrophoneInfoProvider>& micInfoProvider);

    ~StreamInHalAidl() override = default;
};

} // namespace android
