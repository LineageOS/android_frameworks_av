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

#define LOG_TAG "StreamHalAidl"
//#define LOG_NDEBUG 0

#include <aidl/android/hardware/audio/core/BnStreamCallback.h>
#include <mediautils/TimeCheck.h>
#include <utils/Log.h>

#include "DeviceHalAidl.h"
#include "StreamHalAidl.h"

using ::aidl::android::hardware::audio::core::IStreamCommon;
using ::aidl::android::hardware::audio::core::IStreamIn;
using ::aidl::android::hardware::audio::core::IStreamOut;
using ::aidl::android::hardware::audio::core::StreamDescriptor;

namespace android {

// static
template<class T>
std::shared_ptr<IStreamCommon> StreamHalAidl::getStreamCommon(const std::shared_ptr<T>& stream) {
    std::shared_ptr<::aidl::android::hardware::audio::core::IStreamCommon> streamCommon;
    if (stream != nullptr) {
        if (ndk::ScopedAStatus status = stream->getStreamCommon(&streamCommon);
                !status.isOk()) {
            ALOGE("%s: failed to retrieve IStreamCommon instance: %s", __func__,
                    status.getDescription().c_str());
        }
    }
    return streamCommon;
}

StreamHalAidl::StreamHalAidl(
        std::string_view className, bool isInput, const StreamDescriptor& descriptor,
        const std::shared_ptr<IStreamCommon>& stream)
        : ConversionHelperAidl(className),
          mIsInput(isInput),
          mFrameSizeBytes(descriptor.frameSizeBytes),
          mBufferSizeFrames(descriptor.bufferSizeFrames),
          mCommandMQ(new CommandMQ(descriptor.command)),
          mReplyMQ(new ReplyMQ(descriptor.reply)),
          mDataMQ(maybeCreateDataMQ(descriptor)),
          mStream(stream) {
    // Instrument audio signal power logging.
    // Note: This assumes channel mask, format, and sample rate do not change after creation.
    if (audio_config_base_t config = AUDIO_CONFIG_BASE_INITIALIZER;
            /* mStreamPowerLog.isUserDebugOrEngBuild() && */
            StreamHalAidl::getAudioProperties(&config) == NO_ERROR) {
        mStreamPowerLog.init(config.sample_rate, config.channel_mask, config.format);
    }
}

StreamHalAidl::~StreamHalAidl() {
    if (mStream != nullptr) {
        ndk::ScopedAStatus status = mStream->close();
        ALOGE_IF(!status.isOk(), "%s: status %s", __func__, status.getDescription().c_str());
    }
}

status_t StreamHalAidl::getBufferSize(size_t *size) {
    if (size == nullptr) {
        return BAD_VALUE;
    }
    if (mFrameSizeBytes == 0 || mBufferSizeFrames == 0) {
        return NO_INIT;
    }
    *size = mFrameSizeBytes * mBufferSizeFrames;
    return OK;
}

status_t StreamHalAidl::getAudioProperties(audio_config_base_t *configBase) {
    if (configBase == nullptr) {
        return BAD_VALUE;
    }
    TIME_CHECK();
    *configBase = AUDIO_CONFIG_BASE_INITIALIZER;
    configBase->sample_rate = 48000;
    configBase->format = AUDIO_FORMAT_PCM_24_BIT_PACKED;
    configBase->channel_mask = mIsInput ? AUDIO_CHANNEL_IN_STEREO : AUDIO_CHANNEL_OUT_STEREO;
    // if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::setParameters(const String8& kvPairs __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::getParameters(const String8& keys __unused, String8 *values) {
    TIME_CHECK();
    values->clear();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::getFrameSize(size_t *size) {
    if (size == nullptr) {
        return BAD_VALUE;
    }
    if (mFrameSizeBytes == 0) {
        return NO_INIT;
    }
    *size = mFrameSizeBytes;
    return OK;
}

status_t StreamHalAidl::addEffect(sp<EffectHalInterface> effect __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::removeEffect(sp<EffectHalInterface> effect __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::standby() {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::dump(int fd, const Vector<String16>& args) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    return mStream->dump(fd, Args(args).args(), args.size());
}

status_t StreamHalAidl::start() {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::stop() {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::createMmapBuffer(int32_t minSizeFrames __unused,
                                  struct audio_mmap_buffer_info *info __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::getMmapPosition(struct audio_mmap_position *position __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::setHalThreadPriority(int priority __unused) {
    mHalThreadPriority = priority;
    return OK;
}

status_t StreamHalAidl::getHalPid(pid_t *pid __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

bool StreamHalAidl::requestHalThreadPriority(pid_t threadPid __unused, pid_t threadId __unused) {
    if (mHalThreadPriority == HAL_THREAD_PRIORITY_DEFAULT) {
        return true;
    }
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::legacyCreateAudioPatch(const struct audio_port_config& port __unused,
                                               std::optional<audio_source_t> source __unused,
                                               audio_devices_t type __unused) {
    // Obsolete since 'DeviceHalAidl.supportsAudioPatches' always returns 'true'.
    return INVALID_OPERATION;
}

status_t StreamHalAidl::legacyReleaseAudioPatch() {
    // Obsolete since 'DeviceHalAidl.supportsAudioPatches' always returns 'true'.
    return INVALID_OPERATION;
}

namespace {

/* Notes on callback ownership.

This is how Binder ownership model looks like. The server implementation
is owned by Binder framework (via sp<>). Proxies are owned by clients.
When the last proxy disappears, Binder framework releases the server impl.

Thus, it is not needed to keep any references to StreamCallback (this is
the server impl) -- it will live as long as HAL server holds a strong ref to
IStreamCallback proxy.

The callback only keeps a weak reference to the stream. The stream is owned
by AudioFlinger.

*/

class StreamCallback : public ::aidl::android::hardware::audio::core::BnStreamCallback {
    ndk::ScopedAStatus onTransferReady() override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus onError() override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus onDrainReady() override {
        return ndk::ScopedAStatus::ok();
    }
};

}  // namespace

StreamOutHalAidl::StreamOutHalAidl(
        const StreamDescriptor& descriptor, const std::shared_ptr<IStreamOut>& stream)
        : StreamHalAidl("StreamOutHalAidl", false /*isInput*/, descriptor, getStreamCommon(stream)),
          mStream(stream) {}

status_t StreamOutHalAidl::getLatency(uint32_t *latency) {
    TIME_CHECK();
    *latency = 0;
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::setVolume(float left __unused, float right __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::selectPresentation(int presentationId __unused, int programId __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::write(
        const void *buffer __unused, size_t bytes __unused, size_t *written __unused) {
    // TIME_CHECK();  // TODO(b/238654698) reenable only when optimized.
    if (!mStream) return NO_INIT;
    *written = 0;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::getRenderPosition(uint32_t *dspFrames __unused) {
    // TIME_CHECK();  // TODO(b/238654698) reenable only when optimized.
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::getNextWriteTimestamp(int64_t *timestamp __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::setCallback(wp<StreamOutHalInterfaceCallback> callback __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::supportsPauseAndResume(
        bool *supportsPause __unused, bool *supportsResume __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::pause() {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::resume() {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::supportsDrain(bool *supportsDrain __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::drain(bool earlyNotify __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::flush() {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::getPresentationPosition(
        uint64_t *frames __unused, struct timespec *timestamp __unused) {
    // TIME_CHECK();  // TODO(b/238654698) reenable only when optimized.
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::updateSourceMetadata(
        const StreamOutHalInterface::SourceMetadata& sourceMetadata __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::getDualMonoMode(audio_dual_mono_mode_t* mode __unused) {
    return INVALID_OPERATION;
}

status_t StreamOutHalAidl::setDualMonoMode(audio_dual_mono_mode_t mode __unused) {
    return INVALID_OPERATION;
}

status_t StreamOutHalAidl::getAudioDescriptionMixLevel(float* leveldB __unused) {
    return INVALID_OPERATION;
}

status_t StreamOutHalAidl::setAudioDescriptionMixLevel(float leveldB __unused) {
    return INVALID_OPERATION;
}

status_t StreamOutHalAidl::getPlaybackRateParameters(
        audio_playback_rate_t* playbackRate __unused) {
    return INVALID_OPERATION;
}

status_t StreamOutHalAidl::setPlaybackRateParameters(
        const audio_playback_rate_t& playbackRate __unused) {
    return INVALID_OPERATION;
}

status_t StreamOutHalAidl::setEventCallback(
        const sp<StreamOutHalInterfaceEventCallback>& callback __unused) {
    return INVALID_OPERATION;
}

namespace {

struct StreamOutEventCallback {
    StreamOutEventCallback(const wp<StreamOutHalAidl>& stream) : mStream(stream) {}
  private:
    wp<StreamOutHalAidl> mStream;
};

}  // namespace

status_t StreamOutHalAidl::setLatencyMode(audio_latency_mode_t mode __unused) {
    return INVALID_OPERATION;
};

status_t StreamOutHalAidl::getRecommendedLatencyModes(
        std::vector<audio_latency_mode_t> *modes __unused) {
    return INVALID_OPERATION;
};

status_t StreamOutHalAidl::setLatencyModeCallback(
        const sp<StreamOutHalInterfaceLatencyModeCallback>& callback __unused) {
    return INVALID_OPERATION;
};

void StreamOutHalAidl::onWriteReady() {
    sp<StreamOutHalInterfaceCallback> callback = mCallback.load().promote();
    if (callback == 0) return;
    ALOGV("asyncCallback onWriteReady");
    callback->onWriteReady();
}

void StreamOutHalAidl::onDrainReady() {
    sp<StreamOutHalInterfaceCallback> callback = mCallback.load().promote();
    if (callback == 0) return;
    ALOGV("asyncCallback onDrainReady");
    callback->onDrainReady();
}

void StreamOutHalAidl::onError() {
    sp<StreamOutHalInterfaceCallback> callback = mCallback.load().promote();
    if (callback == 0) return;
    ALOGV("asyncCallback onError");
    callback->onError();
}

void StreamOutHalAidl::onCodecFormatChanged(const std::basic_string<uint8_t>& metadataBs __unused) {
    sp<StreamOutHalInterfaceEventCallback> callback = mEventCallback.load().promote();
    if (callback == nullptr) return;
    ALOGV("asyncCodecFormatCallback %s", __func__);
    callback->onCodecFormatChanged(metadataBs);
}

void StreamOutHalAidl::onRecommendedLatencyModeChanged(
        const std::vector<audio_latency_mode_t>& modes __unused) {
    sp<StreamOutHalInterfaceLatencyModeCallback> callback = mLatencyModeCallback.load().promote();
    if (callback == nullptr) return;
    callback->onRecommendedLatencyModeChanged(modes);
}

status_t StreamOutHalAidl::exit() {
    // FIXME this is using hard-coded strings but in the future, this functionality will be
    //       converted to use audio HAL extensions required to support tunneling
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

StreamInHalAidl::StreamInHalAidl(
        const StreamDescriptor& descriptor, const std::shared_ptr<IStreamIn>& stream)
        : StreamHalAidl("StreamInHalAidl", true /*isInput*/, descriptor, getStreamCommon(stream)),
          mStream(stream) {}

status_t StreamInHalAidl::setGain(float gain __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamInHalAidl::read(
        void *buffer __unused, size_t bytes __unused, size_t *read __unused) {
    // TIME_CHECK();  // TODO(b/238654698) reenable only when optimized.
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    // FIXME: Don't forget to update mPowerLog
    return OK;
}

status_t StreamInHalAidl::getInputFramesLost(uint32_t *framesLost __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamInHalAidl::getCapturePosition(int64_t *frames __unused, int64_t *time __unused) {
    // TIME_CHECK();  // TODO(b/238654698) reenable only when optimized.
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamInHalAidl::getActiveMicrophones(
        std::vector<media::MicrophoneInfo> *microphones __unused) {
    if (mStream == 0) return NO_INIT;
    return INVALID_OPERATION;
}

status_t StreamInHalAidl::updateSinkMetadata(
        const StreamInHalInterface::SinkMetadata& sinkMetadata  __unused) {
    return INVALID_OPERATION;
}

status_t StreamInHalAidl::setPreferredMicrophoneDirection(
            audio_microphone_direction_t direction __unused) {
    if (mStream == 0) return NO_INIT;
    return INVALID_OPERATION;
}

status_t StreamInHalAidl::setPreferredMicrophoneFieldDimension(float zoom __unused) {
    if (mStream == 0) return NO_INIT;
    return INVALID_OPERATION;
}

} // namespace android
