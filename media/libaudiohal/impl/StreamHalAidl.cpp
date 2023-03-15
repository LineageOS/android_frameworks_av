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

#include <algorithm>
#include <cstdint>

#include <audio_utils/clock.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionUtil.h>
#include <media/AudioParameter.h>
#include <mediautils/TimeCheck.h>
#include <system/audio.h>
#include <utils/Log.h>

#include "DeviceHalAidl.h"
#include "StreamHalAidl.h"

using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::common::PlaybackTrackMetadata;
using ::aidl::android::hardware::audio::common::RecordTrackMetadata;
using ::aidl::android::hardware::audio::core::IStreamCommon;
using ::aidl::android::hardware::audio::core::IStreamIn;
using ::aidl::android::hardware::audio::core::IStreamOut;
using ::aidl::android::hardware::audio::core::StreamDescriptor;
using ::aidl::android::legacy2aidl_audio_channel_mask_t_AudioChannelLayout;

namespace android {

using HalCommand = StreamDescriptor::Command;
namespace {
template<HalCommand::Tag cmd> HalCommand makeHalCommand() {
    return HalCommand::make<cmd>(::aidl::android::media::audio::common::Void{});
}
template<HalCommand::Tag cmd, typename T> HalCommand makeHalCommand(T data) {
    return HalCommand::make<cmd>(data);
}
}  // namespace

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
        std::string_view className, bool isInput, const audio_config& config,
        int32_t nominalLatency, StreamContextAidl&& context,
        const std::shared_ptr<IStreamCommon>& stream)
        : ConversionHelperAidl(className),
          mIsInput(isInput),
          mConfig(configToBase(config)),
          mContext(std::move(context)),
          mStream(stream) {
    {
        std::lock_guard l(mLock);
        mLastReply.latencyMs = nominalLatency;
    }
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
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    if (size == nullptr) {
        return BAD_VALUE;
    }
    if (mContext.getFrameSizeBytes() == 0 || mContext.getBufferSizeFrames() == 0 ||
            !mStream) {
        return NO_INIT;
    }
    *size = mContext.getBufferSizeBytes();
    return OK;
}

status_t StreamHalAidl::getAudioProperties(audio_config_base_t *configBase) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    if (configBase == nullptr) {
        return BAD_VALUE;
    }
    if (!mStream) return NO_INIT;
    *configBase = mConfig;
    return OK;
}

namespace {

// 'action' must accept a value of type 'T' and return 'status_t'.
// The function returns 'true' if the parameter was found, and the action has succeeded.
// The function returns 'false' if the parameter was not found.
// Any errors get propagated, if there are errors it means the parameter was found.
template<typename T, typename F>
error::Result<bool> filterOutAndProcessParameter(
        AudioParameter& parameters, const String8& key, const F& action) {
    if (parameters.containsKey(key)) {
        T value;
        status_t status = parameters.get(key, value);
        if (status == OK) {
            parameters.remove(key);
            status = action(value);
            if (status == OK) return true;
        }
        return base::unexpected(status);
    }
    return false;
}

}  // namespace

status_t StreamHalAidl::setParameters(const String8& kvPairs) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;

    AudioParameter parameters(kvPairs);
    ALOGD("%s: parameters: %s", __func__, parameters.toString().c_str());

    (void)VALUE_OR_RETURN_STATUS(filterOutAndProcessParameter<int>(
                    parameters, String8(AudioParameter::keyStreamHwAvSync),
            [&](int hwAvSyncId) {
                return statusTFromBinderStatus(mStream->updateHwAvSyncId(hwAvSyncId));
            }));

    ALOGW_IF(parameters.size() != 0, "%s: unknown parameters, ignored: %s",
            __func__, parameters.toString().c_str());
    return OK;
}

status_t StreamHalAidl::getParameters(const String8& keys __unused, String8 *values) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    values->clear();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::getFrameSize(size_t *size) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    if (size == nullptr) {
        return BAD_VALUE;
    }
    if (mContext.getFrameSizeBytes() == 0 || !mStream) {
        return NO_INIT;
    }
    *size = mContext.getFrameSizeBytes();
    return OK;
}

status_t StreamHalAidl::addEffect(sp<EffectHalInterface> effect __unused) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::removeEffect(sp<EffectHalInterface> effect __unused) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::standby() {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    const auto state = getState();
    StreamDescriptor::Reply reply;
    switch (state) {
        case StreamDescriptor::State::ACTIVE:
            if (status_t status = pause(&reply); status != OK) return status;
            if (reply.state != StreamDescriptor::State::PAUSED) {
                ALOGE("%s: unexpected stream state: %s (expected PAUSED)",
                        __func__, toString(reply.state).c_str());
                return INVALID_OPERATION;
            }
            FALLTHROUGH_INTENDED;
        case StreamDescriptor::State::PAUSED:
        case StreamDescriptor::State::DRAIN_PAUSED:
            if (mIsInput) return flush();
            if (status_t status = flush(&reply); status != OK) return status;
            if (reply.state != StreamDescriptor::State::IDLE) {
                ALOGE("%s: unexpected stream state: %s (expected IDLE)",
                        __func__, toString(reply.state).c_str());
                return INVALID_OPERATION;
            }
            FALLTHROUGH_INTENDED;
        case StreamDescriptor::State::IDLE:
            if (status_t status = sendCommand(makeHalCommand<HalCommand::Tag::standby>(),
                            &reply, true /*safeFromNonWorkerThread*/); status != OK) {
                return status;
            }
            if (reply.state != StreamDescriptor::State::STANDBY) {
                ALOGE("%s: unexpected stream state: %s (expected STANDBY)",
                        __func__, toString(reply.state).c_str());
                return INVALID_OPERATION;
            }
            FALLTHROUGH_INTENDED;
        case StreamDescriptor::State::STANDBY:
            return OK;
        default:
            ALOGE("%s: not supported from %s stream state %s",
                    __func__, mIsInput ? "input" : "output", toString(state).c_str());
            return INVALID_OPERATION;
    }
}

status_t StreamHalAidl::dump(int fd, const Vector<String16>& args) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    return mStream->dump(fd, Args(args).args(), args.size());
}

status_t StreamHalAidl::start() {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::stop() {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::getLatency(uint32_t *latency) {
    ALOGV("%p %s::%s", this, getClassName().c_str(), __func__);
    if (!mStream) return NO_INIT;
    StreamDescriptor::Reply reply;
    if (status_t status = updateCountersIfNeeded(&reply); status != OK) {
        return status;
    }
    *latency = std::max<int32_t>(0, reply.latencyMs);
    return OK;
}

status_t StreamHalAidl::getObservablePosition(int64_t *frames, int64_t *timestamp) {
    ALOGV("%p %s::%s", this, getClassName().c_str(), __func__);
    if (!mStream) return NO_INIT;
    StreamDescriptor::Reply reply;
    if (status_t status = updateCountersIfNeeded(&reply); status != OK) {
        return status;
    }
    *frames = reply.observable.frames;
    *timestamp = reply.observable.timeNs;
    return OK;
}

status_t StreamHalAidl::getXruns(int32_t *frames) {
    ALOGV("%p %s::%s", this, getClassName().c_str(), __func__);
    if (!mStream) return NO_INIT;
    StreamDescriptor::Reply reply;
    if (status_t status = updateCountersIfNeeded(&reply); status != OK) {
        return status;
    }
    *frames = reply.xrunFrames;
    return OK;
}

status_t StreamHalAidl::transfer(void *buffer, size_t bytes, size_t *transferred) {
    ALOGV("%p %s::%s", this, getClassName().c_str(), __func__);
    // TIME_CHECK();  // TODO(b/243839867) reenable only when optimized.
    if (!mStream || mContext.getDataMQ() == nullptr) return NO_INIT;
    mWorkerTid.store(gettid(), std::memory_order_release);
    // Switch the stream into an active state if needed.
    // Note: in future we may add support for priming the audio pipeline
    // with data prior to enabling output (thus we can issue a "burst" command in the "standby"
    // stream state), however this scenario wasn't supported by the HIDL HAL.
    if (getState() == StreamDescriptor::State::STANDBY) {
        StreamDescriptor::Reply reply;
        if (status_t status = sendCommand(makeHalCommand<HalCommand::Tag::start>(), &reply);
                status != OK) {
            return status;
        }
        if (reply.state != StreamDescriptor::State::IDLE) {
            ALOGE("%s: failed to get the stream out of standby, actual state: %s",
                    __func__, toString(reply.state).c_str());
            return INVALID_OPERATION;
        }
    }
    if (!mIsInput) {
        bytes = std::min(bytes, mContext.getDataMQ()->availableToWrite());
    }
    StreamDescriptor::Command burst =
            StreamDescriptor::Command::make<StreamDescriptor::Command::Tag::burst>(bytes);
    if (!mIsInput) {
        if (!mContext.getDataMQ()->write(static_cast<const int8_t*>(buffer), bytes)) {
            ALOGE("%s: failed to write %zu bytes to data MQ", __func__, bytes);
            return NOT_ENOUGH_DATA;
        }
    }
    StreamDescriptor::Reply reply;
    if (status_t status = sendCommand(burst, &reply); status != OK) {
        return status;
    }
    *transferred = reply.fmqByteCount;
    if (mIsInput) {
        LOG_ALWAYS_FATAL_IF(*transferred > bytes,
                "%s: HAL module read %zu bytes, which exceeds requested count %zu",
                __func__, *transferred, bytes);
        if (auto toRead = mContext.getDataMQ()->availableToRead();
                toRead != 0 && !mContext.getDataMQ()->read(static_cast<int8_t*>(buffer), toRead)) {
            ALOGE("%s: failed to read %zu bytes to data MQ", __func__, toRead);
            return NOT_ENOUGH_DATA;
        }
    }
    mStreamPowerLog.log(buffer, *transferred);
    return OK;
}

status_t StreamHalAidl::pause(StreamDescriptor::Reply* reply) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    return sendCommand(makeHalCommand<HalCommand::Tag::pause>(), reply,
            true /*safeFromNonWorkerThread*/);  // The workers stops its I/O activity first.
}

status_t StreamHalAidl::resume(StreamDescriptor::Reply* reply) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (mIsInput) {
        return sendCommand(makeHalCommand<HalCommand::Tag::burst>(0), reply);
    } else {
        if (mContext.isAsynchronous()) {
            // Handle pause-flush-resume sequence. 'flush' from PAUSED goes to
            // IDLE. We move here from IDLE to ACTIVE (same as 'start' from PAUSED).
            const auto state = getState();
            if (state == StreamDescriptor::State::IDLE) {
                StreamDescriptor::Reply localReply{};
                StreamDescriptor::Reply* innerReply = reply ?: &localReply;
                if (status_t status =
                        sendCommand(makeHalCommand<HalCommand::Tag::burst>(0), innerReply);
                        status != OK) {
                    return status;
                }
                if (innerReply->state != StreamDescriptor::State::ACTIVE) {
                    ALOGE("%s: unexpected stream state: %s (expected ACTIVE)",
                            __func__, toString(innerReply->state).c_str());
                    return INVALID_OPERATION;
                }
                return OK;
            }
        }
        return sendCommand(makeHalCommand<HalCommand::Tag::start>(), reply);
    }
}

status_t StreamHalAidl::drain(bool earlyNotify, StreamDescriptor::Reply* reply) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    return sendCommand(makeHalCommand<HalCommand::Tag::drain>(
                    mIsInput ? StreamDescriptor::DrainMode::DRAIN_UNSPECIFIED :
                    earlyNotify ? StreamDescriptor::DrainMode::DRAIN_EARLY_NOTIFY :
                    StreamDescriptor::DrainMode::DRAIN_ALL), reply,
                    true /*safeFromNonWorkerThread*/);
}

status_t StreamHalAidl::flush(StreamDescriptor::Reply* reply) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    return sendCommand(makeHalCommand<HalCommand::Tag::flush>(), reply,
            true /*safeFromNonWorkerThread*/);  // The workers stops its I/O activity first.
}

status_t StreamHalAidl::exit() {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::createMmapBuffer(int32_t minSizeFrames __unused,
                                  struct audio_mmap_buffer_info *info __unused) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::getMmapPosition(struct audio_mmap_position *position __unused) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamHalAidl::setHalThreadPriority(int priority __unused) {
    // Obsolete, must be done by the HAL module.
    return OK;
}

status_t StreamHalAidl::getHalPid(pid_t *pid __unused) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

bool StreamHalAidl::requestHalThreadPriority(pid_t threadPid __unused, pid_t threadId __unused) {
    // Obsolete, must be done by the HAL module.
    return true;
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

status_t StreamHalAidl::sendCommand(
        const ::aidl::android::hardware::audio::core::StreamDescriptor::Command &command,
        ::aidl::android::hardware::audio::core::StreamDescriptor::Reply* reply,
        bool safeFromNonWorkerThread) {
    // TIME_CHECK();  // TODO(b/243839867) reenable only when optimized.
    if (!safeFromNonWorkerThread) {
        const pid_t workerTid = mWorkerTid.load(std::memory_order_acquire);
        LOG_ALWAYS_FATAL_IF(workerTid != gettid(),
                "%s %s: must be invoked from the worker thread (%d)",
                __func__, command.toString().c_str(), workerTid);
    }
    if (!mContext.getCommandMQ()->writeBlocking(&command, 1)) {
        ALOGE("%s: failed to write command %s to MQ", __func__, command.toString().c_str());
        return NOT_ENOUGH_DATA;
    }
    StreamDescriptor::Reply localReply{};
    if (reply == nullptr) {
        reply = &localReply;
    }
    if (!mContext.getReplyMQ()->readBlocking(reply, 1)) {
        ALOGE("%s: failed to read from reply MQ, command %s", __func__, command.toString().c_str());
        return NOT_ENOUGH_DATA;
    }
    {
        std::lock_guard l(mLock);
        mLastReply = *reply;
    }
    switch (reply->status) {
        case STATUS_OK: return OK;
        case STATUS_BAD_VALUE: return BAD_VALUE;
        case STATUS_INVALID_OPERATION: return INVALID_OPERATION;
        case STATUS_NOT_ENOUGH_DATA: return NOT_ENOUGH_DATA;
        default:
            ALOGE("%s: unexpected status %d returned for command %s",
                    __func__, reply->status, command.toString().c_str());
            return INVALID_OPERATION;
    }
}

status_t StreamHalAidl::updateCountersIfNeeded(
        ::aidl::android::hardware::audio::core::StreamDescriptor::Reply* reply) {
    if (mWorkerTid.load(std::memory_order_acquire) == gettid()) {
        if (const auto state = getState(); state != StreamDescriptor::State::ACTIVE &&
                state != StreamDescriptor::State::DRAINING &&
                state != StreamDescriptor::State::TRANSFERRING) {
            return sendCommand(makeHalCommand<HalCommand::Tag::getStatus>(), reply);
        }
    }
    if (reply != nullptr) {
        std::lock_guard l(mLock);
        *reply = mLastReply;
    }
    return OK;
}

// static
ConversionResult<::aidl::android::hardware::audio::common::SourceMetadata>
StreamOutHalAidl::legacy2aidl_SourceMetadata(const StreamOutHalInterface::SourceMetadata& legacy) {
    ::aidl::android::hardware::audio::common::SourceMetadata aidl;
    aidl.tracks = VALUE_OR_RETURN(
            ::aidl::android::convertContainer<std::vector<PlaybackTrackMetadata>>(
                    legacy.tracks,
                    ::aidl::android::legacy2aidl_playback_track_metadata_v7_PlaybackTrackMetadata));
    return aidl;
}

StreamOutHalAidl::StreamOutHalAidl(
        const audio_config& config, StreamContextAidl&& context, int32_t nominalLatency,
        const std::shared_ptr<IStreamOut>& stream, const sp<CallbackBroker>& callbackBroker)
        : StreamHalAidl("StreamOutHalAidl", false /*isInput*/, config, nominalLatency,
                std::move(context), getStreamCommon(stream)),
          mStream(stream), mCallbackBroker(callbackBroker) {
    // Initialize the offload metadata
    mOffloadMetadata.sampleRate = static_cast<int32_t>(config.sample_rate);
    mOffloadMetadata.channelMask = VALUE_OR_FATAL(
            ::aidl::android::legacy2aidl_audio_channel_mask_t_AudioChannelLayout(
                    config.channel_mask, false));
    mOffloadMetadata.averageBitRatePerSecond = static_cast<int32_t>(config.offload_info.bit_rate);
}

StreamOutHalAidl::~StreamOutHalAidl() {
    if (auto broker = mCallbackBroker.promote(); broker != nullptr) {
        broker->clearCallbacks(this);
    }
}

status_t StreamOutHalAidl::setParameters(const String8& kvPairs) {
    if (!mStream) return NO_INIT;

    AudioParameter parameters(kvPairs);
    ALOGD("%s parameters: %s", __func__, parameters.toString().c_str());

    if (status_t status = filterAndUpdateOffloadMetadata(parameters); status != OK) {
        ALOGW("%s filtering or updating offload metadata failed: %d", __func__, status);
    }

    return StreamHalAidl::setParameters(parameters.toString());
}

status_t StreamOutHalAidl::getLatency(uint32_t *latency) {
    return StreamHalAidl::getLatency(latency);
}

status_t StreamOutHalAidl::setVolume(float left, float right) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    return statusTFromBinderStatus(mStream->setHwVolume({left, right}));
}

status_t StreamOutHalAidl::selectPresentation(int presentationId __unused, int programId __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::write(const void *buffer, size_t bytes, size_t *written) {
    if (buffer == nullptr || written == nullptr) {
        return BAD_VALUE;
    }
    // For the output scenario, 'transfer' does not modify the buffer.
    return transfer(const_cast<void*>(buffer), bytes, written);
}

status_t StreamOutHalAidl::getRenderPosition(uint32_t *dspFrames) {
    if (dspFrames == nullptr) {
        return BAD_VALUE;
    }
    int64_t aidlFrames = 0, aidlTimestamp = 0;
    if (status_t status = getObservablePosition(&aidlFrames, &aidlTimestamp); status != OK) {
        return OK;
    }
    *dspFrames = std::clamp<int64_t>(aidlFrames, 0, UINT32_MAX);
    return OK;
}

status_t StreamOutHalAidl::getNextWriteTimestamp(int64_t *timestamp __unused) {
    // Obsolete, use getPresentationPosition.
    return INVALID_OPERATION;
}

status_t StreamOutHalAidl::setCallback(wp<StreamOutHalInterfaceCallback> callback) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (!mContext.isAsynchronous()) {
        ALOGE("%s: the callback is intended for asynchronous streams only", __func__);
        return INVALID_OPERATION;
    }
    if (auto broker = mCallbackBroker.promote(); broker != nullptr) {
        if (auto cb = callback.promote(); cb != nullptr) {
            broker->setStreamOutCallback(this, cb);
        } else {
            // It is expected that the framework never passes a null pointer.
            // In the AIDL model callbacks can't be "unregistered".
            LOG_ALWAYS_FATAL("%s: received an expired or null callback pointer", __func__);
        }
    }
    return OK;
}

status_t StreamOutHalAidl::supportsPauseAndResume(bool *supportsPause, bool *supportsResume) {
    if (supportsPause == nullptr || supportsResume == nullptr) {
        return BAD_VALUE;
    }
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    *supportsPause = *supportsResume = true;
    return OK;
}

status_t StreamOutHalAidl::pause() {
    return StreamHalAidl::pause();
}

status_t StreamOutHalAidl::resume() {
    return StreamHalAidl::resume();
}

status_t StreamOutHalAidl::supportsDrain(bool *supportsDrain) {
    if (supportsDrain == nullptr) {
        return BAD_VALUE;
    }
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    *supportsDrain = true;
    return OK;
}

status_t StreamOutHalAidl::drain(bool earlyNotify) {
    return StreamHalAidl::drain(earlyNotify);
}

status_t StreamOutHalAidl::flush() {
    return StreamHalAidl::flush();
}

status_t StreamOutHalAidl::getPresentationPosition(uint64_t *frames, struct timespec *timestamp) {
    if (frames == nullptr || timestamp == nullptr) {
        return BAD_VALUE;
    }
    int64_t aidlFrames = 0, aidlTimestamp = 0;
    if (status_t status = getObservablePosition(&aidlFrames, &aidlTimestamp); status != OK) {
        return status;
    }
    *frames = std::max<int64_t>(0, aidlFrames);
    timestamp->tv_sec = aidlTimestamp / NANOS_PER_SECOND;
    timestamp->tv_nsec = aidlTimestamp - timestamp->tv_sec * NANOS_PER_SECOND;
    return OK;
}

status_t StreamOutHalAidl::updateSourceMetadata(
        const StreamOutHalInterface::SourceMetadata& sourceMetadata) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ::aidl::android::hardware::audio::common::SourceMetadata aidlMetadata =
              VALUE_OR_RETURN_STATUS(legacy2aidl_SourceMetadata(sourceMetadata));
    return statusTFromBinderStatus(mStream->updateMetadata(aidlMetadata));
}

status_t StreamOutHalAidl::getDualMonoMode(audio_dual_mono_mode_t* mode __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::setDualMonoMode(audio_dual_mono_mode_t mode __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::getAudioDescriptionMixLevel(float* leveldB __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::setAudioDescriptionMixLevel(float leveldB __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamOutHalAidl::getPlaybackRateParameters(
        audio_playback_rate_t* playbackRate __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return BAD_VALUE;
}

status_t StreamOutHalAidl::setPlaybackRateParameters(
        const audio_playback_rate_t& playbackRate __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return BAD_VALUE;
}

status_t StreamOutHalAidl::setEventCallback(
        const sp<StreamOutHalInterfaceEventCallback>& callback) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (auto broker = mCallbackBroker.promote(); broker != nullptr) {
        broker->setStreamOutEventCallback(this, callback);
    }
    return OK;
}

status_t StreamOutHalAidl::setLatencyMode(audio_latency_mode_t mode __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
};

status_t StreamOutHalAidl::getRecommendedLatencyModes(
        std::vector<audio_latency_mode_t> *modes __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
};

status_t StreamOutHalAidl::setLatencyModeCallback(
        const sp<StreamOutHalInterfaceLatencyModeCallback>& callback) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (auto broker = mCallbackBroker.promote(); broker != nullptr) {
        broker->setStreamOutLatencyModeCallback(this, callback);
    }
    return OK;
};

status_t StreamOutHalAidl::exit() {
    return StreamHalAidl::exit();
}

status_t StreamOutHalAidl::filterAndUpdateOffloadMetadata(AudioParameter &parameters) {
    TIME_CHECK();
    bool updateMetadata = false;
    if (VALUE_OR_RETURN_STATUS(filterOutAndProcessParameter<int>(
                parameters, String8(AudioParameter::keyOffloadCodecAverageBitRate),
                [&](int value) {
                    return value > 0 ?
                            mOffloadMetadata.averageBitRatePerSecond = value, OK : BAD_VALUE;
                }))) {
        updateMetadata = true;
    }
    if (VALUE_OR_RETURN_STATUS(filterOutAndProcessParameter<int>(
                parameters, String8(AudioParameter::keyOffloadCodecSampleRate),
                [&](int value) {
                    return value > 0 ? mOffloadMetadata.sampleRate = value, OK : BAD_VALUE;
                }))) {
        updateMetadata = true;
    }
    if (VALUE_OR_RETURN_STATUS(filterOutAndProcessParameter<int>(
                parameters, String8(AudioParameter::keyOffloadCodecChannels),
                [&](int value) -> status_t {
                    if (value > 0) {
                        audio_channel_mask_t channel_mask = audio_channel_out_mask_from_count(
                                static_cast<uint32_t>(value));
                        if (channel_mask == AUDIO_CHANNEL_INVALID) return BAD_VALUE;
                        mOffloadMetadata.channelMask = VALUE_OR_RETURN_STATUS(
                                ::aidl::android::legacy2aidl_audio_channel_mask_t_AudioChannelLayout(
                                        channel_mask, false /*isInput*/));
                    }
                    return BAD_VALUE;
                }))) {
        updateMetadata = true;
    }
    if (VALUE_OR_RETURN_STATUS(filterOutAndProcessParameter<int>(
                parameters, String8(AudioParameter::keyOffloadCodecDelaySamples),
                [&](int value) {
                    // The legacy keys are misnamed, the value is in frames.
                    return value > 0 ? mOffloadMetadata.delayFrames = value, OK : BAD_VALUE;
                }))) {
        updateMetadata = true;
    }
    if (VALUE_OR_RETURN_STATUS(filterOutAndProcessParameter<int>(
                parameters, String8(AudioParameter::keyOffloadCodecPaddingSamples),
                [&](int value) {
                    // The legacy keys are misnamed, the value is in frames.
                    return value > 0 ? mOffloadMetadata.paddingFrames = value, OK : BAD_VALUE;
                }))) {
        updateMetadata = true;
    }
    if (updateMetadata) {
        ALOGD("%s set offload metadata %s", __func__, mOffloadMetadata.toString().c_str());
        if (status_t status = statusTFromBinderStatus(
                        mStream->updateOffloadMetadata(mOffloadMetadata)); status != OK) {
            ALOGE("%s: updateOffloadMetadata failed %d", __func__, status);
            return status;
        }
    }
    return OK;
}

// static
ConversionResult<::aidl::android::hardware::audio::common::SinkMetadata>
StreamInHalAidl::legacy2aidl_SinkMetadata(const StreamInHalInterface::SinkMetadata& legacy) {
    ::aidl::android::hardware::audio::common::SinkMetadata aidl;
    aidl.tracks = VALUE_OR_RETURN(
            ::aidl::android::convertContainer<std::vector<RecordTrackMetadata>>(
                    legacy.tracks,
                    ::aidl::android::legacy2aidl_record_track_metadata_v7_RecordTrackMetadata));
    return aidl;
}

StreamInHalAidl::StreamInHalAidl(
        const audio_config& config, StreamContextAidl&& context, int32_t nominalLatency,
        const std::shared_ptr<IStreamIn>& stream)
        : StreamHalAidl("StreamInHalAidl", true /*isInput*/, config, nominalLatency,
                std::move(context), getStreamCommon(stream)),
          mStream(stream) {}

status_t StreamInHalAidl::setGain(float gain __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamInHalAidl::read(void *buffer, size_t bytes, size_t *read) {
    if (buffer == nullptr || read == nullptr) {
        return BAD_VALUE;
    }
    return transfer(buffer, bytes, read);
}

status_t StreamInHalAidl::getInputFramesLost(uint32_t *framesLost) {
    if (framesLost == nullptr) {
        return BAD_VALUE;
    }
    int32_t aidlXruns = 0;
    if (status_t status = getXruns(&aidlXruns); status != OK) {
        return status;
    }
    *framesLost = std::max<int32_t>(0, aidlXruns);
    return OK;
}

status_t StreamInHalAidl::getCapturePosition(int64_t *frames, int64_t *time) {
    if (frames == nullptr || time == nullptr) {
        return BAD_VALUE;
    }
    return getObservablePosition(frames, time);
}

status_t StreamInHalAidl::getActiveMicrophones(
        std::vector<media::MicrophoneInfoFw> *microphones __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamInHalAidl::updateSinkMetadata(
        const StreamInHalInterface::SinkMetadata& sinkMetadata) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ::aidl::android::hardware::audio::common::SinkMetadata aidlMetadata =
              VALUE_OR_RETURN_STATUS(legacy2aidl_SinkMetadata(sinkMetadata));
    return statusTFromBinderStatus(mStream->updateMetadata(aidlMetadata));
}

status_t StreamInHalAidl::setPreferredMicrophoneDirection(
            audio_microphone_direction_t direction __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t StreamInHalAidl::setPreferredMicrophoneFieldDimension(float zoom __unused) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

} // namespace android
