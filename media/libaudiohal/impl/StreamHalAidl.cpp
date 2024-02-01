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
#include <media/AidlConversion.h>
#include <media/AidlConversionCore.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionUtil.h>
#include <media/AudioParameter.h>
#include <mediautils/TimeCheck.h>
#include <system/audio.h>
#include <utils/Log.h>

#include "DeviceHalAidl.h"
#include "EffectHalAidl.h"
#include "StreamHalAidl.h"

using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::common::PlaybackTrackMetadata;
using ::aidl::android::hardware::audio::common::RecordTrackMetadata;
using ::aidl::android::hardware::audio::core::IStreamCommon;
using ::aidl::android::hardware::audio::core::IStreamIn;
using ::aidl::android::hardware::audio::core::IStreamOut;
using ::aidl::android::hardware::audio::core::StreamDescriptor;
using ::aidl::android::hardware::audio::core::MmapBufferDescriptor;
using ::aidl::android::media::audio::common::MicrophoneDynamicInfo;
using ::aidl::android::media::audio::IHalAdapterVendorExtension;

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
        const std::shared_ptr<IStreamCommon>& stream,
        const std::shared_ptr<IHalAdapterVendorExtension>& vext)
        : ConversionHelperAidl(className),
          mIsInput(isInput),
          mConfig(configToBase(config)),
          mContext(std::move(context)),
          mStream(stream),
          mVendorExt(vext) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
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
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
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
    return parseAndSetVendorParameters(mVendorExt, mStream, parameters);
}

status_t StreamHalAidl::getParameters(const String8& keys __unused, String8 *values) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (values == nullptr) {
        return BAD_VALUE;
    }
    AudioParameter parameterKeys(keys), result;
    *values = result.toString();
    return parseAndGetVendorParameters(mVendorExt, mStream, parameterKeys, values);
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

status_t StreamHalAidl::addEffect(sp<EffectHalInterface> effect) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (effect == nullptr) {
        return BAD_VALUE;
    }
    auto aidlEffect = sp<effect::EffectHalAidl>::cast(effect);
    return statusTFromBinderStatus(mStream->addEffect(aidlEffect->getIEffect()));
}

status_t StreamHalAidl::removeEffect(sp<EffectHalInterface> effect) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (effect == nullptr) {
        return BAD_VALUE;
    }
    auto aidlEffect = sp<effect::EffectHalAidl>::cast(effect);
    return statusTFromBinderStatus(mStream->removeEffect(aidlEffect->getIEffect()));
}

status_t StreamHalAidl::standby() {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    const auto state = getState();
    StreamDescriptor::Reply reply;
    switch (state) {
        case StreamDescriptor::State::ACTIVE:
            RETURN_STATUS_IF_ERROR(pause(&reply));
            if (reply.state != StreamDescriptor::State::PAUSED) {
                ALOGE("%s: unexpected stream state: %s (expected PAUSED)",
                        __func__, toString(reply.state).c_str());
                return INVALID_OPERATION;
            }
            FALLTHROUGH_INTENDED;
        case StreamDescriptor::State::PAUSED:
        case StreamDescriptor::State::DRAIN_PAUSED:
            if (mIsInput) return flush();
            RETURN_STATUS_IF_ERROR(flush(&reply));
            if (reply.state != StreamDescriptor::State::IDLE) {
                ALOGE("%s: unexpected stream state: %s (expected IDLE)",
                        __func__, toString(reply.state).c_str());
                return INVALID_OPERATION;
            }
            FALLTHROUGH_INTENDED;
        case StreamDescriptor::State::IDLE:
            RETURN_STATUS_IF_ERROR(sendCommand(makeHalCommand<HalCommand::Tag::standby>(),
                            &reply, true /*safeFromNonWorkerThread*/));
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
    status_t status = mStream->dump(fd, Args(args).args(), args.size());
    mStreamPowerLog.dump(fd);
    return status;
}

status_t StreamHalAidl::start() {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    const auto state = getState();
    StreamDescriptor::Reply reply;
    if (state == StreamDescriptor::State::STANDBY) {
        RETURN_STATUS_IF_ERROR(sendCommand(makeHalCommand<HalCommand::Tag::start>(), &reply, true));
        return sendCommand(makeHalCommand<HalCommand::Tag::burst>(0), &reply, true);
    }

    return INVALID_OPERATION;
}

status_t StreamHalAidl::stop() {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    if (!mStream) return NO_INIT;
    return standby();
}

status_t StreamHalAidl::getLatency(uint32_t *latency) {
    ALOGV("%p %s::%s", this, getClassName().c_str(), __func__);
    if (!mStream) return NO_INIT;
    StreamDescriptor::Reply reply;
    RETURN_STATUS_IF_ERROR(updateCountersIfNeeded(&reply));
    *latency = std::clamp(std::max<int32_t>(0, reply.latencyMs), 1, 3000);
    ALOGW_IF(reply.latencyMs != static_cast<int32_t>(*latency),
             "Suspicious latency value reported by HAL: %d, clamped to %u", reply.latencyMs,
             *latency);
    return OK;
}

status_t StreamHalAidl::getObservablePosition(int64_t *frames, int64_t *timestamp) {
    ALOGV("%p %s::%s", this, getClassName().c_str(), __func__);
    if (!mStream) return NO_INIT;
    StreamDescriptor::Reply reply;
    RETURN_STATUS_IF_ERROR(updateCountersIfNeeded(&reply));
    *frames = std::max<int64_t>(0, reply.observable.frames);
    *timestamp = std::max<int64_t>(0, reply.observable.timeNs);
    return OK;
}

status_t StreamHalAidl::getHardwarePosition(int64_t *frames, int64_t *timestamp) {
    ALOGV("%p %s::%s", this, getClassName().c_str(), __func__);
    if (!mStream) return NO_INIT;
    StreamDescriptor::Reply reply;
    // TODO: switch to updateCountersIfNeeded once we sort out mWorkerTid initialization
    RETURN_STATUS_IF_ERROR(sendCommand(makeHalCommand<HalCommand::Tag::getStatus>(), &reply, true));
    *frames = std::max<int64_t>(0, reply.hardware.frames);
    *timestamp = std::max<int64_t>(0, reply.hardware.timeNs);
    return OK;
}

status_t StreamHalAidl::getXruns(int32_t *frames) {
    ALOGV("%p %s::%s", this, getClassName().c_str(), __func__);
    if (!mStream) return NO_INIT;
    StreamDescriptor::Reply reply;
    RETURN_STATUS_IF_ERROR(updateCountersIfNeeded(&reply));
    *frames = std::max<int32_t>(0, reply.xrunFrames);
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
        RETURN_STATUS_IF_ERROR(sendCommand(makeHalCommand<HalCommand::Tag::start>(), &reply));
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
    RETURN_STATUS_IF_ERROR(sendCommand(burst, &reply));
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
                RETURN_STATUS_IF_ERROR(
                        sendCommand(makeHalCommand<HalCommand::Tag::burst>(0), innerReply));
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
    return statusTFromBinderStatus(mStream->prepareToClose());
}

status_t StreamHalAidl::createMmapBuffer(int32_t minSizeFrames __unused,
                                         struct audio_mmap_buffer_info *info) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (!mContext.isMmapped()) {
        return BAD_VALUE;
    }
    const MmapBufferDescriptor& bufferDescriptor = mContext.getMmapBufferDescriptor();
    info->shared_memory_fd = bufferDescriptor.sharedMemory.fd.get();
    info->buffer_size_frames = mContext.getBufferSizeFrames();
    info->burst_size_frames = bufferDescriptor.burstSizeFrames;
    info->flags = static_cast<audio_mmap_buffer_flag>(bufferDescriptor.flags);

    return OK;
}

status_t StreamHalAidl::getMmapPosition(struct audio_mmap_position *position) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (!mContext.isMmapped()) {
        return BAD_VALUE;
    }
    int64_t aidlPosition = 0, aidlTimestamp = 0;
    RETURN_STATUS_IF_ERROR(getHardwarePosition(&aidlPosition, &aidlTimestamp));
    position->time_nanoseconds = aidlTimestamp;
    position->position_frames = static_cast<int32_t>(aidlPosition);
    return OK;
}

status_t StreamHalAidl::setHalThreadPriority(int priority __unused) {
    // Obsolete, must be done by the HAL module.
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
        // Not every command replies with 'latencyMs' field filled out, substitute the last
        // returned value in that case.
        if (reply->latencyMs <= 0) {
            reply->latencyMs = mLastReply.latencyMs;
        }
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
        const std::shared_ptr<IStreamOut>& stream,
        const std::shared_ptr<IHalAdapterVendorExtension>& vext,
        const sp<CallbackBroker>& callbackBroker)
        : StreamHalAidl("StreamOutHalAidl", false /*isInput*/, config, nominalLatency,
                std::move(context), getStreamCommon(stream), vext),
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
    ALOGD("%s: parameters: \"%s\"", __func__, parameters.toString().c_str());

    if (status_t status = filterAndUpdateOffloadMetadata(parameters); status != OK) {
        ALOGW("%s: filtering or updating offload metadata failed: %d", __func__, status);
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

status_t StreamOutHalAidl::selectPresentation(int presentationId, int programId) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    return statusTFromBinderStatus(mStream->selectPresentation(presentationId, programId));
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
    RETURN_STATUS_IF_ERROR(getObservablePosition(&aidlFrames, &aidlTimestamp));
    *dspFrames = static_cast<uint32_t>(aidlFrames);
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
    RETURN_STATUS_IF_ERROR(getObservablePosition(&aidlFrames, &aidlTimestamp));
    *frames = aidlFrames;
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

status_t StreamOutHalAidl::getDualMonoMode(audio_dual_mono_mode_t* mode) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (mode == nullptr) {
        return BAD_VALUE;
    }
    ::aidl::android::media::audio::common::AudioDualMonoMode aidlMode;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mStream->getDualMonoMode(&aidlMode)));
    *mode = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_AudioDualMonoMode_audio_dual_mono_mode_t(aidlMode));
    return OK;
}

status_t StreamOutHalAidl::setDualMonoMode(audio_dual_mono_mode_t mode) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ::aidl::android::media::audio::common::AudioDualMonoMode aidlMode = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_dual_mono_mode_t_AudioDualMonoMode(mode));
    return statusTFromBinderStatus(mStream->setDualMonoMode(aidlMode));
}

status_t StreamOutHalAidl::getAudioDescriptionMixLevel(float* leveldB) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (leveldB == nullptr) {
        return BAD_VALUE;
    }
    return statusTFromBinderStatus(mStream->getAudioDescriptionMixLevel(leveldB));
}

status_t StreamOutHalAidl::setAudioDescriptionMixLevel(float leveldB) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    return statusTFromBinderStatus(mStream->setAudioDescriptionMixLevel(leveldB));
}

status_t StreamOutHalAidl::getPlaybackRateParameters(audio_playback_rate_t* playbackRate) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (playbackRate == nullptr) {
        return BAD_VALUE;
    }
    ::aidl::android::media::audio::common::AudioPlaybackRate aidlRate;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mStream->getPlaybackRateParameters(&aidlRate)));
    *playbackRate = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_AudioPlaybackRate_audio_playback_rate_t(aidlRate));
    return OK;
}

status_t StreamOutHalAidl::setPlaybackRateParameters(const audio_playback_rate_t& playbackRate) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ::aidl::android::media::audio::common::AudioPlaybackRate aidlRate = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_playback_rate_t_AudioPlaybackRate(playbackRate));
    return statusTFromBinderStatus(mStream->setPlaybackRateParameters(aidlRate));
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

status_t StreamOutHalAidl::setLatencyMode(audio_latency_mode_t mode) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ::aidl::android::media::audio::common::AudioLatencyMode aidlMode = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_latency_mode_t_AudioLatencyMode(mode));
    return statusTFromBinderStatus(mStream->setLatencyMode(aidlMode));
};

status_t StreamOutHalAidl::getRecommendedLatencyModes(std::vector<audio_latency_mode_t> *modes) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (modes == nullptr) {
        return BAD_VALUE;
    }
    std::vector<::aidl::android::media::audio::common::AudioLatencyMode> aidlModes;
    RETURN_STATUS_IF_ERROR(
            statusTFromBinderStatus(mStream->getRecommendedLatencyModes(&aidlModes)));
    *modes = VALUE_OR_RETURN_STATUS(
            ::aidl::android::convertContainer<std::vector<audio_latency_mode_t>>(
                    aidlModes,
                    ::aidl::android::aidl2legacy_AudioLatencyMode_audio_latency_mode_t));
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
                    return value >= 0 ?
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
                        return OK;
                    }
                    return BAD_VALUE;
                }))) {
        updateMetadata = true;
    }
    if (VALUE_OR_RETURN_STATUS(filterOutAndProcessParameter<int>(
                parameters, String8(AudioParameter::keyOffloadCodecDelaySamples),
                [&](int value) {
                    // The legacy keys are misnamed, the value is in frames.
                    return value >= 0 ? mOffloadMetadata.delayFrames = value, OK : BAD_VALUE;
                }))) {
        updateMetadata = true;
    }
    if (VALUE_OR_RETURN_STATUS(filterOutAndProcessParameter<int>(
                parameters, String8(AudioParameter::keyOffloadCodecPaddingSamples),
                [&](int value) {
                    // The legacy keys are misnamed, the value is in frames.
                    return value >= 0 ? mOffloadMetadata.paddingFrames = value, OK : BAD_VALUE;
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
        const std::shared_ptr<IStreamIn>& stream,
        const std::shared_ptr<IHalAdapterVendorExtension>& vext,
        const sp<MicrophoneInfoProvider>& micInfoProvider)
        : StreamHalAidl("StreamInHalAidl", true /*isInput*/, config, nominalLatency,
                std::move(context), getStreamCommon(stream), vext),
          mStream(stream), mMicInfoProvider(micInfoProvider) {}

status_t StreamInHalAidl::setGain(float gain) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    return statusTFromBinderStatus(mStream->setHwGain({gain}));
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
    RETURN_STATUS_IF_ERROR(getXruns(&aidlXruns));
    *framesLost = std::max<int32_t>(0, aidlXruns);
    return OK;
}

status_t StreamInHalAidl::getCapturePosition(int64_t *frames, int64_t *time) {
    if (frames == nullptr || time == nullptr) {
        return BAD_VALUE;
    }
    return getObservablePosition(frames, time);
}

status_t StreamInHalAidl::getActiveMicrophones(std::vector<media::MicrophoneInfoFw> *microphones) {
    if (!microphones) {
        return BAD_VALUE;
    }
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    sp<MicrophoneInfoProvider> micInfoProvider = mMicInfoProvider.promote();
    if (!micInfoProvider) return NO_INIT;
    auto staticInfo = micInfoProvider->getMicrophoneInfo();
    if (!staticInfo) return INVALID_OPERATION;
    std::vector<MicrophoneDynamicInfo> dynamicInfo;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mStream->getActiveMicrophones(&dynamicInfo)));
    std::vector<media::MicrophoneInfoFw> result;
    result.reserve(dynamicInfo.size());
    for (const auto& d : dynamicInfo) {
        const auto staticInfoIt = std::find_if(staticInfo->begin(), staticInfo->end(),
                [&](const auto& s) { return s.id == d.id; });
        if (staticInfoIt != staticInfo->end()) {
            // Convert into the c++ backend type from the ndk backend type via the legacy structure.
            audio_microphone_characteristic_t legacy = VALUE_OR_RETURN_STATUS(
                    ::aidl::android::aidl2legacy_MicrophoneInfos_audio_microphone_characteristic_t(
                            *staticInfoIt, d));
            media::MicrophoneInfoFw info = VALUE_OR_RETURN_STATUS(
                    ::android::legacy2aidl_audio_microphone_characteristic_t_MicrophoneInfoFw(
                            legacy));
            // Note: info.portId is not filled because it's a bit of framework info.
            result.push_back(std::move(info));
        } else {
            ALOGE("%s: no static info for active microphone with id '%s'", __func__, d.id.c_str());
        }
    }
    *microphones = std::move(result);
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

status_t StreamInHalAidl::setPreferredMicrophoneDirection(audio_microphone_direction_t direction) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ::aidl::android::hardware::audio::core::IStreamIn::MicrophoneDirection aidlDirection =
              VALUE_OR_RETURN_STATUS(
                      ::aidl::android::legacy2aidl_audio_microphone_direction_t_MicrophoneDirection(
                              direction));
    return statusTFromBinderStatus(mStream->setMicrophoneDirection(aidlDirection));
}

status_t StreamInHalAidl::setPreferredMicrophoneFieldDimension(float zoom) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    return statusTFromBinderStatus(mStream->setMicrophoneFieldDimension(zoom));
}

} // namespace android
