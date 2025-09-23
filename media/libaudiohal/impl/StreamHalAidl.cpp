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
#include <thread>

#include <audio_utils/clock.h>
#include <media/AidlConversion.h>
#include <media/AidlConversionCore.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionUtil.h>
#include <media/AudioParameter.h>
#include <mediautils/TimeCheck.h>
#include <system/audio.h>
#include <Utils.h>
#include <utils/Log.h>

#include "AidlUtils.h"
#include "DeviceHalAidl.h"
#include "EffectHalAidl.h"
#include "StreamHalAidl.h"

using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::common::kDumpFromAudioServerArgument;
using ::aidl::android::hardware::audio::common::PlaybackTrackMetadata;
using ::aidl::android::hardware::audio::common::RecordTrackMetadata;
using ::aidl::android::hardware::audio::core::IStreamCommon;
using ::aidl::android::hardware::audio::core::IStreamIn;
using ::aidl::android::hardware::audio::core::IStreamOut;
using ::aidl::android::hardware::audio::core::MmapBufferDescriptor;
using ::aidl::android::hardware::audio::core::StreamDescriptor;
using ::aidl::android::hardware::audio::core::VendorParameter;
using ::aidl::android::media::audio::common::MicrophoneDynamicInfo;
using ::aidl::android::hardware::audio::core::VendorParameter;
using ::aidl::android::media::audio::IHalAdapterVendorExtension;

/**
 * Notes on the position handling implementation. First, please consult
 * "On position reporting" comment in StreamHalInterface.h for the context.
 *
 * The adaptation layer for AIDL HALs needs to emulate the HIDL HAL behavior
 * (that's until some future release when the framework stops supporting HIDL
 * HALs and it will be possible to remove the code in the framework which
 * translates resetting positions into continuous) by resetting the reported
 * position after certain events, depending on the kind of the audio data
 * stream. Unlike the AIDL interface, the interface between the HAL adaptation
 * layer and the framework uses separate method calls for controlling the stream
 * state and retrieving the position. Because of that, the code which implements
 * position reporting (methods 'getRenderPosition' and 'getObservablePosition')
 * needs to use stored stream positions which it had at certain state changing
 * events, like flush or drain. These are stored in the field called
 * 'mStatePositions'. This field is updated in the code which changes the stream
 * state. There are two places for that: the 'sendCommand' method, which is used
 * for all streams, and handlers of asynchronous stream events called
 * 'onAsync...'.
 */

namespace android {

using HalCommand = StreamDescriptor::Command;

namespace {

enum AidlVersion : int32_t {
    kAidlVersion1 = 1,
    kAidlVersion2 = 2,
    kAidlVersion3 = 3,
};

static constexpr const char* kCreateMmapBuffer = "aosp.createMmapBuffer";

template<HalCommand::Tag cmd> HalCommand makeHalCommand() {
    return HalCommand::make<cmd>(::aidl::android::media::audio::common::Void{});
}
template<HalCommand::Tag cmd, typename T> HalCommand makeHalCommand(T data) {
    return HalCommand::make<cmd>(data);
}

template <typename MQTypeError>
auto fmqErrorHandler(const char* mqName) {
    return [m = std::string(mqName)](MQTypeError fmqError, std::string&& errorMessage) {
        mediautils::TimeCheck::signalAudioHals();
        LOG_ALWAYS_FATAL_IF(fmqError != MQTypeError::NONE, "%s: %s",
                m.c_str(), errorMessage.c_str());
    };
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

StreamHalAidl::StreamHalAidl(std::string_view className, bool isInput, const audio_config& config,
                             int32_t nominalLatency, StreamContextAidl&& context,
                             const std::shared_ptr<IStreamCommon>& stream,
                             const std::shared_ptr<IHalAdapterVendorExtension>& vext,
                             const sp<StreamCloseHandler>& streamCloseHandler)
    : ConversionHelperAidl(className, std::string(isInput ? "in" : "out") + "|ioHandle:" +
            std::to_string(context.getIoHandle())),
          mIsInput(isInput),
          mConfig(configToBase(config)),
          mStreamCloseHandler(streamCloseHandler),
          mContext(std::move(context)),
          mStream(stream),
          mVendorExt(vext),
          mLastReplyLifeTimeNs(
                  std::min(static_cast<size_t>(20),
                           mContext.getBufferDurationMs(mConfig.sample_rate))
                  * NANOS_PER_MILLISECOND)
{
    AUGMENT_LOG(D);
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

    if (mStream == nullptr) return;

    mContext.getCommandMQ()->setErrorHandler(
            fmqErrorHandler<StreamContextAidl::CommandMQ::Error>("CommandMQ"));
    mContext.getReplyMQ()->setErrorHandler(
            fmqErrorHandler<StreamContextAidl::ReplyMQ::Error>("ReplyMQ"));
    if (mContext.getDataMQ() != nullptr) {
        mContext.getDataMQ()->setErrorHandler(
                fmqErrorHandler<StreamContextAidl::DataMQ::Error>("DataMQ"));
    }

    if (auto status = mStream->getInterfaceVersion(&mAidlInterfaceVersion); status.isOk()) {
        if (mAidlInterfaceVersion > kAidlVersion3) {
            mSupportsCreateMmapBuffer = true;
        } else {
            VendorParameter createMmapBuffer{.id = kCreateMmapBuffer};
            mSupportsCreateMmapBuffer =
                    mStream->setVendorParameters({createMmapBuffer}, false).isOk();
        }
    } else {
        AUGMENT_LOG(E, "failed to retrieve stream interface version: %s", status.getMessage());
    }
}

StreamHalAidl::~StreamHalAidl() {
}

status_t StreamHalAidl::close() {
    AUGMENT_LOG(D);
    if (!mStream) return NO_INIT;
    ndk::ScopedAStatus status = serializeCall(mStream, &Stream::close);
    if (status.isOk()) {
        if (auto handler = mStreamCloseHandler.promote(); handler != nullptr) {
            handler->streamClosed(sp<StreamHalInterface>::fromExisting(this));
        }
        std::lock_guard l(mLock);
        mIsClosed = true;
    }
    AUGMENT_LOG_IF(E, !status.isOk(), "status %s", status.getDescription().c_str());
    return statusTFromBinderStatus(status);
}

status_t StreamHalAidl::getBufferSize(size_t *size) {
    AUGMENT_LOG(D);
    if (size == nullptr) {
        return BAD_VALUE;
    }
    if (mContext.getFrameSizeBytes() == 0 || mContext.getBufferSizeFrames() == 0 ||
            !mStream) {
        return NO_INIT;
    }
    *size = mContext.getBufferSizeBytes();
    AUGMENT_LOG(I, "size: %zu", *size);
    return OK;
}

status_t StreamHalAidl::getAudioProperties(audio_config_base_t *configBase) {
    AUGMENT_LOG(D);
    if (configBase == nullptr) {
        return BAD_VALUE;
    }
    if (!mStream) return NO_INIT;
    *configBase = mConfig;
    return OK;
}

status_t StreamHalAidl::setParameters(const String8& kvPairs) {
    AUGMENT_LOG(V);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    AudioParameter parameters(kvPairs);
    AUGMENT_LOG(D, "parameters: %s", parameters.toString().c_str());

    (void)VALUE_OR_RETURN_STATUS(filterOutAndProcessParameter<int>(
            parameters, String8(AudioParameter::keyStreamHwAvSync), [&](int hwAvSyncId) {
                return statusTFromBinderStatus(
                        serializeCall(mStream, &Stream::updateHwAvSyncId, hwAvSyncId));
            }));

    return parseAndSetVendorParameters(parameters);
}

status_t StreamHalAidl::getParameters(const String8& keys __unused, String8 *values) {
    AUGMENT_LOG(V);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (values == nullptr) {
        return BAD_VALUE;
    }
    AudioParameter parameterKeys(keys), result;
    *values = result.toString();
    return parseAndGetVendorParameters(parameterKeys, values);
}

status_t StreamHalAidl::getFrameSize(size_t *size) {
    AUGMENT_LOG(D);
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
    AUGMENT_LOG(D);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (effect == nullptr) {
        return BAD_VALUE;
    }
    auto aidlEffect = sp<effect::EffectHalAidl>::cast(effect);
    return statusTFromBinderStatus(
            serializeCall(mStream, &Stream::addEffect, aidlEffect->getIEffect()));
}

status_t StreamHalAidl::removeEffect(sp<EffectHalInterface> effect) {
    AUGMENT_LOG(D);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (effect == nullptr) {
        return BAD_VALUE;
    }
    auto aidlEffect = sp<effect::EffectHalAidl>::cast(effect);
    return statusTFromBinderStatus(
            serializeCall(mStream, &Stream::removeEffect, aidlEffect->getIEffect()));
}

status_t StreamHalAidl::standby() {
    AUGMENT_LOG(D);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    const auto state = getState();
    StreamDescriptor::Reply reply;
    switch (state) {
        case StreamDescriptor::State::ACTIVE:
        case StreamDescriptor::State::DRAINING:
        case StreamDescriptor::State::TRANSFERRING:
            RETURN_STATUS_IF_ERROR(pause(&reply));
            if (reply.state != StreamDescriptor::State::PAUSED &&
                    reply.state != StreamDescriptor::State::DRAIN_PAUSED &&
                    reply.state != StreamDescriptor::State::TRANSFER_PAUSED &&
                    (state != StreamDescriptor::State::DRAINING ||
                        reply.state != StreamDescriptor::State::IDLE)) {
                AUGMENT_LOG(E, "unexpected stream state: %s (expected PAUSED)",
                            toString(reply.state).c_str());
                return INVALID_OPERATION;
            }
            FALLTHROUGH_INTENDED;
        case StreamDescriptor::State::PAUSED:
        case StreamDescriptor::State::DRAIN_PAUSED:
        case StreamDescriptor::State::TRANSFER_PAUSED:
            if (mIsInput) return flush();
            RETURN_STATUS_IF_ERROR(flush(&reply));
            if (reply.state != StreamDescriptor::State::IDLE) {
                AUGMENT_LOG(E, "unexpected stream state: %s (expected IDLE)",
                            toString(reply.state).c_str());
                return INVALID_OPERATION;
            }
            FALLTHROUGH_INTENDED;
        case StreamDescriptor::State::IDLE:
            RETURN_STATUS_IF_ERROR(sendCommand(makeHalCommand<HalCommand::Tag::standby>(),
                            &reply, true /*safeFromNonWorkerThread*/));
            if (reply.state != StreamDescriptor::State::STANDBY) {
                AUGMENT_LOG(E, "unexpected stream state: %s (expected STANDBY)",
                            toString(reply.state).c_str());
                return INVALID_OPERATION;
            }
            FALLTHROUGH_INTENDED;
        case StreamDescriptor::State::STANDBY:
            return OK;
        default:
            AUGMENT_LOG(E, "not supported from %s stream state %s", mIsInput ? "input" : "output",
                        toString(state).c_str());
            return INVALID_OPERATION;
    }
}

// The behavior depends on the interface implementation version:
//  - if the version < 3, only call `dump` on `IStreamCommon`.
//  - if the version == 3, call on the concrete stream (`IStreamIn|Out`) first, then if there
//       was nothing dumped, fallback to the "< 3" behavior.
//  - if the version > 3, only call `dump` on the concrete stream.
status_t StreamHalAidl::dumpImpl(int fd, const Vector<String16>& args, ::ndk::ICInterface* stream) {
    if (!mStream || !stream) return NO_INIT;
    Vector<String16> newArgs = args;
    newArgs.push(String16(kDumpFromAudioServerArgument));
    // Note: do not serialize the dump call with mCallLock.
    status_t status;
    if (mAidlInterfaceVersion > kAidlVersion3) {
        status = stream->dump(fd, Args(newArgs).args(), newArgs.size());
    } else if (mAidlInterfaceVersion < kAidlVersion3) {
        status = mStream->dump(fd, Args(newArgs).args(), newArgs.size());
    } else {  // mAidlInterfaceVersion == 3
        int pipefd[2];
        if (pipe(pipefd) == -1) {
            AUGMENT_LOG(E, "pipe failed: %d", errno);
            return NO_INIT;
        }
        bool hasOutput = false;
        std::thread reader([&hasOutput](int inFd, int outFd) {
                std::vector<char> buf(32768);
                while (true) {
                    ssize_t r = read(inFd, &buf[0], buf.size());
                    if (r <= 0) break;
                    write(outFd, &buf[0], r);
                    hasOutput = true;
                }
        }, pipefd[0], fd);
        status = stream->dump(pipefd[1], Args(newArgs).args(), newArgs.size());
        ::close(pipefd[1]);
        ::close(pipefd[0]);
        reader.join();
        if (status != OK || !hasOutput) {
            status = mStream->dump(fd, Args(newArgs).args(), newArgs.size());
        }
    }
    mStreamPowerLog.dump(fd);
    return status;
}

status_t StreamHalAidl::start() {
    AUGMENT_LOG(D);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (!mContext.isMmapped()) {
        return BAD_VALUE;
    }
    StreamDescriptor::Reply reply;
    RETURN_STATUS_IF_ERROR(updateCountersIfNeeded(&reply));
    switch (reply.state) {
        case StreamDescriptor::State::STANDBY:
            RETURN_STATUS_IF_ERROR(
                    sendCommand(makeHalCommand<HalCommand::Tag::start>(), &reply, true));
            if (reply.state != StreamDescriptor::State::IDLE) {
                AUGMENT_LOG(E, "unexpected stream state: %s (expected IDLE)",
                            toString(reply.state).c_str());
                return INVALID_OPERATION;
            }
            FALLTHROUGH_INTENDED;
        case StreamDescriptor::State::IDLE:
            RETURN_STATUS_IF_ERROR(
                    sendCommand(makeHalCommand<HalCommand::Tag::burst>(0), &reply, true));
            if (reply.state != StreamDescriptor::State::ACTIVE) {
                AUGMENT_LOG(E, "unexpected stream state: %s (expected ACTIVE)",
                            toString(reply.state).c_str());
                return INVALID_OPERATION;
            }
            FALLTHROUGH_INTENDED;
        case StreamDescriptor::State::ACTIVE:
            return OK;
        case StreamDescriptor::State::DRAINING:
            RETURN_STATUS_IF_ERROR(
                    sendCommand(makeHalCommand<HalCommand::Tag::start>(), &reply, true));
            if (reply.state != StreamDescriptor::State::ACTIVE) {
                AUGMENT_LOG(E, "unexpected stream state: %s (expected ACTIVE)",
                            toString(reply.state).c_str());
                return INVALID_OPERATION;
            }
            return OK;
        case StreamDescriptor::State::PAUSED:
            if (mIsInput) {
                RETURN_STATUS_IF_ERROR(
                        sendCommand(makeHalCommand<HalCommand::Tag::burst>(0), &reply, true));
                if (reply.state != StreamDescriptor::State::ACTIVE) {
                    AUGMENT_LOG(E, "unexpected stream state: %s (expected ACTIVE)",
                                toString(reply.state).c_str());
                    return INVALID_OPERATION;
                }
                if (reply.xrunFrames != 0) {
                    // The framework does not expect any input to be happening when the stream
                    // is stopped. So if the HAL reports any lost frames--ignore them.
                    std::lock_guard l(mLock);
                    mLastReply.xrunFrames = 0;
                }
                return OK;
            }
            FALLTHROUGH_INTENDED;
        default:
            AUGMENT_LOG(E, "not supported from %s stream state %s", mIsInput ? "input" : "output",
                        toString(reply.state).c_str());
            return INVALID_OPERATION;
    }
}

status_t StreamHalAidl::stop() {
    AUGMENT_LOG(D);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (!mContext.isMmapped()) {
        return BAD_VALUE;
    }
    StreamDescriptor::Reply reply;
    RETURN_STATUS_IF_ERROR(updateCountersIfNeeded(&reply));
    const auto state = reply.state;
    if (mIsInput) {
        // For input, just pause. This avoids entering the standby state at the HAL side
        // which can cause releasing of the shared buffer. The MMAP stream interface only
        // expects buffer invalidation when the client calls 'standby' explicitly.
        if (state == StreamDescriptor::State::ACTIVE) {
            return pause();
        } else if (state == StreamDescriptor::State::DRAINING) {
            // Drain until the stream enters standby due to empty buffer.
            do {
                if (status_t status = drain(false /*earlyNotify*/, &reply); status != OK) {
                    if (reply.state == StreamDescriptor::State::STANDBY) break;
                    AUGMENT_LOG(E, "HAL could not complete drain, left in %s state, status %d",
                            toString(reply.state).c_str(), status);
                    return status;
                }
            } while (reply.state == StreamDescriptor::State::DRAINING);
            if (reply.state == StreamDescriptor::State::STANDBY) return OK;
            AUGMENT_LOG(E, "HAL could not complete drain, left in %s state",
                    toString(reply.state).c_str());
            return INVALID_OPERATION;
        }
    } else {  // output
        if (state == StreamDescriptor::State::ACTIVE) {
            return drain(false /*earlyNotify*/, nullptr);
        } else if (state == StreamDescriptor::State::DRAINING) {
            RETURN_STATUS_IF_ERROR(pause());
            return flush();
        }
    }
    if (state == StreamDescriptor::State::PAUSED) {
        return flush();
    } else if (state != StreamDescriptor::State::IDLE &&
            state != StreamDescriptor::State::STANDBY) {
        AUGMENT_LOG(E, "not supported from %s stream state %s", mIsInput ? "input" : "output",
                    toString(state).c_str());
        return INVALID_OPERATION;
    }
    return OK;
}

status_t StreamHalAidl::getLatency(uint32_t *latency) {
    AUGMENT_LOG(V);
    if (!mStream) return NO_INIT;
    StreamDescriptor::Reply reply;
    RETURN_STATUS_IF_ERROR(updateCountersIfNeeded(&reply));
    *latency = std::clamp(std::max<int32_t>(0, reply.latencyMs), 1, 3000);
    AUGMENT_LOG_IF(W, reply.latencyMs != static_cast<int32_t>(*latency),
                   "Suspicious latency value reported by HAL: %d, clamped to %u", reply.latencyMs,
                   *latency);
    return OK;
}

status_t StreamHalAidl::getObservablePosition(int64_t* frames, int64_t* timestamp,
        StatePositions* statePositions) {
    AUGMENT_LOG(V);
    if (!mStream) return NO_INIT;
    StreamDescriptor::Reply reply;
    RETURN_STATUS_IF_ERROR(updateCountersIfNeeded(&reply, statePositions));
    if (reply.observable.frames == StreamDescriptor::Position::UNKNOWN ||
        reply.observable.timeNs == StreamDescriptor::Position::UNKNOWN) {
        return NOT_ENOUGH_DATA;
    }
    *frames = reply.observable.frames;
    *timestamp = reply.observable.timeNs;
    return OK;
}

status_t StreamHalAidl::getHardwarePosition(int64_t *frames, int64_t *timestamp) {
    AUGMENT_LOG(V);
    if (!mStream) return NO_INIT;
    StreamDescriptor::Reply reply;
    StatePositions statePositions{};
    RETURN_STATUS_IF_ERROR(updateCountersIfNeeded(&reply, &statePositions));
    if (reply.hardware.frames == StreamDescriptor::Position::UNKNOWN ||
        reply.hardware.timeNs == StreamDescriptor::Position::UNKNOWN) {
        AUGMENT_LOG(W, "No position was reported by the HAL");
        return NOT_ENOUGH_DATA;
    }
    if (mSupportsCreateMmapBuffer) {
        // HAL is required to report continuous position. Reset for compatibility.
        int64_t mostRecentResetPoint = std::max(statePositions.hardware.framesAtStandby,
                statePositions.hardware.framesAtFlushOrDrain);
        int64_t aidlFrames = reply.hardware.frames;
        *frames = aidlFrames <= mostRecentResetPoint ? 0 : aidlFrames - mostRecentResetPoint;
    } else {
        *frames = reply.hardware.frames;
    }
    *timestamp = reply.hardware.timeNs;
    return OK;
}

status_t StreamHalAidl::getXruns(int32_t *frames) {
    AUGMENT_LOG(V);
    if (!mStream) return NO_INIT;
    StreamDescriptor::Reply reply;
    RETURN_STATUS_IF_ERROR(updateCountersIfNeeded(&reply));
    if (reply.xrunFrames == StreamDescriptor::Position::UNKNOWN) {
        return NOT_ENOUGH_DATA;
    }
    *frames = reply.xrunFrames;
    return OK;
}

status_t StreamHalAidl::transfer(void *buffer, size_t bytes, size_t *transferred) {
    AUGMENT_LOG(V);
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
            AUGMENT_LOG(E, "failed to get the stream out of standby, actual state: %s",
                        toString(reply.state).c_str());
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
            AUGMENT_LOG(E, "failed to write %zu bytes to data MQ", bytes);
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
            AUGMENT_LOG(E, "failed to read %zu bytes to data MQ", toRead);
            return NOT_ENOUGH_DATA;
        }
    } else if (*transferred > bytes) {
        ALOGW("%s: HAL module wrote %zu bytes, which exceeds requested count %zu",
                __func__, *transferred, bytes);
        *transferred = bytes;
    }
    mStreamPowerLog.log(buffer, *transferred);
    return OK;
}

status_t StreamHalAidl::pause(StreamDescriptor::Reply* reply) {
    AUGMENT_LOG(D);
    TIME_CHECK();
    if (!mStream) return NO_INIT;

    if (const auto state = getState(); isInPlayOrRecordState(state)) {
        StreamDescriptor::Reply localReply{};
        StreamDescriptor::Reply* innerReply = reply ?: &localReply;
        auto status = sendCommand(
                makeHalCommand<HalCommand::Tag::pause>(), innerReply,
                true /*safeFromNonWorkerThread*/);  // The workers stops its I/O activity first.
        if (status == STATUS_INVALID_OPERATION &&
                !isInPlayOrRecordState(innerReply->state)) {
            /**
             * In case of transient states like DRAINING, the HAL may change its
             * StreamDescriptor::State on its own and may not be in synchronization with client.
             * Thus, client can send the unexpected command and HAL returns failure. such failure is
             * natural. The client handles it gracefully.
             * Example where HAL change its state,
             * 1) DRAINING -> IDLE (on empty buffer)
             * 2) DRAINING -> IDLE (on IStreamCallback::onDrainReady)
             **/
            AUGMENT_LOG(D,
                        "HAL failed to handle the 'pause' command, but stream state is in one of"
                        " the PAUSED kind of states, current state: %s",
                        toString(innerReply->state).c_str());
            return OK;
        }
        return status;
    } else {
        AUGMENT_LOG(D, "already stream in one of the PAUSED kind of states, current state: %s",
                toString(state).c_str());
        return OK;
    }
}

status_t StreamHalAidl::resume(StreamDescriptor::Reply* reply) {
    AUGMENT_LOG(D);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (mIsInput) {
        return sendCommand(makeHalCommand<HalCommand::Tag::burst>(0), reply);
    } else {
        if (const auto state = getState(); state == StreamDescriptor::State::IDLE) {
            // Handle pause-flush-resume sequence. 'flush' from PAUSED goes to
            // IDLE. We move here from IDLE to ACTIVE (same as 'start' from PAUSED).
            StreamDescriptor::Reply localReply{};
            StreamDescriptor::Reply* innerReply = reply ?: &localReply;
            RETURN_STATUS_IF_ERROR(
                    sendCommand(makeHalCommand<HalCommand::Tag::burst>(0), innerReply));
            if (innerReply->state != StreamDescriptor::State::ACTIVE) {
                AUGMENT_LOG(E, "unexpected stream state: %s (expected ACTIVE)",
                            toString(innerReply->state).c_str());
                return INVALID_OPERATION;
            }
            return OK;
        } else if (isInPausedState(state)) {
            return sendCommand(makeHalCommand<HalCommand::Tag::start>(), reply);
        } else if (isInPlayOrRecordState(state)) {
            AUGMENT_LOG(D, "already in stream state: %s", toString(state).c_str());
            return OK;
        } else {
            AUGMENT_LOG(E, "unexpected stream state: %s (expected IDLE or one of *PAUSED states)",
                        toString(state).c_str());
            return INVALID_OPERATION;
        }
    }
}

status_t StreamHalAidl::drain(bool earlyNotify, StreamDescriptor::Reply* reply) {
    AUGMENT_LOG(D);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    return sendCommand(makeHalCommand<HalCommand::Tag::drain>(
                    mIsInput ? StreamDescriptor::DrainMode::DRAIN_UNSPECIFIED :
                    earlyNotify ? StreamDescriptor::DrainMode::DRAIN_EARLY_NOTIFY :
                    StreamDescriptor::DrainMode::DRAIN_ALL), reply,
                    true /*safeFromNonWorkerThread*/);
}

status_t StreamHalAidl::flush(StreamDescriptor::Reply* reply) {
    AUGMENT_LOG(D);
    TIME_CHECK();
    if (!mStream) return NO_INIT;

    if (const auto state = getState(); isInPlayOrRecordState(state)) {
        RETURN_STATUS_IF_ERROR(pause(reply));
    }

    if (const auto state = getState(); isInPausedState(state)) {
        return sendCommand(
                makeHalCommand<HalCommand::Tag::flush>(), reply,
                true /*safeFromNonWorkerThread*/);  // The workers stops its I/O activity first.
    } else {
        AUGMENT_LOG(D, "already stream in one of the flushed state: current state: %s",
                    toString(state).c_str());
        return OK;
    }
}

status_t StreamHalAidl::exit() {
    AUGMENT_LOG(D);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    return statusTFromBinderStatus(serializeCall(mStream, &Stream::prepareToClose));
}

void StreamHalAidl::onAsyncTransferReady() {
    StreamDescriptor::State state;
    {
        // Use 'mCommandReplyLock' to ensure that 'sendCommand' has finished updating the state
        // after the reply from the 'burst' command.
        std::lock_guard l(mCommandReplyLock);
        state = getState();
    }
    bool isCallbackExpected = false;
    if (state == StreamDescriptor::State::TRANSFERRING) {
        isCallbackExpected = true;
    } else if (mContext.hasClipTransitionSupport() && state == StreamDescriptor::State::DRAINING) {
        std::lock_guard l(mLock);
        isCallbackExpected = mStatePositions.drainState == StatePositions::DrainState::EN_RECEIVED;
        if (!isCallbackExpected) {
            AUGMENT_LOG(W, "drainState %d", static_cast<int>(mStatePositions.drainState));
        }
    }
    if (isCallbackExpected) {
        // Retrieve the current state together with position counters unconditionally
        // to ensure that the state on our side gets updated.
        sendCommand(makeHalCommand<HalCommand::Tag::getStatus>(),
                nullptr, true /*safeFromNonWorkerThread */);
    } else {
        AUGMENT_LOG(W, "unexpected onTransferReady in the state %s", toString(state).c_str());
    }
}

void StreamHalAidl::onAsyncDrainReady() {
    StreamDescriptor::State state;
    {
        // Use 'mCommandReplyLock' to ensure that 'sendCommand' has finished updating the state
        // after the reply from the 'drain' command.
        std::lock_guard l(mCommandReplyLock);
        state = getState();
    }
    if (state == StreamDescriptor::State::DRAINING ||
            (mContext.hasClipTransitionSupport() &&
                    (state == StreamDescriptor::State::TRANSFERRING ||
                            state == StreamDescriptor::State::IDLE))) {
        // Retrieve the current state together with position counters unconditionally
        // to ensure that the state on our side gets updated.
        sendCommand(makeHalCommand<HalCommand::Tag::getStatus>(), nullptr,
                    true /*safeFromNonWorkerThread */);
        // For compatibility with HIDL behavior, apply a "soft" position reset
        // after receiving the "drain ready" callback for the clip end.
        std::lock_guard l(mLock);
        if (mLastReply.observable.frames != StreamDescriptor::Position::UNKNOWN &&
                (!mContext.hasClipTransitionSupport() ||
                        (mStatePositions.drainState == StatePositions::DrainState::EN_RECEIVED
                                || mStatePositions.drainState == StatePositions::DrainState::ALL))) {
            AUGMENT_LOG(D, "setting position %lld as clip end",
                    (long long)mLastReply.observable.frames);
            mStatePositions.observable.framesAtFlushOrDrain = mLastReply.observable.frames;
        }
        mStatePositions.drainState = mStatePositions.drainState == StatePositions::DrainState::EN ?
                StatePositions::DrainState::EN_RECEIVED : StatePositions::DrainState::NONE;
    } else {
        AUGMENT_LOG(W, "unexpected onDrainReady in the state %s", toString(state).c_str());
    }
}

void StreamHalAidl::onAsyncError() {
    std::lock_guard l(mLock);
    AUGMENT_LOG(W, "received in the state %s", toString(mLastReply.state).c_str());
    mLastReply.state = StreamDescriptor::State::ERROR;
}

status_t StreamHalAidl::createMmapBuffer(int32_t minSizeFrames __unused,
                                         struct audio_mmap_buffer_info *info) {
    AUGMENT_LOG(D);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (!mContext.isMmapped()) {
        return BAD_VALUE;
    }
    if (mSupportsCreateMmapBuffer && (mAidlInterfaceVersion <= kAidlVersion3)) {
        std::vector<VendorParameter> parameters;
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
                        mStream->getVendorParameters({kCreateMmapBuffer}, &parameters)));
        if (parameters.size() == 1) {
            std::optional<MmapBufferDescriptor> result;
            RETURN_STATUS_IF_ERROR(parameters[0].ext.getParcelable(&result));
            mContext.updateMmapBufferDescriptor(std::move(*result));
        } else {
            AUGMENT_LOG(E, "invalid output from 'createMmapBuffer' via 'getVendorParameters': %s",
                        internal::ToString(parameters).c_str());
            return INVALID_OPERATION;
        }
    } else if (mSupportsCreateMmapBuffer && (mAidlInterfaceVersion > kAidlVersion3)) {
        MmapBufferDescriptor result;
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mStream->createMmapBuffer(&result)));
        mContext.updateMmapBufferDescriptor(std::move(result));
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

status_t StreamHalAidl::parseAndGetVendorParameters(const AudioParameter& parameterKeys,
                                                    String8* values) {
    std::vector<std::string> vendorParameterIds;
    RETURN_STATUS_IF_ERROR(
            fillVendorParameterIds(mVendorExt, IHalAdapterVendorExtension::ParameterScope::STREAM,
                                   parameterKeys, vendorParameterIds));
    if (vendorParameterIds.empty()) {
        return OK;
    }
    std::vector<VendorParameter> vendorParameters;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(serializeCall(
            mStream, &Stream::getVendorParameters, vendorParameterIds, &vendorParameters)));

    RETURN_STATUS_IF_ERROR(fillKeyValuePairsFromVendorParameters(
            mVendorExt, IHalAdapterVendorExtension::ParameterScope::STREAM, vendorParameters,
            values));
    return OK;
}

status_t StreamHalAidl::parseAndSetVendorParameters(const AudioParameter& parameters) {
    std::vector<VendorParameter> syncParameters, asyncParameters;
    RETURN_STATUS_IF_ERROR(fillVendorParameters(mVendorExt,
                                                IHalAdapterVendorExtension::ParameterScope::STREAM,
                                                parameters, syncParameters, asyncParameters));
    if (!syncParameters.empty())
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(serializeCall(
                mStream, &Stream::setVendorParameters, syncParameters, false /*async*/)));
    if (!asyncParameters.empty())
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(serializeCall(
                mStream, &Stream::setVendorParameters, asyncParameters, true /*async*/)));
    return OK;
}

status_t StreamHalAidl::sendCommand(
        const ::aidl::android::hardware::audio::core::StreamDescriptor::Command& command,
        ::aidl::android::hardware::audio::core::StreamDescriptor::Reply* reply,
        bool safeFromNonWorkerThread, StatePositions* statePositions) {
    {
        std::lock_guard l(mLock);
        if (mIsClosed) return DEAD_OBJECT;
    }

    // Add timeCheck only for start command (pause, flush checked at caller).
    std::unique_ptr<mediautils::TimeCheck> timeCheck;
    if (command.getTag() == StreamDescriptor::Command::start) {
        timeCheck = mediautils::makeTimeCheckStatsForClassMethodUniquePtr(
                getClassName(), "sendCommand_start");
    }
    // TIME_CHECK();  // TODO(b/243839867) reenable only when optimized.
    if (!safeFromNonWorkerThread) {
        const pid_t workerTid = mWorkerTid.load(std::memory_order_acquire);
        LOG_ALWAYS_FATAL_IF(workerTid != gettid(),
                "%s %s: must be invoked from the worker thread (%d)",
                __func__, command.toString().c_str(), workerTid);
    }
    StreamDescriptor::Reply localReply{};
    {
        std::lock_guard l(mCommandReplyLock);
        if (!mContext.getCommandMQ()->writeBlocking(&command, 1)) {
            AUGMENT_LOG(E, "failed to write command %s to MQ", command.toString().c_str());
            return NOT_ENOUGH_DATA;
        }
        if (reply == nullptr) {
            reply = &localReply;
        }
        if (!mContext.getReplyMQ()->readBlocking(reply, 1)) {
            AUGMENT_LOG(E, "failed to read from reply MQ, command %s", command.toString().c_str());
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
            mLastReplyExpirationNs = uptimeNanos() + mLastReplyLifeTimeNs;
            if (!mIsInput && reply->status == STATUS_OK) {
                if (reply->observable.frames != StreamDescriptor::Position::UNKNOWN) {
                    if (command.getTag() == StreamDescriptor::Command::standby &&
                            reply->state == StreamDescriptor::State::STANDBY) {
                        mStatePositions.observable.framesAtStandby = reply->observable.frames;
                        mStatePositions.hardware.framesAtStandby = reply->hardware.frames;
                    } else if (command.getTag() == StreamDescriptor::Command::flush &&
                            reply->state == StreamDescriptor::State::IDLE) {
                        mStatePositions.observable.framesAtFlushOrDrain = reply->observable.frames;
                        mStatePositions.hardware.framesAtFlushOrDrain = reply->hardware.frames;
                    } else if (!mContext.isAsynchronous() &&
                            command.getTag() == StreamDescriptor::Command::drain &&
                            (reply->state == StreamDescriptor::State::IDLE ||
                                    reply->state == StreamDescriptor::State::DRAINING)) {
                        mStatePositions.observable.framesAtFlushOrDrain = reply->observable.frames;
                        mStatePositions.hardware.framesAtFlushOrDrain = reply->hardware.frames;
                    } // for asynchronous drain, the frame count is saved in 'onAsyncDrainReady'
                }
                if (mContext.isAsynchronous() &&
                        command.getTag() == StreamDescriptor::Command::drain) {
                    mStatePositions.drainState =
                            command.get<StreamDescriptor::Command::drain>() ==
                            StreamDescriptor::DrainMode::DRAIN_ALL ?
                            StatePositions::DrainState::ALL : StatePositions::DrainState::EN;
                }
            }
            if (statePositions != nullptr) {
                *statePositions = mStatePositions;
            }
        }
    }
    switch (reply->status) {
        case STATUS_OK: return OK;
        case STATUS_BAD_VALUE: return BAD_VALUE;
        case STATUS_INVALID_OPERATION: return INVALID_OPERATION;
        case STATUS_NOT_ENOUGH_DATA: return NOT_ENOUGH_DATA;
        default:
            AUGMENT_LOG(E, "unexpected status %d returned for command %s", reply->status,
                        command.toString().c_str());
            return INVALID_OPERATION;
    }
}

status_t StreamHalAidl::updateCountersIfNeeded(
        ::aidl::android::hardware::audio::core::StreamDescriptor::Reply* reply,
        StatePositions* statePositions) {
    bool doUpdate = false;
    HalCommand cmd;
    {
        std::lock_guard l(mLock);
        doUpdate = uptimeNanos() > mLastReplyExpirationNs;
        cmd = mContext.isMmapped() && mSupportsCreateMmapBuffer
                && mLastReply.state == StreamDescriptor::State::ACTIVE
                ? makeHalCommand<HalCommand::Tag::burst>(0)
                : makeHalCommand<HalCommand::Tag::getStatus>();
    }
    if (doUpdate) {
        // Since updates are paced, it is OK to perform them from any thread, they should
        // not interfere with I/O operations of the worker.
        return sendCommand(cmd, reply, true /*safeFromNonWorkerThread */, statePositions);
    } else if (reply != nullptr) {  // provide cached reply
        std::lock_guard l(mLock);
        *reply = mLastReply;
        if (statePositions != nullptr) {
            *statePositions = mStatePositions;
        }
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
                std::move(context), getStreamCommon(stream), vext, callbackBroker),
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
        broker->clearCallbacks(static_cast<StreamOutHalInterface*>(this));
    }
}

status_t StreamOutHalAidl::setParameters(const String8& kvPairs) {
    if (!mStream) return NO_INIT;

    AudioParameter parameters(kvPairs);
    AUGMENT_LOG(D, "parameters: \"%s\"", parameters.toString().c_str());

    if (status_t status = filterAndUpdateOffloadMetadata(parameters); status != OK) {
        AUGMENT_LOG(W, "filtering or updating offload metadata failed: %d", status);
    }

    return StreamHalAidl::setParameters(parameters.toString());
}

status_t StreamOutHalAidl::getLatency(uint32_t *latency) {
    return StreamHalAidl::getLatency(latency);
}

status_t StreamOutHalAidl::setVolume(float left, float right) {
    AUGMENT_LOG(V, "left %f right %f", left, right);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    size_t channelCount = audio_channel_count_from_out_mask(mConfig.channel_mask);
    if (channelCount == 0) channelCount = 2;
    std::vector<float> volumes(channelCount);
    if (channelCount == 1) {
        volumes[0] = (left + right) / 2;
    } else {
        volumes[0] = left;
        volumes[1] = right;
        for (size_t i = 2; i < channelCount; ++i) {
            volumes[i] = (left + right) / 2;
        }
    }
    return statusTFromBinderStatus(serializeCall(mStream, &Stream::setHwVolume, volumes));
}

status_t StreamOutHalAidl::selectPresentation(int presentationId, int programId) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    return statusTFromBinderStatus(
            serializeCall(mStream, &Stream::selectPresentation, presentationId, programId));
}

status_t StreamOutHalAidl::write(const void *buffer, size_t bytes, size_t *written) {
    if (buffer == nullptr || written == nullptr) {
        return BAD_VALUE;
    }
    // For the output scenario, 'transfer' does not modify the buffer.
    return transfer(const_cast<void*>(buffer), bytes, written);
}

status_t StreamOutHalAidl::getRenderPosition(uint64_t *dspFrames) {
    if (dspFrames == nullptr) {
        return BAD_VALUE;
    }
    int64_t aidlFrames = 0, aidlTimestamp = 0;
    StatePositions statePositions{};
    RETURN_STATUS_IF_ERROR(
            getObservablePosition(&aidlFrames, &aidlTimestamp, &statePositions));
    // Number of audio frames since the stream has exited standby.
    // See the table at the start of 'StreamHalInterface' on when it needs to reset.
    int64_t mostRecentResetPoint;
    if (!mContext.isAsynchronous() && audio_has_proportional_frames(mConfig.format)) {
        mostRecentResetPoint = statePositions.observable.framesAtStandby;
    } else {
        mostRecentResetPoint = std::max(statePositions.observable.framesAtStandby,
                statePositions.observable.framesAtFlushOrDrain);
    }
    *dspFrames = aidlFrames <= mostRecentResetPoint ? 0 : aidlFrames - mostRecentResetPoint;
    return OK;
}

status_t StreamOutHalAidl::setCallback(wp<StreamOutHalInterfaceCallback> callback) {
    AUGMENT_LOG(D);
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (!mContext.isAsynchronous()) {
        AUGMENT_LOG(E, "the callback is intended for asynchronous streams only");
        return INVALID_OPERATION;
    }
    mClientCallback = callback;
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
    if (!mStream) return NO_INIT;

    if (const auto state = getState();
            state == StreamDescriptor::State::DRAINING || isInDrainedState(state)) {
        AUGMENT_LOG(D, "stream already in %s state", toString(state).c_str());
        if (mContext.isAsynchronous() && isInDrainedState(state)) {
            onDrainReady();
        }
        return OK;
    }

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
    StatePositions statePositions{};
    RETURN_STATUS_IF_ERROR(getObservablePosition(&aidlFrames, &aidlTimestamp, &statePositions));
    // See the table at the start of 'StreamHalInterface'.
    if (!mContext.isAsynchronous() && audio_has_proportional_frames(mConfig.format)) {
        *frames = aidlFrames;
    } else {
        const int64_t mostRecentResetPoint = std::max(statePositions.observable.framesAtStandby,
                statePositions.observable.framesAtFlushOrDrain);
        *frames = aidlFrames <= mostRecentResetPoint ? 0 : aidlFrames - mostRecentResetPoint;
    }
    timestamp->tv_sec = aidlTimestamp / NANOS_PER_SECOND;
    timestamp->tv_nsec = aidlTimestamp - timestamp->tv_sec * NANOS_PER_SECOND;
    return OK;
}

status_t StreamOutHalAidl::presentationComplete() {
    AUGMENT_LOG(D);
    return OK;
}

status_t StreamOutHalAidl::updateSourceMetadata(
        const StreamOutHalInterface::SourceMetadata& sourceMetadata) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ::aidl::android::hardware::audio::common::SourceMetadata aidlMetadata =
              VALUE_OR_RETURN_STATUS(legacy2aidl_SourceMetadata(sourceMetadata));
    return statusTFromBinderStatus(
            serializeCall(mStream, &Stream::updateMetadata, aidlMetadata));
}

status_t StreamOutHalAidl::getDualMonoMode(audio_dual_mono_mode_t* mode) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (mode == nullptr) {
        return BAD_VALUE;
    }
    ::aidl::android::media::audio::common::AudioDualMonoMode aidlMode;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            serializeCall(mStream, &Stream::getDualMonoMode, &aidlMode)));
    *mode = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_AudioDualMonoMode_audio_dual_mono_mode_t(aidlMode));
    return OK;
}

status_t StreamOutHalAidl::setDualMonoMode(audio_dual_mono_mode_t mode) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ::aidl::android::media::audio::common::AudioDualMonoMode aidlMode = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_dual_mono_mode_t_AudioDualMonoMode(mode));
    return statusTFromBinderStatus(
            serializeCall(mStream, &Stream::setDualMonoMode, aidlMode));
}

status_t StreamOutHalAidl::getAudioDescriptionMixLevel(float* leveldB) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (leveldB == nullptr) {
        return BAD_VALUE;
    }
    return statusTFromBinderStatus(
            serializeCall(mStream, &Stream::getAudioDescriptionMixLevel, leveldB));
}

status_t StreamOutHalAidl::setAudioDescriptionMixLevel(float leveldB) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    return statusTFromBinderStatus(
            serializeCall(mStream, &Stream::setAudioDescriptionMixLevel, leveldB));
}

status_t StreamOutHalAidl::getPlaybackRateParameters(audio_playback_rate_t* playbackRate) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (playbackRate == nullptr) {
        return BAD_VALUE;
    }
    ::aidl::android::media::audio::common::AudioPlaybackRate aidlRate;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            serializeCall(mStream, &Stream::getPlaybackRateParameters, &aidlRate)));
    *playbackRate = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_AudioPlaybackRate_audio_playback_rate_t(aidlRate));
    return OK;
}

status_t StreamOutHalAidl::setPlaybackRateParameters(const audio_playback_rate_t& playbackRate) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ::aidl::android::media::audio::common::AudioPlaybackRate aidlRate = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_playback_rate_t_AudioPlaybackRate(playbackRate));
    return statusTFromBinderStatus(
            serializeCall(mStream, &Stream::setPlaybackRateParameters, aidlRate));
}

status_t StreamOutHalAidl::setEventCallback(
        const sp<StreamOutHalInterfaceEventCallback>& callback) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (auto broker = mCallbackBroker.promote(); broker != nullptr) {
        broker->setStreamOutEventCallback(static_cast<StreamOutHalInterface*>(this), callback);
    }
    return OK;
}

status_t StreamOutHalAidl::setLatencyMode(audio_latency_mode_t mode) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ::aidl::android::media::audio::common::AudioLatencyMode aidlMode = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_latency_mode_t_AudioLatencyMode(mode));
    return statusTFromBinderStatus(serializeCall(mStream, &Stream::setLatencyMode, aidlMode));
};

status_t StreamOutHalAidl::getRecommendedLatencyModes(std::vector<audio_latency_mode_t> *modes) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    if (modes == nullptr) {
        return BAD_VALUE;
    }
    std::vector<::aidl::android::media::audio::common::AudioLatencyMode> aidlModes;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            serializeCall(mStream, &Stream::getRecommendedLatencyModes, &aidlModes)));
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
        broker->setStreamOutLatencyModeCallback(
                static_cast<StreamOutHalInterface*>(this), callback);
    }
    return OK;
};

status_t StreamOutHalAidl::exit() {
    return StreamHalAidl::exit();
}

void StreamOutHalAidl::onWriteReady() {
    onAsyncTransferReady();
    if (auto clientCb = mClientCallback.load().promote(); clientCb != nullptr) {
        clientCb->onWriteReady();
    }
}

void StreamOutHalAidl::onDrainReady() {
    onAsyncDrainReady();
    if (auto clientCb = mClientCallback.load().promote(); clientCb != nullptr) {
        clientCb->onDrainReady();
    }
}

void StreamOutHalAidl::onError(bool isHardError) {
    onAsyncError();
    if (auto clientCb = mClientCallback.load().promote(); clientCb != nullptr) {
        clientCb->onError(isHardError);
    }
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
        AUGMENT_LOG(D, "set offload metadata %s", mOffloadMetadata.toString().c_str());
        if (status_t status = statusTFromBinderStatus(
                    serializeCall(mStream, &Stream::updateOffloadMetadata, mOffloadMetadata));
            status != OK) {
            AUGMENT_LOG(E, "updateOffloadMetadata failed %d", status);
            return status;
        }
    }
    return OK;
}

status_t StreamOutHalAidl::dump(int fd, const Vector<String16>& args) {
    AUGMENT_LOG(D);
    TIME_CHECK();
    return dumpImpl(fd, args, mStream.get());
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
                std::move(context), getStreamCommon(stream), vext, micInfoProvider),
          mStream(stream), mMicInfoProvider(micInfoProvider) {}

status_t StreamInHalAidl::setGain(float gain) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    const size_t channelCount = audio_channel_count_from_in_mask(mConfig.channel_mask);
    std::vector<float> gains(channelCount != 0 ? channelCount : 1, gain);
    return statusTFromBinderStatus(serializeCall(mStream, &Stream::setHwGain, gains));
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
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            serializeCall(mStream, &Stream::getActiveMicrophones, &dynamicInfo)));
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
            AUGMENT_LOG(E, "no static info for active microphone with id '%s'", d.id.c_str());
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
    return statusTFromBinderStatus(
            serializeCall(mStream, &Stream::updateMetadata, aidlMetadata));
}

status_t StreamInHalAidl::setPreferredMicrophoneDirection(audio_microphone_direction_t direction) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    ::aidl::android::hardware::audio::core::IStreamIn::MicrophoneDirection aidlDirection =
              VALUE_OR_RETURN_STATUS(
                      ::aidl::android::legacy2aidl_audio_microphone_direction_t_MicrophoneDirection(
                              direction));
    return statusTFromBinderStatus(
            serializeCall(mStream, &Stream::setMicrophoneDirection, aidlDirection));
}

status_t StreamInHalAidl::setPreferredMicrophoneFieldDimension(float zoom) {
    TIME_CHECK();
    if (!mStream) return NO_INIT;
    return statusTFromBinderStatus(
            serializeCall(mStream, &Stream::setMicrophoneFieldDimension, zoom));
}

status_t StreamInHalAidl::dump(int fd, const Vector<String16>& args) {
    AUGMENT_LOG(D);
    TIME_CHECK();
    return dumpImpl(fd, args, mStream.get());
}

} // namespace android
