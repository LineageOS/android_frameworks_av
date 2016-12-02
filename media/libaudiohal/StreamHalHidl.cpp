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

#define LOG_TAG "StreamHalHidl"
//#define LOG_NDEBUG 0

#include <android/hardware/audio/2.0/IStreamOutCallback.h>
#include <utils/Log.h>

#include "DeviceHalHidl.h"
#include "EffectHalHidl.h"
#include "StreamHalHidl.h"

using ::android::hardware::audio::common::V2_0::AudioChannelMask;
using ::android::hardware::audio::common::V2_0::AudioFormat;
using ::android::hardware::audio::V2_0::AudioDrain;
using ::android::hardware::audio::V2_0::IStreamOutCallback;
using ::android::hardware::audio::V2_0::ParameterValue;
using ::android::hardware::audio::V2_0::Result;
using ::android::hardware::audio::V2_0::TimeSpec;
using ::android::hardware::Return;
using ::android::hardware::Void;

namespace android {

StreamHalHidl::StreamHalHidl(IStream *stream)
        : ConversionHelperHidl("Stream"), mStream(stream) {
}

StreamHalHidl::~StreamHalHidl() {
    mStream = nullptr;
}

status_t StreamHalHidl::getSampleRate(uint32_t *rate) {
    if (!mStream) return NO_INIT;
    return processReturn("getSampleRate", mStream->getSampleRate(), rate);
}

status_t StreamHalHidl::getBufferSize(size_t *size) {
    if (!mStream) return NO_INIT;
    return processReturn("getBufferSize", mStream->getBufferSize(), size);
}

status_t StreamHalHidl::getChannelMask(audio_channel_mask_t *mask) {
    if (!mStream) return NO_INIT;
    return processReturn("getChannelMask", mStream->getChannelMask(), mask);
}

status_t StreamHalHidl::getFormat(audio_format_t *format) {
    if (!mStream) return NO_INIT;
    return processReturn("getFormat", mStream->getFormat(), format);
}

status_t StreamHalHidl::getAudioProperties(
        uint32_t *sampleRate, audio_channel_mask_t *mask, audio_format_t *format) {
    if (!mStream) return NO_INIT;
    Return<void> ret = mStream->getAudioProperties(
            [&](uint32_t sr, AudioChannelMask m, AudioFormat f) {
                *sampleRate = sr;
                *mask = static_cast<audio_channel_mask_t>(m);
                *format = static_cast<audio_format_t>(f);
            });
    return processReturn("getAudioProperties", ret);
}

status_t StreamHalHidl::setParameters(const String8& kvPairs) {
    if (!mStream) return NO_INIT;
    hidl_vec<ParameterValue> hidlParams;
    status_t status = parametersFromHal(kvPairs, &hidlParams);
    if (status != OK) return status;
    return processReturn("setParameters", mStream->setParameters(hidlParams));
}

status_t StreamHalHidl::getParameters(const String8& keys, String8 *values) {
    values->clear();
    if (!mStream) return NO_INIT;
    hidl_vec<hidl_string> hidlKeys;
    status_t status = keysFromHal(keys, &hidlKeys);
    if (status != OK) return status;
    Result retval;
    Return<void> ret = mStream->getParameters(
            hidlKeys,
            [&](Result r, const hidl_vec<ParameterValue>& parameters) {
                retval = r;
                if (retval == Result::OK) {
                    parametersToHal(parameters, values);
                }
            });
    return processReturn("getParameters", ret, retval);
}

status_t StreamHalHidl::addEffect(sp<EffectHalInterface> effect) {
    if (!mStream) return NO_INIT;
    return processReturn("addEffect", mStream->addEffect(
                    static_cast<EffectHalHidl*>(effect.get())->effectId()));
}

status_t StreamHalHidl::removeEffect(sp<EffectHalInterface> effect) {
    if (!mStream) return NO_INIT;
    return processReturn("removeEffect", mStream->removeEffect(
                    static_cast<EffectHalHidl*>(effect.get())->effectId()));
}

status_t StreamHalHidl::standby() {
    if (!mStream) return NO_INIT;
    return processReturn("standby", mStream->standby());
}

status_t StreamHalHidl::dump(int fd) {
    if (!mStream) return NO_INIT;
    native_handle_t* hidlHandle = native_handle_create(1, 0);
    hidlHandle->data[0] = fd;
    Return<void> ret = mStream->debugDump(hidlHandle);
    native_handle_delete(hidlHandle);
    return processReturn("dump", ret);
}


namespace {

/* Notes on callback ownership.

This is how (Hw)Binder ownership model looks like. The server implementation
is owned by Binder framework (via sp<>). Proxies are owned by clients.
When the last proxy disappears, Binder framework releases the server impl.

Thus, it is not needed to keep any references to StreamOutCallback (this is
the server impl) -- it will live as long as HAL server holds a strong ref to
IStreamOutCallback proxy. We clear that reference by calling 'clearCallback'
from the destructor of StreamOutHalHidl.

The callback only keeps a weak reference to the stream. The stream is owned
by AudioFlinger.

*/

struct StreamOutCallback : public IStreamOutCallback {
    StreamOutCallback(const wp<StreamOutHalHidl>& stream) : mStream(stream) {}

    // IStreamOutCallback implementation
    Return<void> onWriteReady()  override {
        sp<StreamOutHalHidl> stream = mStream.promote();
        if (stream != 0) {
            stream->onWriteReady();
        }
        return Void();
    }

    Return<void> onDrainReady()  override {
        sp<StreamOutHalHidl> stream = mStream.promote();
        if (stream != 0) {
            stream->onDrainReady();
        }
        return Void();
    }

    Return<void> onError()  override {
        sp<StreamOutHalHidl> stream = mStream.promote();
        if (stream != 0) {
            stream->onError();
        }
        return Void();
    }

  private:
    wp<StreamOutHalHidl> mStream;
};

}  // namespace

StreamOutHalHidl::StreamOutHalHidl(const sp<IStreamOut>& stream)
        : StreamHalHidl(stream.get()), mStream(stream) {
}

StreamOutHalHidl::~StreamOutHalHidl() {
    if (mCallback.unsafe_get() && mStream != 0) {
        processReturn("clearCallback", mStream->clearCallback());
    }
    mCallback.clear();
}

status_t StreamOutHalHidl::getFrameSize(size_t *size) {
    if (mStream == 0) return NO_INIT;
    return processReturn("getFrameSize", mStream->getFrameSize(), size);
}

status_t StreamOutHalHidl::getLatency(uint32_t *latency) {
    if (mStream == 0) return NO_INIT;
    return processReturn("getLatency", mStream->getLatency(), latency);
}

status_t StreamOutHalHidl::setVolume(float left, float right) {
    if (mStream == 0) return NO_INIT;
    return processReturn("setVolume", mStream->setVolume(left, right));
}

status_t StreamOutHalHidl::write(const void *buffer, size_t bytes, size_t *written) {
    if (mStream == 0) return NO_INIT;
    hidl_vec<uint8_t> hidlData;
    hidlData.setToExternal(static_cast<uint8_t*>(const_cast<void*>(buffer)), bytes);
    Result retval;
    Return<void> ret = mStream->write(
            hidlData,
            [&](Result r, uint64_t w) {
                retval = r;
                *written = w;
            });
    return processReturn("write", ret, retval);
}

status_t StreamOutHalHidl::getRenderPosition(uint32_t *dspFrames) {
    if (mStream == 0) return NO_INIT;
    Result retval;
    Return<void> ret = mStream->getRenderPosition(
            [&](Result r, uint32_t d) {
                retval = r;
                if (retval == Result::OK) {
                    *dspFrames = d;
                }
            });
    return processReturn("getRenderPosition", ret, retval);
}

status_t StreamOutHalHidl::getNextWriteTimestamp(int64_t *timestamp) {
    if (mStream == 0) return NO_INIT;
    Result retval;
    Return<void> ret = mStream->getNextWriteTimestamp(
            [&](Result r, int64_t t) {
                retval = r;
                if (retval == Result::OK) {
                    *timestamp = t;
                }
            });
    return processReturn("getRenderPosition", ret, retval);
}

status_t StreamOutHalHidl::setCallback(wp<StreamOutHalInterfaceCallback> callback) {
    if (mStream == 0) return NO_INIT;
    status_t status = processReturn(
            "setCallback", mStream->setCallback(new StreamOutCallback(this)));
    if (status == OK) {
        mCallback = callback;
    }
    return status;
}

status_t StreamOutHalHidl::supportsPauseAndResume(bool *supportsPause, bool *supportsResume) {
    if (mStream == 0) return NO_INIT;
    Return<void> ret = mStream->supportsPauseAndResume(
            [&](bool p, bool r) {
                *supportsPause = p;
                *supportsResume = r;
            });
    return processReturn("supportsPauseAndResume", ret);
}

status_t StreamOutHalHidl::pause() {
    if (mStream == 0) return NO_INIT;
    return processReturn("pause", mStream->pause());
}

status_t StreamOutHalHidl::resume() {
    if (mStream == 0) return NO_INIT;
    return processReturn("pause", mStream->resume());
}

status_t StreamOutHalHidl::supportsDrain(bool *supportsDrain) {
    if (mStream == 0) return NO_INIT;
    return processReturn("supportsDrain", mStream->supportsDrain(), supportsDrain);
}

status_t StreamOutHalHidl::drain(bool earlyNotify) {
    if (mStream == 0) return NO_INIT;
    return processReturn(
            "drain", mStream->drain(earlyNotify ? AudioDrain::EARLY_NOTIFY : AudioDrain::ALL));
}

status_t StreamOutHalHidl::flush() {
    if (mStream == 0) return NO_INIT;
    return processReturn("pause", mStream->flush());
}

status_t StreamOutHalHidl::getPresentationPosition(uint64_t *frames, struct timespec *timestamp) {
    if (mStream == 0) return NO_INIT;
    Result retval;
    Return<void> ret = mStream->getPresentationPosition(
            [&](Result r, uint64_t hidlFrames, const TimeSpec& hidlTimeStamp) {
                retval = r;
                if (retval == Result::OK) {
                    *frames = hidlFrames;
                    timestamp->tv_sec = hidlTimeStamp.tvSec;
                    timestamp->tv_nsec = hidlTimeStamp.tvNSec;
                }
            });
    return processReturn("getPresentationPosition", ret, retval);
}

void StreamOutHalHidl::onWriteReady() {
    sp<StreamOutHalInterfaceCallback> callback = mCallback.promote();
    if (callback == 0) return;
    ALOGV("asyncCallback onWriteReady");
    callback->onWriteReady();
}

void StreamOutHalHidl::onDrainReady() {
    sp<StreamOutHalInterfaceCallback> callback = mCallback.promote();
    if (callback == 0) return;
    ALOGV("asyncCallback onDrainReady");
    callback->onDrainReady();
}

void StreamOutHalHidl::onError() {
    sp<StreamOutHalInterfaceCallback> callback = mCallback.promote();
    if (callback == 0) return;
    ALOGV("asyncCallback onError");
    callback->onError();
}


StreamInHalHidl::StreamInHalHidl(const sp<IStreamIn>& stream)
        : StreamHalHidl(stream.get()), mStream(stream) {
}

StreamInHalHidl::~StreamInHalHidl() {
}

status_t StreamInHalHidl::getFrameSize(size_t *size) {
    if (mStream == 0) return NO_INIT;
    return processReturn("getFrameSize", mStream->getFrameSize(), size);
}

status_t StreamInHalHidl::setGain(float gain) {
    if (mStream == 0) return NO_INIT;
    return processReturn("setGain", mStream->setGain(gain));
}

status_t StreamInHalHidl::read(void *buffer, size_t bytes, size_t *read) {
    if (mStream == 0) return NO_INIT;
    Result retval;
    Return<void> ret = mStream->read(
            bytes,
            [&](Result r, const hidl_vec<uint8_t>& hidlData) {
                retval = r;
                *read = std::min(hidlData.size(), bytes);
                if (retval == Result::OK) {
                    memcpy(buffer, &hidlData[0], *read);
                }
            });
    return processReturn("read", ret, retval);
}

status_t StreamInHalHidl::getInputFramesLost(uint32_t *framesLost) {
    if (mStream == 0) return NO_INIT;
    return processReturn("getInputFramesLost", mStream->getInputFramesLost(), framesLost);
}

status_t StreamInHalHidl::getCapturePosition(int64_t *frames, int64_t *time) {
    if (mStream == 0) return NO_INIT;
    Result retval;
    Return<void> ret = mStream->getCapturePosition(
            [&](Result r, uint64_t hidlFrames, uint64_t hidlTime) {
                retval = r;
                if (retval == Result::OK) {
                    *frames = hidlFrames;
                    *time = hidlTime;
                }
            });
    return processReturn("getCapturePosition", ret, retval);
}

} // namespace android
