/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef ANDROID_AUDIO_IO_DESCRIPTOR_H
#define ANDROID_AUDIO_IO_DESCRIPTOR_H

#include <sstream>
#include <string>

#include <system/audio.h>
#include <utils/RefBase.h>

namespace android {

enum audio_io_config_event_t {
    AUDIO_OUTPUT_REGISTERED,
    AUDIO_OUTPUT_OPENED,
    AUDIO_OUTPUT_CLOSED,
    AUDIO_OUTPUT_CONFIG_CHANGED,
    AUDIO_INPUT_REGISTERED,
    AUDIO_INPUT_OPENED,
    AUDIO_INPUT_CLOSED,
    AUDIO_INPUT_CONFIG_CHANGED,
    AUDIO_CLIENT_STARTED,
};

// audio input/output descriptor used to cache output configurations in client process to avoid
// frequent calls through IAudioFlinger
class AudioIoDescriptor : public virtual RefBase {
public:
    AudioIoDescriptor() = default;
    // For AUDIO_{INPUT|OUTPUT}_CLOSED events.
    AudioIoDescriptor(audio_io_handle_t ioHandle) : mIoHandle(ioHandle) {}
    // For AUDIO_CLIENT_STARTED events.
    AudioIoDescriptor(
            audio_io_handle_t ioHandle, const audio_patch& patch, audio_port_handle_t portId) :
            mIoHandle(ioHandle), mPatch(patch), mPortId(portId) {}
    // For everything else.
    AudioIoDescriptor(
            audio_io_handle_t ioHandle, const audio_patch& patch, bool isInput,
            uint32_t samplingRate, audio_format_t format, audio_channel_mask_t channelMask,
            size_t frameCount, size_t frameCountHal, uint32_t latency = 0,
            audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE) :
            mIoHandle(ioHandle), mPatch(patch), mIsInput(isInput),
            mSamplingRate(samplingRate), mFormat(format), mChannelMask(channelMask),
            mFrameCount(frameCount), mFrameCountHAL(frameCountHal), mLatency(latency),
            mPortId(portId) {}

    audio_io_handle_t getIoHandle() const { return mIoHandle; }
    const audio_patch& getPatch() const { return mPatch; }
    bool getIsInput() const { return mIsInput; }
    uint32_t getSamplingRate() const { return mSamplingRate; }
    audio_format_t getFormat() const { return mFormat; }
    audio_channel_mask_t getChannelMask() const { return mChannelMask; }
    size_t getFrameCount() const { return mFrameCount; }
    size_t getFrameCountHAL() const { return mFrameCountHAL; }
    uint32_t getLatency() const { return mLatency; }
    audio_port_handle_t getPortId() const { return mPortId; }
    audio_port_handle_t getDeviceId() const {
        if (mPatch.num_sources != 0 && mPatch.num_sinks != 0) {
            // FIXME: the API only returns the first device in case of multiple device selection
            return mIsInput ? mPatch.sources[0].id : mPatch.sinks[0].id;
        }
        return AUDIO_PORT_HANDLE_NONE;
    }
    void setPatch(const audio_patch& patch) { mPatch = patch; }

    std::string toDebugString() const {
        std::ostringstream ss;
        ss << mIoHandle << ", samplingRate " << mSamplingRate << ", "
           << audio_format_to_string(mFormat) << ", "
           << (audio_channel_mask_get_representation(mChannelMask) ==
                   AUDIO_CHANNEL_REPRESENTATION_INDEX ?
                   audio_channel_index_mask_to_string(mChannelMask) :
                   (mIsInput ? audio_channel_in_mask_to_string(mChannelMask) :
                           audio_channel_out_mask_to_string(mChannelMask)))
           << ", frameCount " << mFrameCount << ", frameCountHAL " << mFrameCountHAL
           << ", deviceId " << getDeviceId();
        return ss.str();
    }

  private:
    const audio_io_handle_t    mIoHandle = AUDIO_IO_HANDLE_NONE;
          struct audio_patch   mPatch = {};
    const bool                 mIsInput = false;
    const uint32_t             mSamplingRate = 0;
    const audio_format_t       mFormat = AUDIO_FORMAT_DEFAULT;
    const audio_channel_mask_t mChannelMask = AUDIO_CHANNEL_NONE;
    const size_t               mFrameCount = 0;
    const size_t               mFrameCountHAL = 0;
    const uint32_t             mLatency = 0;
    const audio_port_handle_t  mPortId = AUDIO_PORT_HANDLE_NONE;
};


};  // namespace android

#endif  /*ANDROID_AUDIO_IO_DESCRIPTOR_H*/
