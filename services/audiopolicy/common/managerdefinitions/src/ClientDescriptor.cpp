/*
 * Copyright (C) 2018 The Android Open Source Project
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

#define LOG_TAG "APM_ClientDescriptor"
//#define LOG_NDEBUG 0

#include <sstream>

#include <android-base/stringprintf.h>
#include <TypeConverter.h>
#include <utils/Log.h>
#include <utils/String8.h>

#include "AudioOutputDescriptor.h"
#include "AudioPatch.h"
#include "AudioPolicyMix.h"
#include "ClientDescriptor.h"
#include "DeviceDescriptor.h"
#include "HwModule.h"
#include "IOProfile.h"

namespace android {

std::string ClientDescriptor::toShortString() const
{
    std::stringstream ss;

    ss << "PortId: " << mPortId << " SessionId: " << mSessionId << " Uid: " << mUid;
    return ss.str();
}

void ClientDescriptor::dump(String8 *dst, int spaces) const
{
    dst->appendFormat("Port ID: %d; Session ID: %d; uid %d; State: %s\n",
            mPortId, mSessionId, mUid, mActive ? "Active" : "Inactive");
    dst->appendFormat("%*s%s; %d; Channel mask: 0x%x\n", spaces, "",
            audio_format_to_string(mConfig.format), mConfig.sample_rate, mConfig.channel_mask);
    dst->appendFormat("%*sAttributes: %s\n", spaces, "", toString(mAttributes).c_str());
    if (mPreferredDeviceId != AUDIO_PORT_HANDLE_NONE) {
        dst->appendFormat("%*sPreferred Device Port ID: %d;\n", spaces, "", mPreferredDeviceId);
    }
}

void TrackClientDescriptor::dump(String8 *dst, int spaces) const
{
    ClientDescriptor::dump(dst, spaces);
    dst->appendFormat("%*sStream: %d; Flags: %08x; Refcount: %d\n", spaces, "",
            mStream, mFlags, mActivityCount);
    dst->appendFormat("%*sDAP Primary Mix: %p\n", spaces, "", mPrimaryMix.promote().get());
    if (!mSecondaryOutputs.empty()) {
        dst->appendFormat("%*sDAP Secondary Outputs: ", spaces - 2, "");
        for (auto desc : mSecondaryOutputs) {
            dst->appendFormat("%d, ", desc.promote() == nullptr ? 0 : desc.promote()->mIoHandle);
        }
        dst->append("\n");
    }
}

std::string TrackClientDescriptor::toShortString() const
{
    std::stringstream ss;
    ss << ClientDescriptor::toShortString() << " Stream: " << mStream;
    return ss.str();
}

void RecordClientDescriptor::trackEffectEnabled(const sp<EffectDescriptor> &effect, bool enabled)
{
    if (enabled) {
        mEnabledEffects.replaceValueFor(effect->mId, effect);
    } else {
        mEnabledEffects.removeItem(effect->mId);
    }
}

void RecordClientDescriptor::dump(String8 *dst, int spaces) const
{
    ClientDescriptor::dump(dst, spaces);
    dst->appendFormat("%*sSource: %d; Flags: %08x; is soundtrigger: %d\n",
            spaces, "", mSource, mFlags, mIsSoundTrigger);
    mEnabledEffects.dump(dst, spaces + 2 /*spaces*/, false /*verbose*/);
}

SourceClientDescriptor::SourceClientDescriptor(audio_port_handle_t portId, uid_t uid,
         audio_attributes_t attributes, const struct audio_port_config &config,
         const sp<DeviceDescriptor>& srcDevice, audio_stream_type_t stream,
         product_strategy_t strategy, VolumeSource volumeSource, bool isInternal) :
    TrackClientDescriptor::TrackClientDescriptor(portId, uid, AUDIO_SESSION_NONE, attributes,
        {config.sample_rate, config.channel_mask, config.format}, AUDIO_PORT_HANDLE_NONE,
        stream, strategy, volumeSource, AUDIO_OUTPUT_FLAG_NONE, false,
        {} /* Sources do not support secondary outputs*/, nullptr),
    mSrcDevice(srcDevice), mIsInternal(isInternal)
{
}

void SourceClientDescriptor::setSwOutput(
        const sp<SwAudioOutputDescriptor>& swOutput, bool closeOutput)
{
    mSwOutput = swOutput;
    mCloseOutput = closeOutput;
}

void SourceClientDescriptor::setHwOutput(const sp<HwAudioOutputDescriptor>& hwOutput)
{
    mHwOutput = hwOutput;
}

void SourceClientDescriptor::dump(String8 *dst, int spaces) const
{
    TrackClientDescriptor::dump(dst, spaces);
    const std::string prefix = base::StringPrintf("%*sDevice: ", spaces, "");
    dst->appendFormat("%s", prefix.c_str());
    mSrcDevice->dump(dst, prefix.size());
}

void SourceClientCollection::dump(String8 *dst) const
{
    dst->appendFormat("\n Audio sources (%zu):\n", size());
    for (size_t i = 0; i < size(); i++) {
        const std::string prefix = base::StringPrintf("  %zu. ", i + 1);
        dst->appendFormat("%s", prefix.c_str());
        valueAt(i)->dump(dst, prefix.size());
    }
}

}; //namespace android
