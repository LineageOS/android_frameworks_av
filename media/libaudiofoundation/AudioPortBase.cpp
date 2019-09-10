/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <algorithm>

#include <android-base/stringprintf.h>
#include <media/AudioPortBase.h>
#include <utils/Log.h>

namespace android {

void AudioPortBase::toAudioPort(struct audio_port *port) const {
    // TODO: update this function once audio_port structure reflects the new profile definition.
    // For compatibility reason: flatening the AudioProfile into audio_port structure.
    FormatSet flatenedFormats;
    SampleRateSet flatenedRates;
    ChannelMaskSet flatenedChannels;
    for (const auto& profile : mProfiles) {
        if (profile->isValid()) {
            audio_format_t formatToExport = profile->getFormat();
            const SampleRateSet &ratesToExport = profile->getSampleRates();
            const ChannelMaskSet &channelsToExport = profile->getChannels();

            flatenedFormats.insert(formatToExport);
            flatenedRates.insert(ratesToExport.begin(), ratesToExport.end());
            flatenedChannels.insert(channelsToExport.begin(), channelsToExport.end());

            if (flatenedRates.size() > AUDIO_PORT_MAX_SAMPLING_RATES ||
                    flatenedChannels.size() > AUDIO_PORT_MAX_CHANNEL_MASKS ||
                    flatenedFormats.size() > AUDIO_PORT_MAX_FORMATS) {
                ALOGE("%s: bailing out: cannot export profiles to port config", __func__);
                return;
            }
        }
    }
    port->role = mRole;
    port->type = mType;
    strlcpy(port->name, mName.c_str(), AUDIO_PORT_MAX_NAME_LEN);
    port->num_sample_rates = flatenedRates.size();
    port->num_channel_masks = flatenedChannels.size();
    port->num_formats = flatenedFormats.size();
    std::copy(flatenedRates.begin(), flatenedRates.end(), port->sample_rates);
    std::copy(flatenedChannels.begin(), flatenedChannels.end(), port->channel_masks);
    std::copy(flatenedFormats.begin(), flatenedFormats.end(), port->formats);

    ALOGV("AudioPort::toAudioPort() num gains %zu", mGains.size());

    port->num_gains = std::min(mGains.size(), (size_t) AUDIO_PORT_MAX_GAINS);
    for (size_t i = 0; i < port->num_gains; i++) {
        port->gains[i] = mGains[i]->getGain();
    }
}

void AudioPortBase::dump(std::string *dst, int spaces, bool verbose) const {
    if (!mName.empty()) {
        dst->append(base::StringPrintf("%*s- name: %s\n", spaces, "", mName.c_str()));
    }
    if (verbose) {
        std::string profilesStr;
        mProfiles.dump(&profilesStr, spaces);
        dst->append(profilesStr);

        if (mGains.size() != 0) {
            dst->append(base::StringPrintf("%*s- gains:\n", spaces, ""));
            for (size_t i = 0; i < mGains.size(); i++) {
                std::string gainStr;
                mGains[i]->dump(&gainStr, spaces + 2, i);
                dst->append(gainStr);
            }
        }
    }
}

}