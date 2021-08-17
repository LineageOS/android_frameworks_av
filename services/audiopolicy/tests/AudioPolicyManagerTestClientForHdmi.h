/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <map>
#include <set>

#include <system/audio.h>
#include <utils/Log.h>
#include <utils/String8.h>

#include "AudioPolicyTestClient.h"

namespace android {

class AudioPolicyManagerTestClientForHdmi : public AudioPolicyManagerTestClient {
public:
    String8 getParameters(audio_io_handle_t /* ioHandle */, const String8&  /* keys*/ ) override {
        return mAudioParameters.toString();
    }

    void addSupportedFormat(audio_format_t format) override {
        mAudioParameters.add(
                String8(AudioParameter::keyStreamSupportedFormats),
                String8(audio_format_to_string(format)));
        mAudioParameters.addInt(String8(AudioParameter::keyStreamSupportedSamplingRates), 48000);
        mAudioParameters.add(String8(AudioParameter::keyStreamSupportedChannels), String8(""));
    }

private:
    AudioParameter mAudioParameters;
};

} // namespace android