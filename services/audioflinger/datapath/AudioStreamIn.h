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

#include "AudioHwDevice.h"
#include <media/audiohal/DeviceHalInterface.h>
#include <media/audiohal/StreamHalInterface.h>

namespace android {

// Abstraction for the Audio Source for the RecordThread (HAL or PassthruPatchRecord).
struct Source {
    virtual ~Source() = default;
    // The following methods have the same signatures as in StreamHalInterface.
    virtual status_t read(void* buffer, size_t bytes, size_t* read) = 0;
    virtual status_t getCapturePosition(int64_t* frames, int64_t* time) = 0;
    virtual status_t standby() = 0;
};

// AudioStreamIn is immutable, so its fields are const.
// The methods must not be const to match StreamHalInterface signature.

struct AudioStreamIn : public Source {
    const AudioHwDevice* const audioHwDev;
    const sp<StreamInHalInterface> stream;
    const audio_input_flags_t flags;

    AudioStreamIn(
            const AudioHwDevice* dev, const sp<StreamInHalInterface>& in,
            audio_input_flags_t flags)
        : audioHwDev(dev), stream(in), flags(flags) {}

    status_t read(void* buffer, size_t bytes, size_t* read) final {
        return stream->read(buffer, bytes, read);
    }

    status_t getCapturePosition(int64_t* frames, int64_t* time) final {
        return stream->getCapturePosition(frames, time);
    }

    status_t standby() final { return stream->standby(); }

    sp<DeviceHalInterface> hwDev() const { return audioHwDev->hwDevice(); }
};

}  // namespace android
