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

#include <system/audio.h>

namespace android {

class VolumeInterface : public virtual RefBase {
public:
    virtual void setMasterVolume(float value) = 0;
    virtual void setMasterBalance(float balance) = 0;
    virtual void setMasterMute(bool muted) = 0;
    virtual void setStreamVolume(audio_stream_type_t stream, float value) = 0;
    virtual void setStreamMute(audio_stream_type_t stream, bool muted) = 0;
    // TODO(b/290699744) add "get" prefix for getter below.
    virtual float streamVolume(audio_stream_type_t stream) const = 0;
};

}  // namespace android
