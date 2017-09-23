/*
 * Copyright (C) 2009 The Android Open Source Project
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

#include <media/stagefright/MediaSource.h>

namespace android {

MediaSource::MediaSource() {}

MediaSource::~MediaSource() {}

}  // namespace android

extern "C" {

bool _ZNK7android11MediaSource11ReadOptions9getSeekToEPxPNS1_8SeekModeE(android::IMediaSource::ReadOptions *readOptions, int64_t *time_us, android::IMediaSource::ReadOptions::SeekMode *mode) {
    ALOGW("_ZNK7android11MediaSource11ReadOptions9getSeekToEPxPNS1_8SeekModeE");
    bool res = readOptions->getSeekTo(time_us, mode);
    ALOGW("_ZNK7android11MediaSource11ReadOptions9getSeekToEPxPNS1_8SeekModeE %lld, %d, %d", *time_us, *mode, res);
    return res;
}

}
