/*
 * Copyright 2020 The Android Open Source Project
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
// Authors: corbin.souffrant@leviathansecurity.com
//          dylan.katz@leviathansecurity.com

#pragma once

#include <fuzzer/FuzzedDataProvider.h>
#include <media/stagefright/foundation/AMessage.h>

namespace android {

// Mappings vectors are the list of attributes that the MediaMuxer
// class looks for in the message.
static std::vector<const char *> floatMappings{
    "capture-rate",
    "time-lapse-fps",
    "frame-rate",
};

static std::vector<const char *> int64Mappings{
    "exif-offset",    "exif-size", "target-time",
    "thumbnail-time", "timeUs",    "durationUs",
};

static std::vector<const char *> int32Mappings{"loop",
                                               "time-scale",
                                               "crypto-mode",
                                               "crypto-default-iv-size",
                                               "crypto-encrypted-byte-block",
                                               "crypto-skip-byte-block",
                                               "frame-count",
                                               "max-bitrate",
                                               "pcm-big-endian",
                                               "temporal-layer-count",
                                               "temporal-layer-id",
                                               "thumbnail-width",
                                               "thumbnail-height",
                                               "track-id",
                                               "valid-samples",
                                               "color-format",
                                               "ca-system-id",
                                               "is-sync-frame",
                                               "bitrate",
                                               "max-bitrate",
                                               "width",
                                               "height",
                                               "sar-width",
                                               "sar-height",
                                               "display-width",
                                               "display-height",
                                               "is-default",
                                               "tile-width",
                                               "tile-height",
                                               "grid-rows",
                                               "grid-cols",
                                               "rotation-degrees",
                                               "channel-count",
                                               "sample-rate",
                                               "bits-per-sample",
                                               "channel-mask",
                                               "encoder-delay",
                                               "encoder-padding",
                                               "is-adts",
                                               "frame-rate",
                                               "max-height",
                                               "max-width",
                                               "max-input-size",
                                               "haptic-channel-count",
                                               "pcm-encoding",
                                               "aac-profile"};

static const std::vector<std::function<void(AMessage *, FuzzedDataProvider *)>>
    amessage_setvals = {
        [](AMessage *msg, FuzzedDataProvider *fdp) -> void {
          msg->setRect("crop", fdp->ConsumeIntegral<int32_t>(),
                       fdp->ConsumeIntegral<int32_t>(),
                       fdp->ConsumeIntegral<int32_t>(),
                       fdp->ConsumeIntegral<int32_t>());
        },
        [](AMessage *msg, FuzzedDataProvider *fdp) -> void {
          msg->setFloat(floatMappings[fdp->ConsumeIntegralInRange<size_t>(
                            0, floatMappings.size() - 1)],
                        fdp->ConsumeFloatingPoint<float>());
        },
        [](AMessage *msg, FuzzedDataProvider *fdp) -> void {
          msg->setInt64(int64Mappings[fdp->ConsumeIntegralInRange<size_t>(
                            0, int64Mappings.size() - 1)],
                        fdp->ConsumeIntegral<int64_t>());
        },
        [](AMessage *msg, FuzzedDataProvider *fdp) -> void {
          msg->setInt32(int32Mappings[fdp->ConsumeIntegralInRange<size_t>(
                            0, int32Mappings.size() - 1)],
                        fdp->ConsumeIntegral<int32_t>());
        }};
} // namespace android
