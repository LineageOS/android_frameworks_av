/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <string.h>

#include "ClearKeyUUID.h"

namespace clearkeydrm {

namespace {

const std::array<uint8_t, 16> kCommonPsshBoxUUID{
    0x10,0x77,0xEF,0xEC,0xC0,0xB2,0x4D,0x02,
    0xAC,0xE3,0x3C,0x1E,0x52,0xE2,0xFB,0x4B
};

// To be used in mpd to specify drm scheme for players
const std::array<uint8_t, 16> kClearKeyUUID{
    0xE2,0x71,0x9D,0x58,0xA9,0x85,0xB3,0xC9,
    0x78,0x1A,0xB0,0x30,0xAF,0x78,0xD3,0x0E
};

}

bool isClearKeyUUID(const uint8_t uuid[16]) {
    return !memcmp(uuid, kCommonPsshBoxUUID.data(), kCommonPsshBoxUUID.size()) ||
           !memcmp(uuid, kClearKeyUUID.data(), kClearKeyUUID.size());
}

std::vector<std::array<uint8_t, 16>> getSupportedCryptoSchemes() {
    return {kCommonPsshBoxUUID, kClearKeyUUID};
}

} // namespace clearkeydrm
