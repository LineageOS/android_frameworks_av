/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <cstdint>
#include <map>
#include <vector>

namespace clearkeydrm {

const uint8_t kBlockSize = 16;  // AES_BLOCK_SIZE;
typedef uint8_t KeyId[kBlockSize];
typedef uint8_t Iv[kBlockSize];

typedef std::map<std::vector<uint8_t>, std::vector<uint8_t>> KeyMap;

#define CLEARKEY_DISALLOW_COPY_AND_ASSIGN(TypeName) \
    TypeName(const TypeName&) = delete;             \
    void operator=(const TypeName&) = delete;

#define CLEARKEY_DISALLOW_COPY_AND_ASSIGN_AND_NEW(TypeName) \
    TypeName() = delete;                                    \
    TypeName(const TypeName&) = delete;                     \
    void operator=(const TypeName&) = delete;

enum CdmResponseType : int32_t {
    OK = 0,
    ERROR_NO_LICENSE = 1,
    ERROR_SESSION_NOT_OPENED = 3,
    ERROR_CANNOT_HANDLE = 4,
    ERROR_INVALID_STATE = 5,
    BAD_VALUE = 6,
    ERROR_DECRYPT = 11,
    ERROR_UNKNOWN = 12,
    ERROR_INSUFFICIENT_SECURITY = 13,
    ERROR_FRAME_TOO_LARGE = 14,
    ERROR_SESSION_LOST_STATE = 15,
    ERROR_RESOURCE_CONTENTION = 16,
};

enum CdmKeyType : int32_t {
    KEY_TYPE_OFFLINE = 0,
    KEY_TYPE_STREAMING = 1,
    KEY_TYPE_RELEASE = 2,
};

}  // namespace clearkeydrm
