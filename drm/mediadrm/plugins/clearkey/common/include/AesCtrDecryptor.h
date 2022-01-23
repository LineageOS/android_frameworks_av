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

#include "ClearKeyTypes.h"

namespace clearkeydrm {

class AesCtrDecryptor {
  public:
    AesCtrDecryptor() {}

    CdmResponseType decrypt(const std::vector<uint8_t>& key, const Iv iv, const uint8_t* source,
                            uint8_t* destination,
                            const std::vector<int32_t>& clearDataLengths,
                            const std::vector<int32_t>& encryptedDataLengths,
                            size_t* bytesDecryptedOut);

  private:
    CLEARKEY_DISALLOW_COPY_AND_ASSIGN(AesCtrDecryptor);
};

}  // namespace clearkeydrm
