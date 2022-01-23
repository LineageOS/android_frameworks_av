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

#include <utils/Mutex.h>
#include <utils/RefBase.h>

#include <cstdint>
#include <vector>

#include "ClearKeyTypes.h"

namespace clearkeydrm {

class Session : public ::android::RefBase {
  public:
    explicit Session(const std::vector<uint8_t>& sessionId)
        : mSessionId(sessionId), mMockError(clearkeydrm::OK) {}
    virtual ~Session() {}

    const std::vector<uint8_t>& sessionId() const { return mSessionId; }

    CdmResponseType getKeyRequest(const std::vector<uint8_t>& initDataType,
                                  const std::string& mimeType,
                                  CdmKeyType keyType,
                                  std::vector<uint8_t>* keyRequest) const;

    CdmResponseType provideKeyResponse(const std::vector<uint8_t>& response);

    CdmResponseType decrypt(const KeyId keyId, const Iv iv, const uint8_t* srcPtr, uint8_t* dstPtr,
                            const std::vector<int32_t>& clearDataLengths,
                            const std::vector<int32_t>& encryptedDataLengths,
                            size_t* bytesDecryptedOut);

    void setMockError(CdmResponseType error) { mMockError = error; }
    CdmResponseType getMockError() const { return mMockError; }

  private:
    CLEARKEY_DISALLOW_COPY_AND_ASSIGN(Session);

    const std::vector<uint8_t> mSessionId;
    KeyMap mKeyMap;
    ::android::Mutex mMapLock;

    // For mocking error return scenarios
    CdmResponseType mMockError;
};

}  // namespace clearkeydrm
