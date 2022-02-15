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
#define LOG_TAG "clearkey-Session"

#include <utils/Log.h>

#include "Session.h"

#include "AesCtrDecryptor.h"
#include "InitDataParser.h"
#include "JsonWebKey.h"

namespace clearkeydrm {

using ::android::Mutex;
using ::android::sp;

CdmResponseType Session::getKeyRequest(const std::vector<uint8_t>& initData,
                                       const std::string& mimeType,
                                       CdmKeyType keyType,
                                       std::vector<uint8_t>* keyRequest) const {
    InitDataParser parser;
    return parser.parse(initData, mimeType, keyType, keyRequest);
}

CdmResponseType Session::provideKeyResponse(const std::vector<uint8_t>& response) {
    std::string responseString(reinterpret_cast<const char*>(response.data()), response.size());
    KeyMap keys;

    Mutex::Autolock lock(mMapLock);
    JsonWebKey parser;
    if (parser.extractKeysFromJsonWebKeySet(responseString, &keys)) {
        for (auto& key : keys) {
            std::string first(key.first.begin(), key.first.end());
            std::string second(key.second.begin(), key.second.end());
            mKeyMap.insert(
                    std::pair<std::vector<uint8_t>, std::vector<uint8_t>>(key.first, key.second));
        }
        return clearkeydrm::OK;
    } else {
        return clearkeydrm::ERROR_UNKNOWN;
    }
}

CdmResponseType Session::decrypt(const KeyId keyId, const Iv iv,
                                 const uint8_t* srcPtr, uint8_t* destPtr,
                                 const std::vector<int32_t>& clearDataLengths,
                                 const std::vector<int32_t>& encryptedDataLengths,
                                 size_t* bytesDecryptedOut) {
    Mutex::Autolock lock(mMapLock);

    if (getMockError() != clearkeydrm::OK) {
        return getMockError();
    }

    std::vector<uint8_t> keyIdVector;
    keyIdVector.clear();
    keyIdVector.insert(keyIdVector.end(), keyId, keyId + kBlockSize);
    std::map<std::vector<uint8_t>, std::vector<uint8_t>>::iterator itr;
    itr = mKeyMap.find(keyIdVector);
    if (itr == mKeyMap.end()) {
        return clearkeydrm::ERROR_NO_LICENSE;
    }

    clearkeydrm::AesCtrDecryptor decryptor;
    auto status = decryptor.decrypt(itr->second /*key*/, iv, srcPtr, destPtr,
                                    clearDataLengths,
                                    encryptedDataLengths,
                                    bytesDecryptedOut);
    return status;
}

}  // namespace clearkeydrm
