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

#include <string>
#include <vector>

#include "jsmn.h"
#include "ClearKeyTypes.h"

namespace clearkeydrm {

class JsonWebKey {
  public:
    JsonWebKey();
    virtual ~JsonWebKey();

    bool extractKeysFromJsonWebKeySet(const std::string& jsonWebKeySet, KeyMap* keys);

  private:
    std::vector<jsmntok_t> mJsmnTokens;
    std::vector<std::string> mJsonObjects;
    std::vector<std::string> mTokens;

    bool decodeBase64String(const std::string& encodedText, std::vector<uint8_t>* decodedText);
    bool findKey(const std::string& jsonObject, std::string* keyId, std::string* encodedKey);
    void findValue(const std::string& key, std::string* value);
    bool isJsonWebKeySet(const std::string& jsonObject) const;
    bool parseJsonObject(const std::string& jsonObject, std::vector<std::string>* tokens);
    bool parseJsonWebKeySet(const std::string& jsonWebKeySet,
                            std::vector<std::string>* jsonObjects);

    CLEARKEY_DISALLOW_COPY_AND_ASSIGN(JsonWebKey);
};

}  // namespace clearkeydrm
