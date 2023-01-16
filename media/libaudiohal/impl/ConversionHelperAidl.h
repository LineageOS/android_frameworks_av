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

#include <string>
#include <string_view>
#include <vector>

#include <utils/String16.h>
#include <utils/Vector.h>

namespace android {

class Args {
  public:
    explicit Args(const Vector<String16>& args)
            : mValues(args.size()), mPtrs(args.size()) {
        for (size_t i = 0; i < args.size(); ++i) {
            mValues[i] = std::string(String8(args[i]));
            mPtrs[i] = mValues[i].c_str();
        }
    }
    const char** args() { return mPtrs.data(); }
  private:
    std::vector<std::string> mValues;
    std::vector<const char*> mPtrs;
};

class ConversionHelperAidl {
  protected:
    ConversionHelperAidl(std::string_view className) : mClassName(className) {}

    const std::string& getClassName() const {
        return mClassName;
    }

    const std::string mClassName;
};

}  // namespace android
