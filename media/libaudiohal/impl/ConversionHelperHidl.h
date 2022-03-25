/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef ANDROID_HARDWARE_CONVERSION_HELPER_HIDL_H
#define ANDROID_HARDWARE_CONVERSION_HELPER_HIDL_H

#include <functional>

#include <hidl/HidlSupport.h>
#include <system/audio.h>

namespace android {

template<typename HalResult>
class ConversionHelperHidl {
  protected:
    using HalResultConverter = std::function<status_t(const HalResult&)>;
    const std::string mClassName;

    ConversionHelperHidl(std::string_view className, HalResultConverter resultConv)
            : mClassName(className), mResultConverter(resultConv) {}

    template<typename R, typename T>
    status_t processReturn(const char* funcName,
            const ::android::hardware::Return<R>& ret, T *retval) {
        if (ret.isOk()) {
            // This way it also works for enum class to unscoped enum conversion.
            *retval = static_cast<T>(static_cast<R>(ret));
            return OK;
        }
        return processReturn(funcName, ret);
    }

    template<typename T>
    status_t processReturn(const char* funcName, const ::android::hardware::Return<T>& ret) {
        if (!ret.isOk()) {
            emitError(funcName, ret.description().c_str());
        }
        return ret.isOk() ? OK : FAILED_TRANSACTION;
    }

    status_t processReturn(const char* funcName,
            const ::android::hardware::Return<HalResult>& ret) {
        if (!ret.isOk()) {
            emitError(funcName, ret.description().c_str());
        }
        return ret.isOk() ? mResultConverter(ret) : FAILED_TRANSACTION;
    }

    template<typename T>
    status_t processReturn(
            const char* funcName, const ::android::hardware::Return<T>& ret, HalResult retval) {
        if (!ret.isOk()) {
            emitError(funcName, ret.description().c_str());
        }
        return ret.isOk() ? mResultConverter(retval) : FAILED_TRANSACTION;
    }

    const std::string& getClassName() const {
        return mClassName;
    }

  private:
    HalResultConverter mResultConverter;

    void emitError(const char* funcName, const char* description) {
        ALOGE("%s %p %s: %s (from rpc)", mClassName.c_str(), this, funcName, description);
    }
};

}  // namespace android

#endif // ANDROID_HARDWARE_CONVERSION_HELPER_HIDL_H
