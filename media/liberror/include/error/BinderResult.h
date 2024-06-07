/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <binder/Status.h>
#include <error/expected_utils.h>
#include <utils/Errors.h>

namespace android {
namespace error {

/**
 * A convenience short-hand for base::expected, where the error type is a binder::Status, for use
 * when implementing binder services.
 * Clients need to link against libbinder, since this library is header only.
 */
template <typename T>
using BinderResult = base::expected<T, binder::Status>;

inline base::unexpected<binder::Status> unexpectedExceptionCode(int32_t exceptionCode,
                                                                const char* s) {
    return base::unexpected{binder::Status::fromExceptionCode(exceptionCode, s)};
}

inline base::unexpected<binder::Status> unexpectedServiceException(int32_t serviceSpecificCode,
                                                                   const char* s) {
    return base::unexpected{binder::Status::fromServiceSpecificError(serviceSpecificCode, s)};
}

}  // namespace error
}  // namespace android

inline std::string errorToString(const ::android::binder::Status& status) {
    return std::string{status.toString8().c_str()};
}
