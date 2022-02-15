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

#include <error/expected_utils.h>
#include <utils/Errors.h>

namespace android {
namespace error {

/**
 * A convenience short-hand for base::expected, where the error type is a status_t.
 */
template <typename T>
using Result = base::expected<T, status_t>;

}  // namespace error
}  // namespace android

// Below are the implementations of errorIsOk and errorToString for status_t .
// This allows status_t to be used in conjunction with the expected_utils.h macros.
// Unfortuantely, since status_t is merely a typedef for int rather than a unique type, we have to
// overload these methods for any int, and do so in the global namespace for ADL to work.

inline bool errorIsOk(int status) {
    return status == android::OK;
}

inline std::string errorToString(int status) {
    return android::statusToString(status);
}
