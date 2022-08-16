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

#include <sstream>

#include <android-base/expected.h>
#include <log/log_main.h>

/**
 * Useful macros for working with status codes and base::expected.
 *
 * These macros facilitate various kinds of strategies for reduction of error-handling-related
 * boilerplate. They can be can be classified by the following criteria:
 * - Whether the argument is a standalone status code vs. base::expected (status or value). In the
 *   latter case, the macro will evaluate to the contained value in the case of success.
 * - Whether to FATAL or return in response to an error.
 *   - In the latter case, whether the enclosing function returns a status code or a base::expected.
 *
 * The table below summarizes which macro serves which case, based on those criteria:
 * +--------------------+------------------+------------------------------------------------------+
 * |     Error response | FATAL            | Early return                                         |
 * |                    |                  +---------------------------+--------------------------+
 * | Expression type    |                  | Function returns expected | Function returns status  |
 * +--------------------+------------------+---------------------------+--------------------------+
 * | status code        | FATAL_IF_ERROR() | RETURN_IF_ERROR()         | RETURN_STATUS_IF_ERROR() |
 * +--------------------+------------------+---------------------------+--------------------------+
 * | expected           | VALUE_OR_FATAL() | VALUE_OR_RETURN()         | VALUE_OR_RETURN_STATUS() |
 * +--------------------+------------------+---------------------------+--------------------------+
 *
 * All macros expect that:
 * - The error type and value value type are movable.
 * - The macro argument can be assigned to a variable using `auto x = (exp)`.
 * - The expression errorIsOk(e) for the error type evaluatea to a bool which is true iff the
 *   status is considered success.
 * - The expression errorToString(e) for a given error type evaluated to a std::string containing a
 *   human-readable version of the status.
 */

#define VALUE_OR_RETURN(exp)                                                         \
    ({                                                                               \
        auto _tmp = (exp);                                                           \
        if (!_tmp.ok()) return ::android::base::unexpected(std::move(_tmp.error())); \
        std::move(_tmp.value());                                                     \
    })

#define VALUE_OR_RETURN_STATUS(exp)                     \
    ({                                                  \
        auto _tmp = (exp);                              \
        if (!_tmp.ok()) return std::move(_tmp.error()); \
        std::move(_tmp.value());                        \
    })

#define VALUE_OR_FATAL(exp)                                                                       \
    ({                                                                                            \
        auto _tmp = (exp);                                                                        \
        LOG_ALWAYS_FATAL_IF(!_tmp.ok(), "Function: %s Line: %d Failed result (%s)", __FUNCTION__, \
                            __LINE__, errorToString(_tmp.error()).c_str());                       \
        std::move(_tmp.value());                                                                  \
    })

#define RETURN_IF_ERROR(exp) \
    if (auto _tmp = (exp); !errorIsOk(_tmp)) return ::android::base::unexpected(std::move(_tmp));

#define RETURN_STATUS_IF_ERROR(exp) \
    if (auto _tmp = (exp); !errorIsOk(_tmp)) return _tmp;

#define FATAL_IF_ERROR(exp)                                                                \
    {                                                                                      \
        auto _tmp = (exp);                                                                 \
        LOG_ALWAYS_FATAL_IF(!errorIsOk(_tmp), "Function: %s Line: %d Failed result: (%s)", \
                            __FUNCTION__, __LINE__, errorToString(_tmp).c_str());         \
    }
