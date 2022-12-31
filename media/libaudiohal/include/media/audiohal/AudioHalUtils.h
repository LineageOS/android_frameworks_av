/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define RETURN_IF_BINDER_FAIL(expr)                                              \
    do {                                                                         \
        const ::ndk::ScopedAStatus _temp_status_ = (expr);                       \
        if (!_temp_status_.isOk()) {                                             \
            ALOGE("%s:%d return with expr %s msg %s", __func__, __LINE__, #expr, \
                  _temp_status_.getMessage());                                   \
            return _temp_status_.getStatus();                                    \
        }                                                                        \
    } while (false)

#define RETURN_IF_NOT_OK(statement) \
    do {                            \
        auto tmp = (statement);     \
        if (tmp != OK) {            \
            return tmp;             \
        }                           \
    } while (false)
