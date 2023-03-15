/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <error/Result.h>

namespace android {
// `ConversionResult` is always defined in the `::android` namespace,
// so that it can be found from any nested namespace.
// See below for the convenience alias specific to the NDK backend.
template <typename T>
using ConversionResult = ::android::error::Result<T>;
}  // namespace android

// Include 'AidlConversionUtil.h' once if 'BACKEND_NDK' is defined,
// or no 'BACKEND_*' is defined (C++ backend). Include twice if
// 'BACKEND_CPP_NDK' is defined: once with 'BACKEND_NDK_IMPL', once w/o defines.

#if defined(BACKEND_CPP_NDK) || defined(BACKEND_NDK)
#define BACKEND_NDK_IMPL
#include <media/AidlConversionUtil-impl.h>
#undef BACKEND_NDK_IMPL
#endif

#if defined(BACKEND_CPP_NDK) || !defined(BACKEND_NDK)
#include <media/AidlConversionUtil-impl.h>
#endif
