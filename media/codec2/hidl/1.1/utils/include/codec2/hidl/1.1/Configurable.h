/*
 * Copyright 2019 The Android Open Source Project
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

#ifndef CODEC2_HIDL_V1_1_UTILS_CONFIGURABLE_H
#define CODEC2_HIDL_V1_1_UTILS_CONFIGURABLE_H

#include <codec2/hidl/1.0/Configurable.h>
#include <codec2/hidl/1.1/types.h>

namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace V1_1 {
namespace utils {

using ::android::hardware::media::c2::V1_0::utils::ConfigurableC2Intf;
using ::android::hardware::media::c2::V1_0::utils::ParameterCache;
using ::android::hardware::media::c2::V1_0::utils::CachedConfigurable;

} // namespace utils
} // namespace V1_1
} // namespace c2
} // namespace media
} // namespace hardware
} // namespace android

#endif // CODEC2_HIDL_V1_1_UTILS_CONFIGURABLE_H
