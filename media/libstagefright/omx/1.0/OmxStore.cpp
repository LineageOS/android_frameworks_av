/*
 * Copyright 2017, The Android Open Source Project
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

#include <ios>
#include <list>

#include <android-base/logging.h>

#include <media/stagefright/omx/1.0/Conversion.h>
#include <media/stagefright/omx/1.0/OmxStore.h>

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

OmxStore::OmxStore() {
}

OmxStore::~OmxStore() {
}

Return<void> OmxStore::listServiceAttributes(listServiceAttributes_cb _hidl_cb) {
    _hidl_cb(toStatus(NO_ERROR), hidl_vec<ServiceAttribute>());
    return Void();
}

Return<void> OmxStore::getNodePrefix(getNodePrefix_cb _hidl_cb) {
    _hidl_cb(hidl_string());
    return Void();
}

Return<void> OmxStore::listRoles(listRoles_cb _hidl_cb) {
    _hidl_cb(hidl_vec<RoleInfo>());
    return Void();
}

Return<sp<IOmx>> OmxStore::getOmx(hidl_string const& omxName) {
    return IOmx::tryGetService(omxName);
}

// Methods from ::android::hidl::base::V1_0::IBase follow.

IOmxStore* HIDL_FETCH_IOmxStore(const char* /* name */) {
    return new OmxStore();
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android
