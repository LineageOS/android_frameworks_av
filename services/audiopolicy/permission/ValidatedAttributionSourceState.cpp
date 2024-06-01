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

#include <media/ValidatedAttributionSourceState.h>

#include <binder/IPCThreadState.h>
#include <error/expected_utils.h>
#include <utils/Log.h>

namespace com::android::media::permission {

using ::android::base::unexpected;

Result<ValidatedAttributionSourceState> ValidatedAttributionSourceState::createFromBinderContext(
        AttributionSourceState attr, const IPermissionProvider& provider) {
    attr.pid = ::android::IPCThreadState::self()->getCallingPid();
    attr.uid = ::android::IPCThreadState::self()->getCallingUid();
    return createFromTrustedUidNoPackage(std::move(attr), provider);
}

Result<ValidatedAttributionSourceState>
ValidatedAttributionSourceState::createFromTrustedUidNoPackage(
        AttributionSourceState attr, const IPermissionProvider& provider) {
    if (attr.packageName.has_value() && attr.packageName->size() != 0) {
        if (VALUE_OR_RETURN(provider.validateUidPackagePair(attr.uid, attr.packageName.value()))) {
            return ValidatedAttributionSourceState{std::move(attr)};
        } else {
            return unexpected{::android::PERMISSION_DENIED};
        }
    } else {
        // For APIs which don't appropriately pass attribution sources or packages, we need
        // to populate the package name with our best guess.
        const auto packageNames = VALUE_OR_RETURN(provider.getPackagesForUid(attr.uid));
        LOG_ALWAYS_FATAL_IF(packageNames.empty());
        attr.packageName = std::move(packageNames[0]);
        return ValidatedAttributionSourceState{std::move(attr)};
    }
}

}  // namespace com::android::media::permission
