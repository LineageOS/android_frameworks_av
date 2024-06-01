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

#include <android/content/AttributionSourceState.h>
#include <error/Result.h>

#include "IPermissionProvider.h"

namespace com::android::media::permission {

using ::android::content::AttributionSourceState;
using ::android::error::Result;

class ValidatedAttributionSourceState {
  public:
    /**
     * Validates an attribution source from within the context of a binder transaction.
     * Overwrites the uid/pid and validates the packageName
     */
    static Result<ValidatedAttributionSourceState> createFromBinderContext(
            AttributionSourceState attr, const IPermissionProvider& provider);

    /**
     * Creates a ValidatedAttributionSourceState in cases where the source is passed from a
     * trusted entity which already performed validation.
     */
    static ValidatedAttributionSourceState createFromTrustedSource(AttributionSourceState attr) {
        return ValidatedAttributionSourceState(attr);
    }

    /**
     * Create a ValidatedAttribubtionSourceState in cases where the uid/pid is trusted, but the
     * packages have not been validated. Proper use of the previous two methods should avoid the
     * necessity of this, but it is useful for migration purposes as well as testing this class.
     */
    static Result<ValidatedAttributionSourceState> createFromTrustedUidNoPackage(
            AttributionSourceState attr, const IPermissionProvider& provider);

    operator AttributionSourceState() const { return state_; }

    operator const AttributionSourceState&() const { return state_; }

    AttributionSourceState unwrapInto() && { return std::move(state_); }

    bool operator==(const ValidatedAttributionSourceState& other) const {
        return operator==(other.state_);
    }

    bool operator==(const AttributionSourceState& other) const { return state_ == other; }

  private:
    ValidatedAttributionSourceState(AttributionSourceState attr) : state_(attr) {}

    AttributionSourceState state_;
};
}  // namespace com::android::media::permission
