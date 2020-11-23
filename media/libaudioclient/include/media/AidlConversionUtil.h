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

#include <limits>
#include <type_traits>
#include <utility>

#include <android-base/expected.h>

namespace android {

template <typename T>
using ConversionResult = base::expected<T, status_t>;

// Convenience macros for working with ConversionResult, useful for writing converted for aggregate
// types.

#define VALUE_OR_RETURN(result)                                \
    ({                                                         \
        auto _tmp = (result);                                  \
        if (!_tmp.ok()) return base::unexpected(_tmp.error()); \
        std::move(_tmp.value());                               \
    })

#define RETURN_IF_ERROR(result) \
    if (status_t _tmp = (result); _tmp != OK) return base::unexpected(_tmp);

#define VALUE_OR_RETURN_STATUS(x)           \
    ({                                      \
       auto _tmp = (x);                     \
       if (!_tmp.ok()) return _tmp.error(); \
       std::move(_tmp.value());             \
     })

/**
 * A generic template to safely cast between integral types, respecting limits of the destination
 * type.
 */
template<typename To, typename From>
ConversionResult<To> convertIntegral(From from) {
    // Special handling is required for signed / vs. unsigned comparisons, since otherwise we may
    // have the signed converted to unsigned and produce wrong results.
    if (std::is_signed_v<From> && !std::is_signed_v<To>) {
        if (from < 0 || from > std::numeric_limits<To>::max()) {
            return base::unexpected(BAD_VALUE);
        }
    } else if (std::is_signed_v<To> && !std::is_signed_v<From>) {
        if (from > std::numeric_limits<To>::max()) {
            return base::unexpected(BAD_VALUE);
        }
    } else {
        if (from < std::numeric_limits<To>::min() || from > std::numeric_limits<To>::max()) {
            return base::unexpected(BAD_VALUE);
        }
    }
    return static_cast<To>(from);
}

/**
 * A generic template to safely cast between types, that are intended to be the same size, but
 * interpreted differently.
 */
template<typename To, typename From>
ConversionResult<To> convertReinterpret(From from) {
    static_assert(sizeof(From) == sizeof(To));
    return static_cast<To>(from);
}

/**
 * A generic template that helps convert containers of convertible types.
 */
template<typename OutputContainer, typename InputContainer, typename Func>
ConversionResult<OutputContainer>
convertContainer(const InputContainer& input, const Func& itemConversion) {
    OutputContainer output;
    auto ins = std::inserter(output, output.begin());
    for (const auto& item : input) {
        *ins = VALUE_OR_RETURN(itemConversion(item));
    }
    return output;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Utilities for working with AIDL unions.
// UNION_GET(obj, fieldname) returns a ConversionResult<T> containing either the strongly-typed
//   value of the respective field, or BAD_VALUE if the union is not set to the requested field.
// UNION_SET(obj, fieldname, value) sets the requested field to the given value.

template<typename T, typename T::Tag tag>
using UnionFieldType = std::decay_t<decltype(std::declval<T>().template get<tag>())>;

template<typename T, typename T::Tag tag>
ConversionResult<UnionFieldType<T, tag>> unionGetField(const T& u) {
    if (u.getTag() != tag) {
        return base::unexpected(BAD_VALUE);
    }
    return u.template get<tag>();
}

#define UNION_GET(u, field) \
    unionGetField<std::decay_t<decltype(u)>, std::decay_t<decltype(u)>::Tag::field>(u)

#define UNION_SET(u, field, value) \
    (u).set<std::decay_t<decltype(u)>::Tag::field>(value)

}  // namespace android
