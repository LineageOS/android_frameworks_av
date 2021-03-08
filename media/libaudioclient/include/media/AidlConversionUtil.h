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
#include <binder/Status.h>

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

#define VALUE_OR_FATAL(result)                                        \
    ({                                                                \
       auto _tmp = (result);                                          \
       LOG_ALWAYS_FATAL_IF(!_tmp.ok(),                                \
                           "Function: %s Line: %d Failed result (%d)",\
                           __FUNCTION__, __LINE__, _tmp.error());     \
       std::move(_tmp.value());                                       \
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
 * A generic template that helps convert containers of convertible types, using iterators.
 */
template<typename InputIterator, typename OutputIterator, typename Func>
status_t convertRange(InputIterator start,
                      InputIterator end,
                      OutputIterator out,
                      const Func& itemConversion) {
    for (InputIterator iter = start; iter != end; ++iter, ++out) {
        *out = VALUE_OR_RETURN_STATUS(itemConversion(*iter));
    }
    return OK;
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
// The code below establishes:
// IntegralTypeOf<T>, which works for either integral types (in which case it evaluates to T), or
// enum types (in which case it evaluates to std::underlying_type_T<T>).

template<typename T, typename = std::enable_if_t<std::is_integral_v<T> || std::is_enum_v<T>>>
struct IntegralTypeOfStruct {
    using Type = T;
};

template<typename T>
struct IntegralTypeOfStruct<T, std::enable_if_t<std::is_enum_v<T>>> {
    using Type = std::underlying_type_t<T>;
};

template<typename T>
using IntegralTypeOf = typename IntegralTypeOfStruct<T>::Type;

////////////////////////////////////////////////////////////////////////////////////////////////////
// Utilities for handling bitmasks.

template<typename Enum>
Enum indexToEnum_index(int index) {
    static_assert(std::is_enum_v<Enum> || std::is_integral_v<Enum>);
    return static_cast<Enum>(index);
}

template<typename Enum>
Enum indexToEnum_bitmask(int index) {
    static_assert(std::is_enum_v<Enum> || std::is_integral_v<Enum>);
    return static_cast<Enum>(1 << index);
}

template<typename Mask, typename Enum>
Mask enumToMask_bitmask(Enum e) {
    static_assert(std::is_enum_v<Enum> || std::is_integral_v<Enum>);
    static_assert(std::is_enum_v<Mask> || std::is_integral_v<Mask>);
    return static_cast<Mask>(e);
}

template<typename Mask, typename Enum>
Mask enumToMask_index(Enum e) {
    static_assert(std::is_enum_v<Enum> || std::is_integral_v<Enum>);
    static_assert(std::is_enum_v<Mask> || std::is_integral_v<Mask>);
    return static_cast<Mask>(static_cast<std::make_unsigned_t<IntegralTypeOf<Mask>>>(1)
            << static_cast<int>(e));
}

template<typename DestMask, typename SrcMask, typename DestEnum, typename SrcEnum>
ConversionResult<DestMask> convertBitmask(
        SrcMask src, const std::function<ConversionResult<DestEnum>(SrcEnum)>& enumConversion,
        const std::function<SrcEnum(int)>& srcIndexToEnum,
        const std::function<DestMask(DestEnum)>& destEnumToMask) {
    using UnsignedDestMask = std::make_unsigned_t<IntegralTypeOf<DestMask>>;
    using UnsignedSrcMask = std::make_unsigned_t<IntegralTypeOf<SrcMask>>;

    UnsignedDestMask dest = static_cast<UnsignedDestMask>(0);
    UnsignedSrcMask usrc = static_cast<UnsignedSrcMask>(src);

    int srcBitIndex = 0;
    while (usrc != 0) {
        if (usrc & 1) {
            SrcEnum srcEnum = srcIndexToEnum(srcBitIndex);
            DestEnum destEnum = VALUE_OR_RETURN(enumConversion(srcEnum));
            DestMask destMask = destEnumToMask(destEnum);
            dest |= destMask;
        }
        ++srcBitIndex;
        usrc >>= 1;
    }
    return static_cast<DestMask>(dest);
}

template<typename Mask, typename Enum>
bool bitmaskIsSet(Mask mask, Enum index) {
    return (mask & enumToMask_index<Mask, Enum>(index)) != 0;
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

namespace aidl_utils {

/**
 * Return the equivalent Android status_t from a binder exception code.
 *
 * Generally one should use statusTFromBinderStatus() instead.
 *
 * Exception codes can be generated from a remote Java service exception, translate
 * them for use on the Native side.
 *
 * Note: for EX_TRANSACTION_FAILED and EX_SERVICE_SPECIFIC a more detailed error code
 * can be found from transactionError() or serviceSpecificErrorCode().
 */
static inline status_t statusTFromExceptionCode(int32_t exceptionCode) {
    using namespace ::android::binder;
    switch (exceptionCode) {
        case Status::EX_NONE:
            return OK;
        case Status::EX_SECURITY: // Java SecurityException, rethrows locally in Java
            return PERMISSION_DENIED;
        case Status::EX_BAD_PARCELABLE: // Java BadParcelableException, rethrows in Java
        case Status::EX_ILLEGAL_ARGUMENT: // Java IllegalArgumentException, rethrows in Java
        case Status::EX_NULL_POINTER: // Java NullPointerException, rethrows in Java
            return BAD_VALUE;
        case Status::EX_ILLEGAL_STATE: // Java IllegalStateException, rethrows in Java
        case Status::EX_UNSUPPORTED_OPERATION: // Java UnsupportedOperationException, rethrows
            return INVALID_OPERATION;
        case Status::EX_HAS_REPLY_HEADER: // Native strictmode violation
        case Status::EX_PARCELABLE: // Java bootclass loader (not standard exception), rethrows
        case Status::EX_NETWORK_MAIN_THREAD: // Java NetworkOnMainThreadException, rethrows
        case Status::EX_TRANSACTION_FAILED: // Native - see error code
        case Status::EX_SERVICE_SPECIFIC:  // Java ServiceSpecificException,
                                           // rethrows in Java with integer error code
            return UNKNOWN_ERROR;
    }
    return UNKNOWN_ERROR;
}

/**
 * Return the equivalent Android status_t from a binder status.
 *
 * Used to handle errors from a AIDL method declaration
 *
 * [oneway] void method(type0 param0, ...)
 *
 * or the following (where return_type is not a status_t)
 *
 * return_type method(type0 param0, ...)
 */
static inline status_t statusTFromBinderStatus(const ::android::binder::Status &status) {
    return status.isOk() ? OK // check OK,
        : status.serviceSpecificErrorCode() // service-side error, not standard Java exception
                                            // (fromServiceSpecificError)
        ?: status.transactionError() // a native binder transaction error (fromStatusT)
        ?: statusTFromExceptionCode(status.exceptionCode()); // a service-side error with a
                                                    // standard Java exception (fromExceptionCode)
}

/**
 * Return a binder::Status from native service status.
 *
 * This is used for methods not returning an explicit status_t,
 * where Java callers expect an exception, not an integer return value.
 */
static inline ::android::binder::Status binderStatusFromStatusT(
        status_t status, const char *optionalMessage = nullptr) {
    const char * const emptyIfNull = optionalMessage == nullptr ? "" : optionalMessage;
    // From binder::Status instructions:
    //  Prefer a generic exception code when possible, then a service specific
    //  code, and finally a status_t for low level failures or legacy support.
    //  Exception codes and service specific errors map to nicer exceptions for
    //  Java clients.

    using namespace ::android::binder;
    switch (status) {
        case OK:
            return Status::ok();
        case PERMISSION_DENIED: // throw SecurityException on Java side
            return Status::fromExceptionCode(Status::EX_SECURITY, emptyIfNull);
        case BAD_VALUE: // throw IllegalArgumentException on Java side
            return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT, emptyIfNull);
        case INVALID_OPERATION: // throw IllegalStateException on Java side
            return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE, emptyIfNull);
    }

    // A service specific error will not show on status.transactionError() so
    // be sure to use statusTFromBinderStatus() for reliable error handling.

    // throw a ServiceSpecificException.
    return Status::fromServiceSpecificError(status, emptyIfNull);
}


} // namespace aidl_utils

}  // namespace android
