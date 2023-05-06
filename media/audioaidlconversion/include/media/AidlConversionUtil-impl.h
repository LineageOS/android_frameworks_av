/*
 * Copyright (C) 2023 The Android Open Source Project
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

// WARNING: This file is intended for multiple inclusion, one time
// with BACKEND_NDK_IMPL defined, one time without it.
// Do not include directly, use 'AidlConversionUtil.h'.
#if (defined(BACKEND_NDK_IMPL) && !defined(AUDIO_AIDL_CONVERSION_AIDL_CONVERSION_UTIL_NDK)) || \
    (!defined(BACKEND_NDK_IMPL) && !defined(AUDIO_AIDL_CONVERSION_AIDL_CONVERSION_UTIL_CPP))
#if defined(BACKEND_NDK_IMPL)
#define AUDIO_AIDL_CONVERSION_AIDL_CONVERSION_UTIL_NDK
#else
#define AUDIO_AIDL_CONVERSION_AIDL_CONVERSION_UTIL_CPP
#endif  // BACKEND_NDK_IMPL

#include <limits>
#include <type_traits>
#include <utility>

#include <android-base/expected.h>
#include <binder/Status.h>

#if defined(BACKEND_NDK_IMPL)
#include <android/binder_auto_utils.h>
#include <android/binder_enums.h>
#include <android/binder_status.h>

namespace aidl {
#else
#include <binder/Enums.h>
#endif  // BACKEND_NDK_IMPL
namespace android {

#if defined(BACKEND_NDK_IMPL)
// This adds `::aidl::android::ConversionResult` for convenience.
// Otherwise, it would be required to write `::android::ConversionResult` everywhere.
template <typename T>
using ConversionResult = ::android::ConversionResult<T>;
#endif  // BACKEND_NDK_IMPL

/**
 * A generic template to safely cast between integral types, respecting limits of the destination
 * type.
 */
template<typename To, typename From>
ConversionResult<To> convertIntegral(From from) {
    // Special handling is required for signed / vs. unsigned comparisons, since otherwise we may
    // have the signed converted to unsigned and produce wrong results.
    if constexpr (std::is_signed_v<From> && !std::is_signed_v<To>) {
        if (from < 0 || from > std::numeric_limits<To>::max()) {
            return ::android::base::unexpected(::android::BAD_VALUE);
        }
    } else if constexpr (std::is_signed_v<To> && !std::is_signed_v<From>) {
        if (from > std::numeric_limits<To>::max()) {
            return ::android::base::unexpected(::android::BAD_VALUE);
        }
    } else /* constexpr */ {
        if (from < std::numeric_limits<To>::min() || from > std::numeric_limits<To>::max()) {
            return ::android::base::unexpected(::android::BAD_VALUE);
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
::android::status_t convertRange(InputIterator start,
                      InputIterator end,
                      OutputIterator out,
                      const Func& itemConversion) {
    for (InputIterator iter = start; iter != end; ++iter, ++out) {
        *out = VALUE_OR_RETURN_STATUS(itemConversion(*iter));
    }
    return ::android::OK;
}

/**
 * A generic template that helps convert containers of convertible types, using iterators.
 * Uses a limit as maximum conversion items.
 */
template<typename InputIterator, typename OutputIterator, typename Func>
::android::status_t convertRangeWithLimit(InputIterator start,
                      InputIterator end,
                      OutputIterator out,
                      const Func& itemConversion,
                      const size_t limit) {
    InputIterator last = end;
    if (end - start > limit) {
        last = start + limit;
    }
    for (InputIterator iter = start; (iter != last); ++iter, ++out) {
        *out = VALUE_OR_RETURN_STATUS(itemConversion(*iter));
    }
    return ::android::OK;
}

/**
 * A generic template that helps convert containers of convertible types without
 * using an intermediate container.
 */
template<typename InputContainer, typename OutputContainer, typename Func>
::android::status_t convertContainer(const InputContainer& input, OutputContainer* output,
        const Func& itemConversion) {
    auto ins = std::inserter(*output, output->begin());
    for (const auto& item : input) {
        *ins = VALUE_OR_RETURN_STATUS(itemConversion(item));
    }
    return ::android::OK;
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

/**
 * A generic template that helps convert containers of convertible types
 * using an item conversion function with an additional parameter.
 */
template<typename OutputContainer, typename InputContainer, typename Func, typename Parameter>
ConversionResult<OutputContainer>
convertContainer(const InputContainer& input, const Func& itemConversion, const Parameter& param) {
    OutputContainer output;
    auto ins = std::inserter(output, output.begin());
    for (const auto& item : input) {
        *ins = VALUE_OR_RETURN(itemConversion(item, param));
    }
    return output;
}

/**
 * A generic template that helps to "zip" two input containers of the same size
 * into a single vector of converted types. The conversion function must
 * thus accept two arguments.
 */
template<typename OutputContainer, typename InputContainer1,
        typename InputContainer2, typename Func>
ConversionResult<OutputContainer>
convertContainers(const InputContainer1& input1, const InputContainer2& input2,
        const Func& itemConversion) {
    auto iter2 = input2.begin();
    OutputContainer output;
    auto ins = std::inserter(output, output.begin());
    for (const auto& item1 : input1) {
        RETURN_IF_ERROR(iter2 != input2.end() ? ::android::OK : ::android::BAD_VALUE);
        *ins = VALUE_OR_RETURN(itemConversion(item1, *iter2++));
    }
    return output;
}

/**
 * A generic template that helps to "unzip" a per-element conversion into
 * a pair of elements into a pair of containers. The conversion function
 * must emit a pair of elements.
 */
template<typename OutputContainer1, typename OutputContainer2,
        typename InputContainer, typename Func>
ConversionResult<std::pair<OutputContainer1, OutputContainer2>>
convertContainerSplit(const InputContainer& input, const Func& itemConversion) {
    OutputContainer1 output1;
    OutputContainer2 output2;
    auto ins1 = std::inserter(output1, output1.begin());
    auto ins2 = std::inserter(output2, output2.begin());
    for (const auto& item : input) {
        auto out_pair = VALUE_OR_RETURN(itemConversion(item));
        *ins1 = out_pair.first;
        *ins2 = out_pair.second;
    }
    return std::make_pair(output1, output2);
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
// Some AIDL enums are specified using bit indices, for example:
//   `AidlEnum { FOO = 0, BAR = 1, BAZ = 2' }`
// while corresponding legacy types universally uses actual bitmasks, for example:
//   `enum legacy_enum_t { LEGACY_FOO = 1 << 0, LEGACY_BAR = 1 << 1, LEGACY_BAZ = 1 << 2 }`
// There is also the third type used to store the resulting mask, which is combined
// from individual bits. In AIDL this is typically an int (`int32_t`), in legacy types this
// is often the enum type itself (although, strictly this is not correct since masks are not
// declared as part of the enum type). The bit index value always has an integer type.
//
// `indexToEnum_index` constructs an instance of the enum from an index,
// for example `AidlEnum::BAR` from `1`.
// `indexToEnum_bitmask` produces a corresponding legacy bitmask enum instance,
// for example, `LEGACY_BAR` (`2`) from `1`.
// `enumToMask_bitmask` simply casts an enum type to a bitmask type.
// `enumToMask_index` creates a mask from an enum type which specifies an index.
//
// All these functions can be plugged into `convertBitmask`. For example, to implement
// conversion from `AidlEnum` to `legacy_enum_t`, with a mask stored in `int32_t`,
// the following call needs to be made:
//   convertBitmask<legacy_enum_t /*DestMask*/, int32_t /*SrcMask*/,
//                  legacy_enum_t /*DestEnum*/, AidlEnum /*SrcEnum*/>(
//     maskField /*int32_t*/, aidl2legacy_AidlEnum_legacy_enum_t /*enumConversion*/,
//     indexToEnum_index<AidlEnum> /*srcIndexToEnum*/,
//     enumToMask_bitmask<legacy_enum_t, legacy_enum_t> /*destEnumToMask*/)
//
// The only extra function needed is for mapping between corresponding enum values
// of the AidlEnum and the legacy_enum_t. Note that the mapping is between values
// of enums, for example, `AidlEnum::BAZ` maps to `LEGACY_BAZ` and vice versa.

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
//   value of the respective field, or ::android::BAD_VALUE if the union is not set to the requested
//   field.
// UNION_SET(obj, fieldname, value) sets the requested field to the given value.

template<typename T, typename T::Tag tag>
using UnionFieldType = std::decay_t<decltype(std::declval<T>().template get<tag>())>;

template<typename T, typename T::Tag tag>
ConversionResult<UnionFieldType<T, tag>> unionGetField(const T& u) {
    if (u.getTag() != tag) {
        return ::android::base::unexpected(::android::BAD_VALUE);
    }
    return u.template get<tag>();
}

#define UNION_GET(u, field) \
    unionGetField<std::decay_t<decltype(u)>, std::decay_t<decltype(u)>::Tag::field>(u)

#define UNION_SET(u, field, value) \
    (u).set<std::decay_t<decltype(u)>::Tag::field>(value)

#define UNION_MAKE(u, field, value) u::make<u::Tag::field>(value)

namespace aidl_utils {

/**
 * Return true if the value is valid for the AIDL enumeration.
 */
template <typename T>
bool isValidEnum(T value) {
#if defined(BACKEND_NDK_IMPL)
    constexpr ndk::enum_range<T> er{};
#else
    constexpr ::android::enum_range<T> er{};
#endif
    return std::find(er.begin(), er.end(), value) != er.end();
}

// T is a "container" of enum binder types with a toString().
template <typename T>
std::string enumsToString(const T& t) {
    std::string s;
    for (const auto item : t) {
        if (s.empty()) {
            s = toString(item);
        } else {
            s.append("|").append(toString(item));
        }
    }
    return s;
}

/**
 * Return the equivalent Android ::android::status_t from a binder exception code.
 *
 * Generally one should use statusTFromBinderStatus() instead.
 *
 * Exception codes can be generated from a remote Java service exception, translate
 * them for use on the Native side.
 *
 * Note: for EX_TRANSACTION_FAILED and EX_SERVICE_SPECIFIC a more detailed error code
 * can be found from transactionError() or serviceSpecificErrorCode().
 */
static inline ::android::status_t statusTFromExceptionCode(int32_t exceptionCode) {
    using namespace ::android::binder;
    switch (exceptionCode) {
        case Status::EX_NONE:
            return ::android::OK;
        case Status::EX_SECURITY:  // Java SecurityException, rethrows locally in Java
            return ::android::PERMISSION_DENIED;
        case Status::EX_BAD_PARCELABLE:  // Java BadParcelableException, rethrows in Java
        case Status::EX_ILLEGAL_ARGUMENT:  // Java IllegalArgumentException, rethrows in Java
        case Status::EX_NULL_POINTER:  // Java NullPointerException, rethrows in Java
            return ::android::BAD_VALUE;
        case Status::EX_ILLEGAL_STATE:  // Java IllegalStateException, rethrows in Java
        case Status::EX_UNSUPPORTED_OPERATION:  // Java UnsupportedOperationException, rethrows
            return ::android::INVALID_OPERATION;
        case Status::EX_HAS_REPLY_HEADER: // Native strictmode violation
        case Status::EX_PARCELABLE:  // Java bootclass loader (not standard exception), rethrows
        case Status::EX_NETWORK_MAIN_THREAD:  // Java NetworkOnMainThreadException, rethrows
        case Status::EX_TRANSACTION_FAILED: // Native - see error code
        case Status::EX_SERVICE_SPECIFIC:   // Java ServiceSpecificException,
                                            // rethrows in Java with integer error code
            return ::android::UNKNOWN_ERROR;
    }
    return ::android::UNKNOWN_ERROR;
}

/**
 * Return the equivalent Android ::android::status_t from a binder status.
 *
 * Used to handle errors from a AIDL method declaration
 *
 * [oneway] void method(type0 param0, ...)
 *
 * or the following (where return_type is not a status_t)
 *
 * return_type method(type0 param0, ...)
 */
static inline ::android::status_t statusTFromBinderStatus(const ::android::binder::Status &status) {
    return status.isOk() ? ::android::OK // check ::android::OK,
        : status.serviceSpecificErrorCode() // service-side error, not standard Java exception
                                            // (fromServiceSpecificError)
        ?: status.transactionError() // a native binder transaction error (fromStatusT)
        ?: statusTFromExceptionCode(status.exceptionCode()); // a service-side error with a
                                                    // standard Java exception (fromExceptionCode)
}

#if defined(BACKEND_NDK_IMPL)
static inline ::android::status_t statusTFromBinderStatus(const ::ndk::ScopedAStatus &status) {
    // What we want to do is to 'return statusTFromBinderStatus(status.get()->get())'
    // However, since the definition of AStatus is not exposed, we have to do the same
    // via methods of ScopedAStatus:
    return status.isOk() ? ::android::OK // check ::android::OK,
        : status.getServiceSpecificError() // service-side error, not standard Java exception
                                           // (fromServiceSpecificError)
        ?: status.getStatus() // a native binder transaction error (fromStatusT)
        ?: statusTFromExceptionCode(status.getExceptionCode()); // a service-side error with a
                                                     // standard Java exception (fromExceptionCode)
}

static inline ::android::status_t statusTFromBinderStatusT(binder_status_t status) {
    return statusTFromBinderStatus(::ndk::ScopedAStatus::fromStatus(status));
}
#endif

/**
 * Return a binder::Status from native service status.
 *
 * This is used for methods not returning an explicit status_t,
 * where Java callers expect an exception, not an integer return value.
 */
static inline ::android::binder::Status binderStatusFromStatusT(
        ::android::status_t status, const char *optionalMessage = nullptr) {
    const char * const emptyIfNull = optionalMessage == nullptr ? "" : optionalMessage;
    // From binder::Status instructions:
    //  Prefer a generic exception code when possible, then a service specific
    //  code, and finally a ::android::status_t for low level failures or legacy support.
    //  Exception codes and service specific errors map to nicer exceptions for
    //  Java clients.

    using namespace ::android::binder;
    switch (status) {
        case ::android::OK:
            return Status::ok();
        case ::android::PERMISSION_DENIED: // throw SecurityException on Java side
            return Status::fromExceptionCode(Status::EX_SECURITY, emptyIfNull);
        case ::android::BAD_VALUE: // throw IllegalArgumentException on Java side
            return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT, emptyIfNull);
        case ::android::INVALID_OPERATION: // throw IllegalStateException on Java side
            return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE, emptyIfNull);
    }

    // A service specific error will not show on status.transactionError() so
    // be sure to use statusTFromBinderStatus() for reliable error handling.

    // throw a ServiceSpecificException.
    return Status::fromServiceSpecificError(status, emptyIfNull);
}

} // namespace aidl_utils

}  // namespace android

#if defined(BACKEND_NDK_IMPL)
}  // namespace aidl
#endif

// (defined(BACKEND_NDK_IMPL) && !defined(AUDIO_AIDL_CONVERSION_AIDL_CONVERSION_UTIL_NDK)) || \
// (!defined(BACKEND_NDK_IMPL) && !defined(AUDIO_AIDL_CONVERSION_AIDL_CONVERSION_UTIL_CPP))
#endif
