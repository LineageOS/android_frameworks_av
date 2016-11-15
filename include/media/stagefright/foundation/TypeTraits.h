/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef STAGEFRIGHT_FOUNDATION_TYPE_TRAITS_H_
#define STAGEFRIGHT_FOUNDATION_TYPE_TRAITS_H_

#include <type_traits>

namespace android {

/**
 * std::is_signed, is_unsigned and is_integral does not consider enums even though the standard
 * considers them integral. Create modified versions of these here. Also create a wrapper around
 * std::underlying_type that does not require checking if the type is an enum.
 */

/**
 * Type support utility class to check if a type is an integral type or an enum.
 */
template<typename T>
struct is_integral_or_enum
    : std::integral_constant<bool, std::is_integral<T>::value || std::is_enum<T>::value> { };

/**
 * Type support utility class to get the underlying std::is_integral supported type for a type.
 * This returns the underlying type for enums, and the same type for types covered by
 * std::is_integral.
 *
 * This is also used as a conditional to return an alternate type if the template param is not
 * an integral or enum type (as in underlying_integral_type<T, TypeIfNotEnumOrIntegral>::type).
 */
template<typename T,
        typename U=typename std::enable_if<is_integral_or_enum<T>::value>::type,
        bool=std::is_enum<T>::value,
        bool=std::is_integral<T>::value>
struct underlying_integral_type {
    static_assert(!std::is_enum<T>::value, "T should not be enum here");
    static_assert(!std::is_integral<T>::value, "T should not be integral here");
    typedef U type;
};

/** Specialization for enums. */
template<typename T, typename U>
struct underlying_integral_type<T, U, true, false> {
    static_assert(std::is_enum<T>::value, "T should be enum here");
    static_assert(!std::is_integral<T>::value, "T should not be integral here");
    typedef typename std::underlying_type<T>::type type;
};

/** Specialization for non-enum std-integral types. */
template<typename T, typename U>
struct underlying_integral_type<T, U, false, true> {
    static_assert(!std::is_enum<T>::value, "T should not be enum here");
    static_assert(std::is_integral<T>::value, "T should be integral here");
    typedef T type;
};

/**
 * Type support utility class to check if the underlying integral type is signed.
 */
template<typename T>
struct is_signed_integral
    : std::integral_constant<bool, std::is_signed<
            typename underlying_integral_type<T, unsigned>::type>::value> { };

/**
 * Type support utility class to check if the underlying integral type is unsigned.
 */
template<typename T>
struct is_unsigned_integral
    : std::integral_constant<bool, std::is_unsigned<
            typename underlying_integral_type<T, signed>::type>::value> {
};

}  // namespace android

#endif  // STAGEFRIGHT_FOUNDATION_TYPE_TRAITS_H_

