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

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace android::mediametrics::stringutils {

// Define a way of printing a vector - this
// is used for proto repeated arguments.
template <typename T>
inline std::ostream & operator<< (std::ostream& s,
                           std::vector<T> const& v) {
    s << "{ ";
    for (const auto& e : v) {
        s << e << " ";
    }
    s << "}";
    return s;
}

/**
 * fieldPrint is a helper method that logs to a stringstream a sequence of
 * field names (in a fixed size array) together with a variable number of arg parameters.
 *
 * stringstream << field[0] << ":" << arg0 << " ";
 * stringstream << field[1] << ":" << arg1 << " ";
 * ...
 * stringstream << field[N-1] << ":" << arg{N-1} << " ";
 *
 * The number of fields must exactly match the (variable) arguments.
 *
 * Example:
 *
 * const char * const fields[] = { "integer" };
 * std::stringstream ss;
 * fieldPrint(ss, fields, int(10));
 */
template <size_t N, typename... Targs>
void fieldPrint(std::stringstream& ss, const char * const (& fields)[N], Targs... args) {
    static_assert(N == sizeof...(args));          // guarantee #fields == #args
    auto fptr = fields;                           // get a pointer to the base of fields array
    ((ss << *fptr++ << ":" << args << " "), ...); // (fold expression), send to stringstream.
}

/**
 * Return string tokens from iterator, separated by spaces and reserved chars.
 */
std::string tokenizer(std::string::const_iterator& it,
        const std::string::const_iterator& end, const char *reserved);

/**
 * Splits flags string based on delimeters (or, whitespace which is removed).
 */
std::vector<std::string> split(const std::string& flags, const char *delim);

/**
 * Parse the devices string and return a vector of device address pairs.
 *
 * A failure to parse returns early with the contents that were able to be parsed.
 */
std::vector<std::pair<std::string, std::string>> getDeviceAddressPairs(const std::string &devices);

/**
 * Replaces targetChars with replaceChar in string, returns number of chars replaced.
 */
size_t replace(std::string &str, const char *targetChars, const char replaceChar);

// RFC 1421, 2045, 2152, 4648(4), 4880
inline constexpr char Base64Table[] =
    // 0000000000111111111122222222223333333333444444444455555555556666
    // 0123456789012345678901234567890123456789012345678901234567890123
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// RFC 4648(5) URL-safe Base64 encoding
inline constexpr char Base64UrlTable[] =
    // 0000000000111111111122222222223333333333444444444455555555556666
    // 0123456789012345678901234567890123456789012345678901234567890123
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// An constexpr struct that transposes/inverts a string conversion table.
struct Transpose {
    // constexpr bug, returning char still means -1 == 0xff, so we use unsigned char.
    using base_char_t = unsigned char;
    static inline constexpr base_char_t INVALID_CHAR = 0xff;

    template <size_t N>
    explicit constexpr Transpose(const char(&string)[N]) {
        for (auto& e : mMap) {
            e = INVALID_CHAR;
        }
        for (size_t i = 0; string[i] != 0; ++i) {
            mMap[static_cast<size_t>(string[i]) & 0xff] = i;
        }
    }

    constexpr base_char_t operator[] (size_t n) const {
        return n < sizeof(mMap) ? mMap[n] : INVALID_CHAR;
    }

    constexpr const auto& get() const {
        return mMap;
    }

private:
    base_char_t mMap[256];  // construct an inverse character mapping.
};

// This table is used to convert an input char to a 6 bit (0 - 63) value.
// If the input char is not in the Base64Url charset, Transpose::INVALID_CHAR is returned.
inline constexpr Transpose InverseBase64UrlTable(Base64UrlTable);

// Returns true if s consists of only valid Base64Url characters (no padding chars allowed).
inline constexpr bool isBase64Url(const char *s) {
    for (; *s != 0; ++s) {
        if (InverseBase64UrlTable[(unsigned char)*s] == Transpose::INVALID_CHAR) return false;
    }
    return true;
}

// Returns true if s is a valid log session id: exactly 16 Base64Url characters.
//
// logSessionIds are a web-safe Base64Url RFC 4648(5) encoded string of 16 characters
// (representing 96 unique bits 16 * 6).
//
// The string version is considered the reference representation.  However, for ease of
// manipulation and comparison, it may be converted to an int128.
//
// For int128 conversion, some common interpretations exist - for example
// (1) the 16 Base64 chars can be converted 6 bits per char to a 96 bit value
// (with the most significant 32 bits as zero) as there are only 12 unique bytes worth of data
// or (2) the 16 Base64 chars can be used to directly fill the 128 bits of int128 assuming
// the 16 chars are 16 bytes, filling the layout of the int128 variable.
// Endianness of the data may follow whatever is convenient in the interpretation as long
// as it is applied to each such conversion of string to int128 identically.
//
inline constexpr bool isLogSessionId(const char *s) {
    return std::char_traits<std::decay_t<decltype(*s)>>::length(s) == 16 && isBase64Url(s);
}

// Returns either the original string or an empty string if isLogSessionId check fails.
inline std::string sanitizeLogSessionId(const std::string& string) {
    if (isLogSessionId(string.c_str())) return string;
    return {}; // if not a logSessionId, return an empty string.
}

inline std::string bytesToString(const std::vector<uint8_t>& bytes, size_t maxSize = SIZE_MAX) {
    if (bytes.size() == 0) {
        return "{}";
    }
    std::stringstream ss;
    ss << "{";
    ss << std::hex << std::setfill('0');
    maxSize = std::min(maxSize, bytes.size());
    for (size_t i = 0; i < maxSize; ++i) {
        ss << " " << std::setw(2) << (int)bytes[i];
    }
    if (maxSize != bytes.size()) {
        ss << " ... }";
    } else {
        ss << " }";
    }
    return ss.str();
}

/**
 * Returns true if the string is non-null, not empty, and contains only digits.
 */
inline constexpr bool isNumeric(const char *s)
{
    if (s == nullptr || *s == 0) return false;
    do {
        if (!isdigit(*s)) return false;
    } while (*++s != 0);
    return true;  // all digits
}

/**
 * Extracts out the prefix from the key, returning a pair of prefix, suffix.
 *
 * Usually the key is something like:
 * Prefix.(ID)
 *   where ID is an integer,
 *               or "error" if the id was not returned because of failure,
 *               or "status" if general status.
 *
 * Example: audio.track.10     -> prefix = audio.track, suffix = 10
 *          audio.track.error  -> prefix = audio.track, suffix = error
 *          audio.track.status -> prefix = audio.track, suffix = status
 *          audio.mute         -> prefix = audio.mute,  suffix = ""
 */
inline std::pair<std::string /* prefix */,
                 std::string /* suffix */> splitPrefixKey(const std::string &key)
{
    const size_t split = key.rfind('.');
    const char* suffix = key.c_str() + split + 1;
    if (*suffix && (!strcmp(suffix, "error") || !strcmp(suffix, "status") || isNumeric(suffix))) {
        return { key.substr(0, split), suffix };
    }
    return { key, "" };
}

std::pair<std::string /* external statsd */, std::string /* internal */>
parseOutputDevicePairs(const std::string& outputDevicePairs);

std::pair<std::string /* external statsd */, std::string /* internal */>
parseInputDevicePairs(const std::string& inputDevicePairs);

inline bool hasBluetoothOutputDevice(std::string_view devices) {
    return devices.find("AUDIO_DEVICE_OUT_BLUETOOTH") != std::string::npos;
}

} // namespace android::mediametrics::stringutils
