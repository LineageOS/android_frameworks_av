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

#include <string>
#include <vector>

namespace android::mediametrics::stringutils {

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

} // namespace android::mediametrics::stringutils
