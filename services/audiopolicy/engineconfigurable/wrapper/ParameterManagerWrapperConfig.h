/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <stdint.h>
#include <string>
#include <vector>
#include <utils/Errors.h>

struct _xmlNode;
struct _xmlDoc;

namespace android {
namespace audio_policy {
namespace wrapper_config {

/** Default path of audio policy usages configuration file. */
constexpr char DEFAULT_PATH[] = "/vendor/etc/policy_wrapper_configuration.xml";

/** Directories where the effect libraries will be search for. */
constexpr const char* POLICY_USAGE_LIBRARY_PATH[] = {"/odm/etc/", "/vendor/etc/", "/system/etc/"};

using ValuePair = std::pair<uint32_t, std::string>;
using ValuePairs = std::vector<ValuePair>;

struct CriterionType
{
    std::string name;
    bool isInclusive;
    ValuePairs valuePairs;
};

using CriterionTypes = std::vector<CriterionType>;

struct Criterion
{
    std::string name;
    std::string typeName;
    std::string defaultLiteralValue;
};

using Criteria = std::vector<Criterion>;

struct Config {
    float version;
    Criteria criteria;
    CriterionTypes criterionTypes;
};

namespace detail
{
struct ValueTraits
{
    static const char *const tag;
    static const char *const collectionTag;

    struct Attributes
    {
        static const char literal[];
        static const char numerical[];
    };

    typedef ValuePair Element;
    typedef ValuePair *PtrElement;
    typedef ValuePairs Collection;

    static android::status_t deserialize(_xmlDoc *doc, const _xmlNode *root,
                                         Collection &collection);
};

struct CriterionTypeTraits
{
    static const char *const tag;
    static const char *const collectionTag;

    struct Attributes
    {
        static const char name[];
        static const char type[];
    };

    typedef CriterionType Element;
    typedef CriterionType *PtrElement;
    typedef CriterionTypes Collection;

    static android::status_t deserialize(_xmlDoc *doc, const _xmlNode *root,
                                         Collection &collection);
};

struct CriterionTraits
{
    static const char *const tag;
    static const char *const collectionTag;

    struct Attributes
    {
        static const char name[];
        static const char type[];
        static const char defaultVal[];
    };

    typedef Criterion Element;
    typedef Criterion *PtrElement;
    typedef Criteria Collection;

    static android::status_t deserialize(_xmlDoc *doc, const _xmlNode *root,
                                         Collection &collection);
};
} // namespace detail

/** Result of `parse(const char*)` */
struct ParsingResult {
    /** Parsed config, nullptr if the xml lib could not load the file */
    std::unique_ptr<Config> parsedConfig;
    size_t nbSkippedElement; //< Number of skipped invalid product strategies
};

/** Parses the provided audio policy usage configuration.
 * @return audio policy usage @see Config
 */
ParsingResult parse(const char* path = DEFAULT_PATH);

} // namespace wrapper_config
} // namespace audio_policy
} // android
