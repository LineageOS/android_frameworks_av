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

#define LOG_TAG "APM::AudioPolicyEngine/PFWWrapperConfig"
#define LOG_NDEBUG 0

#include "ParameterManagerWrapperConfig.h"

#include <media/convert.h>
#include <utils/Log.h>
#include <libxml/parser.h>
#include <libxml/xinclude.h>
#include <string>
#include <vector>
#include <sstream>
#include <istream>


namespace android {

using utilities::convertTo;

namespace audio_policy {
namespace wrapper_config {
namespace detail {

std::string getXmlAttribute(const xmlNode *cur, const char *attribute)
{
    xmlChar *xmlValue = xmlGetProp(cur, (const xmlChar *)attribute);
    if (xmlValue == NULL) {
        return "";
    }
    std::string value((const char *)xmlValue);
    xmlFree(xmlValue);
    return value;
}

template <class Trait>
static status_t deserializeCollection(_xmlDoc *doc, const _xmlNode *cur,
                                      typename Trait::Collection &collection,
                                      size_t &nbSkippedElement)
{
    const xmlNode *root = cur->xmlChildrenNode;
    while (root != NULL) {
        if (xmlStrcmp(root->name, (const xmlChar *)Trait::collectionTag) &&
            xmlStrcmp(root->name, (const xmlChar *)Trait::tag)) {
            root = root->next;
            continue;
        }
        const xmlNode *child = root;
        if (!xmlStrcmp(child->name, (const xmlChar *)Trait::collectionTag)) {
            child = child->xmlChildrenNode;
        }
        while (child != NULL) {
            if (!xmlStrcmp(child->name, (const xmlChar *)Trait::tag)) {
                status_t status = Trait::deserialize(doc, child, collection);
                if (status == NO_ERROR) {
                    nbSkippedElement += 1;
                }
            }
            child = child->next;
        }
        if (!xmlStrcmp(root->name, (const xmlChar *)Trait::tag)) {
            return NO_ERROR;
        }
        root = root->next;
    }
    return NO_ERROR;
}

const char *const ValueTraits::tag = "value";
const char *const ValueTraits::collectionTag = "values";

const char ValueTraits::Attributes::literal[] = "literal";
const char ValueTraits::Attributes::numerical[] = "numerical";

status_t ValueTraits::deserialize(_xmlDoc */*doc*/, const _xmlNode *child, Collection &values)
{
    std::string literal = getXmlAttribute(child, Attributes::literal);
    if (literal.empty()) {
        ALOGE("%s: No attribute %s found", __FUNCTION__, Attributes::literal);
        return BAD_VALUE;
    }
    uint32_t numerical = 0;
    std::string numericalTag = getXmlAttribute(child, Attributes::numerical);
    if (numericalTag.empty()) {
        ALOGE("%s: No attribute %s found", __FUNCTION__, Attributes::literal);
        return BAD_VALUE;
    }
    if (!convertTo(numericalTag, numerical)) {
        ALOGE("%s: : Invalid value(%s)", __FUNCTION__, numericalTag.c_str());
        return BAD_VALUE;
    }
    values.push_back({numerical, literal});
    return NO_ERROR;
}

const char *const CriterionTypeTraits::tag = "criterion_type";
const char *const CriterionTypeTraits::collectionTag = "criterion_types";

const char CriterionTypeTraits::Attributes::name[] = "name";
const char CriterionTypeTraits::Attributes::type[] = "type";

status_t CriterionTypeTraits::deserialize(_xmlDoc *doc, const _xmlNode *child,
                                          Collection &criterionTypes)
{
    std::string name = getXmlAttribute(child, Attributes::name);
    if (name.empty()) {
        ALOGE("%s: No attribute %s found", __FUNCTION__, Attributes::name);
        return BAD_VALUE;
    }
    ALOGV("%s: %s %s = %s", __FUNCTION__, tag, Attributes::name, name.c_str());

    std::string type = getXmlAttribute(child, Attributes::type);
    if (type.empty()) {
        ALOGE("%s: No attribute %s found", __FUNCTION__, Attributes::type);
        return BAD_VALUE;
    }
    ALOGV("%s: %s %s = %s", __FUNCTION__, tag, Attributes::type, type.c_str());
    bool isInclusive(type == "inclusive");

    ValuePairs pairs;
    size_t nbSkippedElements = 0;
    detail::deserializeCollection<detail::ValueTraits>(doc, child, pairs, nbSkippedElements);

    criterionTypes.push_back({name, isInclusive, pairs});
    return NO_ERROR;
}

const char *const CriterionTraits::tag = "criterion";
const char *const CriterionTraits::collectionTag = "criteria";

const char CriterionTraits::Attributes::name[] = "name";
const char CriterionTraits::Attributes::type[] = "type";
const char CriterionTraits::Attributes::defaultVal[] = "default";

status_t CriterionTraits::deserialize(_xmlDoc */*doc*/, const _xmlNode *child, Collection &criteria)
{
    std::string name = getXmlAttribute(child, Attributes::name);
    if (name.empty()) {
        ALOGE("%s: No attribute %s found", __FUNCTION__, Attributes::name);
        return BAD_VALUE;
    }
    ALOGV("%s: %s = %s", __FUNCTION__, Attributes::name, name.c_str());

    std::string defaultValue = getXmlAttribute(child, Attributes::defaultVal);
    if (defaultValue.empty()) {
        // Not mandatory to provide a default value for a criterion, even it is recommanded...
        ALOGV("%s: No attribute %s found", __FUNCTION__, Attributes::defaultVal);
    }
    ALOGV("%s: %s = %s", __FUNCTION__, Attributes::defaultVal, defaultValue.c_str());

    std::string typeName = getXmlAttribute(child, Attributes::type);
    if (typeName.empty()) {
        ALOGE("%s: No attribute %s found", __FUNCTION__, Attributes::name);
        return BAD_VALUE;
    }
    ALOGV("%s: %s = %s", __FUNCTION__, Attributes::type, typeName.c_str());

    criteria.push_back({name, typeName, defaultValue});
    return NO_ERROR;
}
} // namespace detail

ParsingResult parse(const char* path) {
    xmlDocPtr doc;
    doc = xmlParseFile(path);
    if (doc == NULL) {
        ALOGE("%s: Could not parse document %s", __FUNCTION__, path);
        return {nullptr, 0};
    }
    xmlNodePtr cur = xmlDocGetRootElement(doc);
    if (cur == NULL) {
        ALOGE("%s: Could not parse: empty document %s", __FUNCTION__, path);
        xmlFreeDoc(doc);
        return {nullptr, 0};
    }
    if (xmlXIncludeProcess(doc) < 0) {
        ALOGE("%s: libxml failed to resolve XIncludes on document %s", __FUNCTION__, path);
        return {nullptr, 0};
    }
    size_t nbSkippedElements = 0;
    auto config = std::make_unique<Config>();

    detail::deserializeCollection<detail::CriterionTraits>(
                doc, cur, config->criteria, nbSkippedElements);
    detail::deserializeCollection<detail::CriterionTypeTraits>(
                doc, cur, config->criterionTypes, nbSkippedElements);

    return {std::move(config), nbSkippedElements};
}

} // namespace wrapper_config
} // namespace audio_policy
} // namespace android
