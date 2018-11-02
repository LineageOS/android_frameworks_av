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

#define LOG_TAG "APM::AudioPolicyEngine/Config"
//#define LOG_NDEBUG 0

#include "EngineConfig.h"
#include <policy.h>
#include <media/TypeConverter.h>
#include <media/convert.h>
#include <utils/Log.h>
#include <libxml/parser.h>
#include <libxml/xinclude.h>
#include <string>
#include <vector>
#include <sstream>
#include <istream>

#include <cstdint>
#include <string>


namespace android {

using utilities::convertTo;

namespace engineConfig {

static constexpr const char *gVersionAttribute = "version";
static const char *const gReferenceElementName = "reference";
static const char *const gReferenceAttributeName = "name";

template<typename E, typename C>
struct BaseSerializerTraits {
    typedef E Element;
    typedef C Collection;
    typedef void* PtrSerializingCtx;
};

struct AttributesGroupTraits : public BaseSerializerTraits<AttributesGroup, AttributesGroups> {
    static constexpr const char *tag = "AttributesGroup";
    static constexpr const char *collectionTag = "AttributesGroups";

    struct Attributes {
        static constexpr const char *name = "name";
        static constexpr const char *streamType = "streamType";
    };
    static android::status_t deserialize(_xmlDoc *doc, const _xmlNode *root, Collection &ps);
};

struct ProductStrategyTraits : public BaseSerializerTraits<ProductStrategy, ProductStrategies> {
    static constexpr const char *tag = "ProductStrategy";
    static constexpr const char *collectionTag = "ProductStrategies";

    struct Attributes {
        static constexpr const char *name = "name";
    };
    static android::status_t deserialize(_xmlDoc *doc, const _xmlNode *root, Collection &ps);
};

using xmlCharUnique = std::unique_ptr<xmlChar, decltype(xmlFree)>;

std::string getXmlAttribute(const xmlNode *cur, const char *attribute)
{
    xmlCharUnique charPtr(xmlGetProp(cur, reinterpret_cast<const xmlChar *>(attribute)), xmlFree);
    if (charPtr == NULL) {
        return "";
    }
    std::string value(reinterpret_cast<const char*>(charPtr.get()));
    return value;
}

static void getReference(const _xmlNode *root, const _xmlNode *&refNode, const std::string &refName,
                         const char *collectionTag)
{
    for (root = root->xmlChildrenNode; root != NULL; root = root->next) {
        if (!xmlStrcmp(root->name, (const xmlChar *)collectionTag)) {
            for (xmlNode *cur = root->xmlChildrenNode; cur != NULL; cur = cur->next) {
                if ((!xmlStrcmp(cur->name, (const xmlChar *)gReferenceElementName))) {
                    std::string name = getXmlAttribute(cur, gReferenceAttributeName);
                    if (refName == name) {
                        refNode = cur;
                        return;
                    }
                }
            }
        }
    }
    return;
}

template <class Trait>
static status_t deserializeCollection(_xmlDoc *doc, const _xmlNode *cur,
                                      typename Trait::Collection &collection,
                                      size_t &nbSkippedElement)
{
    for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
        if (xmlStrcmp(cur->name, (const xmlChar *)Trait::collectionTag) &&
            xmlStrcmp(cur->name, (const xmlChar *)Trait::tag)) {
            continue;
        }
        const xmlNode *child = cur;
        if (!xmlStrcmp(child->name, (const xmlChar *)Trait::collectionTag)) {
            child = child->xmlChildrenNode;
        }
        for (; child != NULL; child = child->next) {
            if (!xmlStrcmp(child->name, (const xmlChar *)Trait::tag)) {
                status_t status = Trait::deserialize(doc, child, collection);
                if (status != NO_ERROR) {
                    nbSkippedElement += 1;
                }
            }
        }
        if (!xmlStrcmp(cur->name, (const xmlChar *)Trait::tag)) {
            return NO_ERROR;
        }
    }
    return NO_ERROR;
}

static constexpr const char *attributesAttributeRef = "attributesRef"; /**< for factorization. */

static status_t parseAttributes(const _xmlNode *cur, audio_attributes_t &attributes)
{
    for (; cur != NULL; cur = cur->next) {
        if (!xmlStrcmp(cur->name, (const xmlChar *)("ContentType"))) {
            std::string contentTypeXml = getXmlAttribute(cur, "value");
            audio_content_type_t contentType;
            if (not AudioContentTypeConverter::fromString(contentTypeXml.c_str(), contentType)) {
                ALOGE("Invalid content type %s", contentTypeXml.c_str());
                return BAD_VALUE;
            }
            attributes.content_type = contentType;
            ALOGV("%s content type %s",  __FUNCTION__, contentTypeXml.c_str());
        }
        if (!xmlStrcmp(cur->name, (const xmlChar *)("Usage"))) {
            std::string usageXml = getXmlAttribute(cur, "value");
            audio_usage_t usage;
            if (not UsageTypeConverter::fromString(usageXml.c_str(), usage)) {
                ALOGE("Invalid usage %s", usageXml.c_str());
                return BAD_VALUE;
            }
            attributes.usage = usage;
            ALOGV("%s usage %s",  __FUNCTION__, usageXml.c_str());
        }
        if (!xmlStrcmp(cur->name, (const xmlChar *)("Flags"))) {
            std::string flags = getXmlAttribute(cur, "value");

            ALOGV("%s flags %s",  __FUNCTION__, flags.c_str());
            attributes.flags = AudioFlagConverter::maskFromString(flags, " ");
        }
        if (!xmlStrcmp(cur->name, (const xmlChar *)("Bundle"))) {
            std::string bundleKey = getXmlAttribute(cur, "key");
            std::string bundleValue = getXmlAttribute(cur, "value");

            ALOGV("%s Bundle %s %s",  __FUNCTION__, bundleKey.c_str(), bundleValue.c_str());

            std::string tags(bundleKey + "=" + bundleValue);
            std::strncpy(attributes.tags, tags.c_str(), AUDIO_ATTRIBUTES_TAGS_MAX_SIZE - 1);
        }
    }
    return NO_ERROR;
}

static status_t deserializeAttributes(_xmlDoc *doc, const _xmlNode *cur,
                                      audio_attributes_t &attributes) {
    // Retrieve content type, usage, flags, and bundle from xml
    for (; cur != NULL; cur = cur->next) {
        if (not xmlStrcmp(cur->name, (const xmlChar *)("Attributes"))) {
            const xmlNode *attrNode = cur;
            std::string attrRef = getXmlAttribute(cur, attributesAttributeRef);
            if (!attrRef.empty()) {
                getReference(xmlDocGetRootElement(doc), attrNode, attrRef, attributesAttributeRef);
                if (attrNode == NULL) {
                    ALOGE("%s: No reference found for %s", __FUNCTION__, attrRef.c_str());
                    return BAD_VALUE;
                }
                return deserializeAttributes(doc, attrNode->xmlChildrenNode, attributes);
            }
            return parseAttributes(attrNode->xmlChildrenNode, attributes);
        }
        if (not xmlStrcmp(cur->name, (const xmlChar *)("ContentType")) ||
                not xmlStrcmp(cur->name, (const xmlChar *)("Usage")) ||
                not xmlStrcmp(cur->name, (const xmlChar *)("Flags")) ||
                not xmlStrcmp(cur->name, (const xmlChar *)("Bundle"))) {
            return parseAttributes(cur, attributes);
        }
    }
    return BAD_VALUE;
}

static status_t deserializeAttributesCollection(_xmlDoc *doc, const _xmlNode *cur,
                                                AttributesVector &collection)
{
    status_t ret = BAD_VALUE;
    // Either we do provide only one attributes or a collection of supported attributes
    for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
        if (not xmlStrcmp(cur->name, (const xmlChar *)("Attributes")) ||
                not xmlStrcmp(cur->name, (const xmlChar *)("ContentType")) ||
                not xmlStrcmp(cur->name, (const xmlChar *)("Usage")) ||
                not xmlStrcmp(cur->name, (const xmlChar *)("Flags")) ||
                not xmlStrcmp(cur->name, (const xmlChar *)("Bundle"))) {
            audio_attributes_t attributes = AUDIO_ATTRIBUTES_INITIALIZER;
            ret = deserializeAttributes(doc, cur, attributes);
            if (ret == NO_ERROR) {
                collection.push_back(attributes);
                // We are done if the "Attributes" balise is omitted, only one Attributes is allowed
                if (xmlStrcmp(cur->name, (const xmlChar *)("Attributes"))) {
                    return ret;
                }
            }
        }
    }
    return ret;
}

status_t AttributesGroupTraits::deserialize(_xmlDoc *doc, const _xmlNode *child,
                                            Collection &attributesGroup)
{
    std::string name = getXmlAttribute(child, Attributes::name);
    if (name.empty()) {
        ALOGV("AttributesGroupTraits No attribute %s found", Attributes::name);
    }
    ALOGV("%s: %s = %s", __FUNCTION__, Attributes::name, name.c_str());

    audio_stream_type_t streamType = AUDIO_STREAM_DEFAULT;
    std::string streamTypeXml = getXmlAttribute(child, Attributes::streamType);
    if (streamTypeXml.empty()) {
        ALOGV("%s: No attribute %s found", __FUNCTION__, Attributes::streamType);
    } else {
        ALOGV("%s: %s = %s", __FUNCTION__, Attributes::streamType, streamTypeXml.c_str());
        if (not StreamTypeConverter::fromString(streamTypeXml.c_str(), streamType)) {
            ALOGE("Invalid stream type %s", streamTypeXml.c_str());
            return BAD_VALUE;
        }
    }
    AttributesVector attributesVect;
    deserializeAttributesCollection(doc, child, attributesVect);

    attributesGroup.push_back({name, streamType, attributesVect});
    return NO_ERROR;
}

status_t ProductStrategyTraits::deserialize(_xmlDoc *doc, const _xmlNode *child,
                                            Collection &strategies)
{
    std::string name = getXmlAttribute(child, Attributes::name);
    if (name.empty()) {
        ALOGE("ProductStrategyTraits No attribute %s found", Attributes::name);
        return BAD_VALUE;
    }
    ALOGV("%s: %s = %s", __FUNCTION__, Attributes::name, name.c_str());

    size_t skipped = 0;
    AttributesGroups attrGroups;
    deserializeCollection<AttributesGroupTraits>(doc, child, attrGroups, skipped);

    strategies.push_back({name, attrGroups});
    return NO_ERROR;
}

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
    std::string version = getXmlAttribute(cur, gVersionAttribute);
    if (version.empty()) {
        ALOGE("%s: No version found", __func__);
        return {nullptr, 0};
    }
    size_t nbSkippedElements = 0;
    auto config = std::make_unique<Config>();
    config->version = std::stof(version);
    deserializeCollection<ProductStrategyTraits>(
                doc, cur, config->productStrategies, nbSkippedElements);

    return {std::move(config), nbSkippedElements};
}

} // namespace engineConfig
} // namespace android
