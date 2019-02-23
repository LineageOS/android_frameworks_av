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
struct ValueTraits : public BaseSerializerTraits<ValuePair, ValuePairs> {
    static constexpr const char *tag = "value";
    static constexpr const char *collectionTag = "values";

    struct Attributes {
        static constexpr const char *literal = "literal";
        static constexpr const char *numerical = "numerical";
    };

    static android::status_t deserialize(_xmlDoc *doc, const _xmlNode *root,
                                         Collection &collection);
};
struct CriterionTypeTraits : public BaseSerializerTraits<CriterionType, CriterionTypes> {
    static constexpr const char *tag = "criterion_type";
    static constexpr const char *collectionTag = "criterion_types";

    struct Attributes {
        static constexpr const char *name = "name";
        static constexpr const char *type = "type";
    };

    static android::status_t deserialize(_xmlDoc *doc, const _xmlNode *root,
                                         Collection &collection);
};
struct CriterionTraits : public BaseSerializerTraits<Criterion, Criteria> {
    static constexpr const char *tag = "criterion";
    static constexpr const char *collectionTag = "criteria";

    struct Attributes {
        static constexpr const char *name = "name";
        static constexpr const char *type = "type";
        static constexpr const char *defaultVal = "default";
    };

    static android::status_t deserialize(_xmlDoc *doc, const _xmlNode *root,
                                         Collection &collection);
};
struct VolumeTraits : public BaseSerializerTraits<VolumeCurve, VolumeCurves> {
    static constexpr const char *tag = "volume";
    static constexpr const char *collectionTag = "volumes";
    static constexpr const char *volumePointTag = "point";

    struct Attributes {
        static constexpr const char *deviceCategory = "deviceCategory";
        static constexpr const char *reference = "ref"; /**< For volume curves factorization. */
    };

    static android::status_t deserialize(_xmlDoc *doc, const _xmlNode *root,
                                         Collection &collection);
};
struct VolumeGroupTraits : public BaseSerializerTraits<VolumeGroup, VolumeGroups> {
    static constexpr const char *tag = "volumeGroup";
    static constexpr const char *collectionTag = "volumeGroups";

    struct Attributes {
        static constexpr const char *name = "name";
        static constexpr const char *stream = "stream"; // For legacy volume curves
        static constexpr const char *indexMin = "indexMin";
        static constexpr const char *indexMax = "indexMax";
    };

    static android::status_t deserialize(_xmlDoc *doc, const _xmlNode *root,
                                         Collection &collection);
};

using xmlCharUnique = std::unique_ptr<xmlChar, decltype(xmlFree)>;

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
    deserializeCollection<ValueTraits>(doc, child, pairs, nbSkippedElements);
    criterionTypes.push_back({name, isInclusive, pairs});
    return NO_ERROR;
}

status_t CriterionTraits::deserialize(_xmlDoc */*doc*/, const _xmlNode *child,
                                      Collection &criteria)
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
        ALOGV("%s: No attribute %s found (but recommanded)", __FUNCTION__, Attributes::defaultVal);
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

status_t VolumeTraits::deserialize(_xmlDoc *doc, const _xmlNode *root, Collection &volumes)
{
    std::string deviceCategory = getXmlAttribute(root, Attributes::deviceCategory);
    if (deviceCategory.empty()) {
        ALOGW("%s: No %s found", __FUNCTION__, Attributes::deviceCategory);
    }

    std::string referenceName = getXmlAttribute(root, Attributes::reference);
    const _xmlNode *ref = NULL;
    if (!referenceName.empty()) {
        getReference(xmlDocGetRootElement(doc), ref, referenceName, collectionTag);
        if (ref == NULL) {
            ALOGE("%s: No reference Ptr found for %s", __FUNCTION__, referenceName.c_str());
            return BAD_VALUE;
        }
    }
    // Retrieve curve point from reference element if found or directly from current curve
    CurvePoints curvePoints;
    for (const xmlNode *child = referenceName.empty() ?
         root->xmlChildrenNode : ref->xmlChildrenNode; child != NULL; child = child->next) {
        if (!xmlStrcmp(child->name, (const xmlChar *)volumePointTag)) {
            xmlCharUnique pointXml(xmlNodeListGetString(doc, child->xmlChildrenNode, 1), xmlFree);
            if (pointXml == NULL) {
                return BAD_VALUE;
            }
            ALOGV("%s: %s=%s", __func__, tag, reinterpret_cast<const char*>(pointXml.get()));
            std::vector<int> point;
            collectionFromString<DefaultTraits<int>>(
                        reinterpret_cast<const char*>(pointXml.get()), point, ",");
            if (point.size() != 2) {
                ALOGE("%s: Invalid %s: %s", __func__, volumePointTag,
                      reinterpret_cast<const char*>(pointXml.get()));
                return BAD_VALUE;
            }
            curvePoints.push_back({point[0], point[1]});
        }
    }
    volumes.push_back({ deviceCategory, curvePoints });
    return NO_ERROR;
}

status_t VolumeGroupTraits::deserialize(_xmlDoc *doc, const _xmlNode *root, Collection &volumes)
{
    std::string name;
    std::string stream = {};
    int indexMin = 0;
    int indexMax = 0;

    for (const xmlNode *child = root->xmlChildrenNode; child != NULL; child = child->next) {
        if (not xmlStrcmp(child->name, (const xmlChar *)Attributes::name)) {
            xmlCharUnique nameXml(xmlNodeListGetString(doc, child->xmlChildrenNode, 1), xmlFree);
            if (nameXml == nullptr) {
                return BAD_VALUE;
            }
            name = reinterpret_cast<const char*>(nameXml.get());
        }
        if (not xmlStrcmp(child->name, (const xmlChar *)Attributes::stream)) {
            xmlCharUnique streamXml(xmlNodeListGetString(doc, child->xmlChildrenNode, 1), xmlFree);
            if (streamXml == nullptr) {
                return BAD_VALUE;
            }
            stream = reinterpret_cast<const char*>(streamXml.get());
        }
        if (not xmlStrcmp(child->name, (const xmlChar *)Attributes::indexMin)) {
            xmlCharUnique indexMinXml(xmlNodeListGetString(doc, child->xmlChildrenNode, 1), xmlFree);
            if (indexMinXml == nullptr) {
                return BAD_VALUE;
            }
            std::string indexMinLiteral(reinterpret_cast<const char*>(indexMinXml.get()));
            if (!convertTo(indexMinLiteral, indexMin)) {
                return BAD_VALUE;
            }
        }
        if (not xmlStrcmp(child->name, (const xmlChar *)Attributes::indexMax)) {
            xmlCharUnique indexMaxXml(xmlNodeListGetString(doc, child->xmlChildrenNode, 1), xmlFree);
            if (indexMaxXml == nullptr) {
                return BAD_VALUE;
            }
            std::string indexMaxLiteral(reinterpret_cast<const char*>(indexMaxXml.get()));
            if (!convertTo(indexMaxLiteral, indexMax)) {
                return BAD_VALUE;
            }
        }
    }
    ALOGV("%s: group=%s stream=%s indexMin=%d, indexMax=%d",
          __func__, name.c_str(), stream.c_str(), indexMin, indexMax);

    VolumeCurves groupVolumeCurves;
    size_t skipped = 0;
    deserializeCollection<VolumeTraits>(doc, root, groupVolumeCurves, skipped);
    volumes.push_back({ name, stream, indexMin, indexMax, groupVolumeCurves });
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
    deserializeCollection<CriterionTraits>(
                doc, cur, config->criteria, nbSkippedElements);
    deserializeCollection<CriterionTypeTraits>(
                doc, cur, config->criterionTypes, nbSkippedElements);
    deserializeCollection<VolumeGroupTraits>(
                doc, cur, config->volumeGroups, nbSkippedElements);

    return {std::move(config), nbSkippedElements};
}

} // namespace engineConfig
} // namespace android
