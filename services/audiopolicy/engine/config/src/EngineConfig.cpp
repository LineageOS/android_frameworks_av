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

#include <cstdint>
#include <istream>
#include <map>
#include <sstream>
#include <stdarg.h>
#include <string>
#include <string>
#include <vector>

#define LOG_TAG "APM::AudioPolicyEngine/Config"
//#define LOG_NDEBUG 0

#include "EngineConfig.h"
#include <TypeConverter.h>
#include <Volume.h>
#include <cutils/properties.h>
#include <libxml/parser.h>
#include <libxml/xinclude.h>
#include <media/AidlConversion.h>
#include <media/AidlConversionUtil.h>
#include <media/TypeConverter.h>
#include <media/convert.h>
#include <system/audio_config.h>
#include <utils/Log.h>

namespace android {

using utilities::convertTo;

namespace engineConfig {

static constexpr const char *gVersionAttribute = "version";
static const char *const gReferenceElementName = "reference";
static const char *const gReferenceAttributeName = "name";

namespace {

ConversionResult<AttributesGroup> aidl2legacy_AudioHalAttributeGroup_AttributesGroup(
        const media::audio::common::AudioHalAttributesGroup& aidl) {
    AttributesGroup legacy;
    legacy.stream = VALUE_OR_RETURN(
            aidl2legacy_AudioStreamType_audio_stream_type_t(aidl.streamType));
    legacy.volumeGroup = aidl.volumeGroupName;
    legacy.attributesVect = VALUE_OR_RETURN(convertContainer<AttributesVector>(
                    aidl.attributes, aidl2legacy_AudioAttributes_audio_attributes_t));
    return legacy;
}

ConversionResult<ProductStrategy> aidl2legacy_AudioHalProductStrategy_ProductStrategy(
        const media::audio::common::AudioHalProductStrategy& aidl) {
    ProductStrategy legacy;
    legacy.name = "strategy_" + std::to_string(aidl.id);
    legacy.attributesGroups = VALUE_OR_RETURN(convertContainer<AttributesGroups>(
                    aidl.attributesGroups,
                    aidl2legacy_AudioHalAttributeGroup_AttributesGroup));
    return legacy;
}

ConversionResult<std::string> legacy_device_category_to_string(device_category legacy) {
    std::string s;
    if (DeviceCategoryConverter::toString(legacy, s)) {
        return s;
    }
    return base::unexpected(BAD_VALUE);
}

ConversionResult<std::string> aidl2legacy_DeviceCategory(
        const media::audio::common::AudioHalVolumeCurve::DeviceCategory aidl) {
    using DeviceCategory = media::audio::common::AudioHalVolumeCurve::DeviceCategory;
    switch (aidl) {
        case DeviceCategory::HEADSET:
            return legacy_device_category_to_string(DEVICE_CATEGORY_HEADSET);
        case DeviceCategory::SPEAKER:
            return legacy_device_category_to_string(DEVICE_CATEGORY_SPEAKER);
        case DeviceCategory::EARPIECE:
            return legacy_device_category_to_string(DEVICE_CATEGORY_EARPIECE);
        case DeviceCategory::EXT_MEDIA:
            return legacy_device_category_to_string(DEVICE_CATEGORY_EXT_MEDIA);
        case DeviceCategory::HEARING_AID:
            return legacy_device_category_to_string(DEVICE_CATEGORY_HEARING_AID);
    }
    return base::unexpected(BAD_VALUE);
}

ConversionResult<CurvePoint> aidl2legacy_AudioHalCurvePoint_CurvePoint(
        const media::audio::common::AudioHalVolumeCurve::CurvePoint& aidl) {
    CurvePoint legacy;
    legacy.index = VALUE_OR_RETURN(convertIntegral<int>(aidl.index));
    legacy.attenuationInMb = aidl.attenuationMb;
    return legacy;
}

ConversionResult<VolumeCurve> aidl2legacy_AudioHalVolumeCurve_VolumeCurve(
        const media::audio::common::AudioHalVolumeCurve& aidl) {
    VolumeCurve legacy;
    legacy.deviceCategory = VALUE_OR_RETURN(aidl2legacy_DeviceCategory(aidl.deviceCategory));
    legacy.curvePoints = VALUE_OR_RETURN(convertContainer<CurvePoints>(
                    aidl.curvePoints, aidl2legacy_AudioHalCurvePoint_CurvePoint));
    return legacy;
}

ConversionResult<VolumeGroup> aidl2legacy_AudioHalVolumeGroup_VolumeGroup(
        const media::audio::common::AudioHalVolumeGroup& aidl) {
    VolumeGroup legacy;
    legacy.name = aidl.name;
    legacy.indexMin = aidl.minIndex;
    legacy.indexMax = aidl.maxIndex;
    legacy.volumeCurves = VALUE_OR_RETURN(convertContainer<VolumeCurves>(
                    aidl.volumeCurves, aidl2legacy_AudioHalVolumeCurve_VolumeCurve));
    return legacy;
}

}  // namespace

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
        static constexpr const char *streamType = "streamType";
        static constexpr const char *volumeGroup = "volumeGroup";
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
        static constexpr const char *androidType = "android_type";
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
        static constexpr const char *stream = "stream"; // For legacy volume curves
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

template <class T>
constexpr void (*xmlDeleter)(T* t);
template <>
constexpr auto xmlDeleter<xmlDoc> = xmlFreeDoc;
template <>
constexpr auto xmlDeleter<xmlChar> = [](xmlChar *s) { xmlFree(s); };

/** @return a unique_ptr with the correct deleter for the libxml2 object. */
template <class T>
constexpr auto make_xmlUnique(T *t) {
    // Wrap deleter in lambda to enable empty base optimization
    auto deleter = [](T *t) { xmlDeleter<T>(t); };
    return std::unique_ptr<T, decltype(deleter)>{t, deleter};
}

std::string getXmlAttribute(const xmlNode *cur, const char *attribute)
{
    auto charPtr = make_xmlUnique(xmlGetProp(cur, reinterpret_cast<const xmlChar *>(attribute)));
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
            attributes.flags = static_cast<audio_flags_mask_t>(
                    AudioFlagConverter::maskFromString(flags, " "));
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
    std::string volumeGroup = getXmlAttribute(child, Attributes::volumeGroup);
    if (volumeGroup.empty()) {
        ALOGE("%s: No attribute %s found", __FUNCTION__, Attributes::volumeGroup);
    }
    ALOGV("%s: %s = %s", __FUNCTION__, Attributes::volumeGroup, volumeGroup.c_str());

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

    attributesGroup.push_back({streamType, volumeGroup, attributesVect});
    return NO_ERROR;
}

status_t ValueTraits::deserialize(_xmlDoc */*doc*/, const _xmlNode *child, Collection &values)
{
    std::string literal = getXmlAttribute(child, Attributes::literal);
    if (literal.empty()) {
        ALOGE("%s: No attribute %s found", __FUNCTION__, Attributes::literal);
        return BAD_VALUE;
    }
    uint32_t androidType = 0;
    std::string androidTypeliteral = getXmlAttribute(child, Attributes::androidType);
    if (!androidTypeliteral.empty()) {
        ALOGV("%s: androidType %s", __FUNCTION__, androidTypeliteral.c_str());
        if (!convertTo(androidTypeliteral, androidType)) {
            ALOGE("%s: : Invalid typeset value(%s)", __FUNCTION__, androidTypeliteral.c_str());
            return BAD_VALUE;
        }
    }
    uint64_t numerical = 0;
    std::string numericalTag = getXmlAttribute(child, Attributes::numerical);
    if (numericalTag.empty()) {
        ALOGE("%s: No attribute %s found", __FUNCTION__, Attributes::literal);
        return BAD_VALUE;
    }
    if (!convertTo(numericalTag, numerical)) {
        ALOGE("%s: : Invalid value(%s)", __FUNCTION__, numericalTag.c_str());
        return BAD_VALUE;
    }
    values.push_back({numerical,  androidType, literal});
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
            auto pointXml = make_xmlUnique(xmlNodeListGetString(doc, child->xmlChildrenNode, 1));
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
    int indexMin = 0;
    int indexMax = 0;
    StreamVector streams = {};
    AttributesVector attributesVect = {};

    for (const xmlNode *child = root->xmlChildrenNode; child != NULL; child = child->next) {
        if (not xmlStrcmp(child->name, (const xmlChar *)Attributes::name)) {
            auto nameXml = make_xmlUnique(xmlNodeListGetString(doc, child->xmlChildrenNode, 1));
            if (nameXml == nullptr) {
                return BAD_VALUE;
            }
            name = reinterpret_cast<const char*>(nameXml.get());
        }
        if (not xmlStrcmp(child->name, (const xmlChar *)Attributes::indexMin)) {
            auto indexMinXml = make_xmlUnique(xmlNodeListGetString(doc, child->xmlChildrenNode, 1));
            if (indexMinXml == nullptr) {
                return BAD_VALUE;
            }
            std::string indexMinLiteral(reinterpret_cast<const char*>(indexMinXml.get()));
            if (!convertTo(indexMinLiteral, indexMin)) {
                return BAD_VALUE;
            }
        }
        if (not xmlStrcmp(child->name, (const xmlChar *)Attributes::indexMax)) {
            auto indexMaxXml = make_xmlUnique(xmlNodeListGetString(doc, child->xmlChildrenNode, 1));
            if (indexMaxXml == nullptr) {
                return BAD_VALUE;
            }
            std::string indexMaxLiteral(reinterpret_cast<const char*>(indexMaxXml.get()));
            if (!convertTo(indexMaxLiteral, indexMax)) {
                return BAD_VALUE;
            }
        }
    }
    deserializeAttributesCollection(doc, root, attributesVect);

    std::string streamNames;
    for (const auto &stream : streams) {
        streamNames += android::toString(stream) + " ";
    }
    std::string attrmNames;
    for (const auto &attr : attributesVect) {
        attrmNames += android::toString(attr) + "\n";
    }
    ALOGV("%s: group=%s indexMin=%d, indexMax=%d streams=%s attributes=%s",
          __func__, name.c_str(), indexMin, indexMax, streamNames.c_str(), attrmNames.c_str( ));

    VolumeCurves groupVolumeCurves;
    size_t skipped = 0;
    deserializeCollection<VolumeTraits>(doc, root, groupVolumeCurves, skipped);
    volumes.push_back({ name, indexMin, indexMax, groupVolumeCurves });
    return NO_ERROR;
}

static constexpr const char *legacyVolumecollectionTag = "volumes";
static constexpr const char *legacyVolumeTag = "volume";

status_t deserializeLegacyVolume(_xmlDoc *doc, const _xmlNode *cur,
                                 std::map<std::string, VolumeCurves> &legacyVolumes)
{
    std::string streamTypeLiteral = getXmlAttribute(cur, "stream");
    if (streamTypeLiteral.empty()) {
        ALOGE("%s: No attribute stream found", __func__);
        return BAD_VALUE;
    }
    std::string deviceCategoryLiteral = getXmlAttribute(cur, "deviceCategory");
    if (deviceCategoryLiteral.empty()) {
        ALOGE("%s: No attribute deviceCategory found", __func__);
        return BAD_VALUE;
    }
    std::string referenceName = getXmlAttribute(cur, "ref");
    const xmlNode *ref = NULL;
    if (!referenceName.empty()) {
        getReference(xmlDocGetRootElement(doc), ref, referenceName, legacyVolumecollectionTag);
        if (ref == NULL) {
            ALOGE("%s: No reference Ptr found for %s", __func__, referenceName.c_str());
            return BAD_VALUE;
        }
        ALOGV("%s: reference found for %s", __func__, referenceName.c_str());
    }
    CurvePoints curvePoints;
    for (const xmlNode *child = referenceName.empty() ?
         cur->xmlChildrenNode : ref->xmlChildrenNode; child != NULL; child = child->next) {
        if (!xmlStrcmp(child->name, (const xmlChar *)VolumeTraits::volumePointTag)) {
            auto pointXml = make_xmlUnique(xmlNodeListGetString(doc, child->xmlChildrenNode, 1));
            if (pointXml == NULL) {
                return BAD_VALUE;
            }
            ALOGV("%s: %s=%s", __func__, legacyVolumeTag,
                  reinterpret_cast<const char*>(pointXml.get()));
            std::vector<int> point;
            collectionFromString<DefaultTraits<int>>(
                        reinterpret_cast<const char*>(pointXml.get()), point, ",");
            if (point.size() != 2) {
                ALOGE("%s: Invalid %s: %s", __func__, VolumeTraits::volumePointTag,
                      reinterpret_cast<const char*>(pointXml.get()));
                return BAD_VALUE;
            }
            curvePoints.push_back({point[0], point[1]});
        }
    }
    legacyVolumes[streamTypeLiteral].push_back({ deviceCategoryLiteral, curvePoints });
    return NO_ERROR;
}

static status_t deserializeLegacyVolumeCollection(_xmlDoc *doc, const _xmlNode *cur,
                                                  VolumeGroups &volumeGroups,
                                                  size_t &nbSkippedElement)
{
    std::map<std::string, VolumeCurves> legacyVolumeMap;
    for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
        if (xmlStrcmp(cur->name, (const xmlChar *)legacyVolumecollectionTag)) {
            continue;
        }
        const xmlNode *child = cur->xmlChildrenNode;
        for (; child != NULL; child = child->next) {
            if (!xmlStrcmp(child->name, (const xmlChar *)legacyVolumeTag)) {

                status_t status = deserializeLegacyVolume(doc, child, legacyVolumeMap);
                if (status != NO_ERROR) {
                    nbSkippedElement += 1;
                }
            }
        }
    }
    VolumeGroups tempVolumeGroups = volumeGroups;
    for (const auto &volumeMapIter : legacyVolumeMap) {
        // In order to let AudioService setting the min and max (compatibility), set Min and Max
        // to -1 except for private streams
        audio_stream_type_t streamType;
        if (!StreamTypeConverter::fromString(volumeMapIter.first, streamType)) {
            ALOGE("%s: Invalid stream %s", __func__, volumeMapIter.first.c_str());
            return BAD_VALUE;
        }
        int indexMin = streamType >= AUDIO_STREAM_PUBLIC_CNT ? 0 : -1;
        int indexMax = streamType >= AUDIO_STREAM_PUBLIC_CNT ? 100 : -1;
        tempVolumeGroups.push_back(
                { volumeMapIter.first, indexMin, indexMax, volumeMapIter.second });
    }
    std::swap(tempVolumeGroups, volumeGroups);
    return NO_ERROR;
}

namespace {

class XmlErrorHandler {
public:
    XmlErrorHandler() {
        xmlSetGenericErrorFunc(this, &xmlErrorHandler);
    }
    XmlErrorHandler(const XmlErrorHandler&) = delete;
    XmlErrorHandler(XmlErrorHandler&&) = delete;
    XmlErrorHandler& operator=(const XmlErrorHandler&) = delete;
    XmlErrorHandler& operator=(XmlErrorHandler&&) = delete;
    ~XmlErrorHandler() {
        xmlSetGenericErrorFunc(NULL, NULL);
        if (!mErrorMessage.empty()) {
            ALOG(LOG_ERROR, "libxml2", "%s", mErrorMessage.c_str());
        }
    }
    static void xmlErrorHandler(void* ctx, const char* msg, ...) {
        char buffer[256];
        va_list args;
        va_start(args, msg);
        vsnprintf(buffer, sizeof(buffer), msg, args);
        va_end(args);
        static_cast<XmlErrorHandler*>(ctx)->mErrorMessage += buffer;
    }
private:
    std::string mErrorMessage;
};

}  // namespace

ParsingResult parse(const char* path) {
    XmlErrorHandler errorHandler;
    auto doc = make_xmlUnique(xmlParseFile(path));
    if (doc == NULL) {
        // It is OK not to find an engine config file at the default location
        // as the caller will default to hardcoded default config
        if (strncmp(path, DEFAULT_PATH, strlen(DEFAULT_PATH))) {
            ALOGW("%s: Could not parse document %s", __FUNCTION__, path);
        }
        return {nullptr, 0};
    }
    xmlNodePtr cur = xmlDocGetRootElement(doc.get());
    if (cur == NULL) {
        ALOGE("%s: Could not parse: empty document %s", __FUNCTION__, path);
        return {nullptr, 0};
    }
    if (xmlXIncludeProcess(doc.get()) < 0) {
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
                doc.get(), cur, config->productStrategies, nbSkippedElements);
    deserializeCollection<CriterionTraits>(
                doc.get(), cur, config->criteria, nbSkippedElements);
    deserializeCollection<CriterionTypeTraits>(
                doc.get(), cur, config->criterionTypes, nbSkippedElements);
    deserializeCollection<VolumeGroupTraits>(
                doc.get(), cur, config->volumeGroups, nbSkippedElements);

    return {std::move(config), nbSkippedElements};
}

android::status_t parseLegacyVolumeFile(const char* path, VolumeGroups &volumeGroups) {
    XmlErrorHandler errorHandler;
    auto doc = make_xmlUnique(xmlParseFile(path));
    if (doc == NULL) {
        ALOGE("%s: Could not parse document %s", __FUNCTION__, path);
        return BAD_VALUE;
    }
    xmlNodePtr cur = xmlDocGetRootElement(doc.get());
    if (cur == NULL) {
        ALOGE("%s: Could not parse: empty document %s", __FUNCTION__, path);
        return BAD_VALUE;
    }
    if (xmlXIncludeProcess(doc.get()) < 0) {
        ALOGE("%s: libxml failed to resolve XIncludes on document %s", __FUNCTION__, path);
        return BAD_VALUE;
    }
    size_t nbSkippedElements = 0;
    return deserializeLegacyVolumeCollection(doc.get(), cur, volumeGroups, nbSkippedElements);
}

android::status_t parseLegacyVolumes(VolumeGroups &volumeGroups) {
    if (std::string audioPolicyXmlConfigFile = audio_get_audio_policy_config_file();
            !audioPolicyXmlConfigFile.empty()) {
        return parseLegacyVolumeFile(audioPolicyXmlConfigFile.c_str(), volumeGroups);
    } else {
        ALOGE("No readable audio policy config file found");
        return BAD_VALUE;
    }
}

ParsingResult convert(const ::android::media::audio::common::AudioHalEngineConfig& aidlConfig) {
    auto config = std::make_unique<engineConfig::Config>();
    config->version = 1.0f;
    if (auto conv = convertContainer<engineConfig::ProductStrategies>(
                    aidlConfig.productStrategies,
                    aidl2legacy_AudioHalProductStrategy_ProductStrategy); conv.ok()) {
        config->productStrategies = std::move(conv.value());
    } else {
        return ParsingResult{};
    }
    if (auto conv = convertContainer<engineConfig::VolumeGroups>(
                    aidlConfig.volumeGroups,
                    aidl2legacy_AudioHalVolumeGroup_VolumeGroup); conv.ok()) {
        config->volumeGroups = std::move(conv.value());
    } else {
        return ParsingResult{};
    }
    return {.parsedConfig=std::move(config), .nbSkippedElement=0};
 }

} // namespace engineConfig
} // namespace android
