/*
 * Copyright (C) 2015 The Android Open Source Project
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

#define LOG_TAG "APM::Serializer"
//#define LOG_NDEBUG 0

#include <memory>
#include <string>

#include <libxml/parser.h>
#include <libxml/xinclude.h>
#include <media/convert.h>
#include <utils/Log.h>
#include <utils/StrongPointer.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>
#include "Serializer.h"
#include "TypeConverter.h"

namespace android {

namespace {

using utilities::convertTo;

template<typename E, typename C>
struct BaseSerializerTraits {
    typedef E Element;
    typedef sp<E> PtrElement;
    typedef C Collection;
    typedef void* PtrSerializingCtx;
};

struct AudioGainTraits : public BaseSerializerTraits<AudioGain, AudioGainCollection>
{
    static constexpr const char *tag = "gain";
    static constexpr const char *collectionTag = "gains";

    struct Attributes
    {
        /** gain modes supported, e.g. AUDIO_GAIN_MODE_CHANNELS. */
        static constexpr const char *mode = "mode";
        /** controlled channels, needed if mode AUDIO_GAIN_MODE_CHANNELS. */
        static constexpr const char *channelMask = "channel_mask";
        static constexpr const char *minValueMB = "minValueMB"; /**< min value in millibel. */
        static constexpr const char *maxValueMB = "maxValueMB"; /**< max value in millibel. */
        /** default value in millibel. */
        static constexpr const char *defaultValueMB = "defaultValueMB";
        static constexpr const char *stepValueMB = "stepValueMB"; /**< step value in millibel. */
        /** needed if mode AUDIO_GAIN_MODE_RAMP. */
        static constexpr const char *minRampMs = "minRampMs";
        /** needed if mode AUDIO_GAIN_MODE_RAMP. */
        static constexpr const char *maxRampMs = "maxRampMs";
    };

    static status_t deserialize(xmlDoc *doc, const xmlNode *root, PtrElement *element,
                                PtrSerializingCtx serializingContext);
    // No children
};

// A profile section contains a name,  one audio format and the list of supported sampling rates
// and channel masks for this format
struct AudioProfileTraits : public BaseSerializerTraits<AudioProfile, AudioProfileVector>
{
    static constexpr const char *tag = "profile";
    static constexpr const char *collectionTag = "profiles";

    struct Attributes
    {
        static constexpr const char *samplingRates = "samplingRates";
        static constexpr const char *format = "format";
        static constexpr const char *channelMasks = "channelMasks";
    };

    static status_t deserialize(xmlDoc *doc, const xmlNode *root, PtrElement *element,
                                PtrSerializingCtx serializingContext);
};

struct MixPortTraits : public BaseSerializerTraits<IOProfile, IOProfileCollection>
{
    static constexpr const char *tag = "mixPort";
    static constexpr const char *collectionTag = "mixPorts";

    struct Attributes
    {
        static constexpr const char *name = "name";
        static constexpr const char *role = "role";
        static constexpr const char *roleSource = "source"; /**< <attribute role source value>. */
        static constexpr const char *flags = "flags";
        static constexpr const char *maxOpenCount = "maxOpenCount";
        static constexpr const char *maxActiveCount = "maxActiveCount";
    };

    static status_t deserialize(xmlDoc *doc, const xmlNode *root, PtrElement *element,
                                PtrSerializingCtx serializingContext);
    // Children: GainTraits
};

struct DevicePortTraits : public BaseSerializerTraits<DeviceDescriptor, DeviceVector>
{
    static constexpr const char *tag = "devicePort";
    static constexpr const char *collectionTag = "devicePorts";

    struct Attributes
    {
        /**  <device tag name>: any string without space. */
        static constexpr const char *tagName = "tagName";
        static constexpr const char *type = "type"; /**< <device type>. */
        static constexpr const char *role = "role"; /**< <device role: sink or source>. */
        static constexpr const char *roleSource = "source"; /**< <attribute role source value>. */
        /** optional: device address, char string less than 64. */
        static constexpr const char *address = "address";
    };

    static status_t deserialize(xmlDoc *doc, const xmlNode *root, PtrElement *element,
                                PtrSerializingCtx serializingContext);
    // Children: GainTraits (optional)
};

struct RouteTraits : public BaseSerializerTraits<AudioRoute, AudioRouteVector>
{
    static constexpr const char *tag = "route";
    static constexpr const char *collectionTag = "routes";

    struct Attributes
    {
        static constexpr const char *type = "type"; /**< <route type>: mix or mux. */
        static constexpr const char *typeMix = "mix"; /**< type attribute mix value. */
        static constexpr const char *sink = "sink"; /**< <sink: involved in this route>. */
        /** sources: all source that can be involved in this route. */
        static constexpr const char *sources = "sources";
    };

    typedef HwModule *PtrSerializingCtx;

    static status_t deserialize(xmlDoc *doc, const xmlNode *root, PtrElement *element,
                                PtrSerializingCtx ctx);
};

struct ModuleTraits : public BaseSerializerTraits<HwModule, HwModuleCollection>
{
    static constexpr const char *tag = "module";
    static constexpr const char *collectionTag = "modules";

    static constexpr const char *childAttachedDevicesTag = "attachedDevices";
    static constexpr const char *childAttachedDeviceTag = "item";
    static constexpr const char *childDefaultOutputDeviceTag = "defaultOutputDevice";

    struct Attributes
    {
        static constexpr const char *name = "name";
        static constexpr const char *version = "halVersion";
    };

    typedef AudioPolicyConfig *PtrSerializingCtx;

    static status_t deserialize(xmlDoc *doc, const xmlNode *root, PtrElement *element,
                                PtrSerializingCtx serializingContext);

    // Children: mixPortTraits, devicePortTraits, and routeTraits
    // Need to call deserialize on each child
};

struct GlobalConfigTraits
{
    static constexpr const char *tag = "globalConfiguration";

    struct Attributes
    {
        static constexpr const char *speakerDrcEnabled = "speaker_drc_enabled";
    };

    static status_t deserialize(const xmlNode *root, AudioPolicyConfig *config);
};

struct VolumeTraits : public BaseSerializerTraits<VolumeCurve, VolumeCurvesCollection>
{
    static constexpr const char *tag = "volume";
    static constexpr const char *collectionTag = "volumes";
    static constexpr const char *volumePointTag = "point";
    static constexpr const char *referenceTag = "reference";

    struct Attributes
    {
        static constexpr const char *stream = "stream";
        static constexpr const char *deviceCategory = "deviceCategory";
        static constexpr const char *reference = "ref";
        static constexpr const char *referenceName = "name";
    };

    static status_t deserialize(xmlDoc *doc, const xmlNode *root, PtrElement *element,
                                PtrSerializingCtx serializingContext);
    // No Children
};

class PolicySerializer
{
public:
    PolicySerializer() : mVersion{std::to_string(gMajor) + "." + std::to_string(gMinor)}
    {
        ALOGV("%s: Version=%s Root=%s", __func__, mVersion.c_str(), rootName);
    }
    status_t deserialize(const char *str, AudioPolicyConfig *config);

private:
    static constexpr const char *rootName = "audioPolicyConfiguration";
    static constexpr const char *versionAttribute = "version";
    static constexpr uint32_t gMajor = 1; /**< the major number of the policy xml format version. */
    static constexpr uint32_t gMinor = 0; /**< the minor number of the policy xml format version. */

    typedef AudioPolicyConfig Element;

    const std::string mVersion;

    // Children: ModulesTraits, VolumeTraits
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
    auto xmlValue = make_xmlUnique(xmlGetProp(cur, reinterpret_cast<const xmlChar*>(attribute)));
    if (xmlValue == nullptr) {
        return "";
    }
    std::string value(reinterpret_cast<const char*>(xmlValue.get()));
    return value;
}

template <class Trait>
const xmlNode* getReference(const xmlNode *cur, const std::string &refName)
{
    while (cur != NULL) {
        if (!xmlStrcmp(cur->name, reinterpret_cast<const xmlChar*>(Trait::collectionTag))) {
            const xmlNode *child = cur->children;
            while (child != NULL) {
                if ((!xmlStrcmp(child->name,
                                        reinterpret_cast<const xmlChar*>(Trait::referenceTag)))) {
                    std::string name = getXmlAttribute(child, Trait::Attributes::referenceName);
                    if (refName == name) {
                        return child;
                    }
                }
                child = child->next;
            }
        }
        cur = cur->next;
    }
    return NULL;
}

template <class Trait>
status_t deserializeCollection(xmlDoc *doc, const xmlNode *cur,
        typename Trait::Collection *collection,
        typename Trait::PtrSerializingCtx serializingContext)
{
    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if (xmlStrcmp(cur->name, reinterpret_cast<const xmlChar*>(Trait::collectionTag)) &&
                xmlStrcmp(cur->name, reinterpret_cast<const xmlChar*>(Trait::tag))) {
            cur = cur->next;
            continue;
        }
        const xmlNode *child = cur;
        if (!xmlStrcmp(child->name, reinterpret_cast<const xmlChar*>(Trait::collectionTag))) {
            child = child->xmlChildrenNode;
        }
        while (child != NULL) {
            if (!xmlStrcmp(child->name, reinterpret_cast<const xmlChar*>(Trait::tag))) {
                typename Trait::PtrElement element;
                status_t status = Trait::deserialize(doc, child, &element, serializingContext);
                if (status != NO_ERROR) {
                    return status;
                }
                if (collection->add(element) < 0) {
                    ALOGE("%s: could not add element to %s collection", __func__,
                          Trait::collectionTag);
                    return BAD_VALUE;
                }
            }
            child = child->next;
        }
        if (!xmlStrcmp(cur->name, reinterpret_cast<const xmlChar*>(Trait::tag))) {
            return NO_ERROR;
        }
        cur = cur->next;
    }
    return NO_ERROR;
}

status_t AudioGainTraits::deserialize(xmlDoc */*doc*/, const xmlNode *root, PtrElement *element,
                                      PtrSerializingCtx /*serializingContext*/)
{
    static uint32_t index = 0;
    PtrElement &gain = *element = new Element(index++, true);

    std::string mode = getXmlAttribute(root, Attributes::mode);
    if (!mode.empty()) {
        gain->setMode(GainModeConverter::maskFromString(mode));
    }

    std::string channelsLiteral = getXmlAttribute(root, Attributes::channelMask);
    if (!channelsLiteral.empty()) {
        gain->setChannelMask(channelMaskFromString(channelsLiteral));
    }

    std::string minValueMBLiteral = getXmlAttribute(root, Attributes::minValueMB);
    int32_t minValueMB;
    if (!minValueMBLiteral.empty() && convertTo(minValueMBLiteral, minValueMB)) {
        gain->setMinValueInMb(minValueMB);
    }

    std::string maxValueMBLiteral = getXmlAttribute(root, Attributes::maxValueMB);
    int32_t maxValueMB;
    if (!maxValueMBLiteral.empty() && convertTo(maxValueMBLiteral, maxValueMB)) {
        gain->setMaxValueInMb(maxValueMB);
    }

    std::string defaultValueMBLiteral = getXmlAttribute(root, Attributes::defaultValueMB);
    int32_t defaultValueMB;
    if (!defaultValueMBLiteral.empty() && convertTo(defaultValueMBLiteral, defaultValueMB)) {
        gain->setDefaultValueInMb(defaultValueMB);
    }

    std::string stepValueMBLiteral = getXmlAttribute(root, Attributes::stepValueMB);
    uint32_t stepValueMB;
    if (!stepValueMBLiteral.empty() && convertTo(stepValueMBLiteral, stepValueMB)) {
        gain->setStepValueInMb(stepValueMB);
    }

    std::string minRampMsLiteral = getXmlAttribute(root, Attributes::minRampMs);
    uint32_t minRampMs;
    if (!minRampMsLiteral.empty() && convertTo(minRampMsLiteral, minRampMs)) {
        gain->setMinRampInMs(minRampMs);
    }

    std::string maxRampMsLiteral = getXmlAttribute(root, Attributes::maxRampMs);
    uint32_t maxRampMs;
    if (!maxRampMsLiteral.empty() && convertTo(maxRampMsLiteral, maxRampMs)) {
        gain->setMaxRampInMs(maxRampMs);
    }
    ALOGV("%s: adding new gain mode %08x channel mask %08x min mB %d max mB %d", __func__,
          gain->getMode(), gain->getChannelMask(), gain->getMinValueInMb(),
          gain->getMaxValueInMb());

    if (gain->getMode() == 0) {
        return BAD_VALUE;
    }
    return NO_ERROR;
}

status_t AudioProfileTraits::deserialize(xmlDoc */*doc*/, const xmlNode *root, PtrElement *element,
                                         PtrSerializingCtx /*serializingContext*/)
{
    std::string samplingRates = getXmlAttribute(root, Attributes::samplingRates);
    std::string format = getXmlAttribute(root, Attributes::format);
    std::string channels = getXmlAttribute(root, Attributes::channelMasks);

    PtrElement &profile = *element = new Element(formatFromString(format, gDynamicFormat),
            channelMasksFromString(channels, ","),
            samplingRatesFromString(samplingRates, ","));

    profile->setDynamicFormat(profile->getFormat() == gDynamicFormat);
    profile->setDynamicChannels(profile->getChannels().isEmpty());
    profile->setDynamicRate(profile->getSampleRates().isEmpty());

    return NO_ERROR;
}

status_t MixPortTraits::deserialize(xmlDoc *doc, const xmlNode *child, PtrElement *element,
                                    PtrSerializingCtx /*serializingContext*/)
{
    std::string name = getXmlAttribute(child, Attributes::name);
    if (name.empty()) {
        ALOGE("%s: No %s found", __func__, Attributes::name);
        return BAD_VALUE;
    }
    ALOGV("%s: %s %s=%s", __func__, tag, Attributes::name, name.c_str());
    std::string role = getXmlAttribute(child, Attributes::role);
    if (role.empty()) {
        ALOGE("%s: No %s found", __func__, Attributes::role);
        return BAD_VALUE;
    }
    ALOGV("%s: Role=%s", __func__, role.c_str());
    audio_port_role_t portRole = (role == Attributes::roleSource) ?
            AUDIO_PORT_ROLE_SOURCE : AUDIO_PORT_ROLE_SINK;

    PtrElement &mixPort = *element = new Element(String8(name.c_str()), portRole);

    AudioProfileTraits::Collection profiles;
    status_t status = deserializeCollection<AudioProfileTraits>(doc, child, &profiles, NULL);
    if (status != NO_ERROR) {
        return status;
    }
    if (profiles.isEmpty()) {
        profiles.add(AudioProfile::createFullDynamic());
    }
    mixPort->setAudioProfiles(profiles);

    std::string flags = getXmlAttribute(child, Attributes::flags);
    if (!flags.empty()) {
        // Source role
        if (portRole == AUDIO_PORT_ROLE_SOURCE) {
            mixPort->setFlags(OutputFlagConverter::maskFromString(flags));
        } else {
            // Sink role
            mixPort->setFlags(InputFlagConverter::maskFromString(flags));
        }
    }
    std::string maxOpenCount = getXmlAttribute(child, Attributes::maxOpenCount);
    if (!maxOpenCount.empty()) {
        convertTo(maxOpenCount, mixPort->maxOpenCount);
    }
    std::string maxActiveCount = getXmlAttribute(child, Attributes::maxActiveCount);
    if (!maxActiveCount.empty()) {
        convertTo(maxActiveCount, mixPort->maxActiveCount);
    }
    // Deserialize children
    AudioGainTraits::Collection gains;
    status = deserializeCollection<AudioGainTraits>(doc, child, &gains, NULL);
    if (status != NO_ERROR) {
        return status;
    }
    mixPort->setGains(gains);

    return NO_ERROR;
}

status_t DevicePortTraits::deserialize(xmlDoc *doc, const xmlNode *root, PtrElement *element,
                                       PtrSerializingCtx /*serializingContext*/)
{
    std::string name = getXmlAttribute(root, Attributes::tagName);
    if (name.empty()) {
        ALOGE("%s: No %s found", __func__, Attributes::tagName);
        return BAD_VALUE;
    }
    ALOGV("%s: %s %s=%s", __func__, tag, Attributes::tagName, name.c_str());
    std::string typeName = getXmlAttribute(root, Attributes::type);
    if (typeName.empty()) {
        ALOGE("%s: no type for %s", __func__, name.c_str());
        return BAD_VALUE;
    }
    ALOGV("%s: %s %s=%s", __func__, tag, Attributes::type, typeName.c_str());
    std::string role = getXmlAttribute(root, Attributes::role);
    if (role.empty()) {
        ALOGE("%s: No %s found", __func__, Attributes::role);
        return BAD_VALUE;
    }
    ALOGV("%s: %s %s=%s", __func__, tag, Attributes::role, role.c_str());
    audio_port_role_t portRole = (role == Attributes::roleSource) ?
                AUDIO_PORT_ROLE_SOURCE : AUDIO_PORT_ROLE_SINK;

    audio_devices_t type = AUDIO_DEVICE_NONE;
    if (!deviceFromString(typeName, type) ||
            (!audio_is_input_device(type) && portRole == AUDIO_PORT_ROLE_SOURCE) ||
            (!audio_is_output_devices(type) && portRole == AUDIO_PORT_ROLE_SINK)) {
        ALOGW("%s: bad type %08x", __func__, type);
        return BAD_VALUE;
    }
    PtrElement &deviceDesc = *element = new Element(type, String8(name.c_str()));

    std::string address = getXmlAttribute(root, Attributes::address);
    if (!address.empty()) {
        ALOGV("%s: address=%s for %s", __func__, address.c_str(), name.c_str());
        deviceDesc->mAddress = String8(address.c_str());
    }

    AudioProfileTraits::Collection profiles;
    status_t status = deserializeCollection<AudioProfileTraits>(doc, root, &profiles, NULL);
    if (status != NO_ERROR) {
        return status;
    }
    if (profiles.isEmpty()) {
        profiles.add(AudioProfile::createFullDynamic());
    }
    deviceDesc->setAudioProfiles(profiles);

    // Deserialize AudioGain children
    status = deserializeCollection<AudioGainTraits>(doc, root, &deviceDesc->mGains, NULL);
    if (status != NO_ERROR) {
        return status;
    }
    ALOGV("%s: adding device tag %s type %08x address %s", __func__,
          deviceDesc->getName().string(), type, deviceDesc->mAddress.string());
    return NO_ERROR;
}

status_t RouteTraits::deserialize(xmlDoc */*doc*/, const xmlNode *root, PtrElement *element,
                                  PtrSerializingCtx ctx)
{
    std::string type = getXmlAttribute(root, Attributes::type);
    if (type.empty()) {
        ALOGE("%s: No %s found", __func__, Attributes::type);
        return BAD_VALUE;
    }
    audio_route_type_t routeType = (type == Attributes::typeMix) ?
                AUDIO_ROUTE_MIX : AUDIO_ROUTE_MUX;

    ALOGV("%s: %s %s=%s", __func__, tag, Attributes::type, type.c_str());
    PtrElement &route = *element = new Element(routeType);

    std::string sinkAttr = getXmlAttribute(root, Attributes::sink);
    if (sinkAttr.empty()) {
        ALOGE("%s: No %s found", __func__, Attributes::sink);
        return BAD_VALUE;
    }
    // Convert Sink name to port pointer
    sp<AudioPort> sink = ctx->findPortByTagName(String8(sinkAttr.c_str()));
    if (sink == NULL) {
        ALOGE("%s: no sink found with name=%s", __func__, sinkAttr.c_str());
        return BAD_VALUE;
    }
    route->setSink(sink);

    std::string sourcesAttr = getXmlAttribute(root, Attributes::sources);
    if (sourcesAttr.empty()) {
        ALOGE("%s: No %s found", __func__, Attributes::sources);
        return BAD_VALUE;
    }
    // Tokenize and Convert Sources name to port pointer
    AudioPortVector sources;
    std::unique_ptr<char[]> sourcesLiteral{strndup(
                sourcesAttr.c_str(), strlen(sourcesAttr.c_str()))};
    char *devTag = strtok(sourcesLiteral.get(), ",");
    while (devTag != NULL) {
        if (strlen(devTag) != 0) {
            sp<AudioPort> source = ctx->findPortByTagName(String8(devTag));
            if (source == NULL) {
                ALOGE("%s: no source found with name=%s", __func__, devTag);
                return BAD_VALUE;
            }
            sources.add(source);
        }
        devTag = strtok(NULL, ",");
    }

    sink->addRoute(route);
    for (size_t i = 0; i < sources.size(); i++) {
        sp<AudioPort> source = sources.itemAt(i);
        source->addRoute(route);
    }
    route->setSources(sources);
    return NO_ERROR;
}

status_t ModuleTraits::deserialize(xmlDocPtr doc, const xmlNode *root, PtrElement *element,
                                   PtrSerializingCtx ctx)
{
    std::string name = getXmlAttribute(root, Attributes::name);
    if (name.empty()) {
        ALOGE("%s: No %s found", __func__, Attributes::name);
        return BAD_VALUE;
    }
    uint32_t versionMajor = 0, versionMinor = 0;
    std::string versionLiteral = getXmlAttribute(root, Attributes::version);
    if (!versionLiteral.empty()) {
        sscanf(versionLiteral.c_str(), "%u.%u", &versionMajor, &versionMinor);
        ALOGV("%s: mHalVersion = major %u minor %u",  __func__,
              versionMajor, versionMajor);
    }

    ALOGV("%s: %s %s=%s", __func__, tag, Attributes::name, name.c_str());

    PtrElement &module = *element = new Element(name.c_str(), versionMajor, versionMinor);

    // Deserialize childrens: Audio Mix Port, Audio Device Ports (Source/Sink), Audio Routes
    MixPortTraits::Collection mixPorts;
    status_t status = deserializeCollection<MixPortTraits>(doc, root, &mixPorts, NULL);
    if (status != NO_ERROR) {
        return status;
    }
    module->setProfiles(mixPorts);

    DevicePortTraits::Collection devicePorts;
    status = deserializeCollection<DevicePortTraits>(doc, root, &devicePorts, NULL);
    if (status != NO_ERROR) {
        return status;
    }
    module->setDeclaredDevices(devicePorts);

    RouteTraits::Collection routes;
    status = deserializeCollection<RouteTraits>(doc, root, &routes, module.get());
    if (status != NO_ERROR) {
        return status;
    }
    module->setRoutes(routes);

    const xmlNode *children = root->xmlChildrenNode;
    while (children != NULL) {
        if (!xmlStrcmp(children->name, reinterpret_cast<const xmlChar*>(childAttachedDevicesTag))) {
            ALOGV("%s: %s %s found", __func__, tag, childAttachedDevicesTag);
            const xmlNode *child = children->xmlChildrenNode;
            while (child != NULL) {
                if (!xmlStrcmp(child->name,
                                reinterpret_cast<const xmlChar*>(childAttachedDeviceTag))) {
                    auto attachedDevice = make_xmlUnique(xmlNodeListGetString(
                                    doc, child->xmlChildrenNode, 1));
                    if (attachedDevice != nullptr) {
                        ALOGV("%s: %s %s=%s", __func__, tag, childAttachedDeviceTag,
                                reinterpret_cast<const char*>(attachedDevice.get()));
                        sp<DeviceDescriptor> device = module->getDeclaredDevices().
                                getDeviceFromTagName(String8(reinterpret_cast<const char*>(
                                                        attachedDevice.get())));
                        ctx->addAvailableDevice(device);
                    }
                }
                child = child->next;
            }
        }
        if (!xmlStrcmp(children->name,
                        reinterpret_cast<const xmlChar*>(childDefaultOutputDeviceTag))) {
            auto defaultOutputDevice = make_xmlUnique(xmlNodeListGetString(
                            doc, children->xmlChildrenNode, 1));
            if (defaultOutputDevice != nullptr) {
                ALOGV("%s: %s %s=%s", __func__, tag, childDefaultOutputDeviceTag,
                        reinterpret_cast<const char*>(defaultOutputDevice.get()));
                sp<DeviceDescriptor> device = module->getDeclaredDevices().getDeviceFromTagName(
                        String8(reinterpret_cast<const char*>(defaultOutputDevice.get())));
                if (device != 0 && ctx->getDefaultOutputDevice() == 0) {
                    ctx->setDefaultOutputDevice(device);
                    ALOGV("%s: default is %08x",
                            __func__, ctx->getDefaultOutputDevice()->type());
                }
            }
        }
        children = children->next;
    }
    return NO_ERROR;
}

status_t GlobalConfigTraits::deserialize(const xmlNode *cur, AudioPolicyConfig *config)
{
    const xmlNode *root = cur->xmlChildrenNode;
    while (root != NULL) {
        if (!xmlStrcmp(root->name, reinterpret_cast<const xmlChar*>(tag))) {
            std::string speakerDrcEnabled =
                    getXmlAttribute(root, Attributes::speakerDrcEnabled);
            bool isSpeakerDrcEnabled;
            if (!speakerDrcEnabled.empty() &&
                    convertTo<std::string, bool>(speakerDrcEnabled, isSpeakerDrcEnabled)) {
                config->setSpeakerDrcEnabled(isSpeakerDrcEnabled);
            }
            return NO_ERROR;
        }
        root = root->next;
    }
    return NO_ERROR;
}

status_t VolumeTraits::deserialize(xmlDoc *doc, const xmlNode *root, PtrElement *element,
                                   PtrSerializingCtx /*serializingContext*/)
{
    std::string streamTypeLiteral = getXmlAttribute(root, Attributes::stream);
    if (streamTypeLiteral.empty()) {
        ALOGE("%s: No %s found", __func__, Attributes::stream);
        return BAD_VALUE;
    }
    audio_stream_type_t streamType;
    if (!StreamTypeConverter::fromString(streamTypeLiteral, streamType)) {
        ALOGE("%s: Invalid %s", __func__, Attributes::stream);
        return BAD_VALUE;
    }
    std::string deviceCategoryLiteral = getXmlAttribute(root, Attributes::deviceCategory);
    if (deviceCategoryLiteral.empty()) {
        ALOGE("%s: No %s found", __func__, Attributes::deviceCategory);
        return BAD_VALUE;
    }
    device_category deviceCategory;
    if (!DeviceCategoryConverter::fromString(deviceCategoryLiteral, deviceCategory)) {
        ALOGE("%s: Invalid %s=%s", __func__, Attributes::deviceCategory,
              deviceCategoryLiteral.c_str());
        return BAD_VALUE;
    }

    std::string referenceName = getXmlAttribute(root, Attributes::reference);
    const xmlNode *ref = NULL;
    if (!referenceName.empty()) {
        ref = getReference<VolumeTraits>(root->parent, referenceName);
        if (ref == NULL) {
            ALOGE("%s: No reference Ptr found for %s", __func__, referenceName.c_str());
            return BAD_VALUE;
        }
    }

    PtrElement &volCurve = *element = new Element(deviceCategory, streamType);

    const xmlNode *child = referenceName.empty() ? root->xmlChildrenNode : ref->xmlChildrenNode;
    while (child != NULL) {
        if (!xmlStrcmp(child->name, reinterpret_cast<const xmlChar*>(volumePointTag))) {
            auto pointDefinition = make_xmlUnique(xmlNodeListGetString(
                            doc, child->xmlChildrenNode, 1));
            if (pointDefinition == nullptr) {
                return BAD_VALUE;
            }
            ALOGV("%s: %s=%s",
                    __func__, tag, reinterpret_cast<const char*>(pointDefinition.get()));
            Vector<int32_t> point;
            collectionFromString<DefaultTraits<int32_t>>(
                    reinterpret_cast<const char*>(pointDefinition.get()), point, ",");
            if (point.size() != 2) {
                ALOGE("%s: Invalid %s: %s", __func__, volumePointTag,
                        reinterpret_cast<const char*>(pointDefinition.get()));
                return BAD_VALUE;
            }
            volCurve->add(CurvePoint(point[0], point[1]));
        }
        child = child->next;
    }
    return NO_ERROR;
}

status_t PolicySerializer::deserialize(const char *configFile, AudioPolicyConfig *config)
{
    auto doc = make_xmlUnique(xmlParseFile(configFile));
    if (doc == nullptr) {
        ALOGE("%s: Could not parse %s document.", __func__, configFile);
        return BAD_VALUE;
    }
    xmlNodePtr cur = xmlDocGetRootElement(doc.get());
    if (cur == NULL) {
        ALOGE("%s: Could not parse %s document: empty.", __func__, configFile);
        return BAD_VALUE;
    }
    if (xmlXIncludeProcess(doc.get()) < 0) {
        ALOGE("%s: libxml failed to resolve XIncludes on %s document.", __func__, configFile);
    }

    if (xmlStrcmp(cur->name, reinterpret_cast<const xmlChar*>(rootName)))  {
        ALOGE("%s: No %s root element found in xml data %s.", __func__, rootName,
                reinterpret_cast<const char*>(cur->name));
        return BAD_VALUE;
    }

    std::string version = getXmlAttribute(cur, versionAttribute);
    if (version.empty()) {
        ALOGE("%s: No version found in root node %s", __func__, rootName);
        return BAD_VALUE;
    }
    if (version != mVersion) {
        ALOGE("%s: Version does not match; expect %s got %s", __func__, mVersion.c_str(),
              version.c_str());
        return BAD_VALUE;
    }
    // Lets deserialize children
    // Modules
    ModuleTraits::Collection modules;
    status_t status = deserializeCollection<ModuleTraits>(doc.get(), cur, &modules, config);
    if (status != NO_ERROR) {
        return status;
    }
    config->setHwModules(modules);

    // deserialize volume section
    VolumeTraits::Collection volumes;
    status = deserializeCollection<VolumeTraits>(doc.get(), cur, &volumes, config);
    if (status != NO_ERROR) {
        return status;
    }
    config->setVolumes(volumes);

    // Global Configuration
    GlobalConfigTraits::deserialize(cur, config);

    return android::OK;
}

}  // namespace

status_t deserializeAudioPolicyFile(const char *fileName, AudioPolicyConfig *config)
{
    PolicySerializer serializer;
    return serializer.deserialize(fileName, config);
}

} // namespace android
