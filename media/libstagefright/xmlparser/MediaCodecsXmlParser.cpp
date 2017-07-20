/*
 * Copyright 2017, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "MediaCodecsXmlParser"
#include <utils/Log.h>

#include <media/stagefright/xmlparser/MediaCodecsXmlParser.h>

#include <media/MediaCodecInfo.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/AUtils.h>
#include <media/stagefright/MediaErrors.h>

#include <sys/stat.h>

#include <expat.h>
#include <string>

#define MEDIA_CODECS_CONFIG_FILE_PATH_MAX_LENGTH 256

namespace android {

namespace { // Local variables and functions

const char *kProfilingResults =
        "/data/misc/media/media_codecs_profiling_results.xml";

// Treblized media codec list will be located in /odm/etc or /vendor/etc.
const char *kConfigLocationList[] =
        {"/odm/etc", "/vendor/etc", "/etc"};
constexpr int kConfigLocationListSize =
        (sizeof(kConfigLocationList) / sizeof(kConfigLocationList[0]));

bool findMediaCodecListFileFullPath(
        const char *file_name, std::string *out_path) {
    for (int i = 0; i < kConfigLocationListSize; i++) {
        *out_path = std::string(kConfigLocationList[i]) + "/" + file_name;
        struct stat file_stat;
        if (stat(out_path->c_str(), &file_stat) == 0 &&
                S_ISREG(file_stat.st_mode)) {
            return true;
        }
    }
    return false;
}

// Find TypeInfo by name.
std::vector<TypeInfo>::iterator findTypeInfo(
        CodecInfo &codecInfo, const AString &typeName) {
    return std::find_if(
            codecInfo.mTypes.begin(), codecInfo.mTypes.end(),
            [typeName](const auto &typeInfo) {
                return typeInfo.mName == typeName;
            });
}

// Convert a string into a boolean value.
bool ParseBoolean(const char *s) {
    if (!strcasecmp(s, "true") || !strcasecmp(s, "yes") || !strcasecmp(s, "y")) {
        return true;
    }
    char *end;
    unsigned long res = strtoul(s, &end, 10);
    return *s != '\0' && *end == '\0' && res > 0;
}

} // unnamed namespace

MediaCodecsXmlParser::MediaCodecsXmlParser() :
    mInitCheck(NO_INIT),
    mUpdate(false) {
    std::string config_file_path;
    if (findMediaCodecListFileFullPath(
            "media_codecs.xml", &config_file_path)) {
        parseTopLevelXMLFile(config_file_path.c_str(), false);
    } else {
        mInitCheck = NAME_NOT_FOUND;
    }
    if (findMediaCodecListFileFullPath(
            "media_codecs_performance.xml", &config_file_path)) {
        parseTopLevelXMLFile(config_file_path.c_str(), true);
    }
    parseTopLevelXMLFile(kProfilingResults, true);
}

void MediaCodecsXmlParser::parseTopLevelXMLFile(
        const char *codecs_xml, bool ignore_errors) {
    // get href_base
    const char *href_base_end = strrchr(codecs_xml, '/');
    if (href_base_end != NULL) {
        mHrefBase = AString(codecs_xml, href_base_end - codecs_xml + 1);
    }

    mInitCheck = OK; // keeping this here for safety
    mCurrentSection = SECTION_TOPLEVEL;
    mDepth = 0;

    parseXMLFile(codecs_xml);

    if (mInitCheck != OK) {
        if (ignore_errors) {
            mInitCheck = OK;
            return;
        }
        mCodecInfos.clear();
        return;
    }
}

MediaCodecsXmlParser::~MediaCodecsXmlParser() {
}

status_t MediaCodecsXmlParser::initCheck() const {
    return mInitCheck;
}

void MediaCodecsXmlParser::parseXMLFile(const char *path) {
    FILE *file = fopen(path, "r");

    if (file == NULL) {
        ALOGW("unable to open media codecs configuration xml file: %s", path);
        mInitCheck = NAME_NOT_FOUND;
        return;
    }

    ALOGV("Start parsing %s", path);
    XML_Parser parser = ::XML_ParserCreate(NULL);
    CHECK(parser != NULL);

    ::XML_SetUserData(parser, this);
    ::XML_SetElementHandler(
            parser, StartElementHandlerWrapper, EndElementHandlerWrapper);

    const int BUFF_SIZE = 512;
    while (mInitCheck == OK) {
        void *buff = ::XML_GetBuffer(parser, BUFF_SIZE);
        if (buff == NULL) {
            ALOGE("failed in call to XML_GetBuffer()");
            mInitCheck = UNKNOWN_ERROR;
            break;
        }

        int bytes_read = ::fread(buff, 1, BUFF_SIZE, file);
        if (bytes_read < 0) {
            ALOGE("failed in call to read");
            mInitCheck = ERROR_IO;
            break;
        }

        XML_Status status = ::XML_ParseBuffer(parser, bytes_read, bytes_read == 0);
        if (status != XML_STATUS_OK) {
            ALOGE("malformed (%s)", ::XML_ErrorString(::XML_GetErrorCode(parser)));
            mInitCheck = ERROR_MALFORMED;
            break;
        }

        if (bytes_read == 0) {
            break;
        }
    }

    ::XML_ParserFree(parser);

    fclose(file);
    file = NULL;
}

// static
void MediaCodecsXmlParser::StartElementHandlerWrapper(
        void *me, const char *name, const char **attrs) {
    static_cast<MediaCodecsXmlParser *>(me)->startElementHandler(name, attrs);
}

// static
void MediaCodecsXmlParser::EndElementHandlerWrapper(void *me, const char *name) {
    static_cast<MediaCodecsXmlParser *>(me)->endElementHandler(name);
}

status_t MediaCodecsXmlParser::includeXMLFile(const char **attrs) {
    const char *href = NULL;
    size_t i = 0;
    while (attrs[i] != NULL) {
        if (!strcmp(attrs[i], "href")) {
            if (attrs[i + 1] == NULL) {
                return -EINVAL;
            }
            href = attrs[i + 1];
            ++i;
        } else {
            ALOGE("includeXMLFile: unrecognized attribute: %s", attrs[i]);
            return -EINVAL;
        }
        ++i;
    }

    // For security reasons and for simplicity, file names can only contain
    // [a-zA-Z0-9_.] and must start with  media_codecs_ and end with .xml
    for (i = 0; href[i] != '\0'; i++) {
        if (href[i] == '.' || href[i] == '_' ||
                (href[i] >= '0' && href[i] <= '9') ||
                (href[i] >= 'A' && href[i] <= 'Z') ||
                (href[i] >= 'a' && href[i] <= 'z')) {
            continue;
        }
        ALOGE("invalid include file name: %s", href);
        return -EINVAL;
    }

    AString filename = href;
    if (!filename.startsWith("media_codecs_") ||
        !filename.endsWith(".xml")) {
        ALOGE("invalid include file name: %s", href);
        return -EINVAL;
    }
    filename.insert(mHrefBase, 0);

    parseXMLFile(filename.c_str());
    return mInitCheck;
}

void MediaCodecsXmlParser::startElementHandler(
        const char *name, const char **attrs) {
    if (mInitCheck != OK) {
        return;
    }

    bool inType = true;

    if (!strcmp(name, "Include")) {
        mInitCheck = includeXMLFile(attrs);
        if (mInitCheck == OK) {
            mPastSections.push(mCurrentSection);
            mCurrentSection = SECTION_INCLUDE;
        }
        ++mDepth;
        return;
    }

    switch (mCurrentSection) {
        case SECTION_TOPLEVEL:
        {
            if (!strcmp(name, "Decoders")) {
                mCurrentSection = SECTION_DECODERS;
            } else if (!strcmp(name, "Encoders")) {
                mCurrentSection = SECTION_ENCODERS;
            } else if (!strcmp(name, "Settings")) {
                mCurrentSection = SECTION_SETTINGS;
            }
            break;
        }

        case SECTION_SETTINGS:
        {
            if (!strcmp(name, "Setting")) {
                mInitCheck = addSettingFromAttributes(attrs);
            }
            break;
        }

        case SECTION_DECODERS:
        {
            if (!strcmp(name, "MediaCodec")) {
                mInitCheck =
                    addMediaCodecFromAttributes(false /* encoder */, attrs);

                mCurrentSection = SECTION_DECODER;
            }
            break;
        }

        case SECTION_ENCODERS:
        {
            if (!strcmp(name, "MediaCodec")) {
                mInitCheck =
                    addMediaCodecFromAttributes(true /* encoder */, attrs);

                mCurrentSection = SECTION_ENCODER;
            }
            break;
        }

        case SECTION_DECODER:
        case SECTION_ENCODER:
        {
            if (!strcmp(name, "Quirk")) {
                mInitCheck = addQuirk(attrs);
            } else if (!strcmp(name, "Type")) {
                mInitCheck = addTypeFromAttributes(attrs, (mCurrentSection == SECTION_ENCODER));
                mCurrentSection =
                    (mCurrentSection == SECTION_DECODER
                            ? SECTION_DECODER_TYPE : SECTION_ENCODER_TYPE);
            }
        }
        inType = false;
        // fall through

        case SECTION_DECODER_TYPE:
        case SECTION_ENCODER_TYPE:
        {
            // ignore limits and features specified outside of type
            bool outside = !inType && mCurrentType == mCodecInfos[mCurrentName].mTypes.end();
            if (outside && (!strcmp(name, "Limit") || !strcmp(name, "Feature"))) {
                ALOGW("ignoring %s specified outside of a Type", name);
            } else if (!strcmp(name, "Limit")) {
                mInitCheck = addLimit(attrs);
            } else if (!strcmp(name, "Feature")) {
                mInitCheck = addFeature(attrs);
            }
            break;
        }

        default:
            break;
    }

    ++mDepth;
}

void MediaCodecsXmlParser::endElementHandler(const char *name) {
    if (mInitCheck != OK) {
        return;
    }

    switch (mCurrentSection) {
        case SECTION_SETTINGS:
        {
            if (!strcmp(name, "Settings")) {
                mCurrentSection = SECTION_TOPLEVEL;
            }
            break;
        }

        case SECTION_DECODERS:
        {
            if (!strcmp(name, "Decoders")) {
                mCurrentSection = SECTION_TOPLEVEL;
            }
            break;
        }

        case SECTION_ENCODERS:
        {
            if (!strcmp(name, "Encoders")) {
                mCurrentSection = SECTION_TOPLEVEL;
            }
            break;
        }

        case SECTION_DECODER_TYPE:
        case SECTION_ENCODER_TYPE:
        {
            if (!strcmp(name, "Type")) {
                mCurrentSection =
                    (mCurrentSection == SECTION_DECODER_TYPE
                            ? SECTION_DECODER : SECTION_ENCODER);

                mCurrentType = mCodecInfos[mCurrentName].mTypes.end();
            }
            break;
        }

        case SECTION_DECODER:
        {
            if (!strcmp(name, "MediaCodec")) {
                mCurrentSection = SECTION_DECODERS;
                mCurrentName.clear();
            }
            break;
        }

        case SECTION_ENCODER:
        {
            if (!strcmp(name, "MediaCodec")) {
                mCurrentSection = SECTION_ENCODERS;
                mCurrentName.clear();
            }
            break;
        }

        case SECTION_INCLUDE:
        {
            if (!strcmp(name, "Include") && mPastSections.size() > 0) {
                mCurrentSection = mPastSections.top();
                mPastSections.pop();
            }
            break;
        }

        default:
            break;
    }

    --mDepth;
}

status_t MediaCodecsXmlParser::addSettingFromAttributes(const char **attrs) {
    const char *name = NULL;
    const char *value = NULL;
    const char *update = NULL;

    size_t i = 0;
    while (attrs[i] != NULL) {
        if (!strcmp(attrs[i], "name")) {
            if (attrs[i + 1] == NULL) {
                ALOGE("addSettingFromAttributes: name is null");
                return -EINVAL;
            }
            name = attrs[i + 1];
            ++i;
        } else if (!strcmp(attrs[i], "value")) {
            if (attrs[i + 1] == NULL) {
                ALOGE("addSettingFromAttributes: value is null");
                return -EINVAL;
            }
            value = attrs[i + 1];
            ++i;
        } else if (!strcmp(attrs[i], "update")) {
            if (attrs[i + 1] == NULL) {
                ALOGE("addSettingFromAttributes: update is null");
                return -EINVAL;
            }
            update = attrs[i + 1];
            ++i;
        } else {
            ALOGE("addSettingFromAttributes: unrecognized attribute: %s", attrs[i]);
            return -EINVAL;
        }

        ++i;
    }

    if (name == NULL || value == NULL) {
        ALOGE("addSettingFromAttributes: name or value unspecified");
        return -EINVAL;
    }

    mUpdate = (update != NULL) && ParseBoolean(update);
    if (mUpdate != (mGlobalSettings.count(name) > 0)) {
        ALOGE("addSettingFromAttributes: updating non-existing setting");
        return -EINVAL;
    }
    mGlobalSettings[name] = value;

    return OK;
}

status_t MediaCodecsXmlParser::addMediaCodecFromAttributes(
        bool encoder, const char **attrs) {
    const char *name = NULL;
    const char *type = NULL;
    const char *update = NULL;

    size_t i = 0;
    while (attrs[i] != NULL) {
        if (!strcmp(attrs[i], "name")) {
            if (attrs[i + 1] == NULL) {
                ALOGE("addMediaCodecFromAttributes: name is null");
                return -EINVAL;
            }
            name = attrs[i + 1];
            ++i;
        } else if (!strcmp(attrs[i], "type")) {
            if (attrs[i + 1] == NULL) {
                ALOGE("addMediaCodecFromAttributes: type is null");
                return -EINVAL;
            }
            type = attrs[i + 1];
            ++i;
        } else if (!strcmp(attrs[i], "update")) {
            if (attrs[i + 1] == NULL) {
                ALOGE("addMediaCodecFromAttributes: update is null");
                return -EINVAL;
            }
            update = attrs[i + 1];
            ++i;
        } else {
            ALOGE("addMediaCodecFromAttributes: unrecognized attribute: %s", attrs[i]);
            return -EINVAL;
        }

        ++i;
    }

    if (name == NULL) {
        ALOGE("addMediaCodecFromAttributes: name not found");
        return -EINVAL;
    }

    mUpdate = (update != NULL) && ParseBoolean(update);
    if (mUpdate != (mCodecInfos.count(name) > 0)) {
        ALOGE("addMediaCodecFromAttributes: updating non-existing codec or vice versa");
        return -EINVAL;
    }

    CodecInfo *info = &mCodecInfos[name];
    if (mUpdate) {
        // existing codec
        mCurrentName = name;
        mCurrentType = info->mTypes.begin();
        if (type != NULL) {
            // existing type
            mCurrentType = findTypeInfo(*info, type);
            if (mCurrentType == info->mTypes.end()) {
                ALOGE("addMediaCodecFromAttributes: updating non-existing type");
                return -EINVAL;
            }
        }
    } else {
        // new codec
        mCurrentName = name;
        mQuirks[name].clear();
        info->mTypes.clear();
        info->mTypes.emplace_back();
        mCurrentType = --info->mTypes.end();
        mCurrentType->mName = type;
        info->mIsEncoder = encoder;
    }

    return OK;
}

status_t MediaCodecsXmlParser::addQuirk(const char **attrs) {
    const char *name = NULL;

    size_t i = 0;
    while (attrs[i] != NULL) {
        if (!strcmp(attrs[i], "name")) {
            if (attrs[i + 1] == NULL) {
                ALOGE("addQuirk: name is null");
                return -EINVAL;
            }
            name = attrs[i + 1];
            ++i;
        } else {
            ALOGE("addQuirk: unrecognized attribute: %s", attrs[i]);
            return -EINVAL;
        }

        ++i;
    }

    if (name == NULL) {
        ALOGE("addQuirk: name not found");
        return -EINVAL;
    }

    mQuirks[mCurrentName].emplace_back(name);
    return OK;
}

status_t MediaCodecsXmlParser::addTypeFromAttributes(const char **attrs, bool encoder) {
    const char *name = NULL;
    const char *update = NULL;

    size_t i = 0;
    while (attrs[i] != NULL) {
        if (!strcmp(attrs[i], "name")) {
            if (attrs[i + 1] == NULL) {
                ALOGE("addTypeFromAttributes: name is null");
                return -EINVAL;
            }
            name = attrs[i + 1];
            ++i;
        } else if (!strcmp(attrs[i], "update")) {
            if (attrs[i + 1] == NULL) {
                ALOGE("addTypeFromAttributes: update is null");
                return -EINVAL;
            }
            update = attrs[i + 1];
            ++i;
        } else {
            ALOGE("addTypeFromAttributes: unrecognized attribute: %s", attrs[i]);
            return -EINVAL;
        }

        ++i;
    }

    if (name == NULL) {
        return -EINVAL;
    }

    CodecInfo *info = &mCodecInfos[mCurrentName];
    info->mIsEncoder = encoder;
    mCurrentType = findTypeInfo(*info, name);
    if (!mUpdate) {
        if (mCurrentType != info->mTypes.end()) {
            ALOGE("addTypeFromAttributes: re-defining existing type without update");
            return -EINVAL;
        }
        info->mTypes.emplace_back();
        mCurrentType = --info->mTypes.end();
    } else if (mCurrentType == info->mTypes.end()) {
        ALOGE("addTypeFromAttributes: updating non-existing type");
        return -EINVAL;
    }

    return OK;
}

static status_t limitFoundMissingAttr(const AString &name, const char *attr, bool found = true) {
    ALOGE("limit '%s' with %s'%s' attribute", name.c_str(),
            (found ? "" : "no "), attr);
    return -EINVAL;
}

static status_t limitError(const AString &name, const char *msg) {
    ALOGE("limit '%s' %s", name.c_str(), msg);
    return -EINVAL;
}

static status_t limitInvalidAttr(const AString &name, const char *attr, const AString &value) {
    ALOGE("limit '%s' with invalid '%s' attribute (%s)", name.c_str(),
            attr, value.c_str());
    return -EINVAL;
}

status_t MediaCodecsXmlParser::addLimit(const char **attrs) {
    sp<AMessage> msg = new AMessage();

    size_t i = 0;
    while (attrs[i] != NULL) {
        if (attrs[i + 1] == NULL) {
            ALOGE("addLimit: limit is not given");
            return -EINVAL;
        }

        // attributes with values
        if (!strcmp(attrs[i], "name")
                || !strcmp(attrs[i], "default")
                || !strcmp(attrs[i], "in")
                || !strcmp(attrs[i], "max")
                || !strcmp(attrs[i], "min")
                || !strcmp(attrs[i], "range")
                || !strcmp(attrs[i], "ranges")
                || !strcmp(attrs[i], "scale")
                || !strcmp(attrs[i], "value")) {
            msg->setString(attrs[i], attrs[i + 1]);
            ++i;
        } else {
            ALOGE("addLimit: unrecognized limit: %s", attrs[i]);
            return -EINVAL;
        }
        ++i;
    }

    AString name;
    if (!msg->findString("name", &name)) {
        ALOGE("limit with no 'name' attribute");
        return -EINVAL;
    }

    // size, blocks, bitrate, frame-rate, blocks-per-second, aspect-ratio,
    // measured-frame-rate, measured-blocks-per-second: range
    // quality: range + default + [scale]
    // complexity: range + default
    bool found;
    if (mCurrentType == mCodecInfos[mCurrentName].mTypes.end()) {
        ALOGW("ignoring null type");
        return OK;
    }

    if (name == "aspect-ratio" || name == "bitrate" || name == "block-count"
            || name == "blocks-per-second" || name == "complexity"
            || name == "frame-rate" || name == "quality" || name == "size"
            || name == "measured-blocks-per-second" || name.startsWith("measured-frame-rate-")) {
        AString min, max;
        if (msg->findString("min", &min) && msg->findString("max", &max)) {
            min.append("-");
            min.append(max);
            if (msg->contains("range") || msg->contains("value")) {
                return limitError(name, "has 'min' and 'max' as well as 'range' or "
                        "'value' attributes");
            }
            msg->setString("range", min);
        } else if (msg->contains("min") || msg->contains("max")) {
            return limitError(name, "has only 'min' or 'max' attribute");
        } else if (msg->findString("value", &max)) {
            min = max;
            min.append("-");
            min.append(max);
            if (msg->contains("range")) {
                return limitError(name, "has both 'range' and 'value' attributes");
            }
            msg->setString("range", min);
        }

        AString range, scale = "linear", def, in_;
        if (!msg->findString("range", &range)) {
            return limitError(name, "with no 'range', 'value' or 'min'/'max' attributes");
        }

        if ((name == "quality" || name == "complexity") ^
                (found = msg->findString("default", &def))) {
            return limitFoundMissingAttr(name, "default", found);
        }
        if (name != "quality" && msg->findString("scale", &scale)) {
            return limitFoundMissingAttr(name, "scale");
        }
        if ((name == "aspect-ratio") ^ (found = msg->findString("in", &in_))) {
            return limitFoundMissingAttr(name, "in", found);
        }

        if (name == "aspect-ratio") {
            if (!(in_ == "pixels") && !(in_ == "blocks")) {
                return limitInvalidAttr(name, "in", in_);
            }
            in_.erase(5, 1); // (pixel|block)-aspect-ratio
            in_.append("-");
            in_.append(name);
            name = in_;
        }
        if (name == "quality") {
            mCurrentType->mDetails["quality-scale"] = scale;
        }
        if (name == "quality" || name == "complexity") {
            AString tag = name;
            tag.append("-default");
            mCurrentType->mDetails[tag] = def;
        }
        AString tag = name;
        tag.append("-range");
        mCurrentType->mDetails[tag] = range;
    } else {
        AString max, value, ranges;
        if (msg->contains("default")) {
            return limitFoundMissingAttr(name, "default");
        } else if (msg->contains("in")) {
            return limitFoundMissingAttr(name, "in");
        } else if ((name == "channel-count" || name == "concurrent-instances") ^
                (found = msg->findString("max", &max))) {
            return limitFoundMissingAttr(name, "max", found);
        } else if (msg->contains("min")) {
            return limitFoundMissingAttr(name, "min");
        } else if (msg->contains("range")) {
            return limitFoundMissingAttr(name, "range");
        } else if ((name == "sample-rate") ^
                (found = msg->findString("ranges", &ranges))) {
            return limitFoundMissingAttr(name, "ranges", found);
        } else if (msg->contains("scale")) {
            return limitFoundMissingAttr(name, "scale");
        } else if ((name == "alignment" || name == "block-size") ^
                (found = msg->findString("value", &value))) {
            return limitFoundMissingAttr(name, "value", found);
        }

        if (max.size()) {
            AString tag = "max-";
            tag.append(name);
            mCurrentType->mDetails[tag] = max;
        } else if (value.size()) {
            mCurrentType->mDetails[name] = value;
        } else if (ranges.size()) {
            AString tag = name;
            tag.append("-ranges");
            mCurrentType->mDetails[tag] = ranges;
        } else {
            ALOGW("Ignoring unrecognized limit '%s'", name.c_str());
        }
    }

    return OK;
}

status_t MediaCodecsXmlParser::addFeature(const char **attrs) {
    size_t i = 0;
    const char *name = NULL;
    int32_t optional = -1;
    int32_t required = -1;
    const char *value = NULL;

    while (attrs[i] != NULL) {
        if (attrs[i + 1] == NULL) {
            ALOGE("addFeature: feature is not given");
            return -EINVAL;
        }

        // attributes with values
        if (!strcmp(attrs[i], "name")) {
            name = attrs[i + 1];
            ++i;
        } else if (!strcmp(attrs[i], "optional") || !strcmp(attrs[i], "required")) {
            int value = (int)ParseBoolean(attrs[i + 1]);
            if (!strcmp(attrs[i], "optional")) {
                optional = value;
            } else {
                required = value;
            }
            ++i;
        } else if (!strcmp(attrs[i], "value")) {
            value = attrs[i + 1];
            ++i;
        } else {
            ALOGE("addFeature: unrecognized attribute: %s", attrs[i]);
            return -EINVAL;
        }
        ++i;
    }
    if (name == NULL) {
        ALOGE("feature with no 'name' attribute");
        return -EINVAL;
    }

    if (optional == required && optional != -1) {
        ALOGE("feature '%s' is both/neither optional and required", name);
        return -EINVAL;
    }

    if (mCurrentType == mCodecInfos[mCurrentName].mTypes.end()) {
        ALOGW("ignoring null type");
        return OK;
    }
    if (value != NULL) {
        mCurrentType->mStringFeatures[name] = value;
    } else {
        mCurrentType->mBoolFeatures[name] = (required == 1) || (optional == 0);
    }
    return OK;
}

void MediaCodecsXmlParser::getGlobalSettings(
        std::map<AString, AString> *settings) const {
    settings->clear();
    settings->insert(mGlobalSettings.begin(), mGlobalSettings.end());
}

status_t MediaCodecsXmlParser::getCodecInfo(const char *name, CodecInfo *info) const {
    if (mCodecInfos.count(name) == 0) {
        ALOGE("Codec not found with name '%s'", name);
        return NAME_NOT_FOUND;
    }
    *info = mCodecInfos.at(name);
    return OK;
}

status_t MediaCodecsXmlParser::getQuirks(const char *name, std::vector<AString> *quirks) const {
    if (mQuirks.count(name) == 0) {
        ALOGE("Codec not found with name '%s'", name);
        return NAME_NOT_FOUND;
    }
    quirks->clear();
    quirks->insert(quirks->end(), mQuirks.at(name).begin(), mQuirks.at(name).end());
    return OK;
}

}  // namespace android
