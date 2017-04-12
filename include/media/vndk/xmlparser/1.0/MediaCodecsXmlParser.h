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

#ifndef MEDIA_CODECS_XML_PARSER_H_

#define MEDIA_CODECS_XML_PARSER_H_

#include <map>
#include <vector>

#include <media/stagefright/foundation/ABase.h>
#include <media/stagefright/foundation/AString.h>

#include <sys/types.h>
#include <utils/Errors.h>
#include <utils/Vector.h>
#include <utils/StrongPointer.h>

namespace android {

struct AMessage;

// Quirk still supported, even though deprecated
enum Quirks {
    kRequiresAllocateBufferOnInputPorts   = 1,
    kRequiresAllocateBufferOnOutputPorts  = 2,

    kQuirksMask = kRequiresAllocateBufferOnInputPorts
                | kRequiresAllocateBufferOnOutputPorts,
};

// Lightweight struct for querying components.
struct TypeInfo {
    AString mName;
    std::map<AString, AString> mStringFeatures;
    std::map<AString, bool> mBoolFeatures;
    std::map<AString, AString> mDetails;
};

struct ProfileLevel {
    uint32_t mProfile;
    uint32_t mLevel;
};

struct CodecInfo {
    std::vector<TypeInfo> mTypes;
    std::vector<ProfileLevel> mProfileLevels;
    std::vector<uint32_t> mColorFormats;
    uint32_t mFlags;
    bool mIsEncoder;
};

class MediaCodecsXmlParser {
public:
    MediaCodecsXmlParser();
    ~MediaCodecsXmlParser();

    void getGlobalSettings(std::map<AString, AString> *settings) const;

    status_t getCodecInfo(const char *name, CodecInfo *info) const;

    status_t getQuirks(const char *name, std::vector<AString> *quirks) const;

private:
    enum Section {
        SECTION_TOPLEVEL,
        SECTION_SETTINGS,
        SECTION_DECODERS,
        SECTION_DECODER,
        SECTION_DECODER_TYPE,
        SECTION_ENCODERS,
        SECTION_ENCODER,
        SECTION_ENCODER_TYPE,
        SECTION_INCLUDE,
    };

    status_t mInitCheck;
    Section mCurrentSection;
    bool mUpdate;
    Vector<Section> mPastSections;
    int32_t mDepth;
    AString mHrefBase;

    std::map<AString, AString> mGlobalSettings;

    // name -> CodecInfo
    std::map<AString, CodecInfo> mCodecInfos;
    std::map<AString, std::vector<AString>> mQuirks;
    AString mCurrentName;
    std::vector<TypeInfo>::iterator mCurrentType;

    status_t initCheck() const;
    void parseTopLevelXMLFile(const char *path, bool ignore_errors = false);

    void parseXMLFile(const char *path);

    static void StartElementHandlerWrapper(
            void *me, const char *name, const char **attrs);

    static void EndElementHandlerWrapper(void *me, const char *name);

    void startElementHandler(const char *name, const char **attrs);
    void endElementHandler(const char *name);

    status_t includeXMLFile(const char **attrs);
    status_t addSettingFromAttributes(const char **attrs);
    status_t addMediaCodecFromAttributes(bool encoder, const char **attrs);
    void addMediaCodec(bool encoder, const char *name, const char *type = NULL);

    status_t addQuirk(const char **attrs);
    status_t addTypeFromAttributes(const char **attrs, bool encoder);
    status_t addLimit(const char **attrs);
    status_t addFeature(const char **attrs);
    void addType(const char *name);

    DISALLOW_EVIL_CONSTRUCTORS(MediaCodecsXmlParser);
};

}  // namespace android

#endif  // MEDIA_CODECS_XML_PARSER_H_

