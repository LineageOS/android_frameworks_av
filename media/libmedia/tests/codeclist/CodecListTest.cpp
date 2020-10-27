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

//#define LOG_NDEBUG 0
#define LOG_TAG "CodecListTest"
#include <utils/Log.h>

#include <gtest/gtest.h>

#include <binder/Parcel.h>
#include <media/stagefright/MediaCodecConstants.h>
#include <media/stagefright/MediaCodecList.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AString.h>
#include <media/stagefright/xmlparser/MediaCodecsXmlParser.h>

#define kSwCodecXmlPath "/apex/com.android.media.swcodec/etc/"

using namespace android;

struct CddReq {
    CddReq(const char *type, bool encoder) {
        mediaType = type;
        isEncoder = encoder;
    }

    const char *mediaType;
    bool isEncoder;
};

TEST(CodecListTest, CodecListSanityTest) {
    sp<IMediaCodecList> list = MediaCodecList::getInstance();
    ASSERT_NE(list, nullptr) << "Unable to get MediaCodecList instance.";
    EXPECT_GT(list->countCodecs(), 0) << "No codecs in CodecList";
    for (size_t i = 0; i < list->countCodecs(); ++i) {
        sp<MediaCodecInfo> info = list->getCodecInfo(i);
        ASSERT_NE(info, nullptr) << "CodecInfo is null";
        ssize_t index = list->findCodecByName(info->getCodecName());
        EXPECT_GE(index, 0) << "Wasn't able to find existing codec: " << info->getCodecName();
    }
}

TEST(CodecListTest, CodecListByTypeTest) {
    sp<IMediaCodecList> list = MediaCodecList::getInstance();
    ASSERT_NE(list, nullptr) << "Unable to get MediaCodecList instance.";

    std::vector<CddReq> cddReq{
            // media type, isEncoder
            CddReq(MIMETYPE_AUDIO_AAC, false),
            CddReq(MIMETYPE_AUDIO_AAC, true),

            CddReq(MIMETYPE_VIDEO_AVC, false),
            CddReq(MIMETYPE_VIDEO_HEVC, false),
            CddReq(MIMETYPE_VIDEO_MPEG4, false),
            CddReq(MIMETYPE_VIDEO_VP8, false),
            CddReq(MIMETYPE_VIDEO_VP9, false),

            CddReq(MIMETYPE_VIDEO_AVC, true),
            CddReq(MIMETYPE_VIDEO_VP8, true),
    };

    for (CddReq codecReq : cddReq) {
        ssize_t index = list->findCodecByType(codecReq.mediaType, codecReq.isEncoder);
        EXPECT_GE(index, 0) << "Wasn't able to find codec for media type: " << codecReq.mediaType
                            << (codecReq.isEncoder ? " encoder" : " decoder");
    }
}

TEST(CodecInfoTest, ListInfoTest) {
    ALOGV("Compare CodecInfo with info in XML");
    MediaCodecsXmlParser parser;
    status_t status = parser.parseXmlFilesInSearchDirs();
    ASSERT_EQ(status, OK) << "XML Parsing failed for default paths";

    const std::vector<std::string> &xmlFiles = MediaCodecsXmlParser::getDefaultXmlNames();
    const std::vector<std::string> &searchDirsApex{std::string(kSwCodecXmlPath)};
    status = parser.parseXmlFilesInSearchDirs(xmlFiles, searchDirsApex);
    ASSERT_EQ(status, OK) << "XML Parsing of " << kSwCodecXmlPath << " failed";

    MediaCodecsXmlParser::CodecMap codecMap = parser.getCodecMap();

    sp<IMediaCodecList> list = MediaCodecList::getInstance();
    ASSERT_NE(list, nullptr) << "Unable to get MediaCodecList instance";

    // Compare CodecMap from XML to CodecList
    for (auto mapIter : codecMap) {
        ssize_t index = list->findCodecByName(mapIter.first.c_str());
        if (index < 0) {
            std::cout << "[   WARN   ] " << mapIter.first << " not found in CodecList \n";
            continue;
        }

        sp<MediaCodecInfo> info = list->getCodecInfo(index);
        ASSERT_NE(info, nullptr) << "CodecInfo is null";

        MediaCodecsXmlParser::CodecProperties codecProperties = mapIter.second;
        ASSERT_EQ(codecProperties.isEncoder, info->isEncoder()) << "Encoder property mismatch";

        ALOGV("codec name: %s", info->getCodecName());
        ALOGV("codec rank: %d", info->getRank());
        ALOGV("codec ownername: %s", info->getOwnerName());
        ALOGV("codec isEncoder: %d", info->isEncoder());

        ALOGV("attributeFlags: kFlagIsHardwareAccelerated, kFlagIsSoftwareOnly, kFlagIsVendor, "
              "kFlagIsEncoder");
        std::bitset<4> attr(info->getAttributes());
        ALOGV("codec attributes: %s", attr.to_string().c_str());

        Vector<AString> mediaTypes;
        info->getSupportedMediaTypes(&mediaTypes);
        ALOGV("supported media types count: %zu", mediaTypes.size());
        ASSERT_FALSE(mediaTypes.isEmpty())
                << "no media type supported by codec: " << info->getCodecName();

        MediaCodecsXmlParser::TypeMap typeMap = codecProperties.typeMap;
        for (auto mediaType : mediaTypes) {
            ALOGV("codec mediaTypes: %s", mediaType.c_str());
            auto searchTypeMap = typeMap.find(mediaType.c_str());
            ASSERT_NE(searchTypeMap, typeMap.end())
                    << "CodecList doesn't contain codec media type: " << mediaType.c_str();
            MediaCodecsXmlParser::AttributeMap attributeMap = searchTypeMap->second;

            const sp<MediaCodecInfo::Capabilities> &capabilities =
                    info->getCapabilitiesFor(mediaType.c_str());

            Vector<uint32_t> colorFormats;
            capabilities->getSupportedColorFormats(&colorFormats);
            for (auto colorFormat : colorFormats) {
                ALOGV("supported color formats: %d", colorFormat);
            }

            Vector<MediaCodecInfo::ProfileLevel> profileLevels;
            capabilities->getSupportedProfileLevels(&profileLevels);
            if (!profileLevels.empty()) {
                ALOGV("supported profilelevel for media type: %s", mediaType.c_str());
            }
            for (auto profileLevel : profileLevels) {
                ALOGV("profile: %d, level: %d", profileLevel.mProfile, profileLevel.mLevel);
            }

            sp<AMessage> details = capabilities->getDetails();
            ASSERT_NE(details, nullptr) << "Details in codec capabilities is null";
            ALOGV("no. of entries in details: %zu", details->countEntries());

            for (size_t idxDetail = 0; idxDetail < details->countEntries(); idxDetail++) {
                AMessage::Type type;
                const char *name = details->getEntryNameAt(idxDetail, &type);
                ALOGV("details entry name: %s", name);
                AMessage::ItemData itemData = details->getEntryAt(idxDetail);
                switch (type) {
                    case AMessage::kTypeInt32:
                        int32_t val32;
                        if (itemData.find(&val32)) {
                            ALOGV("entry int val: %d", val32);
                            auto searchAttr = attributeMap.find(name);
                            if (searchAttr == attributeMap.end()) {
                                ALOGW("Parser doesn't have key: %s", name);
                            } else if (stoi(searchAttr->second) != val32) {
                                ALOGW("Values didn't match for key: %s", name);
                                ALOGV("Values act/exp: %d / %d", val32, stoi(searchAttr->second));
                            }
                        }
                        break;
                    case AMessage::kTypeString:
                        if (AString valStr; itemData.find(&valStr)) {
                            ALOGV("entry str val: %s", valStr.c_str());
                            auto searchAttr = attributeMap.find(name);
                            if (searchAttr == attributeMap.end()) {
                                ALOGW("Parser doesn't have key: %s", name);
                            } else if (searchAttr->second != valStr.c_str()) {
                                ALOGW("Values didn't match for key: %s", name);
                                ALOGV("Values act/exp: %s / %s", valStr.c_str(),
                                      searchAttr->second.c_str());
                            }
                        }
                        break;
                    default:
                        ALOGV("data type: %d shouldn't be present in details", type);
                        break;
                }
            }
        }

        Parcel *codecInfoParcel = new Parcel();
        ASSERT_NE(codecInfoParcel, nullptr) << "Unable to create parcel";

        status_t status = info->writeToParcel(codecInfoParcel);
        ASSERT_EQ(status, OK) << "Writing to parcel failed";

        codecInfoParcel->setDataPosition(0);
        sp<MediaCodecInfo> parcelCodecInfo = info->FromParcel(*codecInfoParcel);
        ASSERT_NE(parcelCodecInfo, nullptr) << "CodecInfo from parcel is null";
        delete codecInfoParcel;

        EXPECT_STREQ(info->getCodecName(), parcelCodecInfo->getCodecName())
                << "Returned codec name in info doesn't match";
        EXPECT_EQ(info->getRank(), parcelCodecInfo->getRank())
                << "Returned component rank in info doesn't match";
    }
}

TEST(CodecListTest, CodecListGlobalSettingsTest) {
    sp<IMediaCodecList> list = MediaCodecList::getInstance();
    ASSERT_NE(list, nullptr) << "Unable to get MediaCodecList instance";

    sp<AMessage> globalSettings = list->getGlobalSettings();
    ASSERT_NE(globalSettings, nullptr) << "GlobalSettings AMessage is null";
    ALOGV("global settings: %s", globalSettings->debugString(0).c_str());
}
