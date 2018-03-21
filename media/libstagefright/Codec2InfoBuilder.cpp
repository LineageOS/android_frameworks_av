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

//#define LOG_NDEBUG 0
#define LOG_TAG "Codec2InfoBuilder"
#include <log/log.h>

#include <C2Component.h>
#include <C2PlatformSupport.h>
#include <C2V4l2Support.h>

#include <cutils/properties.h>
#include <media/stagefright/foundation/MediaDefs.h>
#include <media/stagefright/xmlparser/MediaCodecsXmlParser.h>
#include <media/stagefright/Codec2InfoBuilder.h>

namespace android {

using ConstTraitsPtr = std::shared_ptr<const C2Component::Traits>;

struct ProfileLevel {
    uint32_t profile;
    uint32_t level;
};
static const ProfileLevel kAvcProfileLevels[] = {
    { 0x01, 0x0001 },  // { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel1  },
    { 0x01, 0x0002 },  // { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel1b },
    { 0x01, 0x0004 },  // { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel11 },
    { 0x01, 0x0008 },  // { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel12 },
    { 0x01, 0x0010 },  // { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel13 },
    { 0x01, 0x0020 },  // { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel2  },
    { 0x01, 0x0040 },  // { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel21 },
    { 0x01, 0x0080 },  // { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel22 },
    { 0x01, 0x0100 },  // { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel3  },
    { 0x01, 0x0200 },  // { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel31 },
    { 0x01, 0x0400 },  // { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel32 },
    { 0x01, 0x0800 },  // { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel4  },
    { 0x01, 0x1000 },  // { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel41 },
    { 0x01, 0x2000 },  // { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel42 },
    { 0x01, 0x4000 },  // { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel5  },
    { 0x01, 0x8000 },  // { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel51 },

    { 0x02, 0x0001 },  // { OMX_VIDEO_AVCProfileMain,     OMX_VIDEO_AVCLevel1  },
    { 0x02, 0x0002 },  // { OMX_VIDEO_AVCProfileMain,     OMX_VIDEO_AVCLevel1b },
    { 0x02, 0x0004 },  // { OMX_VIDEO_AVCProfileMain,     OMX_VIDEO_AVCLevel11 },
    { 0x02, 0x0008 },  // { OMX_VIDEO_AVCProfileMain,     OMX_VIDEO_AVCLevel12 },
    { 0x02, 0x0010 },  // { OMX_VIDEO_AVCProfileMain,     OMX_VIDEO_AVCLevel13 },
    { 0x02, 0x0020 },  // { OMX_VIDEO_AVCProfileMain,     OMX_VIDEO_AVCLevel2  },
    { 0x02, 0x0040 },  // { OMX_VIDEO_AVCProfileMain,     OMX_VIDEO_AVCLevel21 },
    { 0x02, 0x0080 },  // { OMX_VIDEO_AVCProfileMain,     OMX_VIDEO_AVCLevel22 },
    { 0x02, 0x0100 },  // { OMX_VIDEO_AVCProfileMain,     OMX_VIDEO_AVCLevel3  },
    { 0x02, 0x0200 },  // { OMX_VIDEO_AVCProfileMain,     OMX_VIDEO_AVCLevel31 },
    { 0x02, 0x0400 },  // { OMX_VIDEO_AVCProfileMain,     OMX_VIDEO_AVCLevel32 },
    { 0x02, 0x0800 },  // { OMX_VIDEO_AVCProfileMain,     OMX_VIDEO_AVCLevel4  },
    { 0x02, 0x1000 },  // { OMX_VIDEO_AVCProfileMain,     OMX_VIDEO_AVCLevel41 },
    { 0x02, 0x2000 },  // { OMX_VIDEO_AVCProfileMain,     OMX_VIDEO_AVCLevel42 },
    { 0x02, 0x4000 },  // { OMX_VIDEO_AVCProfileMain,     OMX_VIDEO_AVCLevel5  },
    { 0x02, 0x8000 },  // { OMX_VIDEO_AVCProfileMain,     OMX_VIDEO_AVCLevel51 },

    { 0x04, 0x0001 },  // { OMX_VIDEO_AVCProfileHigh,     OMX_VIDEO_AVCLevel1  },
    { 0x04, 0x0002 },  // { OMX_VIDEO_AVCProfileHigh,     OMX_VIDEO_AVCLevel1b },
    { 0x04, 0x0004 },  // { OMX_VIDEO_AVCProfileHigh,     OMX_VIDEO_AVCLevel11 },
    { 0x04, 0x0008 },  // { OMX_VIDEO_AVCProfileHigh,     OMX_VIDEO_AVCLevel12 },
    { 0x04, 0x0010 },  // { OMX_VIDEO_AVCProfileHigh,     OMX_VIDEO_AVCLevel13 },
    { 0x04, 0x0020 },  // { OMX_VIDEO_AVCProfileHigh,     OMX_VIDEO_AVCLevel2  },
    { 0x04, 0x0040 },  // { OMX_VIDEO_AVCProfileHigh,     OMX_VIDEO_AVCLevel21 },
    { 0x04, 0x0080 },  // { OMX_VIDEO_AVCProfileHigh,     OMX_VIDEO_AVCLevel22 },
    { 0x04, 0x0100 },  // { OMX_VIDEO_AVCProfileHigh,     OMX_VIDEO_AVCLevel3  },
    { 0x04, 0x0200 },  // { OMX_VIDEO_AVCProfileHigh,     OMX_VIDEO_AVCLevel31 },
    { 0x04, 0x0400 },  // { OMX_VIDEO_AVCProfileHigh,     OMX_VIDEO_AVCLevel32 },
    { 0x04, 0x0800 },  // { OMX_VIDEO_AVCProfileHigh,     OMX_VIDEO_AVCLevel4  },
    { 0x04, 0x1000 },  // { OMX_VIDEO_AVCProfileHigh,     OMX_VIDEO_AVCLevel41 },
    { 0x04, 0x2000 },  // { OMX_VIDEO_AVCProfileHigh,     OMX_VIDEO_AVCLevel42 },
    { 0x04, 0x4000 },  // { OMX_VIDEO_AVCProfileHigh,     OMX_VIDEO_AVCLevel5  },
    { 0x04, 0x8000 },  // { OMX_VIDEO_AVCProfileHigh,     OMX_VIDEO_AVCLevel51 },
};

status_t Codec2InfoBuilder::buildMediaCodecList(MediaCodecListWriter* writer) {
    // Obtain C2ComponentStore
    std::shared_ptr<C2ComponentStore> store = GetCodec2PlatformComponentStore();
    if (store == nullptr) {
        ALOGE("Cannot find a component store.");
        return NO_INIT;
    }

    std::vector<ConstTraitsPtr> traits = store->listComponents();

    if (property_get_bool("debug.stagefright.ccodec_v4l2", false)) {
        std::shared_ptr<C2ComponentStore> v4l2Store = GetCodec2VDAComponentStore();
        if (v4l2Store == nullptr) {
            ALOGD("Cannot find a V4L2 component store.");
            // non-fatal.
        } else {
            std::vector<ConstTraitsPtr> v4l2Traits = v4l2Store->listComponents();
            traits.insert(traits.end(), v4l2Traits.begin(), v4l2Traits.end());
        }
    }

    MediaCodecsXmlParser parser(
            MediaCodecsXmlParser::defaultSearchDirs,
            "media_codecs_c2.xml");
    if (parser.getParsingStatus() != OK) {
        ALOGD("XML parser no good");
        return OK;
    }
    for (const ConstTraitsPtr &trait : traits) {
        if (parser.getCodecMap().count(trait->name.c_str()) == 0) {
            ALOGD("%s not found in xml", trait->name.c_str());
            continue;
        }
        const MediaCodecsXmlParser::CodecProperties &codec = parser.getCodecMap().at(trait->name);
        std::unique_ptr<MediaCodecInfoWriter> codecInfo = writer->addMediaCodecInfo();
        codecInfo->setName(trait->name.c_str());
        codecInfo->setOwner("dummy");
        // TODO: get this from trait->kind
        bool encoder = (trait->name.find("encoder") != std::string::npos);
        codecInfo->setEncoder(encoder);
        codecInfo->setRank(trait->rank);
        for (auto typeIt = codec.typeMap.begin(); typeIt != codec.typeMap.end(); ++typeIt) {
            const std::string &mediaType = typeIt->first;
            const MediaCodecsXmlParser::AttributeMap &attrMap = typeIt->second;
            std::unique_ptr<MediaCodecInfo::CapabilitiesWriter> caps =
                codecInfo->addMime(mediaType.c_str());
            for (auto attrIt = attrMap.begin(); attrIt != attrMap.end(); ++attrIt) {
                std::string key, value;
                std::tie(key, value) = *attrIt;
                if (key.find("feature-") == 0 && key.find("feature-bitrate-modes") != 0) {
                    caps->addDetail(key.c_str(), std::stoi(value));
                } else {
                    caps->addDetail(key.c_str(), value.c_str());
                }
            }
            // TODO: get this from intf(), and apply to other codecs as well.
            if (mediaType.find("video/avc") != std::string::npos && !encoder) {
                for (const auto& pl : kAvcProfileLevels) {
                    caps->addProfileLevel(pl.profile, pl.level);
                }
            }
            // TODO: get this from intf().
            if (mediaType.find("video") != std::string::npos && !encoder) {
                caps->addColorFormat(0x7F420888);  // COLOR_FormatYUV420Flexible
            }
        }
    }
    return OK;
}

}  // namespace android

extern "C" android::MediaCodecListBuilderBase *CreateBuilder() {
    return new android::Codec2InfoBuilder;
}
