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

#include <strings.h>

#include <C2Component.h>
#include <C2Config.h>
#include <C2Debug.h>
#include <C2PlatformSupport.h>
#include <Codec2Mapper.h>

#include <OMX_Audio.h>
#include <OMX_AudioExt.h>
#include <OMX_IndexExt.h>
#include <OMX_Types.h>
#include <OMX_Video.h>
#include <OMX_VideoExt.h>
#include <OMX_AsString.h>

#include <android/hardware/media/omx/1.0/IOmx.h>
#include <android/hardware/media/omx/1.0/IOmxObserver.h>
#include <android/hardware/media/omx/1.0/IOmxNode.h>
#include <android/hardware/media/omx/1.0/types.h>

#include <android-base/properties.h>
#include <codec2/hidl/client.h>
#include <cutils/native_handle.h>
#include <media/omx/1.0/WOmxNode.h>
#include <media/stagefright/MediaCodecConstants.h>
#include <media/stagefright/foundation/MediaDefs.h>
#include <media/stagefright/omx/OMXUtils.h>
#include <media/stagefright/xmlparser/MediaCodecsXmlParser.h>

#include "Codec2InfoBuilder.h"

namespace android {

using Traits = C2Component::Traits;

namespace /* unnamed */ {

bool hasPrefix(const std::string& s, const char* prefix) {
    size_t prefixLen = strlen(prefix);
    return s.compare(0, prefixLen, prefix) == 0;
}

bool hasSuffix(const std::string& s, const char* suffix) {
    size_t suffixLen = strlen(suffix);
    return suffixLen > s.size() ? false :
            s.compare(s.size() - suffixLen, suffixLen, suffix) == 0;
}

// Constants from ACodec
constexpr OMX_U32 kPortIndexInput = 0;
constexpr OMX_U32 kPortIndexOutput = 1;
constexpr OMX_U32 kMaxIndicesToCheck = 32;

status_t queryOmxCapabilities(
        const char* name, const char* mediaType, bool isEncoder,
        MediaCodecInfo::CapabilitiesWriter* caps) {

    const char *role = GetComponentRole(isEncoder, mediaType);
    if (role == nullptr) {
        return BAD_VALUE;
    }

    using namespace ::android::hardware::media::omx::V1_0;
    using ::android::hardware::Return;
    using ::android::hardware::Void;
    using ::android::hardware::hidl_vec;
    using ::android::hardware::media::omx::V1_0::utils::LWOmxNode;

    sp<IOmx> omx = IOmx::getService();
    if (!omx) {
        ALOGW("Could not obtain IOmx service.");
        return NO_INIT;
    }

    struct Observer : IOmxObserver {
        virtual Return<void> onMessages(const hidl_vec<Message>&) override {
            return Void();
        }
    };

    sp<Observer> observer = new Observer();
    Status status;
    sp<IOmxNode> tOmxNode;
    Return<void> transStatus = omx->allocateNode(
            name, observer,
            [&status, &tOmxNode](Status s, const sp<IOmxNode>& n) {
                status = s;
                tOmxNode = n;
            });
    if (!transStatus.isOk()) {
        ALOGW("IOmx::allocateNode -- transaction failed.");
        return NO_INIT;
    }
    if (status != Status::OK) {
        ALOGW("IOmx::allocateNode -- error returned: %d.",
                static_cast<int>(status));
        return NO_INIT;
    }

    sp<LWOmxNode> omxNode = new LWOmxNode(tOmxNode);

    status_t err = SetComponentRole(omxNode, role);
    if (err != OK) {
        omxNode->freeNode();
        ALOGW("Failed to SetComponentRole: component = %s, role = %s.",
                name, role);
        return err;
    }

    bool isVideo = hasPrefix(mediaType, "video/") == 0;
    bool isImage = hasPrefix(mediaType, "image/") == 0;

    if (isVideo || isImage) {
        OMX_VIDEO_PARAM_PROFILELEVELTYPE param;
        InitOMXParams(&param);
        param.nPortIndex = isEncoder ? kPortIndexOutput : kPortIndexInput;

        for (OMX_U32 index = 0; index <= kMaxIndicesToCheck; ++index) {
            param.nProfileIndex = index;
            status_t err = omxNode->getParameter(
                    OMX_IndexParamVideoProfileLevelQuerySupported,
                    &param, sizeof(param));
            if (err != OK) {
                break;
            }
            caps->addProfileLevel(param.eProfile, param.eLevel);

            // AVC components may not list the constrained profiles explicitly, but
            // decoders that support a profile also support its constrained version.
            // Encoders must explicitly support constrained profiles.
            if (!isEncoder && strcasecmp(mediaType, MEDIA_MIMETYPE_VIDEO_AVC) == 0) {
                if (param.eProfile == OMX_VIDEO_AVCProfileHigh) {
                    caps->addProfileLevel(OMX_VIDEO_AVCProfileConstrainedHigh, param.eLevel);
                } else if (param.eProfile == OMX_VIDEO_AVCProfileBaseline) {
                    caps->addProfileLevel(OMX_VIDEO_AVCProfileConstrainedBaseline, param.eLevel);
                }
            }

            if (index == kMaxIndicesToCheck) {
                ALOGW("[%s] stopping checking profiles after %u: %x/%x",
                        name, index,
                        param.eProfile, param.eLevel);
            }
        }

        // Color format query
        // return colors in the order reported by the OMX component
        // prefix "flexible" standard ones with the flexible equivalent
        OMX_VIDEO_PARAM_PORTFORMATTYPE portFormat;
        InitOMXParams(&portFormat);
        portFormat.nPortIndex = isEncoder ? kPortIndexInput : kPortIndexOutput;
        for (OMX_U32 index = 0; index <= kMaxIndicesToCheck; ++index) {
            portFormat.nIndex = index;
            status_t err = omxNode->getParameter(
                    OMX_IndexParamVideoPortFormat,
                    &portFormat, sizeof(portFormat));
            if (err != OK) {
                break;
            }

            OMX_U32 flexibleEquivalent;
            if (IsFlexibleColorFormat(
                    omxNode, portFormat.eColorFormat, false /* usingNativeWindow */,
                    &flexibleEquivalent)) {
                caps->addColorFormat(flexibleEquivalent);
            }
            caps->addColorFormat(portFormat.eColorFormat);

            if (index == kMaxIndicesToCheck) {
                ALOGW("[%s] stopping checking formats after %u: %s(%x)",
                        name, index,
                        asString(portFormat.eColorFormat), portFormat.eColorFormat);
            }
        }
    } else if (strcasecmp(mediaType, MEDIA_MIMETYPE_AUDIO_AAC) == 0) {
        // More audio codecs if they have profiles.
        OMX_AUDIO_PARAM_ANDROID_PROFILETYPE param;
        InitOMXParams(&param);
        param.nPortIndex = isEncoder ? kPortIndexOutput : kPortIndexInput;
        for (OMX_U32 index = 0; index <= kMaxIndicesToCheck; ++index) {
            param.nProfileIndex = index;
            status_t err = omxNode->getParameter(
                    (OMX_INDEXTYPE)OMX_IndexParamAudioProfileQuerySupported,
                    &param, sizeof(param));
            if (err != OK) {
                break;
            }
            // For audio, level is ignored.
            caps->addProfileLevel(param.eProfile, 0 /* level */);

            if (index == kMaxIndicesToCheck) {
                ALOGW("[%s] stopping checking profiles after %u: %x",
                        name, index,
                        param.eProfile);
            }
        }

        // NOTE: Without Android extensions, OMX does not provide a way to query
        // AAC profile support
        if (param.nProfileIndex == 0) {
            ALOGW("component %s doesn't support profile query.", name);
        }
    }

    if (isVideo && !isEncoder) {
        native_handle_t *sidebandHandle = nullptr;
        if (omxNode->configureVideoTunnelMode(
                kPortIndexOutput, OMX_TRUE, 0, &sidebandHandle) == OK) {
            // tunneled playback includes adaptive playback
        } else {
            // tunneled playback is not supported
            caps->removeDetail(MediaCodecInfo::Capabilities::FEATURE_TUNNELED_PLAYBACK);
            if (omxNode->setPortMode(
                    kPortIndexOutput, IOMX::kPortModeDynamicANWBuffer) == OK ||
                    omxNode->prepareForAdaptivePlayback(
                            kPortIndexOutput, OMX_TRUE,
                            1280 /* width */, 720 /* height */) != OK) {
                // adaptive playback is not supported
                caps->removeDetail(MediaCodecInfo::Capabilities::FEATURE_ADAPTIVE_PLAYBACK);
            }
        }
    }

    if (isVideo && isEncoder) {
        OMX_VIDEO_CONFIG_ANDROID_INTRAREFRESHTYPE params;
        InitOMXParams(&params);
        params.nPortIndex = kPortIndexOutput;

        OMX_VIDEO_PARAM_INTRAREFRESHTYPE fallbackParams;
        InitOMXParams(&fallbackParams);
        fallbackParams.nPortIndex = kPortIndexOutput;
        fallbackParams.eRefreshMode = OMX_VIDEO_IntraRefreshCyclic;

        if (omxNode->getConfig(
                (OMX_INDEXTYPE)OMX_IndexConfigAndroidIntraRefresh,
                &params, sizeof(params)) != OK &&
                omxNode->getParameter(
                    OMX_IndexParamVideoIntraRefresh, &fallbackParams,
                    sizeof(fallbackParams)) != OK) {
            // intra refresh is not supported
            caps->removeDetail(MediaCodecInfo::Capabilities::FEATURE_INTRA_REFRESH);
        }
    }

    omxNode->freeNode();
    return OK;
}

void buildOmxInfo(const MediaCodecsXmlParser& parser,
                  MediaCodecListWriter* writer) {
    uint32_t omxRank = ::android::base::GetUintProperty(
            "debug.stagefright.omx_default_rank", uint32_t(0x100));
    for (const MediaCodecsXmlParser::Codec& codec : parser.getCodecMap()) {
        const std::string &name = codec.first;
        if (!hasPrefix(codec.first, "OMX.")) {
            continue;
        }
        const MediaCodecsXmlParser::CodecProperties &properties = codec.second;
        bool encoder = properties.isEncoder;
        std::unique_ptr<MediaCodecInfoWriter> info =
                writer->addMediaCodecInfo();
        info->setName(name.c_str());
        info->setOwner("default");
        typename std::underlying_type<MediaCodecInfo::Attributes>::type attrs = 0;
        if (encoder) {
            attrs |= MediaCodecInfo::kFlagIsEncoder;
        }
        // NOTE: we don't support software-only codecs in OMX
        if (!hasPrefix(name, "OMX.google.")) {
            attrs |= MediaCodecInfo::kFlagIsVendor;
            if (properties.quirkSet.find("attribute::software-codec")
                    == properties.quirkSet.end()) {
                attrs |= MediaCodecInfo::kFlagIsHardwareAccelerated;
            }
        }
        info->setAttributes(attrs);
        info->setRank(omxRank);
        // OMX components don't have aliases
        for (const MediaCodecsXmlParser::Type &type : properties.typeMap) {
            const std::string &mediaType = type.first;

            std::unique_ptr<MediaCodecInfo::CapabilitiesWriter> caps =
                    info->addMediaType(mediaType.c_str());
            const MediaCodecsXmlParser::AttributeMap &attrMap = type.second;
            for (const MediaCodecsXmlParser::Attribute& attr : attrMap) {
                const std::string &key = attr.first;
                const std::string &value = attr.second;
                if (hasPrefix(key, "feature-") &&
                        !hasPrefix(key, "feature-bitrate-modes")) {
                    caps->addDetail(key.c_str(), hasPrefix(value, "1") ? 1 : 0);
                } else {
                    caps->addDetail(key.c_str(), value.c_str());
                }
            }
            status_t err = queryOmxCapabilities(
                    name.c_str(),
                    mediaType.c_str(),
                    encoder,
                    caps.get());
            if (err != OK) {
                ALOGI("Failed to query capabilities for %s (media type: %s). Error: %d",
                        name.c_str(),
                        mediaType.c_str(),
                        static_cast<int>(err));
            }
        }
    }
}

} // unnamed namespace

status_t Codec2InfoBuilder::buildMediaCodecList(MediaCodecListWriter* writer) {
    // TODO: Remove run-time configurations once all codecs are working
    // properly. (Assume "full" behavior eventually.)
    //
    // debug.stagefright.ccodec supports 5 values.
    //   0 - Only OMX components are available.
    //   1 - Audio decoders and encoders with prefix "c2.android." are available
    //       and ranked first.
    //       All other components with prefix "c2.android." are available with
    //       their normal ranks.
    //       Components with prefix "c2.vda." are available with their normal
    //       ranks.
    //       All other components with suffix ".avc.decoder" or ".avc.encoder"
    //       are available but ranked last.
    //   2 - Components with prefix "c2.android." are available and ranked
    //       first.
    //       Components with prefix "c2.vda." are available with their normal
    //       ranks.
    //       All other components with suffix ".avc.decoder" or ".avc.encoder"
    //       are available but ranked last.
    //   3 - Components with prefix "c2.android." are available and ranked
    //       first.
    //       All other components are available with their normal ranks.
    //   4 - All components are available with their normal ranks.
    //
    // The default value (boot time) is 1.
    //
    // Note: Currently, OMX components have default rank 0x100, while all
    // Codec2.0 software components have default rank 0x200.
    int option = ::android::base::GetIntProperty("debug.stagefright.ccodec", 1);

    // Obtain Codec2Client
    std::vector<Traits> traits = Codec2Client::ListComponents();

    MediaCodecsXmlParser parser(
            MediaCodecsXmlParser::defaultSearchDirs,
            option == 0 ? "media_codecs.xml" :
                          "media_codecs_c2.xml",
            option == 0 ? "media_codecs_performance.xml" :
                          "media_codecs_performance_c2.xml");
    if (parser.getParsingStatus() != OK) {
        ALOGD("XML parser no good");
        return OK;
    }

    bool surfaceTest(Codec2Client::CreateInputSurface());
    if (option == 0 || !surfaceTest) {
        buildOmxInfo(parser, writer);
    }

    for (const Traits& trait : traits) {
        C2Component::rank_t rank = trait.rank;

        std::shared_ptr<Codec2Client::Interface> intf =
            Codec2Client::CreateInterfaceByName(trait.name.c_str());
        if (!intf || parser.getCodecMap().count(intf->getName()) == 0) {
            ALOGD("%s not found in xml", trait.name.c_str());
            continue;
        }
        std::string canonName = intf->getName();

        // TODO: Remove this block once all codecs are enabled by default.
        switch (option) {
        case 0:
            continue;
        case 1:
            if (hasPrefix(canonName, "c2.vda.")) {
                break;
            }
            if (hasPrefix(canonName, "c2.android.")) {
                if (trait.domain == C2Component::DOMAIN_AUDIO) {
                    rank = 1;
                    break;
                }
                break;
            }
            if (hasSuffix(canonName, ".avc.decoder") ||
                    hasSuffix(canonName, ".avc.encoder")) {
                rank = std::numeric_limits<decltype(rank)>::max();
                break;
            }
            continue;
        case 2:
            if (hasPrefix(canonName, "c2.vda.")) {
                break;
            }
            if (hasPrefix(canonName, "c2.android.")) {
                rank = 1;
                break;
            }
            if (hasSuffix(canonName, ".avc.decoder") ||
                    hasSuffix(canonName, ".avc.encoder")) {
                rank = std::numeric_limits<decltype(rank)>::max();
                break;
            }
            continue;
        case 3:
            if (hasPrefix(canonName, "c2.android.")) {
                rank = 1;
            }
            break;
        }

        ALOGV("canonName = %s", canonName.c_str());
        std::unique_ptr<MediaCodecInfoWriter> codecInfo = writer->addMediaCodecInfo();
        codecInfo->setName(trait.name.c_str());
        codecInfo->setOwner(("codec2::" + trait.owner).c_str());
        const MediaCodecsXmlParser::CodecProperties &codec = parser.getCodecMap().at(canonName);

        bool encoder = trait.kind == C2Component::KIND_ENCODER;
        typename std::underlying_type<MediaCodecInfo::Attributes>::type attrs = 0;

        if (encoder) {
            attrs |= MediaCodecInfo::kFlagIsEncoder;
        }
        if (trait.owner == "software") {
            attrs |= MediaCodecInfo::kFlagIsSoftwareOnly;
        } else {
            attrs |= MediaCodecInfo::kFlagIsVendor;
            if (trait.owner == "vendor-software") {
                attrs |= MediaCodecInfo::kFlagIsSoftwareOnly;
            } else if (codec.quirkSet.find("attribute::software-codec") == codec.quirkSet.end()) {
                attrs |= MediaCodecInfo::kFlagIsHardwareAccelerated;
            }
        }
        codecInfo->setAttributes(attrs);
        codecInfo->setRank(rank);

        for (const std::string &alias : codec.aliases) {
            codecInfo->addAlias(alias.c_str());
        }

        for (auto typeIt = codec.typeMap.begin(); typeIt != codec.typeMap.end(); ++typeIt) {
            const std::string &mediaType = typeIt->first;
            const MediaCodecsXmlParser::AttributeMap &attrMap = typeIt->second;
            std::unique_ptr<MediaCodecInfo::CapabilitiesWriter> caps =
                codecInfo->addMediaType(mediaType.c_str());
            for (auto attrIt = attrMap.begin(); attrIt != attrMap.end(); ++attrIt) {
                std::string key, value;
                std::tie(key, value) = *attrIt;
                if (key.find("feature-") == 0 && key.find("feature-bitrate-modes") != 0) {
                    caps->addDetail(key.c_str(), std::stoi(value));
                } else {
                    caps->addDetail(key.c_str(), value.c_str());
                }
            }

            bool gotProfileLevels = false;
            if (intf) {
                std::shared_ptr<C2Mapper::ProfileLevelMapper> mapper =
                    C2Mapper::GetProfileLevelMapper(trait.mediaType);
                // if we don't know the media type, pass through all values unmapped

                // TODO: we cannot find levels that are local 'maxima' without knowing the coding
                // e.g. H.263 level 45 and level 30 could be two values for highest level as
                // they don't include one another. For now we use the last supported value.
                C2StreamProfileLevelInfo pl(encoder /* output */, 0u);
                std::vector<C2FieldSupportedValuesQuery> profileQuery = {
                    C2FieldSupportedValuesQuery::Possible(C2ParamField(&pl, &pl.profile))
                };

                c2_status_t err = intf->querySupportedValues(profileQuery, C2_DONT_BLOCK);
                ALOGV("query supported profiles -> %s | %s",
                        asString(err), asString(profileQuery[0].status));
                if (err == C2_OK && profileQuery[0].status == C2_OK) {
                    if (profileQuery[0].values.type == C2FieldSupportedValues::VALUES) {
                        std::vector<std::shared_ptr<C2ParamDescriptor>> paramDescs;
                        c2_status_t err1 = intf->querySupportedParams(&paramDescs);
                        bool isHdr = false, isHdr10Plus = false;
                        if (err1 == C2_OK) {
                            for (const std::shared_ptr<C2ParamDescriptor> &desc : paramDescs) {
                                if ((uint32_t)desc->index() ==
                                        C2StreamHdr10PlusInfo::output::PARAM_TYPE) {
                                    isHdr10Plus = true;
                                } else if ((uint32_t)desc->index() ==
                                        C2StreamHdrStaticInfo::output::PARAM_TYPE) {
                                    isHdr = true;
                                }
                            }
                        }
                        // For VP9, the static info is always propagated by framework.
                        isHdr |= (mediaType == MIMETYPE_VIDEO_VP9);

                        for (C2Value::Primitive profile : profileQuery[0].values.values) {
                            pl.profile = (C2Config::profile_t)profile.ref<uint32_t>();
                            std::vector<std::unique_ptr<C2SettingResult>> failures;
                            err = intf->config({&pl}, C2_DONT_BLOCK, &failures);
                            ALOGV("set profile to %u -> %s", pl.profile, asString(err));
                            std::vector<C2FieldSupportedValuesQuery> levelQuery = {
                                C2FieldSupportedValuesQuery::Current(C2ParamField(&pl, &pl.level))
                            };
                            err = intf->querySupportedValues(levelQuery, C2_DONT_BLOCK);
                            ALOGV("query supported levels -> %s | %s",
                                    asString(err), asString(levelQuery[0].status));
                            if (err == C2_OK && levelQuery[0].status == C2_OK) {
                                if (levelQuery[0].values.type == C2FieldSupportedValues::VALUES
                                        && levelQuery[0].values.values.size() > 0) {
                                    C2Value::Primitive level = levelQuery[0].values.values.back();
                                    pl.level = (C2Config::level_t)level.ref<uint32_t>();
                                    ALOGV("supporting level: %u", pl.level);
                                    int32_t sdkProfile, sdkLevel;
                                    if (mapper && mapper->mapProfile(pl.profile, &sdkProfile)
                                            && mapper->mapLevel(pl.level, &sdkLevel)) {
                                        caps->addProfileLevel(
                                                (uint32_t)sdkProfile, (uint32_t)sdkLevel);
                                        gotProfileLevels = true;
                                        if (isHdr) {
                                            auto hdrMapper = C2Mapper::GetHdrProfileLevelMapper(
                                                    trait.mediaType);
                                            if (hdrMapper && hdrMapper->mapProfile(
                                                    pl.profile, &sdkProfile)) {
                                                caps->addProfileLevel(
                                                        (uint32_t)sdkProfile,
                                                        (uint32_t)sdkLevel);
                                            }
                                            if (isHdr10Plus) {
                                                hdrMapper = C2Mapper::GetHdrProfileLevelMapper(
                                                        trait.mediaType, true /*isHdr10Plus*/);
                                                if (hdrMapper && hdrMapper->mapProfile(
                                                        pl.profile, &sdkProfile)) {
                                                    caps->addProfileLevel(
                                                            (uint32_t)sdkProfile,
                                                            (uint32_t)sdkLevel);
                                                }
                                            }
                                        }
                                    } else if (!mapper) {
                                        caps->addProfileLevel(pl.profile, pl.level);
                                        gotProfileLevels = true;
                                    }

                                    // for H.263 also advertise the second highest level if the
                                    // codec supports level 45, as level 45 only covers level 10
                                    // TODO: move this to some form of a setting so it does not
                                    // have to be here
                                    if (mediaType == MIMETYPE_VIDEO_H263) {
                                        C2Config::level_t nextLevel = C2Config::LEVEL_UNUSED;
                                        for (C2Value::Primitive v : levelQuery[0].values.values) {
                                            C2Config::level_t level =
                                                (C2Config::level_t)v.ref<uint32_t>();
                                            if (level < C2Config::LEVEL_H263_45
                                                    && level > nextLevel) {
                                                nextLevel = level;
                                            }
                                        }
                                        if (nextLevel != C2Config::LEVEL_UNUSED
                                                && nextLevel != pl.level
                                                && mapper
                                                && mapper->mapProfile(pl.profile, &sdkProfile)
                                                && mapper->mapLevel(nextLevel, &sdkLevel)) {
                                            caps->addProfileLevel(
                                                    (uint32_t)sdkProfile, (uint32_t)sdkLevel);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (!gotProfileLevels) {
                if (mediaType == MIMETYPE_VIDEO_VP9) {
                    if (encoder) {
                        caps->addProfileLevel(VP9Profile0,    VP9Level41);
                    } else {
                        caps->addProfileLevel(VP9Profile0,    VP9Level5);
                        caps->addProfileLevel(VP9Profile2,    VP9Level5);
                        caps->addProfileLevel(VP9Profile2HDR, VP9Level5);
                    }
                } else if (mediaType == MIMETYPE_VIDEO_AV1 && !encoder) {
                    caps->addProfileLevel(AV1Profile0,      AV1Level2);
                    caps->addProfileLevel(AV1Profile0,      AV1Level21);
                    caps->addProfileLevel(AV1Profile1,      AV1Level22);
                    caps->addProfileLevel(AV1Profile1,      AV1Level3);
                    caps->addProfileLevel(AV1Profile2,      AV1Level31);
                    caps->addProfileLevel(AV1Profile2,      AV1Level32);
                } else if (mediaType == MIMETYPE_VIDEO_HEVC && !encoder) {
                    caps->addProfileLevel(HEVCProfileMain,      HEVCMainTierLevel51);
                    caps->addProfileLevel(HEVCProfileMainStill, HEVCMainTierLevel51);
                } else if (mediaType == MIMETYPE_VIDEO_VP8) {
                    if (encoder) {
                        caps->addProfileLevel(VP8ProfileMain, VP8Level_Version0);
                    } else {
                        caps->addProfileLevel(VP8ProfileMain, VP8Level_Version0);
                    }
                } else if (mediaType == MIMETYPE_VIDEO_AVC) {
                    if (encoder) {
                        caps->addProfileLevel(AVCProfileBaseline,            AVCLevel41);
//                      caps->addProfileLevel(AVCProfileConstrainedBaseline, AVCLevel41);
                        caps->addProfileLevel(AVCProfileMain,                AVCLevel41);
                    } else {
                        caps->addProfileLevel(AVCProfileBaseline,            AVCLevel52);
                        caps->addProfileLevel(AVCProfileConstrainedBaseline, AVCLevel52);
                        caps->addProfileLevel(AVCProfileMain,                AVCLevel52);
                        caps->addProfileLevel(AVCProfileConstrainedHigh,     AVCLevel52);
                        caps->addProfileLevel(AVCProfileHigh,                AVCLevel52);
                    }
                } else if (mediaType == MIMETYPE_VIDEO_MPEG4) {
                    if (encoder) {
                        caps->addProfileLevel(MPEG4ProfileSimple,  MPEG4Level2);
                    } else {
                        caps->addProfileLevel(MPEG4ProfileSimple,  MPEG4Level3);
                    }
                } else if (mediaType == MIMETYPE_VIDEO_H263) {
                    if (encoder) {
                        caps->addProfileLevel(H263ProfileBaseline, H263Level45);
                    } else {
                        caps->addProfileLevel(H263ProfileBaseline, H263Level30);
                        caps->addProfileLevel(H263ProfileBaseline, H263Level45);
                        caps->addProfileLevel(H263ProfileISWV2,    H263Level30);
                        caps->addProfileLevel(H263ProfileISWV2,    H263Level45);
                    }
                } else if (mediaType == MIMETYPE_VIDEO_MPEG2 && !encoder) {
                    caps->addProfileLevel(MPEG2ProfileSimple, MPEG2LevelHL);
                    caps->addProfileLevel(MPEG2ProfileMain,   MPEG2LevelHL);
                }
            }

            // TODO: get this from intf() as well, but how do we map them to
            // MediaCodec color formats?
            if (mediaType.find("video") != std::string::npos) {
                // vendor video codecs prefer opaque format
                if (trait.name.find("android") == std::string::npos) {
                    caps->addColorFormat(COLOR_FormatSurface);
                }
                caps->addColorFormat(COLOR_FormatYUV420Flexible);
                caps->addColorFormat(COLOR_FormatYUV420Planar);
                caps->addColorFormat(COLOR_FormatYUV420SemiPlanar);
                caps->addColorFormat(COLOR_FormatYUV420PackedPlanar);
                caps->addColorFormat(COLOR_FormatYUV420PackedSemiPlanar);
                // framework video encoders must support surface format, though it is unclear
                // that they will be able to map it if it is opaque
                if (encoder && trait.name.find("android") != std::string::npos) {
                    caps->addColorFormat(COLOR_FormatSurface);
                }
            }
        }
    }
    return OK;
}

}  // namespace android

extern "C" android::MediaCodecListBuilderBase *CreateBuilder() {
    return new android::Codec2InfoBuilder;
}

