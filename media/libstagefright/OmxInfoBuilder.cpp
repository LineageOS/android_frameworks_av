/*
 * Copyright (C) 2017 The Android Open Source Project
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
#define LOG_TAG "OmxInfoBuilder"

#ifdef __LP64__
#define OMX_ANDROID_COMPILE_AS_32BIT_ON_64BIT_PLATFORMS
#endif

#include <utils/Log.h>
#include <cutils/properties.h>

#include <media/stagefright/foundation/MediaDefs.h>
#include <media/stagefright/OmxInfoBuilder.h>
#include <media/stagefright/ACodec.h>

#include <android/hardware/media/omx/1.0/IOmxStore.h>
#include <android/hardware/media/omx/1.0/IOmx.h>
#include <android/hardware/media/omx/1.0/IOmxNode.h>
#include <media/stagefright/omx/OMXUtils.h>

#include <media/IOMX.h>
#include <media/omx/1.0/WOmx.h>

#include <media/openmax/OMX_Index.h>
#include <media/openmax/OMX_IndexExt.h>
#include <media/openmax/OMX_Audio.h>
#include <media/openmax/OMX_AudioExt.h>
#include <media/openmax/OMX_Video.h>
#include <media/openmax/OMX_VideoExt.h>

namespace android {

using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using namespace ::android::hardware::media::omx::V1_0;

namespace /* unnamed */ {

bool hasPrefix(const hidl_string& s, const char* prefix) {
    return strncmp(s.c_str(), prefix, strlen(prefix)) == 0;
}

status_t queryCapabilities(
        const IOmxStore::NodeInfo& node, const char* mime, bool isEncoder,
        MediaCodecInfo::CapabilitiesWriter* caps) {
    sp<ACodec> codec = new ACodec();
    status_t err = codec->queryCapabilities(
            node.owner.c_str(), node.name.c_str(), mime, isEncoder, caps);
    if (err != OK) {
        return err;
    }
    for (const auto& attribute : node.attributes) {
        // All features have an int32 value except
        // "feature-bitrate-modes", which has a string value.
        if (hasPrefix(attribute.key, "feature-") &&
                !hasPrefix(attribute.key, "feature-bitrate-modes")) {
            // If this attribute.key is a feature that is not bitrate modes,
            // add an int32 value.
            caps->addDetail(
                    attribute.key.c_str(),
                    hasPrefix(attribute.value, "1") ? 1 : 0);
        } else {
            // Non-feature attributes
            caps->addDetail(
                    attribute.key.c_str(), attribute.value.c_str());
        }
    }
    return OK;
}

}  // unnamed namespace

OmxInfoBuilder::OmxInfoBuilder() {
}

status_t OmxInfoBuilder::buildMediaCodecList(MediaCodecListWriter* writer) {
    hidl_vec<IOmxStore::RoleInfo> roles;

    // Obtain IOmxStore
    sp<IOmxStore> omxStore = IOmxStore::getService();
    if (omxStore == nullptr) {
        ALOGE("Cannot find an IOmxStore service.");
        return NO_INIT;
    }

    // List service attributes (global settings)
    Status status;
    hidl_vec<IOmxStore::ServiceAttribute> serviceAttributes;
    auto transStatus = omxStore->listServiceAttributes(
            [&status, &serviceAttributes] (
            Status inStatus,
            const hidl_vec<IOmxStore::ServiceAttribute>& inAttributes) {
                status = inStatus;
                serviceAttributes = inAttributes;
            });
    if (!transStatus.isOk()) {
        ALOGE("Fail to obtain global settings from IOmxStore.");
        return NO_INIT;
    }
    if (status != Status::OK) {
        ALOGE("IOmxStore reports parsing error.");
        return NO_INIT;
    }
    for (const auto& p : serviceAttributes) {
        writer->addGlobalSetting(
                p.key.c_str(), p.value.c_str());
    }

    transStatus = omxStore->listRoles(
            [&roles] (
            const hidl_vec<IOmxStore::RoleInfo>& inRoleList) {
                roles = inRoleList;
            });
    if (!transStatus.isOk()) {
        ALOGE("Fail to obtain codec roles from IOmxStore.");
        return NO_INIT;
    }

    // Convert roles to lists of codecs

    // codec name -> index into swCodecs/hwCodecs
    std::map<hidl_string, std::unique_ptr<MediaCodecInfoWriter>>
            swCodecName2Info, hwCodecName2Info;
    // owner name -> MediaCodecInfo
    // This map will be used to obtain the correct IOmx service(s) needed for
    // creating IOmxNode instances and querying capabilities.
    std::map<std::string, std::vector<sp<MediaCodecInfo> > >
            owner2CodecInfo;

    for (const auto& role : roles) {
        const auto& typeName = role.type;
        bool isEncoder = role.isEncoder;
        bool preferPlatformNodes = role.preferPlatformNodes;
        // If preferPlatformNodes is true, hardware nodes must be added after
        // platform (software) nodes. hwCodecs is used to hold hardware nodes
        // that need to be added after software nodes for the same role.
        std::vector<const IOmxStore::NodeInfo*> hwCodecs;
        for (const auto& node : role.nodes) {
            const auto& nodeName = node.name;
            bool isSoftware = hasPrefix(nodeName, "OMX.google");
            MediaCodecInfoWriter* info;
            if (isSoftware) {
                auto c2i = swCodecName2Info.find(nodeName);
                if (c2i == swCodecName2Info.end()) {
                    // Create a new MediaCodecInfo for a new node.
                    c2i = swCodecName2Info.insert(std::make_pair(
                            nodeName, writer->addMediaCodecInfo())).first;
                    info = c2i->second.get();
                    info->setName(nodeName.c_str());
                    info->setOwner(node.owner.c_str());
                    info->setEncoder(isEncoder);
                } else {
                    // The node has been seen before. Simply retrieve the
                    // existing MediaCodecInfoWriter.
                    info = c2i->second.get();
                }
            } else {
                auto c2i = hwCodecName2Info.find(nodeName);
                if (c2i == hwCodecName2Info.end()) {
                    // Create a new MediaCodecInfo for a new node.
                    if (!preferPlatformNodes) {
                        c2i = hwCodecName2Info.insert(std::make_pair(
                                nodeName, writer->addMediaCodecInfo())).first;
                        info = c2i->second.get();
                        info->setName(nodeName.c_str());
                        info->setOwner(node.owner.c_str());
                        info->setEncoder(isEncoder);
                    } else {
                        // If preferPlatformNodes is true, this node must be
                        // added after all software nodes.
                        hwCodecs.push_back(&node);
                        continue;
                    }
                } else {
                    // The node has been seen before. Simply retrieve the
                    // existing MediaCodecInfoWriter.
                    info = c2i->second.get();
                }
            }
            std::unique_ptr<MediaCodecInfo::CapabilitiesWriter> caps =
                    info->addMime(typeName.c_str());
            if (queryCapabilities(
                    node, typeName.c_str(), isEncoder, caps.get()) != OK) {
                ALOGW("Fail to add mime %s to codec %s",
                        typeName.c_str(), nodeName.c_str());
                info->removeMime(typeName.c_str());
            }
        }

        // If preferPlatformNodes is true, hardware nodes will not have been
        // added in the loop above, but rather saved in hwCodecs. They are
        // going to be added here.
        if (preferPlatformNodes) {
            for (const auto& node : hwCodecs) {
                MediaCodecInfoWriter* info;
                const auto& nodeName = node->name;
                auto c2i = hwCodecName2Info.find(nodeName);
                if (c2i == hwCodecName2Info.end()) {
                    // Create a new MediaCodecInfo for a new node.
                    c2i = hwCodecName2Info.insert(std::make_pair(
                            nodeName, writer->addMediaCodecInfo())).first;
                    info = c2i->second.get();
                    info->setName(nodeName.c_str());
                    info->setOwner(node->owner.c_str());
                    info->setEncoder(isEncoder);
                } else {
                    // The node has been seen before. Simply retrieve the
                    // existing MediaCodecInfoWriter.
                    info = c2i->second.get();
                }
                std::unique_ptr<MediaCodecInfo::CapabilitiesWriter> caps =
                        info->addMime(typeName.c_str());
                if (queryCapabilities(
                        *node, typeName.c_str(), isEncoder, caps.get()) != OK) {
                    ALOGW("Fail to add mime %s to codec %s "
                          "after software codecs",
                          typeName.c_str(), nodeName.c_str());
                    info->removeMime(typeName.c_str());
                }
            }
        }
    }
    return OK;
}

}  // namespace android

