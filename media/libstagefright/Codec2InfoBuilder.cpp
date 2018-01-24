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
#include <media/stagefright/Codec2InfoBuilder.h>

namespace android {

using ConstTraitsPtr = std::shared_ptr<const C2Component::Traits>;

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

    for (const ConstTraitsPtr &trait : traits) {
        std::unique_ptr<MediaCodecInfoWriter> codecInfo = writer->addMediaCodecInfo();
        codecInfo->setName(trait->name.c_str());
        codecInfo->setOwner("dummy");
        // TODO: get this from trait->kind
        codecInfo->setEncoder(trait->name.find("encoder") != std::string::npos);
        codecInfo->setRank(trait->rank);
        (void)codecInfo->addMime(trait->mediaType.c_str());
    }
    return OK;
}

}  // namespace android
