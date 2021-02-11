
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

#pragma once

#include <media/stagefright/MetaData.h>
#include "MediaMimeTypes.h"

#define MAX_METADATA_BUF_SIZE 512

namespace android {

std::vector<std::shared_ptr<char>> generated_mime_types;

sp<MetaData> generateMetaData(FuzzedDataProvider *fdp) {
    sp<MetaData> newMeta = new MetaData();

    // random MIME Type
    const char *mime_type;
    size_t index = fdp->ConsumeIntegralInRange<size_t>(0, kMimeTypes.size());
    // Let there be a chance of a true random string
    if (index == kMimeTypes.size()) {
        std::string mime_str = fdp->ConsumeRandomLengthString(64);
        std::shared_ptr<char> mime_cstr(new char[mime_str.length()+1]);
        generated_mime_types.push_back(mime_cstr);
        strncpy(mime_cstr.get(), mime_str.c_str(), mime_str.length()+1);
        mime_type = mime_cstr.get();
    } else {
        mime_type = kMimeTypes[index];
    }
    newMeta->setCString(kKeyMIMEType, mime_type);

    // Thumbnail time
    newMeta->setInt64(kKeyThumbnailTime, fdp->ConsumeIntegral<int64_t>());

    // Values used by allocVideoFrame
    newMeta->setInt32(kKeyRotation, fdp->ConsumeIntegral<int32_t>());
    size_t profile_size =
        fdp->ConsumeIntegralInRange<size_t>(0, MAX_METADATA_BUF_SIZE);
    std::vector<uint8_t> profile_bytes =
        fdp->ConsumeBytes<uint8_t>(profile_size);
    newMeta->setData(kKeyIccProfile,
                     fdp->ConsumeIntegral<int32_t>(),
                     profile_bytes.empty() ? nullptr : profile_bytes.data(),
                     profile_bytes.size());
    newMeta->setInt32(kKeySARWidth, fdp->ConsumeIntegral<int32_t>());
    newMeta->setInt32(kKeySARHeight, fdp->ConsumeIntegral<int32_t>());
    newMeta->setInt32(kKeyDisplayWidth, fdp->ConsumeIntegral<int32_t>());
    newMeta->setInt32(kKeyDisplayHeight, fdp->ConsumeIntegral<int32_t>());

    // Values used by findThumbnailInfo
    newMeta->setInt32(kKeyThumbnailWidth, fdp->ConsumeIntegral<int32_t>());
    newMeta->setInt32(kKeyThumbnailHeight, fdp->ConsumeIntegral<int32_t>());
    size_t thumbnail_size =
        fdp->ConsumeIntegralInRange<size_t>(0, MAX_METADATA_BUF_SIZE);
    std::vector<uint8_t> thumb_bytes =
        fdp->ConsumeBytes<uint8_t>(thumbnail_size);
    newMeta->setData(kKeyThumbnailHVCC,
                     fdp->ConsumeIntegral<int32_t>(),
                     thumb_bytes.empty() ? nullptr : thumb_bytes.data(),
                     thumb_bytes.size());

    // Values used by findGridInfo
    newMeta->setInt32(kKeyTileWidth, fdp->ConsumeIntegral<int32_t>());
    newMeta->setInt32(kKeyTileHeight, fdp->ConsumeIntegral<int32_t>());
    newMeta->setInt32(kKeyGridRows, fdp->ConsumeIntegral<int32_t>());
    newMeta->setInt32(kKeyGridCols, fdp->ConsumeIntegral<int32_t>());

    // A few functions perform a CHECK() that height/width are set
    newMeta->setInt32(kKeyHeight, fdp->ConsumeIntegral<int32_t>());
    newMeta->setInt32(kKeyWidth, fdp->ConsumeIntegral<int32_t>());

    return newMeta;
}

}  // namespace android
