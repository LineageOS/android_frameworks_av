/*
 * Copyright (C) 2021 The Android Open Source Project
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
#define LOG_TAG "VideoShaper"
#include <utils/Log.h>

#include <string>
#include <inttypes.h>

#include <media/NdkMediaFormat.h>

#include "CodecProperties.h"
#include "VideoShaper.h"
#include "VQops.h"

namespace android {
namespace mediaformatshaper {

// mediatype-specific operations

vqOps_t mediaInfo[] = {
    {
        .mediaType = "video/avc",
        .qpMin = 0,
        .qpMax = 51,
        .qpDelta = 3,
    },
    {
        .mediaType = "video/hevc",
        .qpMin = 0,
        .qpMax = 51,
        .qpDelta = 3,
    },
    {
        .mediaType = NULL,                // matches everything, it must come last
        .qpMin = INT32_MIN,
        .qpMax = INT32_MAX,
        .qpDelta = 3,
    }
};
int nMediaInfos = sizeof(mediaInfo) / sizeof(mediaInfo[0]);

//
// Caller retains ownership of and responsibility for inFormat
//

int videoShaper(CodecProperties *codec, AMediaFormat* inFormat, int flags) {
    if (codec == nullptr) {
        return -1;
    }
    ALOGV("codec %s inFormat %p flags x%x", codec->getName().c_str(), inFormat, flags);

    int ix;

    std::string mediaType = codec->getMediaType();
    // we should always come out of this with a selection, because the final entry
    // is deliberaly a NULL -- so that it will act as a default
    for(ix = 0; mediaInfo[ix].mediaType != NULL; ix++) {
        if (strcmp(mediaType.c_str(), mediaInfo[ix].mediaType) == 0) {
            break;
        }
    }
    if (ix >= nMediaInfos) {
        // shouldn't happen, but if it does .....
    }

    vqOps_t *info = &mediaInfo[ix];

    // apply any quality transforms in here..
    (void) VQApply(codec, info, inFormat, flags);

    // We always spread any QP parameters.
    // Sometimes it's something we inserted here, sometimes it's a value that the user injected.
    //
    qpSpreadPerFrameType(inFormat, info->qpDelta, info->qpMin, info->qpMax, /* override */ true);

    //
    return 0;

}

}  // namespace mediaformatshaper
}  // namespace android

