/*
 * Copyright 2021, The Android Open Source Project
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

#ifndef LIBMEDIAFORMATSHAPER_VQOPS_H_
#define LIBMEDIAFORMATSHAPER_VQOPS_H_

#include "CodecProperties.h"
#include <media/NdkMediaFormat.h>

namespace android {
namespace mediaformatshaper {

// parameterized info for the different mediaType types
typedef struct {
    const char *mediaType;

    int32_t qpMin;      // codec type limit (e.g. h264, not c2.android.avc.encoder)
    int32_t qpMax;
    int32_t qpDelta;    // from I to P to B

} vqOps_t;

int VQApply(CodecProperties *codec, vqOps_t *info, AMediaFormat* inFormat, int flags);

// spread the overall QP setting to any un-set per-frame-type settings
void qpSpreadPerFrameType(AMediaFormat *format, int delta, int qplow, int qphigh, bool override);
void qpSpreadMaxPerFrameType(AMediaFormat *format, int delta, int qphigh, bool override);
void qpSpreadMinPerFrameType(AMediaFormat *format, int qplow, bool override);
void qpVerifyMinMaxOrdering(AMediaFormat *format);

// does the format have QP bounding entries
bool hasQpMax(AMediaFormat *format);
bool hasQpMaxGlobal(AMediaFormat *format);
bool hasQpMaxPerFrameType(AMediaFormat *format);

}  // namespace mediaformatshaper
}  // namespace android

#endif  // LIBMEDIAFORMATSHAPER_VQOPS_H_
