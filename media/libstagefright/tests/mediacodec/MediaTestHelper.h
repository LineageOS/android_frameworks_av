/*
 * Copyright 2020, The Android Open Source Project
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

#ifndef MEDIA_TEST_HELPER_H_

#define MEDIA_TEST_HELPER_H_

#include <media/stagefright/foundation/AString.h>
#include <utils/StrongPointer.h>

namespace android {

struct ALooper;
struct CodecBase;
struct MediaCodec;
struct MediaCodecInfo;
struct MediaCodecListWriter;

class MediaTestHelper {
public:
    // MediaCodec
    static sp<MediaCodec> CreateCodec(
            const AString &name,
            const sp<ALooper> &looper,
            std::function<sp<CodecBase>(const AString &, const char *)> getCodecBase,
            std::function<status_t(const AString &, sp<MediaCodecInfo> *)> getCodecInfo);
    static void Reclaim(const sp<MediaCodec> &codec, bool force);

    // MediaCodecListWriter
    static std::shared_ptr<MediaCodecListWriter> CreateCodecListWriter();
    static void WriteCodecInfos(
            const std::shared_ptr<MediaCodecListWriter> &writer,
            std::vector<sp<MediaCodecInfo>> *codecInfos);
};

}  // namespace android

#endif  // MEDIA_TEST_HELPER_H_
