/*
 * Copyright 2024, The Android Open Source Project
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

#ifndef ENCODER_CAPABILITIES_H_

#define ENCODER_CAPABILITIES_H_

#include <string>
#include <vector>

#include <media/CodecCapabilitiesUtils.h>
#include <media/stagefright/foundation/AMessage.h>

#include <utils/StrongPointer.h>

namespace android {

/**
 * A class that supports querying the encoding capabilities of a codec.
 */
struct EncoderCapabilities {
    /**
    * Returns the supported range of quality values.
    *
    * Quality is implementation-specific. As a general rule, a higher quality
    * setting results in a better image quality and a lower compression ratio.
    */
    const Range<int>& getQualityRange();

    /**
     * Returns the supported range of encoder complexity values.
     * <p>
     * Some codecs may support multiple complexity levels, where higher
     * complexity values use more encoder tools (e.g. perform more
     * intensive calculations) to improve the quality or the compression
     * ratio.  Use a lower value to save power and/or time.
     */
    const Range<int>& getComplexityRange();

    /** Constant quality mode */
    inline static constexpr int BITRATE_MODE_CQ = 0;
    /** Variable bitrate mode */
    inline static constexpr int BITRATE_MODE_VBR = 1;
    /** Constant bitrate mode */
    inline static constexpr int BITRATE_MODE_CBR = 2;
    /** Constant bitrate mode with frame drops */
    inline static constexpr int BITRATE_MODE_CBR_FD =  3;

    /**
     * Query whether a bitrate mode is supported.
     */
    bool isBitrateModeSupported(int mode);

    /**
     * Query the supported layers schemas. Returns an array of null-terminated C-style strings,
     * or an empty array if supported layers schema is unknown.
     *
     * Note: This method returns pointers to internal data and is intended for use by the NDK API
     * to return these pointers verbatim to the caller.
     */
    const std::vector<const char*>& getSupportedLayeringSchemasPointers();

    /** @hide */
    static std::shared_ptr<EncoderCapabilities> Create(std::string mediaType,
            std::vector<ProfileLevel> profLevs, const sp<AMessage> &format);

    /** @hide */
    void getDefaultFormat(sp<AMessage> &format);

    /** @hide */
    bool supportsFormat(const sp<AMessage> &format);

private:
    inline static const Feature sBitrateModes[] = {
        Feature("VBR", BITRATE_MODE_VBR, true),
        Feature("CBR", BITRATE_MODE_CBR, false),
        Feature("CQ",  BITRATE_MODE_CQ,  false),
        Feature("CBR-FD", BITRATE_MODE_CBR_FD, false)
    };
    static int ParseBitrateMode(std::string mode);

    std::string mMediaType;
    std::vector<ProfileLevel> mProfileLevels;

    Range<int> mQualityRange;
    Range<int> mComplexityRange;
    std::vector<std::string> mLayeringSchemas;
    std::vector<const char*> mLayeringSchemaPointerArray;
    int mBitControl;
    int mDefaultComplexity;
    int mDefaultQuality;
    std::string mQualityScale;

    /* no public constructor */
    EncoderCapabilities() {}
    void init(std::string mediaType, std::vector<ProfileLevel> profLevs,
            const sp<AMessage> &format);
    void applyLevelLimits();
    void parseFromInfo(const sp<AMessage> &format);
    bool supports(std::optional<int> complexity, std::optional<int> quality,
                  std::optional<int> profile);
};

}  // namespace android

#endif  // ENCODER_CAPABILITIES_H_
