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

// Test AAudio attributes such as Usage, ContentType, InputPreset and Tags.

// TODO Many of these tests are duplicates of CTS tests in
// "test_aaudio_attributes.cpp". That other file is more current.
// So these tests could be deleted.
// Also note audio attributes tags, which is system api, it cannot be tested
// from the CTS. In that case, please do not delete audio attributes tags test.

#include <algorithm>
#include <memory>
#include <stdio.h>
#include <unistd.h>
#include <vector>

#include <aaudio/AAudio.h>
#include <gtest/gtest.h>
#include <system/audio.h>
#include <system/aaudio/AAudio.h>

constexpr int64_t kNanosPerSecond = 1000000000;
constexpr int kNumFrames = 256;
constexpr int kChannelCount = 2;

constexpr int32_t DONT_SET = -1000;

static void checkAttributes(aaudio_performance_mode_t perfMode,
                            aaudio_usage_t usage,
                            aaudio_content_type_t contentType,
                            std::vector<const char*>* tags = nullptr,
                            aaudio_input_preset_t preset = DONT_SET,
                            aaudio_allowed_capture_policy_t capturePolicy = DONT_SET,
                            int privacyMode = DONT_SET,
                            aaudio_direction_t direction = AAUDIO_DIRECTION_OUTPUT,
                            const char* tagToBeCleared = "TagsToBeCleared") {

    std::unique_ptr<float[]> buffer(new float[kNumFrames * kChannelCount]);

    AAudioStreamBuilder *aaudioBuilder = nullptr;
    AAudioStream *aaudioStream = nullptr;
    aaudio_result_t expectedAddTagResult = AAUDIO_OK;

    // Use an AAudioStreamBuilder to contain requested parameters.
    ASSERT_EQ(AAUDIO_OK, AAudio_createStreamBuilder(&aaudioBuilder));

    // Request stream properties.
    AAudioStreamBuilder_setPerformanceMode(aaudioBuilder, perfMode);
    AAudioStreamBuilder_setDirection(aaudioBuilder, direction);

    // Set the attribute in the builder.
    if (usage != DONT_SET) {
        AAudioStreamBuilder_setUsage(aaudioBuilder, usage);
    }
    if (contentType != DONT_SET) {
        AAudioStreamBuilder_setContentType(aaudioBuilder, contentType);
    }
    std::set<std::string> addedTags;
    if (tags != nullptr) {
        EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_addTag(aaudioBuilder, tagToBeCleared));
        AAudioStreamBuilder_clearTags(aaudioBuilder);
        int totalLength = 0;
        for (int i = 0; i < tags->size(); ++i) {
            if (tags->at(i) == nullptr) {
                EXPECT_EQ(AAUDIO_ERROR_ILLEGAL_ARGUMENT,
                          AAudioStreamBuilder_addTag(aaudioBuilder, tags->at(i)));
                continue;
            }
            // When sending all tags across the framework and the HAL, all tags are joined as a
            // string. In that case, a delimiter will be added if the tag is not the last added
            // tag or NULL terminator will be added if the tag is the last added tag.
            int lengthToAdd = strlen(tags->at(i)) + 1;
            totalLength += lengthToAdd;
            aaudio_result_t result = AAudioStreamBuilder_addTag(aaudioBuilder, tags->at(i));
            expectedAddTagResult = (totalLength > AUDIO_ATTRIBUTES_TAGS_MAX_SIZE) ?
                                   AAUDIO_ERROR_OUT_OF_RANGE : AAUDIO_OK;
            EXPECT_EQ(result, expectedAddTagResult) << "total length=" << totalLength;
            if (expectedAddTagResult != AAUDIO_OK) {
                totalLength -= lengthToAdd;
            } else {
                addedTags.insert(tags->at(i));
            }
        }
    }
    if (preset != DONT_SET) {
        AAudioStreamBuilder_setInputPreset(aaudioBuilder, preset);
    }
    if (capturePolicy != DONT_SET) {
        AAudioStreamBuilder_setAllowedCapturePolicy(aaudioBuilder, capturePolicy);
    }
    if (privacyMode != DONT_SET) {
        AAudioStreamBuilder_setPrivacySensitive(aaudioBuilder, (bool)privacyMode);
    }

    // Create an AAudioStream using the Builder.
    ASSERT_EQ(AAUDIO_OK, AAudioStreamBuilder_openStream(aaudioBuilder, &aaudioStream));
    AAudioStreamBuilder_delete(aaudioBuilder);

    // Make sure we get the same attributes back from the stream.
    aaudio_usage_t expectedUsage =
            (usage == DONT_SET || usage == AAUDIO_UNSPECIFIED)
            ? AAUDIO_USAGE_MEDIA // default
            : usage;
    EXPECT_EQ(expectedUsage, AAudioStream_getUsage(aaudioStream));

    aaudio_content_type_t expectedContentType =
            (contentType == DONT_SET || contentType == AAUDIO_UNSPECIFIED)
            ? AAUDIO_CONTENT_TYPE_MUSIC // default
            : contentType;
    EXPECT_EQ(expectedContentType, AAudioStream_getContentType(aaudioStream));

    char** readTags = nullptr;
    const int32_t numOfTagsRead = AAudioStream_obtainTags(aaudioStream, &readTags);
    EXPECT_EQ(addedTags.size(), numOfTagsRead);
    EXPECT_EQ(numOfTagsRead == 0, readTags == nullptr);
    std::set<std::string> readTagsSet;
    for (int i = 0; i < numOfTagsRead; ++i) {
        readTagsSet.insert(readTags[i]);
    }
    EXPECT_EQ(addedTags, readTagsSet);
    AAudioStream_destroyTags(aaudioStream, readTags);

    aaudio_input_preset_t expectedPreset =
            (preset == DONT_SET || preset == AAUDIO_UNSPECIFIED)
            ? AAUDIO_INPUT_PRESET_VOICE_RECOGNITION // default
            : preset;
    EXPECT_EQ(expectedPreset, AAudioStream_getInputPreset(aaudioStream));

    aaudio_allowed_capture_policy_t expectedCapturePolicy =
            (capturePolicy == DONT_SET || capturePolicy == AAUDIO_UNSPECIFIED)
            ? AAUDIO_ALLOW_CAPTURE_BY_ALL // default
            : capturePolicy;
    EXPECT_EQ(expectedCapturePolicy, AAudioStream_getAllowedCapturePolicy(aaudioStream));

    bool expectedPrivacyMode =
            (privacyMode == DONT_SET) ?
                ((preset == AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION
                    || preset == AAUDIO_INPUT_PRESET_CAMCORDER) ? true : false) :
                privacyMode;
    EXPECT_EQ(expectedPrivacyMode, AAudioStream_isPrivacySensitive(aaudioStream));

    EXPECT_EQ(AAUDIO_OK, AAudioStream_requestStart(aaudioStream));

    if (direction == AAUDIO_DIRECTION_INPUT) {
        EXPECT_EQ(kNumFrames,
                  AAudioStream_read(aaudioStream, buffer.get(), kNumFrames, kNanosPerSecond));
    } else {
        EXPECT_EQ(kNumFrames,
                  AAudioStream_write(aaudioStream, buffer.get(), kNumFrames, kNanosPerSecond));
    }

    EXPECT_EQ(AAUDIO_OK, AAudioStream_requestStop(aaudioStream));

    EXPECT_EQ(AAUDIO_OK, AAudioStream_close(aaudioStream));
}

static const aaudio_usage_t sUsages[] = {
    DONT_SET,
    AAUDIO_UNSPECIFIED,
    AAUDIO_USAGE_MEDIA,
    AAUDIO_USAGE_VOICE_COMMUNICATION,
    AAUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
    AAUDIO_USAGE_ALARM,
    AAUDIO_USAGE_NOTIFICATION,
    AAUDIO_USAGE_NOTIFICATION_RINGTONE,
    AAUDIO_USAGE_NOTIFICATION_EVENT,
    AAUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
    AAUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
    AAUDIO_USAGE_ASSISTANCE_SONIFICATION,
    AAUDIO_USAGE_GAME,
    AAUDIO_USAGE_ASSISTANT,
    // Note that the AAUDIO_SYSTEM_USAGE_* values requires special permission.
};

static const std::string oversizedTags2 = std::string(AUDIO_ATTRIBUTES_TAGS_MAX_SIZE + 1, 'A');
static const std::string oversizedTags = std::string(AUDIO_ATTRIBUTES_TAGS_MAX_SIZE, 'B');
static const std::string maxSizeTags = std::string(AUDIO_ATTRIBUTES_TAGS_MAX_SIZE - 1, 'C');

static const int TOTAL_TAGS = 7;
static const char * const sTags[TOTAL_TAGS] = {
    nullptr,
    "",
    "oem=routing_extension",
    "VX_OEM_ROUTING_EXTENSION",
    maxSizeTags.c_str(),
    // intentionnaly use oversized tags
    oversizedTags.c_str(),
    oversizedTags2.c_str()
};

static const aaudio_content_type_t sContentypes[] = {
    DONT_SET,
    AAUDIO_UNSPECIFIED,
    AAUDIO_CONTENT_TYPE_SPEECH,
    AAUDIO_CONTENT_TYPE_MUSIC,
    AAUDIO_CONTENT_TYPE_MOVIE,
    AAUDIO_CONTENT_TYPE_SONIFICATION
};

static const aaudio_input_preset_t sInputPresets[] = {
    DONT_SET,
    AAUDIO_UNSPECIFIED,
    AAUDIO_INPUT_PRESET_GENERIC,
    AAUDIO_INPUT_PRESET_CAMCORDER,
    AAUDIO_INPUT_PRESET_VOICE_RECOGNITION,
    AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION,
    AAUDIO_INPUT_PRESET_UNPROCESSED,
    AAUDIO_INPUT_PRESET_VOICE_PERFORMANCE,
};

static const aaudio_input_preset_t sAllowCapturePolicies[] = {
    DONT_SET,
    AAUDIO_UNSPECIFIED,
    AAUDIO_ALLOW_CAPTURE_BY_ALL,
    AAUDIO_ALLOW_CAPTURE_BY_SYSTEM,
    AAUDIO_ALLOW_CAPTURE_BY_NONE,
};

static const int sPrivacyModes[] = {
    DONT_SET,
    false,
    true,
};

static void checkAttributesUsage(aaudio_performance_mode_t perfMode) {
    for (aaudio_usage_t usage : sUsages) {
        checkAttributes(perfMode, usage, DONT_SET);
    }
}

static void checkAttributesContentType(aaudio_performance_mode_t perfMode) {
    for (aaudio_content_type_t contentType : sContentypes) {
        checkAttributes(perfMode, DONT_SET, contentType);
    }
}

static void checkAttributesTags(aaudio_performance_mode_t perfMode) {
    checkAttributes(perfMode, DONT_SET, DONT_SET, nullptr /*tags*/);
    for (int i = 0; i < TOTAL_TAGS; ++i) {
        std::vector<const char*> tags = {sTags[i]};
        if (i > 0) {
            tags.push_back(sTags[i-1]);
        }
        checkAttributes(perfMode, DONT_SET, DONT_SET, &tags);
    }
}

static void checkAttributesTagsInput(aaudio_performance_mode_t perfMode) {
    checkAttributes(perfMode, DONT_SET, DONT_SET, nullptr /*tags*/, DONT_SET, DONT_SET,
                    DONT_SET, AAUDIO_DIRECTION_INPUT);
    for (int i = 0; i < TOTAL_TAGS; ++i) {
        std::vector<const char*> tags = {sTags[i]};
        if (i > 0) {
            tags.push_back(sTags[i-1]);
        }
        checkAttributes(perfMode, DONT_SET, DONT_SET, &tags, DONT_SET, DONT_SET,
                        DONT_SET, AAUDIO_DIRECTION_INPUT);
    }
}

static void checkAttributesInputPreset(aaudio_performance_mode_t perfMode) {
    for (aaudio_input_preset_t inputPreset : sInputPresets) {
        checkAttributes(perfMode,
                        DONT_SET,
                        DONT_SET,
                        nullptr,
                        inputPreset,
                        DONT_SET,
                        DONT_SET,
                        AAUDIO_DIRECTION_INPUT);
    }
}

static void checkAttributesAllowedCapturePolicy(aaudio_performance_mode_t perfMode) {
    for (aaudio_allowed_capture_policy_t policy : sAllowCapturePolicies) {
        checkAttributes(perfMode,
                        DONT_SET,
                        DONT_SET,
                        nullptr,
                        DONT_SET,
                        policy,
                        AAUDIO_DIRECTION_INPUT);
    }
}

static void checkAttributesPrivacySensitive(aaudio_performance_mode_t perfMode) {
    for (int privacyMode : sPrivacyModes) {
        checkAttributes(perfMode,
                        DONT_SET,
                        DONT_SET,
                        nullptr,
                        DONT_SET,
                        DONT_SET,
                        privacyMode,
                        AAUDIO_DIRECTION_INPUT);
    }
}

TEST(test_attributes, aaudio_usage_perfnone) {
    checkAttributesUsage(AAUDIO_PERFORMANCE_MODE_NONE);
}

TEST(test_attributes, aaudio_content_type_perfnone) {
    checkAttributesContentType(AAUDIO_PERFORMANCE_MODE_NONE);
}

TEST(test_attributes, aaudio_tags_perfnone) {
    checkAttributesTags(AAUDIO_PERFORMANCE_MODE_NONE);
}

TEST(test_attributes, aaudio_tags_input_perfnone) {
    checkAttributesTagsInput(AAUDIO_PERFORMANCE_MODE_NONE);
}

TEST(test_attributes, aaudio_input_preset_perfnone) {
    checkAttributesInputPreset(AAUDIO_PERFORMANCE_MODE_NONE);
}

TEST(test_attributes, aaudio_allowed_capture_policy_perfnone) {
    checkAttributesAllowedCapturePolicy(AAUDIO_PERFORMANCE_MODE_NONE);
}

TEST(test_attributes, aaudio_usage_lowlat) {
    checkAttributesUsage(AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
}

TEST(test_attributes, aaudio_content_type_lowlat) {
    checkAttributesContentType(AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
}

TEST(test_attributes, aaudio_tags_lowlat) {
    checkAttributesTags(AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
}

TEST(test_attributes, aaudio_tags_input_lowlat) {
    checkAttributesTagsInput(AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
}

TEST(test_attributes, aaudio_input_preset_lowlat) {
    checkAttributesInputPreset(AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
}

TEST(test_attributes, aaudio_allowed_capture_policy_lowlat) {
    checkAttributesAllowedCapturePolicy(AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
}

TEST(test_attributes, aaudio_allowed_privacy_sensitive_lowlat) {
    checkAttributesPrivacySensitive(AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
}
