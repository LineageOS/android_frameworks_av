/*
 * Copyright (C) 2022 The Android Open Source Project
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
#include "tests/UsecaseValidator-test.h"

#include <gtest/gtest.h>

namespace android {
namespace media {

/**
 * Helper test functions.
 */

/**
 * Register a mock stream.
 */
audio_io_handle_t UsecaseValidatorTest::testRegisterStream(bool outputFlagGame) {
    static int streamId = 0;
    status_t result;
    static audio_config_base_t audioConfig = AUDIO_CONFIG_BASE_INITIALIZER;
    audio_output_flags_t outputFlags = outputFlagGame ? GAME_OUTPUT_FLAGS : MEDIA_OUTPUT_FLAGS;

    result = m_validator->registerStream(++streamId, audioConfig, outputFlags);

    return result == OK ? streamId : 0;
}

/**
 * Create a mock portId.
 */
audio_port_handle_t UsecaseValidatorTest::testCreatePortId(audio_io_handle_t streamId) {
    static int portId = 0;

    return (streamId << 8) | (++portId);
}

/**
 * Add a mock portId to a stream and verify.
 */
error::Result<audio_attributes_t> UsecaseValidatorTest::testStartClient(audio_io_handle_t streamId,
        audio_port_handle_t portId,
        audio_attributes_t attributes) {
    content::AttributionSourceState attributionSource;

    return m_validator->startClient(streamId, portId, attributionSource, attributes, NULL);
}

/**
 * Verify a mock stream.
 */
error::Result<audio_attributes_t> UsecaseValidatorTest::testVerifyAudioAttributes(
        audio_io_handle_t streamId,
        audio_usage_t usage) {
    content::AttributionSourceState attributionSource;
    audio_attributes_t attributes = AUDIO_ATTRIBUTES_INITIALIZER;
    attributes.usage = usage;

    return m_validator->verifyAudioAttributes(streamId, attributionSource, attributes);
}

/**
 * Test functions.
 */

/**
 * Test adding and removing streams.
 */
TEST_F(UsecaseLookupTest, testAddAndRemoveStream) {
    addStream(1, false);
    addStream(2, true);

    EXPECT_NE(m_streams.find(1), m_streams.end());
    EXPECT_NE(m_streams.find(2), m_streams.end());
    EXPECT_EQ(m_streams.find(3), m_streams.end());

    EXPECT_FALSE(isGameStream(1));
    EXPECT_TRUE(isGameStream(2));
    EXPECT_FALSE(isGameStream(3));

    removeStream(2);

    EXPECT_FALSE(isGameStream(2));
}

/**
 * Verify attributes usage for stream.
 */
TEST_F(UsecaseValidatorTest, testAttributesUsage) {
    audio_io_handle_t gameStreamId, mediaStreamId;

    // Register game and media stream.
    gameStreamId = testRegisterStream(true);
    mediaStreamId = testRegisterStream(false);
    EXPECT_NE(gameStreamId, 0);
    EXPECT_NE(mediaStreamId, 0);
    EXPECT_NE(gameStreamId, mediaStreamId);

    // Verify attributes on game stream.
    auto attr = testVerifyAudioAttributes(gameStreamId, AUDIO_USAGE_GAME);
    EXPECT_EQ(attr.value().usage, AUDIO_USAGE_GAME);

    // Verify attributes on media stream.
    attr = testVerifyAudioAttributes(mediaStreamId, AUDIO_USAGE_MEDIA);
    EXPECT_EQ(attr.value().usage, AUDIO_USAGE_MEDIA);

    EXPECT_EQ(m_validator->unregisterStream(gameStreamId), 0);
    EXPECT_EQ(m_validator->unregisterStream(mediaStreamId), 0);
}

/**
 * Test hanging client.
 */
TEST_F(UsecaseValidatorTest, testHangingClient) {
    audio_io_handle_t gameStreamId, mediaStreamId;
    audio_port_handle_t gamePortId, mediaPortId;

    // Register game and media stream.
    gameStreamId = testRegisterStream(true);
    EXPECT_NE(gameStreamId, 0);
    mediaStreamId = testRegisterStream(false);
    EXPECT_NE(mediaStreamId, 0);

    // Assign portId.
    gamePortId = testCreatePortId(gameStreamId);
    EXPECT_NE(gamePortId, 0);
    mediaPortId = testCreatePortId(mediaStreamId);
    EXPECT_NE(mediaPortId, 0);

    audio_attributes_t attributes = AUDIO_ATTRIBUTES_INITIALIZER;
    attributes.usage = AUDIO_USAGE_GAME;
    // Start client on game stream.
    testStartClient(gameStreamId, gamePortId, attributes);

    attributes.usage = AUDIO_USAGE_MEDIA;
    // Start client on media stream.
    testStartClient(mediaStreamId, mediaPortId, attributes);

    // Unregister media stream before stopClient.
    EXPECT_EQ(m_validator->unregisterStream(gameStreamId), 0);
    EXPECT_EQ(m_validator->unregisterStream(mediaStreamId), 0);
}

/**
 * Verify attributes usage does not change.
 */
TEST_F(UsecaseValidatorTest, testAttributesUsageUnchanged) {
    audio_io_handle_t gameStreamId, mediaStreamId;
    audio_port_handle_t gamePortId, mediaPortId, unknownPortId, voiceCommPortId;

    // Register game and media stream.
    gameStreamId = testRegisterStream(true);
    EXPECT_NE(gameStreamId, 0);
    mediaStreamId = testRegisterStream(false);
    EXPECT_NE(mediaStreamId, 0);

    // Assign portId.
    gamePortId = testCreatePortId(gameStreamId);
    EXPECT_NE(gamePortId, 0);
    mediaPortId = testCreatePortId(mediaStreamId);
    EXPECT_NE(mediaPortId, 0);
    unknownPortId = testCreatePortId(mediaStreamId);
    EXPECT_NE(unknownPortId, 0);
    voiceCommPortId = testCreatePortId(gameStreamId);
    EXPECT_NE(voiceCommPortId, 0);

    audio_attributes_t attributes = AUDIO_ATTRIBUTES_INITIALIZER;
    // Verify attributes on game stream.
    attributes.usage = AUDIO_USAGE_GAME;
    auto attr = testStartClient(gameStreamId, gamePortId, attributes);
    EXPECT_EQ(attr.value().usage, AUDIO_USAGE_GAME);

    attributes.usage = AUDIO_USAGE_VOICE_COMMUNICATION;
    attr = testStartClient(gameStreamId, voiceCommPortId, attributes);
    EXPECT_EQ(attr.value().usage, AUDIO_USAGE_VOICE_COMMUNICATION);

    // Verify attributes on media stream.
    attributes.usage = AUDIO_USAGE_MEDIA;
    attr = testStartClient(mediaStreamId, mediaPortId, attributes);
    EXPECT_EQ(attr.value().usage, AUDIO_USAGE_MEDIA);

    attributes.usage = AUDIO_USAGE_UNKNOWN;
    attr = testStartClient(mediaStreamId, unknownPortId, attributes);
    EXPECT_EQ(attr.value().usage, AUDIO_USAGE_UNKNOWN);

    // Stop client on game and media stream.
    EXPECT_EQ(m_validator->stopClient(gameStreamId, gamePortId), 0);
    EXPECT_EQ(m_validator->stopClient(mediaStreamId, mediaPortId), 0);

    // Unregister game and media stream.
    EXPECT_EQ(m_validator->unregisterStream(gameStreamId), 0);
    EXPECT_EQ(m_validator->unregisterStream(mediaStreamId), 0);
}

/**
 * Verify attributes usage changes.
 */
TEST_F(UsecaseValidatorTest, testAttributesUsageChanged) {
    audio_io_handle_t gameStreamId;
    audio_port_handle_t mediaPortId, unknownPortId;

    // Register game and media stream.
    gameStreamId = testRegisterStream(true);
    EXPECT_NE(gameStreamId, 0);

    // Assign portId.
    mediaPortId = testCreatePortId(gameStreamId);
    EXPECT_NE(mediaPortId, 0);
    unknownPortId = testCreatePortId(gameStreamId);
    EXPECT_NE(unknownPortId, 0);

    audio_attributes_t attributes = AUDIO_ATTRIBUTES_INITIALIZER;
    attributes.flags = AUDIO_FLAG_LOW_LATENCY;
    // Verify attributes on game stream.
    attributes.usage = AUDIO_USAGE_MEDIA;
    auto attr = testStartClient(gameStreamId, mediaPortId, attributes);
    EXPECT_EQ(attr.value().usage, AUDIO_USAGE_GAME);

    attributes.usage = AUDIO_USAGE_UNKNOWN;
    attr = testStartClient(gameStreamId, unknownPortId, attributes);
    EXPECT_EQ(attr.value().usage, AUDIO_USAGE_GAME);

    // Unregister game stream.
    EXPECT_EQ(m_validator->unregisterStream(gameStreamId), 0);
}

/**
 * Verify attributes usage does not change for non low latency clients.
 */
TEST_F(UsecaseValidatorTest, testAttributesUsageUnChangedIfNotLowLatency) {
    audio_io_handle_t gameStreamId;
    audio_port_handle_t mediaPortId, unknownPortId;

    // Register game and media stream.
    gameStreamId = testRegisterStream(true);
    EXPECT_NE(gameStreamId, 0);

    // Assign portId.
    mediaPortId = testCreatePortId(gameStreamId);
    EXPECT_NE(mediaPortId, 0);
    unknownPortId = testCreatePortId(gameStreamId);
    EXPECT_NE(unknownPortId, 0);

    audio_attributes_t attributes = AUDIO_ATTRIBUTES_INITIALIZER;
    // Verify attributes on game stream.
    attributes.usage = AUDIO_USAGE_MEDIA;
    auto attr = testStartClient(gameStreamId, mediaPortId, attributes);
    EXPECT_EQ(attr.value().usage, AUDIO_USAGE_MEDIA);

    attributes.usage = AUDIO_USAGE_UNKNOWN;
    attr = testStartClient(gameStreamId, unknownPortId, attributes);
    EXPECT_EQ(attr.value().usage, AUDIO_USAGE_UNKNOWN);

    // Unregister game stream.
    EXPECT_EQ(m_validator->unregisterStream(gameStreamId), 0);
}

/**
 * Verify attributes usage does not change for content type speech.
 */
TEST_F(UsecaseValidatorTest, testAttributesUsageUnChangedIfSpeech) {
    audio_io_handle_t gameStreamId;
    audio_port_handle_t mediaPortId, unknownPortId;

    // Register game and media stream.
    gameStreamId = testRegisterStream(true);
    EXPECT_NE(gameStreamId, 0);

    // Assign portId.
    mediaPortId = testCreatePortId(gameStreamId);
    EXPECT_NE(mediaPortId, 0);
    unknownPortId = testCreatePortId(gameStreamId);
    EXPECT_NE(unknownPortId, 0);

    audio_attributes_t attributes = AUDIO_ATTRIBUTES_INITIALIZER;
    // Verify attributes on game stream.
    attributes.usage = AUDIO_USAGE_MEDIA;
    attributes.content_type = AUDIO_CONTENT_TYPE_SPEECH;
    auto attr = testStartClient(gameStreamId, mediaPortId, attributes);
    EXPECT_EQ(attr.value().usage, AUDIO_USAGE_MEDIA);

    // Unregister game stream.
    EXPECT_EQ(m_validator->unregisterStream(gameStreamId), 0);
}

}  // namespace media
}  // namespace android
