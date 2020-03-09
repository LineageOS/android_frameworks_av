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

//#define LOG_NDEBUG 0
#define LOG_TAG "OpusHeaderTest"
#include <utils/Log.h>

#include <fstream>
#include <stdio.h>
#include <string.h>

#include <media/stagefright/foundation/OpusHeader.h>

#include "OpusHeaderTestEnvironment.h"

using namespace android;

#define OUTPUT_FILE_NAME "/data/local/tmp/OpusOutput"

// Opus in WebM is a well-known, yet under-documented, format. The codec private data
// of the track is an Opus Ogg header (https://tools.ietf.org/html/rfc7845#section-5.1)
// channel mapping offset in opus header
constexpr size_t kOpusHeaderStreamMapOffset = 21;
constexpr size_t kMaxOpusHeaderSize = 100;
// AOPUSHDR + AOPUSHDRLength +
// (8 + 8 ) +
// Header(csd) + num_streams + num_coupled + 1
// (19 + 1 + 1 + 1) +
// AOPUSDLY + AOPUSDLYLength + DELAY + AOPUSPRL + AOPUSPRLLength + PRL
// (8 + 8 + 8 + 8 + 8 + 8)
// = 86
constexpr size_t kOpusHeaderChannelMapOffset = 86;
constexpr uint32_t kOpusSampleRate = 48000;
constexpr uint64_t kOpusSeekPrerollNs = 80000000;
constexpr int64_t kNsecPerSec = 1000000000ll;

// Opus uses Vorbis channel mapping, and Vorbis channel mapping specifies
// mappings for up to 8 channels. This information is part of the Vorbis I
// Specification:
// http://www.xiph.org/vorbis/doc/Vorbis_I_spec.html
constexpr int kMaxChannels = 8;
constexpr uint8_t kOpusChannelMap[kMaxChannels][kMaxChannels] = {
        {0},
        {0, 1},
        {0, 2, 1},
        {0, 1, 2, 3},
        {0, 4, 1, 2, 3},
        {0, 4, 1, 2, 3, 5},
        {0, 4, 1, 2, 3, 5, 6},
        {0, 6, 1, 2, 3, 4, 5, 7},
};

static OpusHeaderTestEnvironment *gEnv = nullptr;

class OpusHeaderTest {
  public:
    OpusHeaderTest() : mInputBuffer(nullptr) {}

    ~OpusHeaderTest() {
        if (mEleStream.is_open()) mEleStream.close();
        if (mInputBuffer) {
            free(mInputBuffer);
            mInputBuffer = nullptr;
        }
    }
    ifstream mEleStream;
    uint8_t *mInputBuffer;
};

class OpusHeaderParseTest : public OpusHeaderTest,
                            public ::testing::TestWithParam<
                                    tuple<string /* InputFileName */, int32_t /* ChannelCount */,
                                          bool /* isHeaderValid */, bool /* isCodecDelayValid */,
                                          bool /* isSeekPreRollValid */, bool /* isInputValid */>> {
};

class OpusHeaderWriteTest
    : public OpusHeaderTest,
      public ::testing::TestWithParam<pair<int32_t /* ChannelCount */, int32_t /* skipSamples */>> {
};

TEST_P(OpusHeaderWriteTest, WriteTest) {
    OpusHeader writtenHeader;
    memset(&writtenHeader, 0, sizeof(writtenHeader));
    int32_t channels = GetParam().first;
    writtenHeader.channels = channels;
    writtenHeader.num_streams = channels;
    writtenHeader.channel_mapping = ((channels > 8) ? 255 : (channels > 2));
    int32_t skipSamples = GetParam().second;
    writtenHeader.skip_samples = skipSamples;
    uint64_t codecDelayNs = skipSamples * kNsecPerSec / kOpusSampleRate;
    uint8_t headerData[kMaxOpusHeaderSize];
    int32_t headerSize = WriteOpusHeaders(writtenHeader, kOpusSampleRate, headerData,
                                          sizeof(headerData), codecDelayNs, kOpusSeekPrerollNs);
    ASSERT_GT(headerSize, 0) << "failed to generate Opus header";
    ASSERT_LE(headerSize, kMaxOpusHeaderSize)
            << "Invalid header written. Header size can't exceed kMaxOpusHeaderSize";

    ofstream ostrm;
    ostrm.open(OUTPUT_FILE_NAME, ofstream::binary);
    ASSERT_TRUE(ostrm.is_open()) << "Failed to open output file " << OUTPUT_FILE_NAME;

    // TODO : Validate bitstream (b/150116402)
    ostrm.write(reinterpret_cast<char *>(headerData), sizeof(headerData));
    ostrm.close();

    size_t opusHeadSize = 0;
    size_t codecDelayBufSize = 0;
    size_t seekPreRollBufSize = 0;
    void *opusHeadBuf = nullptr;
    void *codecDelayBuf = nullptr;
    void *seekPreRollBuf = nullptr;
    bool status = GetOpusHeaderBuffers(headerData, headerSize, &opusHeadBuf, &opusHeadSize,
                                       &codecDelayBuf, &codecDelayBufSize, &seekPreRollBuf,
                                       &seekPreRollBufSize);
    ASSERT_TRUE(status) << "Encountered error in GetOpusHeaderBuffers";

    uint64_t value = *((uint64_t *)codecDelayBuf);
    ASSERT_EQ(value, codecDelayNs);

    value = *((uint64_t *)seekPreRollBuf);
    ASSERT_EQ(value, kOpusSeekPrerollNs);

    OpusHeader parsedHeader;
    status = ParseOpusHeader((uint8_t *)opusHeadBuf, opusHeadSize, &parsedHeader);
    ASSERT_TRUE(status) << "Encountered error while Parsing Opus Header.";

    ASSERT_EQ(writtenHeader.channels, parsedHeader.channels)
            << "Invalid header generated. Mismatch between channel counts";

    ASSERT_EQ(writtenHeader.skip_samples, parsedHeader.skip_samples)
            << "Mismatch between no of skipSamples written "
               "and no of skipSamples got after parsing";

    ASSERT_EQ(writtenHeader.channel_mapping, parsedHeader.channel_mapping)
            << "Mismatch between channelMapping written "
               "and channelMapping got after parsing";

    if (parsedHeader.channel_mapping) {
        ASSERT_GT(parsedHeader.channels, 2);
        ASSERT_EQ(writtenHeader.num_streams, parsedHeader.num_streams)
                << "Invalid header generated. Mismatch between channel counts";

        ASSERT_EQ(writtenHeader.num_coupled, parsedHeader.num_coupled)
                << "Invalid header generated. Mismatch between channel counts";

        ASSERT_EQ(parsedHeader.num_coupled + parsedHeader.num_streams, parsedHeader.channels);

        ASSERT_LE(parsedHeader.num_coupled, parsedHeader.num_streams)
                << "Invalid header generated. Number of coupled streams cannot be greater than "
                   "number "
                   "of streams.";

        ASSERT_EQ(headerSize, kOpusHeaderChannelMapOffset + writtenHeader.channels)
                << "Invalid header written. Header size should be equal to 86 + "
                   "writtenHeader.channels";

        uint8_t mappedChannelNumber;
        for (int32_t channelNumber = 0; channelNumber < channels; channelNumber++) {
            mappedChannelNumber = *(reinterpret_cast<uint8_t *>(opusHeadBuf) +
                                    kOpusHeaderStreamMapOffset + channelNumber);
            ASSERT_LT(mappedChannelNumber, channels) << "Invalid header generated. Channel mapping "
                                                        "cannot be greater than channel count.";

            ASSERT_EQ(mappedChannelNumber, kOpusChannelMap[channels - 1][channelNumber])
                    << "Invalid header generated. Channel mapping is not as per specification.";
        }
    } else {
        ASSERT_LE(parsedHeader.channels, 2);
    }
}

TEST_P(OpusHeaderParseTest, ParseTest) {
    tuple<string, int32_t, bool, bool, bool, bool> params = GetParam();
    string inputFileName = gEnv->getRes() + get<0>(params);
    mEleStream.open(inputFileName, ifstream::binary);
    ASSERT_EQ(mEleStream.is_open(), true) << "Failed to open inputfile " << get<0>(params);
    bool isHeaderValid = get<2>(params);
    bool isCodecDelayValid = get<3>(params);
    bool isSeekPreRollValid = get<4>(params);
    bool isInputValid = get<5>(params);

    struct stat buf;
    stat(inputFileName.c_str(), &buf);
    size_t fileSize = buf.st_size;
    mInputBuffer = (uint8_t *)malloc(fileSize);
    ASSERT_NE(mInputBuffer, nullptr) << "Insufficient memory. Malloc failed for size " << fileSize;

    mEleStream.read(reinterpret_cast<char *>(mInputBuffer), fileSize);
    ASSERT_EQ(mEleStream.gcount(), fileSize) << "mEleStream.gcount() != bytesCount";

    OpusHeader header;
    size_t opusHeadSize = 0;
    size_t codecDelayBufSize = 0;
    size_t seekPreRollBufSize = 0;
    void *opusHeadBuf = nullptr;
    void *codecDelayBuf = nullptr;
    void *seekPreRollBuf = nullptr;
    bool status = GetOpusHeaderBuffers(mInputBuffer, fileSize, &opusHeadBuf, &opusHeadSize,
                                       &codecDelayBuf, &codecDelayBufSize, &seekPreRollBuf,
                                       &seekPreRollBufSize);
    if (!isHeaderValid) {
        ASSERT_EQ(opusHeadBuf, nullptr);
    } else {
        ASSERT_NE(opusHeadBuf, nullptr);
    }
    if (!isCodecDelayValid) {
        ASSERT_EQ(codecDelayBuf, nullptr);
    } else {
        ASSERT_NE(codecDelayBuf, nullptr);
    }
    if (!isSeekPreRollValid) {
        ASSERT_EQ(seekPreRollBuf, nullptr);
    } else {
        ASSERT_NE(seekPreRollBuf, nullptr);
    }
    if (!status) {
        ASSERT_FALSE(isInputValid) << "GetOpusHeaderBuffers failed";
        return;
    }

    status = ParseOpusHeader((uint8_t *)opusHeadBuf, opusHeadSize, &header);

    if (status) {
        ASSERT_TRUE(isInputValid) << "Parse opus header didn't fail for invalid input";
    } else {
        ASSERT_FALSE(isInputValid);
        return;
    }

    int32_t channels = get<1>(params);
    ASSERT_EQ(header.channels, channels) << "Parser returned invalid channel count";
    ASSERT_LE(header.channels, kMaxChannels);

    ASSERT_LE(header.num_coupled, header.num_streams)
            << "Invalid header generated. Number of coupled streams cannot be greater than number "
               "of streams.";

    ASSERT_EQ(header.num_coupled + header.num_streams, header.channels);

    if (header.channel_mapping) {
        uint8_t mappedChannelNumber;
        for (int32_t channelNumber = 0; channelNumber < channels; channelNumber++) {
            mappedChannelNumber = *(reinterpret_cast<uint8_t *>(opusHeadBuf) +
                                    kOpusHeaderStreamMapOffset + channelNumber);
            ASSERT_LT(mappedChannelNumber, channels)
                    << "Invalid header. Channel mapping cannot be greater than channel count.";

            ASSERT_EQ(mappedChannelNumber, kOpusChannelMap[channels - 1][channelNumber])
                    << "Invalid header generated. Channel mapping "
                       "is not as per specification.";
        }
    }
}

INSTANTIATE_TEST_SUITE_P(OpusHeaderTestAll, OpusHeaderWriteTest,
                         ::testing::Values(make_pair(1, 312),
                                           make_pair(2, 312),
                                           make_pair(5, 312),
                                           make_pair(6, 312),
                                           make_pair(1, 0),
                                           make_pair(2, 0),
                                           make_pair(5, 0),
                                           make_pair(6, 0),
                                           make_pair(1, 624),
                                           make_pair(2, 624),
                                           make_pair(5, 624),
                                           make_pair(6, 624)));

INSTANTIATE_TEST_SUITE_P(
        OpusHeaderTestAll, OpusHeaderParseTest,
        ::testing::Values(
                make_tuple("2ch_valid_size83B.opus", 2, true, true, true, true),
                make_tuple("3ch_valid_size88B.opus", 3, true, true, true, true),
                make_tuple("5ch_valid.opus", 5, true, false, false, true),
                make_tuple("6ch_valid.opus", 6, true, false, false, true),
                make_tuple("1ch_valid.opus", 1, true, false, false, true),
                make_tuple("2ch_valid.opus", 2, true, false, false, true),
                make_tuple("3ch_invalid_size.opus", 3, true, true, true, false),
                make_tuple("3ch_invalid_streams.opus", 3, true, true, true, false),
                make_tuple("5ch_invalid_channelmapping.opus", 5, true, false, false, false),
                make_tuple("5ch_invalid_coupledstreams.opus", 5, true, false, false, false),
                make_tuple("6ch_invalid_channelmapping.opus", 6, true, false, false, false),
                make_tuple("9ch_invalid_channels.opus", 9, true, true, true, false),
                make_tuple("2ch_invalid_header.opus", 2, false, false, false, false),
                make_tuple("2ch_invalid_headerlength_16.opus", 2, false, false, false, false),
                make_tuple("2ch_invalid_headerlength_256.opus", 2, false, false, false, false),
                make_tuple("2ch_invalid_size.opus", 2, false, false, false, false),
                make_tuple("3ch_invalid_channelmapping_0.opus", 3, true, true, true, false),
                make_tuple("3ch_invalid_coupledstreams.opus", 3, true, true, true, false),
                make_tuple("3ch_invalid_headerlength.opus", 3, true, true, true, false),
                make_tuple("3ch_invalid_headerSize1.opus", 3, false, false, false, false),
                make_tuple("3ch_invalid_headerSize2.opus", 3, false, false, false, false),
                make_tuple("3ch_invalid_headerSize3.opus", 3, false, false, false, false),
                make_tuple("3ch_invalid_nodelay.opus", 3, false, false, false, false),
                make_tuple("3ch_invalid_nopreroll.opus", 3, false, false, false, false)));

int main(int argc, char **argv) {
    gEnv = new OpusHeaderTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGD("Opus Header Test Result = %d\n", status);
    }
    return status;
}
