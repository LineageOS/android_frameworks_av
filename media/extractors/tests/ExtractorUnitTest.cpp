/*
 * Copyright (C) 2019 The Android Open Source Project
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
#define LOG_TAG "ExtractorUnitTest"
#include <utils/Log.h>

#include <datasource/FileSource.h>
#include <media/stagefright/MediaBufferGroup.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MetaDataUtils.h>

#include "aac/AACExtractor.h"
#include "amr/AMRExtractor.h"
#include "flac/FLACExtractor.h"
#include "midi/MidiExtractor.h"
#include "mkv/MatroskaExtractor.h"
#include "mp3/MP3Extractor.h"
#include "mp4/MPEG4Extractor.h"
#include "mp4/SampleTable.h"
#include "mpeg2/MPEG2PSExtractor.h"
#include "mpeg2/MPEG2TSExtractor.h"
#include "ogg/OggExtractor.h"
#include "wav/WAVExtractor.h"

#include "ExtractorUnitTestEnvironment.h"

using namespace android;

#define OUTPUT_DUMP_FILE "/data/local/tmp/extractorOutput"

constexpr int32_t kMaxCount = 10;
constexpr int32_t kOpusSeekPreRollUs = 80000;  // 80 ms;

static ExtractorUnitTestEnvironment *gEnv = nullptr;

class ExtractorUnitTest : public ::testing::TestWithParam<pair<string, string>> {
  public:
    ExtractorUnitTest() : mInputFp(nullptr), mDataSource(nullptr), mExtractor(nullptr) {}

    ~ExtractorUnitTest() {
        if (mInputFp) {
            fclose(mInputFp);
            mInputFp = nullptr;
        }
        if (mDataSource) {
            mDataSource.clear();
            mDataSource = nullptr;
        }
        if (mExtractor) {
            delete mExtractor;
            mExtractor = nullptr;
        }
    }

    virtual void SetUp() override {
        mExtractorName = unknown_comp;
        mDisableTest = false;

        static const std::map<std::string, standardExtractors> mapExtractor = {
                {"aac", AAC},     {"amr", AMR},         {"mp3", MP3},        {"ogg", OGG},
                {"wav", WAV},     {"mkv", MKV},         {"flac", FLAC},      {"midi", MIDI},
                {"mpeg4", MPEG4}, {"mpeg2ts", MPEG2TS}, {"mpeg2ps", MPEG2PS}};
        // Find the component type
        string writerFormat = GetParam().first;
        if (mapExtractor.find(writerFormat) != mapExtractor.end()) {
            mExtractorName = mapExtractor.at(writerFormat);
        }
        if (mExtractorName == standardExtractors::unknown_comp) {
            cout << "[   WARN   ] Test Skipped. Invalid extractor\n";
            mDisableTest = true;
        }
    }

    int32_t setDataSource(string inputFileName);

    int32_t createExtractor();

    enum standardExtractors {
        AAC,
        AMR,
        FLAC,
        MIDI,
        MKV,
        MP3,
        MPEG4,
        MPEG2PS,
        MPEG2TS,
        OGG,
        WAV,
        unknown_comp,
    };

    bool mDisableTest;
    standardExtractors mExtractorName;

    FILE *mInputFp;
    sp<DataSource> mDataSource;
    MediaExtractorPluginHelper *mExtractor;
};

int32_t ExtractorUnitTest::setDataSource(string inputFileName) {
    mInputFp = fopen(inputFileName.c_str(), "rb");
    if (!mInputFp) {
        ALOGE("Unable to open input file for reading");
        return -1;
    }
    struct stat buf;
    stat(inputFileName.c_str(), &buf);
    int32_t fd = fileno(mInputFp);
    mDataSource = new FileSource(dup(fd), 0, buf.st_size);
    if (!mDataSource) return -1;
    return 0;
}

int32_t ExtractorUnitTest::createExtractor() {
    switch (mExtractorName) {
        case AAC:
            mExtractor = new AACExtractor(new DataSourceHelper(mDataSource->wrap()), 0);
            break;
        case AMR:
            mExtractor = new AMRExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case MP3:
            mExtractor = new MP3Extractor(new DataSourceHelper(mDataSource->wrap()), nullptr);
            break;
        case OGG:
            mExtractor = new OggExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case WAV:
            mExtractor = new WAVExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case MKV:
            mExtractor = new MatroskaExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case FLAC:
            mExtractor = new FLACExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case MPEG4:
            mExtractor = new MPEG4Extractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case MPEG2TS:
            mExtractor = new MPEG2TSExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case MPEG2PS:
            mExtractor = new MPEG2PSExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case MIDI:
            mExtractor = new MidiExtractor(mDataSource->wrap());
            break;
        default:
            return -1;
    }
    if (!mExtractor) return -1;
    return 0;
}

void getSeekablePoints(vector<int64_t> &seekablePoints, MediaTrackHelper *track) {
    int32_t status = 0;
    if (!seekablePoints.empty()) {
        seekablePoints.clear();
    }
    int64_t timeStamp;
    while (status != AMEDIA_ERROR_END_OF_STREAM) {
        MediaBufferHelper *buffer = nullptr;
        status = track->read(&buffer);
        if (buffer) {
            AMediaFormat *metaData = buffer->meta_data();
            int32_t isSync = 0;
            AMediaFormat_getInt32(metaData, AMEDIAFORMAT_KEY_IS_SYNC_FRAME, &isSync);
            if (isSync) {
                AMediaFormat_getInt64(metaData, AMEDIAFORMAT_KEY_TIME_US, &timeStamp);
                seekablePoints.push_back(timeStamp);
            }
            buffer->release();
        }
    }
}

TEST_P(ExtractorUnitTest, CreateExtractorTest) {
    if (mDisableTest) return;

    ALOGV("Checks if a valid extractor is created for a given input file");
    string inputFileName = gEnv->getRes() + GetParam().second;

    ASSERT_EQ(setDataSource(inputFileName), 0)
            << "SetDataSource failed for" << GetParam().first << "extractor";

    ASSERT_EQ(createExtractor(), 0)
            << "Extractor creation failed for" << GetParam().first << "extractor";

    // A valid extractor instace should return success for following calls
    ASSERT_GT(mExtractor->countTracks(), 0);

    AMediaFormat *format = AMediaFormat_new();
    ASSERT_NE(format, nullptr) << "AMediaFormat_new returned null AMediaformat";

    ASSERT_EQ(mExtractor->getMetaData(format), AMEDIA_OK);
    AMediaFormat_delete(format);
}

TEST_P(ExtractorUnitTest, ExtractorTest) {
    if (mDisableTest) return;

    ALOGV("Validates %s Extractor for a given input file", GetParam().first.c_str());
    string inputFileName = gEnv->getRes() + GetParam().second;

    int32_t status = setDataSource(inputFileName);
    ASSERT_EQ(status, 0) << "SetDataSource failed for" << GetParam().first << "extractor";

    status = createExtractor();
    ASSERT_EQ(status, 0) << "Extractor creation failed for" << GetParam().first << "extractor";

    int32_t numTracks = mExtractor->countTracks();
    ASSERT_GT(numTracks, 0) << "Extractor didn't find any track for the given clip";

    for (int32_t idx = 0; idx < numTracks; idx++) {
        MediaTrackHelper *track = mExtractor->getTrack(idx);
        ASSERT_NE(track, nullptr) << "Failed to get track for index " << idx;

        CMediaTrack *cTrack = wrap(track);
        ASSERT_NE(cTrack, nullptr) << "Failed to get track wrapper for index " << idx;

        MediaBufferGroup *bufferGroup = new MediaBufferGroup();
        status = cTrack->start(track, bufferGroup->wrap());
        ASSERT_EQ(OK, (media_status_t)status) << "Failed to start the track";

        FILE *outFp = fopen((OUTPUT_DUMP_FILE + to_string(idx)).c_str(), "wb");
        if (!outFp) {
            ALOGW("Unable to open output file for dumping extracted stream");
        }

        while (status != AMEDIA_ERROR_END_OF_STREAM) {
            MediaBufferHelper *buffer = nullptr;
            status = track->read(&buffer);
            ALOGV("track->read Status = %d buffer %p", status, buffer);
            if (buffer) {
                ALOGV("buffer->data %p buffer->size() %zu buffer->range_length() %zu",
                      buffer->data(), buffer->size(), buffer->range_length());
                if (outFp) fwrite(buffer->data(), 1, buffer->range_length(), outFp);
                buffer->release();
            }
        }
        if (outFp) fclose(outFp);
        status = cTrack->stop(track);
        ASSERT_EQ(OK, status) << "Failed to stop the track";
        delete bufferGroup;
        delete track;
    }
}

TEST_P(ExtractorUnitTest, MetaDataComparisonTest) {
    if (mDisableTest) return;

    ALOGV("Validates Extractor's meta data for a given input file");
    string inputFileName = gEnv->getRes() + GetParam().second;

    int32_t status = setDataSource(inputFileName);
    ASSERT_EQ(status, 0) << "SetDataSource failed for" << GetParam().first << "extractor";

    status = createExtractor();
    ASSERT_EQ(status, 0) << "Extractor creation failed for" << GetParam().first << "extractor";

    int32_t numTracks = mExtractor->countTracks();
    ASSERT_GT(numTracks, 0) << "Extractor didn't find any track for the given clip";

    AMediaFormat *extractorFormat = AMediaFormat_new();
    ASSERT_NE(extractorFormat, nullptr) << "AMediaFormat_new returned null AMediaformat";
    AMediaFormat *trackFormat = AMediaFormat_new();
    ASSERT_NE(trackFormat, nullptr) << "AMediaFormat_new returned null AMediaformat";

    for (int32_t idx = 0; idx < numTracks; idx++) {
        MediaTrackHelper *track = mExtractor->getTrack(idx);
        ASSERT_NE(track, nullptr) << "Failed to get track for index " << idx;

        CMediaTrack *cTrack = wrap(track);
        ASSERT_NE(cTrack, nullptr) << "Failed to get track wrapper for index " << idx;

        MediaBufferGroup *bufferGroup = new MediaBufferGroup();
        status = cTrack->start(track, bufferGroup->wrap());
        ASSERT_EQ(OK, (media_status_t)status) << "Failed to start the track";

        status = mExtractor->getTrackMetaData(extractorFormat, idx, 1);
        ASSERT_EQ(OK, (media_status_t)status) << "Failed to get trackMetaData";

        status = track->getFormat(trackFormat);
        ASSERT_EQ(OK, (media_status_t)status) << "Failed to get track meta data";

        const char *extractorMime, *trackMime;
        AMediaFormat_getString(extractorFormat, AMEDIAFORMAT_KEY_MIME, &extractorMime);
        AMediaFormat_getString(trackFormat, AMEDIAFORMAT_KEY_MIME, &trackMime);
        ASSERT_TRUE(!strcmp(extractorMime, trackMime))
                << "Extractor's format doesn't match track format";

        if (!strncmp(extractorMime, "audio/", 6)) {
            int32_t exSampleRate, exChannelCount;
            int32_t trackSampleRate, trackChannelCount;
            ASSERT_TRUE(AMediaFormat_getInt32(extractorFormat, AMEDIAFORMAT_KEY_CHANNEL_COUNT,
                                              &exChannelCount));
            ASSERT_TRUE(AMediaFormat_getInt32(extractorFormat, AMEDIAFORMAT_KEY_SAMPLE_RATE,
                                              &exSampleRate));
            ASSERT_TRUE(AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_CHANNEL_COUNT,
                                              &trackChannelCount));
            ASSERT_TRUE(AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_SAMPLE_RATE,
                                              &trackSampleRate));
            ASSERT_EQ(exChannelCount, trackChannelCount) << "ChannelCount not as expected";
            ASSERT_EQ(exSampleRate, trackSampleRate) << "SampleRate not as expected";
        } else {
            int32_t exWidth, exHeight;
            int32_t trackWidth, trackHeight;
            ASSERT_TRUE(AMediaFormat_getInt32(extractorFormat, AMEDIAFORMAT_KEY_WIDTH, &exWidth));
            ASSERT_TRUE(AMediaFormat_getInt32(extractorFormat, AMEDIAFORMAT_KEY_HEIGHT, &exHeight));
            ASSERT_TRUE(AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_WIDTH, &trackWidth));
            ASSERT_TRUE(AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_HEIGHT, &trackHeight));
            ASSERT_EQ(exWidth, trackWidth) << "Width not as expected";
            ASSERT_EQ(exHeight, trackHeight) << "Height not as expected";
        }
        status = cTrack->stop(track);
        ASSERT_EQ(OK, status) << "Failed to stop the track";
        delete bufferGroup;
        delete track;
    }
    AMediaFormat_delete(trackFormat);
    AMediaFormat_delete(extractorFormat);
}

TEST_P(ExtractorUnitTest, MultipleStartStopTest) {
    if (mDisableTest) return;

    ALOGV("Test %s extractor for multiple start and stop calls", GetParam().first.c_str());
    string inputFileName = gEnv->getRes() + GetParam().second;

    int32_t status = setDataSource(inputFileName);
    ASSERT_EQ(status, 0) << "SetDataSource failed for" << GetParam().first << "extractor";

    status = createExtractor();
    ASSERT_EQ(status, 0) << "Extractor creation failed for" << GetParam().first << "extractor";

    int32_t numTracks = mExtractor->countTracks();
    ASSERT_GT(numTracks, 0) << "Extractor didn't find any track for the given clip";

    // start/stop the tracks multiple times
    for (int32_t count = 0; count < kMaxCount; count++) {
        for (int32_t idx = 0; idx < numTracks; idx++) {
            MediaTrackHelper *track = mExtractor->getTrack(idx);
            ASSERT_NE(track, nullptr) << "Failed to get track for index " << idx;

            CMediaTrack *cTrack = wrap(track);
            ASSERT_NE(cTrack, nullptr) << "Failed to get track wrapper for index " << idx;

            MediaBufferGroup *bufferGroup = new MediaBufferGroup();
            status = cTrack->start(track, bufferGroup->wrap());
            ASSERT_EQ(OK, (media_status_t)status) << "Failed to start the track";
            MediaBufferHelper *buffer = nullptr;
            status = track->read(&buffer);
            if (buffer) {
                ALOGV("buffer->data %p buffer->size() %zu buffer->range_length() %zu",
                      buffer->data(), buffer->size(), buffer->range_length());
                buffer->release();
            }
            status = cTrack->stop(track);
            ASSERT_EQ(OK, status) << "Failed to stop the track";
            delete bufferGroup;
            delete track;
        }
    }
}

TEST_P(ExtractorUnitTest, SeekTest) {
    // Both Flac and Wav extractor can give samples from any pts and mark the given sample as
    // sync frame. So, this seek test is not applicable to FLAC and WAV extractors
    if (mDisableTest || mExtractorName == FLAC || mExtractorName == WAV) return;

    ALOGV("Validates %s Extractor behaviour for different seek modes", GetParam().first.c_str());
    string inputFileName = gEnv->getRes() + GetParam().second;

    int32_t status = setDataSource(inputFileName);
    ASSERT_EQ(status, 0) << "SetDataSource failed for" << GetParam().first << "extractor";

    status = createExtractor();
    ASSERT_EQ(status, 0) << "Extractor creation failed for" << GetParam().first << "extractor";

    int32_t numTracks = mExtractor->countTracks();
    ASSERT_GT(numTracks, 0) << "Extractor didn't find any track for the given clip";

    uint32_t seekFlag = mExtractor->flags();
    if (!(seekFlag & MediaExtractorPluginHelper::CAN_SEEK)) {
        cout << "[   WARN   ] Test Skipped. " << GetParam().first
             << " Extractor doesn't support seek\n";
        return;
    }

    vector<int64_t> seekablePoints;
    for (int32_t idx = 0; idx < numTracks; idx++) {
        MediaTrackHelper *track = mExtractor->getTrack(idx);
        ASSERT_NE(track, nullptr) << "Failed to get track for index " << idx;

        CMediaTrack *cTrack = wrap(track);
        ASSERT_NE(cTrack, nullptr) << "Failed to get track wrapper for index " << idx;

        // Get all the seekable points of a given input
        MediaBufferGroup *bufferGroup = new MediaBufferGroup();
        status = cTrack->start(track, bufferGroup->wrap());
        ASSERT_EQ(OK, (media_status_t)status) << "Failed to start the track";
        getSeekablePoints(seekablePoints, track);
        ASSERT_GT(seekablePoints.size(), 0)
                << "Failed to get seekable points for " << GetParam().first << " extractor";

        AMediaFormat *trackFormat = AMediaFormat_new();
        ASSERT_NE(trackFormat, nullptr) << "AMediaFormat_new returned null format";
        status = track->getFormat(trackFormat);
        ASSERT_EQ(OK, (media_status_t)status) << "Failed to get track meta data";

        bool isOpus = false;
        const char *mime;
        AMediaFormat_getString(trackFormat, AMEDIAFORMAT_KEY_MIME, &mime);
        if (!strcmp(mime, "audio/opus")) isOpus = true;
        AMediaFormat_delete(trackFormat);

        int32_t seekIdx = 0;
        size_t seekablePointsSize = seekablePoints.size();
        for (int32_t mode = CMediaTrackReadOptions::SEEK_PREVIOUS_SYNC;
             mode <= CMediaTrackReadOptions::SEEK_CLOSEST; mode++) {
            for (int32_t seekCount = 0; seekCount < kMaxCount; seekCount++) {
                seekIdx = rand() % seekablePointsSize + 1;
                if (seekIdx >= seekablePointsSize) seekIdx = seekablePointsSize - 1;

                int64_t seekToTimeStamp = seekablePoints[seekIdx];
                if (seekablePointsSize > 1) {
                    int64_t prevTimeStamp = seekablePoints[seekIdx - 1];
                    seekToTimeStamp = seekToTimeStamp - ((seekToTimeStamp - prevTimeStamp) >> 3);
                }

                // Opus has a seekPreRollUs. TimeStamp returned by the
                // extractor is calculated based on (seekPts - seekPreRollUs).
                // So we add the preRoll value to the timeStamp we want to seek to.
                if (isOpus) {
                    seekToTimeStamp += kOpusSeekPreRollUs;
                }

                MediaTrackHelper::ReadOptions *options = new MediaTrackHelper::ReadOptions(
                        mode | CMediaTrackReadOptions::SEEK, seekToTimeStamp);
                ASSERT_NE(options, nullptr) << "Cannot create read option";

                MediaBufferHelper *buffer = nullptr;
                status = track->read(&buffer, options);
                if (status == AMEDIA_ERROR_END_OF_STREAM) {
                    delete options;
                    continue;
                }
                if (buffer) {
                    AMediaFormat *metaData = buffer->meta_data();
                    int64_t timeStamp;
                    AMediaFormat_getInt64(metaData, AMEDIAFORMAT_KEY_TIME_US, &timeStamp);
                    buffer->release();

                    // CMediaTrackReadOptions::SEEK is 8. Using mask 0111b to get true modes
                    switch (mode & 0x7) {
                        case CMediaTrackReadOptions::SEEK_PREVIOUS_SYNC:
                            if (seekablePointsSize == 1) {
                                EXPECT_EQ(timeStamp, seekablePoints[seekIdx]);
                            } else {
                                EXPECT_EQ(timeStamp, seekablePoints[seekIdx - 1]);
                            }
                            break;
                        case CMediaTrackReadOptions::SEEK_NEXT_SYNC:
                        case CMediaTrackReadOptions::SEEK_CLOSEST_SYNC:
                        case CMediaTrackReadOptions::SEEK_CLOSEST:
                            EXPECT_EQ(timeStamp, seekablePoints[seekIdx]);
                            break;
                        default:
                            break;
                    }
                }
                delete options;
            }
        }
        status = cTrack->stop(track);
        ASSERT_EQ(OK, status) << "Failed to stop the track";
        delete bufferGroup;
        delete track;
    }
    seekablePoints.clear();
}

// TODO: (b/145332185)
// Add MIDI inputs
INSTANTIATE_TEST_SUITE_P(ExtractorUnitTestAll, ExtractorUnitTest,
                         ::testing::Values(make_pair("aac", "loudsoftaac.aac"),
                                           make_pair("amr", "testamr.amr"),
                                           make_pair("amr", "amrwb.wav"),
                                           make_pair("ogg", "john_cage.ogg"),
                                           make_pair("wav", "monotestgsm.wav"),
                                           make_pair("mpeg2ts", "segment000001.ts"),
                                           make_pair("flac", "sinesweepflac.flac"),
                                           make_pair("ogg", "testopus.opus"),
                                           make_pair("mkv", "sinesweepvorbis.mkv"),
                                           make_pair("mpeg4", "sinesweepoggmp4.mp4"),
                                           make_pair("mp3", "sinesweepmp3lame.mp3"),
                                           make_pair("mkv", "swirl_144x136_vp9.webm"),
                                           make_pair("mkv", "swirl_144x136_vp8.webm"),
                                           make_pair("mpeg2ps", "swirl_144x136_mpeg2.mpg"),
                                           make_pair("mpeg4", "swirl_132x130_mpeg4.mp4")));

int main(int argc, char **argv) {
    gEnv = new ExtractorUnitTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
