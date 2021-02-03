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

#include <inttypes.h>

#include <datasource/FileSource.h>
#include <media/stagefright/MediaBufferGroup.h>
#include <media/stagefright/MediaCodecConstants.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MetaDataUtils.h>
#include <media/stagefright/foundation/OpusHeader.h>

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
constexpr int32_t kAudioDefaultSampleDuration = 20000;                       // 20ms
constexpr int32_t kRandomSeekToleranceUs = 2 * kAudioDefaultSampleDuration;  // 40 ms;
constexpr int32_t kRandomSeed = 700;
constexpr int32_t kUndefined = -1;

enum inputID {
    // audio streams
    AAC_1,
    AMR_NB_1,
    AMR_WB_1,
    FLAC_1,
    GSM_1,
    MIDI_1,
    MP3_1,
    OPUS_1,
    VORBIS_1,
    // video streams
    HEVC_1,
    HEVC_2,
    MPEG2_PS_1,
    MPEG2_TS_1,
    MPEG4_1,
    VP9_1,
    UNKNOWN_ID,
};

// LookUpTable of clips and metadata for component testing
static const struct InputData {
    inputID inpId;
    string mime;
    string inputFile;
    int32_t firstParam;
    int32_t secondParam;
    int32_t profile;
    int32_t frameRate;
} kInputData[] = {
        {AAC_1, MEDIA_MIMETYPE_AUDIO_AAC, "test_mono_44100Hz_aac.aac", 44100, 1, AACObjectLC,
         kUndefined},
        {AMR_NB_1, MEDIA_MIMETYPE_AUDIO_AMR_NB, "bbb_mono_8kHz_amrnb.amr", 8000, 1, kUndefined,
         kUndefined},
        {AMR_WB_1, MEDIA_MIMETYPE_AUDIO_AMR_WB, "bbb_mono_16kHz_amrwb.amr", 16000, 1, kUndefined,
         kUndefined},
        {FLAC_1, MEDIA_MIMETYPE_AUDIO_RAW, "bbb_stereo_48kHz_flac.flac", 48000, 2, kUndefined,
         kUndefined},
        {GSM_1, MEDIA_MIMETYPE_AUDIO_MSGSM, "test_mono_8kHz_gsm.wav", 8000, 1, kUndefined,
         kUndefined},
        {MIDI_1, MEDIA_MIMETYPE_AUDIO_RAW, "midi_a.mid", 22050, 2, kUndefined, kUndefined},
        {MP3_1, MEDIA_MIMETYPE_AUDIO_MPEG, "bbb_stereo_48kHz_mp3.mp3", 48000, 2, kUndefined,
         kUndefined},
        {OPUS_1, MEDIA_MIMETYPE_AUDIO_OPUS, "test_stereo_48kHz_opus.opus", 48000, 2, kUndefined,
         kUndefined},
        {VORBIS_1, MEDIA_MIMETYPE_AUDIO_VORBIS, "bbb_stereo_48kHz_vorbis.ogg", 48000, 2, kUndefined,
         kUndefined},

        // Test (b/151677264) for MP4 extractor
        {HEVC_1, MEDIA_MIMETYPE_VIDEO_HEVC, "crowd_508x240_25fps_hevc.mp4", 508, 240,
         HEVCProfileMain, 25},
        {HEVC_2, MEDIA_MIMETYPE_IMAGE_ANDROID_HEIC, "test3.heic", 820, 460, kUndefined, kUndefined},
        {MPEG2_PS_1, MEDIA_MIMETYPE_VIDEO_MPEG2, "swirl_144x136_mpeg2.mpg", 144, 136,
         MPEG2ProfileMain, 12},
        {MPEG2_TS_1, MEDIA_MIMETYPE_VIDEO_MPEG2, "bbb_cif_768kbps_30fps_mpeg2.ts", 352, 288,
         MPEG2ProfileMain, 30},
        {MPEG4_1, MEDIA_MIMETYPE_VIDEO_MPEG4, "bbb_cif_768kbps_30fps_mpeg4.mkv", 352, 288,
         MPEG4ProfileSimple, 30},
        {VP9_1, MEDIA_MIMETYPE_VIDEO_VP9, "bbb_340x280_30fps_vp9.webm", 340, 280, VP9Profile0, 30},
};

static ExtractorUnitTestEnvironment *gEnv = nullptr;

class ExtractorUnitTest {
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

    void setupExtractor(string writerFormat) {
        mExtractorName = unknown_comp;
        mDisableTest = false;

        static const std::map<std::string, standardExtractors> mapExtractor = {
                {"aac", AAC},
                {"amr", AMR},
                {"flac", FLAC},
                {"mid", MIDI},
                {"midi", MIDI},
                {"mkv", MKV},
                {"mp3", MP3},
                {"mp4", MPEG4},
                {"mpeg2ps", MPEG2PS},
                {"mpeg2ts", MPEG2TS},
                {"mpeg4", MPEG4},
                {"mpg", MPEG2PS},
                {"ogg", OGG},
                {"opus", OGG},
                {"ts", MPEG2TS},
                {"wav", WAV},
                {"webm", MKV}};
        // Find the component type
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

class ExtractorFunctionalityTest
    : public ExtractorUnitTest,
      public ::testing::TestWithParam<tuple<string /* container */, string /* InputFile */,
                                            int32_t /* numTracks */, bool /* seekSupported */>> {
  public:
    virtual void SetUp() override {
        tuple<string, string, int32_t, bool> params = GetParam();
        mContainer = get<0>(params);
        mNumTracks = get<2>(params);
        setupExtractor(mContainer);
    }
    string mContainer;
    int32_t mNumTracks;
};

class ConfigParamTest : public ExtractorUnitTest,
                        public ::testing::TestWithParam<pair<string, inputID>> {
  public:
    virtual void SetUp() override { setupExtractor(GetParam().first); }

    struct configFormat {
        string mime;
        int32_t width;
        int32_t height;
        int32_t sampleRate;
        int32_t channelCount;
        int32_t profile;
        int32_t frameRate;
    };

    void getFileProperties(inputID inputId, string &inputFile, configFormat &configParam);
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

void ConfigParamTest::getFileProperties(inputID inputId, string &inputFile,
                                        configFormat &configParam) {
    int32_t inputDataSize = sizeof(kInputData) / sizeof(kInputData[0]);
    int32_t inputIdx = 0;
    for (; inputIdx < inputDataSize; inputIdx++) {
        if (inputId == kInputData[inputIdx].inpId) {
            break;
        }
    }
    if (inputIdx == inputDataSize) {
        return;
    }
    inputFile += kInputData[inputIdx].inputFile;
    configParam.mime = kInputData[inputIdx].mime;
    size_t found = configParam.mime.find("audio/");
    // Check if 'audio/' is present in the begininig of the mime type
    if (found == 0) {
        configParam.sampleRate = kInputData[inputIdx].firstParam;
        configParam.channelCount = kInputData[inputIdx].secondParam;
    } else {
        configParam.width = kInputData[inputIdx].firstParam;
        configParam.height = kInputData[inputIdx].secondParam;
    }
    configParam.profile = kInputData[inputIdx].profile;
    configParam.frameRate = kInputData[inputIdx].frameRate;
    return;
}

void randomSeekTest(MediaTrackHelper *track, int64_t clipDuration) {
    int32_t status = 0;
    int32_t seekCount = 0;
    bool hasTimestamp = false;
    vector<int64_t> seekToTimeStamp;
    string seekPtsString;

    srand(kRandomSeed);
    while (seekCount < kMaxCount) {
        int64_t timeStamp = ((double)rand() / RAND_MAX) * clipDuration;
        seekToTimeStamp.push_back(timeStamp);
        seekPtsString.append(to_string(timeStamp));
        seekPtsString.append(", ");
        seekCount++;
    }

    for (int64_t seekPts : seekToTimeStamp) {
        MediaTrackHelper::ReadOptions *options = new MediaTrackHelper::ReadOptions(
                CMediaTrackReadOptions::SEEK_CLOSEST | CMediaTrackReadOptions::SEEK, seekPts);
        ASSERT_NE(options, nullptr) << "Cannot create read option";

        MediaBufferHelper *buffer = nullptr;
        status = track->read(&buffer, options);
        if (buffer) {
            AMediaFormat *metaData = buffer->meta_data();
            int64_t timeStamp = 0;
            hasTimestamp = AMediaFormat_getInt64(metaData, AMEDIAFORMAT_KEY_TIME_US, &timeStamp);
            ASSERT_TRUE(hasTimestamp) << "Extractor didn't set timestamp for the given sample";

            buffer->release();
            EXPECT_LE(abs(timeStamp - seekPts), kRandomSeekToleranceUs)
                    << "Seek unsuccessful. Expected timestamp range ["
                    << seekPts - kRandomSeekToleranceUs << ", " << seekPts + kRandomSeekToleranceUs
                    << "] "
                    << "received " << timeStamp << ", list of input seek timestamps ["
                    << seekPtsString << "]";
        }
        delete options;
    }
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

TEST_P(ExtractorFunctionalityTest, CreateExtractorTest) {
    if (mDisableTest) return;

    ALOGV("Checks if a valid extractor is created for a given input file");
    string inputFileName = gEnv->getRes() + get<1>(GetParam());

    int32_t status = setDataSource(inputFileName);
    ASSERT_EQ(status, 0) << "SetDataSource failed for" << mContainer << "extractor";

    status = createExtractor();
    ASSERT_EQ(status, 0) << "Extractor creation failed for" << mContainer << "extractor";

    int32_t numTracks = mExtractor->countTracks();
    ASSERT_EQ(numTracks, mNumTracks)
            << "Extractor reported wrong number of track for the given clip";

    AMediaFormat *format = AMediaFormat_new();
    ASSERT_NE(format, nullptr) << "AMediaFormat_new returned null AMediaformat";

    ASSERT_EQ(mExtractor->getMetaData(format), AMEDIA_OK);
    AMediaFormat_delete(format);
}

TEST_P(ExtractorFunctionalityTest, ExtractorTest) {
    if (mDisableTest) return;

    ALOGV("Validates %s Extractor for a given input file", mContainer.c_str());
    string inputFileName = gEnv->getRes() + get<1>(GetParam());

    int32_t status = setDataSource(inputFileName);
    ASSERT_EQ(status, 0) << "SetDataSource failed for" << mContainer << "extractor";

    status = createExtractor();
    ASSERT_EQ(status, 0) << "Extractor creation failed for" << mContainer << "extractor";

    int32_t numTracks = mExtractor->countTracks();
    ASSERT_EQ(numTracks, mNumTracks)
            << "Extractor reported wrong number of track for the given clip";

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

TEST_P(ExtractorFunctionalityTest, MetaDataComparisonTest) {
    if (mDisableTest) return;

    ALOGV("Validates Extractor's meta data for a given input file");
    string inputFileName = gEnv->getRes() + get<1>(GetParam());

    int32_t status = setDataSource(inputFileName);
    ASSERT_EQ(status, 0) << "SetDataSource failed for" << mContainer << "extractor";

    status = createExtractor();
    ASSERT_EQ(status, 0) << "Extractor creation failed for" << mContainer << "extractor";

    int32_t numTracks = mExtractor->countTracks();
    ASSERT_EQ(numTracks, mNumTracks)
            << "Extractor reported wrong number of track for the given clip";

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
        } else if (!strncmp(extractorMime, "video/", 6)) {
            int32_t exWidth, exHeight;
            int32_t trackWidth, trackHeight;
            ASSERT_TRUE(AMediaFormat_getInt32(extractorFormat, AMEDIAFORMAT_KEY_WIDTH, &exWidth));
            ASSERT_TRUE(AMediaFormat_getInt32(extractorFormat, AMEDIAFORMAT_KEY_HEIGHT, &exHeight));
            ASSERT_TRUE(AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_WIDTH, &trackWidth));
            ASSERT_TRUE(AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_HEIGHT, &trackHeight));
            ASSERT_EQ(exWidth, trackWidth) << "Width not as expected";
            ASSERT_EQ(exHeight, trackHeight) << "Height not as expected";
        } else {
            ALOGV("non a/v track");
        }
        status = cTrack->stop(track);
        ASSERT_EQ(OK, status) << "Failed to stop the track";
        delete bufferGroup;
        delete track;
    }
    AMediaFormat_delete(trackFormat);
    AMediaFormat_delete(extractorFormat);
}

TEST_P(ExtractorFunctionalityTest, MultipleStartStopTest) {
    if (mDisableTest) return;

    ALOGV("Test %s extractor for multiple start and stop calls", mContainer.c_str());
    string inputFileName = gEnv->getRes() + get<1>(GetParam());

    int32_t status = setDataSource(inputFileName);
    ASSERT_EQ(status, 0) << "SetDataSource failed for" << mContainer << "extractor";

    status = createExtractor();
    ASSERT_EQ(status, 0) << "Extractor creation failed for" << mContainer << "extractor";

    int32_t numTracks = mExtractor->countTracks();
    ASSERT_EQ(numTracks, mNumTracks)
            << "Extractor reported wrong number of track for the given clip";

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

TEST_P(ExtractorFunctionalityTest, SeekTest) {
    if (mDisableTest) return;

    string inputFileName = gEnv->getRes() + get<1>(GetParam());
    ALOGV("Validates %s Extractor behaviour for different seek modes filename %s",
          mContainer.c_str(), inputFileName.c_str());

    int32_t status = setDataSource(inputFileName);
    ASSERT_EQ(status, 0) << "SetDataSource failed for" << mContainer << "extractor";

    status = createExtractor();
    ASSERT_EQ(status, 0) << "Extractor creation failed for" << mContainer << "extractor";

    int32_t numTracks = mExtractor->countTracks();
    ASSERT_EQ(numTracks, mNumTracks)
            << "Extractor reported wrong number of track for the given clip";

    uint32_t seekFlag = mExtractor->flags();
    bool seekSupported = get<3>(GetParam());
    bool seekable = seekFlag & MediaExtractorPluginHelper::CAN_SEEK;
    if (!seekable) {
        ASSERT_FALSE(seekSupported) << mContainer << "Extractor is expected to support seek ";
        cout << "[   WARN   ] Test Skipped. " << mContainer << " Extractor doesn't support seek\n";
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

        // For Flac, Wav and Midi extractor, all samples are seek points.
        // We cannot create list of all seekable points for these.
        // This means that if we pass a seekToTimeStamp between two seek points, we may
        // end up getting the timestamp of next sample as a seekable timestamp.
        // This timestamp may/may not be a part of the seekable point vector thereby failing the
        // test. So we test these extractors using random seek test.
        if (mExtractorName == FLAC || mExtractorName == WAV || mExtractorName == MIDI) {
            AMediaFormat *trackMeta = AMediaFormat_new();
            ASSERT_NE(trackMeta, nullptr) << "AMediaFormat_new returned null AMediaformat";

            status = mExtractor->getTrackMetaData(trackMeta, idx, 1);
            ASSERT_EQ(OK, (media_status_t)status) << "Failed to get trackMetaData";

            int64_t clipDuration = 0;
            AMediaFormat_getInt64(trackMeta, AMEDIAFORMAT_KEY_DURATION, &clipDuration);
            ASSERT_GT(clipDuration, 0) << "Invalid clip duration ";
            randomSeekTest(track, clipDuration);
            AMediaFormat_delete(trackMeta);
            continue;
        }

        AMediaFormat *trackFormat = AMediaFormat_new();
        ASSERT_NE(trackFormat, nullptr) << "AMediaFormat_new returned null format";
        status = track->getFormat(trackFormat);
        ASSERT_EQ(OK, (media_status_t)status) << "Failed to get track meta data";

        const char *mime;
        ASSERT_TRUE(AMediaFormat_getString(trackFormat, AMEDIAFORMAT_KEY_MIME, &mime))
                << "Failed to get mime";

        // Image formats are not expected to be seekable
        if (!strncmp(mime, "image/", 6)) continue;

        // Request seekable points for remaining extractors which will be used to validate the seek
        // accuracy for the extractors. Depending on SEEK Mode, we expect the extractors to return
        // the expected sync frame. We don't prefer random seek test for these extractors because
        // they aren't expected to seek to random samples. MP4 for instance can seek to
        // next/previous sync frames but not to samples between two sync frames.
        getSeekablePoints(seekablePoints, track);
        ASSERT_GT(seekablePoints.size(), 0)
                << "Failed to get seekable points for " << mContainer << " extractor";

        bool isOpus = false;
        int64_t opusSeekPreRollUs = 0;
        if (!strcmp(mime, "audio/opus")) {
            isOpus = true;
            void *seekPreRollBuf = nullptr;
            size_t size = 0;
            if (!AMediaFormat_getBuffer(trackFormat, "csd-2", &seekPreRollBuf, &size)) {
                size_t opusHeadSize = 0;
                size_t codecDelayBufSize = 0;
                size_t seekPreRollBufSize = 0;
                void *csdBuffer = nullptr;
                void *opusHeadBuf = nullptr;
                void *codecDelayBuf = nullptr;
                AMediaFormat_getBuffer(trackFormat, "csd-0", &csdBuffer, &size);
                ASSERT_NE(csdBuffer, nullptr);

                GetOpusHeaderBuffers((uint8_t *)csdBuffer, size, &opusHeadBuf, &opusHeadSize,
                                     &codecDelayBuf, &codecDelayBufSize, &seekPreRollBuf,
                                     &seekPreRollBufSize);
            }
            ASSERT_NE(seekPreRollBuf, nullptr)
                    << "Invalid track format. SeekPreRoll info missing for Opus file";
            opusSeekPreRollUs = *((int64_t *)seekPreRollBuf);
        }
        AMediaFormat_delete(trackFormat);

        int32_t seekIdx = 0;
        size_t seekablePointsSize = seekablePoints.size();
        for (int32_t mode = CMediaTrackReadOptions::SEEK_PREVIOUS_SYNC;
             mode <= CMediaTrackReadOptions::SEEK_CLOSEST; mode++) {
            for (int32_t seekCount = 0; seekCount < kMaxCount; seekCount++) {
                seekIdx = rand() % seekablePointsSize + 1;
                if (seekIdx >= seekablePointsSize) seekIdx = seekablePointsSize - 1;

                int64_t seekToTimeStamp = seekablePoints[seekIdx];
                if (seekIdx > 1) {
                    // pick a time just earlier than this seek point
                    int64_t prevTimeStamp = seekablePoints[seekIdx - 1];
                    seekToTimeStamp = seekToTimeStamp - ((seekToTimeStamp - prevTimeStamp) >> 3);
                }

                // Opus has a seekPreRollUs. TimeStamp returned by the
                // extractor is calculated based on (seekPts - seekPreRollUs).
                // So we add the preRoll value to the timeStamp we want to seek to.
                if (isOpus) {
                    seekToTimeStamp += opusSeekPreRollUs;
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
                            EXPECT_EQ(timeStamp, seekablePoints[seekIdx > 0 ? (seekIdx - 1) : 0]);
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

// Tests the extractors for seek beyond range : (0, ClipDuration)
TEST_P(ExtractorFunctionalityTest, MonkeySeekTest) {
    if (mDisableTest) return;
    // TODO(b/155630778): Enable test for wav extractors
    if (mExtractorName == WAV) return;

    string inputFileName = gEnv->getRes() + get<1>(GetParam());
    ALOGV("Validates %s Extractor behaviour for invalid seek points, filename %s",
          mContainer.c_str(), inputFileName.c_str());

    int32_t status = setDataSource(inputFileName);
    ASSERT_EQ(status, 0) << "SetDataSource failed for" << mContainer << "extractor";

    status = createExtractor();
    ASSERT_EQ(status, 0) << "Extractor creation failed for" << mContainer << "extractor";

    int32_t numTracks = mExtractor->countTracks();
    ASSERT_EQ(numTracks, mNumTracks)
            << "Extractor reported wrong number of track for the given clip";

    uint32_t seekFlag = mExtractor->flags();
    bool seekSupported = get<3>(GetParam());
    bool seekable = seekFlag & MediaExtractorPluginHelper::CAN_SEEK;
    if (!seekable) {
        ASSERT_FALSE(seekSupported) << mContainer << "Extractor is expected to support seek ";
        cout << "[   WARN   ] Test Skipped. " << mContainer << " Extractor doesn't support seek\n";
        return;
    }

    for (int32_t idx = 0; idx < numTracks; idx++) {
        MediaTrackHelper *track = mExtractor->getTrack(idx);
        ASSERT_NE(track, nullptr) << "Failed to get track for index " << idx;

        CMediaTrack *cTrack = wrap(track);
        ASSERT_NE(cTrack, nullptr) << "Failed to get track wrapper for index " << idx;

        MediaBufferGroup *bufferGroup = new MediaBufferGroup();
        status = cTrack->start(track, bufferGroup->wrap());
        ASSERT_EQ(OK, (media_status_t)status) << "Failed to start the track";

        AMediaFormat *trackMeta = AMediaFormat_new();
        ASSERT_NE(trackMeta, nullptr) << "AMediaFormat_new returned null AMediaformat";

        status = mExtractor->getTrackMetaData(
                trackMeta, idx, MediaExtractorPluginHelper::kIncludeExtensiveMetaData);
        ASSERT_EQ(OK, (media_status_t)status) << "Failed to get trackMetaData";

        const char *mime;
        ASSERT_TRUE(AMediaFormat_getString(trackMeta, AMEDIAFORMAT_KEY_MIME, &mime))
                << "Failed to get mime";

        int64_t clipDuration = 0;
        AMediaFormat_getInt64(trackMeta, AMEDIAFORMAT_KEY_DURATION, &clipDuration);
        // Image formats are not expected to have duration information
        ASSERT_TRUE(clipDuration > 0 || !strncmp(mime, "image/", 6)) << "Invalid clip duration ";
        AMediaFormat_delete(trackMeta);

        int64_t seekToTimeStampUs[] = {-clipDuration, clipDuration / 2, clipDuration,
                                       clipDuration * 2};
        for (int32_t mode = CMediaTrackReadOptions::SEEK_PREVIOUS_SYNC;
             mode <= CMediaTrackReadOptions::SEEK_CLOSEST; mode++) {
            for (int64_t seekTimeUs : seekToTimeStampUs) {
                MediaTrackHelper::ReadOptions *options = new MediaTrackHelper::ReadOptions(
                        mode | CMediaTrackReadOptions::SEEK, seekTimeUs);
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
                    ALOGV("Seeked to timestamp : %lld, requested : %lld", (long long)timeStamp,
                          (long long)seekTimeUs);
                    buffer->release();
                }
                delete options;
            }
        }
        status = cTrack->stop(track);
        ASSERT_EQ(OK, status) << "Failed to stop the track";
        delete bufferGroup;
        delete track;
    }
}

// Tests extractors for invalid tracks
TEST_P(ExtractorFunctionalityTest, SanityTest) {
    if (mDisableTest) return;
    // TODO(b/155626946): Enable test for MPEG2 TS/PS extractors
    if (mExtractorName == MPEG2TS || mExtractorName == MPEG2PS) return;

    string inputFileName = gEnv->getRes() + get<1>(GetParam());
    ALOGV("Validates %s Extractor behaviour for invalid tracks - file %s",
          mContainer.c_str(), inputFileName.c_str());

    int32_t status = setDataSource(inputFileName);
    ASSERT_EQ(status, 0) << "SetDataSource failed for" << mContainer << "extractor";

    status = createExtractor();
    ASSERT_EQ(status, 0) << "Extractor creation failed for" << mContainer << "extractor";

    int32_t numTracks = mExtractor->countTracks();
    ASSERT_EQ(numTracks, mNumTracks)
            << "Extractor reported wrong number of track for the given clip";

    int32_t trackIdx[] = {-1, numTracks};
    for (int32_t idx : trackIdx) {
        MediaTrackHelper *track = mExtractor->getTrack(idx);
        ASSERT_EQ(track, nullptr) << "Failed to get track for index " << idx << "\n";

        AMediaFormat *extractorFormat = AMediaFormat_new();
        ASSERT_NE(extractorFormat, nullptr) << "AMediaFormat_new returned null AMediaformat";

        status = mExtractor->getTrackMetaData(
                extractorFormat, idx, MediaExtractorPluginHelper::kIncludeExtensiveMetaData);
        ASSERT_NE(OK, status) << "getTrackMetaData should return error for invalid index " << idx;
        AMediaFormat_delete(extractorFormat);
    }

    // Validate Extractor's getTrackMetaData for null format
    AMediaFormat *mediaFormat = nullptr;
    status = mExtractor->getTrackMetaData(mediaFormat, 0,
                                          MediaExtractorPluginHelper::kIncludeExtensiveMetaData);
    ASSERT_NE(OK, status) << "getTrackMetaData should return error for null Media format";
}

// This test validates config params for a given input file.
// For this test we only take single track files since the focus of this test is
// to validate the file properties reported by Extractor and not multi-track behavior
TEST_P(ConfigParamTest, ConfigParamValidation) {
    if (mDisableTest) return;

    const int trackNumber = 0;

    string container = GetParam().first;
    string inputFileName = gEnv->getRes();
    inputID inputFileId = GetParam().second;
    configFormat configParam;
    getFileProperties(inputFileId, inputFileName, configParam);

    ALOGV("Validates %s Extractor for input's file properties, file %s",
          container.c_str(), inputFileName.c_str());

    int32_t status = setDataSource(inputFileName);
    ASSERT_EQ(status, 0) << "SetDataSource failed for " << container << "extractor";

    status = createExtractor();
    ASSERT_EQ(status, 0) << "Extractor creation failed for " << container << "extractor";

    int32_t numTracks = mExtractor->countTracks();
    ASSERT_GT(numTracks, 0) << "Extractor didn't find any track for the given clip";

    MediaTrackHelper *track = mExtractor->getTrack(trackNumber);
    ASSERT_NE(track, nullptr) << "Failed to get track for index 0";

    AMediaFormat *trackFormat = AMediaFormat_new();
    ASSERT_NE(trackFormat, nullptr) << "AMediaFormat_new returned null format";

    status = track->getFormat(trackFormat);
    ASSERT_EQ(OK, (media_status_t)status) << "Failed to get track meta data";

    const char *trackMime;
    bool valueFound = AMediaFormat_getString(trackFormat, AMEDIAFORMAT_KEY_MIME, &trackMime);
    ASSERT_TRUE(valueFound) << "Mime type not set by extractor";
    ASSERT_STREQ(configParam.mime.c_str(), trackMime) << "Invalid track format";

    if (!strncmp(trackMime, "audio/", 6)) {
        int32_t trackSampleRate, trackChannelCount;
        ASSERT_TRUE(AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_CHANNEL_COUNT,
                                          &trackChannelCount));
        ASSERT_TRUE(
                AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_SAMPLE_RATE, &trackSampleRate));
        ASSERT_EQ(configParam.sampleRate, trackSampleRate) << "SampleRate not as expected";
        ASSERT_EQ(configParam.channelCount, trackChannelCount) << "ChannelCount not as expected";
    } else if (!strncmp(trackMime, "video/", 6)) {
        int32_t trackWidth, trackHeight;
        ASSERT_TRUE(AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_WIDTH, &trackWidth));
        ASSERT_TRUE(AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_HEIGHT, &trackHeight));
        ASSERT_EQ(configParam.width, trackWidth) << "Width not as expected";
        ASSERT_EQ(configParam.height, trackHeight) << "Height not as expected";

        if (configParam.frameRate != kUndefined) {
            int32_t frameRate;
            ASSERT_TRUE(
                    AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_FRAME_RATE, &frameRate));
            ASSERT_EQ(configParam.frameRate, frameRate) << "frameRate not as expected";
        }
    }
    // validate the profile for the input clip
    int32_t profile;
    if (configParam.profile != kUndefined) {
        if (AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_PROFILE, &profile)) {
            ASSERT_EQ(configParam.profile, profile) << "profile not as expected";
        } else if (mExtractorName == AAC &&
                   AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_AAC_PROFILE, &profile)) {
            ASSERT_EQ(configParam.profile, profile) << "profile not as expected";
        } else {
            ASSERT_TRUE(false) << "profile not returned in extractor";
        }
    }

    delete track;
    AMediaFormat_delete(trackFormat);
}

class ExtractorComparison
    : public ExtractorUnitTest,
      public ::testing::TestWithParam<pair<string /* InputFile0 */, string /* InputFile1 */>> {
  public:
    ~ExtractorComparison() {
        for (int8_t *extractorOp : mExtractorOutput) {
            if (extractorOp != nullptr) {
                free(extractorOp);
            }
        }
    }

    int8_t *mExtractorOutput[2]{};
    size_t mExtractorOuputSize[2]{};
};

size_t allocateOutputBuffers(string inputFileName, AMediaFormat *extractorFormat) {
    size_t bufferSize = 0u;
    // allocating the buffer size as sampleRate * channelCount * clipDuration since
    // some extractors like flac, midi and wav decodes the file. These extractors
    // advertise the mime type as raw.
    const char *mime;
    AMediaFormat_getString(extractorFormat, AMEDIAFORMAT_KEY_MIME, &mime);
    if (!strcmp(mime, MEDIA_MIMETYPE_AUDIO_RAW)) {
        int64_t clipDurationUs = -1;
        int32_t channelCount = -1;
        int32_t sampleRate = -1;
        int32_t bitsPerSampple = -1;
        if (!AMediaFormat_getInt32(extractorFormat, AMEDIAFORMAT_KEY_CHANNEL_COUNT,
                                   &channelCount) || channelCount <= 0) {
            ALOGE("Invalid channelCount for input file : %s", inputFileName.c_str());
            return 0;
        }
        if (!AMediaFormat_getInt32(extractorFormat, AMEDIAFORMAT_KEY_SAMPLE_RATE, &sampleRate) ||
            sampleRate <= 0) {
            ALOGE("Invalid sampleRate for input file : %s", inputFileName.c_str());
            return 0;
        }
        if (!AMediaFormat_getInt64(extractorFormat, AMEDIAFORMAT_KEY_DURATION, &clipDurationUs) ||
            clipDurationUs <= 0) {
            ALOGE("Invalid clip duration for input file : %s", inputFileName.c_str());
            return 0;
        }
        if (!AMediaFormat_getInt32(extractorFormat, AMEDIAFORMAT_KEY_PCM_ENCODING,
                                   &bitsPerSampple) || bitsPerSampple <= 0) {
            ALOGE("Invalid bits per sample for input file : %s", inputFileName.c_str());
            return 0;
        }
        bufferSize = bitsPerSampple * channelCount * sampleRate * (clipDurationUs / 1000000 + 1);
    } else {
        struct stat buf;
        int32_t status = stat(inputFileName.c_str(), &buf);
        if (status != 0) {
            ALOGE("Unable to get file properties for: %s", inputFileName.c_str());
            return 0;
        }
        bufferSize = buf.st_size;
    }
    return bufferSize;
}

// Compare output of two extractors for identical content
TEST_P(ExtractorComparison, ExtractorComparisonTest) {
    vector<string> inputFileNames = {GetParam().first, GetParam().second};
    size_t extractedOutputSize[2]{};
    AMediaFormat *extractorFormat[2]{};
    int32_t status = OK;

    for (int32_t idx = 0; idx < inputFileNames.size(); idx++) {
        string containerFormat = inputFileNames[idx].substr(inputFileNames[idx].find(".") + 1);
        setupExtractor(containerFormat);
        if (mDisableTest) {
            ALOGV("Unknown extractor %s. Skipping the test", containerFormat.c_str());
            return;
        }

        ALOGV("Validates %s Extractor for %s", containerFormat.c_str(),
              inputFileNames[idx].c_str());
        string inputFileName = gEnv->getRes() + inputFileNames[idx];

        status = setDataSource(inputFileName);
        ASSERT_EQ(status, 0) << "SetDataSource failed for" << containerFormat << "extractor";

        status = createExtractor();
        ASSERT_EQ(status, 0) << "Extractor creation failed for " << containerFormat << " extractor";

        int32_t numTracks = mExtractor->countTracks();
        ASSERT_EQ(numTracks, 1) << "This test expects inputs with one track only";

        int32_t trackIdx = 0;
        MediaTrackHelper *track = mExtractor->getTrack(trackIdx);
        ASSERT_NE(track, nullptr) << "Failed to get track for index " << trackIdx;

        extractorFormat[idx] = AMediaFormat_new();
        ASSERT_NE(extractorFormat[idx], nullptr) << "AMediaFormat_new returned null AMediaformat";

        status = track->getFormat(extractorFormat[idx]);
        ASSERT_EQ(OK, (media_status_t)status) << "Failed to get track meta data";

        CMediaTrack *cTrack = wrap(track);
        ASSERT_NE(cTrack, nullptr) << "Failed to get track wrapper for index " << trackIdx;

        mExtractorOuputSize[idx] = allocateOutputBuffers(inputFileName, extractorFormat[idx]);
        ASSERT_GT(mExtractorOuputSize[idx], 0u) << " Invalid size for output buffers";

        mExtractorOutput[idx] = (int8_t *)calloc(1, mExtractorOuputSize[idx]);
        ASSERT_NE(mExtractorOutput[idx], nullptr)
                << "Unable to allocate memory for writing extractor's output";

        MediaBufferGroup *bufferGroup = new MediaBufferGroup();
        status = cTrack->start(track, bufferGroup->wrap());
        ASSERT_EQ(OK, (media_status_t)status) << "Failed to start the track";

        int32_t offset = 0;
        while (status != AMEDIA_ERROR_END_OF_STREAM) {
            MediaBufferHelper *buffer = nullptr;
            status = track->read(&buffer);
            ALOGV("track->read Status = %d buffer %p", status, buffer);
            if (buffer) {
                ASSERT_LE(offset + buffer->range_length(), mExtractorOuputSize[idx])
                        << "Memory overflow. Extracted output size more than expected";

                memcpy(mExtractorOutput[idx] + offset, buffer->data(), buffer->range_length());
                extractedOutputSize[idx] += buffer->range_length();
                offset += buffer->range_length();
                buffer->release();
            }
        }
        status = cTrack->stop(track);
        ASSERT_EQ(OK, status) << "Failed to stop the track";

        fclose(mInputFp);
        delete bufferGroup;
        delete track;
        mDataSource.clear();
        delete mExtractor;
        mInputFp = nullptr;
        mExtractor = nullptr;
    }

    // Compare the meta data from both the extractors
    const char *mime[2];
    AMediaFormat_getString(extractorFormat[0], AMEDIAFORMAT_KEY_MIME, &mime[0]);
    AMediaFormat_getString(extractorFormat[1], AMEDIAFORMAT_KEY_MIME, &mime[1]);
    ASSERT_STREQ(mime[0], mime[1]) << "Mismatch between extractor's format";

    if (!strncmp(mime[0], "audio/", 6)) {
        int32_t channelCount0, channelCount1;
        int32_t sampleRate0, sampleRate1;
        ASSERT_TRUE(AMediaFormat_getInt32(extractorFormat[0], AMEDIAFORMAT_KEY_CHANNEL_COUNT,
                                          &channelCount0));
        ASSERT_TRUE(AMediaFormat_getInt32(extractorFormat[0], AMEDIAFORMAT_KEY_SAMPLE_RATE,
                                          &sampleRate0));
        ASSERT_TRUE(AMediaFormat_getInt32(extractorFormat[1], AMEDIAFORMAT_KEY_CHANNEL_COUNT,
                                          &channelCount1));
        ASSERT_TRUE(AMediaFormat_getInt32(extractorFormat[1], AMEDIAFORMAT_KEY_SAMPLE_RATE,
                                          &sampleRate1));
        ASSERT_EQ(channelCount0, channelCount1) << "Mismatch between extractor's channelCount";
        ASSERT_EQ(sampleRate0, sampleRate1) << "Mismatch between extractor's sampleRate";
    } else if (!strncmp(mime[0], "video/", 6)) {
        int32_t width0, height0;
        int32_t width1, height1;
        ASSERT_TRUE(AMediaFormat_getInt32(extractorFormat[0], AMEDIAFORMAT_KEY_WIDTH, &width0));
        ASSERT_TRUE(AMediaFormat_getInt32(extractorFormat[0], AMEDIAFORMAT_KEY_HEIGHT, &height0));
        ASSERT_TRUE(AMediaFormat_getInt32(extractorFormat[1], AMEDIAFORMAT_KEY_WIDTH, &width1));
        ASSERT_TRUE(AMediaFormat_getInt32(extractorFormat[1], AMEDIAFORMAT_KEY_HEIGHT, &height1));
        ASSERT_EQ(width0, width1) << "Mismatch between extractor's width";
        ASSERT_EQ(height0, height1) << "Mismatch between extractor's height";
    } else {
        ASSERT_TRUE(false) << "Invalid mime type " << mime[0];
    }

    for (AMediaFormat *exFormat : extractorFormat) {
        AMediaFormat_delete(exFormat);
    }

    // Compare the extracted outputs of both extractor
    ASSERT_EQ(extractedOutputSize[0], extractedOutputSize[1])
            << "Extractor's output size doesn't match between " << inputFileNames[0] << "and "
            << inputFileNames[1] << " extractors";
    status = memcmp(mExtractorOutput[0], mExtractorOutput[1], extractedOutputSize[0]);
    ASSERT_EQ(status, 0) << "Extracted content mismatch between " << inputFileNames[0] << "and "
                         << inputFileNames[1] << " extractors";
}

INSTANTIATE_TEST_SUITE_P(
        ExtractorComparisonAll, ExtractorComparison,
        ::testing::Values(make_pair("swirl_144x136_vp9.mp4", "swirl_144x136_vp9.webm"),
                          make_pair("video_480x360_mp4_vp9_333kbps_25fps.mp4",
                                    "video_480x360_webm_vp9_333kbps_25fps.webm"),
                          make_pair("video_1280x720_av1_hdr_static_3mbps.mp4",
                                    "video_1280x720_av1_hdr_static_3mbps.webm"),
                          make_pair("swirl_132x130_mpeg4.3gp", "swirl_132x130_mpeg4.mkv"),
                          make_pair("swirl_144x136_avc.mkv", "swirl_144x136_avc.mp4"),
                          make_pair("swirl_132x130_mpeg4.mp4", "swirl_132x130_mpeg4.mkv"),
                          make_pair("crowd_508x240_25fps_hevc.mp4","crowd_508x240_25fps_hevc.mkv"),
                          make_pair("bbb_cif_768kbps_30fps_mpeg2.mp4",
                                    "bbb_cif_768kbps_30fps_mpeg2.ts"),

                          make_pair("loudsoftaac.aac", "loudsoftaac.mkv"),
                          make_pair("sinesweepflacmkv.mkv", "sinesweepflacmp4.mp4"),
                          make_pair("sinesweepmp3lame.mp3", "sinesweepmp3lame.mkv"),
                          make_pair("sinesweepoggmp4.mp4", "sinesweepogg.ogg"),
                          make_pair("sinesweepvorbis.mp4", "sinesweepvorbis.ogg"),
                          make_pair("sinesweepvorbis.mkv", "sinesweepvorbis.ogg"),
                          make_pair("testopus.mkv", "testopus.mp4"),
                          make_pair("testopus.mp4", "testopus.opus"),

                          make_pair("loudsoftaac.aac", "loudsoftaac.aac"),
                          make_pair("testamr.amr", "testamr.amr"),
                          make_pair("sinesweepflac.flac", "sinesweepflac.flac"),
                          make_pair("midi_a.mid", "midi_a.mid"),
                          make_pair("sinesweepvorbis.mkv", "sinesweepvorbis.mkv"),
                          make_pair("sinesweepmp3lame.mp3", "sinesweepmp3lame.mp3"),
                          make_pair("sinesweepoggmp4.mp4", "sinesweepoggmp4.mp4"),
                          make_pair("testopus.opus", "testopus.opus"),
                          make_pair("john_cage.ogg", "john_cage.ogg"),
                          make_pair("monotestgsm.wav", "monotestgsm.wav"),

                          make_pair("swirl_144x136_mpeg2.mpg", "swirl_144x136_mpeg2.mpg"),
                          make_pair("swirl_132x130_mpeg4.mp4", "swirl_132x130_mpeg4.mp4"),
                          make_pair("swirl_144x136_vp9.webm", "swirl_144x136_vp9.webm"),
                          make_pair("swirl_144x136_vp8.webm", "swirl_144x136_vp8.webm")));

INSTANTIATE_TEST_SUITE_P(ConfigParamTestAll, ConfigParamTest,
                         ::testing::Values(make_pair("aac", AAC_1),
                                           make_pair("amr", AMR_NB_1),
                                           make_pair("amr", AMR_WB_1),
                                           make_pair("flac", FLAC_1),
                                           make_pair("wav", GSM_1),
                                           make_pair("midi", MIDI_1),
                                           make_pair("mp3", MP3_1),
                                           make_pair("ogg", OPUS_1),
                                           make_pair("ogg", VORBIS_1),

                                           make_pair("mpeg4", HEVC_1),
                                           make_pair("mpeg4", HEVC_2),
                                           make_pair("mpeg2ps", MPEG2_PS_1),
                                           make_pair("mpeg2ts", MPEG2_TS_1),
                                           make_pair("mkv", MPEG4_1),
                                           make_pair("mkv", VP9_1)));

// Validate extractors for container format, input file, no. of tracks and supports seek flag
INSTANTIATE_TEST_SUITE_P(
        ExtractorUnitTestAll, ExtractorFunctionalityTest,
        ::testing::Values(
                make_tuple("aac", "loudsoftaac.aac", 1, true),
                make_tuple("amr", "testamr.amr", 1, true),
                make_tuple("amr", "amrwb.wav", 1, true),
                make_tuple("flac", "sinesweepflac.flac", 1, true),
                make_tuple("midi", "midi_a.mid", 1, true),
                make_tuple("mkv", "sinesweepvorbis.mkv", 1, true),
                make_tuple("mkv", "sinesweepmp3lame.mkv", 1, true),
                make_tuple("mkv", "loudsoftaac.mkv", 1, true),
                make_tuple("mp3", "sinesweepmp3lame.mp3", 1, true),
                make_tuple("mp3", "id3test10.mp3", 1, true),
                make_tuple("mpeg2ts", "segment000001.ts", 2, false),
                make_tuple("mpeg2ts", "testac3ts.ts", 1, false),
                make_tuple("mpeg2ts", "testac4ts.ts", 1, false),
                make_tuple("mpeg2ts", "testeac3ts.ts", 1, false),
                make_tuple("mpeg4", "audio_aac_mono_70kbs_44100hz.mp4", 2, true),
                make_tuple("mpeg4", "multi0_ac4.mp4", 1, true),
                make_tuple("mpeg4", "noise_6ch_44khz_aot5_dr_sbr_sig2_mp4.m4a", 1, true),
                make_tuple("mpeg4", "sinesweepalac.mov", 1, true),
                make_tuple("mpeg4", "sinesweepflacmp4.mp4", 1, true),
                make_tuple("mpeg4", "sinesweepm4a.m4a", 1, true),
                make_tuple("mpeg4", "sinesweepoggmp4.mp4", 1, true),
                make_tuple("mpeg4", "sinesweepopusmp4.mp4", 1, true),
                make_tuple("mpeg4", "testac3mp4.mp4", 1, true),
                make_tuple("mpeg4", "testeac3mp4.mp4", 1, true),
                make_tuple("ogg", "john_cage.ogg", 1, true),
                make_tuple("ogg", "testopus.opus", 1, true),
                make_tuple("ogg", "sinesweepoggalbumart.ogg", 1, true),
                make_tuple("wav", "loudsoftwav.wav", 1, true),
                make_tuple("wav", "monotestgsm.wav", 1, true),
                make_tuple("wav", "noise_5ch_44khz_aot2_wave.wav", 1, true),
                make_tuple("wav", "sine1khzm40db_alaw.wav", 1, true),
                make_tuple("wav", "sine1khzm40db_f32le.wav", 1, true),
                make_tuple("wav", "sine1khzm40db_mulaw.wav", 1, true),

                make_tuple("mkv", "swirl_144x136_avc.mkv", 1, true),
                make_tuple("mkv", "withoutcues.mkv", 2, true),
                make_tuple("mkv", "swirl_144x136_vp9.webm", 1, true),
                make_tuple("mkv", "swirl_144x136_vp8.webm", 1, true),
                make_tuple("mpeg2ps", "swirl_144x136_mpeg2.mpg", 1, false),
                make_tuple("mpeg2ps", "programstream.mpeg", 2, false),
                make_tuple("mpeg4", "color_176x144_bt601_525_lr_sdr_h264.mp4", 1, true),
                make_tuple("mpeg4", "heifwriter_input.heic", 4, false),
                make_tuple("mpeg4", "psshtest.mp4", 1, true),
                make_tuple("mpeg4", "swirl_132x130_mpeg4.mp4", 1, true),
                make_tuple("mpeg4", "testvideo.3gp", 4, true),
                make_tuple("mpeg4", "testvideo_with_2_timedtext_tracks.3gp", 4, true),
                make_tuple("mpeg4",
                           "video_176x144_3gp_h263_300kbps_25fps_aac_stereo_128kbps_11025hz_"
                           "metadata_gyro_compliant.3gp",
                           3, true),
                make_tuple(
                        "mpeg4",
                        "video_1920x1080_mp4_mpeg2_12000kbps_30fps_aac_stereo_128kbps_48000hz.mp4",
                        2, true),
                make_tuple("mpeg4",
                           "video_480x360_mp4_hevc_650kbps_30fps_aac_stereo_128kbps_48000hz.mp4", 2,
                           true),
                make_tuple(
                        "mpeg4",
                        "video_480x360_mp4_h264_1350kbps_30fps_aac_stereo_128kbps_44100hz_dash.mp4",
                        2, true)));

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
