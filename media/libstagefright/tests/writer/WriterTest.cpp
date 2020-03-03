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
#define LOG_TAG "WriterTest"
#include <utils/Log.h>

#include <fstream>
#include <iostream>

#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/Utils.h>

#include <media/mediarecorder.h>

#include <media/stagefright/AACWriter.h>
#include <media/stagefright/AMRWriter.h>
#include <media/stagefright/MPEG2TSWriter.h>
#include <media/stagefright/MPEG4Writer.h>
#include <media/stagefright/OggWriter.h>
#include <webm/WebmWriter.h>

#include "WriterTestEnvironment.h"
#include "WriterUtility.h"

#define OUTPUT_FILE_NAME "/data/local/tmp/writer.out"

static WriterTestEnvironment *gEnv = nullptr;

struct configFormat {
    char mime[128];
    int32_t width;
    int32_t height;
    int32_t sampleRate;
    int32_t channelCount;
};

// LookUpTable of clips and metadata for component testing
static const struct InputData {
    const char *mime;
    string inputFile;
    string info;
    int32_t firstParam;
    int32_t secondParam;
    bool isAudio;
} kInputData[] = {
        {MEDIA_MIMETYPE_AUDIO_OPUS, "bbb_opus_stereo_128kbps_48000hz.opus",
         "bbb_opus_stereo_128kbps_48000hz.info", 48000, 2, true},
        {MEDIA_MIMETYPE_AUDIO_AAC, "bbb_aac_stereo_128kbps_48000hz.aac",
         "bbb_aac_stereo_128kbps_48000hz.info", 48000, 2, true},
        {MEDIA_MIMETYPE_AUDIO_AAC_ADTS, "Mps_2_c2_fr1_Sc1_Dc2_0x03_raw.adts",
         "Mps_2_c2_fr1_Sc1_Dc2_0x03_raw.info", 48000, 2, true},
        {MEDIA_MIMETYPE_AUDIO_AMR_NB, "sine_amrnb_1ch_12kbps_8000hz.amrnb",
         "sine_amrnb_1ch_12kbps_8000hz.info", 8000, 1, true},
        {MEDIA_MIMETYPE_AUDIO_AMR_WB, "bbb_amrwb_1ch_14kbps_16000hz.amrwb",
         "bbb_amrwb_1ch_14kbps_16000hz.info", 16000, 1, true},
        {MEDIA_MIMETYPE_AUDIO_VORBIS, "bbb_vorbis_stereo_128kbps_48000hz.vorbis",
         "bbb_vorbis_stereo_128kbps_48000hz.info", 48000, 2, true},
        {MEDIA_MIMETYPE_AUDIO_FLAC, "bbb_flac_stereo_680kbps_48000hz.flac",
         "bbb_flac_stereo_680kbps_48000hz.info", 48000, 2, true},
        {MEDIA_MIMETYPE_VIDEO_VP9, "bbb_vp9_176x144_285kbps_60fps.vp9",
         "bbb_vp9_176x144_285kbps_60fps.info", 176, 144, false},
        {MEDIA_MIMETYPE_VIDEO_VP8, "bbb_vp8_176x144_240kbps_60fps.vp8",
         "bbb_vp8_176x144_240kbps_60fps.info", 176, 144, false},
        {MEDIA_MIMETYPE_VIDEO_AVC, "bbb_avc_176x144_300kbps_60fps.h264",
         "bbb_avc_176x144_300kbps_60fps.info", 176, 144, false},
        {MEDIA_MIMETYPE_VIDEO_HEVC, "bbb_hevc_176x144_176kbps_60fps.hevc",
         "bbb_hevc_176x144_176kbps_60fps.info", 176, 144, false},
        {MEDIA_MIMETYPE_VIDEO_AV1, "bbb_av1_176_144.av1", "bbb_av1_176_144.info", 176, 144, false},
        {MEDIA_MIMETYPE_VIDEO_H263, "bbb_h263_352x288_300kbps_12fps.h263",
         "bbb_h263_352x288_300kbps_12fps.info", 352, 288, false},
        {MEDIA_MIMETYPE_VIDEO_MPEG4, "bbb_mpeg4_352x288_512kbps_30fps.m4v",
         "bbb_mpeg4_352x288_512kbps_30fps.info", 352, 288, false},
};

class WriterTest : public ::testing::TestWithParam<pair<string, int32_t>> {
  public:
    WriterTest() : mWriter(nullptr), mFileMeta(nullptr), mCurrentTrack(nullptr) {}

    ~WriterTest() {
        if (mWriter) {
            mWriter.clear();
            mWriter = nullptr;
        }
        if (mFileMeta) {
            mFileMeta.clear();
            mFileMeta = nullptr;
        }
        if (mCurrentTrack) {
            mCurrentTrack.clear();
            mCurrentTrack = nullptr;
        }
    }

    virtual void SetUp() override {
        mNumCsds = 0;
        mInputFrameId = 0;
        mWriterName = unknown_comp;
        mDisableTest = false;

        static const std::map<std::string, standardWriters> mapWriter = {
                {"ogg", OGG},     {"aac", AAC},      {"aac_adts", AAC_ADTS}, {"webm", WEBM},
                {"mpeg4", MPEG4}, {"amrnb", AMR_NB}, {"amrwb", AMR_WB},      {"mpeg2Ts", MPEG2TS}};
        // Find the component type
        string writerFormat = GetParam().first;
        if (mapWriter.find(writerFormat) != mapWriter.end()) {
            mWriterName = mapWriter.at(writerFormat);
        }
        if (mWriterName == standardWriters::unknown_comp) {
            cout << "[   WARN   ] Test Skipped. No specific writer mentioned\n";
            mDisableTest = true;
        }
    }

    virtual void TearDown() override {
        mBufferInfo.clear();
        if (mInputStream.is_open()) mInputStream.close();
    }

    void getInputBufferInfo(string inputFileName, string inputInfo);

    int32_t createWriter(int32_t fd);

    int32_t addWriterSource(bool isAudio, configFormat params);

    enum standardWriters {
        OGG,
        AAC,
        AAC_ADTS,
        WEBM,
        MPEG4,
        AMR_NB,
        AMR_WB,
        MPEG2TS,
        unknown_comp,
    };

    standardWriters mWriterName;
    sp<MediaWriter> mWriter;
    sp<MetaData> mFileMeta;
    sp<MediaAdapter> mCurrentTrack;

    bool mDisableTest;
    int32_t mNumCsds;
    int32_t mInputFrameId;
    ifstream mInputStream;
    vector<BufferInfo> mBufferInfo;
};

void WriterTest::getInputBufferInfo(string inputFileName, string inputInfo) {
    std::ifstream eleInfo;
    eleInfo.open(inputInfo.c_str());
    ASSERT_EQ(eleInfo.is_open(), true);
    int32_t bytesCount = 0;
    uint32_t flags = 0;
    int64_t timestamp = 0;
    while (1) {
        if (!(eleInfo >> bytesCount)) break;
        eleInfo >> flags;
        eleInfo >> timestamp;
        mBufferInfo.push_back({bytesCount, flags, timestamp});
        if (flags == CODEC_CONFIG_FLAG) mNumCsds++;
    }
    eleInfo.close();
    mInputStream.open(inputFileName.c_str(), std::ifstream::binary);
    ASSERT_EQ(mInputStream.is_open(), true);
}

int32_t WriterTest::createWriter(int32_t fd) {
    mFileMeta = new MetaData;
    switch (mWriterName) {
        case OGG:
            mWriter = new OggWriter(fd);
            mFileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_OGG);
            break;
        case AAC:
            mWriter = new AACWriter(fd);
            mFileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_AAC_ADIF);
            break;
        case AAC_ADTS:
            mWriter = new AACWriter(fd);
            mFileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_AAC_ADTS);
            break;
        case WEBM:
            mWriter = new WebmWriter(fd);
            mFileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_WEBM);
            break;
        case MPEG4:
            mWriter = new MPEG4Writer(fd);
            mFileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_MPEG_4);
            break;
        case AMR_NB:
            mWriter = new AMRWriter(fd);
            mFileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_AMR_NB);
            break;
        case AMR_WB:
            mWriter = new AMRWriter(fd);
            mFileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_AMR_WB);
            break;
        case MPEG2TS:
            mWriter = new MPEG2TSWriter(fd);
            mFileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_MPEG2TS);
            break;
        default:
            return -1;
    }
    if (mWriter == nullptr) return -1;
    mFileMeta->setInt32(kKeyRealTimeRecording, false);
    return 0;
}

int32_t WriterTest::addWriterSource(bool isAudio, configFormat params) {
    if (mInputFrameId) return -1;
    sp<AMessage> format = new AMessage;
    if (mInputStream.is_open()) {
        format->setString("mime", params.mime);
        if (isAudio) {
            format->setInt32("channel-count", params.channelCount);
            format->setInt32("sample-rate", params.sampleRate);
        } else {
            format->setInt32("width", params.width);
            format->setInt32("height", params.height);
        }

        int32_t status =
                writeHeaderBuffers(mInputStream, mBufferInfo, mInputFrameId, format, mNumCsds);
        if (status != 0) return -1;
    }
    sp<MetaData> trackMeta = new MetaData;
    convertMessageToMetaData(format, trackMeta);
    mCurrentTrack = new MediaAdapter(trackMeta);
    if (mCurrentTrack == nullptr) {
        ALOGE("MediaAdapter returned nullptr");
        return -1;
    }
    status_t result = mWriter->addSource(mCurrentTrack);
    return result;
}

void getFileDetails(string &inputFilePath, string &info, configFormat &params, bool &isAudio,
                    int32_t streamIndex = 0) {
    if (streamIndex >= sizeof(kInputData) / sizeof(kInputData[0])) {
        return;
    }
    inputFilePath += kInputData[streamIndex].inputFile;
    info += kInputData[streamIndex].info;
    strcpy(params.mime, kInputData[streamIndex].mime);
    isAudio = kInputData[streamIndex].isAudio;
    if (isAudio) {
        params.sampleRate = kInputData[streamIndex].firstParam;
        params.channelCount = kInputData[streamIndex].secondParam;
    } else {
        params.width = kInputData[streamIndex].firstParam;
        params.height = kInputData[streamIndex].secondParam;
    }
    return;
}

TEST_P(WriterTest, CreateWriterTest) {
    if (mDisableTest) return;
    ALOGV("Tests the creation of writers");

    string outputFile = OUTPUT_FILE_NAME;
    int32_t fd =
            open(outputFile.c_str(), O_CREAT | O_LARGEFILE | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0) << "Failed to open output file to dump writer's data";

    // Creating writer within a test scope. Destructor should be called when the test ends
    ASSERT_EQ((status_t)OK, createWriter(fd))
            << "Failed to create writer for output format:" << GetParam().first;
}

TEST_P(WriterTest, WriterTest) {
    if (mDisableTest) return;
    ALOGV("Checks if for a given input, a valid muxed file has been created or not");

    string writerFormat = GetParam().first;
    string outputFile = OUTPUT_FILE_NAME;
    int32_t fd =
            open(outputFile.c_str(), O_CREAT | O_LARGEFILE | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0) << "Failed to open output file to dump writer's data";

    int32_t status = createWriter(fd);
    ASSERT_EQ((status_t)OK, status) << "Failed to create writer for output format:" << writerFormat;

    string inputFile = gEnv->getRes();
    string inputInfo = gEnv->getRes();
    configFormat param;
    bool isAudio;
    int32_t inputFileIdx = GetParam().second;
    getFileDetails(inputFile, inputInfo, param, isAudio, inputFileIdx);
    ASSERT_NE(inputFile.compare(gEnv->getRes()), 0) << "No input file specified";

    ASSERT_NO_FATAL_FAILURE(getInputBufferInfo(inputFile, inputInfo));
    status = addWriterSource(isAudio, param);
    ASSERT_EQ((status_t)OK, status) << "Failed to add source for " << writerFormat << "Writer";

    status = mWriter->start(mFileMeta.get());
    ASSERT_EQ((status_t)OK, status);
    status = sendBuffersToWriter(mInputStream, mBufferInfo, mInputFrameId, mCurrentTrack, 0,
                                 mBufferInfo.size());
    ASSERT_EQ((status_t)OK, status) << writerFormat << " writer failed";
    mCurrentTrack->stop();

    status = mWriter->stop();
    ASSERT_EQ((status_t)OK, status) << "Failed to stop the writer";
    close(fd);
}

TEST_P(WriterTest, PauseWriterTest) {
    if (mDisableTest) return;
    ALOGV("Validates the pause() api of writers");

    string writerFormat = GetParam().first;
    string outputFile = OUTPUT_FILE_NAME;
    int32_t fd =
            open(outputFile.c_str(), O_CREAT | O_LARGEFILE | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0) << "Failed to open output file to dump writer's data";

    int32_t status = createWriter(fd);
    ASSERT_EQ((status_t)OK, status) << "Failed to create writer for output format:" << writerFormat;

    string inputFile = gEnv->getRes();
    string inputInfo = gEnv->getRes();
    configFormat param;
    bool isAudio;
    int32_t inputFileIdx = GetParam().second;
    getFileDetails(inputFile, inputInfo, param, isAudio, inputFileIdx);
    ASSERT_NE(inputFile.compare(gEnv->getRes()), 0) << "No input file specified";

    ASSERT_NO_FATAL_FAILURE(getInputBufferInfo(inputFile, inputInfo));
    status = addWriterSource(isAudio, param);
    ASSERT_EQ((status_t)OK, status) << "Failed to add source for " << writerFormat << "Writer";

    status = mWriter->start(mFileMeta.get());
    ASSERT_EQ((status_t)OK, status);
    status = sendBuffersToWriter(mInputStream, mBufferInfo, mInputFrameId, mCurrentTrack, 0,
                                 mBufferInfo.size() / 4);
    ASSERT_EQ((status_t)OK, status) << writerFormat << " writer failed";

    bool isPaused = false;
    if ((mWriterName != standardWriters::MPEG2TS) && (mWriterName != standardWriters::MPEG4)) {
        status = mWriter->pause();
        ASSERT_EQ((status_t)OK, status);
        isPaused = true;
    }
    // In the pause state, writers shouldn't write anything. Testing the writers for the same
    int32_t numFramesPaused = mBufferInfo.size() / 4;
    status = sendBuffersToWriter(mInputStream, mBufferInfo, mInputFrameId, mCurrentTrack,
                                  mInputFrameId, numFramesPaused, isPaused);
    ASSERT_EQ((status_t)OK, status) << writerFormat << " writer failed";

    if (isPaused) {
        status = mWriter->start(mFileMeta.get());
        ASSERT_EQ((status_t)OK, status);
    }
    status = sendBuffersToWriter(mInputStream, mBufferInfo, mInputFrameId, mCurrentTrack,
                                  mInputFrameId, mBufferInfo.size());
    ASSERT_EQ((status_t)OK, status) << writerFormat << " writer failed";
    mCurrentTrack->stop();

    status = mWriter->stop();
    ASSERT_EQ((status_t)OK, status) << "Failed to stop the writer";
    close(fd);
}

TEST_P(WriterTest, MultiStartStopPauseTest) {
    // TODO: (b/144821804)
    // Enable the test for MPE2TS writer
    if (mDisableTest || mWriterName == standardWriters::MPEG2TS) return;
    ALOGV("Test writers for multiple start, stop and pause calls");

    string outputFile = OUTPUT_FILE_NAME;
    int32_t fd =
            open(outputFile.c_str(), O_CREAT | O_LARGEFILE | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0) << "Failed to open output file to dump writer's data";

    string writerFormat = GetParam().first;
    int32_t status = createWriter(fd);
    ASSERT_EQ(status, (status_t)OK) << "Failed to create writer for output format:" << writerFormat;

    string inputFile = gEnv->getRes();
    string inputInfo = gEnv->getRes();
    configFormat param;
    bool isAudio;
    int32_t inputFileIdx = GetParam().second;
    getFileDetails(inputFile, inputInfo, param, isAudio, inputFileIdx);
    ASSERT_NE(inputFile.compare(gEnv->getRes()), 0) << "No input file specified";

    ASSERT_NO_FATAL_FAILURE(getInputBufferInfo(inputFile, inputInfo));
    status = addWriterSource(isAudio, param);
    ASSERT_EQ((status_t)OK, status) << "Failed to add source for " << writerFormat << "Writer";

    // first start should succeed.
    status = mWriter->start(mFileMeta.get());
    ASSERT_EQ((status_t)OK, status) << "Could not start the writer";

    // Multiple start() may/may not succeed.
    // Writers are expected to not crash on multiple start() calls.
    for (int32_t count = 0; count < kMaxCount; count++) {
        mWriter->start(mFileMeta.get());
    }

    status = sendBuffersToWriter(mInputStream, mBufferInfo, mInputFrameId, mCurrentTrack, 0,
                              mBufferInfo.size() / 4);
    ASSERT_EQ((status_t)OK, status) << writerFormat << " writer failed";

    for (int32_t count = 0; count < kMaxCount; count++) {
        mWriter->pause();
        mWriter->start(mFileMeta.get());
    }

    mWriter->pause();
    int32_t numFramesPaused = mBufferInfo.size() / 4;
    status = sendBuffersToWriter(mInputStream, mBufferInfo, mInputFrameId, mCurrentTrack,
                              mInputFrameId, numFramesPaused, true);
    ASSERT_EQ((status_t)OK, status) << writerFormat << " writer failed";

    for (int32_t count = 0; count < kMaxCount; count++) {
        mWriter->start(mFileMeta.get());
    }

    status = sendBuffersToWriter(mInputStream, mBufferInfo, mInputFrameId, mCurrentTrack,
                              mInputFrameId, mBufferInfo.size());
    ASSERT_EQ((status_t)OK, status) << writerFormat << " writer failed";

    mCurrentTrack->stop();

    // first stop should succeed.
    status = mWriter->stop();
    ASSERT_EQ((status_t)OK, status) << "Failed to stop the writer";
    // Multiple stop() may/may not succeed.
    // Writers are expected to not crash on multiple stop() calls.
    for (int32_t count = 0; count < kMaxCount; count++) {
        mWriter->stop();
    }
    close(fd);
}

// TODO: (b/144476164)
// Add AAC_ADTS, FLAC, AV1 input
INSTANTIATE_TEST_SUITE_P(WriterTestAll, WriterTest,
                         ::testing::Values(make_pair("ogg", 0), make_pair("webm", 0),
                                           make_pair("aac", 1), make_pair("mpeg4", 1),
                                           make_pair("amrnb", 3), make_pair("amrwb", 4),
                                           make_pair("webm", 5), make_pair("webm", 7),
                                           make_pair("webm", 8), make_pair("mpeg4", 9),
                                           make_pair("mpeg4", 10), make_pair("mpeg4", 12),
                                           make_pair("mpeg4", 13), make_pair("mpeg2Ts", 1),
                                           make_pair("mpeg2Ts", 9)));

int main(int argc, char **argv) {
    gEnv = new WriterTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
