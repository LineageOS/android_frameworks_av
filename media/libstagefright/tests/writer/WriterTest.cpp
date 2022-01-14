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

#include <binder/ProcessState.h>

#include <inttypes.h>
#include <fstream>
#include <iostream>

#include <media/NdkMediaExtractor.h>
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

// Stts values within 0.1ms(100us) difference are fudged to save too
// many stts entries in MPEG4Writer.
constexpr int32_t kMpeg4MuxToleranceTimeUs = 100;
// Tolerance value for other writers
constexpr int32_t kMuxToleranceTimeUs = 1;

static WriterTestEnvironment *gEnv = nullptr;

enum inputId {
    // audio streams
    AAC_1,
    AAC_ADTS_1,
    AMR_NB_1,
    AMR_WB_1,
    FLAC_1,
    OPUS_1,
    VORBIS_1,
    // video streams
    AV1_1,
    AVC_1,
    H263_1,
    HEVC_1,
    MPEG4_1,
    VP8_1,
    VP9_1,
    // heif stream
    HEIC_1,
    UNUSED_ID,
    UNKNOWN_ID,
};

// LookUpTable of clips and metadata for component testing
static const struct InputData {
    inputId inpId;
    const char *mime;
    string inputFile;
    string info;
    int32_t firstParam;
    int32_t secondParam;
    bool isAudio;
} kInputData[] = {
        {AAC_1, MEDIA_MIMETYPE_AUDIO_AAC, "audio_aac_stereo_8kbps_11025hz.aac",
         "audio_aac_stereo_8kbps_11025hz.info", 11025, 2, true},
        {AAC_ADTS_1, MEDIA_MIMETYPE_AUDIO_AAC_ADTS, "Mps_2_c2_fr1_Sc1_Dc2_0x03_raw.adts",
         "Mps_2_c2_fr1_Sc1_Dc2_0x03_raw.info", 48000, 2, true},
        {AMR_NB_1, MEDIA_MIMETYPE_AUDIO_AMR_NB, "sine_amrnb_1ch_12kbps_8000hz.amrnb",
         "sine_amrnb_1ch_12kbps_8000hz.info", 8000, 1, true},
        {AMR_WB_1, MEDIA_MIMETYPE_AUDIO_AMR_WB, "bbb_amrwb_1ch_14kbps_16000hz.amrwb",
         "bbb_amrwb_1ch_14kbps_16000hz.info", 16000, 1, true},
        {FLAC_1, MEDIA_MIMETYPE_AUDIO_FLAC, "bbb_flac_stereo_680kbps_48000hz.flac",
         "bbb_flac_stereo_680kbps_48000hz.info", 48000, 2, true},
        {OPUS_1, MEDIA_MIMETYPE_AUDIO_OPUS, "bbb_opus_stereo_128kbps_48000hz.opus",
         "bbb_opus_stereo_128kbps_48000hz.info", 48000, 2, true},
        {VORBIS_1, MEDIA_MIMETYPE_AUDIO_VORBIS, "bbb_vorbis_1ch_64kbps_16kHz.vorbis",
         "bbb_vorbis_1ch_64kbps_16kHz.info", 16000, 1, true},

        {AV1_1, MEDIA_MIMETYPE_VIDEO_AV1, "bbb_av1_176_144.av1", "bbb_av1_176_144.info", 176, 144,
         false},
        {AVC_1, MEDIA_MIMETYPE_VIDEO_AVC, "bbb_avc_352x288_768kbps_30fps.avc",
         "bbb_avc_352x288_768kbps_30fps.info", 352, 288, false},
        {H263_1, MEDIA_MIMETYPE_VIDEO_H263, "bbb_h263_352x288_300kbps_12fps.h263",
         "bbb_h263_352x288_300kbps_12fps.info", 352, 288, false},
        {HEVC_1, MEDIA_MIMETYPE_VIDEO_HEVC, "bbb_hevc_340x280_768kbps_30fps.hevc",
         "bbb_hevc_340x280_768kbps_30fps.info", 340, 280, false},
        {MPEG4_1, MEDIA_MIMETYPE_VIDEO_MPEG4, "bbb_mpeg4_352x288_512kbps_30fps.m4v",
         "bbb_mpeg4_352x288_512kbps_30fps.info", 352, 288, false},
        {VP8_1, MEDIA_MIMETYPE_VIDEO_VP8, "bbb_vp8_176x144_240kbps_60fps.vp8",
         "bbb_vp8_176x144_240kbps_60fps.info", 176, 144, false},
        {VP9_1, MEDIA_MIMETYPE_VIDEO_VP9, "bbb_vp9_176x144_285kbps_60fps.vp9",
         "bbb_vp9_176x144_285kbps_60fps.info", 176, 144, false},

        {HEIC_1, MEDIA_MIMETYPE_IMAGE_ANDROID_HEIC, "bbb_hevc_176x144_176kbps_60fps.hevc",
         "bbb_heic_176x144_176kbps_60fps.info", 176, 144, false},
};

class WriterTest {
  public:
    WriterTest() : mWriter(nullptr), mFileMeta(nullptr) {}

    ~WriterTest() {
        if (mFileMeta) {
            mFileMeta.clear();
            mFileMeta = nullptr;
        }
        if (mWriter) {
            mWriter.clear();
            mWriter = nullptr;
        }
        if (gEnv->cleanUp()) remove(OUTPUT_FILE_NAME);

        for (int32_t idx = 0; idx < kMaxTrackCount; idx++) {
            mBufferInfo[idx].clear();
            if (mCurrentTrack[idx]) {
                mCurrentTrack[idx]->stop();
                mCurrentTrack[idx].clear();
                mCurrentTrack[idx] = nullptr;
            }
            if (mInputStream[idx].is_open()) mInputStream[idx].close();
        }
    }

    void setupWriterType(string writerFormat) {
        mWriterName = unknown_comp;
        mDisableTest = false;
        static const std::map<std::string, standardWriters> mapWriter = {
                {"ogg", OGG},     {"aac", AAC},      {"aac_adts", AAC_ADTS}, {"webm", WEBM},
                {"mpeg4", MPEG4}, {"amrnb", AMR_NB}, {"amrwb", AMR_WB},      {"mpeg2Ts", MPEG2TS}};
        // Find the component type
        if (mapWriter.find(writerFormat) != mapWriter.end()) {
            mWriterName = mapWriter.at(writerFormat);
        }
        if (mWriterName == standardWriters::unknown_comp) {
            cout << "[   WARN   ] Test Skipped. No specific writer mentioned\n";
            mDisableTest = true;
        }
    }

    void getInputBufferInfo(string inputFileName, string inputInfo, int32_t idx = 0);

    int32_t createWriter(int32_t fd);

    int32_t addWriterSource(bool isAudio, configFormat params, int32_t idx = 0);

    void setupExtractor(AMediaExtractor *extractor, string inputFileName, int32_t &trackCount);

    void extract(AMediaExtractor *extractor, configFormat &params, vector<BufferInfo> &bufferInfo,
                 uint8_t *buffer, size_t bufSize, size_t *bytesExtracted, int32_t idx);

    void compareParams(configFormat srcParam, configFormat dstParam, vector<BufferInfo> dstBufInfo,
                       int32_t index);

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
    sp<MediaAdapter> mCurrentTrack[kMaxTrackCount]{};

    bool mDisableTest;
    int32_t mNumCsds[kMaxTrackCount]{};
    int32_t mInputFrameId[kMaxTrackCount]{};
    ifstream mInputStream[kMaxTrackCount]{};
    vector<BufferInfo> mBufferInfo[kMaxTrackCount];
};

class WriteFunctionalityTest
    : public WriterTest,
      public ::testing::TestWithParam<tuple<string /* writerFormat*/, inputId /* inputId0*/,
                                            inputId /* inputId1*/, float /* BufferInterval*/>> {
  public:
    virtual void SetUp() override { setupWriterType(get<0>(GetParam())); }
};

void WriterTest::getInputBufferInfo(string inputFileName, string inputInfo, int32_t idx) {
    std::ifstream eleInfo;
    eleInfo.open(inputInfo.c_str());
    ASSERT_EQ(eleInfo.is_open(), true);
    int32_t bytesCount = 0;
    uint32_t flags = 0;
    int64_t timestamp = 0;
    int32_t numCsds = 0;
    while (1) {
        if (!(eleInfo >> bytesCount)) break;
        eleInfo >> flags;
        eleInfo >> timestamp;
        mBufferInfo[idx].push_back({bytesCount, flags, timestamp});
        if (flags == CODEC_CONFIG_FLAG) numCsds++;
    }
    eleInfo.close();
    mNumCsds[idx] = numCsds;
    mInputStream[idx].open(inputFileName.c_str(), std::ifstream::binary);
    ASSERT_EQ(mInputStream[idx].is_open(), true);
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

int32_t WriterTest::addWriterSource(bool isAudio, configFormat params, int32_t idx) {
    if (mInputFrameId[idx]) return -1;
    sp<AMessage> format = new AMessage;
    if (mInputStream[idx].is_open()) {
        format->setString("mime", params.mime);
        if (isAudio) {
            format->setInt32("channel-count", params.channelCount);
            format->setInt32("sample-rate", params.sampleRate);
        } else {
            format->setInt32("width", params.width);
            format->setInt32("height", params.height);
        }
        if (mNumCsds[idx]) {
            int32_t status = writeHeaderBuffers(mInputStream[idx], mBufferInfo[idx],
                                                mInputFrameId[idx], format, mNumCsds[idx]);
            if (status != 0) return -1;
        }
    }

    sp<MetaData> trackMeta = new MetaData;
    convertMessageToMetaData(format, trackMeta);
    mCurrentTrack[idx] = new MediaAdapter(trackMeta);
    if (mCurrentTrack[idx] == nullptr) {
        ALOGE("MediaAdapter returned nullptr");
        return -1;
    }
    status_t result = mWriter->addSource(mCurrentTrack[idx]);
    return result;
}

void getFileDetails(string &inputFilePath, string &info, configFormat &params, bool &isAudio,
                    inputId inpId) {
    int32_t inputDataSize = sizeof(kInputData) / sizeof(kInputData[0]);
    int32_t streamIndex = 0;
    for (; streamIndex < inputDataSize; streamIndex++) {
        if (inpId == kInputData[streamIndex].inpId) {
            break;
        }
    }
    if (streamIndex == inputDataSize) {
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

void WriterTest::setupExtractor(AMediaExtractor *extractor, string inputFileName,
                                int32_t &trackCount) {
    ALOGV("Input file for extractor: %s", inputFileName.c_str());

    int32_t fd = open(inputFileName.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0) << "Failed to open writer's output file to validate";

    struct stat buf;
    int32_t status = fstat(fd, &buf);
    ASSERT_EQ(status, 0) << "Failed to get properties of input file for extractor";

    size_t fileSize = buf.st_size;
    ALOGV("Size of input file to extractor: %zu", fileSize);

    status = AMediaExtractor_setDataSourceFd(extractor, fd, 0, fileSize);
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to set data source for extractor";

    trackCount = AMediaExtractor_getTrackCount(extractor);
    ASSERT_GT(trackCount, 0) << "No tracks reported by extractor";
    ALOGV("Number of tracks reported by extractor : %d", trackCount);
    return;
}

void WriterTest::extract(AMediaExtractor *extractor, configFormat &params,
                         vector<BufferInfo> &bufferInfo, uint8_t *buffer, size_t bufSize,
                         size_t *bytesExtracted, int32_t idx) {
    AMediaExtractor_selectTrack(extractor, idx);
    AMediaFormat *format = AMediaExtractor_getTrackFormat(extractor, idx);
    ASSERT_NE(format, nullptr) << "Track format is NULL";
    ALOGI("Track format = %s", AMediaFormat_toString(format));

    const char *mime = nullptr;
    AMediaFormat_getString(format, AMEDIAFORMAT_KEY_MIME, &mime);
    ASSERT_NE(mime, nullptr) << "Track mime is NULL";
    ALOGI("Track mime = %s", mime);
    strlcpy(params.mime, mime, kMimeSize);

    if (!strncmp(mime, "audio/", 6)) {
        ASSERT_TRUE(
                AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_CHANNEL_COUNT, &params.channelCount))
                << "Extractor did not report channel count";
        ASSERT_TRUE(AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_SAMPLE_RATE, &params.sampleRate))
                << "Extractor did not report sample rate";
    } else if (!strncmp(mime, "video/", 6) || !strncmp(mime, "image/", 6)) {
        ASSERT_TRUE(AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_WIDTH, &params.width))
                << "Extractor did not report width";
        ASSERT_TRUE(AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_HEIGHT, &params.height))
                << "Extractor did not report height";
    } else {
        ASSERT_TRUE(false) << "Invalid mime " << mime;
    }

    int32_t bufferOffset = 0;
    // Get CSD data
    int index = 0;
    void *csdBuf;
    while (1) {
        csdBuf = nullptr;
        char csdName[16];
        snprintf(csdName, 16, "csd-%d", index);
        size_t csdSize = 0;
        bool csdFound = AMediaFormat_getBuffer(format, csdName, &csdBuf, &csdSize);
        if (!csdFound || !csdBuf || !csdSize) break;

        bufferInfo.push_back({static_cast<int32_t>(csdSize), CODEC_CONFIG_FLAG, 0});
        memcpy(buffer + bufferOffset, csdBuf, csdSize);
        bufferOffset += csdSize;
        index++;
    }

    // Get frame data
    while (1) {
        ssize_t sampleSize = AMediaExtractor_getSampleSize(extractor);
        if (sampleSize < 0) break;

        uint8_t *sampleBuffer = (uint8_t *)malloc(sampleSize);
        ASSERT_NE(sampleBuffer, nullptr) << "Failed to allocate the buffer of size " << sampleSize;

        int bytesRead = AMediaExtractor_readSampleData(extractor, sampleBuffer, sampleSize);
        ASSERT_EQ(bytesRead, sampleSize)
                << "Number of bytes extracted does not match with sample size";
        int64_t pts = AMediaExtractor_getSampleTime(extractor);
        uint32_t flag = AMediaExtractor_getSampleFlags(extractor);

        if (mime == MEDIA_MIMETYPE_AUDIO_VORBIS) {
            // Removing 4 bytes of AMEDIAFORMAT_KEY_VALID_SAMPLES from sample size
            bytesRead = bytesRead - 4;
        }

        ASSERT_LE(bufferOffset + bytesRead, bufSize)
                << "Size of the buffer is insufficient to store the extracted data";
        bufferInfo.push_back({bytesRead, flag, pts});
        memcpy(buffer + bufferOffset, sampleBuffer, bytesRead);
        bufferOffset += bytesRead;

        AMediaExtractor_advance(extractor);
        free(sampleBuffer);
    }
    *bytesExtracted = bufferOffset;
    return;
}

void WriterTest::compareParams(configFormat srcParam, configFormat dstParam,
                               vector<BufferInfo> dstBufInfo, int32_t index) {
    ASSERT_STREQ(srcParam.mime, dstParam.mime)
            << "Extracted mime type does not match with input mime type";

    if (!strncmp(srcParam.mime, "audio/", 6)) {
        ASSERT_EQ(srcParam.channelCount, dstParam.channelCount)
                << "Extracted channel count does not match with input channel count";
        ASSERT_EQ(srcParam.sampleRate, dstParam.sampleRate)
                << "Extracted sample rate does not match with input sample rate";
    } else if (!strncmp(srcParam.mime, "video/", 6) || !strncmp(srcParam.mime, "image/", 6)) {
        ASSERT_EQ(srcParam.width, dstParam.width)
                << "Extracted width does not match with input width";
        ASSERT_EQ(srcParam.height, dstParam.height)
                << "Extracted height does not match with input height";
    } else {
        ASSERT_TRUE(false) << "Invalid mime type" << srcParam.mime;
    }

    int32_t toleranceValueUs = kMuxToleranceTimeUs;
    if (mWriterName == MPEG4) {
        toleranceValueUs = kMpeg4MuxToleranceTimeUs;
    }
    for (int32_t i = 0; i < dstBufInfo.size(); i++) {
        ASSERT_EQ(mBufferInfo[index][i].size, dstBufInfo[i].size)
                << "Input size " << mBufferInfo[index][i].size << " mismatched with extracted size "
                << dstBufInfo[i].size;
        ASSERT_EQ(mBufferInfo[index][i].flags, dstBufInfo[i].flags)
                << "Input flag " << mBufferInfo[index][i].flags
                << " mismatched with extracted size " << dstBufInfo[i].flags;
        ASSERT_LE(abs(mBufferInfo[index][i].timeUs - dstBufInfo[i].timeUs), toleranceValueUs)
                << "Difference between original timestamp " << mBufferInfo[index][i].timeUs
                << " and extracted timestamp " << dstBufInfo[i].timeUs
                << "is greater than tolerance value = " << toleranceValueUs << " micro seconds";
    }
    return;
}

TEST_P(WriteFunctionalityTest, CreateWriterTest) {
    if (mDisableTest) return;
    ALOGV("Tests the creation of writers");

    string outputFile = OUTPUT_FILE_NAME;
    int32_t fd =
            open(outputFile.c_str(), O_CREAT | O_LARGEFILE | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0) << "Failed to open output file to dump writer's data";

    // Creating writer within a test scope. Destructor should be called when the test ends
    ASSERT_EQ((status_t)OK, createWriter(fd))
            << "Failed to create writer for output format:" << get<0>(GetParam());
}

TEST_P(WriteFunctionalityTest, WriterTest) {
    if (mDisableTest) return;
    ALOGV("Checks if for a given input, a valid muxed file has been created or not");

    string writerFormat = get<0>(GetParam());
    string outputFile = OUTPUT_FILE_NAME;
    int32_t fd =
            open(outputFile.c_str(), O_CREAT | O_LARGEFILE | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0) << "Failed to open output file to dump writer's data";

    int32_t status = createWriter(fd);
    ASSERT_EQ((status_t)OK, status) << "Failed to create writer for output format:" << writerFormat;

    inputId inpId[] = {get<1>(GetParam()), get<2>(GetParam())};
    ASSERT_NE(inpId[0], UNUSED_ID) << "Test expects first inputId to be a valid id";

    int32_t numTracks = 1;
    if (inpId[1] != UNUSED_ID) {
        numTracks++;
    }

    size_t fileSize[numTracks];
    configFormat param[numTracks];
    for (int32_t idx = 0; idx < numTracks; idx++) {
        string inputFile = gEnv->getRes();
        string inputInfo = gEnv->getRes();
        bool isAudio;
        getFileDetails(inputFile, inputInfo, param[idx], isAudio, inpId[idx]);
        ASSERT_NE(inputFile.compare(gEnv->getRes()), 0) << "No input file specified";

        struct stat buf;
        status = stat(inputFile.c_str(), &buf);
        ASSERT_EQ(status, 0) << "Failed to get properties of input file:" << inputFile;
        fileSize[idx] = buf.st_size;

        ASSERT_NO_FATAL_FAILURE(getInputBufferInfo(inputFile, inputInfo, idx));
        status = addWriterSource(isAudio, param[idx], idx);
        ASSERT_EQ((status_t)OK, status) << "Failed to add source for " << writerFormat << "Writer";
    }

    status = mWriter->start(mFileMeta.get());
    ASSERT_EQ((status_t)OK, status);
    float interval = get<3>(GetParam());
    ASSERT_LE(interval, 1.0f) << "Buffer interval invalid. Should be less than or equal to 1.0";

    size_t range = 0;
    int32_t loopCount = 0;
    int32_t offset[kMaxTrackCount]{};
    while (loopCount < ceil(1.0 / interval)) {
        for (int32_t idx = 0; idx < numTracks; idx++) {
            range = mBufferInfo[idx].size() * interval;
            status = sendBuffersToWriter(mInputStream[idx], mBufferInfo[idx], mInputFrameId[idx],
                                         mCurrentTrack[idx], offset[idx], range);
            ASSERT_EQ((status_t)OK, status) << writerFormat << " writer failed";
            offset[idx] += range;
        }
        loopCount++;
    }
    for (int32_t idx = 0; idx < kMaxTrackCount; idx++) {
        if (mCurrentTrack[idx]) {
            mCurrentTrack[idx]->stop();
        }
    }
    status = mWriter->stop();
    ASSERT_EQ((status_t)OK, status) << "Failed to stop the writer";
    close(fd);

    // Validate the output muxed file created by writer
    // TODO(b/146423022): Skip validating output for webm writer
    // TODO(b/146421018): Skip validating output for ogg writer
    if (mWriterName != OGG && mWriterName != WEBM) {
        configFormat extractorParams[numTracks];
        vector<BufferInfo> extractorBufferInfo[numTracks];
        int32_t trackCount = -1;

        AMediaExtractor *extractor = AMediaExtractor_new();
        ASSERT_NE(extractor, nullptr) << "Failed to create extractor";
        ASSERT_NO_FATAL_FAILURE(setupExtractor(extractor, outputFile, trackCount));
        ASSERT_EQ(trackCount, numTracks)
                << "Tracks reported by extractor does not match with input number of tracks";

        for (int32_t idx = 0; idx < numTracks; idx++) {
            char *inputBuffer = (char *)malloc(fileSize[idx]);
            ASSERT_NE(inputBuffer, nullptr)
                    << "Failed to allocate the buffer of size " << fileSize[idx];
            mInputStream[idx].seekg(0, mInputStream[idx].beg);
            mInputStream[idx].read(inputBuffer, fileSize[idx]);
            ASSERT_EQ(mInputStream[idx].gcount(), fileSize[idx]);

            uint8_t *extractedBuffer = (uint8_t *)malloc(fileSize[idx]);
            ASSERT_NE(extractedBuffer, nullptr)
                    << "Failed to allocate the buffer of size " << fileSize[idx];
            size_t bytesExtracted = 0;

            ASSERT_NO_FATAL_FAILURE(extract(extractor, extractorParams[idx],
                                            extractorBufferInfo[idx], extractedBuffer,
                                            fileSize[idx], &bytesExtracted, idx));
            ASSERT_GT(bytesExtracted, 0) << "Total bytes extracted by extractor cannot be zero";

            ASSERT_NO_FATAL_FAILURE(
                    compareParams(param[idx], extractorParams[idx], extractorBufferInfo[idx], idx));

            ASSERT_EQ(memcmp(extractedBuffer, (uint8_t *)inputBuffer, bytesExtracted), 0)
                    << "Extracted bit stream does not match with input bit stream";

            free(inputBuffer);
            free(extractedBuffer);
        }
        AMediaExtractor_delete(extractor);
    }
}

TEST_P(WriteFunctionalityTest, PauseWriterTest) {
    if (mDisableTest) return;
    ALOGV("Validates the pause() api of writers");

    string writerFormat = get<0>(GetParam());
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
    inputId inpId = get<1>(GetParam());
    ASSERT_NE(inpId, UNUSED_ID) << "Test expects first inputId to be a valid id";

    getFileDetails(inputFile, inputInfo, param, isAudio, inpId);
    ASSERT_NE(inputFile.compare(gEnv->getRes()), 0) << "No input file specified";

    ASSERT_NO_FATAL_FAILURE(getInputBufferInfo(inputFile, inputInfo));
    status = addWriterSource(isAudio, param);
    ASSERT_EQ((status_t)OK, status) << "Failed to add source for " << writerFormat << "Writer";

    status = mWriter->start(mFileMeta.get());
    ASSERT_EQ((status_t)OK, status);
    status = sendBuffersToWriter(mInputStream[0], mBufferInfo[0], mInputFrameId[0],
                                 mCurrentTrack[0], 0, mBufferInfo[0].size() / 4);
    ASSERT_EQ((status_t)OK, status) << writerFormat << " writer failed";

    bool isPaused = false;
    if ((mWriterName != standardWriters::MPEG2TS) && (mWriterName != standardWriters::MPEG4)) {
        status = mWriter->pause();
        ASSERT_EQ((status_t)OK, status);
        isPaused = true;
    }
    // In the pause state, writers shouldn't write anything. Testing the writers for the same
    int32_t numFramesPaused = mBufferInfo[0].size() / 4;
    status = sendBuffersToWriter(mInputStream[0], mBufferInfo[0], mInputFrameId[0],
                                 mCurrentTrack[0], mInputFrameId[0], numFramesPaused, isPaused);
    ASSERT_EQ((status_t)OK, status) << writerFormat << " writer failed";

    if (isPaused) {
        status = mWriter->start(mFileMeta.get());
        ASSERT_EQ((status_t)OK, status);
    }
    status = sendBuffersToWriter(mInputStream[0], mBufferInfo[0], mInputFrameId[0],
                                 mCurrentTrack[0], mInputFrameId[0], mBufferInfo[0].size());
    ASSERT_EQ((status_t)OK, status) << writerFormat << " writer failed";
    mCurrentTrack[0]->stop();

    status = mWriter->stop();
    ASSERT_EQ((status_t)OK, status) << "Failed to stop the writer";
    close(fd);
}

TEST_P(WriteFunctionalityTest, MultiStartStopPauseTest) {
    // TODO: (b/144821804)
    // Enable the test for MPE2TS writer
    if (mDisableTest || mWriterName == standardWriters::MPEG2TS) return;
    ALOGV("Test writers for multiple start, stop and pause calls");

    string outputFile = OUTPUT_FILE_NAME;
    int32_t fd =
            open(outputFile.c_str(), O_CREAT | O_LARGEFILE | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0) << "Failed to open output file to dump writer's data";

    string writerFormat = get<0>(GetParam());
    int32_t status = createWriter(fd);
    ASSERT_EQ(status, (status_t)OK) << "Failed to create writer for output format:" << writerFormat;

    string inputFile = gEnv->getRes();
    string inputInfo = gEnv->getRes();
    configFormat param;
    bool isAudio;
    inputId inpId = get<1>(GetParam());
    ASSERT_NE(inpId, UNUSED_ID) << "Test expects first inputId to be a valid id";

    getFileDetails(inputFile, inputInfo, param, isAudio, inpId);
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

    status = sendBuffersToWriter(mInputStream[0], mBufferInfo[0], mInputFrameId[0],
                                 mCurrentTrack[0], 0, mBufferInfo[0].size() / 4);
    ASSERT_EQ((status_t)OK, status) << writerFormat << " writer failed";

    for (int32_t count = 0; count < kMaxCount; count++) {
        mWriter->pause();
        mWriter->start(mFileMeta.get());
    }

    mWriter->pause();
    int32_t numFramesPaused = mBufferInfo[0].size() / 4;
    status = sendBuffersToWriter(mInputStream[0], mBufferInfo[0], mInputFrameId[0],
                                 mCurrentTrack[0], mInputFrameId[0], numFramesPaused, true);
    ASSERT_EQ((status_t)OK, status) << writerFormat << " writer failed";

    for (int32_t count = 0; count < kMaxCount; count++) {
        mWriter->start(mFileMeta.get());
    }

    status = sendBuffersToWriter(mInputStream[0], mBufferInfo[0], mInputFrameId[0],
                                 mCurrentTrack[0], mInputFrameId[0], mBufferInfo[0].size());
    ASSERT_EQ((status_t)OK, status) << writerFormat << " writer failed";

    mCurrentTrack[0]->stop();

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

class WriterValidityTest
    : public WriterTest,
      public ::testing::TestWithParam<
              tuple<string /* writerFormat*/, inputId /* inputId0*/, bool /* addSourceFail*/>> {
  public:
    virtual void SetUp() override { setupWriterType(get<0>(GetParam())); }
};

TEST_P(WriterValidityTest, InvalidInputTest) {
    if (mDisableTest) return;
    ALOGV("Validates writer's behavior for invalid inputs");

    string writerFormat = get<0>(GetParam());
    inputId inpId = get<1>(GetParam());
    bool addSourceFailExpected = get<2>(GetParam());

    // Test writers for invalid FD value
    int32_t fd = -1;
    int32_t status = createWriter(fd);
    if (status != OK) {
        ALOGV("createWriter failed for invalid FD, this is expected behavior");
        return;
    }

    // If writer was created for invalid fd, test it further.
    string inputFile = gEnv->getRes();
    string inputInfo = gEnv->getRes();
    configFormat param;
    bool isAudio;
    ASSERT_NE(inpId, UNUSED_ID) << "Test expects first inputId to be a valid id";

    getFileDetails(inputFile, inputInfo, param, isAudio, inpId);
    ASSERT_NE(inputFile.compare(gEnv->getRes()), 0) << "No input file specified";

    ASSERT_NO_FATAL_FAILURE(getInputBufferInfo(inputFile, inputInfo));
    status = addWriterSource(isAudio, param);
    if (status != OK) {
        ASSERT_TRUE(addSourceFailExpected)
                << "Failed to add source for " << writerFormat << " writer";
        ALOGV("addWriterSource failed for invalid FD, this is expected behavior");
        return;
    }

    // start the writer with valid argument but invalid FD
    status = mWriter->start(mFileMeta.get());
    ASSERT_NE((status_t)OK, status) << "Writer did not fail for invalid FD";

    status = sendBuffersToWriter(mInputStream[0], mBufferInfo[0], mInputFrameId[0],
                                 mCurrentTrack[0], 0, mBufferInfo[0].size());
    ASSERT_NE((status_t)OK, status) << "Writer did not report error for invalid FD";

    status = mCurrentTrack[0]->stop();
    ASSERT_EQ((status_t)OK, status) << "Failed to stop the track";

    status = mWriter->stop();
    ASSERT_EQ((status_t)OK, status) << "Failed to stop " << writerFormat << " writer";
}

TEST_P(WriterValidityTest, MalFormedDataTest) {
    if (mDisableTest) return;
    // Enable test for Ogg writer
    ASSERT_NE(mWriterName, OGG) << "TODO(b/160105646)";
    ALOGV("Test writer for malformed inputs");

    string writerFormat = get<0>(GetParam());
    inputId inpId = get<1>(GetParam());
    bool addSourceFailExpected = get<2>(GetParam());
    int32_t fd =
            open(OUTPUT_FILE_NAME, O_CREAT | O_LARGEFILE | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0) << "Failed to open output file to dump writer's data";

    int32_t status = createWriter(fd);
    ASSERT_EQ(status, (status_t)OK)
            << "Failed to create writer for " << writerFormat << " output format";

    string inputFile = gEnv->getRes();
    string inputInfo = gEnv->getRes();
    configFormat param;
    bool isAudio;
    ASSERT_NE(inpId, UNUSED_ID) << "Test expects first inputId to be a valid id";

    getFileDetails(inputFile, inputInfo, param, isAudio, inpId);
    ASSERT_NE(inputFile.compare(gEnv->getRes()), 0) << "No input file specified";

    ASSERT_NO_FATAL_FAILURE(getInputBufferInfo(inputFile, inputInfo));
    // Remove CSD data from input
    mNumCsds[0] = 0;
    status = addWriterSource(isAudio, param);
    if (status != OK) {
        ASSERT_TRUE(addSourceFailExpected)
                << "Failed to add source for " << writerFormat << " writer";
        ALOGV("%s writer failed to addSource after removing CSD from input", writerFormat.c_str());
        return;
    }

    status = mWriter->start(mFileMeta.get());
    ASSERT_EQ((status_t)OK, status) << "Could not start " << writerFormat << "writer";

    // Skip first few frames. These may contain sync frames also.
    int32_t frameID = mInputFrameId[0] + mBufferInfo[0].size() / 4;
    status = sendBuffersToWriter(mInputStream[0], mBufferInfo[0], frameID, mCurrentTrack[0], 0,
                                 mBufferInfo[0].size());
    ASSERT_EQ((status_t)OK, status) << writerFormat << " writer failed";

    status = mCurrentTrack[0]->stop();
    ASSERT_EQ((status_t)OK, status) << "Failed to stop the track";

    Vector<String16> args;
    status = mWriter->dump(fd, args);
    ASSERT_EQ((status_t)OK, status) << "Failed to dump statistics from writer";

    status = mWriter->stop();
    ASSERT_EQ((status_t)OK, status) << "Failed to stop " << writerFormat << " writer";
    close(fd);
}

// This test is specific to MPEG4Writer to test more APIs
TEST_P(WriteFunctionalityTest, Mpeg4WriterTest) {
    if (mDisableTest) return;
    if (mWriterName != standardWriters::MPEG4) return;
    ALOGV("Test MPEG4 writer specific APIs");

    inputId inpId = get<1>(GetParam());
    int32_t fd =
            open(OUTPUT_FILE_NAME, O_CREAT | O_LARGEFILE | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0) << "Failed to open output file to dump writer's data";

    int32_t status = createWriter(fd);
    ASSERT_EQ(status, (status_t)OK) << "Failed to create writer for mpeg4 output format";

    string inputFile = gEnv->getRes();
    string inputInfo = gEnv->getRes();
    configFormat param;
    bool isAudio;
    ASSERT_NE(inpId, UNUSED_ID) << "Test expects first inputId to be a valid id";

    getFileDetails(inputFile, inputInfo, param, isAudio, inpId);
    ASSERT_NE(inputFile.compare(gEnv->getRes()), 0) << "No input file specified";

    ASSERT_NO_FATAL_FAILURE(getInputBufferInfo(inputFile, inputInfo));
    status = addWriterSource(isAudio, param);
    ASSERT_EQ((status_t)OK, status) << "Failed to add source for mpeg4 Writer";

    // signal meta data for the writer
    sp<MPEG4Writer> mp4writer = static_cast<MPEG4Writer *>(mWriter.get());
    status = mp4writer->setInterleaveDuration(kDefaultInterleaveDuration);
    ASSERT_EQ((status_t)OK, status) << "setInterleaveDuration failed";

    status = mp4writer->setGeoData(kDefaultLatitudex10000, kDefaultLongitudex10000);
    ASSERT_EQ((status_t)OK, status) << "setGeoData failed";

    status = mp4writer->setCaptureRate(kDefaultFPS);
    ASSERT_EQ((status_t)OK, status) << "setCaptureRate failed";

    status = mWriter->start(mFileMeta.get());
    ASSERT_EQ((status_t)OK, status) << "Could not start the writer";

    status = sendBuffersToWriter(mInputStream[0], mBufferInfo[0], mInputFrameId[0],
                                 mCurrentTrack[0], 0, mBufferInfo[0].size());
    ASSERT_EQ((status_t)OK, status) << "mpeg4 writer failed";

    status = mCurrentTrack[0]->stop();
    ASSERT_EQ((status_t)OK, status) << "Failed to stop the track";

    status = mWriter->stop();
    ASSERT_EQ((status_t)OK, status) << "Failed to stop the writer";
    mp4writer.clear();
    close(fd);
}

class ListenerTest
    : public WriterTest,
      public ::testing::TestWithParam<tuple<
              string /* writerFormat*/, inputId /* inputId0*/, inputId /* inputId1*/,
              float /* FileSizeLimit*/, float /* FileDurationLimit*/, float /* BufferInterval*/>> {
  public:
    virtual void SetUp() override { setupWriterType(get<0>(GetParam())); }
};

TEST_P(ListenerTest, SetMaxFileLimitsTest) {
    // TODO(b/151892414): Enable test for other writers
    if (mDisableTest || mWriterName != MPEG4) return;
    ALOGV("Validates writer when max file limits are set");

    string writerFormat = get<0>(GetParam());
    string outputFile = OUTPUT_FILE_NAME;
    int32_t fd =
            open(outputFile.c_str(), O_CREAT | O_LARGEFILE | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0) << "Failed to open output file to dump writer's data";

    int32_t status = createWriter(fd);
    ASSERT_EQ((status_t)OK, status) << "Failed to create writer for output format:" << writerFormat;

    inputId inpId[] = {get<1>(GetParam()), get<2>(GetParam())};
    ASSERT_NE(inpId[0], UNUSED_ID) << "Test expects first inputId to be a valid id";

    size_t inputFileSize = 0;
    int64_t lastFrameTimeStampUs = INT_MAX;
    int32_t numTracks = 1;
    if (inpId[1] != UNUSED_ID) {
        numTracks++;
    }
    for (int32_t idx = 0; idx < numTracks; idx++) {
        string inputFile = gEnv->getRes();
        string inputInfo = gEnv->getRes();
        configFormat param;
        bool isAudio;
        getFileDetails(inputFile, inputInfo, param, isAudio, inpId[idx]);
        ASSERT_NE(inputFile.compare(gEnv->getRes()), 0) << "No input file specified";

        ASSERT_NO_FATAL_FAILURE(getInputBufferInfo(inputFile, inputInfo, idx));
        status = addWriterSource(isAudio, param, idx);
        ASSERT_EQ((status_t)OK, status) << "Failed to add source for " << writerFormat << "Writer";

        // Read file properties
        struct stat buf;
        status = stat(inputFile.c_str(), &buf);
        ASSERT_EQ(0, status);

        inputFileSize += buf.st_size;
        if (lastFrameTimeStampUs > mBufferInfo[idx][mBufferInfo[idx].size() - 1].timeUs) {
            lastFrameTimeStampUs = mBufferInfo[idx][mBufferInfo[idx].size() - 1].timeUs;
        }
    }

    float fileSizeLimit = get<3>(GetParam());
    float fileDurationLimit = get<4>(GetParam());
    int64_t maxFileSize = 0;
    int64_t maxFileDuration = 0;
    if (fileSizeLimit > 0) {
        maxFileSize = (int64_t)(fileSizeLimit * inputFileSize);
        mWriter->setMaxFileSize(maxFileSize);
    }
    if (fileDurationLimit > 0) {
        maxFileDuration = (int64_t)(fileDurationLimit * lastFrameTimeStampUs);
        mWriter->setMaxFileDuration(maxFileDuration);
    }

    sp<WriterListener> listener = new WriterListener();
    ASSERT_NE(listener, nullptr) << "unable to allocate listener";

    mWriter->setListener(listener);
    status = mWriter->start(mFileMeta.get());
    ASSERT_EQ((status_t)OK, status);

    float interval = get<5>(GetParam());
    ASSERT_LE(interval, 1.0f) << "Buffer interval invalid. Should be less than or equal to 1.0";

    size_t range = 0;
    int32_t loopCount = 0;
    int32_t offset[kMaxTrackCount]{};
    while (loopCount < ceil(1.0 / interval)) {
        for (int32_t idx = 0; idx < numTracks; idx++) {
            range = mBufferInfo[idx].size() * interval;
            status = sendBuffersToWriter(mInputStream[idx], mBufferInfo[idx], mInputFrameId[idx],
                                         mCurrentTrack[idx], offset[idx], range, false, listener);
            ASSERT_EQ((status_t)OK, status) << writerFormat << " writer failed";
            offset[idx] += range;
        }
        loopCount++;
    }

    ASSERT_TRUE(mWriter->reachedEOS()) << "EOS not signalled.";

    for (int32_t idx = 0; idx < kMaxTrackCount; idx++) {
        if (mCurrentTrack[idx]) {
            mCurrentTrack[idx]->stop();
        }
    }

    status = mWriter->stop();
    ASSERT_EQ((status_t)OK, status) << "Failed to stop the writer";
    close(fd);

    if (maxFileSize <= 0) {
        ASSERT_FALSE(listener->mSignaledSize);
    } else if (maxFileDuration <= 0) {
        ASSERT_FALSE(listener->mSignaledDuration);
    } else if (maxFileSize > 0 && maxFileDuration <= 0) {
        ASSERT_TRUE(listener->mSignaledSize);
    } else if (maxFileDuration > 0 && maxFileSize <= 0) {
        ASSERT_TRUE(listener->mSignaledDuration);
    } else {
        ASSERT_TRUE(listener->mSignaledSize || listener->mSignaledDuration);
    }

    if (maxFileSize > 0) {
        struct stat buf;
        status = stat(outputFile.c_str(), &buf);
        ASSERT_EQ(0, status);
        ASSERT_LE(buf.st_size, maxFileSize);
    }
}

// TODO: (b/150923387)
// Add WEBM input
INSTANTIATE_TEST_SUITE_P(ListenerTestAll, ListenerTest,
                         ::testing::Values(make_tuple("aac", AAC_1, UNUSED_ID, 0.6, 0.7, 1),
                                           make_tuple("amrnb", AMR_NB_1, UNUSED_ID, 0.2, 0.6, 1),
                                           make_tuple("amrwb", AMR_WB_1, UNUSED_ID, 0.5, 0.5, 1),
                                           make_tuple("mpeg2Ts", AAC_1, UNUSED_ID, 0.2, 1, 1),
                                           make_tuple("mpeg4", AAC_1, UNUSED_ID, 0.4, 0.3, 0.25),
                                           make_tuple("mpeg4", AAC_1, UNUSED_ID, 0.3, 1, 0.5),
                                           make_tuple("ogg", OPUS_1, UNUSED_ID, 0.7, 0.3, 1)));

// TODO: (b/144476164)
// Add AAC_ADTS, FLAC, AV1 input
INSTANTIATE_TEST_SUITE_P(
        WriterTestAll, WriteFunctionalityTest,
        ::testing::Values(
                make_tuple("aac", AAC_1, UNUSED_ID, 1),

                make_tuple("amrnb", AMR_NB_1, UNUSED_ID, 1),
                make_tuple("amrwb", AMR_WB_1, UNUSED_ID, 1),

                // TODO(b/144902018): Enable test for mpeg2ts
                // make_tuple("mpeg2Ts", AAC_1, UNUSED_ID, 1),
                // make_tuple("mpeg2Ts", AVC_1, UNUSED_ID, 1),
                // TODO(b/156355857): Add multitrack for mpeg2ts
                // make_tuple("mpeg2Ts", AAC_1, AVC_1, 0.50),
                // make_tuple("mpeg2Ts", AVC_1, AAC_1, 0.25),

                make_tuple("mpeg4", AAC_1, UNUSED_ID, 1),
                make_tuple("mpeg4", AMR_NB_1, UNUSED_ID, 1),
                make_tuple("mpeg4", AMR_WB_1, UNUSED_ID, 1),
                make_tuple("mpeg4", AVC_1, UNUSED_ID, 1),
                make_tuple("mpeg4", H263_1, UNUSED_ID, 1),
                make_tuple("mpeg4", HEIC_1, UNUSED_ID, 1),
                make_tuple("mpeg4", HEVC_1, UNUSED_ID, 1),
                make_tuple("mpeg4", MPEG4_1, UNUSED_ID, 1),
                make_tuple("mpeg4", AAC_1, AVC_1, 0.25),
                make_tuple("mpeg4", AVC_1, AAC_1, 0.75),
                make_tuple("mpeg4", AMR_WB_1, AAC_1, 0.75),
                make_tuple("mpeg4", HEVC_1, AMR_WB_1, 0.25),
                make_tuple("mpeg4", H263_1, AMR_NB_1, 0.50),
                make_tuple("mpeg4", MPEG4_1, AAC_1, 0.75),
                make_tuple("mpeg4", AMR_NB_1, AMR_WB_1, 0.25),
                make_tuple("mpeg4", H263_1, AMR_NB_1, 0.50),
                make_tuple("mpeg4", MPEG4_1, HEVC_1, 0.75),

                make_tuple("ogg", OPUS_1, UNUSED_ID, 1),

                make_tuple("webm", OPUS_1, UNUSED_ID, 1),
                make_tuple("webm", VORBIS_1, UNUSED_ID, 1),
                make_tuple("webm", VP8_1, UNUSED_ID, 1),
                make_tuple("webm", VP9_1, UNUSED_ID, 1),
                make_tuple("webm", VP8_1, OPUS_1, 0.50),
                make_tuple("webm", VORBIS_1, VP8_1, 0.25)));

INSTANTIATE_TEST_SUITE_P(
        WriterValidityTest, WriterValidityTest,
        ::testing::Values(
                make_tuple("aac", AAC_1, true),

                make_tuple("amrnb", AMR_NB_1, true),
                make_tuple("amrwb", AMR_WB_1, true),

                make_tuple("mpeg4", AAC_1, false),
                make_tuple("mpeg4", AMR_NB_1, false),
                make_tuple("mpeg4", AVC_1, false),
                make_tuple("mpeg4", H263_1, false),
                make_tuple("mpeg4", HEIC_1, false),
                make_tuple("mpeg4", HEVC_1, false),
                make_tuple("mpeg4", MPEG4_1, false),

                make_tuple("ogg", OPUS_1, true),

                make_tuple("webm", OPUS_1, false),
                make_tuple("webm", VORBIS_1, true),
                make_tuple("webm", VP8_1, false),
                make_tuple("webm", VP9_1, false)));

int main(int argc, char **argv) {
    ProcessState::self()->startThreadPool();
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
