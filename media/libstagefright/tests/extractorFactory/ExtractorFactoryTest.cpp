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
#define LOG_TAG "ExtractorFactoryTest"
#include <utils/Log.h>

#include <binder/ProcessState.h>

#include <datasource/FileSource.h>
#include <media/stagefright/MediaExtractorFactory.h>
#include <media/stagefright/foundation/MediaDefs.h>

#include "ExtractorFactoryTestEnvironment.h"

#define OUTPUT_FILE_NAME "/data/local/tmp/exFactoryLogs"

using namespace android;

static ExtractorFactoryTestEnvironment *gEnv = nullptr;

class ExtractorFactoryTest : public ::testing::TestWithParam<pair<string, string>> {
  public:
    ExtractorFactoryTest() : mDataSource(nullptr), mExtractor(nullptr) {}

    ~ExtractorFactoryTest() {
        if (mDataSource) {
            mDataSource.clear();
            mDataSource = nullptr;
        }
        if (mExtractor) {
            mExtractor.clear();
            mExtractor = nullptr;
        }
    }

    int32_t createDataSource(string inputFileName);
    int32_t createExtractor(bool createFromService, string inputMime);

    sp<DataSource> mDataSource;
    sp<IMediaExtractor> mExtractor;
};

int32_t ExtractorFactoryTest::createDataSource(string inputFileName) {
    FILE *mInputFp = fopen(inputFileName.c_str(), "rb");
    if (!mInputFp) {
        ALOGE("Unable to open input file : %s for reading", inputFileName.c_str());
        return -1;
    }
    struct stat buf;
    int32_t status = stat(inputFileName.c_str(), &buf);
    if (status != 0) {
        ALOGE("Failed to read file properties for input file : %s", inputFileName.c_str());
        return -1;
    }
    int32_t fd = fileno(mInputFp);
    if (fd < 0) {
        ALOGE("Invalid file descriptor for input file : %s", inputFileName.c_str());
        return -1;
    }
    mDataSource = new FileSource(dup(fd), 0, buf.st_size);
    if (!mDataSource) return -1;
    return 0;
}

int32_t ExtractorFactoryTest::createExtractor(bool createFromService, string inputMime) {
    ALOGV("Creating extractor for mime : %s", inputMime.c_str());
    if (createFromService) {
        mExtractor = MediaExtractorFactory::CreateFromService(mDataSource, inputMime.c_str());
    } else {
        mExtractor = MediaExtractorFactory::Create(mDataSource);
    }
    if (mExtractor == nullptr) return -1;
    return 0;
}

TEST_F(ExtractorFactoryTest, ListExtractorsTest) {
    MediaExtractorFactory::LoadExtractors();
    vector<std::string> supportedTypes = MediaExtractorFactory::getSupportedTypes();
    ASSERT_GT(supportedTypes.size(), 0) << " MediaExtractorFactory doesn't suuport any extractor";

    FILE *outputLog = fopen(OUTPUT_FILE_NAME, "wb");
    ASSERT_NE(outputLog, nullptr) << "Unable to open output file - " << OUTPUT_FILE_NAME
                                  << " for writing";

    int32_t fd = fileno(outputLog);
    ASSERT_GE(fd, 0);

    Vector<String16> args;
    int32_t status = MediaExtractorFactory::dump(fd, args);
    ASSERT_EQ(status, OK) << "MediaExtractorFactory dump failed";
    fclose(outputLog);
}

TEST_P(ExtractorFactoryTest, ExtractorFactoryApiTest) {
    string inputMime = GetParam().second;
    string inputFileName = gEnv->getRes() + GetParam().first;

    MediaExtractorFactory::LoadExtractors();
    bool createMode[] = {true, false};
    for (bool createFromService : createMode) {
        int32_t status = createDataSource(inputFileName);
        ASSERT_EQ(status, 0) << "create data source failed";

        status = createExtractor(createFromService, inputMime);
        ASSERT_EQ(status, 0) << "Extractor creation failed for input: " << inputFileName;

        int32_t numTracks = mExtractor->countTracks();
        ASSERT_GT(numTracks, 0) << "Extractor didn't find any track for the given clip";

        sp<MetaData> meta = mExtractor->getMetaData();
        ASSERT_NE(meta, nullptr) << "getMetaData returned null";

        const char *mime;
        bool valueFound = meta->findCString(kKeyMIMEType, &mime);
        ASSERT_TRUE(valueFound) << "Extractor did not provide MIME type";
        ASSERT_EQ(mime, inputMime) << "Extractor factory returned invalid mime type";
        mExtractor.clear();
        mDataSource.clear();
    }
}

// TODO: (b/150111966)
// Replace mime strings with appropriate definitions
INSTANTIATE_TEST_SUITE_P(
        ExtractorFactoryTestAll, ExtractorFactoryTest,
        ::testing::Values(make_pair("loudsoftaac.aac", MEDIA_MIMETYPE_AUDIO_AAC_ADTS),
                          make_pair("testamr.amr", "audio/amr"),
                          make_pair("amrwb.wav", MEDIA_MIMETYPE_AUDIO_AMR_WB),
                          make_pair("john_cage.ogg", MEDIA_MIMETYPE_CONTAINER_OGG),
                          make_pair("monotestgsm.wav", MEDIA_MIMETYPE_CONTAINER_WAV),
                          make_pair("segment000001.ts", MEDIA_MIMETYPE_CONTAINER_MPEG2TS),
                          make_pair("sinesweepflac.flac", MEDIA_MIMETYPE_AUDIO_FLAC),
                          make_pair("testopus.opus", MEDIA_MIMETYPE_CONTAINER_OGG),
                          make_pair("midi_a.mid", MEDIA_MIMETYPE_AUDIO_MIDI),
                          make_pair("sinesweepvorbis.mkv", MEDIA_MIMETYPE_CONTAINER_MATROSKA),
                          make_pair("sinesweepoggmp4.mp4", "audio/mp4"),
                          make_pair("sinesweepmp3lame.mp3", MEDIA_MIMETYPE_AUDIO_MPEG),
                          make_pair("swirl_144x136_vp9.webm", "video/webm"),
                          make_pair("swirl_144x136_vp8.webm", "video/webm"),
                          make_pair("swirl_132x130_mpeg4.mp4", MEDIA_MIMETYPE_CONTAINER_MPEG4)));

int main(int argc, char **argv) {
    ProcessState::self()->startThreadPool();
    gEnv = new ExtractorFactoryTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
