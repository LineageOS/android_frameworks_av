/*
 * Copyright (C) 2018 The Android Open Source Project
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

// #define LOG_NDEBUG 0
#define LOG_TAG "codec2_hidl_hal_audio_dec_test"

#include <android-base/logging.h>
#include <gtest/gtest.h>
#include <hidl/GtestPrinter.h>
#include <stdio.h>
#include <algorithm>

#include <C2AllocatorIon.h>
#include <C2Buffer.h>
#include <C2BufferPriv.h>
#include <C2Config.h>
#include <C2Debug.h>
#include <codec2/hidl/client.h>

using android::C2AllocatorIon;

#include "media_c2_hidl_test_common.h"

static std::vector<std::tuple<std::string, std::string, std::string, std::string>>
        kDecodeTestParameters;

static std::vector<std::tuple<std::string, std::string, std::string>> kCsdFlushTestParameters;

// Resource directory
static std::string sResourceDir = "";

class LinearBuffer : public C2Buffer {
  public:
    explicit LinearBuffer(const std::shared_ptr<C2LinearBlock>& block)
        : C2Buffer({block->share(block->offset(), block->size(), ::C2Fence())}) {}
};

namespace {

class Codec2AudioDecHidlTestBase : public ::testing::Test {
  public:
    // google.codec2 Audio test setup
    virtual void SetUp() override {
        getParams();
        mDisableTest = false;
        ALOGV("Codec2AudioDecHidlTest SetUp");
        mClient = android::Codec2Client::CreateFromService(
                mInstanceName.c_str(),
                !bool(android::Codec2Client::CreateFromService("default", true)));
        ASSERT_NE(mClient, nullptr);
        mListener.reset(new CodecListener([this](std::list<std::unique_ptr<C2Work>>& workItems) {
            handleWorkDone(workItems);
        }));
        ASSERT_NE(mListener, nullptr);
        for (int i = 0; i < MAX_INPUT_BUFFERS; ++i) {
            mWorkQueue.emplace_back(new C2Work);
        }
        mClient->createComponent(mComponentName, mListener, &mComponent);
        ASSERT_NE(mComponent, nullptr);

        std::shared_ptr<C2AllocatorStore> store = android::GetCodec2PlatformAllocatorStore();
        CHECK_EQ(store->fetchAllocator(C2AllocatorStore::DEFAULT_LINEAR, &mLinearAllocator), C2_OK);
        mLinearPool = std::make_shared<C2PooledBlockPool>(mLinearAllocator, mBlockPoolId++);
        ASSERT_NE(mLinearPool, nullptr);

        mCompName = unknown_comp;
        struct StringToName {
            const char* Name;
            standardComp CompName;
        };
        const StringToName kStringToName[] = {
                {"xaac", xaac},          {"mp3", mp3}, {"amrnb", amrnb},
                {"amrwb", amrwb},        {"aac", aac}, {"vorbis", vorbis},
                {"opus", opus},          {"pcm", pcm}, {"g711.alaw", g711alaw},
                {"g711.mlaw", g711mlaw}, {"gsm", gsm}, {"raw", raw},
                {"flac", flac},
        };
        const size_t kNumStringToName = sizeof(kStringToName) / sizeof(kStringToName[0]);

        // Find the component type
        for (size_t i = 0; i < kNumStringToName; ++i) {
            if (strcasestr(mComponentName.c_str(), kStringToName[i].Name)) {
                mCompName = kStringToName[i].CompName;
                break;
            }
        }
        mEos = false;
        mFramesReceived = 0;
        mTimestampUs = 0u;
        mWorkResult = C2_OK;
        mTimestampDevTest = false;
        if (mCompName == unknown_comp) mDisableTest = true;
        if (mDisableTest) std::cout << "[   WARN   ] Test Disabled \n";
    }

    virtual void TearDown() override {
        if (mComponent != nullptr) {
            if (::testing::Test::HasFatalFailure()) return;
            mComponent->release();
            mComponent = nullptr;
        }
    }

    // Get the test parameters from GetParam call.
    virtual void getParams() {}

    virtual void validateTimestampList(int32_t* bitStreamInfo);

    struct outputMetaData {
        uint64_t timestampUs;
        uint32_t rangeLength;
    };
    // callback function to process onWorkDone received by Listener
    void handleWorkDone(std::list<std::unique_ptr<C2Work>>& workItems) {
        for (std::unique_ptr<C2Work>& work : workItems) {
            if (!work->worklets.empty()) {
                // For decoder components current timestamp always exceeds
                // previous timestamp
                mWorkResult |= work->result;
                bool codecConfig = ((work->worklets.front()->output.flags &
                                     C2FrameData::FLAG_CODEC_CONFIG) != 0);
                if (!codecConfig && !work->worklets.front()->output.buffers.empty()) {
                    EXPECT_GE(work->worklets.front()->output.ordinal.timestamp.peeku(),
                              mTimestampUs);
                    mTimestampUs = work->worklets.front()->output.ordinal.timestamp.peeku();
                    uint32_t rangeLength = work->worklets.front()
                                                   ->output.buffers[0]
                                                   ->data()
                                                   .linearBlocks()
                                                   .front()
                                                   .map()
                                                   .get()
                                                   .capacity();
                    // List of timestamp values and output size to calculate timestamp
                    if (mTimestampDevTest) {
                        outputMetaData meta = {mTimestampUs, rangeLength};
                        oBufferMetaData.push_back(meta);
                    }
                }
                bool mCsd = false;
                workDone(mComponent, work, mFlushedIndices, mQueueLock, mQueueCondition, mWorkQueue,
                         mEos, mCsd, mFramesReceived);
                (void)mCsd;
            }
        }
    }

    enum standardComp {
        xaac,
        mp3,
        amrnb,
        amrwb,
        aac,
        vorbis,
        opus,
        pcm,
        g711alaw,
        g711mlaw,
        gsm,
        raw,
        flac,
        unknown_comp,
    };

    std::string mInstanceName;
    std::string mComponentName;
    bool mEos;
    bool mDisableTest;
    bool mTimestampDevTest;
    standardComp mCompName;

    int32_t mWorkResult;
    uint64_t mTimestampUs;
    uint32_t mFramesReceived;
    std::list<uint64_t> mFlushedIndices;
    std::list<uint64_t> mTimestampUslist;
    std::list<outputMetaData> oBufferMetaData;

    C2BlockPool::local_id_t mBlockPoolId;
    std::shared_ptr<C2BlockPool> mLinearPool;
    std::shared_ptr<C2Allocator> mLinearAllocator;

    std::mutex mQueueLock;
    std::condition_variable mQueueCondition;
    std::list<std::unique_ptr<C2Work>> mWorkQueue;

    std::shared_ptr<android::Codec2Client> mClient;
    std::shared_ptr<android::Codec2Client::Listener> mListener;
    std::shared_ptr<android::Codec2Client::Component> mComponent;

  protected:
    static void description(const std::string& description) {
        RecordProperty("description", description);
    }
};

class Codec2AudioDecHidlTest
    : public Codec2AudioDecHidlTestBase,
      public ::testing::WithParamInterface<std::tuple<std::string, std::string>> {
    void getParams() {
        mInstanceName = std::get<0>(GetParam());
        mComponentName = std::get<1>(GetParam());
    }
};

void validateComponent(const std::shared_ptr<android::Codec2Client::Component>& component,
                       Codec2AudioDecHidlTest::standardComp compName, bool& disableTest) {
    // Validate its a C2 Component
    if (component->getName().find("c2") == std::string::npos) {
        ALOGE("Not a c2 component");
        disableTest = true;
        return;
    }

    // Validate its not an encoder and the component to be tested is audio
    if (component->getName().find("encoder") != std::string::npos) {
        ALOGE("Expected Decoder, given Encoder");
        disableTest = true;
        return;
    }
    std::vector<std::unique_ptr<C2Param>> queried;
    c2_status_t c2err = component->query({}, {C2PortMediaTypeSetting::input::PARAM_TYPE},
                                         C2_DONT_BLOCK, &queried);
    if (c2err != C2_OK && queried.size() == 0) {
        ALOGE("Query media type failed => %d", c2err);
    } else {
        std::string inputDomain = ((C2StreamMediaTypeSetting::input*)queried[0].get())->m.value;
        if (inputDomain.find("audio/") == std::string::npos) {
            ALOGE("Expected Audio Component");
            disableTest = true;
            return;
        }
    }

    // Validates component name
    if (compName == Codec2AudioDecHidlTest::unknown_comp) {
        ALOGE("Component InValid");
        disableTest = true;
        return;
    }
    ALOGV("Component Valid");
}

// Set Default config param.
bool setupConfigParam(const std::shared_ptr<android::Codec2Client::Component>& component,
                      int32_t* bitStreamInfo) {
    std::vector<std::unique_ptr<C2SettingResult>> failures;
    C2StreamSampleRateInfo::output sampleRateInfo(0u, bitStreamInfo[0]);
    C2StreamChannelCountInfo::output channelCountInfo(0u, bitStreamInfo[1]);

    std::vector<C2Param*> configParam{&sampleRateInfo, &channelCountInfo};
    c2_status_t status = component->config(configParam, C2_DONT_BLOCK, &failures);
    if (status == C2_OK && failures.size() == 0u) return true;
    return false;
}

// In decoder components, often the input parameters get updated upon
// parsing the header of elementary stream. Client needs to collect this
// information and reconfigure
void getInputChannelInfo(const std::shared_ptr<android::Codec2Client::Component>& component,
                         Codec2AudioDecHidlTest::standardComp compName, int32_t* bitStreamInfo) {
    // query nSampleRate and nChannels
    std::initializer_list<C2Param::Index> indices{
            C2StreamSampleRateInfo::output::PARAM_TYPE,
            C2StreamChannelCountInfo::output::PARAM_TYPE,
    };
    std::vector<std::unique_ptr<C2Param>> inParams;
    c2_status_t status = component->query({}, indices, C2_DONT_BLOCK, &inParams);
    if (status != C2_OK && inParams.size() == 0) {
        ALOGE("Query media type failed => %d", status);
        ASSERT_TRUE(false);
    } else {
        size_t offset = sizeof(C2Param);
        for (size_t i = 0; i < inParams.size(); ++i) {
            C2Param* param = inParams[i].get();
            bitStreamInfo[i] = *(int32_t*)((uint8_t*)param + offset);
        }
        switch (compName) {
            case Codec2AudioDecHidlTest::amrnb: {
                ASSERT_EQ(bitStreamInfo[0], 8000);
                ASSERT_EQ(bitStreamInfo[1], 1);
                break;
            }
            case Codec2AudioDecHidlTest::amrwb: {
                ASSERT_EQ(bitStreamInfo[0], 16000);
                ASSERT_EQ(bitStreamInfo[1], 1);
                break;
            }
            case Codec2AudioDecHidlTest::gsm: {
                ASSERT_EQ(bitStreamInfo[0], 8000);
                break;
            }
            default:
                break;
        }
    }
}

// number of elementary streams per component
#define STREAM_COUNT 2

// LookUpTable of clips and metadata for component testing
void GetURLForComponent(Codec2AudioDecHidlTest::standardComp comp, char* mURL, char* info,
                        size_t streamIndex = 0) {
    struct CompToURL {
        Codec2AudioDecHidlTest::standardComp comp;
        const char mURL[STREAM_COUNT][512];
        const char info[STREAM_COUNT][512];
    };
    ASSERT_TRUE(streamIndex < STREAM_COUNT);

    static const CompToURL kCompToURL[] = {
            {Codec2AudioDecHidlTest::standardComp::xaac,
             {"bbb_aac_stereo_128kbps_48000hz.aac", "bbb_aac_stereo_128kbps_48000hz.aac"},
             {"bbb_aac_stereo_128kbps_48000hz.info",
              "bbb_aac_stereo_128kbps_48000hz_multi_frame.info"}},
            {Codec2AudioDecHidlTest::standardComp::mp3,
             {"bbb_mp3_stereo_192kbps_48000hz.mp3", "bbb_mp3_stereo_192kbps_48000hz.mp3"},
             {"bbb_mp3_stereo_192kbps_48000hz.info",
              "bbb_mp3_stereo_192kbps_48000hz_multi_frame.info"}},
            {Codec2AudioDecHidlTest::standardComp::aac,
             {"bbb_aac_stereo_128kbps_48000hz.aac", "bbb_aac_stereo_128kbps_48000hz.aac"},
             {"bbb_aac_stereo_128kbps_48000hz.info",
              "bbb_aac_stereo_128kbps_48000hz_multi_frame.info"}},
            {Codec2AudioDecHidlTest::standardComp::amrnb,
             {"sine_amrnb_1ch_12kbps_8000hz.amrnb", "sine_amrnb_1ch_12kbps_8000hz.amrnb"},
             {"sine_amrnb_1ch_12kbps_8000hz.info",
              "sine_amrnb_1ch_12kbps_8000hz_multi_frame.info"}},
            {Codec2AudioDecHidlTest::standardComp::amrwb,
             {"bbb_amrwb_1ch_14kbps_16000hz.amrwb", "bbb_amrwb_1ch_14kbps_16000hz.amrwb"},
             {"bbb_amrwb_1ch_14kbps_16000hz.info",
              "bbb_amrwb_1ch_14kbps_16000hz_multi_frame.info"}},
            {Codec2AudioDecHidlTest::standardComp::vorbis,
             {"bbb_vorbis_stereo_128kbps_48000hz.vorbis", ""},
             {"bbb_vorbis_stereo_128kbps_48000hz.info", ""}},
            {Codec2AudioDecHidlTest::standardComp::opus,
             {"bbb_opus_stereo_128kbps_48000hz.opus", ""},
             {"bbb_opus_stereo_128kbps_48000hz.info", ""}},
            {Codec2AudioDecHidlTest::standardComp::g711alaw,
             {"bbb_g711alaw_1ch_8khz.raw", ""},
             {"bbb_g711alaw_1ch_8khz.info", ""}},
            {Codec2AudioDecHidlTest::standardComp::g711mlaw,
             {"bbb_g711mulaw_1ch_8khz.raw", ""},
             {"bbb_g711mulaw_1ch_8khz.info", ""}},
            {Codec2AudioDecHidlTest::standardComp::gsm,
             {"bbb_gsm_1ch_8khz_13kbps.raw", ""},
             {"bbb_gsm_1ch_8khz_13kbps.info", ""}},
            {Codec2AudioDecHidlTest::standardComp::raw,
             {"bbb_raw_1ch_8khz_s32le.raw", ""},
             {"bbb_raw_1ch_8khz_s32le.info", ""}},
            {Codec2AudioDecHidlTest::standardComp::flac,
             {"bbb_flac_stereo_680kbps_48000hz.flac", ""},
             {"bbb_flac_stereo_680kbps_48000hz.info", ""}},
    };

    for (size_t i = 0; i < sizeof(kCompToURL) / sizeof(kCompToURL[0]); ++i) {
        if (kCompToURL[i].comp == comp) {
            strcat(mURL, kCompToURL[i].mURL[streamIndex]);
            strcat(info, kCompToURL[i].info[streamIndex]);
            return;
        }
    }
}

void decodeNFrames(const std::shared_ptr<android::Codec2Client::Component>& component,
                   std::mutex& queueLock, std::condition_variable& queueCondition,
                   std::list<std::unique_ptr<C2Work>>& workQueue,
                   std::list<uint64_t>& flushedIndices, std::shared_ptr<C2BlockPool>& linearPool,
                   std::ifstream& eleStream, android::Vector<FrameInfo>* Info, int offset,
                   int range, bool signalEOS = true) {
    typedef std::unique_lock<std::mutex> ULock;
    int frameID = offset;
    int maxRetry = 0;
    while (1) {
        if (frameID == (int)Info->size() || frameID == (offset + range)) break;
        uint32_t flags = 0;
        std::unique_ptr<C2Work> work;
        // Prepare C2Work
        while (!work && (maxRetry < MAX_RETRY)) {
            ULock l(queueLock);
            if (!workQueue.empty()) {
                work.swap(workQueue.front());
                workQueue.pop_front();
            } else {
                queueCondition.wait_for(l, TIME_OUT);
                maxRetry++;
            }
        }
        if (!work && (maxRetry >= MAX_RETRY)) {
            ASSERT_TRUE(false) << "Wait for generating C2Work exceeded timeout";
        }
        int64_t timestamp = (*Info)[frameID].timestamp;
        if ((*Info)[frameID].flags) flags = 1u << ((*Info)[frameID].flags - 1);
        if (signalEOS && ((frameID == (int)Info->size() - 1) || (frameID == (offset + range - 1))))
            flags |= C2FrameData::FLAG_END_OF_STREAM;

        work->input.flags = (C2FrameData::flags_t)flags;
        work->input.ordinal.timestamp = timestamp;
        work->input.ordinal.frameIndex = frameID;
        {
            ULock l(queueLock);
            flushedIndices.emplace_back(frameID);
        }
        int size = (*Info)[frameID].bytesCount;
        char* data = (char*)malloc(size);
        ASSERT_NE(data, nullptr);

        eleStream.read(data, size);
        ASSERT_EQ(eleStream.gcount(), size);

        work->input.buffers.clear();
        if (size) {
            std::shared_ptr<C2LinearBlock> block;
            ASSERT_EQ(C2_OK,
                      linearPool->fetchLinearBlock(
                              size, {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE}, &block));
            ASSERT_TRUE(block);

            // Write View
            C2WriteView view = block->map().get();
            if (view.error() != C2_OK) {
                fprintf(stderr, "C2LinearBlock::map() failed : %d", view.error());
                break;
            }
            ASSERT_EQ((size_t)size, view.capacity());
            ASSERT_EQ(0u, view.offset());
            ASSERT_EQ((size_t)size, view.size());

            memcpy(view.base(), data, size);

            work->input.buffers.emplace_back(new LinearBuffer(block));
            free(data);
        }
        work->worklets.clear();
        work->worklets.emplace_back(new C2Worklet);

        std::list<std::unique_ptr<C2Work>> items;
        items.push_back(std::move(work));

        // DO THE DECODING
        ASSERT_EQ(component->queue(&items), C2_OK);
        ALOGV("Frame #%d size = %d queued", frameID, size);
        frameID++;
        maxRetry = 0;
    }
}

void Codec2AudioDecHidlTestBase::validateTimestampList(int32_t* bitStreamInfo) {
    uint32_t samplesReceived = 0;
    // Update SampleRate and ChannelCount
    ASSERT_NO_FATAL_FAILURE(getInputChannelInfo(mComponent, mCompName, bitStreamInfo));
    int32_t nSampleRate = bitStreamInfo[0];
    int32_t nChannels = bitStreamInfo[1];
    std::list<uint64_t>::iterator itIn = mTimestampUslist.begin();
    auto itOut = oBufferMetaData.begin();
    EXPECT_EQ(*itIn, itOut->timestampUs);
    uint64_t expectedTimeStamp = *itIn;
    while (itOut != oBufferMetaData.end()) {
        EXPECT_EQ(expectedTimeStamp, itOut->timestampUs);
        if (expectedTimeStamp != itOut->timestampUs) break;
        // buffer samples = ((total bytes) / (ac * (bits per sample / 8))
        samplesReceived += ((itOut->rangeLength) / (nChannels * 2));
        expectedTimeStamp = samplesReceived * 1000000ll / nSampleRate;
        itOut++;
    }
    itIn = mTimestampUslist.end();
    --itIn;
    EXPECT_GT(expectedTimeStamp, *itIn);
    oBufferMetaData.clear();
    mTimestampUslist.clear();
}

TEST_P(Codec2AudioDecHidlTest, validateCompName) {
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";
    ALOGV("Checks if the given component is a valid audio component");
    validateComponent(mComponent, mCompName, mDisableTest);
    ASSERT_EQ(mDisableTest, false);
}

TEST_P(Codec2AudioDecHidlTest, configComp) {
    description("Tests component specific configuration");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";
    ASSERT_EQ(mComponent->start(), C2_OK);
    int32_t bitStreamInfo[2] = {0};
    ASSERT_NO_FATAL_FAILURE(getInputChannelInfo(mComponent, mCompName, bitStreamInfo));
    setupConfigParam(mComponent, bitStreamInfo);
    ASSERT_EQ(mComponent->stop(), C2_OK);
}

class Codec2AudioDecDecodeTest
    : public Codec2AudioDecHidlTestBase,
      public ::testing::WithParamInterface<
              std::tuple<std::string, std::string, std::string, std::string>> {
    void getParams() {
        mInstanceName = std::get<0>(GetParam());
        mComponentName = std::get<1>(GetParam());
    }
};

TEST_P(Codec2AudioDecDecodeTest, DecodeTest) {
    description("Decodes input file");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    uint32_t streamIndex = std::stoi(std::get<2>(GetParam()));
    ;
    bool signalEOS = !std::get<3>(GetParam()).compare("true");
    mTimestampDevTest = true;
    char mURL[512], info[512];
    android::Vector<FrameInfo> Info;

    strcpy(mURL, sResourceDir.c_str());
    strcpy(info, sResourceDir.c_str());
    GetURLForComponent(mCompName, mURL, info, streamIndex);
    if (!strcmp(mURL, sResourceDir.c_str())) {
        ALOGV("EMPTY INPUT sResourceDir.c_str() %s mURL  %s ", sResourceDir.c_str(), mURL);
        return;
    }

    int32_t numCsds = populateInfoVector(info, &Info, mTimestampDevTest, &mTimestampUslist);
    ASSERT_GE(numCsds, 0) << "Error in parsing input info file: " << info;

    // Reset total no of frames received
    mFramesReceived = 0;
    mTimestampUs = 0;
    int32_t bitStreamInfo[2] = {0};
    if (mCompName == raw) {
        bitStreamInfo[0] = 8000;
        bitStreamInfo[1] = 1;
    } else {
        ASSERT_NO_FATAL_FAILURE(getInputChannelInfo(mComponent, mCompName, bitStreamInfo));
    }
    if (!setupConfigParam(mComponent, bitStreamInfo)) {
        std::cout << "[   WARN   ] Test Skipped \n";
        return;
    }
    ASSERT_EQ(mComponent->start(), C2_OK);
    ALOGV("mURL : %s", mURL);
    std::ifstream eleStream;
    eleStream.open(mURL, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true);
    ASSERT_NO_FATAL_FAILURE(decodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                          mFlushedIndices, mLinearPool, eleStream, &Info, 0,
                                          (int)Info.size(), signalEOS));

    // If EOS is not sent, sending empty input with EOS flag
    size_t infoSize = Info.size();
    if (!signalEOS) {
        ASSERT_NO_FATAL_FAILURE(waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue, 1));
        ASSERT_NO_FATAL_FAILURE(testInputBuffer(mComponent, mQueueLock, mWorkQueue,
                                                C2FrameData::FLAG_END_OF_STREAM, false));
        infoSize += 1;
    }
    // blocking call to ensures application to Wait till all the inputs are
    // consumed
    waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue);
    eleStream.close();
    if (mFramesReceived != infoSize) {
        ALOGE("Input buffer count and Output buffer count mismatch");
        ALOGE("framesReceived : %d inputFrames : %zu", mFramesReceived, infoSize);
        ASSERT_TRUE(false);
    }
    ASSERT_EQ(mEos, true);

    if (mTimestampDevTest) {
        validateTimestampList(bitStreamInfo);
    }
    ASSERT_EQ(mComponent->stop(), C2_OK);
    ASSERT_EQ(mWorkResult, C2_OK);
}

// thumbnail test
TEST_P(Codec2AudioDecHidlTest, ThumbnailTest) {
    description("Test Request for thumbnail");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    char mURL[512], info[512];
    android::Vector<FrameInfo> Info;

    strcpy(mURL, sResourceDir.c_str());
    strcpy(info, sResourceDir.c_str());
    GetURLForComponent(mCompName, mURL, info);

    int32_t numCsds = populateInfoVector(info, &Info, mTimestampDevTest, &mTimestampUslist);
    ASSERT_GE(numCsds, 0) << "Error in parsing input info file: " << info;

    int32_t bitStreamInfo[2] = {0};
    if (mCompName == raw) {
        bitStreamInfo[0] = 8000;
        bitStreamInfo[1] = 1;
    } else {
        ASSERT_NO_FATAL_FAILURE(getInputChannelInfo(mComponent, mCompName, bitStreamInfo));
    }
    if (!setupConfigParam(mComponent, bitStreamInfo)) {
        std::cout << "[   WARN   ] Test Skipped \n";
        return;
    }
    ASSERT_EQ(mComponent->start(), C2_OK);
    ALOGV("mURL : %s", mURL);

    // request EOS for thumbnail
    // signal EOS flag with last frame
    size_t i = -1;
    uint32_t flags;
    do {
        i++;
        flags = 0;
        if (Info[i].flags) flags = 1u << (Info[i].flags - 1);

    } while (!(flags & SYNC_FRAME));
    std::ifstream eleStream;
    eleStream.open(mURL, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true);
    ASSERT_NO_FATAL_FAILURE(decodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                          mFlushedIndices, mLinearPool, eleStream, &Info, 0,
                                          i + 1));
    waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue);
    eleStream.close();
    EXPECT_GE(mFramesReceived, 1U);
    ASSERT_EQ(mEos, true);
    ASSERT_EQ(mComponent->stop(), C2_OK);
    ASSERT_EQ(mWorkResult, C2_OK);
}

TEST_P(Codec2AudioDecHidlTest, EOSTest) {
    description("Test empty input buffer with EOS flag");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";
    typedef std::unique_lock<std::mutex> ULock;
    ASSERT_EQ(mComponent->start(), C2_OK);
    std::unique_ptr<C2Work> work;
    // Prepare C2Work
    {
        ULock l(mQueueLock);
        if (!mWorkQueue.empty()) {
            work.swap(mWorkQueue.front());
            mWorkQueue.pop_front();
        } else {
            ASSERT_TRUE(false) << "mWorkQueue Empty at the start of test";
        }
    }
    ASSERT_NE(work, nullptr);

    work->input.flags = (C2FrameData::flags_t)C2FrameData::FLAG_END_OF_STREAM;
    work->input.ordinal.timestamp = 0;
    work->input.ordinal.frameIndex = 0;
    work->input.buffers.clear();
    work->worklets.clear();
    work->worklets.emplace_back(new C2Worklet);

    std::list<std::unique_ptr<C2Work>> items;
    items.push_back(std::move(work));
    ASSERT_EQ(mComponent->queue(&items), C2_OK);

    {
        ULock l(mQueueLock);
        if (mWorkQueue.size() != MAX_INPUT_BUFFERS) {
            mQueueCondition.wait_for(l, TIME_OUT);
        }
    }
    ASSERT_EQ(mEos, true);
    ASSERT_EQ(mWorkQueue.size(), (size_t)MAX_INPUT_BUFFERS);
    ASSERT_EQ(mComponent->stop(), C2_OK);
    ASSERT_EQ(mWorkResult, C2_OK);
}

TEST_P(Codec2AudioDecHidlTest, FlushTest) {
    description("Tests Flush calls");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";
    char mURL[512], info[512];
    android::Vector<FrameInfo> Info;

    strcpy(mURL, sResourceDir.c_str());
    strcpy(info, sResourceDir.c_str());
    GetURLForComponent(mCompName, mURL, info);

    int32_t numCsds = populateInfoVector(info, &Info, mTimestampDevTest, &mTimestampUslist);
    ASSERT_GE(numCsds, 0) << "Error in parsing input info file: " << info;

    int32_t bitStreamInfo[2] = {0};
    if (mCompName == raw) {
        bitStreamInfo[0] = 8000;
        bitStreamInfo[1] = 1;
    } else {
        ASSERT_NO_FATAL_FAILURE(getInputChannelInfo(mComponent, mCompName, bitStreamInfo));
    }
    if (!setupConfigParam(mComponent, bitStreamInfo)) {
        std::cout << "[   WARN   ] Test Skipped \n";
        return;
    }
    ASSERT_EQ(mComponent->start(), C2_OK);
    // flush
    std::list<std::unique_ptr<C2Work>> flushedWork;
    c2_status_t err = mComponent->flush(C2Component::FLUSH_COMPONENT, &flushedWork);
    ASSERT_EQ(err, C2_OK);
    ASSERT_NO_FATAL_FAILURE(
            verifyFlushOutput(flushedWork, mWorkQueue, mFlushedIndices, mQueueLock));
    ASSERT_EQ(mWorkQueue.size(), MAX_INPUT_BUFFERS);

    ALOGV("mURL : %s", mURL);
    std::ifstream eleStream;
    eleStream.open(mURL, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true);
    // Decode 30 frames and flush.
    uint32_t numFramesFlushed = FLUSH_INTERVAL;
    ASSERT_NO_FATAL_FAILURE(decodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                          mFlushedIndices, mLinearPool, eleStream, &Info, 0,
                                          numFramesFlushed, false));
    // flush
    err = mComponent->flush(C2Component::FLUSH_COMPONENT, &flushedWork);
    ASSERT_EQ(err, C2_OK);
    waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue,
                           (size_t)MAX_INPUT_BUFFERS - flushedWork.size());
    ASSERT_NO_FATAL_FAILURE(
            verifyFlushOutput(flushedWork, mWorkQueue, mFlushedIndices, mQueueLock));
    ASSERT_EQ(mWorkQueue.size(), MAX_INPUT_BUFFERS);

    // Seek to next key frame and start decoding till the end
    mFlushedIndices.clear();
    int index = numFramesFlushed;
    bool keyFrame = false;
    uint32_t flags = 0;
    while (index < (int)Info.size()) {
        if (Info[index].flags) flags = 1u << (Info[index].flags - 1);
        if ((flags & SYNC_FRAME) == SYNC_FRAME) {
            keyFrame = true;
            break;
        }
        flags = 0;
        eleStream.ignore(Info[index].bytesCount);
        index++;
    }
    if (keyFrame) {
        ASSERT_NO_FATAL_FAILURE(decodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                              mFlushedIndices, mLinearPool, eleStream, &Info, index,
                                              (int)Info.size() - index));
    }
    eleStream.close();
    err = mComponent->flush(C2Component::FLUSH_COMPONENT, &flushedWork);
    ASSERT_EQ(err, C2_OK);
    waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue,
                           (size_t)MAX_INPUT_BUFFERS - flushedWork.size());
    ASSERT_NO_FATAL_FAILURE(
            verifyFlushOutput(flushedWork, mWorkQueue, mFlushedIndices, mQueueLock));
    ASSERT_EQ(mWorkQueue.size(), MAX_INPUT_BUFFERS);
    // TODO: (b/154671521)
    // Add assert for mWorkResult
    ASSERT_EQ(mComponent->stop(), C2_OK);
}

TEST_P(Codec2AudioDecHidlTest, DecodeTestEmptyBuffersInserted) {
    description("Decode with multiple empty input frames");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    char mURL[512], info[512];
    std::ifstream eleStream, eleInfo;

    strcpy(mURL, sResourceDir.c_str());
    strcpy(info, sResourceDir.c_str());
    GetURLForComponent(mCompName, mURL, info);

    eleInfo.open(info);
    ASSERT_EQ(eleInfo.is_open(), true) << mURL << " - file not found";
    android::Vector<FrameInfo> Info;
    int bytesCount = 0;
    uint32_t frameId = 0;
    uint32_t flags = 0;
    uint32_t timestamp = 0;
    bool codecConfig = false;
    // This test introduces empty CSD after every 20th frame
    // and empty input frames at an interval of 5 frames.
    while (1) {
        if (!(frameId % 5)) {
            if (!(frameId % 20))
                flags = 32;
            else
                flags = 0;
            bytesCount = 0;
        } else {
            if (!(eleInfo >> bytesCount)) break;
            eleInfo >> flags;
            eleInfo >> timestamp;
            codecConfig = flags ? ((1 << (flags - 1)) & C2FrameData::FLAG_CODEC_CONFIG) != 0 : 0;
        }
        Info.push_back({bytesCount, flags, timestamp});
        frameId++;
    }
    eleInfo.close();
    int32_t bitStreamInfo[2] = {0};
    if (mCompName == raw) {
        bitStreamInfo[0] = 8000;
        bitStreamInfo[1] = 1;
    } else {
        ASSERT_NO_FATAL_FAILURE(getInputChannelInfo(mComponent, mCompName, bitStreamInfo));
    }
    if (!setupConfigParam(mComponent, bitStreamInfo)) {
        std::cout << "[   WARN   ] Test Skipped \n";
        return;
    }
    ASSERT_EQ(mComponent->start(), C2_OK);
    ALOGV("mURL : %s", mURL);
    eleStream.open(mURL, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true);
    ASSERT_NO_FATAL_FAILURE(decodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                          mFlushedIndices, mLinearPool, eleStream, &Info, 0,
                                          (int)Info.size()));

    // blocking call to ensures application to Wait till all the inputs are
    // consumed
    if (!mEos) {
        ALOGV("Waiting for input consumption");
        waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue);
    }

    eleStream.close();
    if (mFramesReceived != Info.size()) {
        ALOGE("Input buffer count and Output buffer count mismatch");
        ALOGV("framesReceived : %d inputFrames : %zu", mFramesReceived, Info.size());
        ASSERT_TRUE(false);
    }

    ASSERT_EQ(mComponent->stop(), C2_OK);
}

class Codec2AudioDecCsdInputTests
    : public Codec2AudioDecHidlTestBase,
      public ::testing::WithParamInterface<std::tuple<std::string, std::string, std::string>> {
    void getParams() {
        mInstanceName = std::get<0>(GetParam());
        mComponentName = std::get<1>(GetParam());
    }
};

// Test the codecs for the following
// start - csd - data… - (with/without)flush - data… - flush - data…
TEST_P(Codec2AudioDecCsdInputTests, CSDFlushTest) {
    description("Tests codecs for flush at different states");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    char mURL[512], info[512];
    android::Vector<FrameInfo> Info;

    strcpy(mURL, sResourceDir.c_str());
    strcpy(info, sResourceDir.c_str());
    GetURLForComponent(mCompName, mURL, info);
    if (!strcmp(mURL, sResourceDir.c_str())) {
        ALOGV("EMPTY INPUT sResourceDir.c_str() %s mURL  %s ", sResourceDir.c_str(), mURL);
        return;
    }
    ALOGV("mURL : %s", mURL);

    int32_t numCsds = populateInfoVector(info, &Info, mTimestampDevTest, &mTimestampUslist);
    ASSERT_GE(numCsds, 0) << "Error in parsing input info file";

    int32_t bitStreamInfo[2] = {0};
    if (mCompName == raw) {
        bitStreamInfo[0] = 8000;
        bitStreamInfo[1] = 1;
    } else {
        ASSERT_NO_FATAL_FAILURE(getInputChannelInfo(mComponent, mCompName, bitStreamInfo));
    }
    if (!setupConfigParam(mComponent, bitStreamInfo)) {
        std::cout << "[   WARN   ] Test Skipped \n";
        return;
    }

    ASSERT_EQ(mComponent->start(), C2_OK);
    std::ifstream eleStream;
    eleStream.open(mURL, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true);

    bool signalEOS = false;
    bool flushCsd = !std::get<2>(GetParam()).compare("true");
    ALOGV("sending %d csd data ", numCsds);
    int framesToDecode = numCsds;
    ASSERT_NO_FATAL_FAILURE(decodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                          mFlushedIndices, mLinearPool, eleStream, &Info, 0,
                                          framesToDecode, false));

    c2_status_t err = C2_OK;
    std::list<std::unique_ptr<C2Work>> flushedWork;
    if (numCsds && flushCsd) {
        // We wait for all the CSD buffers to get consumed.
        // Once we have received all CSD work back, we call flush
        waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue);

        err = mComponent->flush(C2Component::FLUSH_COMPONENT, &flushedWork);
        ASSERT_EQ(err, C2_OK);
        waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue,
                               MAX_INPUT_BUFFERS - flushedWork.size());
        ASSERT_NO_FATAL_FAILURE(
                verifyFlushOutput(flushedWork, mWorkQueue, mFlushedIndices, mQueueLock));
        ASSERT_EQ(mWorkQueue.size(), MAX_INPUT_BUFFERS);
        oBufferMetaData.clear();
    }

    int offset = framesToDecode;
    while (1) {
        framesToDecode = c2_min(FLUSH_INTERVAL, (int)Info.size() - offset);
        if (framesToDecode < FLUSH_INTERVAL) signalEOS = true;
        ASSERT_NO_FATAL_FAILURE(decodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                              mFlushedIndices, mLinearPool, eleStream, &Info,
                                              offset, framesToDecode, signalEOS));
        offset += framesToDecode;
        err = mComponent->flush(C2Component::FLUSH_COMPONENT, &flushedWork);
        ASSERT_EQ(err, C2_OK);
        // blocking call to ensures application to Wait till remaining
        // 'non-flushed' inputs are consumed
        waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue,
                               MAX_INPUT_BUFFERS - flushedWork.size());
        ASSERT_NO_FATAL_FAILURE(
                verifyFlushOutput(flushedWork, mWorkQueue, mFlushedIndices, mQueueLock));
        ASSERT_EQ(mWorkQueue.size(), MAX_INPUT_BUFFERS);
        if (signalEOS || offset >= (int)Info.size()) {
            break;
        }
    }
    if (!signalEOS) {
        ASSERT_NO_FATAL_FAILURE(testInputBuffer(mComponent, mQueueLock, mWorkQueue,
                                                C2FrameData::FLAG_END_OF_STREAM, false));
        waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue);
    }
    eleStream.close();
    ASSERT_EQ(mWorkQueue.size(), MAX_INPUT_BUFFERS);
    ASSERT_EQ(mComponent->stop(), C2_OK);
}

INSTANTIATE_TEST_SUITE_P(PerInstance, Codec2AudioDecHidlTest, testing::ValuesIn(kTestParameters),
                         android::hardware::PrintInstanceTupleNameToString<>);

// DecodeTest with StreamIndex and EOS / No EOS
INSTANTIATE_TEST_SUITE_P(StreamIndexAndEOS, Codec2AudioDecDecodeTest,
                         testing::ValuesIn(kDecodeTestParameters),
                         android::hardware::PrintInstanceTupleNameToString<>);

INSTANTIATE_TEST_SUITE_P(CsdInputs, Codec2AudioDecCsdInputTests,
                         testing::ValuesIn(kCsdFlushTestParameters),
                         android::hardware::PrintInstanceTupleNameToString<>);

}  // anonymous namespace

int main(int argc, char** argv) {
    kTestParameters = getTestParameters(C2Component::DOMAIN_AUDIO, C2Component::KIND_DECODER);
    for (auto params : kTestParameters) {
        kDecodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "0", "false"));
        kDecodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "0", "true"));
        kDecodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "1", "false"));
        kDecodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "1", "true"));

        kCsdFlushTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "true"));
        kCsdFlushTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "false"));
    }

    // Set the resource directory based on command line args.
    // Test will fail to set up if the argument is not set.
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-P") == 0 && i < argc - 1) {
            sResourceDir = argv[i + 1];
            break;
        }
    }

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
