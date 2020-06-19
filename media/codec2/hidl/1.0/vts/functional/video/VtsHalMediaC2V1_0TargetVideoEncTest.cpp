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

//#define LOG_NDEBUG 0
#define LOG_TAG "codec2_hidl_hal_video_enc_test"

#include <android-base/logging.h>
#include <gtest/gtest.h>
#include <hidl/GtestPrinter.h>
#include <stdio.h>
#include <fstream>

#include <C2AllocatorIon.h>
#include <C2Buffer.h>
#include <C2BufferPriv.h>
#include <C2Config.h>
#include <C2Debug.h>
#include <codec2/hidl/client.h>

using android::C2AllocatorIon;

#include "media_c2_hidl_test_common.h"
#include "media_c2_video_hidl_test_common.h"

class GraphicBuffer : public C2Buffer {
  public:
    explicit GraphicBuffer(const std::shared_ptr<C2GraphicBlock>& block)
        : C2Buffer({block->share(C2Rect(block->width(), block->height()), ::C2Fence())}) {}
};

static std::vector<std::tuple<std::string, std::string, std::string, std::string, std::string>>
        kEncodeTestParameters;
static std::vector<std::tuple<std::string, std::string, std::string, std::string>>
        kEncodeResolutionTestParameters;

// Resource directory
static std::string sResourceDir = "";

namespace {

class Codec2VideoEncHidlTestBase : public ::testing::Test {
  public:
    // google.codec2 Video test setup
    virtual void SetUp() override {
        getParams();
        mDisableTest = false;
        ALOGV("Codec2VideoEncHidlTest SetUp");
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
        CHECK_EQ(store->fetchAllocator(C2AllocatorStore::DEFAULT_GRAPHIC, &mGraphicAllocator),
                 C2_OK);
        mGraphicPool = std::make_shared<C2PooledBlockPool>(mGraphicAllocator, mBlockPoolId++);
        ASSERT_NE(mGraphicPool, nullptr);

        mCompName = unknown_comp;
        struct StringToName {
            const char* Name;
            standardComp CompName;
        };

        const StringToName kStringToName[] = {
                {"h263", h263}, {"avc", avc}, {"mpeg4", mpeg4},
                {"hevc", hevc}, {"vp8", vp8}, {"vp9", vp9},
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
        mCsd = false;
        mConfigBPictures = false;
        mFramesReceived = 0;
        mFailedWorkReceived = 0;
        mTimestampUs = 0u;
        mOutputSize = 0u;
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

    bool setupConfigParam(int32_t nWidth, int32_t nHeight, int32_t nBFrame = 0);

    // callback function to process onWorkDone received by Listener
    void handleWorkDone(std::list<std::unique_ptr<C2Work>>& workItems) {
        for (std::unique_ptr<C2Work>& work : workItems) {
            if (!work->worklets.empty()) {
                // For encoder components current timestamp always exceeds
                // previous timestamp
                typedef std::unique_lock<std::mutex> ULock;
                if (!mTimestampUslist.empty()) {
                    if (!mConfigBPictures) {
                        EXPECT_GE((work->worklets.front()->output.ordinal.timestamp.peeku()),
                                  mTimestampUs);
                    }
                    mTimestampUs = work->worklets.front()->output.ordinal.timestamp.peeku();
                    // Currently this lock is redundant as no mTimestampUslist is only initialized
                    // before queuing any work to component. Once AdaptiveTest is added similar to
                    // the one in video decoders, this is needed.
                    ULock l(mQueueLock);

                    if (mTimestampDevTest) {
                        bool tsHit = false;
                        std::list<uint64_t>::iterator it = mTimestampUslist.begin();
                        while (it != mTimestampUslist.end()) {
                            if (*it == mTimestampUs) {
                                mTimestampUslist.erase(it);
                                tsHit = true;
                                break;
                            }
                            it++;
                        }
                        if (tsHit == false) {
                            if (mTimestampUslist.empty() == false) {
                                EXPECT_EQ(tsHit, true) << "TimeStamp not recognized";
                            } else {
                                std::cout << "[   INFO   ] Received non-zero "
                                             "output / TimeStamp not recognized \n";
                            }
                        }
                    }
                }

                if (work->result != C2_OK) mFailedWorkReceived++;
                if (!work->worklets.front()->output.buffers.empty()) {
                    mOutputSize += work->worklets.front()
                                           ->output.buffers[0]
                                           ->data()
                                           .linearBlocks()
                                           .front()
                                           .map()
                                           .get()
                                           .capacity();
                }
                workDone(mComponent, work, mFlushedIndices, mQueueLock, mQueueCondition, mWorkQueue,
                         mEos, mCsd, mFramesReceived);
            }
        }
    }

    enum standardComp {
        h263,
        avc,
        mpeg4,
        hevc,
        vp8,
        vp9,
        unknown_comp,
    };

    std::string mInstanceName;
    std::string mComponentName;
    bool mEos;
    bool mCsd;
    bool mDisableTest;
    bool mConfigBPictures;
    bool mTimestampDevTest;
    standardComp mCompName;
    uint32_t mFramesReceived;
    uint32_t mFailedWorkReceived;
    uint64_t mTimestampUs;
    uint64_t mOutputSize;

    std::list<uint64_t> mTimestampUslist;
    std::list<uint64_t> mFlushedIndices;

    C2BlockPool::local_id_t mBlockPoolId;
    std::shared_ptr<C2BlockPool> mGraphicPool;
    std::shared_ptr<C2Allocator> mGraphicAllocator;

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

class Codec2VideoEncHidlTest
    : public Codec2VideoEncHidlTestBase,
      public ::testing::WithParamInterface<std::tuple<std::string, std::string>> {
    void getParams() {
        mInstanceName = std::get<0>(GetParam());
        mComponentName = std::get<1>(GetParam());
    }
};

void validateComponent(const std::shared_ptr<android::Codec2Client::Component>& component,
                       Codec2VideoEncHidlTest::standardComp compName, bool& disableTest) {
    // Validate its a C2 Component
    if (component->getName().find("c2") == std::string::npos) {
        ALOGE("Not a c2 component");
        disableTest = true;
        return;
    }

    // Validate its not an encoder and the component to be tested is video
    if (component->getName().find("decoder") != std::string::npos) {
        ALOGE("Expected Encoder, given Decoder");
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
        if (inputDomain.find("video/") == std::string::npos) {
            ALOGE("Expected Video Component");
            disableTest = true;
            return;
        }
    }

    // Validates component name
    if (compName == Codec2VideoEncHidlTest::unknown_comp) {
        ALOGE("Component InValid");
        disableTest = true;
        return;
    }
    ALOGV("Component Valid");
}

// Set Default config param.
bool Codec2VideoEncHidlTestBase::setupConfigParam(int32_t nWidth, int32_t nHeight,
                                                  int32_t nBFrame) {
    c2_status_t status = C2_OK;
    std::vector<std::unique_ptr<C2Param>> configParam;
    std::vector<std::unique_ptr<C2SettingResult>> failures;

    configParam.push_back(std::make_unique<C2StreamPictureSizeInfo::input>(0u, nWidth, nHeight));

    if (nBFrame > 0) {
        std::unique_ptr<C2StreamGopTuning::output> gop =
                C2StreamGopTuning::output::AllocUnique(2 /* flexCount */, 0u /* stream */);
        gop->m.values[0] = {P_FRAME, UINT32_MAX};
        gop->m.values[1] = {C2Config::picture_type_t(P_FRAME | B_FRAME), uint32_t(nBFrame)};
        configParam.push_back(std::move(gop));
    }

    for (const std::unique_ptr<C2Param>& param : configParam) {
        status = mComponent->config({param.get()}, C2_DONT_BLOCK, &failures);
        if (status != C2_OK || failures.size() != 0u) return false;
    }
    return true;
}

// LookUpTable of clips for component testing
void GetURLForComponent(char* URL) {
    strcat(URL, "bbb_352x288_420p_30fps_32frames.yuv");
}

void encodeNFrames(const std::shared_ptr<android::Codec2Client::Component>& component,
                   std::mutex& queueLock, std::condition_variable& queueCondition,
                   std::list<std::unique_ptr<C2Work>>& workQueue,
                   std::list<uint64_t>& flushedIndices, std::shared_ptr<C2BlockPool>& graphicPool,
                   std::ifstream& eleStream, bool& disableTest, uint32_t frameID, uint32_t nFrames,
                   uint32_t nWidth, int32_t nHeight, bool flushed = false, bool signalEOS = true) {
    typedef std::unique_lock<std::mutex> ULock;

    uint32_t maxRetry = 0;
    int bytesCount = nWidth * nHeight * 3 >> 1;
    int32_t timestampIncr = ENCODER_TIMESTAMP_INCREMENT;
    c2_status_t err = C2_OK;
    while (1) {
        if (nFrames == 0) break;
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
        if (signalEOS && (nFrames == 1)) flags |= C2FrameData::FLAG_END_OF_STREAM;
        if (flushed) {
            flags |= SYNC_FRAME;
            flushed = false;
        }

        work->input.flags = (C2FrameData::flags_t)flags;
        work->input.ordinal.timestamp = frameID * timestampIncr;
        work->input.ordinal.frameIndex = frameID;
        {
            ULock l(queueLock);
            flushedIndices.emplace_back(frameID);
        }
        char* data = (char*)malloc(bytesCount);
        ASSERT_NE(data, nullptr);
        memset(data, 0, bytesCount);
        if (eleStream.is_open()) {
            eleStream.read(data, bytesCount);
            ASSERT_EQ(eleStream.gcount(), bytesCount);
        }
        std::shared_ptr<C2GraphicBlock> block;
        err = graphicPool->fetchGraphicBlock(nWidth, nHeight, HAL_PIXEL_FORMAT_YV12,
                                             {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE},
                                             &block);
        if (err != C2_OK) {
            fprintf(stderr, "fetchGraphicBlock failed : %d\n", err);
            disableTest = true;
            break;
        }

        ASSERT_TRUE(block);
        // Graphic View
        C2GraphicView view = block->map().get();
        if (view.error() != C2_OK) {
            fprintf(stderr, "C2GraphicBlock::map() failed : %d", view.error());
            disableTest = true;
            break;
        }

        uint8_t* pY = view.data()[C2PlanarLayout::PLANE_Y];
        uint8_t* pU = view.data()[C2PlanarLayout::PLANE_U];
        uint8_t* pV = view.data()[C2PlanarLayout::PLANE_V];

        memcpy(pY, data, nWidth * nHeight);
        memcpy(pU, data + nWidth * nHeight, (nWidth * nHeight >> 2));
        memcpy(pV, data + (nWidth * nHeight * 5 >> 2), nWidth * nHeight >> 2);

        work->input.buffers.clear();
        work->input.buffers.emplace_back(new GraphicBuffer(block));
        work->worklets.clear();
        work->worklets.emplace_back(new C2Worklet);
        free(data);

        std::list<std::unique_ptr<C2Work>> items;
        items.push_back(std::move(work));

        // DO THE ENCODING
        ASSERT_EQ(component->queue(&items), C2_OK);
        ALOGV("Frame #%d size = %d queued", frameID, bytesCount);
        nFrames--;
        frameID++;
        maxRetry = 0;
    }
}

TEST_P(Codec2VideoEncHidlTest, validateCompName) {
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";
    ALOGV("Checks if the given component is a valid video component");
    validateComponent(mComponent, mCompName, mDisableTest);
    ASSERT_EQ(mDisableTest, false);
}

class Codec2VideoEncEncodeTest
    : public Codec2VideoEncHidlTestBase,
      public ::testing::WithParamInterface<
              std::tuple<std::string, std::string, std::string, std::string, std::string>> {
    void getParams() {
        mInstanceName = std::get<0>(GetParam());
        mComponentName = std::get<1>(GetParam());
    }
};

TEST_P(Codec2VideoEncEncodeTest, EncodeTest) {
    description("Encodes input file");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    char mURL[512];
    int32_t nWidth = ENC_DEFAULT_FRAME_WIDTH;
    int32_t nHeight = ENC_DEFAULT_FRAME_HEIGHT;
    bool signalEOS = !std::get<2>(GetParam()).compare("true");
    // Send an empty frame to receive CSD data from encoder.
    bool sendEmptyFirstFrame = !std::get<3>(GetParam()).compare("true");
    mConfigBPictures = !std::get<4>(GetParam()).compare("true");

    strcpy(mURL, sResourceDir.c_str());
    GetURLForComponent(mURL);

    std::ifstream eleStream;
    eleStream.open(mURL, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true) << mURL << " file not found";
    ALOGV("mURL : %s", mURL);

    mTimestampUs = 0;
    mTimestampDevTest = true;
    mFlushedIndices.clear();
    mTimestampUslist.clear();
    int32_t inputFrames = ENC_NUM_FRAMES + (sendEmptyFirstFrame ? 1 : 0);
    uint32_t timestamp = 0;

    // Add input timestamp to timestampUslist
    while (inputFrames) {
        if (mTimestampDevTest) mTimestampUslist.push_back(timestamp);
        timestamp += ENCODER_TIMESTAMP_INCREMENT;
        inputFrames--;
    }

    if (!setupConfigParam(nWidth, nHeight, mConfigBPictures ? 1 : 0)) {
        std::cout << "[   WARN   ] Test Skipped \n";
        return;
    }
    std::vector<std::unique_ptr<C2Param>> inParams;
    c2_status_t c2_status = mComponent->query({}, {C2StreamGopTuning::output::PARAM_TYPE},
                                              C2_DONT_BLOCK, &inParams);

    if (c2_status != C2_OK || inParams.size() == 0) {
        std::cout << "[   WARN   ] Bframe not supported for " << mComponentName
                  << " resetting num BFrames to 0\n";
        mConfigBPictures = false;
    } else {
        size_t offset = sizeof(C2Param);
        C2Param* param = inParams[0].get();
        int32_t numBFrames = *(int32_t*)((uint8_t*)param + offset);

        if (!numBFrames) {
            std::cout << "[   WARN   ] Bframe not supported for " << mComponentName
                      << " resetting num BFrames to 0\n";
            mConfigBPictures = false;
        }
    }

    ASSERT_EQ(mComponent->start(), C2_OK);

    if (sendEmptyFirstFrame) {
        ASSERT_NO_FATAL_FAILURE(testInputBuffer(mComponent, mQueueLock, mWorkQueue, 0, false));
        inputFrames += 1;
    }
    ASSERT_NO_FATAL_FAILURE(encodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                          mFlushedIndices, mGraphicPool, eleStream, mDisableTest,
                                          inputFrames, ENC_NUM_FRAMES, nWidth, nHeight, false,
                                          signalEOS));
    // mDisableTest will be set if buffer was not fetched properly.
    // This may happen when resolution is not proper but config succeeded
    // In this cases, we skip encoding the input stream
    if (mDisableTest) {
        std::cout << "[   WARN   ] Test Disabled \n";
        ASSERT_EQ(mComponent->stop(), C2_OK);
        return;
    }

    // If EOS is not sent, sending empty input with EOS flag
    inputFrames += ENC_NUM_FRAMES;
    if (!signalEOS) {
        waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue, 1);
        ASSERT_NO_FATAL_FAILURE(testInputBuffer(mComponent, mQueueLock, mWorkQueue,
                                                C2FrameData::FLAG_END_OF_STREAM, false));
        inputFrames += 1;
    }

    // blocking call to ensures application to Wait till all the inputs are
    // consumed
    ALOGD("Waiting for input consumption");
    waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue);

    eleStream.close();
    if (mFramesReceived != inputFrames) {
        ALOGE("Input buffer count and Output buffer count mismatch");
        ALOGE("framesReceived : %d inputFrames : %d", mFramesReceived, inputFrames);
        ASSERT_TRUE(false);
    }

    if (mCompName == vp8 || mCompName == h263) {
        ASSERT_FALSE(mCsd) << "CSD Buffer not expected";
    } else if (mCompName != vp9) {
        ASSERT_TRUE(mCsd) << "CSD Buffer not received";
    }

    if (mTimestampDevTest) EXPECT_EQ(mTimestampUslist.empty(), true);
    ASSERT_EQ(mComponent->stop(), C2_OK);

    // TODO: (b/155534991)
    // Add assert for mFailedWorkReceived
}

TEST_P(Codec2VideoEncHidlTest, EOSTest) {
    description("Test empty input buffer with EOS flag");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";
    ASSERT_EQ(mComponent->start(), C2_OK);

    typedef std::unique_lock<std::mutex> ULock;
    std::unique_ptr<C2Work> work;
    {
        ULock l(mQueueLock);
        if (!mWorkQueue.empty()) {
            work.swap(mWorkQueue.front());
            mWorkQueue.pop_front();
        } else {
            ALOGE("mWorkQueue Empty is not expected at the start of the test");
            ASSERT_TRUE(false);
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
    uint32_t queueSize;
    {
        ULock l(mQueueLock);
        queueSize = mWorkQueue.size();
        if (queueSize < MAX_INPUT_BUFFERS) {
            mQueueCondition.wait_for(l, TIME_OUT);
        }
    }
    ASSERT_EQ(mEos, true);
    ASSERT_EQ(mComponent->stop(), C2_OK);
    ASSERT_EQ(mFailedWorkReceived, 0);
}

TEST_P(Codec2VideoEncHidlTest, FlushTest) {
    description("Test Request for flush");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    char mURL[512];
    int32_t nWidth = ENC_DEFAULT_FRAME_WIDTH;
    int32_t nHeight = ENC_DEFAULT_FRAME_HEIGHT;
    strcpy(mURL, sResourceDir.c_str());
    GetURLForComponent(mURL);

    if (!setupConfigParam(nWidth, nHeight)) {
        std::cout << "[   WARN   ] Test Skipped \n";
        return;
    }
    ASSERT_EQ(mComponent->start(), C2_OK);

    // Setting default configuration
    mFlushedIndices.clear();
    std::ifstream eleStream;
    uint32_t numFramesFlushed = 10;
    uint32_t numFrames = ENC_NUM_FRAMES;
    eleStream.open(mURL, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true);
    ALOGV("mURL : %s", mURL);
    // flush
    std::list<std::unique_ptr<C2Work>> flushedWork;
    c2_status_t err = mComponent->flush(C2Component::FLUSH_COMPONENT, &flushedWork);
    ASSERT_EQ(err, C2_OK);
    ASSERT_NO_FATAL_FAILURE(
            verifyFlushOutput(flushedWork, mWorkQueue, mFlushedIndices, mQueueLock));
    ASSERT_EQ(mWorkQueue.size(), MAX_INPUT_BUFFERS);

    ASSERT_NO_FATAL_FAILURE(encodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                          mFlushedIndices, mGraphicPool, eleStream, mDisableTest, 0,
                                          numFramesFlushed, nWidth, nHeight, false, false));
    // mDisableTest will be set if buffer was not fetched properly.
    // This may happen when resolution is not proper but config succeeded
    // In this cases, we skip encoding the input stream
    if (mDisableTest) {
        std::cout << "[   WARN   ] Test Disabled \n";
        ASSERT_EQ(mComponent->stop(), C2_OK);
        return;
    }

    // flush
    err = mComponent->flush(C2Component::FLUSH_COMPONENT, &flushedWork);
    ASSERT_EQ(err, C2_OK);
    waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue,
                           (size_t)MAX_INPUT_BUFFERS - flushedWork.size());
    ASSERT_NO_FATAL_FAILURE(
            verifyFlushOutput(flushedWork, mWorkQueue, mFlushedIndices, mQueueLock));
    ASSERT_EQ(mWorkQueue.size(), MAX_INPUT_BUFFERS);
    ASSERT_NO_FATAL_FAILURE(encodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                          mFlushedIndices, mGraphicPool, eleStream, mDisableTest,
                                          numFramesFlushed, numFrames - numFramesFlushed, nWidth,
                                          nHeight, true));
    eleStream.close();
    // mDisableTest will be set if buffer was not fetched properly.
    // This may happen when resolution is not proper but config succeeded
    // In this cases, we skip encoding the input stream
    if (mDisableTest) {
        std::cout << "[   WARN   ] Test Disabled \n";
        ASSERT_EQ(mComponent->stop(), C2_OK);
        return;
    }

    err = mComponent->flush(C2Component::FLUSH_COMPONENT, &flushedWork);
    ASSERT_EQ(err, C2_OK);
    waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue,
                           (size_t)MAX_INPUT_BUFFERS - flushedWork.size());
    ASSERT_NO_FATAL_FAILURE(
            verifyFlushOutput(flushedWork, mWorkQueue, mFlushedIndices, mQueueLock));
    ASSERT_EQ(mWorkQueue.size(), MAX_INPUT_BUFFERS);
    // TODO: (b/154671521)
    // Add assert for mFailedWorkReceived
    ASSERT_EQ(mComponent->stop(), C2_OK);
}

TEST_P(Codec2VideoEncHidlTest, InvalidBufferTest) {
    description("Tests feeding larger/smaller input buffer");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    std::ifstream eleStream;
    int32_t nWidth = ENC_DEFAULT_FRAME_WIDTH / 2;
    int32_t nHeight = ENC_DEFAULT_FRAME_HEIGHT / 2;

    if (!setupConfigParam(nWidth, nHeight)) {
        std::cout << "[   WARN   ] Test Skipped \n";
        return;
    }
    ASSERT_EQ(mComponent->start(), C2_OK);

    ASSERT_NO_FATAL_FAILURE(encodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                          mFlushedIndices, mGraphicPool, eleStream, mDisableTest, 0,
                                          1, nWidth, nHeight, false, false));

    // Feed larger input buffer.
    ASSERT_NO_FATAL_FAILURE(encodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                          mFlushedIndices, mGraphicPool, eleStream, mDisableTest, 1,
                                          1, nWidth * 2, nHeight * 2, false, false));

    // Feed smaller input buffer.
    ASSERT_NO_FATAL_FAILURE(encodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                          mFlushedIndices, mGraphicPool, eleStream, mDisableTest, 2,
                                          1, nWidth / 2, nHeight / 2, false, true));

    // blocking call to ensures application to Wait till all the inputs are
    // consumed
    ALOGD("Waiting for input consumption");
    waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue);

    if (mFramesReceived != 3) {
        std::cout << "[   WARN   ] Component didn't receive all buffers back \n";
        ALOGW("framesReceived : %d inputFrames : 3", mFramesReceived);
    }

    if (mFailedWorkReceived == 0) {
        std::cout << "[   WARN   ] Expected failed frame count mismatch \n";
        ALOGW("failedFramesReceived : %d", mFailedWorkReceived);
    }

    ASSERT_EQ(mComponent->stop(), C2_OK);
}

class Codec2VideoEncResolutionTest
    : public Codec2VideoEncHidlTestBase,
      public ::testing::WithParamInterface<
              std::tuple<std::string, std::string, std::string, std::string>> {
    void getParams() {
        mInstanceName = std::get<0>(GetParam());
        mComponentName = std::get<1>(GetParam());
    }
};

TEST_P(Codec2VideoEncResolutionTest, ResolutionTest) {
    description("Tests encoding at different resolutions");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    std::ifstream eleStream;
    int32_t nWidth = std::stoi(std::get<2>(GetParam()));
    int32_t nHeight = std::stoi(std::get<3>(GetParam()));
    ALOGD("Trying encode for width %d height %d", nWidth, nHeight);
    mEos = false;

    if (!setupConfigParam(nWidth, nHeight)) {
        std::cout << "[   WARN   ] Test Skipped \n";
        return;
    }
    ASSERT_EQ(mComponent->start(), C2_OK);

    ASSERT_NO_FATAL_FAILURE(encodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                          mFlushedIndices, mGraphicPool, eleStream, mDisableTest, 0,
                                          MAX_INPUT_BUFFERS, nWidth, nHeight, false, true));

    // mDisableTest will be set if buffer was not fetched properly.
    // This may happen when resolution is not proper but config succeeded
    // In this cases, we skip encoding the input stream
    if (mDisableTest) {
        std::cout << "[   WARN   ] Test Disabled \n";
        ASSERT_EQ(mComponent->stop(), C2_OK);
        return;
    }

    ALOGD("Waiting for input consumption");
    waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue);

    ASSERT_EQ(mEos, true);
    ASSERT_EQ(mComponent->stop(), C2_OK);
    ASSERT_EQ(mComponent->reset(), C2_OK);
}

INSTANTIATE_TEST_SUITE_P(PerInstance, Codec2VideoEncHidlTest, testing::ValuesIn(kTestParameters),
                         android::hardware::PrintInstanceTupleNameToString<>);

INSTANTIATE_TEST_SUITE_P(NonStdSizes, Codec2VideoEncResolutionTest,
                         ::testing::ValuesIn(kEncodeResolutionTestParameters));

// EncodeTest with EOS / No EOS
INSTANTIATE_TEST_SUITE_P(EncodeTestwithEOS, Codec2VideoEncEncodeTest,
                         ::testing::ValuesIn(kEncodeTestParameters));

TEST_P(Codec2VideoEncHidlTest, AdaptiveBitrateTest) {
    description("Encodes input file for different bitrates");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    char mURL[512];

    strcpy(mURL, sResourceDir.c_str());
    GetURLForComponent(mURL);

    std::ifstream eleStream;
    eleStream.open(mURL, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true) << mURL << " file not found";
    ALOGV("mURL : %s", mURL);

    mFlushedIndices.clear();

    int32_t nWidth = ENC_DEFAULT_FRAME_WIDTH;
    int32_t nHeight = ENC_DEFAULT_FRAME_HEIGHT;
    if (!setupConfigParam(nWidth, nHeight)) {
        std::cout << "[   WARN   ] Test Skipped \n";
        return;
    }
    ASSERT_EQ(mComponent->start(), C2_OK);

    uint64_t prevOutputSize = 0u;
    uint32_t bitrateValues[] = {100000, 64000, 200000};
    uint32_t prevBitrate = 0;
    int32_t inputFrameId = 0;

    for (uint32_t curBitrate : bitrateValues) {
        // Configuring bitrate
        std::vector<std::unique_ptr<C2SettingResult>> failures;
        C2StreamBitrateInfo::output bitrate(0u, curBitrate);
        std::vector<C2Param*> configParam{&bitrate};
        c2_status_t status = mComponent->config(configParam, C2_DONT_BLOCK, &failures);
        if (status != C2_OK && failures.size() != 0u) {
            ALOGW("BitRate Config failed, using previous bitrate");
        }

        ASSERT_NO_FATAL_FAILURE(encodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                              mFlushedIndices, mGraphicPool, eleStream,
                                              mDisableTest, inputFrameId, ENC_NUM_FRAMES, nWidth,
                                              nHeight, false, false));
        // mDisableTest will be set if buffer was not fetched properly.
        // This may happen when resolution is not proper but config succeeded
        // In this cases, we skip encoding the input stream
        if (mDisableTest) {
            std::cout << "[   WARN   ] Test Disabled \n";
            ASSERT_EQ(mComponent->stop(), C2_OK);
            return;
        }
        inputFrameId += ENC_NUM_FRAMES;
        // blocking call to ensures application to Wait till all the inputs are
        // consumed
        ALOGD("Waiting for input consumption");
        waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue);

        // Change in bitrate may result in different outputSize
        if (prevBitrate >= curBitrate) {
            EXPECT_LE(mOutputSize, prevOutputSize);
        } else {
            EXPECT_GE(mOutputSize, prevOutputSize);
        }
        prevBitrate = curBitrate;
        prevOutputSize = mOutputSize;
        // Reset the file pointer and output size
        mOutputSize = 0;
        eleStream.seekg(0, eleStream.beg);
    }

    // Sending empty input with EOS flag
    ASSERT_NO_FATAL_FAILURE(testInputBuffer(mComponent, mQueueLock, mWorkQueue,
                                            C2FrameData::FLAG_END_OF_STREAM, false));
    inputFrameId += 1;
    waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue);

    eleStream.close();
    if (mFramesReceived != inputFrameId) {
        ALOGE("Input buffer count and Output buffer count mismatch");
        ALOGE("framesReceived : %d inputFrames : %d", mFramesReceived, inputFrameId);
        ASSERT_TRUE(false);
    }

    ASSERT_EQ(mComponent->stop(), C2_OK);
}

}  // anonymous namespace

int main(int argc, char** argv) {
    kTestParameters = getTestParameters(C2Component::DOMAIN_VIDEO, C2Component::KIND_ENCODER);
    for (auto params : kTestParameters) {
        constexpr char const* kBoolString[] = { "false", "true" };
        for (size_t i = 0; i < 1 << 3; ++i) {
            kEncodeTestParameters.push_back(std::make_tuple(
                    std::get<0>(params), std::get<1>(params),
                    kBoolString[i & 1],
                    kBoolString[(i >> 1) & 1],
                    kBoolString[(i >> 2) & 1]));
        }

        kEncodeResolutionTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "52", "18"));
        kEncodeResolutionTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "365", "365"));
        kEncodeResolutionTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "484", "362"));
        kEncodeResolutionTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "244", "488"));
        kEncodeResolutionTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "852", "608"));
        kEncodeResolutionTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "1400", "442"));
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
