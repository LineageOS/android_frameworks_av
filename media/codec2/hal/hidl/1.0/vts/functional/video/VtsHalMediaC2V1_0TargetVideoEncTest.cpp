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
#include <android/binder_process.h>
#include <codec2/common/HalSelection.h>
#include <gtest/gtest.h>
#include <hidl/GtestPrinter.h>
#include <stdio.h>
#include <fstream>

#include <C2Buffer.h>
#include <C2BufferPriv.h>
#include <C2Config.h>
#include <C2Debug.h>
#include <codec2/hidl/client.h>

#include "media_c2_hidl_test_common.h"
#include "media_c2_video_hidl_test_common.h"

class GraphicBuffer : public C2Buffer {
  public:
    explicit GraphicBuffer(const std::shared_ptr<C2GraphicBlock>& block)
        : C2Buffer({block->share(C2Rect(block->width(), block->height()), ::C2Fence())}) {}
};

using EncodeTestParameters = std::tuple<std::string, std::string, bool, bool, bool>;
static std::vector<EncodeTestParameters> gEncodeTestParameters;

using EncodeResolutionTestParameters = std::tuple<std::string, std::string, int32_t, int32_t>;
static std::vector<EncodeResolutionTestParameters> gEncodeResolutionTestParameters;

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
        C2PooledBlockPool::BufferPoolVer ver = ::android::IsCodec2AidlHalSelected() ?
                C2PooledBlockPool::VER_AIDL2 : C2PooledBlockPool::VER_HIDL;
        mGraphicPool = std::make_shared<C2PooledBlockPool>(mGraphicAllocator, mBlockPoolId++, ver);
        ASSERT_NE(mGraphicPool, nullptr);

        std::vector<std::unique_ptr<C2Param>> queried;
        c2_status_t c2err = mComponent->query({}, {C2PortMediaTypeSetting::output::PARAM_TYPE},
                                              C2_DONT_BLOCK, &queried);
        ASSERT_EQ(c2err, C2_OK) << "Query media type failed";
        ASSERT_EQ(queried.size(), 1) << "Size of the vector returned is invalid";

        mMime = ((C2PortMediaTypeSetting::output*)queried[0].get())->m.value;
        std::cout << "mime : " << mMime << "\n";
        mEos = false;
        mCsd = false;
        mConfigBPictures = false;
        mFramesReceived = 0;
        mFailedWorkReceived = 0;
        mTimestampUs = 0u;
        mOutputSize = 0u;
        mTimestampDevTest = false;
        mWidth = ENC_DEFAULT_FRAME_WIDTH;
        mHeight = ENC_DEFAULT_FRAME_HEIGHT;
        mMaxWidth = 0;
        mMaxHeight = 0;
        mMinWidth = INT32_MAX;
        mMinHeight = INT32_MAX;

        ASSERT_EQ(getMaxMinResolutionSupported(), C2_OK);
        mWidth = std::max(std::min(mWidth, mMaxWidth), mMinWidth);
        mHeight = std::max(std::min(mHeight, mMaxHeight), mMinHeight);
        ALOGV("mWidth %d mHeight %d", mWidth, mHeight);

        C2SecureModeTuning secureModeTuning{};
        mComponent->query({&secureModeTuning}, {}, C2_MAY_BLOCK, nullptr);
        if (secureModeTuning.value == C2Config::SM_READ_PROTECTED ||
            secureModeTuning.value == C2Config::SM_READ_PROTECTED_WITH_ENCRYPTED) {
            mDisableTest = true;
        }

        getFile();
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
    void getFile();
    bool setupConfigParam(int32_t nWidth, int32_t nHeight, int32_t nBFrame = 0);
    c2_status_t getMaxMinResolutionSupported();

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

    std::string mMime;
    std::string mInstanceName;
    std::string mComponentName;
    bool mEos;
    bool mCsd;
    bool mDisableTest;
    bool mConfigBPictures;
    bool mTimestampDevTest;
    uint32_t mFramesReceived;
    uint32_t mFailedWorkReceived;
    uint64_t mTimestampUs;
    uint64_t mOutputSize;
    int32_t mWidth;
    int32_t mHeight;
    int32_t mMaxWidth;
    int32_t mMaxHeight;
    int32_t mMinWidth;
    int32_t mMinHeight;

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

    std::string mInputFile;

  protected:
    static void description(const std::string& description) {
        RecordProperty("description", description);
    }
};

class Codec2VideoEncHidlTest : public Codec2VideoEncHidlTestBase,
                               public ::testing::WithParamInterface<TestParameters> {
    void getParams() {
        mInstanceName = std::get<0>(GetParam());
        mComponentName = std::get<1>(GetParam());
    }
};

void validateComponent(const std::shared_ptr<android::Codec2Client::Component>& component,
                       bool& disableTest) {
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

void Codec2VideoEncHidlTestBase::getFile() {
    mInputFile = sResourceDir + "bbb_352x288_420p_30fps_32frames.yuv";
}

void fillByteBuffer(char* inputBuffer, char* mInputData, uint32_t nWidth, int32_t nHeight) {
    int width, height, tileWidth, tileHeight;
    int offset = 0, frmOffset = 0;
    int numOfPlanes = 3;
    for (int plane = 0; plane < numOfPlanes; plane++) {
        if (plane == 0) {
            width = nWidth;
            height = nHeight;
            tileWidth = ENC_DEFAULT_FRAME_WIDTH;
            tileHeight = ENC_DEFAULT_FRAME_HEIGHT;
        } else {
            width = nWidth / 2;
            tileWidth = ENC_DEFAULT_FRAME_WIDTH / 2;
            height = nHeight / 2;
            tileHeight = ENC_DEFAULT_FRAME_HEIGHT / 2;
        }
        for (int k = 0; k < height; k += tileHeight) {
            int rowsToCopy = std::min(height - k, tileHeight);
            for (int j = 0; j < rowsToCopy; j++) {
                for (int i = 0; i < width; i += tileWidth) {
                    int colsToCopy = std::min(width - i, tileWidth);
                    memcpy(inputBuffer + (offset + (k + j) * width + i),
                           mInputData + (frmOffset + j * tileWidth), colsToCopy);
                }
            }
        }
        offset += width * height;
        frmOffset += tileWidth * tileHeight;
    }
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

    // Query component's memory usage flags
    std::vector<std::unique_ptr<C2Param>> params;
    C2StreamUsageTuning::input compUsage(0u, 0u);
    component->query({&compUsage}, {}, C2_DONT_BLOCK, &params);

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
        std::vector<uint8_t> buffer(bytesCount);
        char* data = (char*)buffer.data();
        if (nWidth != ENC_DEFAULT_FRAME_WIDTH || nHeight != ENC_DEFAULT_FRAME_HEIGHT) {
            int defaultBytesCount = ENC_DEFAULT_FRAME_HEIGHT * ENC_DEFAULT_FRAME_WIDTH * 3 >> 1;
            std::vector<uint8_t> srcBuffer(defaultBytesCount);
            char* srcData = (char*)srcBuffer.data();
            if (eleStream.is_open()) {
                eleStream.read(srcData, defaultBytesCount);
                ASSERT_EQ(eleStream.gcount(), defaultBytesCount);
            }
            fillByteBuffer(data, srcData, nWidth, nHeight);
        } else {
            if (eleStream.is_open()) {
                eleStream.read(data, bytesCount);
                ASSERT_EQ(eleStream.gcount(), bytesCount);
            }
        }
        std::shared_ptr<C2GraphicBlock> block;
        err = graphicPool->fetchGraphicBlock(nWidth, nHeight, HAL_PIXEL_FORMAT_YV12,
                                             {C2MemoryUsage::CPU_READ | compUsage.value,
                                                 C2MemoryUsage::CPU_WRITE | compUsage.value},
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
    validateComponent(mComponent, mDisableTest);
    ASSERT_EQ(mDisableTest, false);
}

class Codec2VideoEncEncodeTest : public Codec2VideoEncHidlTestBase,
                                 public ::testing::WithParamInterface<EncodeTestParameters> {
    void getParams() {
        mInstanceName = std::get<0>(GetParam());
        mComponentName = std::get<1>(GetParam());
    }
};

c2_status_t Codec2VideoEncHidlTestBase::getMaxMinResolutionSupported() {
    std::unique_ptr<C2StreamPictureSizeInfo::input> param =
            std::make_unique<C2StreamPictureSizeInfo::input>();
    std::vector<C2FieldSupportedValuesQuery> validValueInfos = {
            C2FieldSupportedValuesQuery::Current(
                    C2ParamField(param.get(), &C2StreamPictureSizeInfo::width)),
            C2FieldSupportedValuesQuery::Current(
                    C2ParamField(param.get(), &C2StreamPictureSizeInfo::height))};
    c2_status_t c2err = mComponent->querySupportedValues(validValueInfos, C2_MAY_BLOCK);
    if (c2err != C2_OK || validValueInfos.size() != 2u) {
        ALOGE("querySupportedValues_vb failed for pictureSize");
        return c2err;
    }

    const auto& c2FSVWidth = validValueInfos[0].values;
    const auto& c2FSVHeight = validValueInfos[1].values;
    switch (c2FSVWidth.type) {
        case C2FieldSupportedValues::type_t::RANGE: {
            const auto& widthRange = c2FSVWidth.range;
            const auto& heightRange = c2FSVHeight.range;
            mMaxWidth = (uint32_t)(widthRange.max).ref<uint32_t>();
            mMaxHeight = (uint32_t)(heightRange.max).ref<uint32_t>();
            mMinWidth = (uint32_t)(widthRange.min).ref<uint32_t>();
            mMinHeight = (uint32_t)(heightRange.min).ref<uint32_t>();
            break;
        }
        case C2FieldSupportedValues::type_t::VALUES: {
            int32_t curr = 0;
            for (const C2Value::Primitive& prim : c2FSVWidth.values) {
                curr = (uint32_t)prim.ref<uint32_t>();
                mMaxWidth = std::max(curr, mMaxWidth);
                mMinWidth = std::min(curr, mMinWidth);
            }
            for (const C2Value::Primitive& prim : c2FSVHeight.values) {
                curr = (uint32_t)prim.ref<uint32_t>();
                mMaxHeight = std::max(curr, mMaxHeight);
                mMinHeight = std::min(curr, mMinHeight);
            }
            break;
        }
        default:
            ALOGE("Non supported data");
            return C2_BAD_VALUE;
    }
    return C2_OK;
}

TEST_P(Codec2VideoEncEncodeTest, EncodeTest) {
    description("Encodes input file");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    bool signalEOS = std::get<2>(GetParam());
    // Send an empty frame to receive CSD data from encoder.
    bool sendEmptyFirstFrame = std::get<3>(GetParam());
    mConfigBPictures = std::get<4>(GetParam());

    std::ifstream eleStream;
    eleStream.open(mInputFile, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true) << mInputFile << " file not found";

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

    std::vector<std::unique_ptr<C2Param>> inParams;
    c2_status_t c2_status = mComponent->query({}, {C2StreamGopTuning::output::PARAM_TYPE},
                                              C2_DONT_BLOCK, &inParams);

    if (c2_status != C2_OK || inParams.size() == 0) {
        std::cout << "[   WARN   ] Bframe not supported for " << mComponentName
                  << " resetting num BFrames to 0\n";
        mConfigBPictures = false;
    } else {
        int32_t numBFrames = 0;
        C2StreamGopTuning::output* gop = C2StreamGopTuning::output::From(inParams[0].get());
        if (gop && gop->flexCount() >= 1) {
            for (size_t i = 0; i < gop->flexCount(); ++i) {
                const C2GopLayerStruct& layer = gop->m.values[i];
                if (layer.type_ == C2Config::picture_type_t(P_FRAME | B_FRAME)) {
                    numBFrames = layer.count;
                    break;
                }
            }
        }

        if (!numBFrames) {
            std::cout << "[   WARN   ] Bframe not supported for " << mComponentName
                      << " resetting num BFrames to 0\n";
            mConfigBPictures = false;
        }
    }
    if (!setupConfigParam(mWidth, mHeight, mConfigBPictures ? 1 : 0)) {
        ASSERT_TRUE(false) << "Failed while configuring height and width for " << mComponentName;
    }

    ASSERT_EQ(mComponent->start(), C2_OK);

    if (sendEmptyFirstFrame) {
        ASSERT_NO_FATAL_FAILURE(testInputBuffer(mComponent, mQueueLock, mWorkQueue, 0, false));
        inputFrames += 1;
    }
    ASSERT_NO_FATAL_FAILURE(encodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                          mFlushedIndices, mGraphicPool, eleStream, mDisableTest,
                                          inputFrames, ENC_NUM_FRAMES, mWidth, mHeight, false,
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

    if ((mMime.find("vp8") != std::string::npos) || (mMime.find("3gpp") != std::string::npos)) {
        ASSERT_FALSE(mCsd) << "CSD Buffer not expected";
    } else if (mMime.find("vp9") == std::string::npos) {
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

    if (!setupConfigParam(mWidth, mHeight)) {
        ASSERT_TRUE(false) << "Failed while configuring height and width for " << mComponentName;
    }
    ASSERT_EQ(mComponent->start(), C2_OK);

    // Setting default configuration
    mFlushedIndices.clear();
    std::ifstream eleStream;
    uint32_t numFramesFlushed = 10;
    uint32_t numFrames = ENC_NUM_FRAMES;
    eleStream.open(mInputFile, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true);

    // flush
    std::list<std::unique_ptr<C2Work>> flushedWork;
    c2_status_t err = mComponent->flush(C2Component::FLUSH_COMPONENT, &flushedWork);
    ASSERT_EQ(err, C2_OK);
    ASSERT_NO_FATAL_FAILURE(
            verifyFlushOutput(flushedWork, mWorkQueue, mFlushedIndices, mQueueLock));
    ASSERT_EQ(mWorkQueue.size(), MAX_INPUT_BUFFERS);

    ASSERT_NO_FATAL_FAILURE(encodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                          mFlushedIndices, mGraphicPool, eleStream, mDisableTest, 0,
                                          numFramesFlushed, mWidth, mHeight, false, false));
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
                                          numFramesFlushed, numFrames - numFramesFlushed, mWidth,
                                          mHeight, true));
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
      public ::testing::WithParamInterface<EncodeResolutionTestParameters> {
    void getParams() {
        mInstanceName = std::get<0>(GetParam());
        mComponentName = std::get<1>(GetParam());
    }
};

TEST_P(Codec2VideoEncResolutionTest, ResolutionTest) {
    description("Tests encoding at different resolutions");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    std::ifstream eleStream;
    int32_t nWidth = std::get<2>(GetParam());
    int32_t nHeight = std::get<3>(GetParam());
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

INSTANTIATE_TEST_SUITE_P(PerInstance, Codec2VideoEncHidlTest, testing::ValuesIn(gTestParameters),
                         PrintInstanceTupleNameToString<>);

INSTANTIATE_TEST_SUITE_P(NonStdSizes, Codec2VideoEncResolutionTest,
                         ::testing::ValuesIn(gEncodeResolutionTestParameters),
                         PrintInstanceTupleNameToString<>);

// EncodeTest with EOS / No EOS
INSTANTIATE_TEST_SUITE_P(EncodeTestwithEOS, Codec2VideoEncEncodeTest,
                         ::testing::ValuesIn(gEncodeTestParameters),
                         PrintInstanceTupleNameToString<>);

TEST_P(Codec2VideoEncHidlTest, AdaptiveBitrateTest) {
    description("Encodes input file for different bitrates");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";
    if (mMime != "video/avc" && mMime != "video/hevc" && mMime != "video/x-vnd.on2.vp8" &&
        mMime != "video/x-vnd.on2.vp9") {
        GTEST_SKIP() << "AdaptiveBitrateTest is enabled only for avc, hevc, vp8 and vp9 encoders";
    }

    std::ifstream eleStream;
    eleStream.open(mInputFile, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true) << mInputFile << " file not found";

    mFlushedIndices.clear();

    if (!setupConfigParam(mWidth, mHeight)) {
        ASSERT_TRUE(false) << "Failed while configuring height and width for " << mComponentName;
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
                                              mDisableTest, inputFrameId, ENC_NUM_FRAMES, mWidth,
                                              mHeight, false, false));
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
    parseArgs(argc, argv);
    gTestParameters = getTestParameters(C2Component::DOMAIN_VIDEO, C2Component::KIND_ENCODER);
    for (auto params : gTestParameters) {
        for (size_t i = 0; i < 1 << 3; ++i) {
            gEncodeTestParameters.push_back(std::make_tuple(
                    std::get<0>(params), std::get<1>(params), i & 1, (i >> 1) & 1, (i >> 2) & 1));
        }

        gEncodeResolutionTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), 52, 18));
        gEncodeResolutionTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), 365, 365));
        gEncodeResolutionTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), 484, 362));
        gEncodeResolutionTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), 244, 488));
        gEncodeResolutionTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), 852, 608));
        gEncodeResolutionTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), 1400, 442));
    }

    ::testing::InitGoogleTest(&argc, argv);
    ABinderProcess_startThreadPool();
    return RUN_ALL_TESTS();
}
