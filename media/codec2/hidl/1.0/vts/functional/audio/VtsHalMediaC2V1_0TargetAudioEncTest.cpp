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
#define LOG_TAG "codec2_hidl_hal_audio_enc_test"

#include <android-base/logging.h>
#include <gtest/gtest.h>
#include <hidl/GtestPrinter.h>
#include <stdio.h>
#include <algorithm>
#include <fstream>

#include <C2Buffer.h>
#include <C2BufferPriv.h>
#include <C2Config.h>
#include <C2Debug.h>
#include <codec2/hidl/client.h>

#include "media_c2_hidl_test_common.h"

using EncodeTestParameters = std::tuple<std::string, std::string, bool, int32_t>;

static std::vector<EncodeTestParameters> gEncodeTestParameters;

class LinearBuffer : public C2Buffer {
  public:
    explicit LinearBuffer(const std::shared_ptr<C2LinearBlock>& block)
        : C2Buffer({block->share(block->offset(), block->size(), ::C2Fence())}) {}
};

constexpr uint32_t kMaxSamplesPerFrame = 256;

namespace {

class Codec2AudioEncHidlTestBase : public ::testing::Test {
  public:
    // google.codec2 Audio test setup
    virtual void SetUp() override {
        getParams();
        mDisableTest = false;
        ALOGV("Codec2AudioEncHidlTest SetUp");
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

        std::vector<std::unique_ptr<C2Param>> queried;
        c2_status_t c2err = mComponent->query({}, {C2PortMediaTypeSetting::output::PARAM_TYPE},
                                              C2_DONT_BLOCK, &queried);
        ASSERT_EQ(c2err, C2_OK) << "Query media type failed";
        ASSERT_EQ(queried.size(), 1) << "Size of the vector returned is invalid";

        mMime = ((C2PortMediaTypeSetting::output*)queried[0].get())->m.value;
        mEos = false;
        mCsd = false;
        mFramesReceived = 0;
        mEncoderFrameSize = 0;
        mWorkResult = C2_OK;
        mOutputSize = 0u;
        ASSERT_NO_FATAL_FAILURE(getInputMaxBufSize());
        ASSERT_NO_FATAL_FAILURE(getChannelCount(&mNumChannels));
        ASSERT_NO_FATAL_FAILURE(getSampleRate(&mSampleRate));
        ASSERT_NO_FATAL_FAILURE(getSamplesPerFrame(mNumChannels, &mSamplesPerFrame));

        getFile(mNumChannels, mSampleRate);
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

    void getChannelCount(int32_t* nChannels);
    void getSampleRate(int32_t* nSampleRate);
    void getSamplesPerFrame(int32_t nChannels, int32_t* samplesPerFrame);

    void getFile(int32_t channelCount, int32_t sampleRate);

    // callback function to process onWorkDone received by Listener
    void handleWorkDone(std::list<std::unique_ptr<C2Work>>& workItems) {
        for (std::unique_ptr<C2Work>& work : workItems) {
            if (!work->worklets.empty()) {
                mWorkResult |= work->result;
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

    int32_t mWorkResult;
    uint32_t mFramesReceived;
    int32_t mInputMaxBufSize;
    uint64_t mOutputSize;
    uint32_t mEncoderFrameSize;
    std::list<uint64_t> mFlushedIndices;

    C2BlockPool::local_id_t mBlockPoolId;
    std::shared_ptr<C2BlockPool> mLinearPool;
    std::shared_ptr<C2Allocator> mLinearAllocator;

    std::mutex mQueueLock;
    std::condition_variable mQueueCondition;
    std::list<std::unique_ptr<C2Work>> mWorkQueue;

    std::shared_ptr<android::Codec2Client> mClient;
    std::shared_ptr<android::Codec2Client::Listener> mListener;
    std::shared_ptr<android::Codec2Client::Component> mComponent;

    int32_t mNumChannels;
    int32_t mSampleRate;
    int32_t mSamplesPerFrame;

    std::string mInputFile;

  protected:
    static void description(const std::string& description) {
        RecordProperty("description", description);
    }

    // In encoder components, fetch the size of input buffer allocated
    void getInputMaxBufSize() {
        std::vector<std::unique_ptr<C2Param>> inParams;
        c2_status_t status = mComponent->query({}, {C2StreamMaxBufferSizeInfo::input::PARAM_TYPE},
                                               C2_DONT_BLOCK, &inParams);
        ASSERT_EQ(status, C2_OK) << "Query max buffer size info failed";
        ASSERT_EQ(inParams.size(), 1) << "Size of the vector returned is invalid";

        mInputMaxBufSize = C2StreamMaxBufferSizeInfo::input::From(inParams[0].get())->value;
    }
};

class Codec2AudioEncHidlTest : public Codec2AudioEncHidlTestBase,
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

    // Validate its not an encoder and the component to be tested is audio
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
        if (inputDomain.find("audio/") == std::string::npos) {
            ALOGE("Expected Audio Component");
            disableTest = true;
            return;
        }
    }
    ALOGV("Component Valid");
}

// Set Default config param.
bool setupConfigParam(const std::shared_ptr<android::Codec2Client::Component>& component,
                      int32_t nChannels, int32_t nSampleRate) {
    std::vector<std::unique_ptr<C2SettingResult>> failures;
    C2StreamSampleRateInfo::input sampleRateInfo(0u, nSampleRate);
    C2StreamChannelCountInfo::input channelCountInfo(0u, nChannels);

    std::vector<C2Param*> configParam{&sampleRateInfo, &channelCountInfo};
    c2_status_t status = component->config(configParam, C2_DONT_BLOCK, &failures);
    if (status == C2_OK && failures.size() == 0u) return true;
    return false;
}

void Codec2AudioEncHidlTestBase::getChannelCount(int32_t* nChannels) {
    std::unique_ptr<C2StreamChannelCountInfo::input> channelCount =
            std::make_unique<C2StreamChannelCountInfo::input>();
    std::vector<C2FieldSupportedValuesQuery> validValueInfos = {
            C2FieldSupportedValuesQuery::Current(
                    C2ParamField(channelCount.get(), &C2StreamChannelCountInfo::value))};
    c2_status_t c2err = mComponent->querySupportedValues(validValueInfos, C2_DONT_BLOCK);
    ASSERT_EQ(c2err, C2_OK) << "Query channel count info failed";
    ASSERT_EQ(validValueInfos.size(), 1) << "Size of the vector returned is invalid";

    // setting default value of channelCount
    *nChannels = 1;
    const auto& c2FSV = validValueInfos[0].values;
    switch (c2FSV.type) {
        case C2FieldSupportedValues::type_t::RANGE: {
            const auto& range = c2FSV.range;
            uint32_t rmax = (uint32_t)(range.max).ref<uint32_t>();
            if (rmax >= 2) {
                *nChannels = 2;
            } else {
                *nChannels = 1;
            }
            break;
        }
        case C2FieldSupportedValues::type_t::VALUES: {
            for (const C2Value::Primitive& prim : c2FSV.values) {
                if ((uint32_t)prim.ref<uint32_t>() == 2) {
                    *nChannels = 2;
                } else if ((uint32_t)prim.ref<uint32_t>() == 1) {
                    *nChannels = 1;
                }
            }
            break;
        }
        default:
            ASSERT_TRUE(false) << "Unsupported type: " << c2FSV.type;
            break;
    }
    return;
}
void Codec2AudioEncHidlTestBase::getSampleRate(int32_t* nSampleRate) {
    // Use the default sample rate for mComponents
    std::vector<std::unique_ptr<C2Param>> queried;
    c2_status_t c2err = mComponent->query({}, {C2StreamSampleRateInfo::input::PARAM_TYPE},
                                          C2_DONT_BLOCK, &queried);
    ASSERT_EQ(c2err, C2_OK) << "Query sample rate info failed";
    ASSERT_EQ(queried.size(), 1) << "Size of the vector returned is invalid";

    *nSampleRate = C2StreamSampleRateInfo::input::From(queried[0].get())->value;
    return;
}

void Codec2AudioEncHidlTestBase::getSamplesPerFrame(int32_t nChannels, int32_t* samplesPerFrame) {
    std::vector<std::unique_ptr<C2Param>> queried;
    c2_status_t c2err = mComponent->query({}, {C2StreamAudioFrameSizeInfo::input::PARAM_TYPE},
                                          C2_DONT_BLOCK, &queried);

    if (c2err == C2_OK && queried.size() == 1) {
        mEncoderFrameSize = C2StreamAudioFrameSizeInfo::input::From(queried[0].get())->value;
        if (mEncoderFrameSize) {
            *samplesPerFrame = mEncoderFrameSize;
            return;
        }
    }

    c2err = mComponent->query({}, {C2StreamMaxBufferSizeInfo::input::PARAM_TYPE}, C2_DONT_BLOCK,
                              &queried);
    ASSERT_EQ(c2err, C2_OK) << "Query max buffer size info failed";
    ASSERT_EQ(queried.size(), 1) << "Size of the vector returned is invalid";

    uint32_t maxInputSize = C2StreamMaxBufferSizeInfo::input::From(queried[0].get())->value;
    *samplesPerFrame = std::min((maxInputSize / (nChannels * 2)), kMaxSamplesPerFrame);

    return;
}

// LookUpTable of clips and metadata for component testing
void Codec2AudioEncHidlTestBase::getFile(int32_t channelCount, int32_t sampleRate) {
    std::string rawInput = "bbb_raw_1ch_8khz_s16le.raw";
    if (channelCount == 1 && sampleRate == 16000) {
        rawInput = "bbb_raw_1ch_16khz_s16le.raw";
    } else if (channelCount == 2) {
        rawInput = "bbb_raw_2ch_48khz_s16le.raw";
    }

    mInputFile = sResourceDir + rawInput;
}

void encodeNFrames(const std::shared_ptr<android::Codec2Client::Component>& component,
                   std::mutex& queueLock, std::condition_variable& queueCondition,
                   std::list<std::unique_ptr<C2Work>>& workQueue,
                   std::list<uint64_t>& flushedIndices, std::shared_ptr<C2BlockPool>& linearPool,
                   std::ifstream& eleStream, uint32_t nFrames, int32_t samplesPerFrame,
                   int32_t nChannels, int32_t nSampleRate, bool flushed = false,
                   bool signalEOS = true) {
    typedef std::unique_lock<std::mutex> ULock;

    uint32_t frameID = 0;
    uint32_t maxRetry = 0;
    uint32_t bytesCount = samplesPerFrame * nChannels * 2;
    int32_t timestampIncr = (int)(((float)samplesPerFrame / nSampleRate) * 1000000);
    uint64_t timestamp = 0;

    // get length of file:
    int32_t currPos = eleStream.tellg();
    eleStream.seekg(0, eleStream.end);
    uint32_t remainingBytes = (uint32_t)eleStream.tellg() - currPos;
    eleStream.seekg(currPos, eleStream.beg);

    nFrames = std::min(nFrames, remainingBytes / bytesCount);
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
        work->input.ordinal.timestamp = timestamp;
        work->input.ordinal.frameIndex = frameID;
        {
            ULock l(queueLock);
            flushedIndices.emplace_back(frameID);
        }
        char* data = (char*)malloc(bytesCount);
        ASSERT_NE(data, nullptr);
        eleStream.read(data, bytesCount);
        // if we have reached at the end of input stream, signal eos
        if (eleStream.gcount() < bytesCount) {
            bytesCount = eleStream.gcount();
            if (signalEOS) flags |= C2FrameData::FLAG_END_OF_STREAM;
        }

        std::shared_ptr<C2LinearBlock> block;
        ASSERT_EQ(C2_OK,
                  linearPool->fetchLinearBlock(
                          bytesCount, {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE}, &block));
        ASSERT_TRUE(block);
        // Write View
        C2WriteView view = block->map().get();
        if (view.error() != C2_OK) {
            fprintf(stderr, "C2LinearBlock::map() failed : %d", view.error());
            break;
        }
        ASSERT_EQ((size_t)bytesCount, view.capacity());
        ASSERT_EQ(0u, view.offset());
        ASSERT_EQ((size_t)bytesCount, view.size());

        memcpy(view.base(), data, bytesCount);
        work->input.buffers.clear();
        work->input.buffers.emplace_back(new LinearBuffer(block));
        work->worklets.clear();
        work->worklets.emplace_back(new C2Worklet);
        free(data);

        std::list<std::unique_ptr<C2Work>> items;
        items.push_back(std::move(work));

        // DO THE DECODING
        ASSERT_EQ(component->queue(&items), C2_OK);
        ALOGV("Frame #%d size = %d queued", frameID, bytesCount);
        nFrames--;
        timestamp += timestampIncr;
        frameID++;
        maxRetry = 0;
    }
}

TEST_P(Codec2AudioEncHidlTest, validateCompName) {
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";
    ALOGV("Checks if the given component is a valid audio component");
    validateComponent(mComponent, mDisableTest);
    ASSERT_EQ(mDisableTest, false);
}

class Codec2AudioEncEncodeTest : public Codec2AudioEncHidlTestBase,
                                 public ::testing::WithParamInterface<EncodeTestParameters> {
    void getParams() {
        mInstanceName = std::get<0>(GetParam());
        mComponentName = std::get<1>(GetParam());
    }
};

TEST_P(Codec2AudioEncEncodeTest, EncodeTest) {
    ALOGV("EncodeTest");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";
    bool signalEOS = std::get<2>(GetParam());
    // Set samples per frame based on inputMaxBufRatio if component does not
    // advertise supported frame size
    if (!mEncoderFrameSize) {
        // Ratio w.r.t to mInputMaxBufSize
        int32_t inputMaxBufRatio = std::get<3>(GetParam());
        mSamplesPerFrame = ((mInputMaxBufSize / inputMaxBufRatio) / (mNumChannels * 2));
    }
    ALOGV("signalEOS %d mInputMaxBufSize %d mSamplesPerFrame %d", signalEOS, mInputMaxBufSize,
          mSamplesPerFrame);

    ASSERT_TRUE(setupConfigParam(mComponent, mNumChannels, mSampleRate))
            << "Unable to configure for channels: " << mNumChannels << " and sampling rate "
            << mSampleRate;

    ASSERT_EQ(mComponent->start(), C2_OK);
    std::ifstream eleStream;
    uint32_t numFrames = 16;
    eleStream.open(mInputFile, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true);
    ASSERT_NO_FATAL_FAILURE(encodeNFrames(
            mComponent, mQueueLock, mQueueCondition, mWorkQueue, mFlushedIndices, mLinearPool,
            eleStream, numFrames, mSamplesPerFrame, mNumChannels, mSampleRate, false, signalEOS));

    // If EOS is not sent, sending empty input with EOS flag
    if (!signalEOS) {
        waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue, 1);
        ASSERT_NO_FATAL_FAILURE(testInputBuffer(mComponent, mQueueLock, mWorkQueue,
                                                C2FrameData::FLAG_END_OF_STREAM, false));
        numFrames += 1;
    }

    // blocking call to ensures application to Wait till all the inputs are
    // consumed
    waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue);
    eleStream.close();
    if (mFramesReceived != numFrames) {
        ALOGE("Input buffer count and Output buffer count mismatch");
        ALOGE("framesReceived : %d inputFrames : %u", mFramesReceived, numFrames);
        ASSERT_TRUE(false);
    }
    if ((mMime.find("flac") != std::string::npos) || (mMime.find("opus") != std::string::npos) ||
        (mMime.find("mp4a-latm") != std::string::npos)) {
        ASSERT_TRUE(mCsd) << "CSD buffer missing";
    }
    ASSERT_EQ(mEos, true);
    ASSERT_EQ(mComponent->stop(), C2_OK);
    ASSERT_EQ(mWorkResult, C2_OK);
}

TEST_P(Codec2AudioEncHidlTest, EOSTest) {
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
    ASSERT_EQ(mWorkResult, C2_OK);
}

TEST_P(Codec2AudioEncHidlTest, FlushTest) {
    description("Test Request for flush");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    mFlushedIndices.clear();

    ASSERT_TRUE(setupConfigParam(mComponent, mNumChannels, mSampleRate))
            << "Unable to configure for channels: " << mNumChannels << " and sampling rate "
            << mSampleRate;

    ASSERT_EQ(mComponent->start(), C2_OK);

    std::ifstream eleStream;
    uint32_t numFramesFlushed = 30;
    uint32_t numFrames = 128;
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
                                          mFlushedIndices, mLinearPool, eleStream, numFramesFlushed,
                                          mSamplesPerFrame, mNumChannels, mSampleRate));
    err = mComponent->flush(C2Component::FLUSH_COMPONENT, &flushedWork);
    ASSERT_EQ(err, C2_OK);
    waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue,
                           (size_t)MAX_INPUT_BUFFERS - flushedWork.size());
    ASSERT_NO_FATAL_FAILURE(
            verifyFlushOutput(flushedWork, mWorkQueue, mFlushedIndices, mQueueLock));
    ASSERT_EQ(mWorkQueue.size(), MAX_INPUT_BUFFERS);
    ASSERT_NO_FATAL_FAILURE(encodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                          mFlushedIndices, mLinearPool, eleStream,
                                          numFrames - numFramesFlushed, mSamplesPerFrame,
                                          mNumChannels, mSampleRate, true));
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

TEST_P(Codec2AudioEncHidlTest, MultiChannelCountTest) {
    description("Encodes input file for different channel count");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    int32_t numFrames = 16;
    int32_t maxChannelCount = 8;

    std::ifstream eleStream;
    eleStream.open(mInputFile, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true) << mInputFile << " file not found";

    uint64_t prevOutputSize = 0u;
    uint32_t prevChannelCount = 0u;

    // Looping through the maximum number of channel count supported by encoder
    for (int32_t nChannels = 1; nChannels < maxChannelCount; nChannels++) {
        ALOGV("Configuring encoder %s  for channel count = %d", mComponentName.c_str(), nChannels);
        if (!setupConfigParam(mComponent, nChannels, mSampleRate)) {
            std::cout << "[   WARN   ] Test Skipped \n";
            return;
        }

        std::vector<std::unique_ptr<C2Param>> inParams;
        c2_status_t c2_status = mComponent->query({}, {C2StreamChannelCountInfo::input::PARAM_TYPE},
                                                  C2_DONT_BLOCK, &inParams);
        ASSERT_EQ(c2_status, C2_OK) << "Query channel count info failed";
        ASSERT_EQ(inParams.size(), 1) << "Size of the vector returned is invalid";

        int32_t channelCount = C2StreamChannelCountInfo::input::From(inParams[0].get())->value;

        if (channelCount != nChannels) {
            std::cout << "[   WARN   ] Test Skipped for ChannelCount " << nChannels << "\n";
            continue;
        }

        // To check if the input stream is sufficient to encode for the higher channel count
        struct stat buf;
        stat(mInputFile.c_str(), &buf);
        size_t fileSize = buf.st_size;
        int32_t bytesCount = (mSamplesPerFrame * nChannels * 2) * numFrames;
        if (fileSize < bytesCount) {
            std::cout << "[   WARN   ] Test Skipped for ChannelCount " << nChannels
                      << " because of insufficient input data\n";
            continue;
        }

        ASSERT_EQ(mComponent->start(), C2_OK);

        ASSERT_NO_FATAL_FAILURE(encodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                              mFlushedIndices, mLinearPool, eleStream, numFrames,
                                              mSamplesPerFrame, nChannels, mSampleRate));

        // mDisableTest will be set if buffer was not fetched properly.
        // This may happen when config params is not proper but config succeeded
        // In this cases, we skip encoding the input stream
        if (mDisableTest) {
            std::cout << "[   WARN   ] Test Disabled for ChannelCount " << nChannels << "\n";
            ASSERT_EQ(mComponent->stop(), C2_OK);
            return;
        }

        // blocking call to ensures application to Wait till all the inputs are consumed
        waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue);

        prevChannelCount = nChannels;
        prevOutputSize = mOutputSize;

        if (mFramesReceived != numFrames) {
            ALOGE("Input buffer count and Output buffer count mismatch");
            ALOGE("framesReceived : %d inputFrames : %u", mFramesReceived, numFrames);
            ASSERT_TRUE(false);
        }
        if ((mMime.find("flac") != std::string::npos) ||
            (mMime.find("opus") != std::string::npos) ||
            (mMime.find("mp4a-latm") != std::string::npos)) {
            ASSERT_TRUE(mCsd) << "CSD buffer missing";
        }
        ASSERT_TRUE(mEos);
        // TODO(b/147348711) Use reset instead of stop when using the same instance of codec.
        ASSERT_EQ(mComponent->reset(), C2_OK);
        mFramesReceived = 0;
        mOutputSize = 0;
        mEos = false;
        mCsd = false;
        eleStream.seekg(0, eleStream.beg);
    }
}

TEST_P(Codec2AudioEncHidlTest, MultiSampleRateTest) {
    description("Encodes input file for different SampleRate");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    int32_t numFrames = 16;

    std::ifstream eleStream;
    eleStream.open(mInputFile, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true) << mInputFile << " file not found";

    int32_t sampleRateValues[] = {1000, 8000, 16000, 24000, 48000, 96000, 192000};

    uint64_t prevOutputSize = 0u;
    uint32_t prevSampleRate = 0u;

    for (int32_t nSampleRate : sampleRateValues) {
        ALOGV("Configuring encoder %s  for SampleRate = %d", mComponentName.c_str(), nSampleRate);
        if (!setupConfigParam(mComponent, mNumChannels, nSampleRate)) {
            std::cout << "[   WARN   ] Test Skipped \n";
            return;
        }

        std::vector<std::unique_ptr<C2Param>> inParams;
        c2_status_t c2_status = mComponent->query({}, {C2StreamSampleRateInfo::input::PARAM_TYPE},
                                                  C2_DONT_BLOCK, &inParams);
        ASSERT_EQ(c2_status, C2_OK) << "Query sample rate info failed";
        ASSERT_EQ(inParams.size(), 1) << "Size of the vector returned is invalid";

        int32_t configuredSampleRate =
                C2StreamSampleRateInfo::input::From(inParams[0].get())->value;
        if (configuredSampleRate != nSampleRate) {
            std::cout << "[   WARN   ] Test Skipped for SampleRate " << nSampleRate << "\n";
            continue;
        }

        // To check if the input stream is sufficient to encode for the higher SampleRate
        struct stat buf;
        stat(mInputFile.c_str(), &buf);
        size_t fileSize = buf.st_size;
        int32_t bytesCount = (mSamplesPerFrame * mNumChannels * 2) * numFrames;
        if (fileSize < bytesCount) {
            std::cout << "[   WARN   ] Test Skipped for SampleRate " << nSampleRate
                      << " because of insufficient input data\n";
            continue;
        }

        ASSERT_EQ(mComponent->start(), C2_OK);

        ASSERT_NO_FATAL_FAILURE(encodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                              mFlushedIndices, mLinearPool, eleStream, numFrames,
                                              mSamplesPerFrame, mNumChannels, nSampleRate));

        // mDisableTest will be set if buffer was not fetched properly.
        // This may happen when config params is not proper but config succeeded
        // In this case, we skip encoding the input stream
        if (mDisableTest) {
            std::cout << "[   WARN   ] Test Disabled for SampleRate" << nSampleRate << "\n";
            ASSERT_EQ(mComponent->stop(), C2_OK);
            return;
        }

        // blocking call to ensures application to Wait till all the inputs are consumed
        waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue);

        prevSampleRate = nSampleRate;
        prevOutputSize = mOutputSize;

        if (mFramesReceived != numFrames) {
            ALOGE("Input buffer count and Output buffer count mismatch");
            ALOGE("framesReceived : %d inputFrames : %u", mFramesReceived, numFrames);
            ASSERT_TRUE(false);
        }
        if ((mMime.find("flac") != std::string::npos) ||
            (mMime.find("opus") != std::string::npos) ||
            (mMime.find("mp4a-latm") != std::string::npos)) {
            ASSERT_TRUE(mCsd) << "CSD buffer missing";
        }
        ASSERT_TRUE(mEos);
        // TODO(b/147348711) Use reset instead of stop when using the same instance of codec.
        ASSERT_EQ(mComponent->reset(), C2_OK);
        mFramesReceived = 0;
        mOutputSize = 0;
        mEos = false;
        mCsd = false;
        eleStream.seekg(0, eleStream.beg);
    }
}

INSTANTIATE_TEST_SUITE_P(PerInstance, Codec2AudioEncHidlTest, testing::ValuesIn(gTestParameters),
                         PrintInstanceTupleNameToString<>);

// EncodeTest with EOS / No EOS and inputMaxBufRatio
// inputMaxBufRatio is ratio w.r.t. to mInputMaxBufSize
INSTANTIATE_TEST_SUITE_P(EncodeTest, Codec2AudioEncEncodeTest,
                         testing::ValuesIn(gEncodeTestParameters),
                         PrintInstanceTupleNameToString<>);

}  // anonymous namespace

int main(int argc, char** argv) {
    parseArgs(argc, argv);
    gTestParameters = getTestParameters(C2Component::DOMAIN_AUDIO, C2Component::KIND_ENCODER);
    for (auto params : gTestParameters) {
        gEncodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), false, 1));
        gEncodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), false, 2));
        gEncodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), true, 1));
        gEncodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), true, 2));
    }

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
