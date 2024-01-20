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
#define LOG_TAG "codec2_hidl_hal_audio_dec_test"

#include <android-base/logging.h>
#include <android/binder_process.h>
#include <gtest/gtest.h>
#include <hidl/GtestPrinter.h>
#include <stdio.h>
#include <algorithm>

#include <C2Buffer.h>
#include <C2BufferPriv.h>
#include <C2Config.h>
#include <C2Debug.h>
#include <codec2/aidl/ParamTypes.h>
#include <codec2/hidl/client.h>

#include "media_c2_hidl_test_common.h"

using DecodeTestParameters = std::tuple<std::string /*instance_name*/,
        std::string /*component_name*/,
        uint32_t /*stream_index*/,
        bool /*signal end-of-stream nor not*/>;
static std::vector<DecodeTestParameters> gDecodeTestParameters;

using CsdFlushTestParameters = std::tuple<std::string, std::string, bool>;
static std::vector<CsdFlushTestParameters> gCsdFlushTestParameters;

struct CompToFiles {
    std::string mime;
    std::string inputFile;
    std::string infoFile;
};

std::vector<CompToFiles> gCompToFiles = {
        {"mp4a-latm", "bbb_aac_stereo_128kbps_48000hz.aac", "bbb_aac_stereo_128kbps_48000hz.info"},
        {"mpeg", "bbb_mp3_stereo_192kbps_48000hz.mp3", "bbb_mp3_stereo_192kbps_48000hz.info"},
        {"3gpp", "sine_amrnb_1ch_12kbps_8000hz.amrnb", "sine_amrnb_1ch_12kbps_8000hz.info"},
        {"amr-wb", "bbb_amrwb_1ch_14kbps_16000hz.amrwb", "bbb_amrwb_1ch_14kbps_16000hz.info"},
        {"vorbis", "bbb_vorbis_stereo_128kbps_48000hz.vorbis",
         "bbb_vorbis_stereo_128kbps_48000hz.info"},
        {"opus", "bbb_opus_stereo_128kbps_48000hz.opus", "bbb_opus_stereo_128kbps_48000hz.info"},
        {"g711-alaw", "bbb_g711alaw_1ch_8khz.raw", "bbb_g711alaw_1ch_8khz.info"},
        {"g711-mlaw", "bbb_g711mulaw_1ch_8khz.raw", "bbb_g711mulaw_1ch_8khz.info"},
        {"gsm", "bbb_gsm_1ch_8khz_13kbps.raw", "bbb_gsm_1ch_8khz_13kbps.info"},
        {"raw", "bbb_raw_1ch_8khz_s32le.raw", "bbb_raw_1ch_8khz_s32le.info"},
        {"raw", "bbb_raw_1ch_8khz_s32le.raw", "bbb_raw_1ch_8khz_s32le_largeframe.info"},
        {"flac", "bbb_flac_stereo_680kbps_48000hz.flac", "bbb_flac_stereo_680kbps_48000hz.info"},
};

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
        mLinearPool = std::make_shared<C2PooledBlockPool>(mLinearAllocator, mBlockPoolId++,
                                                          getBufferPoolVer());
        ASSERT_NE(mLinearPool, nullptr);

        std::vector<std::unique_ptr<C2Param>> queried;
        c2_status_t c2err = mComponent->query({}, {C2PortMediaTypeSetting::input::PARAM_TYPE},
                                              C2_DONT_BLOCK, &queried);
        ASSERT_EQ(c2err, C2_OK) << "Query media type failed";
        ASSERT_EQ(queried.size(), 1) << "Size of the vector returned is invalid";

        mMime = ((C2PortMediaTypeSetting::input*)queried[0].get())->m.value;

        mEos = false;
        mFramesReceived = 0;
        mTimestampUs = 0u;
        mWorkResult = C2_OK;
        mTimestampDevTest = false;

        bool valid = getFileNames(mStreamIndex);
        if (!valid) {
            GTEST_SKIP() << "No test file for  mime " << mMime << " index: " << mStreamIndex;
        }
        ALOGV("mStreamIndex : %zu", mStreamIndex);
        ALOGV("mInputFile : %s", mInputFile.c_str());
        ALOGV("mInfoFile : %s", mInfoFile.c_str());

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

    bool getFileNames(size_t streamIndex = 0);

    struct outputMetaData {
        uint64_t timestampUs;
        uint32_t rangeLength;
        // The following is used only if C2AccessUnitInfos::output
        // is present as part of C2Buffer.
        std::vector<C2AccessUnitInfosStruct> largeFrameInfo;
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
                        outputMetaData meta = {mTimestampUs, rangeLength, {}};
                        oBufferMetaData.push_back(meta);
                        std::shared_ptr<const C2AccessUnitInfos::output> inBufferInfo =
                                std::static_pointer_cast<const C2AccessUnitInfos::output>(
                                work->worklets.front()->output.buffers[0]->getInfo(
                                C2AccessUnitInfos::output::PARAM_TYPE));
                        if (inBufferInfo) {
                            for (int nMeta = 0; nMeta < inBufferInfo->flexCount(); nMeta++) {
                                oBufferMetaData.back().largeFrameInfo.push_back(
                                        inBufferInfo->m.values[nMeta]);
                            }
                        }
                    }
                }
                bool mCsd = false;
                workDone(mComponent, work, mFlushedIndices, mQueueLock, mQueueCondition, mWorkQueue,
                         mEos, mCsd, mFramesReceived);
                (void)mCsd;
            }
        }
    }

    std::string mMime;
    std::string mInstanceName;
    std::string mComponentName;
    bool mEos;
    bool mDisableTest;
    bool mTimestampDevTest;

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

    std::string mInputFile;
    std::string mInfoFile;
    size_t mStreamIndex = 0;

    // These are used only with large frame codec
    // Specifies the maximum output size in bytes.
    uint32_t mMaxOutputSize;
    //Specifies the threshold output size in bytes.
    uint32_t mOutputThresholdSize;

  protected:
    static void description(const std::string& description) {
        RecordProperty("description", description);
    }
};

class Codec2AudioDecHidlTest : public Codec2AudioDecHidlTestBase,
                               public ::testing::WithParamInterface<TestParameters> {
    void getParams() {
        mInstanceName = std::get<0>(GetParam());
        mComponentName = std::get<1>(GetParam());
        mStreamIndex = 0;
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
    ALOGV("Component Valid");
}

bool isLargeAudioFrameSupported(const std::shared_ptr<android::Codec2Client::Component> &comp,
        std::vector<C2FieldSupportedValues>& supportedValues) {
    C2LargeFrame::output largeFrameParams;
    std::vector<C2FieldSupportedValuesQuery> validValueInfos = {
            C2FieldSupportedValuesQuery::Current(
                    C2ParamField(&largeFrameParams, &C2LargeFrame::maxSize)),
            C2FieldSupportedValuesQuery::Current(
                    C2ParamField(&largeFrameParams,
                            &C2LargeFrame::thresholdSize))};
    c2_status_t c2err = comp->querySupportedValues(validValueInfos, C2_DONT_BLOCK);
    if (c2err != C2_OK || validValueInfos.size() != 2) {
        return false;
    }
    supportedValues.clear();
    for (int i = 0; i < 2; i++) {
        if (validValueInfos[i].values.type == C2FieldSupportedValues::EMPTY) {
            return false;
        }
        supportedValues.push_back(validValueInfos[i].values);
    }
    return true;
}

c2_status_t configureLargeFrameParams(const std::shared_ptr<android::Codec2Client::Component> &comp,
        uint32_t& maxOutput, uint32_t& outputThreshold,
        const std::vector<C2FieldSupportedValues>& supportedValues) {

    if (supportedValues.empty()) {
        ALOGE("Error: No supported values in large audio frame params");
        return C2_BAD_VALUE;
    }

    auto boundBySupportedValues = [](const C2FieldSupportedValues& supportedValues, uint32_t& value)
            -> c2_status_t {
        uint32_t oBufMin = 0, oBufMax = 0;
        switch (supportedValues.type) {
            case C2FieldSupportedValues::type_t::RANGE:
            {
                const auto& range = supportedValues.range;
                oBufMax = (uint32_t)(range.max).ref<uint32_t>();
                oBufMin = (uint32_t)(range.min).ref<uint32_t>();
                value = (value > oBufMax) ? oBufMax :
                        (value < oBufMin) ? oBufMin : value;
                break;
            }

            case C2FieldSupportedValues::type_t::VALUES:
            {
                uint32_t lastValue;
                for (const C2Value::Primitive& prim : supportedValues.values) {
                    lastValue = (uint32_t)prim.ref<uint32_t>();
                    if (lastValue > value) {
                        value = lastValue;
                        break;
                    }
                }
                if (value > lastValue) {
                    value = lastValue;
                }
                break;
            }

            default:
                return C2_BAD_VALUE;
            }
        return C2_OK;
    };
    c2_status_t c2_err = boundBySupportedValues(supportedValues[0], maxOutput);
    if (c2_err != C2_OK) {
        return c2_err;
    }
    c2_err = boundBySupportedValues(supportedValues[1], outputThreshold);
    if (c2_err != C2_OK) {
        return c2_err;
    }
    if (outputThreshold > maxOutput) {
        outputThreshold = maxOutput;
    }
    ALOGV("Setting large frame format : Max: %d - Threshold: %d", maxOutput, outputThreshold);
    std::vector<std::unique_ptr<C2SettingResult>> failures;
    C2LargeFrame::output largeFrameParams(0u, maxOutput, outputThreshold);
    std::vector<C2Param*> configParam{&largeFrameParams};
    c2_status_t status = comp->config(configParam, C2_DONT_BLOCK, &failures);
    if (status != C2_OK || failures.size() != 0u) {
        ALOGE("Large frame Audio configuration failed for maxSize: %d, thresholdSize: %d",
                maxOutput, outputThreshold);
    }
    return status;
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
                         std::string mime, int32_t* bitStreamInfo) {
    // query nSampleRate and nChannels
    std::initializer_list<C2Param::Index> indices{
            C2StreamSampleRateInfo::output::PARAM_TYPE,
            C2StreamChannelCountInfo::output::PARAM_TYPE,
    };
    std::vector<std::unique_ptr<C2Param>> inParams;
    c2_status_t status = component->query({}, indices, C2_DONT_BLOCK, &inParams);
    ASSERT_EQ(status, C2_OK) << "Query sample rate and channel count info failed";
    ASSERT_EQ(inParams.size(), indices.size()) << "Size of the vector returned is invalid";

    bitStreamInfo[0] = C2StreamSampleRateInfo::output::From(inParams[0].get())->value;
    bitStreamInfo[1] = C2StreamChannelCountInfo::output::From(inParams[1].get())->value;
    if (mime.find("3gpp") != std::string::npos) {
        ASSERT_EQ(bitStreamInfo[0], 8000);
        ASSERT_EQ(bitStreamInfo[1], 1);
    } else if (mime.find("amr-wb") != std::string::npos) {
        ASSERT_EQ(bitStreamInfo[0], 16000);
        ASSERT_EQ(bitStreamInfo[1], 1);
    } else if (mime.find("gsm") != std::string::npos) {
        ASSERT_EQ(bitStreamInfo[0], 8000);
        ASSERT_EQ(bitStreamInfo[1], 1);
    }
}

// LookUpTable of clips and metadata for component testing
bool Codec2AudioDecHidlTestBase::getFileNames(size_t streamIndex) {
    int streamCount = 0;

    for (size_t i = 0; i < gCompToFiles.size(); ++i) {
        if (!mMime.compare("audio/" + gCompToFiles[i].mime)) {
            if (streamCount == streamIndex) {
                mInputFile = sResourceDir + gCompToFiles[i].inputFile;
                mInfoFile = sResourceDir + gCompToFiles[i].infoFile;
                return true;
            }
            streamCount++;
        }
    }
    return false;
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
    std::shared_ptr<C2Buffer> buffer;
    std::vector<C2FieldSupportedValues> largeFrameValues;
    bool isComponentSupportsLargeAudioFrame = isLargeAudioFrameSupported(component,
            largeFrameValues);
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
        flags = ((*Info)[frameID].vtsFlags & (1 << VTS_BIT_FLAG_CSD_FRAME))
                        ? C2FrameData::FLAG_CODEC_CONFIG
                        : 0;
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

            buffer.reset(new LinearBuffer(block));
            if (!(*Info)[frameID].largeFrameInfo.empty() && isComponentSupportsLargeAudioFrame) {
                const std::vector<C2AccessUnitInfosStruct>& meta =
                        (*Info)[frameID].largeFrameInfo;
                ALOGV("Large Audio frame supported for %s, frameID: %d, size: %zu",
                        component->getName().c_str(), frameID, meta.size());
                const std::shared_ptr<C2AccessUnitInfos::input> largeFrame =
                        C2AccessUnitInfos::input::AllocShared(meta.size(), 0u, meta);
                buffer->setInfo(largeFrame);
            }
            work->input.buffers.push_back(buffer);
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
    ASSERT_NO_FATAL_FAILURE(getInputChannelInfo(mComponent, mMime, bitStreamInfo));
    int32_t nSampleRate = bitStreamInfo[0];
    int32_t nChannels = bitStreamInfo[1];
    std::list<uint64_t>::iterator itIn = mTimestampUslist.begin();
    auto itOut = oBufferMetaData.begin();
    EXPECT_EQ(*itIn, itOut->timestampUs);
    uint64_t expectedTimeStamp = *itIn;
    bool err= false;
    while (!err && itOut != oBufferMetaData.end()) {
        EXPECT_EQ(expectedTimeStamp, itOut->timestampUs);
        if (expectedTimeStamp != itOut->timestampUs) break;
        if (!itOut->largeFrameInfo.empty()) {
            // checking large audio frame metadata
            if (itOut->largeFrameInfo[0].timestamp != itOut->timestampUs) {
                ALOGE("Metadata first time stamp doesn't match");
                err = true;
                break;
            }
            uint64_t totalSize = 0;
            uint64_t sampleSize = 0;
            int64_t nextTimestamp = itOut->timestampUs;
            for (auto& meta : itOut->largeFrameInfo) {
                if (nextTimestamp != meta.timestamp) {
                    ALOGE("Metadata timestamp error: expect: %lld, got: %lld",
                            (long long)nextTimestamp, (long long)meta.timestamp);
                    err = true;
                    break;
                }
                totalSize += meta.size;
                sampleSize = (meta.size / (nChannels * 2));
                nextTimestamp += sampleSize * 1000000ll / nSampleRate;
            }
            if (totalSize != itOut->rangeLength) {
                ALOGE("Metadata size error: expected:%lld, got: %d",
                        (long long)totalSize, itOut->rangeLength);
                err = true;
            }
        }
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
    validateComponent(mComponent, mDisableTest);
    ASSERT_EQ(mDisableTest, false);
}

TEST_P(Codec2AudioDecHidlTest, configComp) {
    description("Tests component specific configuration");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";
    ASSERT_EQ(mComponent->start(), C2_OK);
    int32_t bitStreamInfo[2] = {0};
    ASSERT_NO_FATAL_FAILURE(getInputChannelInfo(mComponent, mMime, bitStreamInfo));
    setupConfigParam(mComponent, bitStreamInfo);
    ASSERT_EQ(mComponent->stop(), C2_OK);
}

class Codec2AudioDecDecodeTest : public Codec2AudioDecHidlTestBase,
                                 public ::testing::WithParamInterface<DecodeTestParameters> {
    void getParams() {
        mInstanceName = std::get<0>(GetParam());
        mComponentName = std::get<1>(GetParam());
        mStreamIndex = std::get<2>(GetParam());
    }
};

TEST_P(Codec2AudioDecDecodeTest, DecodeTest) {
    description("Decodes input file");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    bool signalEOS = std::get<3>(GetParam());
    mTimestampDevTest = true;
    android::Vector<FrameInfo> Info;

    int32_t numCsds = populateInfoVector(mInfoFile, &Info, mTimestampDevTest, &mTimestampUslist);
    ASSERT_GE(numCsds, 0) << "Error in parsing input info file: " << mInfoFile <<
            " #CSD " << numCsds;

    // Reset total no of frames received
    mFramesReceived = 0;
    mTimestampUs = 0;
    int32_t bitStreamInfo[2] = {0};
    if (mMime.find("raw") != std::string::npos) {
        bitStreamInfo[0] = 8000;
        bitStreamInfo[1] = 1;
    } else if ((mMime.find("g711-alaw") != std::string::npos) ||
               (mMime.find("g711-mlaw") != std::string::npos)) {
        // g711 test data is all 1-channel and has no embedded config info.
        bitStreamInfo[0] = 8000;
        bitStreamInfo[1] = 1;
    } else {
        ASSERT_NO_FATAL_FAILURE(getInputChannelInfo(mComponent, mMime, bitStreamInfo));
    }
    if (!setupConfigParam(mComponent, bitStreamInfo)) {
        std::cout << "[   WARN   ] Test Skipped \n";
        return;
    }
    getInputChannelInfo(mComponent, mMime, bitStreamInfo);
    std::vector<C2FieldSupportedValues> supportedValues;
    if (!Info.top().largeFrameInfo.empty()) {
        if (!isLargeAudioFrameSupported(mComponent, supportedValues)) {
            GTEST_SKIP() << "As component does not support large frame";
        }
        // time_sec * sample_rate * channel_count * 2 (bytes_per_channel)
        mMaxOutputSize = 60 * bitStreamInfo[0] * bitStreamInfo[1] * 2;
        mOutputThresholdSize = 50 * bitStreamInfo[0] * bitStreamInfo[1] * 2;
        ASSERT_EQ(configureLargeFrameParams(mComponent, mMaxOutputSize,
                mOutputThresholdSize, supportedValues), C2_OK);
    }
    ASSERT_EQ(mComponent->start(), C2_OK);
    std::ifstream eleStream;
    eleStream.open(mInputFile, std::ifstream::binary);
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

    android::Vector<FrameInfo> Info;

    int32_t numCsds = populateInfoVector(mInfoFile, &Info, mTimestampDevTest, &mTimestampUslist);
    ASSERT_GE(numCsds, 0) << "Error in parsing input info file: " << mInfoFile;

    int32_t bitStreamInfo[2] = {0};
    if (mMime.find("raw") != std::string::npos) {
        bitStreamInfo[0] = 8000;
        bitStreamInfo[1] = 1;
    } else {
        ASSERT_NO_FATAL_FAILURE(getInputChannelInfo(mComponent, mMime, bitStreamInfo));
    }
    if (!setupConfigParam(mComponent, bitStreamInfo)) {
        std::cout << "[   WARN   ] Test Skipped \n";
        return;
    }
    getInputChannelInfo(mComponent, mMime, bitStreamInfo);
    std::vector<C2FieldSupportedValues> supportedValues;
    if (!Info.top().largeFrameInfo.empty()) {
        if (!isLargeAudioFrameSupported(mComponent, supportedValues)) {
            GTEST_SKIP() << "As component does not support large frame";
        }
        // time_sec * sample_rate * channel_count * 2 (bytes_per_channel)
        mMaxOutputSize = 60 * bitStreamInfo[0] * bitStreamInfo[1] * 2;
        mOutputThresholdSize = 50 * bitStreamInfo[0] * bitStreamInfo[1] * 2;
        ASSERT_EQ(configureLargeFrameParams(mComponent, mMaxOutputSize,
                mOutputThresholdSize, supportedValues), C2_OK);
    }
    ASSERT_EQ(mComponent->start(), C2_OK);

    // request EOS for thumbnail
    // signal EOS flag with last frame
    size_t i;
    for (i = 0; i < Info.size(); i++) {
        if (Info[i].vtsFlags & (1 << VTS_BIT_FLAG_SYNC_FRAME)) break;
    }
    std::ifstream eleStream;
    eleStream.open(mInputFile, std::ifstream::binary);
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
    android::Vector<FrameInfo> Info;

    int32_t numCsds = populateInfoVector(mInfoFile, &Info, mTimestampDevTest, &mTimestampUslist);
    ASSERT_GE(numCsds, 0) << "Error in parsing input info file: " << mInfoFile;

    int32_t bitStreamInfo[2] = {0};
    if (mMime.find("raw") != std::string::npos) {
        bitStreamInfo[0] = 8000;
        bitStreamInfo[1] = 1;
    } else {
        ASSERT_NO_FATAL_FAILURE(getInputChannelInfo(mComponent, mMime, bitStreamInfo));
    }
    if (!setupConfigParam(mComponent, bitStreamInfo)) {
        std::cout << "[   WARN   ] Test Skipped \n";
        return;
    }
    getInputChannelInfo(mComponent, mMime, bitStreamInfo);
    std::vector<C2FieldSupportedValues> supportedValues;
    if (!Info.top().largeFrameInfo.empty()) {
        if (!isLargeAudioFrameSupported(mComponent, supportedValues)) {
            GTEST_SKIP() << "As component does not support large frame";
        }
        // time_sec * sample_rate * channel_count * 2 (bytes_per_channel)
        mMaxOutputSize = 60 * bitStreamInfo[0] * bitStreamInfo[1] * 2;
        mOutputThresholdSize = 50 * bitStreamInfo[0] * bitStreamInfo[1] * 2;
        ASSERT_EQ(configureLargeFrameParams(mComponent, mMaxOutputSize,
                mOutputThresholdSize, supportedValues), C2_OK);
    }
    ASSERT_EQ(mComponent->start(), C2_OK);
    // flush
    std::list<std::unique_ptr<C2Work>> flushedWork;
    c2_status_t err = mComponent->flush(C2Component::FLUSH_COMPONENT, &flushedWork);
    ASSERT_EQ(err, C2_OK);
    ASSERT_NO_FATAL_FAILURE(
            verifyFlushOutput(flushedWork, mWorkQueue, mFlushedIndices, mQueueLock));
    ASSERT_EQ(mWorkQueue.size(), MAX_INPUT_BUFFERS);

    std::ifstream eleStream;
    eleStream.open(mInputFile, std::ifstream::binary);
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
    while (index < (int)Info.size()) {
        if (Info[index].vtsFlags & (1 << VTS_BIT_FLAG_SYNC_FRAME)) {
            keyFrame = true;
            break;
        }
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

    std::ifstream eleStream, eleInfo;

    eleInfo.open(mInfoFile);
    ASSERT_EQ(eleInfo.is_open(), true) << mInputFile << " - file not found";
    android::Vector<FrameInfo> Info;
    int bytesCount = 0;
    uint32_t frameId = 0;
    uint32_t flags = 0;
    uint32_t vtsFlags = 0;
    uint32_t timestamp = 0;
    uint32_t nLargeFrames = 0;
    bool codecConfig = false;
    // This test introduces empty CSD after every 20th frame
    // and empty input frames at an interval of 5 frames.
    while (1) {
        if (!(frameId % 5)) {
            vtsFlags = !(frameId % 20) ? (1 << VTS_BIT_FLAG_CSD_FRAME) : 0;
            bytesCount = 0;
            Info.push_back({bytesCount, vtsFlags, timestamp, {}});
        } else {
            if (!(eleInfo >> bytesCount)) break;
            eleInfo >> flags;
            vtsFlags = mapInfoFlagstoVtsFlags(flags);
            ASSERT_NE(vtsFlags, 0xFF) << "unrecognized flag entry in info file: " << mInfoFile;
            eleInfo >> timestamp;
            codecConfig = (vtsFlags & (1 << VTS_BIT_FLAG_CSD_FRAME)) != 0;
            Info.push_back({bytesCount, vtsFlags, timestamp, {}});
            if ((vtsFlags & (1 << VTS_BIT_FLAG_LARGE_AUDIO_FRAME)) != 0) {
                eleInfo >> nLargeFrames;
                // this is a large audio frame.
                while(nLargeFrames-- > 0) {
                    eleInfo >> bytesCount;
                    eleInfo >> flags;
                    eleInfo >> timestamp;
                    vtsFlags = mapInfoFlagstoVtsFlags(flags);
                    Info.editItemAt(Info.size() - 1).largeFrameInfo.push_back(
                            {(uint32_t)bytesCount, vtsFlags, timestamp});
                }
            }
        }
        frameId++;
    }
    eleInfo.close();
    int32_t bitStreamInfo[2] = {0};
    if (mMime.find("raw") != std::string::npos) {
        bitStreamInfo[0] = 8000;
        bitStreamInfo[1] = 1;
    } else {
        ASSERT_NO_FATAL_FAILURE(getInputChannelInfo(mComponent, mMime, bitStreamInfo));
    }
    if (!setupConfigParam(mComponent, bitStreamInfo)) {
        std::cout << "[   WARN   ] Test Skipped \n";
        return;
    }
    getInputChannelInfo(mComponent, mMime, bitStreamInfo);
    std::vector<C2FieldSupportedValues> supportedValues;
    if (!Info.top().largeFrameInfo.empty()) {
        if (!isLargeAudioFrameSupported(mComponent, supportedValues)) {
            GTEST_SKIP() << "As component does not support large frame";
        }
        // time_sec * sample_rate * channel_count * 2 (bytes_per_channel)
        mMaxOutputSize = 60 * bitStreamInfo[0] * bitStreamInfo[1] * 2;
        mOutputThresholdSize = 50 * bitStreamInfo[0] * bitStreamInfo[1] * 2;
        ASSERT_EQ(configureLargeFrameParams(mComponent, mMaxOutputSize,
                mOutputThresholdSize, supportedValues), C2_OK);
    }
    ASSERT_EQ(mComponent->start(), C2_OK);
    eleStream.open(mInputFile, std::ifstream::binary);
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

class Codec2AudioDecCsdInputTests : public Codec2AudioDecHidlTestBase,
                                    public ::testing::WithParamInterface<CsdFlushTestParameters> {
    void getParams() {
        mInstanceName = std::get<0>(GetParam());
        mComponentName = std::get<1>(GetParam());
        mStreamIndex = 0;
    }
};

// Test the codecs for the following
// start - csd - data… - (with/without)flush - data… - flush - data…
TEST_P(Codec2AudioDecCsdInputTests, CSDFlushTest) {
    description("Tests codecs for flush at different states");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    android::Vector<FrameInfo> Info;

    int32_t numCsds = populateInfoVector(mInfoFile, &Info, mTimestampDevTest, &mTimestampUslist);
    ASSERT_GE(numCsds, 0) << "Error in parsing input info file";

    int32_t bitStreamInfo[2] = {0};
    if (mMime.find("raw") != std::string::npos) {
        bitStreamInfo[0] = 8000;
        bitStreamInfo[1] = 1;
    } else {
        ASSERT_NO_FATAL_FAILURE(getInputChannelInfo(mComponent, mMime, bitStreamInfo));
    }
    if (!setupConfigParam(mComponent, bitStreamInfo)) {
        std::cout << "[   WARN   ] Test Skipped \n";
        return;
    }
    getInputChannelInfo(mComponent, mMime, bitStreamInfo);
    std::vector<C2FieldSupportedValues> supportedValues;
    if (!Info.top().largeFrameInfo.empty()) {
        if (!isLargeAudioFrameSupported(mComponent, supportedValues)) {
            GTEST_SKIP() << "As component does not support large frame";
        }
        // time_sec * sample_rate * channel_count * 2 (bytes_per_channel)
        mMaxOutputSize = 60 * bitStreamInfo[0] * bitStreamInfo[1] * 2;
        mOutputThresholdSize = 50 * bitStreamInfo[0] * bitStreamInfo[1] * 2;
        ASSERT_EQ(configureLargeFrameParams(mComponent, mMaxOutputSize,
                mOutputThresholdSize, supportedValues), C2_OK);
    }
    ASSERT_EQ(mComponent->start(), C2_OK);
    std::ifstream eleStream;
    eleStream.open(mInputFile, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true);

    bool signalEOS = false;
    bool flushCsd = std::get<2>(GetParam());
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

INSTANTIATE_TEST_SUITE_P(PerInstance, Codec2AudioDecHidlTest, testing::ValuesIn(gTestParameters),
                         PrintInstanceTupleNameToString<>);

// DecodeTest with StreamIndex and EOS / No EOS
INSTANTIATE_TEST_SUITE_P(StreamIndexAndEOS, Codec2AudioDecDecodeTest,
                         testing::ValuesIn(gDecodeTestParameters),
                         PrintInstanceTupleNameToString<>);

INSTANTIATE_TEST_SUITE_P(CsdInputs, Codec2AudioDecCsdInputTests,
                         testing::ValuesIn(gCsdFlushTestParameters),
                         PrintInstanceTupleNameToString<>);

}  // anonymous namespace

int main(int argc, char** argv) {
    parseArgs(argc, argv);
    gTestParameters = getTestParameters(C2Component::DOMAIN_AUDIO, C2Component::KIND_DECODER);
    for (auto params : gTestParameters) {
        gDecodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), 0, false));
        gDecodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), 0, true));
        gDecodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), 1, false));
        gDecodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), 1, true));

        gCsdFlushTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), true));
        gCsdFlushTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), false));
    }

    ::testing::InitGoogleTest(&argc, argv);
    ABinderProcess_startThreadPool();
    return RUN_ALL_TESTS();
}