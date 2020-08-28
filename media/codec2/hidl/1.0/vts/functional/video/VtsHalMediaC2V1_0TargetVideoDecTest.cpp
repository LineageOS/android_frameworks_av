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
#define LOG_TAG "codec2_hidl_hal_video_dec_test"

#include <android-base/logging.h>
#include <gtest/gtest.h>
#include <hidl/GtestPrinter.h>
#include <stdio.h>

#include <openssl/md5.h>

#include <C2AllocatorIon.h>
#include <C2Buffer.h>
#include <C2BufferPriv.h>
#include <C2Config.h>
#include <C2Debug.h>
#include <codec2/hidl/client.h>
#include <gui/BufferQueue.h>
#include <gui/IConsumerListener.h>
#include <gui/IProducerListener.h>
#include <system/window.h>

using android::C2AllocatorIon;

#include "media_c2_hidl_test_common.h"
#include "media_c2_video_hidl_test_common.h"

static std::vector<std::tuple<std::string, std::string, std::string, std::string>>
        kDecodeTestParameters;

static std::vector<std::tuple<std::string, std::string, std::string>> kCsdFlushTestParameters;

// Resource directory
static std::string sResourceDir = "";

class LinearBuffer : public C2Buffer {
  public:
    explicit LinearBuffer(const std::shared_ptr<C2LinearBlock>& block)
        : C2Buffer({block->share(block->offset(), block->size(), ::C2Fence())}) {}

    explicit LinearBuffer(const std::shared_ptr<C2LinearBlock>& block, size_t size)
        : C2Buffer({block->share(block->offset(), size, ::C2Fence())}) {}
};

namespace {

class Codec2VideoDecHidlTestBase : public ::testing::Test {
  public:
    // google.codec2 Video test setup
    virtual void SetUp() override {
        getParams();
        mDisableTest = false;
        ALOGV("Codec2VideoDecHidlTest SetUp");
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
                {"h263", h263}, {"avc", avc}, {"mpeg2", mpeg2}, {"mpeg4", mpeg4},
                {"hevc", hevc}, {"vp8", vp8}, {"vp9", vp9},     {"av1", av1},
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
        mReorderDepth = -1;
        mTimestampDevTest = false;
        mMd5Offset = 0;
        mMd5Enable = false;
        mRefMd5 = nullptr;
        if (mCompName == unknown_comp) mDisableTest = true;

        C2SecureModeTuning secureModeTuning{};
        mComponent->query({&secureModeTuning}, {}, C2_MAY_BLOCK, nullptr);
        if (secureModeTuning.value == C2Config::SM_READ_PROTECTED) {
            mDisableTest = true;
        }

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

    /* Calculate the CKSUM for the data in inbuf */
    void calc_md5_cksum(uint8_t* pu1_inbuf, uint32_t u4_stride, uint32_t u4_width,
                        uint32_t u4_height, uint8_t* pu1_cksum_p) {
        int32_t row;
        MD5_CTX s_md5_context;
        MD5_Init(&s_md5_context);
        for (row = 0; row < u4_height; row++) {
            MD5_Update(&s_md5_context, pu1_inbuf, u4_width);
            pu1_inbuf += u4_stride;
        }
        MD5_Final(pu1_cksum_p, &s_md5_context);
    }

    void compareMd5Chksm(std::unique_ptr<C2Work>& work) {
        uint8_t chksum[48];
        uint8_t* au1_y_chksum = chksum;
        uint8_t* au1_u_chksum = chksum + 16;
        uint8_t* au1_v_chksum = chksum + 32;
        const C2GraphicView output = work->worklets.front()
                                             ->output.buffers[0]
                                             ->data()
                                             .graphicBlocks()
                                             .front()
                                             .map()
                                             .get();
        uint8_t* yPlane = const_cast<uint8_t*>(output.data()[C2PlanarLayout::PLANE_Y]);
        uint8_t* uPlane = const_cast<uint8_t*>(output.data()[C2PlanarLayout::PLANE_U]);
        uint8_t* vPlane = const_cast<uint8_t*>(output.data()[C2PlanarLayout::PLANE_V]);
        C2PlanarLayout layout = output.layout();

        size_t yStride = layout.planes[C2PlanarLayout::PLANE_Y].rowInc;
        size_t uvStride = layout.planes[C2PlanarLayout::PLANE_U].rowInc;
        size_t colInc = layout.planes[C2PlanarLayout::PLANE_U].colInc;
        size_t bitDepth = layout.planes[C2PlanarLayout::PLANE_Y].bitDepth;
        uint32_t layoutType = layout.type;
        size_t cropWidth = output.crop().width;
        size_t cropHeight = output.crop().height;

        if (bitDepth == 8 && layoutType == C2PlanarLayout::TYPE_YUV && colInc == 1) {
            calc_md5_cksum(yPlane, yStride, cropWidth, cropHeight, au1_y_chksum);
            calc_md5_cksum(uPlane, uvStride, cropWidth / 2, cropHeight / 2, au1_u_chksum);
            calc_md5_cksum(vPlane, uvStride, cropWidth / 2, cropHeight / 2, au1_v_chksum);
        } else if (bitDepth == 8 && layoutType == C2PlanarLayout::TYPE_YUV && colInc == 2) {
            uint8_t* cbPlane = (uint8_t*)malloc(cropWidth * cropHeight / 4);
            uint8_t* crPlane = (uint8_t*)malloc(cropWidth * cropHeight / 4);
            ASSERT_NE(cbPlane, nullptr);
            ASSERT_NE(crPlane, nullptr);
            size_t count = 0;
            for (size_t k = 0; k < (cropHeight / 2); k++) {
                for (size_t l = 0; l < (cropWidth); l = l + 2) {
                    cbPlane[count] = uPlane[k * uvStride + l];
                    crPlane[count] = vPlane[k * uvStride + l];
                    count++;
                }
            }
            calc_md5_cksum(yPlane, yStride, cropWidth, cropHeight, au1_y_chksum);
            calc_md5_cksum(cbPlane, cropWidth / 2, cropWidth / 2, cropHeight / 2, au1_u_chksum);
            calc_md5_cksum(crPlane, cropWidth / 2, cropWidth / 2, cropHeight / 2, au1_v_chksum);
            free(cbPlane);
            free(crPlane);
        } else {
            mMd5Enable = false;
            ALOGV("Disabling MD5 chksm flag");
            return;
        }
        if (memcmp(mRefMd5 + mMd5Offset, chksum, 48)) ASSERT_TRUE(false);
        mMd5Offset += 48;
        return;
    }
    bool configPixelFormat(uint32_t format);

    // callback function to process onWorkDone received by Listener
    void handleWorkDone(std::list<std::unique_ptr<C2Work>>& workItems) {
        for (std::unique_ptr<C2Work>& work : workItems) {
            if (!work->worklets.empty()) {
                // For decoder components current timestamp always exceeds
                // previous timestamp if output is in display order
                typedef std::unique_lock<std::mutex> ULock;
                mWorkResult |= work->result;
                bool codecConfig = ((work->worklets.front()->output.flags &
                                     C2FrameData::FLAG_CODEC_CONFIG) != 0);
                if (!codecConfig && !work->worklets.front()->output.buffers.empty()) {
                    if (mReorderDepth < 0) {
                        C2PortReorderBufferDepthTuning::output reorderBufferDepth;
                        mComponent->query({&reorderBufferDepth}, {}, C2_MAY_BLOCK,
                                          nullptr);
                        mReorderDepth = reorderBufferDepth.value;
                        if (mReorderDepth > 0) {
                            // TODO: Add validation for reordered output
                            mTimestampDevTest = false;
                        }
                    }
                    if (mTimestampDevTest) {
                        EXPECT_GE((work->worklets.front()->output.ordinal.timestamp.peeku()),
                                  mTimestampUs);
                        mTimestampUs = work->worklets.front()->output.ordinal.timestamp.peeku();

                        ULock l(mQueueLock);
                        {
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
                    if (mMd5Enable) {
                        compareMd5Chksm(work);
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
        h263,
        avc,
        mpeg2,
        mpeg4,
        hevc,
        vp8,
        vp9,
        av1,
        unknown_comp,
    };

    std::string mInstanceName;
    std::string mComponentName;

    bool mEos;
    bool mDisableTest;
    bool mMd5Enable;
    bool mTimestampDevTest;
    uint64_t mTimestampUs;
    uint64_t mMd5Offset;
    char* mRefMd5;
    std::list<uint64_t> mTimestampUslist;
    std::list<uint64_t> mFlushedIndices;
    standardComp mCompName;

    int32_t mWorkResult;
    int32_t mReorderDepth;
    uint32_t mFramesReceived;
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

class Codec2VideoDecHidlTest
    : public Codec2VideoDecHidlTestBase,
      public ::testing::WithParamInterface<std::tuple<std::string, std::string>> {
    void getParams() {
        mInstanceName = std::get<0>(GetParam());
        mComponentName = std::get<1>(GetParam());
    }
};

void validateComponent(const std::shared_ptr<android::Codec2Client::Component>& component,
                       Codec2VideoDecHidlTest::standardComp compName, bool& disableTest) {
    // Validate its a C2 Component
    if (component->getName().find("c2") == std::string::npos) {
        ALOGE("Not a c2 component");
        disableTest = true;
        return;
    }

    // Validate its not an encoder and the component to be tested is video
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
        if (inputDomain.find("video/") == std::string::npos) {
            ALOGE("Expected Video Component");
            disableTest = true;
            return;
        }
    }

    // Validates component name
    if (compName == Codec2VideoDecHidlTest::unknown_comp) {
        ALOGE("Component InValid");
        disableTest = true;
        return;
    }
    ALOGV("Component Valid");
}

// number of elementary streams per component
#define STREAM_COUNT 3
// LookUpTable of clips, metadata and chksum for component testing
void GetURLChksmForComponent(Codec2VideoDecHidlTest::standardComp comp, char* mURL, char* info,
                             char* chksum, size_t streamIndex = 1) {
    struct CompToURL {
        Codec2VideoDecHidlTest::standardComp comp;
        const char mURL[STREAM_COUNT][512];
        const char info[STREAM_COUNT][512];
        const char chksum[STREAM_COUNT][512];
    };
    ASSERT_TRUE(streamIndex < STREAM_COUNT);

    static const CompToURL kCompToURL[] = {
            {Codec2VideoDecHidlTest::standardComp::avc,
             {"bbb_avc_176x144_300kbps_60fps.h264", "bbb_avc_640x360_768kbps_30fps.h264", ""},
             {"bbb_avc_176x144_300kbps_60fps.info", "bbb_avc_640x360_768kbps_30fps.info", ""},
             {"bbb_avc_176x144_300kbps_60fps_chksum.md5",
              "bbb_avc_640x360_768kbps_30fps_chksum.md5", ""}},
            {Codec2VideoDecHidlTest::standardComp::hevc,
             {"bbb_hevc_176x144_176kbps_60fps.hevc", "bbb_hevc_640x360_1600kbps_30fps.hevc", ""},
             {"bbb_hevc_176x144_176kbps_60fps.info", "bbb_hevc_640x360_1600kbps_30fps.info", ""},
             {"bbb_hevc_176x144_176kbps_60fps_chksum.md5",
              "bbb_hevc_640x360_1600kbps_30fps_chksum.md5", ""}},
            {Codec2VideoDecHidlTest::standardComp::mpeg2,
             {"bbb_mpeg2_176x144_105kbps_25fps.m2v", "bbb_mpeg2_352x288_1mbps_60fps.m2v", ""},
             {"bbb_mpeg2_176x144_105kbps_25fps.info", "bbb_mpeg2_352x288_1mbps_60fps.info", ""},
             {"", "", ""}},
            {Codec2VideoDecHidlTest::standardComp::h263,
             {"", "bbb_h263_352x288_300kbps_12fps.h263", ""},
             {"", "bbb_h263_352x288_300kbps_12fps.info", ""},
             {"", "", ""}},
            {Codec2VideoDecHidlTest::standardComp::mpeg4,
             {"", "bbb_mpeg4_352x288_512kbps_30fps.m4v", ""},
             {"", "bbb_mpeg4_352x288_512kbps_30fps.info", ""},
             {"", "", ""}},
            {Codec2VideoDecHidlTest::standardComp::vp8,
             {"bbb_vp8_176x144_240kbps_60fps.vp8", "bbb_vp8_640x360_2mbps_30fps.vp8", ""},
             {"bbb_vp8_176x144_240kbps_60fps.info", "bbb_vp8_640x360_2mbps_30fps.info", ""},
             {"", "bbb_vp8_640x360_2mbps_30fps_chksm.md5", ""}},
            {Codec2VideoDecHidlTest::standardComp::vp9,
             {"bbb_vp9_176x144_285kbps_60fps.vp9", "bbb_vp9_640x360_1600kbps_30fps.vp9",
              "bbb_vp9_704x480_280kbps_24fps_altref_2.vp9"},
             {"bbb_vp9_176x144_285kbps_60fps.info", "bbb_vp9_640x360_1600kbps_30fps.info",
              "bbb_vp9_704x480_280kbps_24fps_altref_2.info"},
             {"", "bbb_vp9_640x360_1600kbps_30fps_chksm.md5", ""}},
            {Codec2VideoDecHidlTest::standardComp::av1,
             {"bbb_av1_640_360.av1", "bbb_av1_176_144.av1", ""},
             {"bbb_av1_640_360.info", "bbb_av1_176_144.info", ""},
             {"bbb_av1_640_360_chksum.md5", "bbb_av1_176_144_chksm.md5", ""}},
    };

    for (size_t i = 0; i < sizeof(kCompToURL) / sizeof(kCompToURL[0]); ++i) {
        if (kCompToURL[i].comp == comp) {
            strcat(mURL, kCompToURL[i].mURL[streamIndex]);
            strcat(info, kCompToURL[i].info[streamIndex]);
            strcat(chksum, kCompToURL[i].chksum[streamIndex]);
            return;
        }
    }
}

void GetURLForComponent(Codec2VideoDecHidlTest::standardComp comp, char* mURL, char* info,
                        size_t streamIndex = 1) {
    char chksum[512];
    strcpy(chksum, sResourceDir.c_str());
    GetURLChksmForComponent(comp, mURL, info, chksum, streamIndex);
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
        if ((*Info)[frameID].flags) flags = (1 << ((*Info)[frameID].flags - 1));
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
        auto alignedSize = ALIGN(size, PAGE_SIZE);
        if (size) {
            std::shared_ptr<C2LinearBlock> block;
            ASSERT_EQ(C2_OK, linearPool->fetchLinearBlock(
                                     alignedSize,
                                     {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE}, &block));
            ASSERT_TRUE(block);

            // Write View
            C2WriteView view = block->map().get();
            if (view.error() != C2_OK) {
                fprintf(stderr, "C2LinearBlock::map() failed : %d", view.error());
                break;
            }
            ASSERT_EQ((size_t)alignedSize, view.capacity());
            ASSERT_EQ(0u, view.offset());
            ASSERT_EQ((size_t)alignedSize, view.size());

            memcpy(view.base(), data, size);

            work->input.buffers.emplace_back(new LinearBuffer(block, size));
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

TEST_P(Codec2VideoDecHidlTest, validateCompName) {
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";
    ALOGV("Checks if the given component is a valid video component");
    validateComponent(mComponent, mCompName, mDisableTest);
    ASSERT_EQ(mDisableTest, false);
}

TEST_P(Codec2VideoDecHidlTest, configureTunnel) {
    description("Attempts to configure tunneling");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";
    ALOGV("Checks if the component can be configured for tunneling");
    native_handle_t* sidebandStream{};
    c2_status_t err = mComponent->configureVideoTunnel(0, &sidebandStream);
    if (err == C2_OMITTED) {
        return;
    }

    using namespace android;
    sp<NativeHandle> nativeHandle = NativeHandle::create(sidebandStream, true);

    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);

    class DummyConsumerListener : public BnConsumerListener {
      public:
        DummyConsumerListener() : BnConsumerListener() {}
        void onFrameAvailable(const BufferItem&) override {}
        void onBuffersReleased() override {}
        void onSidebandStreamChanged() override {}
    };
    consumer->consumerConnect(new DummyConsumerListener(), false);

    class DummyProducerListener : public BnProducerListener {
      public:
        DummyProducerListener() : BnProducerListener() {}
        virtual void onBufferReleased() override {}
        virtual bool needsReleaseNotify() override { return false; }
        virtual void onBuffersDiscarded(const std::vector<int32_t>&) override {}
    };
    IGraphicBufferProducer::QueueBufferOutput qbo{};
    producer->connect(new DummyProducerListener(), NATIVE_WINDOW_API_MEDIA, false, &qbo);

    ASSERT_EQ(producer->setSidebandStream(nativeHandle), NO_ERROR);
}

// Config output pixel format
bool Codec2VideoDecHidlTestBase::configPixelFormat(uint32_t format) {
    std::vector<std::unique_ptr<C2SettingResult>> failures;
    C2StreamPixelFormatInfo::output pixelformat(0u, format);

    std::vector<C2Param*> configParam{&pixelformat};
    c2_status_t status = mComponent->config(configParam, C2_DONT_BLOCK, &failures);
    if (status == C2_OK && failures.size() == 0u) {
        return true;
    }
    return false;
}

class Codec2VideoDecDecodeTest
    : public Codec2VideoDecHidlTestBase,
      public ::testing::WithParamInterface<
              std::tuple<std::string, std::string, std::string, std::string>> {
    void getParams() {
        mInstanceName = std::get<0>(GetParam());
        mComponentName = std::get<1>(GetParam());
    }
};

// Bitstream Test
TEST_P(Codec2VideoDecDecodeTest, DecodeTest) {
    description("Decodes input file");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    uint32_t streamIndex = std::stoi(std::get<2>(GetParam()));
    bool signalEOS = !std::get<2>(GetParam()).compare("true");
    mTimestampDevTest = true;

    char mURL[512], info[512], chksum[512];
    android::Vector<FrameInfo> Info;

    strcpy(mURL, sResourceDir.c_str());
    strcpy(info, sResourceDir.c_str());
    strcpy(chksum, sResourceDir.c_str());

    GetURLChksmForComponent(mCompName, mURL, info, chksum, streamIndex);
    if (!(strcmp(mURL, sResourceDir.c_str())) || !(strcmp(info, sResourceDir.c_str()))) {
        ALOGV("Skipping Test, Stream not available");
        return;
    }
    mMd5Enable = true;
    if (!strcmp(chksum, sResourceDir.c_str())) mMd5Enable = false;

    uint32_t format = HAL_PIXEL_FORMAT_YCBCR_420_888;
    if (!configPixelFormat(format)) {
        std::cout << "[   WARN   ] Test Skipped PixelFormat not configured\n";
        return;
    }

    mFlushedIndices.clear();
    mTimestampUslist.clear();

    int32_t numCsds = populateInfoVector(info, &Info, mTimestampDevTest, &mTimestampUslist);
    ASSERT_GE(numCsds, 0) << "Error in parsing input info file: " << info;

    ASSERT_EQ(mComponent->start(), C2_OK);
    // Reset total no of frames received
    mFramesReceived = 0;
    mTimestampUs = 0;
    ALOGV("mURL : %s", mURL);
    std::ifstream eleStream;
    eleStream.open(mURL, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true);

    size_t refChksmSize = 0;
    std::ifstream refChksum;
    if (mMd5Enable) {
        ALOGV("chksum file name: %s", chksum);
        refChksum.open(chksum, std::ifstream::binary | std::ifstream::ate);
        ASSERT_EQ(refChksum.is_open(), true);
        refChksmSize = refChksum.tellg();
        refChksum.seekg(0, std::ifstream::beg);

        ALOGV("chksum Size %zu ", refChksmSize);
        mRefMd5 = (char*)malloc(refChksmSize);
        ASSERT_NE(mRefMd5, nullptr);
        refChksum.read(mRefMd5, refChksmSize);
        ASSERT_EQ(refChksum.gcount(), refChksmSize);
        refChksum.close();
    }

    ASSERT_NO_FATAL_FAILURE(decodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                          mFlushedIndices, mLinearPool, eleStream, &Info, 0,
                                          (int)Info.size(), signalEOS));

    // If EOS is not sent, sending empty input with EOS flag
    size_t infoSize = Info.size();
    if (!signalEOS) {
        waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue, 1);
        ASSERT_NO_FATAL_FAILURE(testInputBuffer(mComponent, mQueueLock, mWorkQueue,
                                                C2FrameData::FLAG_END_OF_STREAM, false));
        infoSize += 1;
    }
    // blocking call to ensures application to Wait till all the inputs are
    // consumed
    if (!mEos) {
        ALOGV("Waiting for input consumption");
        waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue);
    }

    eleStream.close();
    if (mFramesReceived != infoSize) {
        ALOGE("Input buffer count and Output buffer count mismatch");
        ALOGV("framesReceived : %d inputFrames : %zu", mFramesReceived, infoSize);
        ASSERT_TRUE(false);
    }

    if (mRefMd5 != nullptr) free(mRefMd5);
    if (mMd5Enable && refChksmSize != mMd5Offset) {
        ALOGE("refChksum size and generated chksum size mismatch refChksum size %zu generated "
              "chksum size %" PRId64 "",
              refChksmSize, mMd5Offset);
        ASSERT_TRUE(false);
    }

    if (mTimestampDevTest) EXPECT_EQ(mTimestampUslist.empty(), true);
    ASSERT_EQ(mComponent->stop(), C2_OK);
    ASSERT_EQ(mWorkResult, C2_OK);
}

// Adaptive Test
TEST_P(Codec2VideoDecHidlTest, AdaptiveDecodeTest) {
    description("Adaptive Decode Test");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";
    if (!(mCompName == avc || mCompName == hevc || mCompName == vp8 || mCompName == vp9 ||
          mCompName == mpeg2))
        return;

    typedef std::unique_lock<std::mutex> ULock;
    ASSERT_EQ(mComponent->start(), C2_OK);

    mTimestampDevTest = true;
    uint32_t timestampOffset = 0;
    uint32_t offset = 0;
    android::Vector<FrameInfo> Info;
    for (uint32_t i = 0; i < STREAM_COUNT * 2; i++) {
        char mURL[512], info[512];
        std::ifstream eleStream, eleInfo;

        strcpy(mURL, sResourceDir.c_str());
        strcpy(info, sResourceDir.c_str());
        GetURLForComponent(mCompName, mURL, info, i % STREAM_COUNT);
        if (!(strcmp(mURL, sResourceDir.c_str())) || !(strcmp(info, sResourceDir.c_str()))) {
            ALOGV("Stream not available, skipping this index");
            continue;
        }

        eleInfo.open(info);
        ASSERT_EQ(eleInfo.is_open(), true) << mURL << " - file not found";
        int bytesCount = 0;
        uint32_t flags = 0;
        uint32_t timestamp = 0;
        uint32_t timestampMax = 0;
        while (1) {
            if (!(eleInfo >> bytesCount)) break;
            eleInfo >> flags;
            eleInfo >> timestamp;
            timestamp += timestampOffset;
            Info.push_back({bytesCount, flags, timestamp});
            bool codecConfig =
                    flags ? ((1 << (flags - 1)) & C2FrameData::FLAG_CODEC_CONFIG) != 0 : 0;
            bool nonDisplayFrame = ((flags & FLAG_NON_DISPLAY_FRAME) != 0);

            {
                ULock l(mQueueLock);
                if (mTimestampDevTest && !codecConfig && !nonDisplayFrame)
                    mTimestampUslist.push_back(timestamp);
            }
            if (timestampMax < timestamp) timestampMax = timestamp;
        }
        timestampOffset = timestampMax;
        eleInfo.close();

        // Reset Total frames before second decode loop
        // mFramesReceived = 0;
        ALOGV("mURL : %s", mURL);
        eleStream.open(mURL, std::ifstream::binary);
        ASSERT_EQ(eleStream.is_open(), true);
        ASSERT_NO_FATAL_FAILURE(decodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                              mFlushedIndices, mLinearPool, eleStream, &Info,
                                              offset, (int)(Info.size() - offset), false));

        eleStream.close();
        offset = (int)Info.size();
    }

    // Send EOS
    // TODO Add function to send EOS work item
    int maxRetry = 0;
    std::unique_ptr<C2Work> work;
    while (!work && (maxRetry < MAX_RETRY)) {
        ULock l(mQueueLock);
        if (!mWorkQueue.empty()) {
            work.swap(mWorkQueue.front());
            mWorkQueue.pop_front();
        } else {
            mQueueCondition.wait_for(l, TIME_OUT);
            maxRetry++;
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

    // blocking call to ensures application to Wait till all the inputs are
    // consumed
    ALOGV("Waiting for input consumption");
    waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue);

    if (mFramesReceived != ((Info.size()) + 1)) {
        ALOGE("Input buffer count and Output buffer count mismatch");
        ALOGV("framesReceived : %d inputFrames : %zu", mFramesReceived, Info.size() + 1);
        ASSERT_TRUE(false);
    }

    if (mTimestampDevTest) EXPECT_EQ(mTimestampUslist.empty(), true);
    ASSERT_EQ(mWorkResult, C2_OK);
}

// thumbnail test
TEST_P(Codec2VideoDecHidlTest, ThumbnailTest) {
    description("Test Request for thumbnail");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    char mURL[512], info[512];
    android::Vector<FrameInfo> Info;

    strcpy(mURL, sResourceDir.c_str());
    strcpy(info, sResourceDir.c_str());
    GetURLForComponent(mCompName, mURL, info);

    int32_t numCsds = populateInfoVector(info, &Info, mTimestampDevTest, &mTimestampUslist);
    ASSERT_GE(numCsds, 0) << "Error in parsing input info file: " << info;

    uint32_t flags = 0;
    for (size_t i = 0; i < MAX_ITERATIONS; i++) {
        ASSERT_EQ(mComponent->start(), C2_OK);

        // request EOS for thumbnail
        // signal EOS flag with last frame
        size_t j = -1;
        do {
            j++;
            flags = 0;
            if (Info[j].flags) flags = 1u << (Info[j].flags - 1);

        } while (!(flags & SYNC_FRAME));

        std::ifstream eleStream;
        eleStream.open(mURL, std::ifstream::binary);
        ASSERT_EQ(eleStream.is_open(), true);
        ASSERT_NO_FATAL_FAILURE(decodeNFrames(mComponent, mQueueLock, mQueueCondition, mWorkQueue,
                                              mFlushedIndices, mLinearPool, eleStream, &Info, 0,
                                              j + 1));
        waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue);
        eleStream.close();
        EXPECT_GE(mFramesReceived, 1U);
        ASSERT_EQ(mEos, true);
        ASSERT_EQ(mComponent->stop(), C2_OK);
    }
    ASSERT_EQ(mComponent->release(), C2_OK);
    ASSERT_EQ(mWorkResult, C2_OK);
}

TEST_P(Codec2VideoDecHidlTest, EOSTest) {
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

TEST_P(Codec2VideoDecHidlTest, FlushTest) {
    description("Tests Flush calls");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    ASSERT_EQ(mComponent->start(), C2_OK);

    char mURL[512], info[512];
    android::Vector<FrameInfo> Info;

    strcpy(mURL, sResourceDir.c_str());
    strcpy(info, sResourceDir.c_str());
    GetURLForComponent(mCompName, mURL, info);

    mFlushedIndices.clear();

    int32_t numCsds = populateInfoVector(info, &Info, mTimestampDevTest, &mTimestampUslist);
    ASSERT_GE(numCsds, 0) << "Error in parsing input info file: " << info;

    ALOGV("mURL : %s", mURL);

    // flush
    std::list<std::unique_ptr<C2Work>> flushedWork;
    c2_status_t err = mComponent->flush(C2Component::FLUSH_COMPONENT, &flushedWork);
    ASSERT_EQ(err, C2_OK);
    ASSERT_NO_FATAL_FAILURE(
            verifyFlushOutput(flushedWork, mWorkQueue, mFlushedIndices, mQueueLock));
    ASSERT_EQ(mWorkQueue.size(), MAX_INPUT_BUFFERS);

    std::ifstream eleStream;
    eleStream.open(mURL, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true);
    // Decode 30 frames and flush. here 30 is chosen to ensure there is a key
    // frame after this so that the below section can be covered for all
    // components
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

TEST_P(Codec2VideoDecHidlTest, DecodeTestEmptyBuffersInserted) {
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
}

class Codec2VideoDecCsdInputTests
    : public Codec2VideoDecHidlTestBase,
      public ::testing::WithParamInterface<std::tuple<std::string, std::string, std::string>> {
    void getParams() {
        mInstanceName = std::get<0>(GetParam());
        mComponentName = std::get<1>(GetParam());
    }
};

// Test the codecs for the following
// start - csd - data… - (with/without)flush - data… - flush - data…
TEST_P(Codec2VideoDecCsdInputTests, CSDFlushTest) {
    description("Tests codecs for flush at different states");
    if (mDisableTest) GTEST_SKIP() << "Test is disabled";

    char mURL[512], info[512];

    android::Vector<FrameInfo> Info;

    strcpy(mURL, sResourceDir.c_str());
    strcpy(info, sResourceDir.c_str());
    GetURLForComponent(mCompName, mURL, info);

    int32_t numCsds = populateInfoVector(info, &Info, mTimestampDevTest, &mTimestampUslist);
    ASSERT_GE(numCsds, 0) << "Error in parsing input info file";

    ASSERT_EQ(mComponent->start(), C2_OK);

    ALOGV("mURL : %s", mURL);
    std::ifstream eleStream;
    eleStream.open(mURL, std::ifstream::binary);
    ASSERT_EQ(eleStream.is_open(), true);
    bool flushedDecoder = false;
    bool signalEOS = false;
    bool keyFrame = false;
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
        flushedDecoder = true;
        waitOnInputConsumption(mQueueLock, mQueueCondition, mWorkQueue,
                               MAX_INPUT_BUFFERS - flushedWork.size());
        ASSERT_NO_FATAL_FAILURE(
                verifyFlushOutput(flushedWork, mWorkQueue, mFlushedIndices, mQueueLock));
        ASSERT_EQ(mWorkQueue.size(), MAX_INPUT_BUFFERS);
    }

    int offset = framesToDecode;
    uint32_t flags = 0;
    while (1) {
        while (offset < (int)Info.size()) {
            flags = 0;
            if (Info[offset].flags) flags = 1u << (Info[offset].flags - 1);
            if (flags & SYNC_FRAME) {
                keyFrame = true;
                break;
            }
            eleStream.ignore(Info[offset].bytesCount);
            offset++;
        }
        if (keyFrame) {
            framesToDecode = c2_min(FLUSH_INTERVAL, (int)Info.size() - offset);
            if (framesToDecode < FLUSH_INTERVAL) signalEOS = true;
            ASSERT_NO_FATAL_FAILURE(decodeNFrames(
                    mComponent, mQueueLock, mQueueCondition, mWorkQueue, mFlushedIndices,
                    mLinearPool, eleStream, &Info, offset, framesToDecode, signalEOS));
            offset += framesToDecode;
        }
        err = mComponent->flush(C2Component::FLUSH_COMPONENT, &flushedWork);
        ASSERT_EQ(err, C2_OK);
        keyFrame = false;
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

INSTANTIATE_TEST_SUITE_P(PerInstance, Codec2VideoDecHidlTest, testing::ValuesIn(kTestParameters),
                         android::hardware::PrintInstanceTupleNameToString<>);

// DecodeTest with StreamIndex and EOS / No EOS
INSTANTIATE_TEST_SUITE_P(StreamIndexAndEOS, Codec2VideoDecDecodeTest,
                         testing::ValuesIn(kDecodeTestParameters),
                         android::hardware::PrintInstanceTupleNameToString<>);

INSTANTIATE_TEST_SUITE_P(CsdInputs, Codec2VideoDecCsdInputTests,
                         testing::ValuesIn(kCsdFlushTestParameters),
                         android::hardware::PrintInstanceTupleNameToString<>);

}  // anonymous namespace

// TODO : Video specific configuration Test
int main(int argc, char** argv) {
    kTestParameters = getTestParameters(C2Component::DOMAIN_VIDEO, C2Component::KIND_DECODER);
    for (auto params : kTestParameters) {
        kDecodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "0", "false"));
        kDecodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "0", "true"));
        kDecodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "1", "false"));
        kDecodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "1", "true"));
        kDecodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "2", "false"));
        kDecodeTestParameters.push_back(
                std::make_tuple(std::get<0>(params), std::get<1>(params), "2", "true"));

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
