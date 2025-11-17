/*
 * Copyright (C) 2025 The Android Open Source Project
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
#define LOG_TAG "codec2_hidl_hal_video_enc_surface_test"

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <codec2/common/HalSelection.h>
#include <gtest/gtest.h>
#include <hidl/GtestPrinter.h>

#include <codec2/hidl/client.h>

#include "media_c2_hidl_test_common.h"

namespace {

// google.codec2 video surface test setup
class Codec2VideoEncSurfaceAidlTestBase : public ::testing::Test {
  public:
    virtual void SetUp() override {
        if (!android::IsCodec2AidlInputSurfaceSelected()) {
            GTEST_SKIP() << "Skipping test: Codec2 AIDL InputSurface not selected.";
        }
        getParams();
        mClient = android::Codec2Client::CreateFromService(
                mInstanceName.c_str(),
                !bool(android::Codec2Client::CreateFromService("default", true)));
        ASSERT_NE(mClient, nullptr);

        mListener.reset(new CodecListener());
        ASSERT_NE(mListener, nullptr);

        // create component
        mClient->createComponent(mComponentName, mListener, &mComponent);
        ASSERT_NE(mComponent, nullptr);
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

  protected:
    static void description(const std::string& description) {
        RecordProperty("description", description);
    }

    std::string mInstanceName;
    std::string mComponentName;
    std::shared_ptr<android::Codec2Client> mClient;
    std::shared_ptr<android::Codec2Client::Listener> mListener;
    std::shared_ptr<android::Codec2Client::Component> mComponent;
};

class Codec2VideoEncSurfaceAidlTest : public Codec2VideoEncSurfaceAidlTestBase,
                                      public ::testing::WithParamInterface<TestParameters> {
    void getParams() {
        mInstanceName = std::get<0>(GetParam());
        mComponentName = std::get<1>(GetParam());
    }
};

// video encoder surface unit test
TEST_P(Codec2VideoEncSurfaceAidlTest, UnitTest) {
    ALOGV("Aidl video encoder surface Test");

    C2String clientName = mClient->getName();
    EXPECT_NE(clientName.empty(), true) << "Invalid Codec2Client Name";

    // create InputSurface
    std::shared_ptr<android::Codec2Client::InputSurface> inputSurface;
    c2_status_t err = mClient->createInputSurface(&inputSurface);
    if (err == C2_OMITTED) {
        GTEST_SKIP() << "Skipping test: InputSurface::createInputSurface is not supported.";
    }
    ASSERT_EQ(err, C2_OK);
    ASSERT_NE(inputSurface, nullptr);

    // Configure the mComponent
    std::vector<std::unique_ptr<C2SettingResult>> failures;
    ASSERT_EQ(mComponent->config({}, C2_MAY_BLOCK, &failures), C2_OK);
    ASSERT_TRUE(failures.empty());

    // Configure the InputSurface
    std::list<std::unique_ptr<C2Param>> surfaceConfigUpdate;
    surfaceConfigUpdate.push_back(std::make_unique<C2StreamBlockSizeInfo::output>(
            0u, 1280 /* width */, 720 /* height */));
    surfaceConfigUpdate.push_back(
            std::make_unique<C2StreamBlockCountInfo::output>(0u, 5 /* bufferCount */));
    surfaceConfigUpdate.push_back(
            std::make_unique<C2StreamUsageTuning::output>(0u, (uint64_t)C2MemoryUsage::CPU_READ));
    surfaceConfigUpdate.push_back(std::make_unique<C2StreamDataSpaceInfo::output>(
            0u, HAL_DATASPACE_BT709 /* dataSpace */));

    std::vector<C2Param*> surfaceConfig;
    for (const auto& param : surfaceConfigUpdate) {
        surfaceConfig.push_back(param.get());
    }
    std::vector<std::unique_ptr<C2SettingResult>> surfaceFailures;
    ASSERT_EQ(inputSurface->config(surfaceConfig, C2_MAY_BLOCK, &surfaceFailures), C2_OK);

    // Connect InputSurface to mComponent
    std::shared_ptr<android::Codec2Client::InputSurfaceConnection> connection;
    ASSERT_EQ(inputSurface->connect(mComponent, &connection), C2_OK);
    ASSERT_NE(connection, nullptr);

    // start the mComponent
    ASSERT_EQ(mComponent->start(), C2_OK);

    // test getSurface() API via getNativeWindow()
    ANativeWindow* nativeWindow = inputSurface->getNativeWindow();
    ASSERT_NE(nativeWindow, nullptr);

    // test notifiesInputBufferDoneToClient() API
    bool inputBufferDone = false;
    err = connection->notifiesInputBufferDoneToClient(&inputBufferDone);
    if (err == C2_OMITTED) {
        ALOGI("InputSurfaceConnection::notifiesInputBufferDoneToClient is not supported");
    } else {
        ASSERT_EQ(err, C2_OK);
        ALOGI("InputSurfaceConnection::notifiesInputBufferDoneToClient returned: %s",
              inputBufferDone ? "True" : "False");
    }

    // test signalEos API
    ASSERT_EQ(connection->signalEos(), C2_OK);

    // test disconnect() API
    ASSERT_EQ(connection->disconnect(), C2_OK);

    ASSERT_EQ(mComponent->stop(), C2_OK);
    ASSERT_EQ(mComponent->release(), C2_OK);
}

}  // anonymous namespace

INSTANTIATE_TEST_SUITE_P(PerInstance, Codec2VideoEncSurfaceAidlTest,
                         testing::ValuesIn(getTestParameters(C2Component::DOMAIN_VIDEO,
                                                             C2Component::KIND_ENCODER)),
                         PrintInstanceTupleNameToString<>);
