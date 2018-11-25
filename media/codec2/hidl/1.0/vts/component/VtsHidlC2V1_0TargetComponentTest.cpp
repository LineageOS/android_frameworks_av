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
#define LOG_TAG "codec2_hidl_hal_component_test"

#include <android-base/logging.h>
#include <gtest/gtest.h>

#include <C2Config.h>
#include <codec2/hidl/client.h>

#include <VtsHalHidlTargetTestBase.h>
#include "media_c2_hidl_test_common.h"

static ComponentTestEnvironment* gEnv = nullptr;

namespace {

// google.codec2 Component test setup
class Codec2ComponentHidlTest : public ::testing::VtsHalHidlTargetTestBase {
   private:
    typedef ::testing::VtsHalHidlTargetTestBase Super;

   public:
    virtual void SetUp() override {
        Super::SetUp();
        mClient = android::Codec2Client::CreateFromService(
            gEnv->getInstance().c_str());
        ASSERT_NE(mClient, nullptr);
        mListener.reset(new CodecListener());
        ASSERT_NE(mListener, nullptr);
        mClient->createComponent(gEnv->getComponent().c_str(), mListener,
                                 &mComponent);
        ASSERT_NE(mComponent, nullptr);
    }

    virtual void TearDown() override {
        if (mComponent != nullptr) {
            // If you have encountered a fatal failure, it is possible that
            // freeNode() will not go through. Instead of hanging the app.
            // let it pass through and report errors
            if (::testing::Test::HasFatalFailure()) return;
            mComponent->release();
            mComponent = nullptr;
        }
        Super::TearDown();
    }

    std::shared_ptr<android::Codec2Client> mClient;
    std::shared_ptr<android::Codec2Client::Listener> mListener;
    std::shared_ptr<android::Codec2Client::Component> mComponent;

   protected:
    static void description(const std::string& description) {
        RecordProperty("description", description);
    }
};

// Test Empty Flush
TEST_F(Codec2ComponentHidlTest, EmptyFlush) {
    ALOGV("Empty Flush Test");
    c2_status_t err = mComponent->start();
    ASSERT_EQ(err, C2_OK);

    std::list<std::unique_ptr<C2Work>> flushedWork;
    err = mComponent->flush(C2Component::FLUSH_COMPONENT, &flushedWork);
    ASSERT_EQ(err, C2_OK);

    err = mComponent->stop();
    ASSERT_EQ(err, C2_OK);
    // Empty Flush should not return any work
    ASSERT_EQ(flushedWork.size(), 0u);
}

// Test Queue Empty Work
TEST_F(Codec2ComponentHidlTest, QueueEmptyWork) {
    ALOGV("Queue Empty Work Test");
    c2_status_t err = mComponent->start();
    ASSERT_EQ(err, C2_OK);

    // Queueing an empty WorkBundle
    std::list<std::unique_ptr<C2Work>> workList;
    err = mComponent->queue(&workList);
    ASSERT_EQ(err, C2_OK);

    err = mComponent->reset();
    ASSERT_EQ(err, C2_OK);
}

// Test Component Configuration
TEST_F(Codec2ComponentHidlTest, Config) {
    ALOGV("Configuration Test");

    C2String name = mComponent->getName();
    EXPECT_NE(name.empty(), true) << "Invalid Component Name";

    c2_status_t err = C2_OK;
    std::vector<std::unique_ptr<C2Param>> queried;
    std::vector<std::unique_ptr<C2SettingResult>> failures;

    // Query supported params by the component
    std::vector<std::shared_ptr<C2ParamDescriptor>> params;
    err = mComponent->querySupportedParams(&params);
    ASSERT_EQ(err, C2_OK);
    ALOGV("Number of total params - %zu", params.size());

    // Query and config all the supported params
    for (std::shared_ptr<C2ParamDescriptor> p : params) {
        ALOGD("Querying index %d", (int)p->index());
        err = mComponent->query({}, {p->index()}, C2_DONT_BLOCK, &queried);
        EXPECT_NE(queried.size(), 0u);
        EXPECT_EQ(err, C2_OK);
        err = mComponent->config({queried[0].get()}, C2_DONT_BLOCK, &failures);
        ASSERT_EQ(err, C2_OK);
        ASSERT_EQ(failures.size(), 0u);
    }
}

// Test Multiple Start Stop Reset Test
TEST_F(Codec2ComponentHidlTest, MultipleStartStopReset) {
    ALOGV("Multiple Start Stop and Reset Test");
    c2_status_t err = C2_OK;

#define MAX_RETRY 16

    for (size_t i = 0; i < MAX_RETRY; i++) {
        err = mComponent->start();
        ASSERT_EQ(err, C2_OK);

        err = mComponent->stop();
        ASSERT_EQ(err, C2_OK);
    }

    err = mComponent->start();
    ASSERT_EQ(err, C2_OK);

    for (size_t i = 0; i < MAX_RETRY; i++) {
        err = mComponent->reset();
        ASSERT_EQ(err, C2_OK);
    }

    err = mComponent->start();
    ASSERT_EQ(err, C2_OK);

    err = mComponent->stop();
    ASSERT_EQ(err, C2_OK);

    // Second stop should return error
    err = mComponent->stop();
    ASSERT_NE(err, C2_OK);
}

// Test Component Release API
TEST_F(Codec2ComponentHidlTest, MultipleRelease) {
    ALOGV("Multiple Release Test");
    c2_status_t err = mComponent->start();
    ASSERT_EQ(err, C2_OK);

    // Query Component Domain Type
    std::vector<std::unique_ptr<C2Param>> queried;
    err = mComponent->query({}, {C2PortMediaTypeSetting::input::PARAM_TYPE},
                            C2_DONT_BLOCK, &queried);
    EXPECT_NE(queried.size(), 0u);

    // Configure Component Domain
    std::vector<std::unique_ptr<C2SettingResult>> failures;
    C2PortMediaTypeSetting::input* portMediaType =
        C2PortMediaTypeSetting::input::From(queried[0].get());
    err = mComponent->config({portMediaType}, C2_DONT_BLOCK, &failures);
    ASSERT_EQ(err, C2_OK);
    ASSERT_EQ(failures.size(), 0u);

#define MAX_RETRY 16
    for (size_t i = 0; i < MAX_RETRY; i++) {
        err = mComponent->release();
        ASSERT_EQ(err, C2_OK);
    }
}

}  // anonymous namespace

// TODO: Add test for Invalid work,
// TODO: Add test for Invalid states
int main(int argc, char** argv) {
    gEnv = new ComponentTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    gEnv->init(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        LOG(INFO) << "C2 Test result = " << status;
    }
    return status;
}
