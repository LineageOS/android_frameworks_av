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
#define LOG_TAG "codec2_hidl_hal_master_test"

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <gtest/gtest.h>
#include <hidl/GtestPrinter.h>
#include <hidl/ServiceManagement.h>

#include <codec2/hidl/client.h>

#include <VtsHalHidlTargetTestBase.h>
#include "media_c2_hidl_test_common.h"

namespace {

// google.codec2 Master test setup
class Codec2MasterHalTest : public ::testing::TestWithParam<std::string> {
  public:
    virtual void SetUp() override {
        mClient = android::Codec2Client::CreateFromService(GetParam().c_str());
        ASSERT_NE(mClient, nullptr);
    }

  protected:
    static void description(const std::string& description) {
        RecordProperty("description", description);
    }

    std::shared_ptr<android::Codec2Client> mClient;
};

void displayComponentInfo(const std::vector<C2Component::Traits>& compList) {
    for (size_t i = 0; i < compList.size(); i++) {
        std::cout << compList[i].name << " | " << compList[i].domain;
        std::cout << " | " << compList[i].kind << "\n";
    }
}

// List Components
TEST_P(Codec2MasterHalTest, ListComponents) {
    ALOGV("ListComponents Test");

    C2String name = mClient->getName();
    EXPECT_NE(name.empty(), true) << "Invalid Codec2Client Name";

    // Get List of components from all known services
    const std::vector<C2Component::Traits> listTraits = mClient->ListComponents();

    if (listTraits.size() == 0)
        ALOGE("Warning, ComponentInfo list empty");
    else {
        (void)displayComponentInfo;
        for (size_t i = 0; i < listTraits.size(); i++) {
            std::shared_ptr<android::Codec2Client::Listener> listener;
            std::shared_ptr<android::Codec2Client::Component> component;
            listener.reset(new CodecListener());
            ASSERT_NE(listener, nullptr);

            // Create component from all known services
            const c2_status_t status =
                    android::Codec2Client::CreateComponentByName(
                            listTraits[i].name.c_str(), listener, &component, &mClient);
            ASSERT_EQ(status, C2_OK)
                    << "Create component failed for " << listTraits[i].name.c_str();
        }
    }
}

TEST_P(Codec2MasterHalTest, MustUseAidlBeyond202404) {
    static int sVendorApiLevel = android::base::GetIntProperty("ro.vendor.api_level", 0);
    if (sVendorApiLevel < 202404) {
        GTEST_SKIP() << "vendor api level less than 202404: " << sVendorApiLevel;
    }
    ALOGV("MustUseAidlBeyond202404 Test");

    EXPECT_NE(mClient->getAidlBase(), nullptr) << "android.hardware.media.c2 MUST use AIDL "
                                               << "for chipsets launching at 202404 or above";
}

}  // anonymous namespace

INSTANTIATE_TEST_SUITE_P(PerInstance, Codec2MasterHalTest,
                         testing::ValuesIn(android::Codec2Client::GetServiceNames()),
                         android::hardware::PrintInstanceNameToString);
