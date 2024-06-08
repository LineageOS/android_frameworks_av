/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <media/NativePermissionController.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <error/BinderStatusMatcher.h>
#include <error/ExpectedMatchers.h>

using android::binder::Status::EX_ILLEGAL_ARGUMENT;
using android::binder::Status::EX_ILLEGAL_STATE;
using android::error::BinderStatusMatcher;
using android::error::IsErrorAnd;
using android::error::IsOkAnd;
using com::android::media::permission::NativePermissionController;
using com::android::media::permission::PermissionEnum;
using com::android::media::permission::UidPackageState;

using ::testing::ElementsAre;
using ::testing::IsFalse;
using ::testing::IsTrue;

class NativePermissionControllerTest : public ::testing::Test {
  protected:
    android::sp<NativePermissionController> holder_ =
            android::sp<NativePermissionController>::make();
    NativePermissionController& controller_ = *holder_;
};
static UidPackageState createState(uid_t uid, std::vector<std::string> packagesNames) {
    UidPackageState out{};
    out.uid = uid;
    out.packageNames = std::move(packagesNames);
    return out;
}

// ---  Tests for non-populated ----
TEST_F(NativePermissionControllerTest, getPackagesForUid_NotPopulated) {
    // Verify errors are returned
    EXPECT_THAT(controller_.getPackagesForUid(10000),
                IsErrorAnd(BinderStatusMatcher::hasException(EX_ILLEGAL_STATE)));
    EXPECT_THAT(controller_.getPackagesForUid(10001),
                IsErrorAnd(BinderStatusMatcher::hasException(EX_ILLEGAL_STATE)));

    // fixed uids should work
    EXPECT_THAT(controller_.getPackagesForUid(1000), IsOkAnd(ElementsAre(std::string{"system"})));
}

TEST_F(NativePermissionControllerTest, validateUidPackagePair_NotPopulated) {
    // Verify errors are returned
    EXPECT_THAT(controller_.validateUidPackagePair(10000, "com.package"),
                IsErrorAnd(BinderStatusMatcher::hasException(EX_ILLEGAL_STATE)));

    // fixed uids should work
    EXPECT_THAT(controller_.validateUidPackagePair(1000, "system"), IsOkAnd(IsTrue()));
}

// ---  Tests for populatePackagesForUids ----
TEST_F(NativePermissionControllerTest, populatePackages_EmptyInput) {
    std::vector<UidPackageState> input;

    // succeeds
    EXPECT_THAT(controller_.populatePackagesForUids(input), BinderStatusMatcher::isOk());

    // Verify unknown uid behavior
    EXPECT_THAT(controller_.getPackagesForUid(10000),
                IsErrorAnd(BinderStatusMatcher::hasException(EX_ILLEGAL_ARGUMENT)));
}

TEST_F(NativePermissionControllerTest, populatePackages_ValidInput) {
    std::vector<UidPackageState> input{
            createState(10000, {"com.example.app1", "com.example.app2"}),
            createState(10001, {"com.example2.app1"}),
    };

    EXPECT_THAT(controller_.populatePackagesForUids(input), BinderStatusMatcher::isOk());

    EXPECT_THAT(controller_.getPackagesForUid(10000),
                IsOkAnd(ElementsAre("com.example.app1", "com.example.app2")));
    EXPECT_THAT(controller_.getPackagesForUid(10001), IsOkAnd(ElementsAre("com.example2.app1")));
}

// --- Tests for updatePackagesForUid ---
TEST_F(NativePermissionControllerTest, updatePackages_NewUid) {
    std::vector<UidPackageState> input{
            createState(10000, {"com.example.app1", "com.example.app2"}),
            createState(10001, {"com.example2.app1"}),
    };
    UidPackageState newState = createState(12000, {"com.example.other"});

    EXPECT_THAT(controller_.populatePackagesForUids(input), BinderStatusMatcher::isOk());
    EXPECT_THAT(controller_.updatePackagesForUid(newState), BinderStatusMatcher::isOk());

    // Verify the results: only the updated package should be changed
    EXPECT_THAT(controller_.getPackagesForUid(10000),
                IsOkAnd(ElementsAre("com.example.app1", "com.example.app2")));
    EXPECT_THAT(controller_.getPackagesForUid(10001), IsOkAnd(ElementsAre("com.example2.app1")));
    EXPECT_THAT(controller_.getPackagesForUid(12000), IsOkAnd(ElementsAre("com.example.other")));
}

TEST_F(NativePermissionControllerTest, updatePackages_ExistingUid) {
    std::vector<UidPackageState> input{
            createState(10000, {"com.example.app1", "com.example.app2", "com.example.app3"}),
            createState(10001, {"com.example2.app1"}),
    };

    EXPECT_THAT(controller_.populatePackagesForUids(input), BinderStatusMatcher::isOk());
    // Update packages for existing uid
    UidPackageState newState = createState(10000, {"com.example.other", "com.example.new"});
    EXPECT_THAT(controller_.updatePackagesForUid(newState), BinderStatusMatcher::isOk());

    // Verify update
    EXPECT_THAT(controller_.getPackagesForUid(10000),
                IsOkAnd(ElementsAre("com.example.other", "com.example.new")));
}

TEST_F(NativePermissionControllerTest, updatePackages_EmptyRemovesEntry) {
    std::vector<UidPackageState> input{
            createState(10000, {"com.example.app1"}),
    };

    EXPECT_THAT(controller_.populatePackagesForUids(input), BinderStatusMatcher::isOk());

    UidPackageState newState{};  // Empty package list
    newState.uid = 10000;
    EXPECT_THAT(controller_.updatePackagesForUid(newState), BinderStatusMatcher::isOk());
    // getPackages for unknown UID should error out
    EXPECT_THAT(controller_.getPackagesForUid(10000),
                IsErrorAnd(BinderStatusMatcher::hasException(EX_ILLEGAL_ARGUMENT)));
}

TEST_F(NativePermissionControllerTest, validateUidPackagePair_ValidPair) {
    std::vector<UidPackageState> input{
            createState(10000, {"com.example.app1", "com.example.app2"}),
    };

    EXPECT_THAT(controller_.populatePackagesForUids(input), BinderStatusMatcher::isOk());

    EXPECT_THAT(controller_.validateUidPackagePair(10000, "com.example.app1"), IsOkAnd(IsTrue()));
}

TEST_F(NativePermissionControllerTest, validateUidPackagePair_InvalidPackage) {
    std::vector<UidPackageState> input{
            createState(10000, {"com.example.app1", "com.example.app2"}),
    };

    EXPECT_THAT(controller_.populatePackagesForUids(input), BinderStatusMatcher::isOk());

    EXPECT_THAT(controller_.validateUidPackagePair(10000, "com.example.other"), IsOkAnd(IsFalse()));
}

TEST_F(NativePermissionControllerTest, validateUidPackagePair_UnknownUid) {
    std::vector<UidPackageState> input{
            createState(10000, {"com.example.app1", "com.example.app2"}),
    };

    EXPECT_THAT(controller_.populatePackagesForUids(input), BinderStatusMatcher::isOk());

    EXPECT_THAT(controller_.validateUidPackagePair(12000, "any.package"), IsOkAnd(IsFalse()));
}

TEST_F(NativePermissionControllerTest, populatePermissionState_InvalidPermission) {
    EXPECT_THAT(controller_.populatePermissionState(PermissionEnum::ENUM_SIZE, {}),
                BinderStatusMatcher::hasException(EX_ILLEGAL_ARGUMENT));
    EXPECT_THAT(
            controller_.populatePermissionState(
                    static_cast<PermissionEnum>(static_cast<int>(PermissionEnum::ENUM_SIZE) + 1),
                    {}),
            BinderStatusMatcher::hasException(EX_ILLEGAL_ARGUMENT));
}

TEST_F(NativePermissionControllerTest, populatePermissionState_HoldsPermission) {
    // Unsorted
    std::vector<int> uids{3, 1, 2, 4, 5};

    EXPECT_THAT(controller_.populatePermissionState(PermissionEnum::MODIFY_AUDIO_ROUTING, uids),
                BinderStatusMatcher::isOk());

    EXPECT_THAT(controller_.checkPermission(PermissionEnum::MODIFY_AUDIO_ROUTING, 3),
                IsOkAnd(IsTrue()));
}

TEST_F(NativePermissionControllerTest, populatePermissionState_DoesNotHoldPermission) {
    // Unsorted
    std::vector<int> uids{3, 1, 2, 4, 5};

    EXPECT_THAT(controller_.populatePermissionState(PermissionEnum::MODIFY_AUDIO_ROUTING, uids),
                BinderStatusMatcher::isOk());

    EXPECT_THAT(controller_.checkPermission(PermissionEnum::MODIFY_AUDIO_ROUTING, 6),
                IsOkAnd(IsFalse()));
}

TEST_F(NativePermissionControllerTest, populatePermissionState_NotInitialized) {
    EXPECT_THAT(controller_.checkPermission(PermissionEnum::MODIFY_AUDIO_ROUTING, 3),
                IsErrorAnd(BinderStatusMatcher::hasException(EX_ILLEGAL_STATE)));
}
