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

#include <android-base/expected.h>

using ::android::base::unexpected;
using ::android::binder::Status;
using com::android::media::permission::NativePermissionController;
using com::android::media::permission::UidPackageState;

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

static std::vector<std::string> makeVector(const char* one) {
    return {one};
}

static std::vector<std::string> makeVector(const char* one, const char* two) {
    return {one, two};
}

#define UNWRAP_EQ(expr, desired_expr)                         \
    do {                                                      \
        auto tmp_ = (expr);                                   \
        EXPECT_TRUE(tmp_.has_value());                        \
        if (tmp_.has_value()) EXPECT_EQ(*tmp_, desired_expr); \
    } while (0)

// ---  Tests for non-populated ----
TEST_F(NativePermissionControllerTest, getPackagesForUid_NotPopulated) {
    // Verify errors are returned
    EXPECT_EQ(controller_.getPackagesForUid(10000), unexpected{android::NO_INIT});
    EXPECT_EQ(controller_.getPackagesForUid(10001), unexpected{android::NO_INIT});

    // fixed uids should work
    UNWRAP_EQ(controller_.getPackagesForUid(1000), makeVector("system"));
}

TEST_F(NativePermissionControllerTest, validateUidPackagePair_NotPopulated) {
    // Verify errors are returned
    EXPECT_EQ(controller_.validateUidPackagePair(10000, "com.package"),
              unexpected{android::NO_INIT});

    // fixed uids should work
    UNWRAP_EQ(controller_.validateUidPackagePair(1000, "system"), true);
}
// ---  Tests for populatePackagesForUids ----
TEST_F(NativePermissionControllerTest, populatePackages_EmptyInput) {
    std::vector<UidPackageState> input;

    // succeeds
    EXPECT_TRUE(controller_.populatePackagesForUids(input).isOk());

    // Verify unknown uid behavior
    const auto res1 = controller_.getPackagesForUid(10000);
    ASSERT_FALSE(res1.has_value());
    EXPECT_EQ(res1.error(), ::android::BAD_VALUE);
}

TEST_F(NativePermissionControllerTest, populatePackages_ValidInput) {
    std::vector<UidPackageState> input{
            createState(10000, {"com.example.app1", "com.example.app2"}),
            createState(10001, {"com.example2.app1"}),
    };

    EXPECT_TRUE(controller_.populatePackagesForUids(input).isOk());

    UNWRAP_EQ(controller_.getPackagesForUid(10000),
              makeVector("com.example.app1", "com.example.app2"));
    UNWRAP_EQ(controller_.getPackagesForUid(10001), makeVector("com.example2.app1"));
}

// --- Tests for updatePackagesForUid ---
TEST_F(NativePermissionControllerTest, updatePackages_NewUid) {
    std::vector<UidPackageState> input{
            createState(10000, {"com.example.app1", "com.example.app2"}),
            createState(10001, {"com.example2.app1"}),
    };
    UidPackageState newState = createState(12000, {"com.example.other"});

    EXPECT_TRUE(controller_.populatePackagesForUids(input).isOk());
    EXPECT_TRUE(controller_.updatePackagesForUid(newState).isOk());

    // Verify the results: only the updated package should be changed
    UNWRAP_EQ(controller_.getPackagesForUid(10000),
              makeVector("com.example.app1", "com.example.app2"));
    UNWRAP_EQ(controller_.getPackagesForUid(10001), makeVector("com.example2.app1"));
    UNWRAP_EQ(controller_.getPackagesForUid(12000), makeVector("com.example.other"));
}

TEST_F(NativePermissionControllerTest, updatePackages_ExistingUid) {
    std::vector<UidPackageState> input{
            createState(10000, {"com.example.app1", "com.example.app2", "com.example.app3"}),
            createState(10001, {"com.example2.app1"}),
    };

    EXPECT_TRUE(controller_.populatePackagesForUids(input).isOk());
    // Update packages for existing uid
    UidPackageState newState = createState(10000, {"com.example.other", "com.example.new"});
    EXPECT_TRUE(controller_.updatePackagesForUid(newState).isOk());

    // Verify update
    UNWRAP_EQ(controller_.getPackagesForUid(10000),
              makeVector("com.example.other", "com.example.new"));
}

TEST_F(NativePermissionControllerTest, updatePackages_EmptyRemovesEntry) {
    std::vector<UidPackageState> input{
            createState(10000, {"com.example.app1"}),
    };

    EXPECT_TRUE(controller_.populatePackagesForUids(input).isOk());

    UidPackageState newState{};  // Empty package list
    newState.uid = 10000;
    EXPECT_TRUE(controller_.updatePackagesForUid(newState).isOk());
    // getPackages for unknown UID should error out
    const auto res = controller_.getPackagesForUid(10000);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), ::android::BAD_VALUE);
}

TEST_F(NativePermissionControllerTest, validateUidPackagePair_ValidPair) {
    std::vector<UidPackageState> input{
            createState(10000, {"com.example.app1", "com.example.app2"}),
    };

    EXPECT_TRUE(controller_.populatePackagesForUids(input).isOk());

    UNWRAP_EQ(controller_.validateUidPackagePair(10000, "com.example.app1"), true);
}

TEST_F(NativePermissionControllerTest, validateUidPackagePair_InvalidPackage) {
    std::vector<UidPackageState> input{
            createState(10000, {"com.example.app1", "com.example.app2"}),
    };

    EXPECT_TRUE(controller_.populatePackagesForUids(input).isOk());

    UNWRAP_EQ(controller_.validateUidPackagePair(10000, "com.example.other"), false);
}

TEST_F(NativePermissionControllerTest, validateUidPackagePair_UnknownUid) {
    std::vector<UidPackageState> input{
            createState(10000, {"com.example.app1", "com.example.app2"}),
    };

    EXPECT_TRUE(controller_.populatePackagesForUids(input).isOk());

    UNWRAP_EQ(controller_.validateUidPackagePair(12000, "any.package"), false);
}
