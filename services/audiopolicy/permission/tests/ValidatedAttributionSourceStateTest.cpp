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

#include <media/ValidatedAttributionSourceState.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <android-base/expected.h>
#include <media/IPermissionProvider.h>

using ::android::base::unexpected;
using ::android::binder::Status;
using ::android::content::AttributionSourceState;
using ::android::error::Result;
using ::com::android::media::permission::IPermissionProvider;
using ::com::android::media::permission::ValidatedAttributionSourceState;
using ::testing::Return;

class MockPermissionProvider : public IPermissionProvider {
  public:
    MOCK_METHOD(Result<std::vector<std::string>>, getPackagesForUid, (uid_t uid),
                (override, const));
    MOCK_METHOD(Result<bool>, validateUidPackagePair, (uid_t uid, const std::string&),
                (override, const));
};

class ValidatedAttributionSourceStateTest : public ::testing::Test {
  protected:
    MockPermissionProvider mMockProvider;
    const uid_t mUid = 10001;
    const std::vector<std::string> mPackageList{"com.package1", "com.package2"};
};

#define UNWRAP_EQ(expr, desired_expr)                         \
    do {                                                      \
        auto tmp_ = (expr);                                   \
        EXPECT_TRUE(tmp_.has_value());                        \
        if (tmp_.has_value()) EXPECT_EQ(*tmp_, desired_expr); \
    } while (0)

TEST_F(ValidatedAttributionSourceStateTest, providedPackageValid) {
    const std::string package = "com.package1";
    EXPECT_CALL(mMockProvider, validateUidPackagePair(mUid, package)).WillOnce(Return(true));
    AttributionSourceState attr;
    attr.uid = mUid;
    attr.packageName = package;
    UNWRAP_EQ(ValidatedAttributionSourceState::createFromTrustedUidNoPackage(attr, mMockProvider),
              attr);
}

TEST_F(ValidatedAttributionSourceStateTest, providedPackageInvalid) {
    const std::string package = "com.package.spoof";
    EXPECT_CALL(mMockProvider, validateUidPackagePair(mUid, package)).WillOnce(Return(false));
    AttributionSourceState attr;
    attr.uid = mUid;
    attr.packageName = package;
    const auto res =
            ValidatedAttributionSourceState::createFromTrustedUidNoPackage(attr, mMockProvider);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), ::android::PERMISSION_DENIED);
}

TEST_F(ValidatedAttributionSourceStateTest, packageLookup_whenMissingPackage) {
    EXPECT_CALL(mMockProvider, getPackagesForUid(mUid)).WillOnce(Return(mPackageList));
    AttributionSourceState attr;
    attr.uid = mUid;
    AttributionSourceState expectedAttr;
    expectedAttr.uid = mUid;
    expectedAttr.packageName = "com.package1";
    UNWRAP_EQ(ValidatedAttributionSourceState::createFromTrustedUidNoPackage(attr, mMockProvider),
              expectedAttr);
}

TEST_F(ValidatedAttributionSourceStateTest, packageLookup_whenEmptyPackage) {
    EXPECT_CALL(mMockProvider, getPackagesForUid(mUid)).WillOnce(Return(mPackageList));
    AttributionSourceState attr;
    attr.uid = mUid;
    attr.packageName = std::string{};
    AttributionSourceState expectedAttr;
    expectedAttr.uid = mUid;
    expectedAttr.packageName = "com.package1";
    UNWRAP_EQ(ValidatedAttributionSourceState::createFromTrustedUidNoPackage(attr, mMockProvider),
              expectedAttr);
}

TEST_F(ValidatedAttributionSourceStateTest, controllerNotInitialized) {
    EXPECT_CALL(mMockProvider, getPackagesForUid(mUid))
            .WillOnce(Return(unexpected{::android::NO_INIT}));
    AttributionSourceState attr;
    attr.uid = mUid;
    attr.packageName = std::string{};
    AttributionSourceState expectedAttr;
    expectedAttr.uid = mUid;
    expectedAttr.packageName = "com.package1";
    const auto res =
            ValidatedAttributionSourceState::createFromTrustedUidNoPackage(attr, mMockProvider);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), ::android::NO_INIT);
}

TEST_F(ValidatedAttributionSourceStateTest, uidNotFound) {
    EXPECT_CALL(mMockProvider, getPackagesForUid(mUid))
            .WillOnce(Return(unexpected{::android::BAD_VALUE}));
    AttributionSourceState attr;
    attr.uid = mUid;
    attr.packageName = std::string{};
    const auto res =
            ValidatedAttributionSourceState::createFromTrustedUidNoPackage(attr, mMockProvider);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), ::android::BAD_VALUE);
}
