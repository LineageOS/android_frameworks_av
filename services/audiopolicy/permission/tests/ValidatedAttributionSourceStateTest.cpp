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
#include <error/ExpectedMatchers.h>
#include <media/IPermissionProvider.h>
#include "error/BinderStatusMatcher.h"

using ::android::base::unexpected;
using ::android::binder::Status;
using ::android::binder::Status::EX_ILLEGAL_ARGUMENT;
using ::android::binder::Status::EX_ILLEGAL_STATE;
using ::android::binder::Status::EX_SECURITY;
using ::android::content::AttributionSourceState;
using ::android::error::BinderResult;
using ::android::error::BinderStatusMatcher;
using ::android::error::IsErrorAnd;
using ::android::error::IsOkAnd;
using ::com::android::media::permission::IPermissionProvider;
using ::com::android::media::permission::PermissionEnum;
using ::com::android::media::permission::ValidatedAttributionSourceState;

using ::testing::Eq;
using ::testing::Return;

class MockPermissionProvider : public IPermissionProvider {
  public:
    MOCK_METHOD(BinderResult<std::vector<std::string>>, getPackagesForUid, (uid_t uid),
                (override, const));
    MOCK_METHOD(BinderResult<bool>, validateUidPackagePair, (uid_t uid, const std::string&),
                (override, const));
    MOCK_METHOD(BinderResult<bool>, checkPermission, (PermissionEnum perm, uid_t),
                (override, const));
};

class ValidatedAttributionSourceStateTest : public ::testing::Test {
  protected:
    MockPermissionProvider mMockProvider;
    const uid_t mUid = 10001;
    const std::vector<std::string> mPackageList{"com.package1", "com.package2"};
};

TEST_F(ValidatedAttributionSourceStateTest, providedPackageValid) {
    const std::string package = "com.package1";
    EXPECT_CALL(mMockProvider, validateUidPackagePair(mUid, package)).WillOnce(Return(true));
    AttributionSourceState attr;
    attr.uid = mUid;
    attr.packageName = package;
    EXPECT_THAT(ValidatedAttributionSourceState::createFromTrustedUidNoPackage(attr, mMockProvider),
                IsOkAnd(Eq(attr)));
}

TEST_F(ValidatedAttributionSourceStateTest, providedPackageInvalid) {
    const std::string package = "com.package.spoof";
    EXPECT_CALL(mMockProvider, validateUidPackagePair(mUid, package)).WillOnce(Return(false));
    AttributionSourceState attr;
    attr.uid = mUid;
    attr.packageName = package;
    EXPECT_THAT(ValidatedAttributionSourceState::createFromTrustedUidNoPackage(attr, mMockProvider),
                IsErrorAnd(BinderStatusMatcher::hasException(EX_SECURITY)));
}

TEST_F(ValidatedAttributionSourceStateTest, packageLookup_whenMissingPackage) {
    EXPECT_CALL(mMockProvider, getPackagesForUid(mUid)).WillOnce(Return(mPackageList));
    AttributionSourceState attr;
    attr.uid = mUid;
    AttributionSourceState expectedAttr;
    expectedAttr.uid = mUid;
    expectedAttr.packageName = "com.package1";
    EXPECT_THAT(ValidatedAttributionSourceState::createFromTrustedUidNoPackage(attr, mMockProvider),
                IsOkAnd(Eq(expectedAttr)));
}

TEST_F(ValidatedAttributionSourceStateTest, packageLookup_whenEmptyPackage) {
    EXPECT_CALL(mMockProvider, getPackagesForUid(mUid)).WillOnce(Return(mPackageList));
    AttributionSourceState attr;
    attr.uid = mUid;
    attr.packageName = std::string{};
    AttributionSourceState expectedAttr;
    expectedAttr.uid = mUid;
    expectedAttr.packageName = "com.package1";
    EXPECT_THAT(ValidatedAttributionSourceState::createFromTrustedUidNoPackage(attr, mMockProvider),
                IsOkAnd(Eq(expectedAttr)));
}

TEST_F(ValidatedAttributionSourceStateTest, controllerNotInitialized) {
    EXPECT_CALL(mMockProvider, getPackagesForUid(mUid))
            .WillOnce(Return(unexpected{Status::fromExceptionCode(EX_ILLEGAL_STATE)}));
    AttributionSourceState attr;
    attr.uid = mUid;
    attr.packageName = std::string{};
    AttributionSourceState expectedAttr;
    expectedAttr.uid = mUid;
    expectedAttr.packageName = "com.package1";
    EXPECT_THAT(ValidatedAttributionSourceState::createFromTrustedUidNoPackage(attr, mMockProvider),
                IsErrorAnd(BinderStatusMatcher::hasException(EX_ILLEGAL_STATE)));
}

TEST_F(ValidatedAttributionSourceStateTest, uidNotFound) {
    EXPECT_CALL(mMockProvider, getPackagesForUid(mUid))
            .WillOnce(Return(unexpected{Status::fromExceptionCode(EX_ILLEGAL_ARGUMENT)}));
    AttributionSourceState attr;
    attr.uid = mUid;
    attr.packageName = std::string{};
    EXPECT_THAT(ValidatedAttributionSourceState::createFromTrustedUidNoPackage(attr, mMockProvider),
                IsErrorAnd(BinderStatusMatcher::hasException(EX_ILLEGAL_ARGUMENT)));
}
