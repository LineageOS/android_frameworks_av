/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <gtest/gtest.h>

#define LOG_TAG "APM_Test"
#include <android-base/file.h>
#include <log/log.h>

#include "EngineConfig.h"

using namespace android;

TEST(EngineConfigTestInit, LegacyVolumeGroupsLoadingIsTransactional) {
    engineConfig::VolumeGroups groups;
    ASSERT_TRUE(groups.empty());
    status_t status = engineConfig::parseLegacyVolumeFile(
            (base::GetExecutableDirectory() + "/test_invalid_apm_volume_tables.xml").c_str(),
            groups);
    ASSERT_NE(NO_ERROR, status);
    EXPECT_TRUE(groups.empty());
    status = engineConfig::parseLegacyVolumeFile(
            (base::GetExecutableDirectory() + "/test_apm_volume_tables.xml").c_str(),
            groups);
    ASSERT_EQ(NO_ERROR, status);
    EXPECT_FALSE(groups.empty());
}
