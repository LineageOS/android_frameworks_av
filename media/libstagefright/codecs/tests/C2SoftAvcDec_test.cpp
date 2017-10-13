/*
 * Copyright 2017 The Android Open Source Project
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
#define LOG_TAG "C2SoftAvcDec_test"
#include <utils/Log.h>

#include <gtest/gtest.h>

#include <media/stagefright/foundation/MediaDefs.h>

#include "C2SoftAvcDec.h"

namespace android {

namespace {

template <class T>
std::unique_ptr<T> alloc_unique_cstr(const char *cstr) {
    std::unique_ptr<T> ptr = T::alloc_unique(strlen(cstr) + 1);
    strcpy(ptr->m.mValue, cstr);
    return ptr;
}

}  // namespace


class C2SoftAvcDecTest : public ::testing::Test {
public:
    C2SoftAvcDecTest() : mIntf(new C2SoftAvcDecIntf("dummy", 0u)) {}
    ~C2SoftAvcDecTest() = default;

    template <typename T>
    void testReadOnlyParam(const T *expected, const T *invalid);

    template <typename T>
    void testReadOnlyParamOnStack(const T *expected, const T *invalid);

    template <typename T>
    void testReadOnlyParamOnHeap(const T *expected, const T *invalid);

    template <typename T>
    void testReadOnlyFlexParam(
            const std::unique_ptr<T> &expected, const std::unique_ptr<T> &invalid);

protected:
    std::shared_ptr<C2SoftAvcDecIntf> mIntf;
};

template <typename T>
void C2SoftAvcDecTest::testReadOnlyParam(const T *expected, const T *invalid) {
    testReadOnlyParamOnStack(expected, invalid);
    testReadOnlyParamOnHeap(expected, invalid);
}

template <typename T>
void C2SoftAvcDecTest::testReadOnlyParamOnStack(const T *expected, const T *invalid) {
    T param;
    ASSERT_EQ(C2_OK, mIntf->query_nb({&param}, {}, nullptr));
    ASSERT_EQ(*expected, param);

    std::vector<C2Param * const> params{ (C2Param * const)invalid };
    std::vector<std::unique_ptr<C2SettingResult>> failures;
    ASSERT_EQ(C2_BAD_VALUE, mIntf->config_nb(params, &failures));

    // The param must not change after failed config.
    ASSERT_EQ(C2_OK, mIntf->query_nb({&param}, {}, nullptr));
    ASSERT_EQ(*expected, param);
}

template <typename T>
void C2SoftAvcDecTest::testReadOnlyParamOnHeap(const T *expected, const T *invalid) {
    std::vector<std::unique_ptr<C2Param>> heapParams;

    uint32_t index = expected->type();
    if (expected->forStream()) {
        index |= ((expected->stream() << 17) & 0x01FE0000) | 0x02000000;
    }

    ASSERT_EQ(C2_OK, mIntf->query_nb({}, {index}, &heapParams));
    ASSERT_EQ(1u, heapParams.size());
    ASSERT_EQ(*expected, *heapParams[0]);

    std::vector<C2Param * const> params{ (C2Param * const)invalid };
    std::vector<std::unique_ptr<C2SettingResult>> failures;
    ASSERT_EQ(C2_BAD_VALUE, mIntf->config_nb(params, &failures));

    // The param must not change after failed config.
    heapParams.clear();
    ASSERT_EQ(C2_OK, mIntf->query_nb({}, {index}, &heapParams));
    ASSERT_EQ(1u, heapParams.size());
    ASSERT_EQ(*expected, *heapParams[0]);
}

template <typename T>
void C2SoftAvcDecTest::testReadOnlyFlexParam(
        const std::unique_ptr<T> &expected, const std::unique_ptr<T> &invalid) {
    std::vector<std::unique_ptr<C2Param>> heapParams;

    uint32_t index = expected->type();
    if (expected->forStream()) {
        index |= ((expected->stream() << 17) & 0x01FE0000) | 0x02000000;
    }

    ASSERT_EQ(C2_OK, mIntf->query_nb({}, {index}, &heapParams));
    ASSERT_EQ(1u, heapParams.size());
    ASSERT_EQ(*expected, *heapParams[0]);

    std::vector<C2Param * const> params{ invalid.get() };
    std::vector<std::unique_ptr<C2SettingResult>> failures;
    ASSERT_EQ(C2_BAD_VALUE, mIntf->config_nb(params, &failures));

    // The param must not change after failed config.
    heapParams.clear();
    ASSERT_EQ(C2_OK, mIntf->query_nb({}, {index}, &heapParams));
    ASSERT_EQ(1u, heapParams.size());
    ASSERT_EQ(*expected, *heapParams[0]);
}


TEST_F(C2SoftAvcDecTest, TestNameAndId) {
    EXPECT_STREQ("dummy", mIntf->getName().c_str());
    EXPECT_EQ(0u, mIntf->getId());
}

TEST_F(C2SoftAvcDecTest, TestDomainInfo) {
    C2ComponentDomainInfo expected(C2DomainVideo);
    C2ComponentDomainInfo invalid(C2DomainAudio);
    testReadOnlyParam(&expected, &invalid);
}

TEST_F(C2SoftAvcDecTest, TestInputStreamCount) {
    C2PortStreamCountConfig::input expected(1);
    C2PortStreamCountConfig::input invalid(100);
    testReadOnlyParam(&expected, &invalid);
}

TEST_F(C2SoftAvcDecTest, TestOutputStreamCount) {
    C2PortStreamCountConfig::output expected(1);
    C2PortStreamCountConfig::output invalid(100);
    testReadOnlyParam(&expected, &invalid);
}

TEST_F(C2SoftAvcDecTest, TestInputPortMime) {
    std::unique_ptr<C2PortMimeConfig::input> expected(
            alloc_unique_cstr<C2PortMimeConfig::input>(MEDIA_MIMETYPE_VIDEO_AVC));
    std::unique_ptr<C2PortMimeConfig::input> invalid(
            alloc_unique_cstr<C2PortMimeConfig::input>(MEDIA_MIMETYPE_VIDEO_RAW));
    testReadOnlyFlexParam(expected, invalid);
}

TEST_F(C2SoftAvcDecTest, TestOutputPortMime) {
    std::unique_ptr<C2PortMimeConfig::output> expected(
            alloc_unique_cstr<C2PortMimeConfig::output>(MEDIA_MIMETYPE_VIDEO_RAW));
    std::unique_ptr<C2PortMimeConfig::output> invalid(
            alloc_unique_cstr<C2PortMimeConfig::output>(MEDIA_MIMETYPE_VIDEO_AVC));
    testReadOnlyFlexParam(expected, invalid);
}

TEST_F(C2SoftAvcDecTest, TestInputStreamFormat) {
    C2StreamFormatConfig::input expected(0u, C2FormatCompressed);
    C2StreamFormatConfig::input invalid(0u, C2FormatVideo);
    testReadOnlyParam(&expected, &invalid);
}

TEST_F(C2SoftAvcDecTest, TestOutputStreamFormat) {
    C2StreamFormatConfig::output expected(0u, C2FormatVideo);
    C2StreamFormatConfig::output invalid(0u, C2FormatCompressed);
    testReadOnlyParam(&expected, &invalid);
}

} // namespace android
