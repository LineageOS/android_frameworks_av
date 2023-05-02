/*
 * Copyright (C) 2022 The Android Open Source Project
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
#ifndef MEDIA_LIBAUDIOUSECASEVALIDATION_TESTS_USECASEVALIDATOR_TEST_H_
#define MEDIA_LIBAUDIOUSECASEVALIDATION_TESTS_USECASEVALIDATOR_TEST_H_

#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <mutex>
#include <set>

#include "media/UsecaseLookup.h"
#include "media/UsecaseValidator.h"

namespace android {
namespace media {

#define MEDIA_OUTPUT_FLAGS (audio_output_flags_t)(0xFFFFF &\
                                ~(AUDIO_OUTPUT_FLAG_FAST | AUDIO_OUTPUT_FLAG_MMAP_NOIRQ))

#define GAME_OUTPUT_FLAGS (audio_output_flags_t)\
                                (AUDIO_OUTPUT_FLAG_FAST | AUDIO_OUTPUT_FLAG_MMAP_NOIRQ)

class TestCallback : public UsecaseValidator::AttributesChangedCallback {
 public:
    TestCallback() {
        m_iCallCnt = 0;
    }
    virtual ~TestCallback() { }
    virtual void onAttributesChanged(audio_port_handle_t /*portId*/,
                                     const audio_attributes_t& /*attributes*/) {
        ++m_iCallCnt;
    }

 public:
    int m_iCallCnt;
};

class UsecaseLookupTest : public UsecaseLookup, public ::testing::Test {
 public:
    UsecaseLookupTest() { }
    virtual ~UsecaseLookupTest() = default;
};

class UsecaseValidatorTest : public ::testing::Test {
 public:
    UsecaseValidatorTest() {
        m_validator = createUsecaseValidator();
    }

    virtual ~UsecaseValidatorTest() = default;

 protected:
    audio_io_handle_t testRegisterStream(bool outputFlagGame);
    audio_port_handle_t testCreatePortId(audio_io_handle_t streamId);
    error::Result<audio_attributes_t> testStartClient(audio_io_handle_t streamId,
                                                      audio_port_handle_t portId,
                                                      audio_attributes_t attributes);
    error::Result<audio_attributes_t> testVerifyAudioAttributes(audio_io_handle_t streamId,
                                                                audio_usage_t usage);

    std::unique_ptr<UsecaseValidator> m_validator;
};

}  // namespace media
}  // namespace android

#endif  // MEDIA_LIBAUDIOUSECASEVALIDATION_TESTS_USECASEVALIDATOR_TEST_H_
