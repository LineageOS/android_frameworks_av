/*
 * Copyright (C) 2021 The Android Open Source Project
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

#define LOG_TAG "TestExecutionTracer"

#include "test_execution_tracer.h"

#include <android-base/logging.h>

void TestExecutionTracer::OnTestStart(const ::testing::TestInfo& test_info) {
    TraceTestState("Started", test_info);
}

void TestExecutionTracer::OnTestEnd(const ::testing::TestInfo& test_info) {
    TraceTestState("Finished", test_info);
}

void TestExecutionTracer::OnTestPartResult(const ::testing::TestPartResult& result) {
    if (result.failed()) {
        LOG(ERROR) << result;
    } else {
        LOG(INFO) << result;
    }
}

// static
void TestExecutionTracer::TraceTestState(const std::string& state,
                                         const ::testing::TestInfo& test_info) {
    LOG(INFO) << state << " " << test_info.test_suite_name() << "::" << test_info.name();
}
