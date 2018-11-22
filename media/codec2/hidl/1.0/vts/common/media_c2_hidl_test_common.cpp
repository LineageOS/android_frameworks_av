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

#define LOG_TAG "media_c2_hidl_test_common"
#include <stdio.h>

#include "media_c2_hidl_test_common.h"
using ::android::hardware::media::c2::V1_0::FieldSupportedValues;

void dumpFSV(const FieldSupportedValues& sv) {
    ALOGD("Dumping FSV data");
    using namespace std;
    if (sv.type == FieldSupportedValues::Type::EMPTY) {
        ALOGD("FSV Value is Empty");
    }
    if (sv.type == FieldSupportedValues::Type::RANGE) {
        ALOGD("Dumping FSV range");
        cout << ".range(" << sv.range.min;
        if (sv.range.step != 0) {
            cout << ":" << sv.range.step;
        }
        if (sv.range.num != 1 || sv.range.denom != 1) {
            cout << ":" << sv.range.num << "/" << sv.range.denom;
        }
        cout << " " << sv.range.max << ")";
    }
    if (sv.values.size()) {
        ALOGD("Dumping FSV value");
        cout << (sv.type == FieldSupportedValues::Type::FLAGS ? ".flags("
                                                              : ".list(");
        const char* sep = "";
        for (const auto& p : sv.values) {
            cout << sep << p;
            sep = ",";
        }
        cout << ")";
    }
    cout << endl;
}
