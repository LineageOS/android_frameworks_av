/*
 * Copyright 2019 The Android Open Source Project
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

#define LOG_TAG "NdkJavaVMHelper"

#include "NdkJavaVMHelperPriv.h"
#include <utils/Log.h>

namespace android {

// static
JNIEnv *NdkJavaVMHelper::getJNIEnv() {
    JNIEnv *env;
    jsize nVMs;
    JavaVM *vm;

    int status = JNI_GetCreatedJavaVMs(&vm, 1, &nVMs);
    if (status != JNI_OK || nVMs == 0 || vm == NULL) {
        ALOGE("Failed to get JVM instance");
        return NULL;
    } else if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        ALOGE("Failed to get JNIEnv for JavaVM: %p", vm);
        return NULL;
    }

    return env;
}

}  // namespace android