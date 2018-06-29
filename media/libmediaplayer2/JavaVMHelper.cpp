/*
 * Copyright 2018 The Android Open Source Project
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

#define LOG_TAG "JavaVMHelper"

#include "mediaplayer2/JavaVMHelper.h"

#include <media/stagefright/foundation/ADebug.h>

#include <stdlib.h>

namespace android {

// static
std::atomic<JavaVM *> JavaVMHelper::sJavaVM(NULL);

// static
JNIEnv *JavaVMHelper::getJNIEnv() {
    JNIEnv *env;
    JavaVM *vm = sJavaVM.load();
    CHECK(vm != NULL);

    if (vm->GetEnv((void **)&env, JNI_VERSION_1_4) != JNI_OK) {
        return NULL;
    }

    return env;
}

// static
void JavaVMHelper::setJavaVM(JavaVM *vm) {
    sJavaVM.store(vm);
}

}  // namespace android
