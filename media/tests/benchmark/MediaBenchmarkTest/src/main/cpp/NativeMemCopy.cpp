/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_TAG "NativeMemCopy"

#include <android/hardware_buffer_jni.h>
#include <jni.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vndk/hardware_buffer.h>
#include <cstring>

#include "BenchmarkCommon.h"

extern "C" JNIEXPORT int JNICALL Java_com_android_media_benchmark_library_Native_NativeMemCopy(
        JNIEnv *env, jobject thiz, jobject jHardwareBuffer, jobject jData, jlong jSize) {
    UNUSED(thiz);
    if (jHardwareBuffer == nullptr || jData == nullptr) {
        return -1;
    }

    void *src_addr = env->GetDirectBufferAddress(jData);
    if (src_addr == nullptr) {
        return -1;
    }

    AHardwareBuffer *ahwb = AHardwareBuffer_fromHardwareBuffer(env, jHardwareBuffer);
    if (ahwb == nullptr) {
        return -1;
    }

    const native_handle_t *handle = AHardwareBuffer_getNativeHandle(ahwb);
    if (handle == nullptr || handle->numFds < 1) {
        return -1;
    }

    int buf_fd = handle->data[0];
    void *buf_addr = mmap(NULL, jSize, PROT_WRITE, MAP_SHARED, buf_fd, 0);
    if (buf_addr == MAP_FAILED) {
        return -1;
    }

    memcpy(buf_addr, src_addr, jSize);

    munmap(buf_addr, jSize);
    return 0;
}
