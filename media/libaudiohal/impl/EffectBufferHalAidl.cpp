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

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#define LOG_TAG "EffectBufferHalAidl"
//#define LOG_NDEBUG 0

#include <cutils/ashmem.h>
#include <utils/Log.h>

#include "EffectBufferHalAidl.h"

using ndk::ScopedFileDescriptor;

namespace android {
namespace effect {

// static
status_t EffectBufferHalAidl::allocate(size_t size, sp<EffectBufferHalInterface>* buffer) {
    return mirror(nullptr, size, buffer);
}

status_t EffectBufferHalAidl::mirror(void* external, size_t size,
                                     sp<EffectBufferHalInterface>* buffer) {
    sp<EffectBufferHalAidl> tempBuffer = new EffectBufferHalAidl(size);
    status_t status = tempBuffer.get()->init();
    if (status != OK) {
        ALOGE("%s init failed %d", __func__, status);
        return status;
    }

    tempBuffer->setExternalData(external);
    *buffer = tempBuffer;
    return OK;
}

EffectBufferHalAidl::EffectBufferHalAidl(size_t size)
    : mBufferSize(size),
      mFrameCountChanged(false),
      mExternalData(nullptr),
      mAudioBuffer{0, {nullptr}} {
}

EffectBufferHalAidl::~EffectBufferHalAidl() {
    if (mAudioBuffer.raw) free(mAudioBuffer.raw);
}

status_t EffectBufferHalAidl::init() {
    if (0 != posix_memalign(&mAudioBuffer.raw, 32, mBufferSize)) {
        return NO_MEMORY;
    }

    return OK;
}

audio_buffer_t* EffectBufferHalAidl::audioBuffer() {
    return &mAudioBuffer;
}

void* EffectBufferHalAidl::externalData() const {
    return mExternalData;
}

void EffectBufferHalAidl::setFrameCount(size_t frameCount) {
    mAudioBuffer.frameCount = frameCount;
    mFrameCountChanged = true;
}

bool EffectBufferHalAidl::checkFrameCountChange() {
    bool result = mFrameCountChanged;
    mFrameCountChanged = false;
    return result;
}

void EffectBufferHalAidl::setExternalData(void* external) {
    mExternalData = external;
}

void EffectBufferHalAidl::update() {
    update(mBufferSize);
}

void EffectBufferHalAidl::commit() {
    commit(mBufferSize);
}

void EffectBufferHalAidl::copy(void* dst, const void* src, size_t n) const {
    if (!dst || !src) {
        return;
    }
    std::memcpy(dst, src, std::min(n, mBufferSize));
}

void EffectBufferHalAidl::update(size_t n) {
    copy(mAudioBuffer.raw, mExternalData, n);
}

void EffectBufferHalAidl::commit(size_t n) {
    copy(mExternalData, mAudioBuffer.raw, n);
}

} // namespace effect
} // namespace android
