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

#define LOG_TAG "EffectBufferHalAidl"
//#define LOG_NDEBUG 0

#include <utils/Log.h>

#include "EffectBufferHalAidl.h"

namespace android {
namespace effect {

// static
status_t EffectBufferHalAidl::allocate(size_t size, sp<EffectBufferHalInterface>* buffer) {
    ALOGE("%s not implemented yet %zu %p", __func__, size, buffer);
    return mirror(nullptr, size, buffer);
}

status_t EffectBufferHalAidl::mirror(void* external, size_t size,
                                     sp<EffectBufferHalInterface>* buffer) {
    // buffer->setExternalData(external);
    ALOGW("%s not implemented yet %p %zu %p", __func__, external, size, buffer);
    return OK;
}

EffectBufferHalAidl::EffectBufferHalAidl(size_t size)
    : mBufferSize(size),
      mFrameCountChanged(false),
      mExternalData(nullptr),
      mAudioBuffer{0, {nullptr}} {
}

EffectBufferHalAidl::~EffectBufferHalAidl() {
}

status_t EffectBufferHalAidl::init() {
    ALOGW("%s not implemented yet", __func__);
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
    ALOGW("%s not implemented yet", __func__);
}

void EffectBufferHalAidl::commit() {
    ALOGW("%s not implemented yet", __func__);
}

} // namespace effect
} // namespace android
