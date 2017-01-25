/*
 * Copyright (C) 2017 The Android Open Source Project
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

#define LOG_TAG "EffectBufferHalLocal"
//#define LOG_NDEBUG 0

#include <utils/Log.h>

#include "EffectBufferHalLocal.h"

namespace android {

// static
status_t EffectBufferHalInterface::allocate(
        size_t size, sp<EffectBufferHalInterface>* buffer) {
    *buffer = new EffectBufferHalLocal(size);
    return OK;
}

// static
status_t EffectBufferHalInterface::mirror(
        void* external, size_t size, sp<EffectBufferHalInterface>* buffer) {
    *buffer = new EffectBufferHalLocal(external, size);
    return OK;
}

EffectBufferHalLocal::EffectBufferHalLocal(size_t size)
        : mOwnBuffer(new uint8_t[size]),
          mBufferSize(size),
          mAudioBuffer{0, {mOwnBuffer.get()}} {
}

EffectBufferHalLocal::EffectBufferHalLocal(void* external, size_t size)
        : mOwnBuffer(nullptr),
          mBufferSize(size),
          mAudioBuffer{0, {external}} {
}

EffectBufferHalLocal::~EffectBufferHalLocal() {
}

audio_buffer_t* EffectBufferHalLocal::audioBuffer() {
    return &mAudioBuffer;
}

void* EffectBufferHalLocal::externalData() const {
    return mAudioBuffer.raw;
}

void EffectBufferHalLocal::setFrameCount(size_t frameCount) {
    mAudioBuffer.frameCount = frameCount;
}

void EffectBufferHalLocal::setExternalData(void* external) {
    ALOGE_IF(mOwnBuffer != nullptr, "Attempt to set external data for allocated buffer");
    mAudioBuffer.raw = external;
}

void EffectBufferHalLocal::update() {
}

void EffectBufferHalLocal::commit() {
}

void EffectBufferHalLocal::update(size_t size) {
}

void EffectBufferHalLocal::commit(size_t size) {
}

} // namespace android
