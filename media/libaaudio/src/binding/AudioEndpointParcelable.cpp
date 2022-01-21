/*
 * Copyright 2016 The Android Open Source Project
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

#define LOG_TAG "AudioEndpointParcelable"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <stdint.h>

#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <utility/AAudioUtilities.h>

#include "binding/AAudioServiceDefinitions.h"
#include "binding/RingBufferParcelable.h"
#include "binding/AudioEndpointParcelable.h"

using android::base::unique_fd;
using android::status_t;

using namespace aaudio;

AudioEndpointParcelable::AudioEndpointParcelable(Endpoint&& parcelable)
        : mUpMessageQueueParcelable(parcelable.upMessageQueueParcelable),
          mDownMessageQueueParcelable(parcelable.downMessageQueueParcelable),
          mUpDataQueueParcelable(parcelable.upDataQueueParcelable),
          mDownDataQueueParcelable(parcelable.downDataQueueParcelable),
          mNumSharedMemories(parcelable.sharedMemories.size()) {
    for (size_t i = 0; i < parcelable.sharedMemories.size() && i < MAX_SHARED_MEMORIES; ++i) {
        // Re-construct.
        mSharedMemories[i].~SharedMemoryParcelable();
        new(&mSharedMemories[i]) SharedMemoryParcelable(std::move(parcelable.sharedMemories[i]));
    }
}

AudioEndpointParcelable& AudioEndpointParcelable::operator=(Endpoint&& parcelable) {
    this->~AudioEndpointParcelable();
    new(this) AudioEndpointParcelable(std::move(parcelable));
    return *this;
}

Endpoint AudioEndpointParcelable::parcelable()&& {
    Endpoint result;
    result.upMessageQueueParcelable = mUpMessageQueueParcelable.parcelable();
    result.downMessageQueueParcelable = mDownMessageQueueParcelable.parcelable();
    result.upDataQueueParcelable = mUpDataQueueParcelable.parcelable();
    result.downDataQueueParcelable = mDownDataQueueParcelable.parcelable();
    result.sharedMemories.reserve(std::min(mNumSharedMemories, MAX_SHARED_MEMORIES));
    for (size_t i = 0; i < mNumSharedMemories && i < MAX_SHARED_MEMORIES; ++i) {
        result.sharedMemories.emplace_back(std::move(mSharedMemories[i]).parcelable());
    }
    return result;
}

/**
 * Add the file descriptor to the table.
 * @return index in table or negative error
 */
int32_t AudioEndpointParcelable::addFileDescriptor(const unique_fd& fd,
                                                   int32_t sizeInBytes) {
    if (mNumSharedMemories >= MAX_SHARED_MEMORIES) {
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }
    int32_t index = mNumSharedMemories++;
    mSharedMemories[index].setup(fd, sizeInBytes);
    return index;
}

void AudioEndpointParcelable::closeDataFileDescriptor() {
    const int32_t curDataMemoryIndex = mDownDataQueueParcelable.getSharedMemoryIndex();
    mSharedMemories[curDataMemoryIndex].closeAndReleaseFd();
}

void AudioEndpointParcelable::updateDataFileDescriptor(
        AudioEndpointParcelable* endpointParcelable) {
    const int32_t curDataMemoryIndex = mDownDataQueueParcelable.getSharedMemoryIndex();
    const int32_t newDataMemoryIndex =
            endpointParcelable->mDownDataQueueParcelable.getSharedMemoryIndex();
    mSharedMemories[curDataMemoryIndex].close();
    mSharedMemories[curDataMemoryIndex].setup(
            endpointParcelable->mSharedMemories[newDataMemoryIndex]);
    mDownDataQueueParcelable.updateMemory(endpointParcelable->mDownDataQueueParcelable);
}

aaudio_result_t AudioEndpointParcelable::resolve(EndpointDescriptor *descriptor) {
    aaudio_result_t result = mUpMessageQueueParcelable.resolve(mSharedMemories,
                                                           &descriptor->upMessageQueueDescriptor);
    if (result != AAUDIO_OK) return result;
    result = mDownMessageQueueParcelable.resolve(mSharedMemories,
                                        &descriptor->downMessageQueueDescriptor);
    if (result != AAUDIO_OK) return result;

    result = mDownDataQueueParcelable.resolve(mSharedMemories,
                                              &descriptor->dataQueueDescriptor);
    return result;
}

aaudio_result_t AudioEndpointParcelable::resolveDataQueue(RingBufferDescriptor *descriptor) {
    return mDownDataQueueParcelable.resolve(mSharedMemories, descriptor);
}

aaudio_result_t AudioEndpointParcelable::close() {
    int err = 0;
    for (int i = 0; i < mNumSharedMemories; i++) {
        int lastErr = mSharedMemories[i].close();
        if (lastErr < 0) err = lastErr;
    }
    return AAudioConvert_androidToAAudioResult(err);
}

aaudio_result_t AudioEndpointParcelable::validate() const {
    if (mNumSharedMemories < 0 || mNumSharedMemories >= MAX_SHARED_MEMORIES) {
        ALOGE("invalid mNumSharedMemories = %d", mNumSharedMemories);
        return AAUDIO_ERROR_INTERNAL;
    }
    return AAUDIO_OK;
}

void AudioEndpointParcelable::dump() {
    ALOGD("======================================= BEGIN");
    ALOGD("mNumSharedMemories = %d", mNumSharedMemories);
    for (int i = 0; i < mNumSharedMemories; i++) {
        mSharedMemories[i].dump();
    }
    ALOGD("mUpMessageQueueParcelable =========");
    mUpMessageQueueParcelable.dump();
    ALOGD("mDownMessageQueueParcelable =======");
    mDownMessageQueueParcelable.dump();
    ALOGD("mUpDataQueueParcelable ============");
    mUpDataQueueParcelable.dump();
    ALOGD("mDownDataQueueParcelable ==========");
    mDownDataQueueParcelable.dump();
    ALOGD("======================================= END");
}

