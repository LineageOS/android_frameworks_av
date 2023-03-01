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

#include <map>
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
          mDownDataQueueParcelable(parcelable.downDataQueueParcelable) {
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

namespace {

void updateSharedMemoryIndex(SharedRegion* sharedRegion, int oldIndex, int newIndex) {
    if (sharedRegion->sharedMemoryIndex == oldIndex) {
        sharedRegion->sharedMemoryIndex = newIndex;
    }
}

void updateSharedMemoryIndex(RingBuffer* ringBuffer, int oldIndex, int newIndex) {
    updateSharedMemoryIndex(&ringBuffer->readCounterParcelable, oldIndex, newIndex);
    updateSharedMemoryIndex(&ringBuffer->writeCounterParcelable, oldIndex, newIndex);
    updateSharedMemoryIndex(&ringBuffer->dataParcelable, oldIndex, newIndex);
}

void updateSharedMemoryIndex(Endpoint* endpoint, int oldIndex, int newIndex) {
    updateSharedMemoryIndex(&endpoint->upMessageQueueParcelable, oldIndex, newIndex);
    updateSharedMemoryIndex(&endpoint->downMessageQueueParcelable, oldIndex, newIndex);
    updateSharedMemoryIndex(&endpoint->upDataQueueParcelable, oldIndex, newIndex);
    updateSharedMemoryIndex(&endpoint->downDataQueueParcelable, oldIndex, newIndex);
}

} // namespace

Endpoint AudioEndpointParcelable::parcelable()&& {
    Endpoint result;
    result.upMessageQueueParcelable = mUpMessageQueueParcelable.parcelable();
    result.downMessageQueueParcelable = mDownMessageQueueParcelable.parcelable();
    result.upDataQueueParcelable = mUpDataQueueParcelable.parcelable();
    result.downDataQueueParcelable = mDownDataQueueParcelable.parcelable();
    // To transfer through binder, only valid/in-use shared memory is allowed. By design, the
    // shared memories that are currently in-use may not be placed continuously from position 0.
    // However, when marshalling the shared memories into Endpoint, the shared memories will be
    // re-indexed from 0. In that case, when placing a shared memory, it is needed to update the
    // corresponding cached indexes.
    for (int i = 0; i < MAX_SHARED_MEMORIES; ++i) {
        if (mSharedMemories[i].isInUse()) {
            const int index = result.sharedMemories.size();
            result.sharedMemories.emplace_back(std::move(mSharedMemories[i]).parcelable());
            // Updating all the SharedRegion that is using `i` as shared memory index with the
            // new shared memory index as `result.sharedMemories.size() - 1`.
            updateSharedMemoryIndex(&result, i, index);
        }
    }
    return result;
}

/**
 * Add the file descriptor to the table.
 * @return index in table or negative error
 */
int32_t AudioEndpointParcelable::addFileDescriptor(const unique_fd& fd,
                                                   int32_t sizeInBytes) {
    const int32_t index = getNextAvailableSharedMemoryPosition();
    if (index < 0) {
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }
    mSharedMemories[index].setup(fd, sizeInBytes);
    return index;
}

void AudioEndpointParcelable::closeDataFileDescriptor() {
    for (const int32_t memoryIndex : std::set{mDownDataQueueParcelable.getDataSharedMemoryIndex(),
                                mDownDataQueueParcelable.getReadCounterSharedMemoryIndex(),
                                mDownDataQueueParcelable.getWriteCounterSharedMemoryIndex()}) {
        mSharedMemories[memoryIndex].closeAndReleaseFd();
    }
}

aaudio_result_t AudioEndpointParcelable::updateDataFileDescriptor(
        AudioEndpointParcelable* endpointParcelable) {
    // Before updating data file descriptor, close the old shared memories.
    closeDataFileDescriptor();
    // The given endpoint parcelable and this one are two different objects, the indexes in
    // `mSharedMemories` for `mDownDataQueueParcelable` can be different. In that case, an index
    // map, which maps from the index in given endpoint parcelable to the index in this endpoint
    // parcelable, is required when updating shared memory.
    std::map<int32_t, int32_t> memoryIndexMap;
    auto& downDataQueueParcelable = endpointParcelable->mDownDataQueueParcelable;
    for (const int32_t memoryIndex : {downDataQueueParcelable.getDataSharedMemoryIndex(),
                                      downDataQueueParcelable.getReadCounterSharedMemoryIndex(),
                                      downDataQueueParcelable.getWriteCounterSharedMemoryIndex()}) {
        if (memoryIndexMap.find(memoryIndex) != memoryIndexMap.end()) {
            // This shared memory has been set up in this endpoint parcelable.
            continue;
        }
        // Set up the memory in the next available shared memory position.
        const int index = getNextAvailableSharedMemoryPosition();
        if (index < 0) {
            return AAUDIO_ERROR_OUT_OF_RANGE;
        }
        mSharedMemories[index].setup(endpointParcelable->mSharedMemories[memoryIndex]);
        memoryIndexMap.emplace(memoryIndex, index);
    }
    mDownDataQueueParcelable.updateMemory(
            endpointParcelable->mDownDataQueueParcelable, memoryIndexMap);
    return AAUDIO_OK;
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
    for (auto& sharedMemory : mSharedMemories) {
        const int lastErr = sharedMemory.close();
        if (lastErr < 0) err = lastErr;
    }
    return AAudioConvert_androidToAAudioResult(err);
}

int32_t AudioEndpointParcelable::getNextAvailableSharedMemoryPosition() const {
    for (int i = 0; i < MAX_SHARED_MEMORIES; ++i) {
        if (!mSharedMemories[i].isInUse()) {
            return i;
        }
    }
    return -1;
}

void AudioEndpointParcelable::dump() {
    ALOGD("======================================= BEGIN");
    for (int i = 0; i < MAX_SHARED_MEMORIES; ++i) {
        if (mSharedMemories[i].isInUse()) {
            ALOGD("Shared memory index=%d", i);
            mSharedMemories[i].dump();
        }
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

