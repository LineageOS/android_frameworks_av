/*
 * Copyright (C) 2016 The Android Open Source Project
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
 *
 */

#define LOG_TAG "AAudio"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <assert.h>
#include <functional>
#include <iomanip>
#include <new>
#include <sstream>
#include <stdint.h>
#include <utils/Mutex.h>

#include <aaudio/AAudio.h>
#include "AAudioUtilities.h"
#include "HandleTracker.h"

using android::Mutex;

// Handle format is: tgggiiii
// where each letter is 4 bits, t=type, g=generation, i=index

#define TYPE_SIZE           4
#define GENERATION_SIZE    12
#define INDEX_SIZE         16

#define GENERATION_INVALID  0
#define GENERATION_SHIFT    INDEX_SIZE

#define TYPE_MASK           ((1 << TYPE_SIZE) - 1)
#define GENERATION_MASK     ((1 << GENERATION_SIZE) - 1)
#define INDEX_MASK          ((1 << INDEX_SIZE) - 1)

#define SLOT_UNAVAILABLE    (-1)

// Error if handle is negative so type is limited to bottom half.
#define HANDLE_INVALID_TYPE TYPE_MASK

static_assert(HANDLE_TRACKER_MAX_TYPES == (1 << (TYPE_SIZE - 1)),
    "Mismatch between header and cpp.");
static_assert(HANDLE_TRACKER_MAX_HANDLES == (1 << (INDEX_SIZE)),
    "Mismatch between header and cpp.");

HandleTracker::HandleTracker(uint32_t maxHandles)
        : mMaxHandleCount(maxHandles)
        , mHandleHeaders(nullptr)
{
    assert(maxHandles <= HANDLE_TRACKER_MAX_HANDLES);
    // Allocate arrays to hold addresses and validation info.
    mHandleAddresses = (handle_tracker_address_t *)
            new(std::nothrow) handle_tracker_address_t[maxHandles];
    if (mHandleAddresses != nullptr) {
        mHandleHeaders = new(std::nothrow) handle_tracker_header_t[maxHandles];

        if (mHandleHeaders != nullptr) {
            handle_tracker_header_t initialHeader = buildHeader(0, 1);
            // Initialize linked list of free nodes. nullptr terminated.
            for (uint32_t i = 0; i < (maxHandles - 1); i++) {
                mHandleAddresses[i] = &mHandleAddresses[i + 1]; // point to next node
                mHandleHeaders[i] = initialHeader;
            }
            mNextFreeAddress = &mHandleAddresses[0];
            mHandleAddresses[maxHandles - 1] = nullptr;
            mHandleHeaders[maxHandles - 1] = 0;
        } else {
            delete[] mHandleAddresses; // so the class appears uninitialized
            mHandleAddresses = nullptr;
        }
    }
}

HandleTracker::~HandleTracker()
{
    Mutex::Autolock _l(mLock);
    delete[] mHandleAddresses;
    delete[] mHandleHeaders;
    mHandleAddresses = nullptr;
}

bool HandleTracker::isInitialized() const {
    return mHandleAddresses != nullptr;
}



std::string HandleTracker::dump() const {
    if (!isInitialized()) {
        return "HandleTracker is not initialized\n";
    }

    std::stringstream result;
    const bool isLocked = AAudio_tryUntilTrue(
            [this]()->bool { return mLock.tryLock(); } /* f */,
            50 /* times */,
            20 /* sleepMs */);
    if (!isLocked) {
        result << "HandleTracker may be deadlocked\n";
    }

    result << "HandleTracker:\n";
    result << "  HandleHeaders:\n";
    // atLineStart() can be changed to support an arbitrary line breaking algorithm;
    // it should return true when a new line starts.
    // For simplicity, we will use a constant 16 items per line.
    const auto atLineStart = [](int index) -> bool {
        // Magic constant of 0xf used for mask to detect start every 16 items.
        return (index & 0xf) == 0; };
    const auto atLineEnd = [this, &atLineStart](int index) -> bool {
        return atLineStart(index + 1) || index == mMaxHandleCount - 1; };

    for (int i = 0; i < mMaxHandleCount; ++i) {
        if (atLineStart(i)) {
            result << "    ";
        }
        result << std::hex << std::setw(4) << std::setfill('0') << mHandleHeaders[i]
               << (atLineEnd(i) ? "\n" : " ");
    }

    if (isLocked) {
        mLock.unlock();
    }
    return result.str();
}

handle_tracker_slot_t HandleTracker::allocateSlot_l() {
    void **allocated = mNextFreeAddress;
    if (allocated == nullptr) {
        return SLOT_UNAVAILABLE;
    }
    // Remove this slot from the head of the linked list.
    mNextFreeAddress = (void **) *allocated;
    return (allocated - mHandleAddresses);
}

handle_tracker_generation_t HandleTracker::nextGeneration_l(handle_tracker_slot_t index) {
    handle_tracker_generation_t generation = (mHandleHeaders[index] + 1) & GENERATION_MASK;
    // Avoid generation zero so that 0x0 is not a valid handle.
    if (generation == GENERATION_INVALID) {
        generation++;
    }
    return generation;
}

aaudio_handle_t HandleTracker::put(handle_tracker_type_t type, void *address)
{
    if (type < 0 || type >= HANDLE_TRACKER_MAX_TYPES) {
        return static_cast<aaudio_handle_t>(AAUDIO_ERROR_OUT_OF_RANGE);
    }
    if (!isInitialized()) {
        return static_cast<aaudio_handle_t>(AAUDIO_ERROR_NO_MEMORY);
    }

    Mutex::Autolock _l(mLock);

    // Find an empty slot.
    handle_tracker_slot_t index = allocateSlot_l();
    if (index == SLOT_UNAVAILABLE) {
        ALOGE("HandleTracker::put() no room for more handles");
        return static_cast<aaudio_handle_t>(AAUDIO_ERROR_NO_FREE_HANDLES);
    }

    // Cycle the generation counter so stale handles can be detected.
    handle_tracker_generation_t generation = nextGeneration_l(index); // reads header table
    handle_tracker_header_t inputHeader = buildHeader(type, generation);

    // These two writes may need to be observed by other threads or cores during get().
    mHandleHeaders[index] = inputHeader;
    mHandleAddresses[index] = address;
    // TODO use store release to enforce memory order with get()

    // Generate a handle.
    aaudio_handle_t handle = buildHandle(inputHeader, index);

    ALOGV("HandleTracker::put(%p) returns 0x%08x", address, handle);
    return handle;
}

handle_tracker_slot_t HandleTracker::handleToIndex(handle_tracker_type_t type,
                                                   aaudio_handle_t handle) const
{
    // Validate the handle.
    handle_tracker_slot_t index = extractIndex(handle);
    if (index >= mMaxHandleCount) {
        ALOGE("HandleTracker::handleToIndex() invalid handle = 0x%08X", handle);
        return static_cast<aaudio_handle_t>(AAUDIO_ERROR_INVALID_HANDLE);
    }
    handle_tracker_generation_t handleGeneration = extractGeneration(handle);
    handle_tracker_header_t inputHeader = buildHeader(type, handleGeneration);
    // We do not need to synchronize this access to mHandleHeaders because it is constant for
    // the lifetime of the handle.
    if (inputHeader != mHandleHeaders[index]) {
        ALOGE("HandleTracker::handleToIndex() inputHeader = 0x%08x != mHandleHeaders[%d] = 0x%08x",
             inputHeader, index, mHandleHeaders[index]);
        return static_cast<aaudio_handle_t>(AAUDIO_ERROR_INVALID_HANDLE);
    }
    return index;
}

handle_tracker_address_t HandleTracker::get(handle_tracker_type_t type, aaudio_handle_t handle) const
{
    if (!isInitialized()) {
        return nullptr;
    }
    handle_tracker_slot_t index = handleToIndex(type, handle);
    if (index >= 0) {
        // We do not need to synchronize this access to mHandleHeaders because this slot
        // is allocated and, therefore, not part of the linked list of free slots.
        return mHandleAddresses[index];
    } else {
        return nullptr;
    }
}

handle_tracker_address_t HandleTracker::remove(handle_tracker_type_t type, aaudio_handle_t handle) {
    if (!isInitialized()) {
        return nullptr;
    }

    Mutex::Autolock _l(mLock);

    handle_tracker_slot_t index = handleToIndex(type,handle);
    if (index >= 0) {
        handle_tracker_address_t address = mHandleAddresses[index];

        // Invalidate the header type but preserve the generation count.
        handle_tracker_generation_t generation = mHandleHeaders[index] & GENERATION_MASK;
        handle_tracker_header_t inputHeader = buildHeader(
                (handle_tracker_type_t) HANDLE_INVALID_TYPE, generation);
        mHandleHeaders[index] = inputHeader;

        // Add this slot to the head of the linked list.
        mHandleAddresses[index] = mNextFreeAddress;
        mNextFreeAddress = (handle_tracker_address_t *) &mHandleAddresses[index];
        return address;
    } else {
        return nullptr;
    }
}

aaudio_handle_t HandleTracker::buildHandle(handle_tracker_header_t typeGeneration,
                                         handle_tracker_slot_t index) {
    return (aaudio_handle_t)((typeGeneration << GENERATION_SHIFT) | (index & INDEX_MASK));
}

handle_tracker_header_t HandleTracker::buildHeader(handle_tracker_type_t type,
                                    handle_tracker_generation_t generation)
{
    return (handle_tracker_header_t) (((type & TYPE_MASK) << GENERATION_SIZE)
        | (generation & GENERATION_MASK));
}

handle_tracker_slot_t HandleTracker::extractIndex(aaudio_handle_t handle)
{
    return handle & INDEX_MASK;
}

handle_tracker_generation_t HandleTracker::extractGeneration(aaudio_handle_t handle)
{
    return (handle >> GENERATION_SHIFT) & GENERATION_MASK;
}
