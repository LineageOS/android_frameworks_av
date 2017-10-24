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

#ifndef UTILITY_HANDLE_TRACKER_H
#define UTILITY_HANDLE_TRACKER_H

#include <stdint.h>
#include <string>
#include <utils/Mutex.h>

typedef int32_t  aaudio_handle_t;
typedef int32_t  handle_tracker_type_t;       // what kind of handle
typedef int32_t  handle_tracker_slot_t;       // index in allocation table
typedef int32_t  handle_tracker_generation_t; // incremented when slot used
typedef uint16_t handle_tracker_header_t;     // combines type and generation
typedef void    *handle_tracker_address_t;    // address of something that is stored here

#define HANDLE_TRACKER_MAX_TYPES    (1 << 3)
#define HANDLE_TRACKER_MAX_HANDLES  (1 << 16)

/**
 * Represent Objects using an integer handle that can be used with Java.
 * This also makes the 'C' ABI more robust.
 *
 * Note that this should only be called from a single thread.
 * If you call it from more than one thread then you need to use your own mutex.
 */
class HandleTracker {

public:
    /**
     * @param maxHandles cannot exceed HANDLE_TRACKER_MAX_HANDLES
     */
    HandleTracker(uint32_t maxHandles = 256);
    virtual ~HandleTracker();

    /**
     * Don't use if this returns false;
     * @return true if the internal allocation succeeded
     */
    bool isInitialized() const;

    /**
     * Returns HandleTracker information.
     *
     * Will attempt to get the object lock, but will proceed
     * even if it cannot.
     *
     * Each line of information ends with a newline.
     *
     * @return a string representing the HandleTracker info.
     */
    std::string dump() const;

    /**
     * Store a pointer and return a handle that can be used to retrieve the pointer.
     *
     * It is safe to call put() or remove() from multiple threads.
     *
     * @param expectedType the type of the object to be tracked
     * @param address pointer to be converted to a handle
     * @return a valid handle or a negative error
     */
    aaudio_handle_t put(handle_tracker_type_t expectedType, handle_tracker_address_t address);

    /**
     * Get the original pointer associated with the handle.
     * The handle will be validated to prevent stale handles from being reused.
     * Note that the validation is designed to prevent common coding errors and not
     * to prevent deliberate hacking.
     *
     * @param expectedType shouldmatch the type we passed to put()
     * @param handle to be converted to a pointer
     * @return address associated with handle or nullptr
     */
    handle_tracker_address_t get(handle_tracker_type_t expectedType, aaudio_handle_t handle) const;

    /**
     * Free up the storage associated with the handle.
     * Subsequent attempts to use the handle will fail.
     *
     * Do NOT remove() a handle while get() is being called for the same handle from another thread.
     *
     * @param expectedType shouldmatch the type we passed to put()
     * @param handle to be removed from tracking
     * @return address associated with handle or nullptr if not found
     */
    handle_tracker_address_t remove(handle_tracker_type_t expectedType, aaudio_handle_t handle);

private:
    const int32_t               mMaxHandleCount;   // size of array
    // This address is const after initialization.
    handle_tracker_address_t  * mHandleAddresses;  // address of objects or a free linked list node
    // This address is const after initialization.
    handle_tracker_header_t   * mHandleHeaders;    // combination of type and generation
    // head of the linked list of free nodes in mHandleAddresses
    handle_tracker_address_t  * mNextFreeAddress;

    // This Mutex protects the linked list of free nodes.
    // The list is managed using mHandleAddresses and mNextFreeAddress.
    // The data in mHandleHeaders is only changed by put() and remove().
    mutable android::Mutex      mLock;

    /**
     * Pull slot off of a list of empty slots.
     * @return index or a negative error
     */
    handle_tracker_slot_t allocateSlot_l();

    /**
     * Increment the generation for the slot, avoiding zero.
     */
    handle_tracker_generation_t nextGeneration_l(handle_tracker_slot_t index);

    /**
     * Validate the handle and return the corresponding index.
     * @return slot index or a negative error
     */
    handle_tracker_slot_t handleToIndex(aaudio_handle_t handle, handle_tracker_type_t type) const;

    /**
     * Construct a handle from a header and an index.
     * @param header combination of a type and a generation
     * @param index slot index returned from allocateSlot
     * @return handle or a negative error
     */
    static aaudio_handle_t buildHandle(handle_tracker_header_t header, handle_tracker_slot_t index);

    /**
     * Combine a type and a generation field into a header.
     */
    static handle_tracker_header_t buildHeader(handle_tracker_type_t type,
                handle_tracker_generation_t generation);

    /**
     * Extract the index from a handle.
     * Does not validate the handle.
     * @return index associated with a handle
     */
    static handle_tracker_slot_t extractIndex(aaudio_handle_t handle);

    /**
     * Extract the generation from a handle.
     * Does not validate the handle.
     * @return generation associated with a handle
     */
    static handle_tracker_generation_t extractGeneration(aaudio_handle_t handle);

};

#endif //UTILITY_HANDLE_TRACKER_H
