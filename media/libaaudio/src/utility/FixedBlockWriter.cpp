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

#include "FixedBlockWriter.h"

// go/keep-sorted start
#include <memory.h>
#include <stdint.h>
// go/keep-sorted end

FixedBlockWriter::FixedBlockWriter(FixedBlockProcessor &fixedBlockProcessor)
        : FixedBlockAdapter(fixedBlockProcessor) {}


int32_t FixedBlockWriter::writeToStorage(const uint8_t *buffer, int32_t numBytes) {
    int32_t bytesToStore = numBytes;
    int32_t roomAvailable = mSize - mPosition;
    if (bytesToStore > roomAvailable) {
        bytesToStore = roomAvailable;
    }
    memcpy(&mStorage[mPosition], buffer, bytesToStore);
    mPosition += bytesToStore;
    return bytesToStore;
}

AdapterProcessResult FixedBlockWriter::processVariableBlock(uint8_t *buffer, int32_t numBytes) {
    int32_t bytesLeft = numBytes;
    int32_t bytesTotalProcessed = 0;

    // If we already have data in storage then add to it.
    if (mPosition > 0) {
        int32_t bytesWritten = writeToStorage(buffer, bytesLeft);
        buffer += bytesWritten;
        bytesLeft -= bytesWritten;
        bytesTotalProcessed += bytesWritten;
        // If storage full then flush it out
        if (mPosition == mSize) {
            int bytes = mFixedBlockProcessor.onProcessFixedBlock(mStorage.get(), mSize);
            mPosition = 0;
            if (bytes < 0) {
                return {AAUDIO_CALLBACK_RESULT_STOP, bytesTotalProcessed};
            } else if (bytes != mSize) {
                // Client only consumes part of the data, it may be busy.
                // Move the unprocessed data to the beginning of the storage, return earlier here.
                mPosition = mSize - bytes;
                memmove(mStorage.get(), mStorage.get() + bytes, mPosition);
                return {AAUDIO_CALLBACK_RESULT_CONTINUE, bytesTotalProcessed};
            }
        }
    }

    // Write through if enough for a complete block.
    while (bytesLeft > mSize) {
        int32_t bytesProcessed = mFixedBlockProcessor.onProcessFixedBlock(buffer, mSize);
        if (bytesProcessed < 0) {
            return {AAUDIO_CALLBACK_RESULT_STOP, bytesTotalProcessed};
        }
        buffer += bytesProcessed;
        bytesLeft -= bytesProcessed;
        bytesTotalProcessed += bytesProcessed;
    }

    // Save any remaining partial block for next time.
    if (bytesLeft > 0) {
        int32_t bytesWritten = writeToStorage(buffer, bytesLeft);
        bytesTotalProcessed += bytesWritten;
    }

    return {AAUDIO_CALLBACK_RESULT_CONTINUE, bytesTotalProcessed};
}
