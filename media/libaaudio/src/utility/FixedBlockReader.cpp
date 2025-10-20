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

#include "FixedBlockReader.h"

// go/keep-sorted start
#include <memory.h>
#include <stdint.h>
// go/keep-sorted end

#include "FixedBlockAdapter.h"

FixedBlockReader::FixedBlockReader(FixedBlockProcessor &fixedBlockProcessor)
    : FixedBlockAdapter(fixedBlockProcessor) {
    mPosition = mSize;
    mAvailable = 0;
}

int32_t FixedBlockReader::open(int32_t bytesPerFixedBlock) {
    int32_t result = FixedBlockAdapter::open(bytesPerFixedBlock);
    mPosition = mSize; // Indicate no data in storage.
    mAvailable = 0;
    return result;
}

int32_t FixedBlockReader::readFromStorage(uint8_t *buffer, int32_t numBytes) {
    if (mAvailable <= mPosition) {
        return 0;
    }
    int32_t bytesToRead = numBytes;
    int32_t dataAvailable = mAvailable - mPosition;
    if (bytesToRead > dataAvailable) {
        bytesToRead = dataAvailable;
    }
    memcpy(buffer, &mStorage[mPosition], bytesToRead);
    mPosition += bytesToRead;
    return bytesToRead;
}

void FixedBlockReader::flush() {
    mPosition = mAvailable;
}

AdapterProcessResult FixedBlockReader::processVariableBlock(uint8_t *buffer, int32_t numBytes) {
    aaudio_data_callback_result_t result = AAUDIO_CALLBACK_RESULT_CONTINUE;
    int32_t bytesLeft = numBytes;
    int32_t totalBytesProcessed = 0;
    while (bytesLeft > 0) {
        if (mPosition < mAvailable) {
            // Use up bytes currently in storage.
            int32_t bytesRead = readFromStorage(buffer, bytesLeft);
            buffer += bytesRead;
            bytesLeft -= bytesRead;
            totalBytesProcessed += bytesRead;
        } else if (bytesLeft >= mSize) {
            // Read through if enough for a complete block.
            int32_t bytesProcessed = mFixedBlockProcessor.onProcessFixedBlock(buffer, mSize);
            if (bytesProcessed < 0) {
                result = AAUDIO_CALLBACK_RESULT_STOP;
                break;
            }
            buffer += bytesProcessed;
            bytesLeft -= bytesProcessed;
            totalBytesProcessed += bytesProcessed;
            if (bytesProcessed != mSize) {
                // The client my not be able to process all data. Let's return earlier
                // and come back later.
                break;
            }
        } else {
            // Just need a partial block so we have to use storage.
            mAvailable = mFixedBlockProcessor.onProcessFixedBlock(
                    mStorage.get(), mSize);
            if (mAvailable < 0) {
                result = AAUDIO_CALLBACK_RESULT_STOP;
                mAvailable = 0;
                break;
            } else {
                mPosition = 0;
                if (mAvailable != mSize) {
                    // The client my not be able to process all data. Let's return earlier
                    // and come back later.
                    break;
                }
            }
        }
    }
    return {result, totalBytesProcessed};
}

