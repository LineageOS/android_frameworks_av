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

#ifndef AAUDIO_FIXED_BLOCK_ADAPTER_H
#define AAUDIO_FIXED_BLOCK_ADAPTER_H

#include <aaudio/AAudio.h>

// go/keep-sorted start
#include <memory>
#include <stdio.h>
#include <utility>
// go/keep-sorted end

/**
 * Interface for a class that needs fixed-size blocks.
 */
class FixedBlockProcessor {
public:
    virtual ~FixedBlockProcessor() = default;
    virtual int32_t onProcessFixedBlock(uint8_t *buffer, int32_t numBytes) = 0;
};

// The first value is used to indicate if callback should be stopped or continued.
// The second value is the actual processed size in bytes.
using AdapterProcessResult = std::pair<aaudio_data_callback_result_t, int32_t>;

/**
 * Base class for a variable-to-fixed-size block adapter.
 */
class FixedBlockAdapter
{
public:
    explicit FixedBlockAdapter(FixedBlockProcessor &fixedBlockProcessor)
    : mFixedBlockProcessor(fixedBlockProcessor) {}

    virtual ~FixedBlockAdapter() = default;

    /**
     * Allocate internal resources needed for buffering data.
     */
    virtual int32_t open(int32_t bytesPerFixedBlock);

    /**
     * Note that if the fixed-sized blocks must be aligned, then the variable-sized blocks
     * must have the same alignment.
     * For example, if the fixed-size blocks must be a multiple of 8, then the variable-sized
     * blocks must also be a multiple of 8.
     *
     * @param buffer
     * @param numBytes
     * @return
     */
    virtual AdapterProcessResult processVariableBlock(uint8_t *buffer, int32_t numBytes) = 0;

    /**
     * Free internal resources.
     */
    int32_t close();

protected:
    FixedBlockProcessor  &mFixedBlockProcessor;
    std::unique_ptr<uint8_t[]> mStorage;         // Store data here while assembling buffers.
    int32_t               mSize = 0;             // Size in bytes of the fixed size buffer.
    int32_t               mPosition = 0;         // Offset of the last byte read or written.
    int32_t               mAvailable = 0;        // Total available data in storage
};

#endif /* AAUDIO_FIXED_BLOCK_ADAPTER_H */
