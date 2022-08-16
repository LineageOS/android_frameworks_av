/*
 * Copyright (C) 2021 The Android Open Source Project
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
#pragma once

#include <utils/RefBase.h>

#include "ClearKeyTypes.h"

namespace clearkeydrm {
struct Buffer : public ::android::RefBase {
    explicit Buffer(size_t capacity);

    uint8_t* base() { return reinterpret_cast<uint8_t*>(mData); }
    uint8_t* data() { return reinterpret_cast<uint8_t*>(mData) + mRangeOffset; }
    size_t capacity() const { return mCapacity; }
    size_t size() const { return mRangeLength; }
    size_t offset() const { return mRangeOffset; }

  protected:
    virtual ~Buffer();

  private:
    void* mData;
    size_t mCapacity;
    size_t mRangeOffset;
    size_t mRangeLength;

    bool mOwnsData;

    CLEARKEY_DISALLOW_COPY_AND_ASSIGN(Buffer);
};

}  // namespace clearkeydrm
