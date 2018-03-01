/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef VTS_VNDK_HIDL_BUFFERPOOL_V1_0_ALLOCATOR_H
#define VTS_VNDK_HIDL_BUFFERPOOL_V1_0_ALLOCATOR_H

#include <BufferPoolTypes.h>

using android::hardware::media::bufferpool::V1_0::ResultStatus;
using android::hardware::media::bufferpool::V1_0::implementation::
    BufferPoolAllocation;
using android::hardware::media::bufferpool::V1_0::implementation::
    BufferPoolAllocator;

// buffer allocator for the tests
class VtsBufferPoolAllocator : public BufferPoolAllocator {
 public:
  VtsBufferPoolAllocator(const std::shared_ptr<C2Allocator> &allocator)
      : mAllocator(allocator) {}

  ~VtsBufferPoolAllocator() override {}

  ResultStatus allocate(const std::vector<uint8_t> &params,
                        std::shared_ptr<BufferPoolAllocation> *alloc) override;

  bool compatible(const std::vector<uint8_t> &newParams,
                  const std::vector<uint8_t> &oldParams) override;

 private:
  const std::shared_ptr<C2Allocator> mAllocator;
};

// retrieve buffer allocator paramters
void getVtsAllocatorParams(std::vector<uint8_t> *params);

#endif  // VTS_VNDK_HIDL_BUFFERPOOL_V1_0_ALLOCATOR_H
