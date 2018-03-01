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

#include <C2Buffer.h>
#include "allocator.h"

union Params {
  struct {
    uint32_t capacity;
    C2MemoryUsage usage;
  } data;
  uint8_t array[0];
  Params() : data{0, {0, 0}} {}
  Params(uint32_t size)
      : data{size, {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE}} {}
};

struct AllocationDtor {
  AllocationDtor(const std::shared_ptr<C2LinearAllocation> &alloc)
      : mAlloc(alloc) {}

  void operator()(BufferPoolAllocation *poolAlloc) { delete poolAlloc; }

  const std::shared_ptr<C2LinearAllocation> mAlloc;
};

ResultStatus VtsBufferPoolAllocator::allocate(
    const std::vector<uint8_t> &params,
    std::shared_ptr<BufferPoolAllocation> *alloc) {
  Params ionParams;
  memcpy(&ionParams, params.data(), std::min(sizeof(Params), params.size()));

  std::shared_ptr<C2LinearAllocation> linearAlloc;
  c2_status_t status = mAllocator->newLinearAllocation(
      ionParams.data.capacity, ionParams.data.usage, &linearAlloc);
  if (status == C2_OK && linearAlloc) {
    BufferPoolAllocation *ptr = new BufferPoolAllocation(linearAlloc->handle());
    if (ptr) {
      *alloc = std::shared_ptr<BufferPoolAllocation>(
          ptr, AllocationDtor(linearAlloc));
      if (*alloc) {
        return ResultStatus::OK;
      }
      delete ptr;
      return ResultStatus::NO_MEMORY;
    }
  }
  return ResultStatus::CRITICAL_ERROR;
}

bool VtsBufferPoolAllocator::compatible(const std::vector<uint8_t> &newParams,
                                        const std::vector<uint8_t> &oldParams) {
  size_t newSize = newParams.size();
  size_t oldSize = oldParams.size();
  if (newSize == oldSize) {
    for (size_t i = 0; i < newSize; ++i) {
      if (newParams[i] != oldParams[i]) {
        return false;
      }
    }
    return true;
  }
  return false;
}

void getVtsAllocatorParams(std::vector<uint8_t> *params) {
  constexpr static int kAllocationSize = 1024 * 10;
  Params ionParams(kAllocationSize);

  params->assign(ionParams.array, ionParams.array + sizeof(ionParams));
}
