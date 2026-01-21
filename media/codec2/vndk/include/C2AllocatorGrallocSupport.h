/*
 * Copyright (C) 2025 The Android Open Source Project
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

#ifndef STAGEFRIGHT_CODEC2_ALLOCATOR_GRALLOC_SUPPORT_H_
#define STAGEFRIGHT_CODEC2_ALLOCATOR_GRALLOC_SUPPORT_H_

#include <C2Buffer.h>
#include <C2Config.h>

namespace android {

/**
 * Sets dataspace and HDR metadata to a gralloc buffer handle inside a graphic
 * block.
 *
 * This may be more optimal as it can access the block's underlying buffer
 * directly, potentially avoiding extra overhead.
 *
 * \param[in]   dataSpace   Dataspace to set.
 * \param[in]   staticInfo  HDR static info to set. Ignored if null or invalid.
 * \param[in]   dynamicInfo HDR dynamic info to set. Ignored if null or invalid.
 * \param[in]   block       graphic block.
 * \return C2_OK if successful
 */
c2_status_t SetMetadataToGralloc4Handle(
        android_dataspace_t dataSpace,
        const std::shared_ptr<const C2StreamHdrStaticMetadataInfo::output> &staticInfo,
        const std::shared_ptr<const C2StreamHdrDynamicMetadataInfo::output> &dynamicInfo,
        const C2ConstGraphicBlock &block);

} // namespace android

#endif // STAGEFRIGHT_CODEC2_ALLOCATOR_GRALLOC_SUPPORT_H_
