/*
 * Copyright 2019 The Android Open Source Project
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

#ifndef CODEC2_HIDL_V1_1_UTILS_TYPES_H
#define CODEC2_HIDL_V1_1_UTILS_TYPES_H

#include <android/hardware/media/c2/1.1/IComponent.h>
#include <android/hardware/media/c2/1.0/IComponentInterface.h>
#include <android/hardware/media/c2/1.0/IComponentListener.h>
#include <android/hardware/media/c2/1.1/IComponentStore.h>
#include <android/hardware/media/c2/1.0/IConfigurable.h>
#include <android/hardware/media/c2/1.0/IInputSink.h>
#include <android/hardware/media/c2/1.0/IInputSurface.h>
#include <android/hardware/media/c2/1.0/IInputSurfaceConnection.h>

#include <codec2/hidl/1.0/types.h>

namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace V1_1 {

using ::android::hardware::media::c2::V1_0::BaseBlock;
using ::android::hardware::media::c2::V1_0::Block;
using ::android::hardware::media::c2::V1_0::Buffer;
using ::android::hardware::media::c2::V1_0::FieldDescriptor;
using ::android::hardware::media::c2::V1_0::FieldId;
using ::android::hardware::media::c2::V1_0::FieldSupportedValues;
using ::android::hardware::media::c2::V1_0::FieldSupportedValuesQuery;
using ::android::hardware::media::c2::V1_0::FieldSupportedValuesQueryResult;
using ::android::hardware::media::c2::V1_0::FrameData;
using ::android::hardware::media::c2::V1_0::InfoBuffer;
using ::android::hardware::media::c2::V1_0::ParamDescriptor;
using ::android::hardware::media::c2::V1_0::ParamField;
using ::android::hardware::media::c2::V1_0::ParamFieldValues;
using ::android::hardware::media::c2::V1_0::ParamIndex;
using ::android::hardware::media::c2::V1_0::Params;
using ::android::hardware::media::c2::V1_0::PrimitiveValue;
using ::android::hardware::media::c2::V1_0::SettingResult;
using ::android::hardware::media::c2::V1_0::Status;
using ::android::hardware::media::c2::V1_0::StructDescriptor;
using ::android::hardware::media::c2::V1_0::ValueRange;
using ::android::hardware::media::c2::V1_0::Work;
using ::android::hardware::media::c2::V1_0::WorkBundle;
using ::android::hardware::media::c2::V1_0::WorkOrdinal;
using ::android::hardware::media::c2::V1_0::Worklet;

using ::android::hardware::media::c2::V1_0::IComponentInterface;
using ::android::hardware::media::c2::V1_0::IComponentListener;
using ::android::hardware::media::c2::V1_0::IConfigurable;
using ::android::hardware::media::c2::V1_0::IInputSink;
using ::android::hardware::media::c2::V1_0::IInputSurface;
using ::android::hardware::media::c2::V1_0::IInputSurfaceConnection;

namespace utils {

using ::android::hardware::media::c2::V1_0::utils::toC2Status;

using ::android::hardware::media::c2::V1_0::utils::C2Hidl_Range;
using ::android::hardware::media::c2::V1_0::utils::C2Hidl_RangeInfo;
using ::android::hardware::media::c2::V1_0::utils::C2Hidl_Rect;
using ::android::hardware::media::c2::V1_0::utils::C2Hidl_RectInfo;

using ::android::hardware::media::c2::V1_0::utils::objcpy;
using ::android::hardware::media::c2::V1_0::utils::parseParamsBlob;
using ::android::hardware::media::c2::V1_0::utils::createParamsBlob;
using ::android::hardware::media::c2::V1_0::utils::copyParamsFromBlob;
using ::android::hardware::media::c2::V1_0::utils::updateParamsFromBlob;

using ::android::hardware::media::c2::V1_0::utils::BufferPoolSender;
using ::android::hardware::media::c2::V1_0::utils::DefaultBufferPoolSender;

using ::android::hardware::media::c2::V1_0::utils::beginTransferBufferQueueBlock;
using ::android::hardware::media::c2::V1_0::utils::beginTransferBufferQueueBlocks;
using ::android::hardware::media::c2::V1_0::utils::endTransferBufferQueueBlock;
using ::android::hardware::media::c2::V1_0::utils::endTransferBufferQueueBlocks;
using ::android::hardware::media::c2::V1_0::utils::displayBufferQueueBlock;

using ::android::hardware::media::c2::V1_0::utils::operator<<;

} // namespace utils
} // namespace V1_1
} // namespace c2
} // namespace media
} // namespace hardware
} // namespace android

#endif // CODEC2_HIDL_V1_1_UTILS_TYPES_H
