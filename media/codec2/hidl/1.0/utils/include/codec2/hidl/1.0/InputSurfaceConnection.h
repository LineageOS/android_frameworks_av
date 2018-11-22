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

#ifndef CODEC2_HIDL_V1_0_UTILS_INPUTSURFACECONNECTION_H
#define CODEC2_HIDL_V1_0_UTILS_INPUTSURFACECONNECTION_H

#include <codec2/hidl/1.0/Component.h>

#include <android/hardware/media/c2/1.0/IComponent.h>
#include <android/hardware/media/c2/1.0/IInputSurfaceConnection.h>

#include <media/stagefright/bqhelper/GraphicBufferSource.h>

#include <hidl/HidlSupport.h>
#include <hidl/Status.h>

#include <C2Component.h>

#include <memory>
#include <mutex>

namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {

using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;
using ::android::GraphicBufferSource;

struct InputSurfaceConnection : public IInputSurfaceConnection {

    virtual Return<Status> disconnect() override;

protected:

    InputSurfaceConnection(
            const sp<GraphicBufferSource>& source,
            const std::shared_ptr<C2Component>& component);

    InputSurfaceConnection(
            const sp<GraphicBufferSource>& source,
            const sp<IComponent>& component);

    bool init();

    friend struct InputSurface;

    InputSurfaceConnection() = delete;
    InputSurfaceConnection(const InputSurfaceConnection&) = delete;
    void operator=(const InputSurfaceConnection&) = delete;

    struct Impl;

    std::mutex mMutex;
    sp<GraphicBufferSource> mSource;
    sp<Impl> mImpl;

    virtual ~InputSurfaceConnection() override;
};

}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android

#endif  // CODEC2_HIDL_V1_0_UTILS_INPUTSURFACECONNECTION_H
