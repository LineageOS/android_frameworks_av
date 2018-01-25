/*
 * Copyright 2018, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "InputSurface"
#include <utils/Log.h>

#include <C2AllocatorGralloc.h>
#include <C2PlatformSupport.h>

#include <media/stagefright/bqhelper/GraphicBufferSource.h>
#include <media/stagefright/codec2/1.0/InputSurface.h>

namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace V1_0 {
namespace implementation {

using ::android::GraphicBufferSource;

sp<InputSurface> InputSurface::Create() {
    sp<GraphicBufferSource> source = new GraphicBufferSource;
    if (source->initCheck() != OK) {
        return nullptr;
    }
    return new InputSurface(source->getIGraphicBufferProducer(), source);
}

InputSurface::InputSurface(
        const sp<BGraphicBufferProducer> &base, const sp<GraphicBufferSource> &source)
    : InputSurfaceBase(base),
      mSource(source) {
}

sp<InputSurfaceConnection> InputSurface::connectToComponent(
        const std::shared_ptr<C2Component> &comp) {
    sp<InputSurfaceConnection> conn = new InputSurfaceConnection(mSource, comp);
    if (!conn->init()) {
        return nullptr;
    }
    return conn;
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android
