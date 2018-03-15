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

#define LOG_NDEBUG 0
#define LOG_TAG "C2SoftRAW"
#include <utils/Log.h>

#include "C2SoftRaw.h"

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/MediaDefs.h>

namespace android {

constexpr char kComponentName[] = "c2.google.raw.decoder";

static std::shared_ptr<C2ComponentInterface> BuildIntf(
        const char *name, c2_node_id_t id,
        std::function<void(C2ComponentInterface*)> deleter =
            std::default_delete<C2ComponentInterface>()) {
    return SimpleC2Interface::Builder(name, id, deleter)
            .inputFormat(C2FormatCompressed)
            .outputFormat(C2FormatAudio)
            .inputMediaType(MEDIA_MIMETYPE_AUDIO_RAW)
            .outputMediaType(MEDIA_MIMETYPE_AUDIO_RAW)
            .build();
}

C2SoftRaw::C2SoftRaw(const char *name, c2_node_id_t id)
    : SimpleC2Component(BuildIntf(name, id)) {
}

C2SoftRaw::~C2SoftRaw() {
    onRelease();
}

c2_status_t C2SoftRaw::onInit() {
    mSignalledEos = false;
    return C2_OK;
}

c2_status_t C2SoftRaw::onStop() {
    mSignalledEos = false;
    return C2_OK;
}

void C2SoftRaw::onReset() {
    (void)onStop();
}

void C2SoftRaw::onRelease() {
}

c2_status_t C2SoftRaw::onFlush_sm() {
    return onStop();
}

void C2SoftRaw::process(
        const std::unique_ptr<C2Work> &work,
        const std::shared_ptr<C2BlockPool> &pool) {
    (void)pool;
    work->result = C2_OK;
    work->workletsProcessed = 0u;
    if (mSignalledEos) {
        work->result = C2_BAD_VALUE;
        return;
    }

    const C2ConstLinearBlock inBuffer = work->input.buffers[0]->data().linearBlocks().front();
    size_t inSize = inBuffer.size();

    ALOGV("in buffer attr. size %zu timestamp %d frameindex %d", inSize,
          (int)work->input.ordinal.timestamp.peeku(), (int)work->input.ordinal.frameIndex.peeku());

    work->worklets.front()->output.flags = work->input.flags;
    work->worklets.front()->output.buffers.clear();
    work->worklets.front()->output.ordinal = work->input.ordinal;
    if (inSize != 0) {
        work->worklets.front()->output.buffers.push_back(work->input.buffers[0]);
    }
    work->workletsProcessed = 1u;
    if (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) {
        mSignalledEos = true;
        ALOGV("signalled EOS");
    }
}

c2_status_t C2SoftRaw::drain(
        uint32_t drainMode,
        const std::shared_ptr<C2BlockPool> &pool) {
    (void) pool;
    if (drainMode == NO_DRAIN) {
        ALOGW("drain with NO_DRAIN: no-op");
        return C2_OK;
    }
    if (drainMode == DRAIN_CHAIN) {
        ALOGW("DRAIN_CHAIN not supported");
        return C2_OMITTED;
    }

    return C2_OK;
}

class C2SoftRawDecFactory : public C2ComponentFactory {
public:
    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(new C2SoftRaw(kComponentName, id), deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id,
            std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = BuildIntf(kComponentName, id, deleter);
        return C2_OK;
    }

    virtual ~C2SoftRawDecFactory() override = default;
};

}  // namespace android

extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftRawDecFactory();
}

extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
