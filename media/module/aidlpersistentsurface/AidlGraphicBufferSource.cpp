/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <inttypes.h>

#define LOG_TAG "AidlGraphicBufferSource"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <media/stagefright/bqhelper/ComponentWrapper.h>
#include <media/stagefright/bqhelper/GraphicBufferSource.h>
#include <media/stagefright/aidlpersistentsurface/AidlGraphicBufferSource.h>
#include <media/stagefright/aidlpersistentsurface/C2NodeDef.h>

namespace android::media {

namespace {

class AidlComponentWrapper : public ComponentWrapper {
public:
    explicit AidlComponentWrapper(const sp<IAidlNodeWrapper> &node)
        : mAidlNode(node) {}
    virtual ~AidlComponentWrapper() = default;

    status_t submitBuffer(
            int32_t bufferId, const sp<GraphicBuffer> &buffer,
            int64_t timestamp, int fenceFd) override {
        return mAidlNode->submitBuffer(
                bufferId, BUFFERFLAG_ENDOFFRAME, buffer, timestamp, fenceFd);
    }

    status_t submitEos(int32_t bufferId) override {
        return mAidlNode->submitBuffer(
            bufferId, BUFFERFLAG_ENDOFFRAME | BUFFERFLAG_EOS);
    }

    void dispatchDataSpaceChanged(
            int32_t dataSpace, int32_t aspects, int32_t pixelFormat) override {
        mAidlNode->dispatchDataSpaceChanged(dataSpace, aspects, pixelFormat);
    }

private:
    sp<IAidlNodeWrapper> mAidlNode;

    DISALLOW_EVIL_CONSTRUCTORS(AidlComponentWrapper);
};

}  // namespace

::ndk::ScopedAStatus AidlGraphicBufferSource::onStart() {
    status_t err = start();
    return (OK == err) ? ::ndk::ScopedAStatus::ok() :
            ::ndk::ScopedAStatus::fromServiceSpecificError(err);
}

::ndk::ScopedAStatus AidlGraphicBufferSource::onStop() {
    status_t err = stop();
    return (OK == err) ? ::ndk::ScopedAStatus::ok() :
            ::ndk::ScopedAStatus::fromServiceSpecificError(err);
}

::ndk::ScopedAStatus AidlGraphicBufferSource::onRelease(){
    status_t err = release();
    return (OK == err) ? ::ndk::ScopedAStatus::ok() :
            ::ndk::ScopedAStatus::fromServiceSpecificError(err);
}

status_t AidlGraphicBufferSource::configure(
        const sp<IAidlNodeWrapper>& aidlNode,
        int32_t dataSpace,
        int32_t bufferCount,
        uint32_t frameWidth,
        uint32_t frameHeight,
        uint64_t consumerUsage) {
    if (aidlNode == NULL) {
        return BAD_VALUE;
    }

    return GraphicBufferSource::configure(
            new AidlComponentWrapper(aidlNode), dataSpace, bufferCount,
            frameWidth, frameHeight, consumerUsage);
}

}  // namespace android::media
