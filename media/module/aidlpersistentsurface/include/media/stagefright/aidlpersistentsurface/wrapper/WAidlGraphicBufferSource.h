/*
 * Copyright 2024, The Android Open Source Project
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
#include <aidl/android/hardware/graphics/common/Dataspace.h>
#include <aidl/android/media/IAidlBufferSource.h>
#include <aidl/android/media/IAidlNode.h>
#include <aidl/android/media/BnAidlGraphicBufferSource.h>

namespace android::media {

class AidlGraphicBufferSource;

using ::android::sp;

/**
 * Aidl wrapper implementation for IAidlGraphicBufferSource
 */
class WAidlGraphicBufferSource : public ::aidl::android::media::BnAidlGraphicBufferSource {
public:

    struct WAidlNodeWrapper;
    class WAidlBufferSource;

    sp<AidlGraphicBufferSource> mBase;
    std::shared_ptr<::aidl::android::media::IAidlBufferSource> mBufferSource;

    WAidlGraphicBufferSource(sp<AidlGraphicBufferSource> const& base);
    ::ndk::ScopedAStatus configure(
            const std::shared_ptr<::aidl::android::media::IAidlNode>& node,
            aidl::android::hardware::graphics::common::Dataspace dataspace) override;
    ::ndk::ScopedAStatus setSuspend(bool suspend, int64_t timeUs) override;
    ::ndk::ScopedAStatus setRepeatPreviousFrameDelayUs(int64_t repeatAfterUs) override;
    ::ndk::ScopedAStatus setMaxFps(float maxFps) override;
    ::ndk::ScopedAStatus setTimeLapseConfig(double fps, double captureFps) override;
    ::ndk::ScopedAStatus setStartTimeUs(int64_t startTimeUs) override;
    ::ndk::ScopedAStatus setStopTimeUs(int64_t stopTimeUs) override;
    ::ndk::ScopedAStatus getStopTimeOffsetUs(int64_t *_aidl_return) override;
    ::ndk::ScopedAStatus setColorAspects(
            const ::aidl::android::media::AidlColorAspects& aspects) override;
    ::ndk::ScopedAStatus setTimeOffsetUs(int64_t timeOffsetUs) override;
    ::ndk::ScopedAStatus signalEndOfInputStream() override;
};

}  // namespace android::media
