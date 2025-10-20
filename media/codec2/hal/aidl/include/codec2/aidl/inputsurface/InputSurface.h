/*
 * Copyright 2024 The Android Open Source Project
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

#include <aidl/android/hardware/media/c2/BnInputSurface.h>
#include <utils/RefBase.h>

#include <C2.h>
#include <C2Config.h>
#include <codec2/aidl/Configurable.h>
#include <util/C2InterfaceHelper.h>

#include <memory>

namespace aidl::android::hardware::media::c2::implementation {
class InputSurfaceSource;
}

namespace aidl::android::hardware::media::c2::utils {
struct InputSurfaceConnection;

struct InputSurface : public BnInputSurface {
    InputSurface();
    c2_status_t status() const;

    // Methods from IInputSurface follow.
    ::ndk::ScopedAStatus getSurface(
            ::aidl::android::view::Surface* surface) override;
    ::ndk::ScopedAStatus getConfigurable(
            std::shared_ptr<IConfigurable>* configurable) override;
    ::ndk::ScopedAStatus connect(
            const std::shared_ptr<IInputSink>& sink,
            std::shared_ptr<IInputSurfaceConnection>* connection) override;

    c2_status_t start();

    // Constant definitions.
    // Default image size for AImageReader
    constexpr static uint32_t kDefaultImageWidth = 1280;
    constexpr static uint32_t kDefaultImageHeight = 720;
    // Default # of buffers for AImageReader
    constexpr static uint32_t kDefaultImageBufferCount = 16;
    constexpr static uint32_t kDefaultImageDataspace = HAL_DATASPACE_BT709;

    // Configs
    // Config for AImageReader creation
    struct ImageConfig {
        int32_t mWidth;         // image width
        int32_t mHeight;        // image height
        int32_t mFormat;        // image pixel format
        int32_t mNumBuffers;    // number of max images for AImageReader(consumer)
        uint64_t mUsage;        // image usage
        uint32_t mDataspace;    // image dataspace
    };

    // Config for InputSurface active buffer stream control
    struct StreamConfig {
        // IN PARAMS
        float mMinFps = 0.0;        // minimum fps (repeat frame to achieve this)
        float mMaxFps = 0.0;        // max fps (via frame drop)
        float mCaptureFps = 0.0;    // capture fps
        float mCodedFps = 0.0;      // coded fps
        bool mSuspended = false;    // suspended
        int64_t mSuspendAtUs = 0;   // suspend time
        int64_t mResumeAtUs = 0;   // resume time
        bool mStopped = false;      // stopped
        int64_t mStopAtUs = 0;      // stop time
        int64_t mStartAtUs = 0;     // start time
        int64_t mTimeOffsetUs = 0;  // time offset (input => codec)

        // IN PARAMS (CODEC WRAPPER)
        C2TimestampGapAdjustmentStruct::mode_t
                mAdjustedFpsMode = C2TimestampGapAdjustmentStruct::NONE;
        int64_t mAdjustedGapUs = 0;
        int mPriority = INT_MAX;        // priority of queue thread (if any);
                                        // INT_MAX for no-op
    };

    // TODO: optimize this
    // The client requests the change of these configurations now.
    // We can request the change of these configurations from HAL directly
    // where onWorkDone() callback is called.
    //
    // Config for current work status w.r.t input buffers
    struct WorkStatusConfig {
        uint64_t mLastDoneIndex = UINT64_MAX;      // Last work done buffer frame index
        uint32_t mLastDoneCount = 0;      // # of work done count
        uint64_t mEmptyCount = 0;         // # of input buffers being emptied
    };


protected:
    class Interface;
    class ConfigurableIntf;

    std::once_flag mInit;
    std::shared_ptr<Interface> mIntf;
    std::shared_ptr<CachedConfigurable> mConfigurable;

    virtual ~InputSurface() override;

private:
    ::android::sp<implementation::InputSurfaceSource> mSource;
    std::shared_ptr<InputSurfaceConnection> mConnection;

    ImageConfig mImageConfig;
    StreamConfig mStreamConfig;
    WorkStatusConfig mWorkStatusConfig;

    std::mutex mLock;

    struct SourceEventCallback;
    std::shared_ptr<SourceEventCallback> mSourceEventCallback;

    friend class ConfigurableIntf;

    bool updateConfig(
            ImageConfig &imageConfig,
            StreamConfig &streamConfig,
            WorkStatusConfig &workStatusConfig,
            int64_t *inputDelayUs);

    void updateImageConfig(ImageConfig &config);
    bool updateStreamConfig(StreamConfig &config, int64_t *inputDelayUs);
    void updateWorkStatusConfig(WorkStatusConfig &config);

    void init();
    void release();
};

}  // namespace aidl::android::hardware::media::c2::utils
