/*
 * Copyright (C) 2022 The Android Open Source Project
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

#ifndef ANDROID_SERVERS_CAMERA_CAMERA3_JPEG_R_COMPOSITE_STREAM_H
#define ANDROID_SERVERS_CAMERA_CAMERA3_JPEG_R_COMPOSITE_STREAM_H

#include <gui/CpuConsumer.h>
#include "aidl/android/hardware/graphics/common/Dataspace.h"
#include "system/graphics-base-v1.1.h"

#include "api1/client2/JpegProcessor.h"
#include "utils/SessionStatsBuilder.h"

#include "CompositeStream.h"

namespace android {

class CameraDeviceClient;
class CameraMetadata;
class Surface;

namespace camera3 {

class JpegRCompositeStream : public CompositeStream, public Thread,
        public CpuConsumer::FrameAvailableListener {

public:
    JpegRCompositeStream(sp<CameraDeviceBase> device,
            wp<hardware::camera2::ICameraDeviceCallbacks> cb);
    ~JpegRCompositeStream() override;

    static bool isJpegRCompositeStream(const sp<Surface> &surface);
    static bool isJpegRCompositeStreamInfo(const OutputStreamInfo& streamInfo);

    // CompositeStream overrides
    status_t createInternalStreams(const std::vector<sp<Surface>>& consumers,
            bool hasDeferredConsumer, uint32_t width, uint32_t height, int format,
            camera_stream_rotation_t rotation, int *id, const std::string& physicalCameraId,
            const std::unordered_set<int32_t> &sensorPixelModesUsed,
            std::vector<int> *surfaceIds,
            int streamSetId, bool isShared, int32_t colorSpace,
            int64_t dynamicProfile, int64_t streamUseCase, bool useReadoutTimestamp) override;
    status_t deleteInternalStreams() override;
    status_t configureStream() override;
    status_t insertGbp(SurfaceMap* /*out*/outSurfaceMap, Vector<int32_t>* /*out*/outputStreamIds,
            int32_t* /*out*/currentStreamId) override;
    status_t insertCompositeStreamIds(std::vector<int32_t>* compositeStreamIds /*out*/) override;
    int getStreamId() override { return mP010StreamId; }

    // CpuConsumer listener implementation
    void onFrameAvailable(const BufferItem& item) override;

    // Return stream information about the internal camera streams
    static status_t getCompositeStreamInfo(const OutputStreamInfo &streamInfo,
            const CameraMetadata& ch, std::vector<OutputStreamInfo>* compositeOutput /*out*/);

    // Get composite stream stats
    void getStreamStats(hardware::CameraStreamStats* streamStats) override;

protected:

    bool threadLoop() override;
    bool onStreamBufferError(const CaptureResultExtras& resultExtras) override;
    void onResultError(const CaptureResultExtras& resultExtras) override;

private:
    struct InputFrame {
        CpuConsumer::LockedBuffer p010Buffer;
        CpuConsumer::LockedBuffer jpegBuffer;
        CameraMetadata            result;
        bool                      error;
        bool                      errorNotified;
        int64_t                   frameNumber;
        int32_t                   requestId;
        nsecs_t                   requestTimeNs;

        InputFrame() : error(false), errorNotified(false), frameNumber(-1), requestId(-1),
            requestTimeNs(-1) { }
    };

    status_t processInputFrame(nsecs_t ts, const InputFrame &inputFrame);

    // Buffer/Results handling
    void compilePendingInputLocked();
    void releaseInputFrameLocked(InputFrame *inputFrame /*out*/);
    void releaseInputFramesLocked(int64_t currentTs);

    // Find first complete and valid frame with smallest timestamp
    bool getNextReadyInputLocked(int64_t *currentTs /*inout*/);

    // Find next failing frame number with smallest timestamp and return respective frame number
    int64_t getNextFailingInputLocked(int64_t *currentTs /*inout*/);

    static void deriveDynamicRangeAndDataspace(int64_t dynamicProfile, int64_t* /*out*/dynamicRange,
            int64_t* /*out*/dataSpace);

    static const nsecs_t kWaitDuration = 10000000; // 10 ms
    static const auto kP010PixelFormat = HAL_PIXEL_FORMAT_YCBCR_P010;
    static const auto kP010DefaultDataSpace = HAL_DATASPACE_BT2020_ITU_HLG;
    static const auto kP010DefaultDynamicRange =
        ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_HLG10;
    static const auto kJpegDataSpace = HAL_DATASPACE_V0_JFIF;
    static const auto kJpegRDataSpace =
        aidl::android::hardware::graphics::common::Dataspace::JPEG_R;

    bool                 mSupportInternalJpeg = false;
    int64_t              mP010DataSpace = HAL_DATASPACE_BT2020_HLG;
    int64_t              mP010DynamicRange =
        ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_HLG10;
    int                  mBlobStreamId, mBlobSurfaceId, mP010StreamId, mP010SurfaceId;
    size_t               mBlobWidth, mBlobHeight;
    sp<CpuConsumer>      mBlobConsumer, mP010Consumer;
    bool                 mP010BufferAcquired, mBlobBufferAcquired;
    sp<Surface>          mP010Surface, mBlobSurface, mOutputSurface;
    int32_t              mOutputColorSpace;
    int64_t              mOutputStreamUseCase;
    nsecs_t              mFirstRequestLatency;
    sp<ProducerListener> mProducerListener;

    ssize_t              mMaxJpegBufferSize;
    ssize_t              mUHRMaxJpegBufferSize;

    camera3::Size        mDefaultMaxJpegSize;
    camera3::Size        mUHRMaxJpegSize;

    // Keep all incoming P010 buffer timestamps pending further processing.
    std::vector<int64_t> mInputP010Buffers;

    // Keep all incoming Jpeg/Blob buffer timestamps pending further processing.
    std::vector<int64_t> mInputJpegBuffers;

    // Map of all input frames pending further processing.
    std::unordered_map<int64_t, InputFrame> mPendingInputFrames;

    const CameraMetadata mStaticInfo;

    SessionStatsBuilder  mSessionStatsBuilder;
};

}; //namespace camera3
}; //namespace android

#endif
