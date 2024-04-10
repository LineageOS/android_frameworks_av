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

#include "hardware/gralloc.h"
#include "system/graphics-base-v1.0.h"
#include "system/graphics-base-v1.1.h"
#define LOG_TAG "Camera3-JpegRCompositeStream"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0

#include <aidl/android/hardware/camera/device/CameraBlob.h>
#include <aidl/android/hardware/camera/device/CameraBlobId.h>

#include "common/CameraProviderManager.h"
#include <gui/Surface.h>
#include <ultrahdr/jpegr.h>
#include <utils/ExifUtils.h>
#include <utils/Log.h>
#include "utils/SessionConfigurationUtils.h"
#include <utils/Trace.h>

#include "JpegRCompositeStream.h"

namespace android {
namespace camera3 {

using aidl::android::hardware::camera::device::CameraBlob;
using aidl::android::hardware::camera::device::CameraBlobId;

JpegRCompositeStream::JpegRCompositeStream(sp<CameraDeviceBase> device,
        wp<hardware::camera2::ICameraDeviceCallbacks> cb) :
        CompositeStream(device, cb),
        mBlobStreamId(-1),
        mBlobSurfaceId(-1),
        mP010StreamId(-1),
        mP010SurfaceId(-1),
        mBlobWidth(0),
        mBlobHeight(0),
        mP010BufferAcquired(false),
        mBlobBufferAcquired(false),
        mOutputColorSpace(ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_UNSPECIFIED),
        mOutputStreamUseCase(0),
        mFirstRequestLatency(-1),
        mProducerListener(new ProducerListener()),
        mMaxJpegBufferSize(-1),
        mUHRMaxJpegBufferSize(-1),
        mStaticInfo(device->info()) {
    auto entry = mStaticInfo.find(ANDROID_JPEG_MAX_SIZE);
    if (entry.count > 0) {
        mMaxJpegBufferSize = entry.data.i32[0];
    } else {
        ALOGW("%s: Maximum jpeg size absent from camera characteristics", __FUNCTION__);
    }

    mUHRMaxJpegSize =
            SessionConfigurationUtils::getMaxJpegResolution(mStaticInfo,
                    /*ultraHighResolution*/true);
    mDefaultMaxJpegSize =
            SessionConfigurationUtils::getMaxJpegResolution(mStaticInfo,
                    /*isUltraHighResolution*/false);

    mUHRMaxJpegBufferSize =
        SessionConfigurationUtils::getUHRMaxJpegBufferSize(mUHRMaxJpegSize, mDefaultMaxJpegSize,
                mMaxJpegBufferSize);
}

JpegRCompositeStream::~JpegRCompositeStream() {
    mBlobConsumer.clear(),
    mBlobSurface.clear(),
    mBlobStreamId = -1;
    mBlobSurfaceId = -1;
    mP010Consumer.clear();
    mP010Surface.clear();
    mP010Consumer = nullptr;
    mP010Surface = nullptr;
}

void JpegRCompositeStream::compilePendingInputLocked() {
    CpuConsumer::LockedBuffer imgBuffer;

    while (mSupportInternalJpeg && !mInputJpegBuffers.empty() && !mBlobBufferAcquired) {
        auto it = mInputJpegBuffers.begin();
        auto res = mBlobConsumer->lockNextBuffer(&imgBuffer);
        if (res == NOT_ENOUGH_DATA) {
            // Can not lock any more buffers.
            break;
        } else if (res != OK) {
            ALOGE("%s: Error locking blob image buffer: %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            mPendingInputFrames[*it].error = true;
            mInputJpegBuffers.erase(it);
            continue;
        }

        if (*it != imgBuffer.timestamp) {
            ALOGW("%s: Expecting jpeg buffer with time stamp: %" PRId64 " received buffer with "
                    "time stamp: %" PRId64, __FUNCTION__, *it, imgBuffer.timestamp);
        }

        if ((mPendingInputFrames.find(imgBuffer.timestamp) != mPendingInputFrames.end()) &&
                (mPendingInputFrames[imgBuffer.timestamp].error)) {
            mBlobConsumer->unlockBuffer(imgBuffer);
        } else {
            mPendingInputFrames[imgBuffer.timestamp].jpegBuffer = imgBuffer;
            mBlobBufferAcquired = true;
        }
        mInputJpegBuffers.erase(it);
    }

    while (!mInputP010Buffers.empty() && !mP010BufferAcquired) {
        auto it = mInputP010Buffers.begin();
        auto res = mP010Consumer->lockNextBuffer(&imgBuffer);
        if (res == NOT_ENOUGH_DATA) {
            // Can not lock any more buffers.
            break;
        } else if (res != OK) {
            ALOGE("%s: Error receiving P010 image buffer: %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            mPendingInputFrames[*it].error = true;
            mInputP010Buffers.erase(it);
            continue;
        }

        if (*it != imgBuffer.timestamp) {
            ALOGW("%s: Expecting P010 buffer with time stamp: %" PRId64 " received buffer with "
                    "time stamp: %" PRId64, __FUNCTION__, *it, imgBuffer.timestamp);
        }

        if ((mPendingInputFrames.find(imgBuffer.timestamp) != mPendingInputFrames.end()) &&
                (mPendingInputFrames[imgBuffer.timestamp].error)) {
            mP010Consumer->unlockBuffer(imgBuffer);
        } else {
            mPendingInputFrames[imgBuffer.timestamp].p010Buffer = imgBuffer;
            mP010BufferAcquired = true;
        }
        mInputP010Buffers.erase(it);
    }

    while (!mCaptureResults.empty()) {
        auto it = mCaptureResults.begin();
        // Negative timestamp indicates that something went wrong during the capture result
        // collection process.
        if (it->first >= 0) {
            auto frameNumber = std::get<0>(it->second);
            mPendingInputFrames[it->first].frameNumber = frameNumber;
            mPendingInputFrames[it->first].result = std::get<1>(it->second);
            mSessionStatsBuilder.incResultCounter(false /*dropped*/);
        }
        mCaptureResults.erase(it);
    }

    while (!mFrameNumberMap.empty()) {
        auto it = mFrameNumberMap.begin();
        auto frameNumber = it->first;
        mPendingInputFrames[it->second].frameNumber = frameNumber;
        auto requestTimeIt = mRequestTimeMap.find(frameNumber);
        if (requestTimeIt != mRequestTimeMap.end()) {
            mPendingInputFrames[it->second].requestTimeNs = requestTimeIt->second;
            mRequestTimeMap.erase(requestTimeIt);
        }
        mFrameNumberMap.erase(it);
    }

    auto it = mErrorFrameNumbers.begin();
    while (it != mErrorFrameNumbers.end()) {
        bool frameFound = false;
        for (auto &inputFrame : mPendingInputFrames) {
            if (inputFrame.second.frameNumber == *it) {
                inputFrame.second.error = true;
                frameFound = true;
                break;
            }
        }

        if (frameFound) {
            mSessionStatsBuilder.incCounter(mP010StreamId, true /*dropped*/,
                    0 /*captureLatencyMs*/);
            it = mErrorFrameNumbers.erase(it);
        } else {
            ALOGW("%s: Not able to find failing input with frame number: %" PRId64, __FUNCTION__,
                    *it);
            it++;
        }
    }
}

bool JpegRCompositeStream::getNextReadyInputLocked(int64_t *currentTs /*inout*/) {
    if (currentTs == nullptr) {
        return false;
    }

    bool newInputAvailable = false;
    for (const auto& it : mPendingInputFrames) {
        if ((!it.second.error) && (it.second.p010Buffer.data != nullptr) &&
                (it.second.requestTimeNs != -1) &&
                ((it.second.jpegBuffer.data != nullptr) || !mSupportInternalJpeg) &&
                (it.first < *currentTs)) {
            *currentTs = it.first;
            newInputAvailable = true;
        }
    }

    return newInputAvailable;
}

int64_t JpegRCompositeStream::getNextFailingInputLocked(int64_t *currentTs /*inout*/) {
    int64_t ret = -1;
    if (currentTs == nullptr) {
        return ret;
    }

    for (const auto& it : mPendingInputFrames) {
        if (it.second.error && !it.second.errorNotified && (it.first < *currentTs)) {
            *currentTs = it.first;
            ret = it.second.frameNumber;
        }
    }

    return ret;
}

status_t JpegRCompositeStream::processInputFrame(nsecs_t ts, const InputFrame &inputFrame) {
    status_t res;
    sp<ANativeWindow> outputANW = mOutputSurface;
    ANativeWindowBuffer *anb;
    int fenceFd;
    void *dstBuffer;

    size_t maxJpegRBufferSize = 0;
    if (mMaxJpegBufferSize > 0) {
        // If this is an ultra high resolution sensor and the input frames size
        // is > default res jpeg.
        if (mUHRMaxJpegSize.width != 0 &&
                inputFrame.jpegBuffer.width * inputFrame.jpegBuffer.height >
                mDefaultMaxJpegSize.width * mDefaultMaxJpegSize.height) {
            maxJpegRBufferSize = mUHRMaxJpegBufferSize;
        } else {
            maxJpegRBufferSize = mMaxJpegBufferSize;
        }
    } else {
        maxJpegRBufferSize = inputFrame.p010Buffer.width * inputFrame.p010Buffer.height;
    }

    uint8_t jpegQuality = 100;
    auto entry = inputFrame.result.find(ANDROID_JPEG_QUALITY);
    if (entry.count > 0) {
        jpegQuality = entry.data.u8[0];
    }

    if ((res = native_window_set_buffers_dimensions(mOutputSurface.get(), maxJpegRBufferSize, 1))
            != OK) {
        ALOGE("%s: Unable to configure stream buffer dimensions"
                " %zux%u for stream %d", __FUNCTION__, maxJpegRBufferSize, 1U, mP010StreamId);
        return res;
    }

    res = outputANW->dequeueBuffer(mOutputSurface.get(), &anb, &fenceFd);
    if (res != OK) {
        ALOGE("%s: Error retrieving output buffer: %s (%d)", __FUNCTION__, strerror(-res),
                res);
        return res;
    }

    sp<GraphicBuffer> gb = GraphicBuffer::from(anb);
    GraphicBufferLocker gbLocker(gb);
    res = gbLocker.lockAsync(&dstBuffer, fenceFd);
    if (res != OK) {
        ALOGE("%s: Error trying to lock output buffer fence: %s (%d)", __FUNCTION__,
                strerror(-res), res);
        outputANW->cancelBuffer(mOutputSurface.get(), anb, /*fence*/ -1);
        return res;
    }

    if ((gb->getWidth() < maxJpegRBufferSize) || (gb->getHeight() != 1)) {
        ALOGE("%s: Blob buffer size mismatch, expected %zux%u received %dx%d", __FUNCTION__,
                maxJpegRBufferSize, 1, gb->getWidth(), gb->getHeight());
        outputANW->cancelBuffer(mOutputSurface.get(), anb, /*fence*/ -1);
        return BAD_VALUE;
    }

    size_t actualJpegRSize = 0;
    ultrahdr::jpegr_uncompressed_struct p010;
    ultrahdr::jpegr_compressed_struct jpegR;
    ultrahdr::JpegR jpegREncoder;

    p010.height = inputFrame.p010Buffer.height;
    p010.width = inputFrame.p010Buffer.width;
    p010.colorGamut = ultrahdr::ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;
    p010.data = inputFrame.p010Buffer.data;
    p010.chroma_data = inputFrame.p010Buffer.dataCb;
    // Strides are expected to be in pixels not bytes
    p010.luma_stride = inputFrame.p010Buffer.stride / 2;
    p010.chroma_stride = inputFrame.p010Buffer.chromaStride / 2;

    jpegR.data = dstBuffer;
    jpegR.maxLength = maxJpegRBufferSize;

    ultrahdr::ultrahdr_transfer_function transferFunction;
    switch (mP010DynamicRange) {
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_HDR10:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_HDR10_PLUS:
            transferFunction = ultrahdr::ultrahdr_transfer_function::ULTRAHDR_TF_PQ;
            break;
        default:
            transferFunction = ultrahdr::ultrahdr_transfer_function::ULTRAHDR_TF_HLG;
    }

    if (mSupportInternalJpeg) {
        ultrahdr::jpegr_compressed_struct jpeg;

        jpeg.data = inputFrame.jpegBuffer.data;
        jpeg.length = android::camera2::JpegProcessor::findJpegSize(inputFrame.jpegBuffer.data,
                inputFrame.jpegBuffer.width);
        if (jpeg.length == 0) {
            ALOGW("%s: Failed to find input jpeg size, default to using entire buffer!",
                    __FUNCTION__);
            jpeg.length = inputFrame.jpegBuffer.width;
        }

        if (mOutputColorSpace == ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_DISPLAY_P3) {
            jpeg.colorGamut = ultrahdr::ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_P3;
        } else {
            jpeg.colorGamut = ultrahdr::ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;
        }

        res = jpegREncoder.encodeJPEGR(&p010, &jpeg, transferFunction, &jpegR);
    } else {
        const uint8_t* exifBuffer = nullptr;
        size_t exifBufferSize = 0;
        std::unique_ptr<ExifUtils> utils(ExifUtils::create());
        utils->initializeEmpty();
        utils->setFromMetadata(inputFrame.result, mStaticInfo, inputFrame.p010Buffer.width,
                inputFrame.p010Buffer.height);
        if (utils->generateApp1()) {
            exifBuffer = utils->getApp1Buffer();
            exifBufferSize = utils->getApp1Length();
        } else {
            ALOGE("%s: Unable to generate App1 buffer", __FUNCTION__);
        }

        ultrahdr::jpegr_exif_struct exif;
        exif.data = reinterpret_cast<void*>(const_cast<uint8_t*>(exifBuffer));
        exif.length = exifBufferSize;

        res = jpegREncoder.encodeJPEGR(&p010, transferFunction, &jpegR, jpegQuality, &exif);
    }

    if (res != OK) {
        ALOGE("%s: Error trying to encode JPEG/R: %s (%d)", __FUNCTION__, strerror(-res), res);
        return res;
    }

    actualJpegRSize = jpegR.length;

    size_t finalJpegRSize = actualJpegRSize + sizeof(CameraBlob);
    if (finalJpegRSize > maxJpegRBufferSize) {
        ALOGE("%s: Final jpeg buffer not large enough for the jpeg blob header", __FUNCTION__);
        outputANW->cancelBuffer(mOutputSurface.get(), anb, /*fence*/ -1);
        return NO_MEMORY;
    }

    res = native_window_set_buffers_timestamp(mOutputSurface.get(), ts);
    if (res != OK) {
        ALOGE("%s: Stream %d: Error setting timestamp: %s (%d)", __FUNCTION__,
                getStreamId(), strerror(-res), res);
        return res;
    }

    ALOGV("%s: Final jpeg size: %zu", __func__, finalJpegRSize);
    uint8_t* header = static_cast<uint8_t *> (dstBuffer) +
        (gb->getWidth() - sizeof(CameraBlob));
    CameraBlob blobHeader = {
        .blobId = CameraBlobId::JPEG,
        .blobSizeBytes = static_cast<int32_t>(actualJpegRSize)
    };
    memcpy(header, &blobHeader, sizeof(CameraBlob));

    if (inputFrame.requestTimeNs != -1) {
        auto captureLatency = ns2ms(systemTime() - inputFrame.requestTimeNs);
        mSessionStatsBuilder.incCounter(mP010StreamId, false /*dropped*/, captureLatency);
        if (mFirstRequestLatency == -1) {
            mFirstRequestLatency = captureLatency;
        }
    }
    outputANW->queueBuffer(mOutputSurface.get(), anb, /*fence*/ -1);

    return res;
}

void JpegRCompositeStream::releaseInputFrameLocked(InputFrame *inputFrame /*out*/) {
    if (inputFrame == nullptr) {
        return;
    }

    if (inputFrame->p010Buffer.data != nullptr) {
        mP010Consumer->unlockBuffer(inputFrame->p010Buffer);
        inputFrame->p010Buffer.data = nullptr;
        mP010BufferAcquired = false;
    }

    if (inputFrame->jpegBuffer.data != nullptr) {
        mBlobConsumer->unlockBuffer(inputFrame->jpegBuffer);
        inputFrame->jpegBuffer.data = nullptr;
        mBlobBufferAcquired = false;
    }

    if ((inputFrame->error || mErrorState) && !inputFrame->errorNotified) {
        //TODO: Figure out correct requestId
        notifyError(inputFrame->frameNumber, -1 /*requestId*/);
        inputFrame->errorNotified = true;
        mSessionStatsBuilder.incCounter(mP010StreamId, true /*dropped*/, 0 /*captureLatencyMs*/);
    }
}

void JpegRCompositeStream::releaseInputFramesLocked(int64_t currentTs) {
    auto it = mPendingInputFrames.begin();
    while (it != mPendingInputFrames.end()) {
        if (it->first <= currentTs) {
            releaseInputFrameLocked(&it->second);
            it = mPendingInputFrames.erase(it);
        } else {
            it++;
        }
    }
}

bool JpegRCompositeStream::threadLoop() {
    int64_t currentTs = INT64_MAX;
    bool newInputAvailable = false;

    {
        Mutex::Autolock l(mMutex);

        if (mErrorState) {
            // In case we landed in error state, return any pending buffers and
            // halt all further processing.
            compilePendingInputLocked();
            releaseInputFramesLocked(currentTs);
            return false;
        }

        while (!newInputAvailable) {
            compilePendingInputLocked();
            newInputAvailable = getNextReadyInputLocked(&currentTs);
            if (!newInputAvailable) {
                auto failingFrameNumber = getNextFailingInputLocked(&currentTs);
                if (failingFrameNumber >= 0) {
                    // We cannot erase 'mPendingInputFrames[currentTs]' at this point because it is
                    // possible for two internal stream buffers to fail. In such scenario the
                    // composite stream should notify the client about a stream buffer error only
                    // once and this information is kept within 'errorNotified'.
                    // Any present failed input frames will be removed on a subsequent call to
                    // 'releaseInputFramesLocked()'.
                    releaseInputFrameLocked(&mPendingInputFrames[currentTs]);
                    currentTs = INT64_MAX;
                }

                auto ret = mInputReadyCondition.waitRelative(mMutex, kWaitDuration);
                if (ret == TIMED_OUT) {
                    return true;
                } else if (ret != OK) {
                    ALOGE("%s: Timed wait on condition failed: %s (%d)", __FUNCTION__,
                            strerror(-ret), ret);
                    return false;
                }
            }
        }
    }

    auto res = processInputFrame(currentTs, mPendingInputFrames[currentTs]);
    Mutex::Autolock l(mMutex);
    if (res != OK) {
        ALOGE("%s: Failed processing frame with timestamp: %" PRIu64 ": %s (%d)", __FUNCTION__,
                currentTs, strerror(-res), res);
        mPendingInputFrames[currentTs].error = true;
    }

    releaseInputFramesLocked(currentTs);

    return true;
}

bool JpegRCompositeStream::isJpegRCompositeStream(const sp<Surface> &surface) {
    if (CameraProviderManager::kFrameworkJpegRDisabled) {
        return false;
    }
    ANativeWindow *anw = surface.get();
    status_t err;
    int format;
    if ((err = anw->query(anw, NATIVE_WINDOW_FORMAT, &format)) != OK) {
        ALOGE("%s: Failed to query Surface format: %s (%d)", __FUNCTION__, strerror(-err),
                err);
        return false;
    }

    int dataspace;
    if ((err = anw->query(anw, NATIVE_WINDOW_DEFAULT_DATASPACE, &dataspace)) != OK) {
        ALOGE("%s: Failed to query Surface dataspace: %s (%d)", __FUNCTION__, strerror(-err),
                err);
        return false;
    }

    if ((format == HAL_PIXEL_FORMAT_BLOB) && (dataspace == static_cast<int>(kJpegRDataSpace))) {
        return true;
    }

    return false;
}

void JpegRCompositeStream::deriveDynamicRangeAndDataspace(int64_t dynamicProfile,
        int64_t* /*out*/dynamicRange, int64_t* /*out*/dataSpace) {
    if ((dynamicRange == nullptr) || (dataSpace == nullptr)) {
        return;
    }

    switch (dynamicProfile) {
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_HDR10:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_HDR10_PLUS:
            *dynamicRange = dynamicProfile;
            *dataSpace = HAL_DATASPACE_BT2020_ITU_PQ;
            break;
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_DOLBY_VISION_10B_HDR_REF:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_DOLBY_VISION_10B_HDR_REF_PO:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_DOLBY_VISION_10B_HDR_OEM:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_DOLBY_VISION_10B_HDR_OEM_PO:
            *dynamicRange = dynamicProfile;
            *dataSpace = HAL_DATASPACE_BT2020_ITU_HLG;
            break;
        default:
            *dynamicRange = kP010DefaultDynamicRange;
            *dataSpace = kP010DefaultDataSpace;
    }

}

status_t JpegRCompositeStream::createInternalStreams(const std::vector<sp<Surface>>& consumers,
        bool /*hasDeferredConsumer*/, uint32_t width, uint32_t height, int format,
        camera_stream_rotation_t rotation, int *id, const std::string& physicalCameraId,
        const std::unordered_set<int32_t> &sensorPixelModesUsed,
        std::vector<int> *surfaceIds,
        int /*streamSetId*/, bool /*isShared*/, int32_t colorSpace,
        int64_t dynamicProfile, int64_t streamUseCase, bool useReadoutTimestamp) {
    sp<CameraDeviceBase> device = mDevice.promote();
    if (!device.get()) {
        ALOGE("%s: Invalid camera device!", __FUNCTION__);
        return NO_INIT;
    }

    deriveDynamicRangeAndDataspace(dynamicProfile, &mP010DynamicRange, &mP010DataSpace);
    mSupportInternalJpeg = CameraProviderManager::isConcurrentDynamicRangeCaptureSupported(
            mStaticInfo, mP010DynamicRange,
            ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD);

    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);
    mP010Consumer = new CpuConsumer(consumer, /*maxLockedBuffers*/1, /*controlledByApp*/ true);
    mP010Consumer->setFrameAvailableListener(this);
    mP010Consumer->setName(String8("Camera3-P010CompositeStream"));
    mP010Surface = new Surface(producer);

    auto ret = device->createStream(mP010Surface, width, height, kP010PixelFormat,
            static_cast<android_dataspace>(mP010DataSpace), rotation,
            id, physicalCameraId, sensorPixelModesUsed, surfaceIds,
            camera3::CAMERA3_STREAM_SET_ID_INVALID, false /*isShared*/, false /*isMultiResolution*/,
            GRALLOC_USAGE_SW_READ_OFTEN, mP010DynamicRange, streamUseCase,
            OutputConfiguration::TIMESTAMP_BASE_DEFAULT, OutputConfiguration::MIRROR_MODE_AUTO,
            ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_UNSPECIFIED, useReadoutTimestamp);
    if (ret == OK) {
        mP010StreamId = *id;
        mP010SurfaceId = (*surfaceIds)[0];
        mOutputSurface = consumers[0];
    } else {
        return ret;
    }

    if (mSupportInternalJpeg) {
        BufferQueue::createBufferQueue(&producer, &consumer);
        mBlobConsumer = new CpuConsumer(consumer, /*maxLockedBuffers*/ 1, /*controlledByApp*/ true);
        mBlobConsumer->setFrameAvailableListener(this);
        mBlobConsumer->setName(String8("Camera3-JpegRCompositeStream"));
        mBlobSurface = new Surface(producer);
        std::vector<int> blobSurfaceId;
        ret = device->createStream(mBlobSurface, width, height, format,
                kJpegDataSpace, rotation, &mBlobStreamId, physicalCameraId, sensorPixelModesUsed,
                &blobSurfaceId,
                /*streamSetI*/ camera3::CAMERA3_STREAM_SET_ID_INVALID,
                /*isShared*/  false,
                /*isMultiResolution*/ false,
                /*consumerUsage*/ GRALLOC_USAGE_SW_READ_OFTEN,
                /*dynamicProfile*/ ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD,
                streamUseCase,
                /*timestampBase*/ OutputConfiguration::TIMESTAMP_BASE_DEFAULT,
                /*mirrorMode*/ OutputConfiguration::MIRROR_MODE_AUTO,
                /*colorSpace*/ colorSpace, useReadoutTimestamp);
        if (ret == OK) {
            mBlobSurfaceId = blobSurfaceId[0];
        } else {
            return ret;
        }

        ret = registerCompositeStreamListener(mBlobStreamId);
        if (ret != OK) {
            ALOGE("%s: Failed to register jpeg stream listener!", __FUNCTION__);
            return ret;
        }
    }

    ret = registerCompositeStreamListener(getStreamId());
    if (ret != OK) {
        ALOGE("%s: Failed to register P010 stream listener!", __FUNCTION__);
        return ret;
    }

    mOutputColorSpace = colorSpace;
    mOutputStreamUseCase = streamUseCase;
    mBlobWidth = width;
    mBlobHeight = height;

    return ret;
}

status_t JpegRCompositeStream::configureStream() {
    if (isRunning()) {
        // Processing thread is already running, nothing more to do.
        return NO_ERROR;
    }

    if (mOutputSurface.get() == nullptr) {
        ALOGE("%s: No valid output surface set!", __FUNCTION__);
        return NO_INIT;
    }

    auto res = mOutputSurface->connect(NATIVE_WINDOW_API_CAMERA, mProducerListener);
    if (res != OK) {
        ALOGE("%s: Unable to connect to native window for stream %d",
                __FUNCTION__, mP010StreamId);
        return res;
    }

    if ((res = native_window_set_buffers_format(mOutputSurface.get(), HAL_PIXEL_FORMAT_BLOB))
            != OK) {
        ALOGE("%s: Unable to configure stream buffer format for stream %d", __FUNCTION__,
                mP010StreamId);
        return res;
    }

    if ((res = native_window_set_usage(mOutputSurface.get(),
            GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN)) != OK) {
        ALOGE("%s: Unable to configure stream buffer usage for stream %d", __FUNCTION__,
                mP010StreamId);
        return res;
    }

    int maxProducerBuffers;
    ANativeWindow *anw = mP010Surface.get();
    if ((res = anw->query(anw, NATIVE_WINDOW_MIN_UNDEQUEUED_BUFFERS, &maxProducerBuffers)) != OK) {
        ALOGE("%s: Unable to query consumer undequeued"
                " buffer count for stream %d", __FUNCTION__, mP010StreamId);
        return res;
    }

    ANativeWindow *anwConsumer = mOutputSurface.get();
    int maxConsumerBuffers;
    if ((res = anwConsumer->query(anwConsumer, NATIVE_WINDOW_MIN_UNDEQUEUED_BUFFERS,
                    &maxConsumerBuffers)) != OK) {
        ALOGE("%s: Unable to query consumer undequeued"
                " buffer count for stream %d", __FUNCTION__, mP010StreamId);
        return res;
    }

    if ((res = native_window_set_buffer_count(
                    anwConsumer, maxProducerBuffers + maxConsumerBuffers)) != OK) {
        ALOGE("%s: Unable to set buffer count for stream %d", __FUNCTION__, mP010StreamId);
        return res;
    }

    mSessionStatsBuilder.addStream(mP010StreamId);

    run("JpegRCompositeStreamProc");

    return NO_ERROR;
}

status_t JpegRCompositeStream::deleteInternalStreams() {
    // The 'CameraDeviceClient' parent will delete the P010 stream
    requestExit();

    auto ret = join();
    if (ret != OK) {
        ALOGE("%s: Failed to join with the main processing thread: %s (%d)", __FUNCTION__,
                strerror(-ret), ret);
    }

    if (mBlobStreamId >= 0) {
        // Camera devices may not be valid after switching to offline mode.
        // In this case, all offline streams including internal composite streams
        // are managed and released by the offline session.
        sp<CameraDeviceBase> device = mDevice.promote();
        if (device.get() != nullptr) {
            ret = device->deleteStream(mBlobStreamId);
        }

        mBlobStreamId = -1;
    }

    if (mOutputSurface != nullptr) {
        mOutputSurface->disconnect(NATIVE_WINDOW_API_CAMERA);
        mOutputSurface.clear();
    }

    return ret;
}

void JpegRCompositeStream::onFrameAvailable(const BufferItem& item) {
    if (item.mDataSpace == kJpegDataSpace) {
        ALOGV("%s: Jpeg buffer with ts: %" PRIu64 " ms. arrived!",
                __func__, ns2ms(item.mTimestamp));

        Mutex::Autolock l(mMutex);
        if (!mErrorState) {
            mInputJpegBuffers.push_back(item.mTimestamp);
            mInputReadyCondition.signal();
        }
    } else if (item.mDataSpace == static_cast<android_dataspace_t>(mP010DataSpace)) {
        ALOGV("%s: P010 buffer with ts: %" PRIu64 " ms. arrived!", __func__,
                ns2ms(item.mTimestamp));

        Mutex::Autolock l(mMutex);
        if (!mErrorState) {
            mInputP010Buffers.push_back(item.mTimestamp);
            mInputReadyCondition.signal();
        }
    } else {
        ALOGE("%s: Unexpected data space: 0x%x", __FUNCTION__, item.mDataSpace);
    }
}

status_t JpegRCompositeStream::insertGbp(SurfaceMap* /*out*/outSurfaceMap,
        Vector<int32_t> * /*out*/outputStreamIds, int32_t* /*out*/currentStreamId) {
    if (outputStreamIds == nullptr) {
        return BAD_VALUE;
    }

    if (outSurfaceMap->find(mP010StreamId) == outSurfaceMap->end()) {
        outputStreamIds->push_back(mP010StreamId);
    }
    (*outSurfaceMap)[mP010StreamId].push_back(mP010SurfaceId);

    if (mSupportInternalJpeg) {
        if (outSurfaceMap->find(mBlobStreamId) == outSurfaceMap->end()) {
            outputStreamIds->push_back(mBlobStreamId);
        }
        (*outSurfaceMap)[mBlobStreamId].push_back(mBlobSurfaceId);
    }

    if (currentStreamId != nullptr) {
        *currentStreamId = mP010StreamId;
    }

    return NO_ERROR;
}

status_t JpegRCompositeStream::insertCompositeStreamIds(
        std::vector<int32_t>* compositeStreamIds /*out*/) {
    if (compositeStreamIds == nullptr) {
        return BAD_VALUE;
    }

    compositeStreamIds->push_back(mP010StreamId);
    if (mSupportInternalJpeg) {
        compositeStreamIds->push_back(mBlobStreamId);
    }

    return OK;
}

void JpegRCompositeStream::onResultError(const CaptureResultExtras& resultExtras) {
    // Processing can continue even in case of result errors.
    // At the moment Jpeg/R composite stream processing relies mainly on static camera
    // characteristics data. The actual result data can be used for the jpeg quality but
    // in case it is absent we can default to maximum.
    eraseResult(resultExtras.frameNumber);
    mSessionStatsBuilder.incResultCounter(true /*dropped*/);
}

bool JpegRCompositeStream::onStreamBufferError(const CaptureResultExtras& resultExtras) {
    bool ret = false;
    // Buffer errors concerning internal composite streams should not be directly visible to
    // camera clients. They must only receive a single buffer error with the public composite
    // stream id.
    if ((resultExtras.errorStreamId == mP010StreamId) ||
            (resultExtras.errorStreamId == mBlobStreamId)) {
        flagAnErrorFrameNumber(resultExtras.frameNumber);
        ret = true;
    }

    return ret;
}

status_t JpegRCompositeStream::getCompositeStreamInfo(const OutputStreamInfo &streamInfo,
            const CameraMetadata& staticInfo,
            std::vector<OutputStreamInfo>* compositeOutput /*out*/) {
    if (compositeOutput == nullptr) {
        return BAD_VALUE;
    }

    int64_t dynamicRange, dataSpace;
    deriveDynamicRangeAndDataspace(streamInfo.dynamicRangeProfile, &dynamicRange, &dataSpace);

    compositeOutput->clear();
    compositeOutput->push_back({});
    (*compositeOutput)[0].width = streamInfo.width;
    (*compositeOutput)[0].height = streamInfo.height;
    (*compositeOutput)[0].format = kP010PixelFormat;
    (*compositeOutput)[0].dataSpace = static_cast<android_dataspace_t>(dataSpace);
    (*compositeOutput)[0].consumerUsage = GRALLOC_USAGE_SW_READ_OFTEN;
    (*compositeOutput)[0].dynamicRangeProfile = dynamicRange;
    (*compositeOutput)[0].colorSpace =
        ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_UNSPECIFIED;

    if (CameraProviderManager::isConcurrentDynamicRangeCaptureSupported(staticInfo,
                streamInfo.dynamicRangeProfile,
                ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD)) {
        compositeOutput->push_back({});
        (*compositeOutput)[1].width = streamInfo.width;
        (*compositeOutput)[1].height = streamInfo.height;
        (*compositeOutput)[1].format = HAL_PIXEL_FORMAT_BLOB;
        (*compositeOutput)[1].dataSpace = kJpegDataSpace;
        (*compositeOutput)[1].consumerUsage = GRALLOC_USAGE_SW_READ_OFTEN;
        (*compositeOutput)[1].dynamicRangeProfile =
            ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD;
        (*compositeOutput)[1].colorSpace = streamInfo.colorSpace;
    }

    return NO_ERROR;
}

void JpegRCompositeStream::getStreamStats(hardware::CameraStreamStats* streamStats) {
    if ((streamStats == nullptr) || (mFirstRequestLatency != -1)) {
        return;
    }

    bool deviceError;
    std::map<int, StreamStats> stats;
    std::pair<int32_t, int32_t> mostRequestedFps;
    mSessionStatsBuilder.buildAndReset(&streamStats->mRequestCount, &streamStats->mErrorCount,
            &deviceError, &mostRequestedFps, &stats);
    if (stats.find(mP010StreamId) != stats.end()) {
        streamStats->mWidth = mBlobWidth;
        streamStats->mHeight = mBlobHeight;
        streamStats->mFormat = HAL_PIXEL_FORMAT_BLOB;
        streamStats->mDataSpace = static_cast<int>(kJpegRDataSpace);
        streamStats->mDynamicRangeProfile = mP010DynamicRange;
        streamStats->mColorSpace = mOutputColorSpace;
        streamStats->mStreamUseCase = mOutputStreamUseCase;
        streamStats->mStartLatencyMs = mFirstRequestLatency;
        streamStats->mHistogramType = hardware::CameraStreamStats::HISTOGRAM_TYPE_CAPTURE_LATENCY;
        streamStats->mHistogramBins.assign(stats[mP010StreamId].mCaptureLatencyBins.begin(),
                stats[mP010StreamId].mCaptureLatencyBins.end());
        streamStats->mHistogramCounts.assign(stats[mP010StreamId].mCaptureLatencyHistogram.begin(),
                stats[mP010StreamId].mCaptureLatencyHistogram.end());
    }
}

}; // namespace camera3
}; // namespace android
