/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_TAG "Camera3-HeicCompositeStream"
#define ATRACE_TAG ATRACE_TAG_CAMERA
#define ALIGN(x, mask) ( ((x) + (mask) - 1) & ~((mask) - 1) )
//#define LOG_NDEBUG 0

#include <linux/memfd.h>
#include <pthread.h>
#include <sys/syscall.h>

#include <aidl/android/hardware/camera/device/CameraBlob.h>
#include <aidl/android/hardware/camera/device/CameraBlobId.h>
#include <camera/StringUtils.h>
#include <com_android_graphics_libgui_flags.h>
#include <com_android_internal_camera_flags.h>
#include <gui/Surface.h>
#include <libyuv.h>
#include <utils/Log.h>
#include <utils/Trace.h>
#include <ultrahdr/jpegr.h>
#include <ultrahdr/ultrahdrcommon.h>

#include <media/MediaCodecBuffer.h>
#include <media/stagefright/MediaCodecConstants.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/MediaDefs.h>
#include <mediadrm/ICrypto.h>
#include <memory>

#include "HeicCompositeStream.h"
#include "HeicEncoderInfoManager.h"
#include "common/CameraDeviceBase.h"
#include "system/camera_metadata.h"
#include "utils/ExifUtils.h"
#include "utils/SessionConfigurationUtils.h"
#include "utils/Utils.h"

using aidl::android::hardware::camera::device::CameraBlob;
using aidl::android::hardware::camera::device::CameraBlobId;

namespace flags = com::android::internal::camera::flags;

namespace android {
namespace camera3 {

HeicCompositeStream::HeicCompositeStream(sp<CameraDeviceBase> device,
                                         wp<hardware::camera2::ICameraDeviceCallbacks> cb)
    : CompositeStream(device, cb),
      mUseHeic(false),
      mNumOutputTiles(1),
      mNumGainmapOutputTiles(1),
      mOutputWidth(0),
      mOutputHeight(0),
      mGainmapOutputWidth(0),
      mGainmapOutputHeight(0),
      mMaxHeicBufferSize(0),
      mGridWidth(HeicEncoderInfoManager::kGridWidth),
      mGridHeight(HeicEncoderInfoManager::kGridHeight),
      mGainmapGridWidth(HeicEncoderInfoManager::kGridWidth),
      mGainmapGridHeight(HeicEncoderInfoManager::kGridHeight),
      mGridRows(1),
      mGridCols(1),
      mGainmapGridRows(1),
      mGainmapGridCols(1),
      mUseGrid(false),
      mGainmapUseGrid(false),
      mAppSegmentStreamId(-1),
      mAppSegmentSurfaceId(-1),
      mMainImageStreamId(-1),
      mMainImageSurfaceId(-1),
      mYuvBufferAcquired(false),
      mStreamSurfaceListener(new StreamSurfaceListener()),
      mDequeuedOutputBufferCnt(0),
      mCodecOutputCounter(0),
      mCodecGainmapOutputCounter(0),
      mQuality(-1),
      mGridTimestampUs(0),
      mStatusId(StatusTracker::NO_STATUS_ID) {
    mStaticInfo = device->info();
    camera_metadata_entry halHeicSupport = mStaticInfo.find(ANDROID_HEIC_INFO_SUPPORTED);
    if (halHeicSupport.count == 1 &&
            halHeicSupport.data.u8[0] == ANDROID_HEIC_INFO_SUPPORTED_TRUE) {
        // The camera device supports the HEIC stream combination,
        // use the standard stream combintion.
        mAppSegmentSupported = true;
    }
}

HeicCompositeStream::~HeicCompositeStream() {
    // Call deinitCodec in case stream hasn't been deleted yet to avoid any
    // memory/resource leak.
    deinitCodec();

    mInputAppSegmentBuffers.clear();
    mCodecOutputBuffers.clear();
    mGainmapCodecOutputBuffers.clear();

    mAppSegmentStreamId = -1;
    mAppSegmentSurfaceId = -1;
    mAppSegmentConsumer.clear();
    mAppSegmentSurface.clear();

    mMainImageStreamId = -1;
    mMainImageSurfaceId = -1;
    mMainImageConsumer.clear();
    mMainImageSurface.clear();
}

bool HeicCompositeStream::isHeicCompositeStreamInfo(const OutputStreamInfo& streamInfo,
                                                    bool isCompositeHeicDisabled,
                                                    bool isCompositeHeicUltraHDRDisabled) {
    return (((streamInfo.dataSpace == static_cast<android_dataspace_t>(HAL_DATASPACE_HEIF) &&
              !isCompositeHeicDisabled) ||
             (streamInfo.dataSpace == static_cast<android_dataspace_t>(kUltraHDRDataSpace) &&
              !isCompositeHeicUltraHDRDisabled)) &&
            (streamInfo.format == HAL_PIXEL_FORMAT_BLOB));
}

bool HeicCompositeStream::isHeicCompositeStream(const sp<Surface>& surface,
                                                bool isCompositeHeicDisabled,
                                                bool isCompositeHeicUltraHDRDisabled) {
    ANativeWindow* anw = surface.get();
    status_t err;
    int format;
    if ((err = anw->query(anw, NATIVE_WINDOW_FORMAT, &format)) != OK) {
        std::string msg = fmt::sprintf("Failed to query Surface format: %s (%d)", strerror(-err),
                err);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return false;
    }

    int dataspace;
    if ((err = anw->query(anw, NATIVE_WINDOW_DEFAULT_DATASPACE, &dataspace)) != OK) {
        std::string msg = fmt::sprintf("Failed to query Surface dataspace: %s (%d)", strerror(-err),
                err);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return false;
    }

    return ((format == HAL_PIXEL_FORMAT_BLOB) &&
            ((dataspace == HAL_DATASPACE_HEIF && !isCompositeHeicDisabled) ||
             (dataspace == static_cast<int>(kUltraHDRDataSpace) &&
              !isCompositeHeicUltraHDRDisabled)));
}

status_t HeicCompositeStream::createInternalStreams(const std::vector<SurfaceHolder>& consumers,
        bool /*hasDeferredConsumer*/, uint32_t width, uint32_t height, int format,
        camera_stream_rotation_t rotation, int *id, const std::string& physicalCameraId,
        const std::unordered_set<int32_t> &sensorPixelModesUsed,
        std::vector<int> *surfaceIds,
        int /*streamSetId*/, bool /*isShared*/, int32_t colorSpace,
        int64_t /*dynamicProfile*/, int64_t /*streamUseCase*/, bool useReadoutTimestamp) {

    sp<CameraDeviceBase> device = mDevice.promote();
    if (!device.get()) {
        ALOGE("%s: Invalid camera device!", __FUNCTION__);
        return NO_INIT;
    }

    ANativeWindow* anw = consumers[0].mSurface.get();
    int dataspace;
    status_t res;
    if ((res = anw->query(anw, NATIVE_WINDOW_DEFAULT_DATASPACE, &dataspace)) != OK) {
        ALOGE("%s: Failed to query Surface dataspace: %s (%d)", __FUNCTION__, strerror(-res),
                res);
        return res;
    }
    if ((dataspace == static_cast<int>(kUltraHDRDataSpace)) && flags::camera_heif_gainmap()) {
        mHDRGainmapEnabled = true;
        mInternalDataSpace = static_cast<android_dataspace_t>(HAL_DATASPACE_BT2020_HLG);
        // APP segment and P010 streams may not be supported on all devices
        mAppSegmentSupported = false;
    }

    res = initializeCodec(width, height, device);
    if (res != OK) {
        ALOGE("%s: Failed to initialize HEIC/HEVC codec: %s (%d)",
                __FUNCTION__, strerror(-res), res);
        return NO_INIT;
    }

    if (mAppSegmentSupported) {
        std::tie(mAppSegmentConsumer, mAppSegmentSurface) =
                CpuConsumer::create(kMaxAcquiredAppSegment);
        mAppSegmentConsumer->setFrameAvailableListener(this);
        mAppSegmentConsumer->setName(String8("Camera3-HeicComposite-AppSegmentStream"));
    }
    sp<MediaSurfaceType> surface =
            mAppSegmentSurface.get() != nullptr
                    ? mediaflagtools::surfaceToSurfaceType(mAppSegmentSurface)
                    : nullptr;

    if (mAppSegmentSupported) {
        std::vector<int> sourceSurfaceId;
        res = device->createStream(mAppSegmentSurface, mAppSegmentMaxSize, 1, format,
                kAppSegmentDataSpace, rotation, &mAppSegmentStreamId, physicalCameraId,
                sensorPixelModesUsed, &sourceSurfaceId, camera3::CAMERA3_STREAM_SET_ID_INVALID,
                /*isShared*/false, /*isMultiResolution*/false,
                /*consumerUsage*/0, ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD,
                ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT,
                OutputConfiguration::TIMESTAMP_BASE_DEFAULT,
                OutputConfiguration::MIRROR_MODE_AUTO,
                colorSpace,
                useReadoutTimestamp);
        if (res == OK) {
            mAppSegmentSurfaceId = sourceSurfaceId[0];
        } else {
            ALOGE("%s: Failed to create JPEG App segment stream: %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            return res;
        }
    }

    if (!mUseGrid && !mHDRGainmapEnabled) {
        res = mCodec->createInputSurface(&surface);
        if (res != OK) {
            ALOGE("%s: Failed to create input surface for Heic codec: %s (%d)",
                    __FUNCTION__, strerror(-res), res);
            return res;
        }
    } else {
        sp<Surface> cpuSurface;
        std::tie(mMainImageConsumer, cpuSurface) = CpuConsumer::create(1);
        surface = mediaflagtools::surfaceToSurfaceType(cpuSurface);
        mMainImageConsumer->setFrameAvailableListener(this);
        mMainImageConsumer->setName(String8("Camera3-HeicComposite-HevcInputYUVStream"));
    }
    mMainImageSurface = mediaflagtools::surfaceTypeToSurface(surface);

    res = mCodec->start();
    if (res != OK) {
        ALOGE("%s: Failed to start codec: %s (%d)", __FUNCTION__,
                strerror(-res), res);
        return res;
    }

    if (mHDRGainmapEnabled) {
        res = mGainmapCodec->start();
        if (res != OK) {
            ALOGE("%s: Failed to start gainmap codec: %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            return res;
        }
    }

    //Use YUV_420 format if framework tiling is needed.
    int srcStreamFmt = mHDRGainmapEnabled ?
        static_cast<android_pixel_format_t>(HAL_PIXEL_FORMAT_YCBCR_P010) : mUseGrid ?
        HAL_PIXEL_FORMAT_YCbCr_420_888 : HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED;
    res = device->createStream(mMainImageSurface, width, height, srcStreamFmt, mInternalDataSpace,
            rotation, id, physicalCameraId, sensorPixelModesUsed, surfaceIds,
            camera3::CAMERA3_STREAM_SET_ID_INVALID, /*isShared*/false, /*isMultiResolution*/false,
            /*consumerUsage*/0, mHDRGainmapEnabled ?
            ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_HLG10 :
            ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD,
            ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT,
            OutputConfiguration::TIMESTAMP_BASE_DEFAULT,
            OutputConfiguration::MIRROR_MODE_AUTO,
            colorSpace,
            useReadoutTimestamp);
    if (res == OK) {
        mMainImageSurfaceId = (*surfaceIds)[0];
        mMainImageStreamId = *id;
    } else {
        ALOGE("%s: Failed to create main image stream: %s (%d)", __FUNCTION__,
                strerror(-res), res);
        return res;
    }

    mOutputSurface = consumers[0].mSurface;
    res = registerCompositeStreamListener(mMainImageStreamId);
    if (res != OK) {
        ALOGE("%s: Failed to register HAL main image stream: %s (%d)", __FUNCTION__,
                strerror(-res), res);
        return res;
    }

    if (mAppSegmentSupported) {
        res = registerCompositeStreamListener(mAppSegmentStreamId);
        if (res != OK) {
            ALOGE("%s: Failed to register HAL app segment stream: %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            return res;
        }
    }

    initCopyRowFunction(width);
    return res;
}

status_t HeicCompositeStream::deleteInternalStreams() {
    requestExit();
    auto res = join();
    if (res != OK) {
        ALOGE("%s: Failed to join with the main processing thread: %s (%d)", __FUNCTION__,
                strerror(-res), res);
    }

    deinitCodec();

    if (mAppSegmentStreamId >= 0) {
        // Camera devices may not be valid after switching to offline mode.
        // In this case, all offline streams including internal composite streams
        // are managed and released by the offline session.
        sp<CameraDeviceBase> device = mDevice.promote();
        if (device.get() != nullptr) {
            res = device->deleteStream(mAppSegmentStreamId);
        }

        mAppSegmentStreamId = -1;
    }

    if (mOutputSurface != nullptr) {
        mOutputSurface->disconnect(NATIVE_WINDOW_API_CAMERA);
        mOutputSurface.clear();
    }

    sp<StatusTracker> statusTracker = mStatusTracker.promote();
    if (statusTracker != nullptr && mStatusId != StatusTracker::NO_STATUS_ID) {
        statusTracker->removeComponent(mStatusId);
        mStatusId = StatusTracker::NO_STATUS_ID;
    }

    if (mPendingInputFrames.size() > 0) {
        ALOGW("%s: mPendingInputFrames has %zu stale entries",
                __FUNCTION__, mPendingInputFrames.size());
        mPendingInputFrames.clear();
    }

    return res;
}

void HeicCompositeStream::onBufferReleased(const BufferInfo& bufferInfo) {
    Mutex::Autolock l(mMutex);

    if (bufferInfo.mError) return;

    if (bufferInfo.mStreamId == mMainImageStreamId) {
        mMainImageFrameNumbers.push(bufferInfo.mFrameNumber);
        mCodecOutputBufferFrameNumbers.push(bufferInfo.mFrameNumber);
        ALOGV("%s: [%" PRId64 "]: Adding main image frame number (%zu frame numbers in total)",
                __FUNCTION__, bufferInfo.mFrameNumber, mMainImageFrameNumbers.size());
        if (mHDRGainmapEnabled) {
            mCodecGainmapOutputBufferFrameNumbers.push(bufferInfo.mFrameNumber);
        }
    } else if (bufferInfo.mStreamId == mAppSegmentStreamId) {
        mAppSegmentFrameNumbers.push(bufferInfo.mFrameNumber);
        ALOGV("%s: [%" PRId64 "]: Adding app segment frame number (%zu frame numbers in total)",
                __FUNCTION__, bufferInfo.mFrameNumber, mAppSegmentFrameNumbers.size());
    }
}

// We need to get the settings early to handle the case where the codec output
// arrives earlier than result metadata.
void HeicCompositeStream::onBufferRequestForFrameNumber(uint64_t frameNumber, int streamId,
        const CameraMetadata& settings) {
    ATRACE_ASYNC_BEGIN("HEIC capture", frameNumber);

    Mutex::Autolock l(mMutex);
    if (mErrorState || (streamId != getStreamId())) {
        return;
    }

    mPendingCaptureResults.emplace(frameNumber, CameraMetadata());

    camera_metadata_ro_entry entry;

    int32_t orientation = 0;
    entry = settings.find(ANDROID_JPEG_ORIENTATION);
    if (entry.count == 1) {
        orientation = entry.data.i32[0];
    }

    int32_t quality = kDefaultJpegQuality;
    entry = settings.find(ANDROID_JPEG_QUALITY);
    if (entry.count == 1) {
        quality = entry.data.i32[0];
    }

    mSettingsByFrameNumber[frameNumber] = {orientation, quality};
}

void HeicCompositeStream::onFrameAvailable(const BufferItem& item) {
    if (item.mDataSpace == static_cast<android_dataspace>(kAppSegmentDataSpace)) {
        ALOGV("%s: JPEG APP segments buffer with ts: %" PRIu64 " ms. arrived!",
                __func__, ns2ms(item.mTimestamp));

        Mutex::Autolock l(mMutex);
        if (!mErrorState) {
            mInputAppSegmentBuffers.push_back(item.mTimestamp);
            mInputReadyCondition.signal();
        }
    } else if (item.mDataSpace == mInternalDataSpace) {
        ALOGV("%s: YUV_420 buffer with ts: %" PRIu64 " ms. arrived!",
                __func__, ns2ms(item.mTimestamp));

        Mutex::Autolock l(mMutex);
        if (!mUseGrid && !mHDRGainmapEnabled) {
            ALOGE("%s: YUV_420 internal stream is only supported for HEVC tiling",
                    __FUNCTION__);
            return;
        }
        if (!mErrorState) {
            mInputYuvBuffers.push_back(item.mTimestamp);
            mInputReadyCondition.signal();
        }
    } else {
        ALOGE("%s: Unexpected data space: 0x%x", __FUNCTION__, item.mDataSpace);
    }
}

status_t HeicCompositeStream::getCompositeStreamInfo(const OutputStreamInfo &streamInfo,
            const CameraMetadata& ch, std::vector<OutputStreamInfo>* compositeOutput /*out*/) {
    bool gainmapEnabled = false;
    if (compositeOutput == nullptr) {
        return BAD_VALUE;
    }

    compositeOutput->clear();

    bool useGrid, useHeic;
    bool isSizeSupported = isSizeSupportedByHeifEncoder(
            streamInfo.width, streamInfo.height, &useHeic, &useGrid, nullptr);
    if (!isSizeSupported) {
        // Size is not supported by either encoder.
        return OK;
    }

    if (streamInfo.dataSpace == static_cast<android_dataspace_t>(kUltraHDRDataSpace)) {
        gainmapEnabled = true;
    }

    compositeOutput->clear();
    compositeOutput->push_back({});

    // YUV/IMPLEMENTATION_DEFINED stream info
    (*compositeOutput)[0].width = streamInfo.width;
    (*compositeOutput)[0].height = streamInfo.height;
    (*compositeOutput)[0].format = gainmapEnabled ?
        static_cast<android_pixel_format_t>(HAL_PIXEL_FORMAT_YCBCR_P010) : useGrid ?
        HAL_PIXEL_FORMAT_YCbCr_420_888 : HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED;
    (*compositeOutput)[0].dataSpace = gainmapEnabled ?
        static_cast<android_dataspace_t>(HAL_DATASPACE_BT2020_HLG) : kHeifDataSpace;
    (*compositeOutput)[0].consumerUsage = useHeic ? GRALLOC_USAGE_HW_IMAGE_ENCODER :
            useGrid ? GRALLOC_USAGE_SW_READ_OFTEN : GRALLOC_USAGE_HW_VIDEO_ENCODER;


    camera_metadata_ro_entry halHeicSupport = ch.find(ANDROID_HEIC_INFO_SUPPORTED);
    if (halHeicSupport.count == 1 &&
            halHeicSupport.data.u8[0] == ANDROID_HEIC_INFO_SUPPORTED_TRUE) {

        compositeOutput->push_back({});
        // JPEG APPS segments Blob stream info
        (*compositeOutput)[1].width = calcAppSegmentMaxSize(ch);
        (*compositeOutput)[1].height = 1;
        (*compositeOutput)[1].format = HAL_PIXEL_FORMAT_BLOB;
        (*compositeOutput)[1].dataSpace = kAppSegmentDataSpace;
        (*compositeOutput)[1].consumerUsage = GRALLOC_USAGE_SW_READ_OFTEN;
    }

    return NO_ERROR;
}

bool HeicCompositeStream::isSizeSupportedByHeifEncoder(int32_t width, int32_t height,
        bool* useHeic, bool* useGrid, int64_t* stall, AString* hevcName, bool allowSWCodec) {
    static HeicEncoderInfoManager& heicManager = HeicEncoderInfoManager::getInstance(allowSWCodec);
    return heicManager.isSizeSupported(width, height, useHeic, useGrid, stall, hevcName);
}

bool HeicCompositeStream::isInMemoryTempFileSupported() {
    int memfd = syscall(__NR_memfd_create, "HEIF-try-memfd", MFD_CLOEXEC);
    if (memfd == -1) {
        if (errno != ENOSYS) {
            ALOGE("%s: Failed to create tmpfs file. errno %d", __FUNCTION__, errno);
        }
        return false;
    }
    close(memfd);
    return true;
}

void HeicCompositeStream::onHeicOutputFrameAvailable(
        const CodecOutputBufferInfo& outputBufferInfo, bool isGainmap) {
    Mutex::Autolock l(mMutex);

    ALOGV("%s: index %d, offset %d, size %d, time %" PRId64 ", flags 0x%x",
            __FUNCTION__, outputBufferInfo.index, outputBufferInfo.offset,
            outputBufferInfo.size, outputBufferInfo.timeUs, outputBufferInfo.flags);

    if (!mErrorState) {
        if ((outputBufferInfo.size > 0) &&
                ((outputBufferInfo.flags & MediaCodec::BUFFER_FLAG_CODECCONFIG) == 0)) {
            isGainmap ? mGainmapCodecOutputBuffers.push_back(outputBufferInfo) :
                mCodecOutputBuffers.push_back(outputBufferInfo);
            mInputReadyCondition.signal();
        } else {
            ALOGV("%s: Releasing output buffer: size %d flags: 0x%x ", __FUNCTION__,
                outputBufferInfo.size, outputBufferInfo.flags);
            isGainmap ? mGainmapCodec->releaseOutputBuffer(outputBufferInfo.index) :
                mCodec->releaseOutputBuffer(outputBufferInfo.index);
        }
    } else {
        isGainmap ? mGainmapCodec->releaseOutputBuffer(outputBufferInfo.index) :
            mCodec->releaseOutputBuffer(outputBufferInfo.index);
    }
}

void HeicCompositeStream::onHeicInputFrameAvailable(int32_t index, bool isGainmap) {
    Mutex::Autolock l(mMutex);

    if (!mUseGrid && !mHDRGainmapEnabled) {
        ALOGE("%s: Codec YUV input mode must only be used for Hevc tiling mode", __FUNCTION__);
        return;
    }

    isGainmap ? mGainmapCodecInputBuffers.push_back(index) : mCodecInputBuffers.push_back(index);
    mInputReadyCondition.signal();
}

void HeicCompositeStream::onHeicGainmapFormatChanged(sp<AMessage>& newFormat) {
    if (newFormat == nullptr) {
        ALOGE("%s: newFormat must not be null!", __FUNCTION__);
        return;
    }

    Mutex::Autolock l(mMutex);

    AString mime;
    AString mimeHeic(MIMETYPE_IMAGE_ANDROID_HEIC);
    newFormat->findString(KEY_MIME, &mime);
    if (mime != mimeHeic) {
        // For HEVC codec, below keys need to be filled out or overwritten so that the
        // muxer can handle them as HEIC output image.
        newFormat->setString(KEY_MIME, mimeHeic);
        newFormat->setInt32(KEY_WIDTH, mGainmapOutputWidth);
        newFormat->setInt32(KEY_HEIGHT, mGainmapOutputHeight);
    }

    if (mGainmapUseGrid) {
        int32_t gridRows, gridCols, tileWidth, tileHeight;
        if (newFormat->findInt32(KEY_GRID_ROWS, &gridRows) &&
                newFormat->findInt32(KEY_GRID_COLUMNS, &gridCols) &&
                newFormat->findInt32(KEY_TILE_WIDTH, &tileWidth) &&
                newFormat->findInt32(KEY_TILE_HEIGHT, &tileHeight)) {
            mGainmapGridWidth = tileWidth;
            mGainmapGridHeight = tileHeight;
            mGainmapGridRows = gridRows;
            mGainmapGridCols = gridCols;
        } else {
            newFormat->setInt32(KEY_TILE_WIDTH, mGainmapGridWidth);
            newFormat->setInt32(KEY_TILE_HEIGHT, mGainmapGridHeight);
            newFormat->setInt32(KEY_GRID_ROWS, mGainmapGridRows);
            newFormat->setInt32(KEY_GRID_COLUMNS, mGainmapGridCols);
        }
        int32_t left, top, right, bottom;
        if (newFormat->findRect("crop", &left, &top, &right, &bottom)) {
            newFormat->setRect("crop", 0, 0, mGainmapOutputWidth - 1, mGainmapOutputHeight - 1);
        }
    }
    newFormat->setInt32(KEY_IS_DEFAULT, 1 /*isPrimary*/);

    int32_t gridRows, gridCols;
    if (newFormat->findInt32(KEY_GRID_ROWS, &gridRows) &&
            newFormat->findInt32(KEY_GRID_COLUMNS, &gridCols)) {
        mNumGainmapOutputTiles = gridRows * gridCols;
    } else {
        mNumGainmapOutputTiles = 1;
    }

    mGainmapFormat = newFormat;

    ALOGV("%s: mNumOutputTiles is %zu", __FUNCTION__, mNumOutputTiles);
    mInputReadyCondition.signal();
}


void HeicCompositeStream::onHeicFormatChanged(sp<AMessage>& newFormat, bool isGainmap) {
    if (newFormat == nullptr) {
        ALOGE("%s: newFormat must not be null!", __FUNCTION__);
        return;
    }

    if (isGainmap) {
        return onHeicGainmapFormatChanged(newFormat);
    }
    Mutex::Autolock l(mMutex);

    AString mime;
    AString mimeHeic(MIMETYPE_IMAGE_ANDROID_HEIC);
    newFormat->findString(KEY_MIME, &mime);
    if (mime != mimeHeic) {
        // For HEVC codec, below keys need to be filled out or overwritten so that the
        // muxer can handle them as HEIC output image.
        newFormat->setString(KEY_MIME, mimeHeic);
        newFormat->setInt32(KEY_WIDTH, mOutputWidth);
        newFormat->setInt32(KEY_HEIGHT, mOutputHeight);
    }

    if (mUseGrid || mUseHeic) {
        int32_t gridRows, gridCols, tileWidth, tileHeight;
        if (newFormat->findInt32(KEY_GRID_ROWS, &gridRows) &&
                newFormat->findInt32(KEY_GRID_COLUMNS, &gridCols) &&
                newFormat->findInt32(KEY_TILE_WIDTH, &tileWidth) &&
                newFormat->findInt32(KEY_TILE_HEIGHT, &tileHeight)) {
            mGridWidth = tileWidth;
            mGridHeight = tileHeight;
            mGridRows = gridRows;
            mGridCols = gridCols;
        } else {
            newFormat->setInt32(KEY_TILE_WIDTH, mGridWidth);
            newFormat->setInt32(KEY_TILE_HEIGHT, mGridHeight);
            newFormat->setInt32(KEY_GRID_ROWS, mGridRows);
            newFormat->setInt32(KEY_GRID_COLUMNS, mGridCols);
        }
        int32_t left, top, right, bottom;
        if (newFormat->findRect("crop", &left, &top, &right, &bottom)) {
            newFormat->setRect("crop", 0, 0, mOutputWidth - 1, mOutputHeight - 1);
        }
    }
    newFormat->setInt32(KEY_IS_DEFAULT, 1 /*isPrimary*/);

    int32_t gridRows, gridCols;
    if (newFormat->findInt32(KEY_GRID_ROWS, &gridRows) &&
            newFormat->findInt32(KEY_GRID_COLUMNS, &gridCols)) {
        mNumOutputTiles = gridRows * gridCols;
    } else {
        mNumOutputTiles = 1;
    }

    mFormat = newFormat;

    ALOGV("%s: mNumOutputTiles is %zu", __FUNCTION__, mNumOutputTiles);
    mInputReadyCondition.signal();
}

void HeicCompositeStream::onHeicCodecError() {
    Mutex::Autolock l(mMutex);
    mErrorState = true;
}

status_t HeicCompositeStream::configureStream() {
    if (isRunning()) {
        // Processing thread is already running, nothing more to do.
        return NO_ERROR;
    }

    if (mOutputSurface.get() == nullptr) {
        ALOGE("%s: No valid output surface set!", __FUNCTION__);
        return NO_INIT;
    }

    auto res = mOutputSurface->connect(NATIVE_WINDOW_API_CAMERA, mStreamSurfaceListener);
    if (res != OK) {
        ALOGE("%s: Unable to connect to native window for stream %d",
                __FUNCTION__, mMainImageStreamId);
        return res;
    }

    if ((res = native_window_set_buffers_format(mOutputSurface.get(), HAL_PIXEL_FORMAT_BLOB))
            != OK) {
        ALOGE("%s: Unable to configure stream buffer format for stream %d", __FUNCTION__,
                mMainImageStreamId);
        return res;
    }

    ANativeWindow *anwConsumer = mOutputSurface.get();
    int maxConsumerBuffers;
    if ((res = anwConsumer->query(anwConsumer, NATIVE_WINDOW_MIN_UNDEQUEUED_BUFFERS,
                    &maxConsumerBuffers)) != OK) {
        ALOGE("%s: Unable to query consumer undequeued"
                " buffer count for stream %d", __FUNCTION__, mMainImageStreamId);
        return res;
    }

    if ((res = setSWUsage(mMainImageStreamId, anwConsumer)) != OK ) {
        return res;
    }


    // Cannot use SourceSurface buffer count since it could be codec's 512*512 tile
    // buffer count.
    if ((res = native_window_set_buffer_count(
                    anwConsumer, kMaxOutputSurfaceProducerCount + maxConsumerBuffers)) != OK) {
        ALOGE("%s: Unable to set buffer count for stream %d", __FUNCTION__, mMainImageStreamId);
        return res;
    }

    if ((res = native_window_set_buffers_dimensions(anwConsumer, mMaxHeicBufferSize, 1)) != OK) {
        ALOGE("%s: Unable to set buffer dimension %zu x 1 for stream %d: %s (%d)",
                __FUNCTION__, mMaxHeicBufferSize, mMainImageStreamId, strerror(-res), res);
        return res;
    }

    sp<camera3::StatusTracker> statusTracker = mStatusTracker.promote();
    if (statusTracker != nullptr) {
        std::string name = std::string("HeicStream ") + std::to_string(getStreamId());
        mStatusId = statusTracker->addComponent(name);
    }

    run("HeicCompositeStreamProc");

    return NO_ERROR;
}

status_t HeicCompositeStream::insertGbp(SurfaceMap* /*out*/outSurfaceMap,
        Vector<int32_t>* /*out*/outputStreamIds, int32_t* /*out*/currentStreamId) {
    if (mAppSegmentSupported) {
        if (outSurfaceMap->find(mAppSegmentStreamId) == outSurfaceMap->end()) {
            outputStreamIds->push_back(mAppSegmentStreamId);
        }
        (*outSurfaceMap)[mAppSegmentStreamId].push_back(mAppSegmentSurfaceId);
    }

    if (outSurfaceMap->find(mMainImageStreamId) == outSurfaceMap->end()) {
        outputStreamIds->push_back(mMainImageStreamId);
    }
    (*outSurfaceMap)[mMainImageStreamId].push_back(mMainImageSurfaceId);

    if (currentStreamId != nullptr) {
        *currentStreamId = mMainImageStreamId;
    }

    return NO_ERROR;
}

status_t HeicCompositeStream::insertCompositeStreamIds(
        std::vector<int32_t>* compositeStreamIds /*out*/) {
    if (compositeStreamIds == nullptr) {
        return BAD_VALUE;
    }

    if (mAppSegmentSupported) {
        compositeStreamIds->push_back(mAppSegmentStreamId);
    }
    compositeStreamIds->push_back(mMainImageStreamId);

    return OK;
}

void HeicCompositeStream::onShutter(const CaptureResultExtras& resultExtras, nsecs_t timestamp) {
    Mutex::Autolock l(mMutex);
    if (mErrorState) {
        return;
    }

    if (mSettingsByFrameNumber.find(resultExtras.frameNumber) != mSettingsByFrameNumber.end()) {
        ALOGV("%s: [%" PRId64 "]: timestamp %" PRId64 ", requestId %d", __FUNCTION__,
                resultExtras.frameNumber, timestamp, resultExtras.requestId);
        mSettingsByFrameNumber[resultExtras.frameNumber].shutterNotified = true;
        mSettingsByFrameNumber[resultExtras.frameNumber].timestamp = timestamp;
        mSettingsByFrameNumber[resultExtras.frameNumber].requestId = resultExtras.requestId;
        mInputReadyCondition.signal();
    }
}

void HeicCompositeStream::compilePendingInputLocked() {
    auto i = mSettingsByFrameNumber.begin();
    while (i != mSettingsByFrameNumber.end()) {
        if (i->second.shutterNotified) {
            mPendingInputFrames[i->first].orientation = i->second.orientation;
            mPendingInputFrames[i->first].quality = i->second.quality;
            mPendingInputFrames[i->first].timestamp = i->second.timestamp;
            mPendingInputFrames[i->first].requestId = i->second.requestId;
            ALOGV("%s: [%" PRId64 "]: timestamp is %" PRId64, __FUNCTION__,
                    i->first, i->second.timestamp);
            i = mSettingsByFrameNumber.erase(i);

            // Set encoder quality if no inflight encoding
            if (mPendingInputFrames.size() == 1) {
                sp<StatusTracker> statusTracker = mStatusTracker.promote();
                if (statusTracker != nullptr) {
                    statusTracker->markComponentActive(mStatusId);
                    ALOGV("%s: Mark component as active", __FUNCTION__);
                }

                int32_t newQuality = mPendingInputFrames.begin()->second.quality;
                updateCodecQualityLocked(newQuality);
            }
        } else {
            i++;
        }
    }

    while (!mInputAppSegmentBuffers.empty() && mAppSegmentFrameNumbers.size() > 0) {
        CpuConsumer::LockedBuffer imgBuffer;
        auto it = mInputAppSegmentBuffers.begin();
        auto res = mAppSegmentConsumer->lockNextBuffer(&imgBuffer);
        if (res == NOT_ENOUGH_DATA) {
            // Can not lock any more buffers.
            break;
        } else if ((res != OK) || (*it != imgBuffer.timestamp)) {
            if (res != OK) {
                ALOGE("%s: Error locking JPEG_APP_SEGMENTS image buffer: %s (%d)", __FUNCTION__,
                        strerror(-res), res);
            } else {
                ALOGE("%s: Expecting JPEG_APP_SEGMENTS buffer with time stamp: %" PRId64
                        " received buffer with time stamp: %" PRId64, __FUNCTION__,
                        *it, imgBuffer.timestamp);
                mAppSegmentConsumer->unlockBuffer(imgBuffer);
            }
            mPendingInputFrames[*it].error = true;
            mInputAppSegmentBuffers.erase(it);
            continue;
        }

        if (mPendingInputFrames.find(mAppSegmentFrameNumbers.front()) == mPendingInputFrames.end()) {
            ALOGE("%s: mPendingInputFrames doesn't contain frameNumber %" PRId64, __FUNCTION__,
                    mAppSegmentFrameNumbers.front());
            mInputAppSegmentBuffers.erase(it);
            mAppSegmentFrameNumbers.pop();
            continue;
        }

        int64_t frameNumber = mAppSegmentFrameNumbers.front();
        // If mPendingInputFrames doesn't contain the expected frame number, the captured
        // input app segment frame must have been dropped via a buffer error.  Simply
        // return the buffer to the buffer queue.
        if ((mPendingInputFrames.find(frameNumber) == mPendingInputFrames.end()) ||
                (mPendingInputFrames[frameNumber].error)) {
            mAppSegmentConsumer->unlockBuffer(imgBuffer);
        } else {
            mPendingInputFrames[frameNumber].appSegmentBuffer = imgBuffer;
        }
        mInputAppSegmentBuffers.erase(it);
        mAppSegmentFrameNumbers.pop();
    }

    while (!mInputYuvBuffers.empty() && !mYuvBufferAcquired && mMainImageFrameNumbers.size() > 0) {
        CpuConsumer::LockedBuffer imgBuffer;
        auto it = mInputYuvBuffers.begin();
        auto res = mMainImageConsumer->lockNextBuffer(&imgBuffer);
        if (res == NOT_ENOUGH_DATA) {
            // Can not lock any more buffers.
            break;
        } else if (res != OK) {
            ALOGE("%s: Error locking YUV_888 image buffer: %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            mPendingInputFrames[*it].error = true;
            mInputYuvBuffers.erase(it);
            continue;
        } else if (*it != imgBuffer.timestamp) {
            ALOGW("%s: Expecting YUV_888 buffer with time stamp: %" PRId64 " received buffer with "
                    "time stamp: %" PRId64, __FUNCTION__, *it, imgBuffer.timestamp);
            mPendingInputFrames[*it].error = true;
            mInputYuvBuffers.erase(it);
            continue;
        }

        if (mPendingInputFrames.find(mMainImageFrameNumbers.front()) == mPendingInputFrames.end()) {
            ALOGE("%s: mPendingInputFrames doesn't contain frameNumber %" PRId64, __FUNCTION__,
                    mMainImageFrameNumbers.front());
            mInputYuvBuffers.erase(it);
            mMainImageFrameNumbers.pop();
            continue;
        }

        int64_t frameNumber = mMainImageFrameNumbers.front();
        // If mPendingInputFrames doesn't contain the expected frame number, the captured
        // input main image must have been dropped via a buffer error. Simply
        // return the buffer to the buffer queue.
        if ((mPendingInputFrames.find(frameNumber) == mPendingInputFrames.end()) ||
                (mPendingInputFrames[frameNumber].error)) {
            mMainImageConsumer->unlockBuffer(imgBuffer);
        } else {
            mPendingInputFrames[frameNumber].yuvBuffer = imgBuffer;
            mYuvBufferAcquired = true;
        }
        mInputYuvBuffers.erase(it);
        mMainImageFrameNumbers.pop();
    }

    while (!mCodecOutputBuffers.empty()) {
        auto it = mCodecOutputBuffers.begin();
        // Assume encoder input to output is FIFO, use a queue to look up
        // frameNumber when handling codec outputs.
        int64_t bufferFrameNumber = -1;
        if (mCodecOutputBufferFrameNumbers.empty()) {
            ALOGV("%s: Failed to find buffer frameNumber for codec output buffer!", __FUNCTION__);
            break;
        } else {
            // Direct mapping between camera frame number and codec timestamp (in us).
            bufferFrameNumber = mCodecOutputBufferFrameNumbers.front();
            mCodecOutputCounter++;
            if (mCodecOutputCounter == mNumOutputTiles) {
                mCodecOutputBufferFrameNumbers.pop();
                mCodecOutputCounter = 0;
            }

            mPendingInputFrames[bufferFrameNumber].codecOutputBuffers.push_back(*it);
            ALOGV("%s: [%" PRId64 "]: Pushing codecOutputBuffers (frameNumber %" PRId64 ")",
                    __FUNCTION__, bufferFrameNumber, it->timeUs);
        }
        mCodecOutputBuffers.erase(it);
    }

    while (!mGainmapCodecOutputBuffers.empty()) {
        auto it = mGainmapCodecOutputBuffers.begin();
        // Assume encoder input to output is FIFO, use a queue to look up
        // frameNumber when handling codec outputs.
        int64_t bufferFrameNumber = -1;
        if (mCodecGainmapOutputBufferFrameNumbers.empty()) {
            ALOGV("%s: Failed to find buffer frameNumber for gainmap codec output buffer!",
                    __FUNCTION__);
            break;
        } else {
            // Direct mapping between camera frame number and codec timestamp (in us).
            bufferFrameNumber = mCodecGainmapOutputBufferFrameNumbers.front();
            mCodecGainmapOutputCounter++;
            if (mCodecGainmapOutputCounter == mNumGainmapOutputTiles) {
                mCodecGainmapOutputBufferFrameNumbers.pop();
                mCodecGainmapOutputCounter = 0;
            }

            mPendingInputFrames[bufferFrameNumber].gainmapCodecOutputBuffers.push_back(*it);
            ALOGV("%s: [%" PRId64 "]: Pushing gainmap codecOutputBuffers (frameNumber %" PRId64 ")",
                    __FUNCTION__, bufferFrameNumber, it->timeUs);
        }
        mGainmapCodecOutputBuffers.erase(it);
    }

    while (!mCaptureResults.empty()) {
        auto it = mCaptureResults.begin();
        // Negative frame number indicates that something went wrong during the capture result
        // collection process.
        int64_t frameNumber = std::get<0>(it->second);
        if (it->first >= 0 &&
                mPendingInputFrames.find(frameNumber) != mPendingInputFrames.end()) {
            if (mPendingInputFrames[frameNumber].timestamp == it->first) {
                mPendingInputFrames[frameNumber].result =
                        std::make_unique<CameraMetadata>(std::get<1>(it->second));
                if (!mAppSegmentSupported) {
                    mPendingInputFrames[frameNumber].exifError = true;
                }
            } else {
                ALOGE("%s: Capture result frameNumber/timestamp mapping changed between "
                        "shutter and capture result! before: %" PRId64 ", after: %" PRId64,
                        __FUNCTION__, mPendingInputFrames[frameNumber].timestamp,
                        it->first);
            }
        }
        mCaptureResults.erase(it);
    }

    // mErrorFrameNumbers stores frame number of dropped buffers.
    auto it = mErrorFrameNumbers.begin();
    while (it != mErrorFrameNumbers.end()) {
        if (mPendingInputFrames.find(*it) != mPendingInputFrames.end()) {
            mPendingInputFrames[*it].error = true;
        } else {
            //Error callback is guaranteed to arrive after shutter notify, which
            //results in mPendingInputFrames being populated.
            ALOGW("%s: Not able to find failing input with frame number: %" PRId64, __FUNCTION__,
                    *it);
        }
        it = mErrorFrameNumbers.erase(it);
    }

    // mExifErrorFrameNumbers stores the frame number of dropped APP_SEGMENT buffers
    it = mExifErrorFrameNumbers.begin();
    while (it != mExifErrorFrameNumbers.end()) {
        if (mPendingInputFrames.find(*it) != mPendingInputFrames.end()) {
            mPendingInputFrames[*it].exifError = true;
        }
        it = mExifErrorFrameNumbers.erase(it);
    }

    // Distribute codec input buffers to be filled out from YUV output
    for (auto it = mPendingInputFrames.begin();
            it != mPendingInputFrames.end() && mCodecInputBuffers.size() > 0; it++) {
        InputFrame& inputFrame(it->second);
        if (inputFrame.codecInputCounter < mGridRows * mGridCols) {
            // Available input tiles that are required for the current input
            // image.
            size_t newInputTiles = std::min(mCodecInputBuffers.size(),
                    mGridRows * mGridCols - inputFrame.codecInputCounter);
            for (size_t i = 0; i < newInputTiles; i++) {
                CodecInputBufferInfo inputInfo =
                        { mCodecInputBuffers[0], mGridTimestampUs++, inputFrame.codecInputCounter };
                inputFrame.codecInputBuffers.push_back(inputInfo);

                mCodecInputBuffers.erase(mCodecInputBuffers.begin());
                inputFrame.codecInputCounter++;
            }
            break;
        }
    }

    // Distribute codec input buffers to be filled out from YUV output
    for (auto it = mPendingInputFrames.begin();
            it != mPendingInputFrames.end() && mGainmapCodecInputBuffers.size() > 0; it++) {
        InputFrame& inputFrame(it->second);
        if (inputFrame.gainmapCodecInputCounter < mGainmapGridRows * mGainmapGridCols) {
            // Available input tiles that are required for the current input
            // image.
            size_t newInputTiles = std::min(mGainmapCodecInputBuffers.size(),
                    mGainmapGridRows * mGainmapGridCols - inputFrame.gainmapCodecInputCounter);
            for (size_t i = 0; i < newInputTiles; i++) {
                CodecInputBufferInfo inputInfo = { mGainmapCodecInputBuffers[0],
                    mGridTimestampUs++, inputFrame.gainmapCodecInputCounter };
                inputFrame.gainmapCodecInputBuffers.push_back(inputInfo);

                mGainmapCodecInputBuffers.erase(mGainmapCodecInputBuffers.begin());
                inputFrame.gainmapCodecInputCounter++;
            }
            break;
        }
    }
}

bool HeicCompositeStream::getNextReadyInputLocked(int64_t *frameNumber /*out*/) {
    if (frameNumber == nullptr) {
        return false;
    }

    bool newInputAvailable = false;
    for (auto& it : mPendingInputFrames) {
        // New input is considered to be available only if:
        // 1. input buffers are ready, or
        // 2. App segment and muxer is created, or
        // 3. A codec output tile is ready, and an output buffer is available.
        // This makes sure that muxer gets created only when an output tile is
        // generated, because right now we only handle 1 HEIC output buffer at a
        // time (max dequeued buffer count is 1).
        bool appSegmentReady =
                (it.second.appSegmentBuffer.data != nullptr || it.second.exifError) &&
                !it.second.appSegmentWritten && it.second.result != nullptr &&
                it.second.muxer != nullptr;
        bool codecOutputReady = !it.second.codecOutputBuffers.empty() ||
                !it.second.gainmapCodecOutputBuffers.empty();
        bool codecInputReady = (it.second.yuvBuffer.data != nullptr) &&
                (!it.second.codecInputBuffers.empty());
        bool hasOutputBuffer = it.second.muxer != nullptr ||
                (mDequeuedOutputBufferCnt < kMaxOutputSurfaceProducerCount);
        if ((!it.second.error) &&
                (appSegmentReady || (codecOutputReady && hasOutputBuffer) || codecInputReady)) {
            *frameNumber = it.first;
            if (it.second.format == nullptr && mFormat != nullptr) {
                it.second.format = mFormat->dup();
            }
            if (it.second.gainmapFormat == nullptr && mGainmapFormat != nullptr){
                it.second.gainmapFormat = mGainmapFormat->dup();
                it.second.gainmapFormat->setInt32("gainmap", 1);
            }
            newInputAvailable = true;
            break;
        }
    }

    return newInputAvailable;
}

int64_t HeicCompositeStream::getNextFailingInputLocked() {
    int64_t res = -1;

    for (const auto& it : mPendingInputFrames) {
        if (it.second.error) {
            res = it.first;
            break;
        }
    }

    return res;
}

status_t HeicCompositeStream::processInputFrame(int64_t frameNumber,
        InputFrame &inputFrame) {
    ATRACE_CALL();
    status_t res = OK;

    bool appSegmentReady =
            (inputFrame.appSegmentBuffer.data != nullptr || inputFrame.exifError) &&
            !inputFrame.appSegmentWritten && inputFrame.result != nullptr &&
            inputFrame.muxer != nullptr;
    bool codecOutputReady = inputFrame.codecOutputBuffers.size() > 0 ||
            inputFrame.gainmapCodecOutputBuffers.size() > 0;
    bool codecInputReady = inputFrame.yuvBuffer.data != nullptr &&
            !inputFrame.codecInputBuffers.empty();
    bool gainmapCodecInputReady = inputFrame.gainmapImage.get() != nullptr &&
            !inputFrame.gainmapCodecInputBuffers.empty();
    bool hasOutputBuffer = inputFrame.muxer != nullptr ||
            (mDequeuedOutputBufferCnt < kMaxOutputSurfaceProducerCount);
    bool hasGainmapMetadata = !inputFrame.isoGainmapMetadata.empty();
    bool hdrGainmapFormatReady = mHDRGainmapEnabled ?
            (inputFrame.gainmapFormat.get() != nullptr) : true;

    ALOGV("%s: [%" PRId64 "]: appSegmentReady %d, codecOutputReady %d, codecInputReady %d,"
            " dequeuedOutputBuffer %d, timestamp %" PRId64, __FUNCTION__, frameNumber,
            appSegmentReady, codecOutputReady, codecInputReady, mDequeuedOutputBufferCnt,
            inputFrame.timestamp);

    // Handle inputs for Hevc tiling
    if (codecInputReady) {
        if (mHDRGainmapEnabled && (inputFrame.baseBuffer.get() == nullptr)) {
            auto res = generateBaseImageAndGainmap(inputFrame);
            if (res != OK) {
                ALOGE("%s: Error generating SDR base image and HDR gainmap: %s (%d)", __FUNCTION__,
                        strerror(-res), res);
                return res;
            }
        }

        res = processCodecInputFrame(inputFrame);
        if (res != OK) {
            ALOGE("%s: Failed to process codec input frame: %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            return res;
        }
    }

    if (gainmapCodecInputReady) {
        res = processCodecGainmapInputFrame(inputFrame);
        if (res != OK) {
            ALOGE("%s: Failed to process gainmap codec input frame: %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            return res;
        }
    }

    if (!hdrGainmapFormatReady) {
        // If HDR gainmap is enabled, we need to wait until the gainmap format
        // is received from the codec before starting the muxer. Otherwise,
        // the muxer will not be able to add the gainmap track.
        return OK;
    }

    if (!(codecOutputReady && hasOutputBuffer) && !appSegmentReady) {
        return OK;
    }

    // Initialize and start muxer if not yet done so. In this case,
    // codecOutputReady must be true. Otherwise, appSegmentReady is guaranteed
    // to be false, and the function must have returned early.
    if (inputFrame.muxer == nullptr) {
        res = startMuxerForInputFrame(frameNumber, inputFrame);
        if (res != OK) {
            ALOGE("%s: Failed to create and start muxer: %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            return res;
        }
    }

    // Write the HDR gainmap metadata
    if (hasGainmapMetadata) {
        uint8_t kGainmapMetaMarker[] = {'t', 'm', 'a', 'p', '\0', '\0'};
        sp<ABuffer> aBuffer =
                new ABuffer(inputFrame.isoGainmapMetadata.size() + sizeof(kGainmapMetaMarker));
        memcpy(aBuffer->data(), kGainmapMetaMarker, sizeof(kGainmapMetaMarker));
        memcpy(aBuffer->data() + sizeof(kGainmapMetaMarker), inputFrame.isoGainmapMetadata.data(),
               inputFrame.isoGainmapMetadata.size());

        aBuffer->meta()->setInt32(KEY_COLOR_FORMAT, kCodecColorFormat);
        aBuffer->meta()->setInt32("color-primaries", kCodecColorPrimaries);
        aBuffer->meta()->setInt32("color-transfer", kCodecColorTransfer);
        aBuffer->meta()->setInt32("color-matrix", kCodecColorMatrix);
        aBuffer->meta()->setInt32("color-range", kCodecColorRange);
        auto res = inputFrame.muxer->writeSampleData(aBuffer, inputFrame.trackIndex,
                                                     inputFrame.timestamp,
                                                     MediaCodec::BUFFER_FLAG_MUXER_DATA);
        if (res != OK) {
            ALOGE("%s: Failed to write HDR gainmap metadata to muxer: %s (%d)",
                    __FUNCTION__, strerror(-res), res);
            return res;
        }
        inputFrame.isoGainmapMetadata.clear();
    }

    // Write JPEG APP segments data to the muxer.
    if (appSegmentReady) {
        res = processAppSegment(frameNumber, inputFrame);
        if (res != OK) {
            ALOGE("%s: Failed to process JPEG APP segments: %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            return res;
        }
    }

    // Write media codec bitstream buffers to muxer.
    while (!inputFrame.codecOutputBuffers.empty()) {
        res = processOneCodecOutputFrame(frameNumber, inputFrame);
        if (res != OK) {
            ALOGE("%s: Failed to process codec output frame: %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            return res;
        }
    }

    // Write media codec gainmap bitstream buffers to muxer.
    while (!inputFrame.gainmapCodecOutputBuffers.empty()) {
        res = processOneCodecGainmapOutputFrame(frameNumber, inputFrame);
        if (res != OK) {
            ALOGE("%s: Failed to process codec gainmap output frame: %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            return res;
        }
    }

    if ((inputFrame.pendingOutputTiles == 0) && (inputFrame.gainmapPendingOutputTiles == 0)) {
        if (inputFrame.appSegmentWritten) {
            res = processCompletedInputFrame(frameNumber, inputFrame);
            if (res != OK) {
                ALOGE("%s: Failed to process completed input frame: %s (%d)", __FUNCTION__,
                        strerror(-res), res);
                return res;
            }
        }
    }

    return res;
}

status_t HeicCompositeStream::startMuxerForInputFrame(int64_t frameNumber, InputFrame &inputFrame) {
    sp<ANativeWindow> outputANW = mOutputSurface;

    auto res = outputANW->dequeueBuffer(mOutputSurface.get(), &inputFrame.anb, &inputFrame.fenceFd);
    if (res != OK) {
        ALOGE("%s: Error retrieving output buffer: %s (%d)", __FUNCTION__, strerror(-res),
                res);
        return res;
    }
    mDequeuedOutputBufferCnt++;

    // Combine current thread id, stream id and timestamp to uniquely identify image.
    std::ostringstream tempOutputFile;
    tempOutputFile << "HEIF-" << pthread_self() << "-"
            << getStreamId() << "-" << frameNumber;
    inputFrame.fileFd = syscall(__NR_memfd_create, tempOutputFile.str().c_str(), MFD_CLOEXEC);
    if (inputFrame.fileFd < 0) {
        ALOGE("%s: Failed to create file %s. Error no is %d", __FUNCTION__,
                tempOutputFile.str().c_str(), errno);
        return NO_INIT;
    }
    inputFrame.muxer = MediaMuxer::create(inputFrame.fileFd, MediaMuxer::OUTPUT_FORMAT_HEIF);
    if (inputFrame.muxer == nullptr) {
        ALOGE("%s: Failed to create MediaMuxer for file fd %d",
                __FUNCTION__, inputFrame.fileFd);
        return NO_INIT;
    }

    res = inputFrame.muxer->setOrientationHint(inputFrame.orientation);
    if (res != OK) {
        ALOGE("%s: Failed to setOrientationHint: %s (%d)", __FUNCTION__,
                strerror(-res), res);
        return res;
    }

    ssize_t trackId = inputFrame.muxer->addTrack(inputFrame.format);
    if (trackId < 0) {
        ALOGE("%s: Failed to addTrack to the muxer: %zd", __FUNCTION__, trackId);
        return NO_INIT;
    }

    inputFrame.trackIndex = trackId;
    inputFrame.pendingOutputTiles = mNumOutputTiles;

    if (inputFrame.gainmapFormat.get() != nullptr) {
        trackId = inputFrame.muxer->addTrack(inputFrame.gainmapFormat);
        if (trackId < 0) {
            ALOGE("%s: Failed to addTrack to the muxer: %zd", __FUNCTION__, trackId);
            return NO_INIT;
        }
        inputFrame.gainmapTrackIndex = trackId;
        inputFrame.gainmapPendingOutputTiles = mNumGainmapOutputTiles;
    }

    res = inputFrame.muxer->start();
    if (res != OK) {
        ALOGE("%s: Failed to start MediaMuxer: %s (%d)",
                __FUNCTION__, strerror(-res), res);
        return res;
    }

    ALOGV("%s: [%" PRId64 "]: Muxer started for inputFrame", __FUNCTION__,
            frameNumber);
    return OK;
}

status_t HeicCompositeStream::processAppSegment(int64_t frameNumber, InputFrame &inputFrame) {
    size_t app1Size = 0;
    size_t appSegmentSize = 0;
    if (!inputFrame.exifError) {
        appSegmentSize = findAppSegmentsSize(inputFrame.appSegmentBuffer.data,
                inputFrame.appSegmentBuffer.width * inputFrame.appSegmentBuffer.height,
                &app1Size);
        if (appSegmentSize == 0) {
            ALOGE("%s: Failed to find JPEG APP segment size", __FUNCTION__);
            return NO_INIT;
        }
    }

    std::unique_ptr<ExifUtils> exifUtils(ExifUtils::create());
    auto exifRes = inputFrame.exifError ?
            exifUtils->initializeEmpty() :
            exifUtils->initialize(inputFrame.appSegmentBuffer.data, app1Size);
    if (!exifRes) {
        ALOGE("%s: Failed to initialize ExifUtils object!", __FUNCTION__);
        return BAD_VALUE;
    }
    exifRes = exifUtils->setFromMetadata(*inputFrame.result, mStaticInfo,
            mOutputWidth, mOutputHeight);
    if (!exifRes) {
        ALOGE("%s: Failed to set Exif tags using metadata and main image sizes", __FUNCTION__);
        return BAD_VALUE;
    }
    exifRes = exifUtils->setOrientation(inputFrame.orientation);
    if (!exifRes) {
        ALOGE("%s: ExifUtils failed to set orientation", __FUNCTION__);
        return BAD_VALUE;
    }
    exifRes = exifUtils->generateApp1();
    if (!exifRes) {
        ALOGE("%s: ExifUtils failed to generate APP1 segment", __FUNCTION__);
        return BAD_VALUE;
    }

    unsigned int newApp1Length = exifUtils->getApp1Length();
    const uint8_t *newApp1Segment = exifUtils->getApp1Buffer();

    //Assemble the APP1 marker buffer required by MediaCodec
    uint8_t kExifApp1Marker[] = {'E', 'x', 'i', 'f', 0xFF, 0xE1, 0x00, 0x00};
    kExifApp1Marker[6] = static_cast<uint8_t>(newApp1Length >> 8);
    kExifApp1Marker[7] = static_cast<uint8_t>(newApp1Length & 0xFF);
    size_t appSegmentBufferSize = sizeof(kExifApp1Marker) +
            appSegmentSize - app1Size + newApp1Length;
    uint8_t* appSegmentBuffer = new uint8_t[appSegmentBufferSize];
    memcpy(appSegmentBuffer, kExifApp1Marker, sizeof(kExifApp1Marker));
    memcpy(appSegmentBuffer + sizeof(kExifApp1Marker), newApp1Segment, newApp1Length);
    if (appSegmentSize - app1Size > 0) {
        memcpy(appSegmentBuffer + sizeof(kExifApp1Marker) + newApp1Length,
                inputFrame.appSegmentBuffer.data + app1Size, appSegmentSize - app1Size);
    }

    sp<ABuffer> aBuffer = new ABuffer(appSegmentBuffer, appSegmentBufferSize);
    auto res = inputFrame.muxer->writeSampleData(aBuffer, inputFrame.trackIndex,
            inputFrame.timestamp, MediaCodec::BUFFER_FLAG_MUXER_DATA);
    delete[] appSegmentBuffer;

    if (res != OK) {
        ALOGE("%s: Failed to write JPEG APP segments to muxer: %s (%d)",
                __FUNCTION__, strerror(-res), res);
        return res;
    }

    ALOGV("%s: [%" PRId64 "]: appSegmentSize is %zu, width %d, height %d, app1Size %zu",
          __FUNCTION__, frameNumber, appSegmentSize, inputFrame.appSegmentBuffer.width,
          inputFrame.appSegmentBuffer.height, app1Size);

    inputFrame.appSegmentWritten = true;
    // Release the buffer now so any pending input app segments can be processed
    if (!inputFrame.exifError) {
        mAppSegmentConsumer->unlockBuffer(inputFrame.appSegmentBuffer);
        inputFrame.appSegmentBuffer.data = nullptr;
        inputFrame.exifError = false;
    }

    return OK;
}

status_t HeicCompositeStream::generateBaseImageAndGainmap(InputFrame &inputFrame) {
    ultrahdr::JpegR jpegR(nullptr /*gles ctx*/, kGainmapScale);
    inputFrame.baseBuffer = std::make_unique<ultrahdr::uhdr_raw_image_ext_t>(
            kUltraHdrOutputFmt, kUltraHdrOutputGamut, kUltraHdrInputTransfer, kUltraHdrOutputRange,
            inputFrame.yuvBuffer.width, inputFrame.yuvBuffer.height, 8/*stride*/);

    uhdr_raw_image_t hdr_intent;
    hdr_intent.fmt = kUltraHdrInputFmt;
    hdr_intent.cg = kUltraHdrInputGamut;
    hdr_intent.ct = kUltraHdrInputTransfer;
    hdr_intent.range = kUltraHdrInputRange;
    hdr_intent.w = inputFrame.yuvBuffer.width;
    hdr_intent.h = inputFrame.yuvBuffer.height;
    hdr_intent.planes[UHDR_PLANE_Y] = inputFrame.yuvBuffer.data;
    hdr_intent.planes[UHDR_PLANE_UV] = inputFrame.yuvBuffer.dataCb;
    hdr_intent.planes[UHDR_PLANE_V] = nullptr;
    //libUltraHDR expects the stride in pixels
    hdr_intent.stride[UHDR_PLANE_Y] = inputFrame.yuvBuffer.stride / 2;
    hdr_intent.stride[UHDR_PLANE_UV] = inputFrame.yuvBuffer.chromaStride / 2;
    hdr_intent.stride[UHDR_PLANE_V] = 0;
    auto res = jpegR.toneMap(&hdr_intent, inputFrame.baseBuffer.get());
    if (res.error_code == UHDR_CODEC_OK) {
        ALOGV("%s: Base image tonemapped successfully", __FUNCTION__);
    } else {
        ALOGE("%s: Failed during HDR to SDR tonemap: %d", __FUNCTION__, res.error_code);
        return BAD_VALUE;
    }

    inputFrame.baseImage = std::make_unique<CpuConsumer::LockedBuffer>();
    *inputFrame.baseImage = inputFrame.yuvBuffer;
    inputFrame.baseImage->data = reinterpret_cast<uint8_t*>(
            inputFrame.baseBuffer->planes[UHDR_PLANE_Y]);
    inputFrame.baseImage->dataCb = reinterpret_cast<uint8_t*>(
            inputFrame.baseBuffer->planes[UHDR_PLANE_U]);
    inputFrame.baseImage->dataCr = reinterpret_cast<uint8_t*>(
            inputFrame.baseBuffer->planes[UHDR_PLANE_V]);
    inputFrame.baseImage->chromaStep = 1;
    inputFrame.baseImage->stride = inputFrame.baseBuffer->stride[UHDR_PLANE_Y];
    inputFrame.baseImage->chromaStride = inputFrame.baseBuffer->stride[UHDR_PLANE_UV];
    inputFrame.baseImage->dataSpace = HAL_DATASPACE_V0_JFIF;

    ultrahdr::uhdr_gainmap_metadata_ext_t metadata;
    res = jpegR.generateGainMap(inputFrame.baseBuffer.get(), &hdr_intent, &metadata,
            inputFrame.gainmap, false /*sdr_is_601*/, true /*use_luminance*/);
    if (res.error_code == UHDR_CODEC_OK) {
        ALOGV("%s: HDR gainmap generated successfully!", __FUNCTION__);
    } else {
        ALOGE("%s: Failed HDR gainmap: %d", __FUNCTION__, res.error_code);
        return BAD_VALUE;
    }
    // We can only generate a single channel gainmap at the moment. However only
    // multi channel HEVC encoding (like YUV420) is required. Set the extra U/V
    // planes to 128 to avoid encoding any actual color data.
    inputFrame.gainmapChroma = std::make_unique<uint8_t[]>(
            inputFrame.gainmap->w * inputFrame.gainmap->h / 2);
    memset(inputFrame.gainmapChroma.get(), 128, inputFrame.gainmap->w * inputFrame.gainmap->h / 2);

    ultrahdr::uhdr_gainmap_metadata_frac iso_secondary_metadata;
    res = ultrahdr::uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(
                &metadata, &iso_secondary_metadata);
    if (res.error_code == UHDR_CODEC_OK) {
        ALOGV("%s: HDR gainmap converted to fractions successfully!", __FUNCTION__);
    } else {
        ALOGE("%s: Failed to convert HDR gainmap to fractions: %d", __FUNCTION__,
                res.error_code);
        return BAD_VALUE;
    }

    res = ultrahdr::uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&iso_secondary_metadata,
                                                               inputFrame.isoGainmapMetadata);
    if (res.error_code == UHDR_CODEC_OK) {
        ALOGV("%s: HDR gainmap encoded to ISO format successfully!", __FUNCTION__);
    } else {
        ALOGE("%s: Failed to encode HDR gainmap to ISO format: %d", __FUNCTION__,
                res.error_code);
        return BAD_VALUE;
    }
    // 6.6.2.4.2 of ISO/IEC 23008-12:2024 expects the ISO 21496-1 gainmap to be
    // preceded by an u8 version equal to 0
    inputFrame.isoGainmapMetadata.insert(inputFrame.isoGainmapMetadata.begin(), 0);

    inputFrame.gainmapImage = std::make_unique<CpuConsumer::LockedBuffer>();
    *inputFrame.gainmapImage = inputFrame.yuvBuffer;
    inputFrame.gainmapImage->data = reinterpret_cast<uint8_t*>(
            inputFrame.gainmap->planes[UHDR_PLANE_Y]);
    inputFrame.gainmapImage->dataCb = inputFrame.gainmapChroma.get();
    inputFrame.gainmapImage->dataCr = inputFrame.gainmapChroma.get() + 1;
    inputFrame.gainmapImage->chromaStep = 2;
    inputFrame.gainmapImage->stride = inputFrame.gainmap->stride[UHDR_PLANE_Y];
    inputFrame.gainmapImage->chromaStride = inputFrame.gainmap->w;
    inputFrame.gainmapImage->dataSpace = HAL_DATASPACE_V0_JFIF;

    return OK;
}

status_t HeicCompositeStream::processCodecInputFrame(InputFrame &inputFrame) {
    for (auto& inputBuffer : inputFrame.codecInputBuffers) {
        sp<MediaCodecBuffer> buffer;
        auto res = mCodec->getInputBuffer(inputBuffer.index, &buffer);
        if (res != OK) {
            ALOGE("%s: Error getting codec input buffer: %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            return res;
        }

        // Copy one tile from source to destination.
        size_t tileX = inputBuffer.tileIndex % mGridCols;
        size_t tileY = inputBuffer.tileIndex / mGridCols;
        size_t top = mGridHeight * tileY;
        size_t left = mGridWidth * tileX;
        size_t width = (tileX == static_cast<size_t>(mGridCols) - 1) ?
                mOutputWidth - tileX * mGridWidth : mGridWidth;
        size_t height = (tileY == static_cast<size_t>(mGridRows) - 1) ?
                mOutputHeight - tileY * mGridHeight : mGridHeight;
        ALOGV("%s: inputBuffer tileIndex [%zu, %zu], top %zu, left %zu, width %zu, height %zu,"
                " timeUs %" PRId64, __FUNCTION__, tileX, tileY, top, left, width, height,
                inputBuffer.timeUs);

        auto yuvInput = (inputFrame.baseImage.get() != nullptr) ?
            *inputFrame.baseImage.get() : inputFrame.yuvBuffer;
        res = copyOneYuvTile(buffer, yuvInput, top, left, width, height);
        if (res != OK) {
            ALOGE("%s: Failed to copy YUV tile %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            return res;
        }

        res = mCodec->queueInputBuffer(inputBuffer.index, 0, buffer->capacity(),
                inputBuffer.timeUs, 0, nullptr /*errorDetailMsg*/);
        if (res != OK) {
            ALOGE("%s: Failed to queueInputBuffer to Codec: %s (%d)",
                    __FUNCTION__, strerror(-res), res);
            return res;
        }
    }

    inputFrame.codecInputBuffers.clear();
    return OK;
}

status_t HeicCompositeStream::processCodecGainmapInputFrame(InputFrame &inputFrame) {
    for (auto& inputBuffer : inputFrame.gainmapCodecInputBuffers) {
        sp<MediaCodecBuffer> buffer;
        auto res = mGainmapCodec->getInputBuffer(inputBuffer.index, &buffer);
        if (res != OK) {
            ALOGE("%s: Error getting codec input buffer: %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            return res;
        }

        // Copy one tile from source to destination.
        size_t tileX = inputBuffer.tileIndex % mGainmapGridCols;
        size_t tileY = inputBuffer.tileIndex / mGainmapGridCols;
        size_t top = mGainmapGridHeight * tileY;
        size_t left = mGainmapGridWidth * tileX;
        size_t width = (tileX == static_cast<size_t>(mGainmapGridCols) - 1) ?
                mGainmapOutputWidth - tileX * mGainmapGridWidth : mGainmapGridWidth;
        size_t height = (tileY == static_cast<size_t>(mGainmapGridRows) - 1) ?
                mGainmapOutputHeight - tileY * mGainmapGridHeight : mGainmapGridHeight;
        ALOGV("%s: gainmap inputBuffer tileIndex [%zu, %zu], top %zu, left %zu, width %zu, "
                "height %zu, timeUs %" PRId64, __FUNCTION__, tileX, tileY, top, left, width, height,
                inputBuffer.timeUs);

        auto yuvInput = *inputFrame.gainmapImage;
        res = copyOneYuvTile(buffer, yuvInput, top, left, width, height);
        if (res != OK) {
            ALOGE("%s: Failed to copy YUV tile %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            return res;
        }

        res = mGainmapCodec->queueInputBuffer(inputBuffer.index, 0, buffer->capacity(),
                inputBuffer.timeUs, 0, nullptr /*errorDetailMsg*/);
        if (res != OK) {
            ALOGE("%s: Failed to queueInputBuffer to Codec: %s (%d)",
                    __FUNCTION__, strerror(-res), res);
            return res;
        }
    }

    inputFrame.gainmapCodecInputBuffers.clear();
    return OK;
}

status_t HeicCompositeStream::processOneCodecOutputFrame(int64_t frameNumber,
        InputFrame &inputFrame) {
    auto it = inputFrame.codecOutputBuffers.begin();
    sp<MediaCodecBuffer> buffer;
    status_t res = mCodec->getOutputBuffer(it->index, &buffer);
    if (res != OK) {
        ALOGE("%s: Error getting Heic codec output buffer at index %d: %s (%d)",
                __FUNCTION__, it->index, strerror(-res), res);
        return res;
    }
    if (buffer == nullptr) {
        ALOGE("%s: Invalid Heic codec output buffer at index %d",
                __FUNCTION__, it->index);
        return BAD_VALUE;
    }

    sp<ABuffer> aBuffer = new ABuffer(buffer->data(), buffer->size());
    if (mHDRGainmapEnabled) {
        aBuffer->meta()->setInt32(KEY_COLOR_FORMAT, kCodecColorFormat);
        aBuffer->meta()->setInt32("color-primaries", kCodecColorPrimaries);
        aBuffer->meta()->setInt32("color-transfer", kCodecColorTransfer);
        aBuffer->meta()->setInt32("color-matrix", kCodecColorMatrix);
        aBuffer->meta()->setInt32("color-range", kCodecColorRange);
    }
    res = inputFrame.muxer->writeSampleData(
            aBuffer, inputFrame.trackIndex, inputFrame.timestamp, 0 /*flags*/);
    if (res != OK) {
        ALOGE("%s: Failed to write buffer index %d to muxer: %s (%d)",
                __FUNCTION__, it->index, strerror(-res), res);
        return res;
    }

    mCodec->releaseOutputBuffer(it->index);
    if (inputFrame.pendingOutputTiles == 0) {
        ALOGW("%s: Codec generated more tiles than expected!", __FUNCTION__);
    } else {
        inputFrame.pendingOutputTiles--;
    }

    inputFrame.codecOutputBuffers.erase(inputFrame.codecOutputBuffers.begin());

    ALOGV("%s: [%" PRId64 "]: Output buffer index %d",
        __FUNCTION__, frameNumber, it->index);
    return OK;
}

status_t HeicCompositeStream::processOneCodecGainmapOutputFrame(int64_t frameNumber,
        InputFrame &inputFrame) {
    auto it = inputFrame.gainmapCodecOutputBuffers.begin();
    sp<MediaCodecBuffer> buffer;
    status_t res = mGainmapCodec->getOutputBuffer(it->index, &buffer);
    if (res != OK) {
        ALOGE("%s: Error getting Heic gainmap codec output buffer at index %d: %s (%d)",
                __FUNCTION__, it->index, strerror(-res), res);
        return res;
    }
    if (buffer == nullptr) {
        ALOGE("%s: Invalid Heic gainmap codec output buffer at index %d",
                __FUNCTION__, it->index);
        return BAD_VALUE;
    }

    uint8_t kGainmapMarker[] = {'g', 'm', 'a', 'p', '\0', '\0'};
    sp<ABuffer> aBuffer = new ABuffer(buffer->size() + sizeof(kGainmapMarker));
    memcpy(aBuffer->data(), kGainmapMarker, sizeof(kGainmapMarker));
    memcpy(aBuffer->data() + sizeof(kGainmapMarker), buffer->data(), buffer->size());
    aBuffer->meta()->setInt32(KEY_COLOR_FORMAT, kCodecGainmapColorFormat);
    aBuffer->meta()->setInt32("color-primaries", kCodecGainmapColorPrimaries);
    aBuffer->meta()->setInt32("color-transfer", kCodecGainmapColorTransfer);
    aBuffer->meta()->setInt32("color-matrix", kCodecGainmapColorMatrix);
    aBuffer->meta()->setInt32("color-range", kCodecGainmapColorRange);
    res = inputFrame.muxer->writeSampleData(aBuffer, inputFrame.gainmapTrackIndex,
                                            inputFrame.timestamp,
                                            MediaCodec::BUFFER_FLAG_MUXER_DATA);
    if (res != OK) {
        ALOGE("%s: Failed to write buffer index %d to muxer: %s (%d)",
                __FUNCTION__, it->index, strerror(-res), res);
        return res;
    }

    mGainmapCodec->releaseOutputBuffer(it->index);
    if (inputFrame.gainmapPendingOutputTiles == 0) {
        ALOGW("%s: Codec generated more gainmap tiles than expected!", __FUNCTION__);
    } else {
        inputFrame.gainmapPendingOutputTiles--;
    }

    inputFrame.gainmapCodecOutputBuffers.erase(inputFrame.gainmapCodecOutputBuffers.begin());

    ALOGV("%s: [%" PRId64 "]: Gainmap output buffer index %d",
        __FUNCTION__, frameNumber, it->index);
    return OK;
}

status_t HeicCompositeStream::processCompletedInputFrame(int64_t frameNumber,
        InputFrame &inputFrame) {
    sp<ANativeWindow> outputANW = mOutputSurface;
    inputFrame.muxer->stop();

    // Copy the content of the file to memory.
    sp<GraphicBuffer> gb = GraphicBuffer::from(inputFrame.anb);
    void* dstBuffer;
    GraphicBufferLocker gbLocker(gb);
    auto res = gbLocker.lockAsync(&dstBuffer, inputFrame.fenceFd);
    if (res != OK) {
        ALOGE("%s: Error trying to lock output buffer fence: %s (%d)", __FUNCTION__,
                strerror(-res), res);
        return res;
    }

    off_t fSize = lseek(inputFrame.fileFd, 0, SEEK_END);
    if (static_cast<size_t>(fSize) > mMaxHeicBufferSize - sizeof(CameraBlob)) {
        ALOGE("%s: Error: MediaMuxer output size %ld is larger than buffer sizer %zu",
                __FUNCTION__, fSize, mMaxHeicBufferSize - sizeof(CameraBlob));
        return BAD_VALUE;
    }

    lseek(inputFrame.fileFd, 0, SEEK_SET);
    ssize_t bytesRead = read(inputFrame.fileFd, dstBuffer, fSize);
    if (bytesRead < fSize) {
        ALOGE("%s: Only %zd of %ld bytes read", __FUNCTION__, bytesRead, fSize);
        return BAD_VALUE;
    }

    close(inputFrame.fileFd);
    inputFrame.fileFd = -1;

    // Fill in HEIC header
    // Must be in sync with CAMERA3_HEIC_BLOB_ID in android_media_Utils.cpp
    uint8_t *header = static_cast<uint8_t*>(dstBuffer) + mMaxHeicBufferSize - sizeof(CameraBlob);
    CameraBlob blobHeader = {
        .blobId = static_cast<CameraBlobId>(0x00FE),
        .blobSizeBytes = static_cast<int32_t>(fSize)
    };
    memcpy(header, &blobHeader, sizeof(CameraBlob));

    res = native_window_set_buffers_timestamp(mOutputSurface.get(), inputFrame.timestamp);
    if (res != OK) {
        ALOGE("%s: Stream %d: Error setting timestamp: %s (%d)",
               __FUNCTION__, getStreamId(), strerror(-res), res);
        return res;
    }

    res = outputANW->queueBuffer(mOutputSurface.get(), inputFrame.anb, /*fence*/ -1);
    if (res != OK) {
        ALOGE("%s: Failed to queueBuffer to Heic stream: %s (%d)", __FUNCTION__,
                strerror(-res), res);
        return res;
    }
    inputFrame.anb = nullptr;
    mDequeuedOutputBufferCnt--;

    ALOGV("%s: [%" PRId64 "]", __FUNCTION__, frameNumber);
    ATRACE_ASYNC_END("HEIC capture", frameNumber);
    return OK;
}


void HeicCompositeStream::releaseInputFrameLocked(int64_t frameNumber,
        InputFrame *inputFrame /*out*/) {
    if (inputFrame == nullptr) {
        return;
    }

    if (inputFrame->appSegmentBuffer.data != nullptr) {
        mAppSegmentConsumer->unlockBuffer(inputFrame->appSegmentBuffer);
        inputFrame->appSegmentBuffer.data = nullptr;
    }

    while (!inputFrame->codecOutputBuffers.empty()) {
        auto it = inputFrame->codecOutputBuffers.begin();
        ALOGV("%s: releaseOutputBuffer index %d", __FUNCTION__, it->index);
        mCodec->releaseOutputBuffer(it->index);
        inputFrame->codecOutputBuffers.erase(it);
    }

    while (!inputFrame->gainmapCodecOutputBuffers.empty()) {
        auto it = inputFrame->gainmapCodecOutputBuffers.begin();
        ALOGV("%s: release gainmap output buffer index %d", __FUNCTION__, it->index);
        mGainmapCodec->releaseOutputBuffer(it->index);
        inputFrame->gainmapCodecOutputBuffers.erase(it);
    }

    if (inputFrame->yuvBuffer.data != nullptr) {
        mMainImageConsumer->unlockBuffer(inputFrame->yuvBuffer);
        inputFrame->yuvBuffer.data = nullptr;
        mYuvBufferAcquired = false;
    }

    while (!inputFrame->codecInputBuffers.empty()) {
        auto it = inputFrame->codecInputBuffers.begin();
        inputFrame->codecInputBuffers.erase(it);
    }

    while (!inputFrame->gainmapCodecInputBuffers.empty()) {
        auto it = inputFrame->gainmapCodecInputBuffers.begin();
        inputFrame->gainmapCodecInputBuffers.erase(it);
    }

    if (inputFrame->error || mErrorState) {
        ALOGV("%s: notifyError called for frameNumber %" PRId64, __FUNCTION__, frameNumber);
        notifyError(frameNumber, inputFrame->requestId);
    }

    if (inputFrame->fileFd >= 0) {
        close(inputFrame->fileFd);
        inputFrame->fileFd = -1;
    }

    if (inputFrame->anb != nullptr) {
        sp<ANativeWindow> outputANW = mOutputSurface;
        outputANW->cancelBuffer(mOutputSurface.get(), inputFrame->anb, /*fence*/ -1);
        inputFrame->anb = nullptr;

        mDequeuedOutputBufferCnt--;
    }
}

void HeicCompositeStream::releaseInputFramesLocked() {
    auto it = mPendingInputFrames.begin();
    bool inputFrameDone = false;
    while (it != mPendingInputFrames.end()) {
        auto& inputFrame = it->second;
        if (inputFrame.error ||
                (inputFrame.appSegmentWritten && inputFrame.pendingOutputTiles == 0 &&
                 inputFrame.gainmapPendingOutputTiles == 0)) {
            releaseInputFrameLocked(it->first, &inputFrame);
            it = mPendingInputFrames.erase(it);
            inputFrameDone = true;
        } else {
            it++;
        }
    }

    // Update codec quality based on first upcoming input frame.
    // Note that when encoding is in surface mode, currently there is  no
    // way for camera service to synchronize quality setting on a per-frame
    // basis: we don't get notification when codec is ready to consume a new
    // input frame. So we update codec quality on a best-effort basis.
    if (inputFrameDone) {
        auto firstPendingFrame = mPendingInputFrames.begin();
        if (firstPendingFrame != mPendingInputFrames.end()) {
            updateCodecQualityLocked(firstPendingFrame->second.quality);
        } else {
            if (mSettingsByFrameNumber.size() == 0) {
                markTrackerIdle();
            }
        }
    }
}

status_t HeicCompositeStream::initializeGainmapCodec() {
    ALOGV("%s", __FUNCTION__);

    if (!mHDRGainmapEnabled) {
        return OK;
    }
    uint32_t width = mOutputWidth / kGainmapScale;
    uint32_t height = mOutputHeight / kGainmapScale;
    bool useGrid = false;
    bool useHeic = false;
    AString hevcName;
    bool isSizeSupported = isSizeSupportedByHeifEncoder(width, height,
            &useHeic, &useGrid, nullptr, &hevcName);
    if (!isSizeSupported) {
        ALOGE("%s: Encoder doesn't support size %u x %u!",
                __FUNCTION__, width, height);
        return BAD_VALUE;
    }

    // Create HEVC codec.
    mGainmapCodec = MediaCodec::CreateByComponentName(mCodecLooper, hevcName);
    if (mGainmapCodec == nullptr) {
        ALOGE("%s: Failed to create gainmap codec", __FUNCTION__);
        return NO_INIT;
    }

    // Create Looper and handler for Codec callback.
    mGainmapCodecCallbackHandler = new CodecCallbackHandler(this, true /*isGainmap*/);
    if (mGainmapCodecCallbackHandler == nullptr) {
        ALOGE("%s: Failed to create gainmap codec callback handler", __FUNCTION__);
        return NO_MEMORY;
    }
    mGainmapCallbackLooper = new ALooper;
    mGainmapCallbackLooper->setName("Camera3-HeicComposite-MediaCodecGainmapCallbackLooper");
    auto res = mGainmapCallbackLooper->start(
            false,   // runOnCallingThread
            false,    // canCallJava
            PRIORITY_AUDIO);
    if (res != OK) {
        ALOGE("%s: Failed to start gainmap media callback looper: %s (%d)",
                __FUNCTION__, strerror(-res), res);
        return NO_INIT;
    }
    mGainmapCallbackLooper->registerHandler(mGainmapCodecCallbackHandler);

    mGainmapAsyncNotify = new AMessage(kWhatCallbackNotify, mGainmapCodecCallbackHandler);
    res = mGainmapCodec->setCallback(mGainmapAsyncNotify);
    if (res != OK) {
        ALOGE("%s: Failed to set MediaCodec callback: %s (%d)", __FUNCTION__,
                strerror(-res), res);
        return res;
    }

    // Create output format and configure the Codec.
    sp<AMessage> outputFormat = new AMessage();
    outputFormat->setString(KEY_MIME, MIMETYPE_VIDEO_HEVC);
    outputFormat->setInt32(KEY_BITRATE_MODE, BITRATE_MODE_CQ);
    outputFormat->setInt32(KEY_QUALITY, kDefaultJpegQuality);
    // Ask codec to skip timestamp check and encode all frames.
    outputFormat->setInt64(KEY_MAX_PTS_GAP_TO_ENCODER, kNoFrameDropMaxPtsGap);

    int32_t gridWidth, gridHeight, gridRows, gridCols;
    if (useGrid){
        gridWidth = HeicEncoderInfoManager::kGridWidth;
        gridHeight = HeicEncoderInfoManager::kGridHeight;
        gridRows = (height + gridHeight - 1)/gridHeight;
        gridCols = (width + gridWidth - 1)/gridWidth;
    } else {
        gridWidth = width;
        gridHeight = height;
        gridRows = 1;
        gridCols = 1;
    }

    outputFormat->setInt32(KEY_WIDTH, !useGrid ? width : gridWidth);
    outputFormat->setInt32(KEY_HEIGHT, !useGrid ? height : gridHeight);
    outputFormat->setInt32(KEY_I_FRAME_INTERVAL, 0);
    outputFormat->setInt32(KEY_COLOR_FORMAT, COLOR_FormatYUV420Flexible);
    outputFormat->setInt32(KEY_FRAME_RATE, useGrid ? gridRows * gridCols : kNoGridOpRate);
    // This only serves as a hint to encoder when encoding is not real-time.
    outputFormat->setInt32(KEY_OPERATING_RATE, useGrid ? kGridOpRate : kNoGridOpRate);

    res = mGainmapCodec->configure(outputFormat, nullptr /*nativeWindow*/,
            nullptr /*crypto*/, CONFIGURE_FLAG_ENCODE);
    if (res != OK) {
        ALOGE("%s: Failed to configure codec: %s (%d)", __FUNCTION__,
                strerror(-res), res);
        return res;
    }

    mGainmapGridWidth = gridWidth;
    mGainmapGridHeight = gridHeight;
    mGainmapGridRows = gridRows;
    mGainmapGridCols = gridCols;
    mGainmapUseGrid = useGrid;
    mGainmapOutputWidth = width;
    mGainmapOutputHeight = height;
    mMaxHeicBufferSize +=
        ALIGN(mGainmapOutputWidth, HeicEncoderInfoManager::kGridWidth) *
        ALIGN(mGainmapOutputHeight, HeicEncoderInfoManager::kGridHeight) * 3 / 2;

    return OK;
}

status_t HeicCompositeStream::initializeCodec(uint32_t width, uint32_t height,
        const sp<CameraDeviceBase>& cameraDevice) {
    ALOGV("%s", __FUNCTION__);

    bool useGrid = false;
    AString hevcName;
    bool isSizeSupported = isSizeSupportedByHeifEncoder(width, height,
            &mUseHeic, &useGrid, nullptr, &hevcName);
    if (!isSizeSupported) {
        ALOGE("%s: Encoder doesnt' support size %u x %u!",
                __FUNCTION__, width, height);
        return BAD_VALUE;
    }
    if (mHDRGainmapEnabled) {
        // HDR Gainmap tonemapping and generation can only be done in SW
        // using P010 as input. HEIC codecs expect private/impl.defined
        // which is opaque.
        mUseHeic = false;
    }

    // Create Looper for MediaCodec.
    auto desiredMime = mUseHeic ? MIMETYPE_IMAGE_ANDROID_HEIC : MIMETYPE_VIDEO_HEVC;
    mCodecLooper = new ALooper;
    mCodecLooper->setName("Camera3-HeicComposite-MediaCodecLooper");
    status_t res = mCodecLooper->start(
            false,   // runOnCallingThread
            false,    // canCallJava
            PRIORITY_AUDIO);
    if (res != OK) {
        ALOGE("%s: Failed to start codec looper: %s (%d)",
                __FUNCTION__, strerror(-res), res);
        return NO_INIT;
    }

    // Create HEIC/HEVC codec.
    if (mUseHeic) {
        mCodec = MediaCodec::CreateByType(mCodecLooper, desiredMime, true /*encoder*/);
    } else {
        mCodec = MediaCodec::CreateByComponentName(mCodecLooper, hevcName);
    }
    if (mCodec == nullptr) {
        ALOGE("%s: Failed to create codec for %s", __FUNCTION__, desiredMime);
        return NO_INIT;
    }

    // Create Looper and handler for Codec callback.
    mCodecCallbackHandler = new CodecCallbackHandler(this);
    if (mCodecCallbackHandler == nullptr) {
        ALOGE("%s: Failed to create codec callback handler", __FUNCTION__);
        return NO_MEMORY;
    }
    mCallbackLooper = new ALooper;
    mCallbackLooper->setName("Camera3-HeicComposite-MediaCodecCallbackLooper");
    res = mCallbackLooper->start(
            false,   // runOnCallingThread
            false,    // canCallJava
            PRIORITY_AUDIO);
    if (res != OK) {
        ALOGE("%s: Failed to start media callback looper: %s (%d)",
                __FUNCTION__, strerror(-res), res);
        return NO_INIT;
    }
    mCallbackLooper->registerHandler(mCodecCallbackHandler);

    mAsyncNotify = new AMessage(kWhatCallbackNotify, mCodecCallbackHandler);
    res = mCodec->setCallback(mAsyncNotify);
    if (res != OK) {
        ALOGE("%s: Failed to set MediaCodec callback: %s (%d)", __FUNCTION__,
                strerror(-res), res);
        return res;
    }

    // Create output format and configure the Codec.
    sp<AMessage> outputFormat = new AMessage();
    outputFormat->setString(KEY_MIME, desiredMime);
    outputFormat->setInt32(KEY_BITRATE_MODE, BITRATE_MODE_CQ);
    outputFormat->setInt32(KEY_QUALITY, kDefaultJpegQuality);
    // Ask codec to skip timestamp check and encode all frames.
    outputFormat->setInt64(KEY_MAX_PTS_GAP_TO_ENCODER, kNoFrameDropMaxPtsGap);

    int32_t gridWidth, gridHeight, gridRows, gridCols;
    if (useGrid || mUseHeic) {
        gridWidth = HeicEncoderInfoManager::kGridWidth;
        gridHeight = HeicEncoderInfoManager::kGridHeight;
        gridRows = (height + gridHeight - 1)/gridHeight;
        gridCols = (width + gridWidth - 1)/gridWidth;

        if (mUseHeic) {
            outputFormat->setInt32(KEY_TILE_WIDTH, gridWidth);
            outputFormat->setInt32(KEY_TILE_HEIGHT, gridHeight);
            outputFormat->setInt32(KEY_GRID_COLUMNS, gridCols);
            outputFormat->setInt32(KEY_GRID_ROWS, gridRows);
        }

    } else {
        gridWidth = width;
        gridHeight = height;
        gridRows = 1;
        gridCols = 1;
    }

    outputFormat->setInt32(KEY_WIDTH, !useGrid ? width : gridWidth);
    outputFormat->setInt32(KEY_HEIGHT, !useGrid ? height : gridHeight);
    outputFormat->setInt32(KEY_I_FRAME_INTERVAL, 0);
    outputFormat->setInt32(KEY_COLOR_FORMAT,
            useGrid || mHDRGainmapEnabled ? COLOR_FormatYUV420Flexible : COLOR_FormatSurface);
    outputFormat->setInt32(KEY_FRAME_RATE, useGrid ? gridRows * gridCols : kNoGridOpRate);
    // This only serves as a hint to encoder when encoding is not real-time.
    outputFormat->setInt32(KEY_OPERATING_RATE, useGrid ? kGridOpRate : kNoGridOpRate);

    res = mCodec->configure(outputFormat, nullptr /*nativeWindow*/,
            nullptr /*crypto*/, CONFIGURE_FLAG_ENCODE);
    if (res != OK) {
        ALOGE("%s: Failed to configure codec: %s (%d)", __FUNCTION__,
                strerror(-res), res);
        return res;
    }

    mGridWidth = gridWidth;
    mGridHeight = gridHeight;
    mGridRows = gridRows;
    mGridCols = gridCols;
    mUseGrid = useGrid;
    mOutputWidth = width;
    mOutputHeight = height;
    mAppSegmentMaxSize = calcAppSegmentMaxSize(cameraDevice->info());
    mMaxHeicBufferSize =
        ALIGN(mOutputWidth, HeicEncoderInfoManager::kGridWidth) *
        ALIGN(mOutputHeight, HeicEncoderInfoManager::kGridHeight) * 3 / 2 + mAppSegmentMaxSize;

    return initializeGainmapCodec();
}

void HeicCompositeStream::deinitGainmapCodec() {
    ALOGV("%s", __FUNCTION__);
    if (mGainmapCodec != nullptr) {
        mGainmapCodec->stop();
        mGainmapCodec->release();
        mGainmapCodec.clear();
    }

    if (mGainmapCallbackLooper != nullptr) {
        mGainmapCallbackLooper->stop();
        mGainmapCallbackLooper.clear();
    }

    mGainmapAsyncNotify.clear();
    mGainmapFormat.clear();
}

void HeicCompositeStream::deinitCodec() {
    ALOGV("%s", __FUNCTION__);
    if (mCodec != nullptr) {
        mCodec->stop();
        mCodec->release();
        mCodec.clear();
    }

    deinitGainmapCodec();

    if (mCodecLooper != nullptr) {
        mCodecLooper->stop();
        mCodecLooper.clear();
    }

    if (mCallbackLooper != nullptr) {
        mCallbackLooper->stop();
        mCallbackLooper.clear();
    }

    mAsyncNotify.clear();
    mFormat.clear();
}

// Return the size of the complete list of app segment, 0 indicates failure
size_t HeicCompositeStream::findAppSegmentsSize(const uint8_t* appSegmentBuffer,
        size_t maxSize, size_t *app1SegmentSize) {
    if (appSegmentBuffer == nullptr || app1SegmentSize == nullptr) {
        ALOGE("%s: Invalid input appSegmentBuffer %p, app1SegmentSize %p",
                __FUNCTION__, appSegmentBuffer, app1SegmentSize);
        return 0;
    }

    size_t expectedSize = 0;
    // First check for EXIF transport header at the end of the buffer
    const uint8_t *header = appSegmentBuffer + (maxSize - sizeof(CameraBlob));
    const CameraBlob *blob = (const CameraBlob*)(header);
    if (blob->blobId != CameraBlobId::JPEG_APP_SEGMENTS) {
        ALOGE("%s: Invalid EXIF blobId %d", __FUNCTION__, eToI(blob->blobId));
        return 0;
    }

    expectedSize = blob->blobSizeBytes;
    if (expectedSize == 0 || expectedSize > maxSize - sizeof(CameraBlob)) {
        ALOGE("%s: Invalid blobSize %zu.", __FUNCTION__, expectedSize);
        return 0;
    }

    uint32_t totalSize = 0;

    // Verify APP1 marker (mandatory)
    uint8_t app1Marker[] = {0xFF, 0xE1};
    if (memcmp(appSegmentBuffer, app1Marker, sizeof(app1Marker))) {
        ALOGE("%s: Invalid APP1 marker: %x, %x", __FUNCTION__,
                appSegmentBuffer[0], appSegmentBuffer[1]);
        return 0;
    }
    totalSize += sizeof(app1Marker);

    uint16_t app1Size = (static_cast<uint16_t>(appSegmentBuffer[totalSize]) << 8) +
            appSegmentBuffer[totalSize+1];
    totalSize += app1Size;

    ALOGV("%s: Expected APP segments size %zu, APP1 segment size %u",
            __FUNCTION__, expectedSize, app1Size);
    while (totalSize < expectedSize) {
        if (appSegmentBuffer[totalSize] != 0xFF ||
                appSegmentBuffer[totalSize+1] <= 0xE1 ||
                appSegmentBuffer[totalSize+1] > 0xEF) {
            // Invalid APPn marker
            ALOGE("%s: Invalid APPn marker: %x, %x", __FUNCTION__,
                    appSegmentBuffer[totalSize], appSegmentBuffer[totalSize+1]);
            return 0;
        }
        totalSize += 2;

        uint16_t appnSize = (static_cast<uint16_t>(appSegmentBuffer[totalSize]) << 8) +
                appSegmentBuffer[totalSize+1];
        totalSize += appnSize;
    }

    if (totalSize != expectedSize) {
        ALOGE("%s: Invalid JPEG APP segments: totalSize %u vs expected size %zu",
                __FUNCTION__, totalSize, expectedSize);
        return 0;
    }

    *app1SegmentSize = app1Size + sizeof(app1Marker);
    return expectedSize;
}

status_t HeicCompositeStream::copyOneYuvTile(sp<MediaCodecBuffer>& codecBuffer,
        const CpuConsumer::LockedBuffer& yuvBuffer,
        size_t top, size_t left, size_t width, size_t height) {
    ATRACE_CALL();

    // Get stride information for codecBuffer
    sp<ABuffer> imageData;
    if (!codecBuffer->meta()->findBuffer("image-data", &imageData)) {
        ALOGE("%s: Codec input buffer is not for image data!", __FUNCTION__);
        return BAD_VALUE;
    }
    if (imageData->size() != sizeof(MediaImage2)) {
        ALOGE("%s: Invalid codec input image size %zu, expected %zu",
                __FUNCTION__, imageData->size(), sizeof(MediaImage2));
        return BAD_VALUE;
    }
    MediaImage2* imageInfo = reinterpret_cast<MediaImage2*>(imageData->data());
    if (imageInfo->mType != MediaImage2::MEDIA_IMAGE_TYPE_YUV ||
            imageInfo->mBitDepth != 8 ||
            imageInfo->mBitDepthAllocated != 8 ||
            imageInfo->mNumPlanes != 3) {
        ALOGE("%s: Invalid codec input image info: mType %d, mBitDepth %d, "
                "mBitDepthAllocated %d, mNumPlanes %d!", __FUNCTION__,
                imageInfo->mType, imageInfo->mBitDepth,
                imageInfo->mBitDepthAllocated, imageInfo->mNumPlanes);
        return BAD_VALUE;
    }

    ALOGV("%s: yuvBuffer chromaStep %d, chromaStride %d",
            __FUNCTION__, yuvBuffer.chromaStep, yuvBuffer.chromaStride);
    ALOGV("%s: U offset %u, V offset %u, U rowInc %d, V rowInc %d, U colInc %d, V colInc %d",
            __FUNCTION__, imageInfo->mPlane[MediaImage2::U].mOffset,
            imageInfo->mPlane[MediaImage2::V].mOffset,
            imageInfo->mPlane[MediaImage2::U].mRowInc,
            imageInfo->mPlane[MediaImage2::V].mRowInc,
            imageInfo->mPlane[MediaImage2::U].mColInc,
            imageInfo->mPlane[MediaImage2::V].mColInc);

    // Y
    for (auto row = top; row < top+height; row++) {
        uint8_t *dst = codecBuffer->data() + imageInfo->mPlane[MediaImage2::Y].mOffset +
                imageInfo->mPlane[MediaImage2::Y].mRowInc * (row - top);
        mFnCopyRow(yuvBuffer.data+row*yuvBuffer.stride+left, dst, width);
    }

    // U is Cb, V is Cr
    bool codecUPlaneFirst = imageInfo->mPlane[MediaImage2::V].mOffset >
            imageInfo->mPlane[MediaImage2::U].mOffset;
    uint32_t codecUvOffsetDiff = codecUPlaneFirst ?
            imageInfo->mPlane[MediaImage2::V].mOffset - imageInfo->mPlane[MediaImage2::U].mOffset :
            imageInfo->mPlane[MediaImage2::U].mOffset - imageInfo->mPlane[MediaImage2::V].mOffset;
    bool isCodecUvSemiplannar = (codecUvOffsetDiff == 1) &&
            (imageInfo->mPlane[MediaImage2::U].mRowInc ==
            imageInfo->mPlane[MediaImage2::V].mRowInc) &&
            (imageInfo->mPlane[MediaImage2::U].mColInc == 2) &&
            (imageInfo->mPlane[MediaImage2::V].mColInc == 2);
    bool isCodecUvPlannar =
            ((codecUPlaneFirst && codecUvOffsetDiff >=
                    imageInfo->mPlane[MediaImage2::U].mRowInc * imageInfo->mHeight/2) ||
            ((!codecUPlaneFirst && codecUvOffsetDiff >=
                    imageInfo->mPlane[MediaImage2::V].mRowInc * imageInfo->mHeight/2))) &&
            imageInfo->mPlane[MediaImage2::U].mColInc == 1 &&
            imageInfo->mPlane[MediaImage2::V].mColInc == 1;
    bool cameraUPlaneFirst = yuvBuffer.dataCr > yuvBuffer.dataCb;

    if (isCodecUvSemiplannar && yuvBuffer.chromaStep == 2 &&
            (codecUPlaneFirst == cameraUPlaneFirst)) {
        // UV semiplannar
        // The chrome plane could be either Cb first, or Cr first. Take the
        // smaller address.
        uint8_t *src = std::min(yuvBuffer.dataCb, yuvBuffer.dataCr);
        MediaImage2::PlaneIndex dstPlane = codecUPlaneFirst ? MediaImage2::U : MediaImage2::V;
        for (auto row = top/2; row < (top+height)/2; row++) {
            uint8_t *dst = codecBuffer->data() + imageInfo->mPlane[dstPlane].mOffset +
                    imageInfo->mPlane[dstPlane].mRowInc * (row - top/2);
            mFnCopyRow(src+row*yuvBuffer.chromaStride+left, dst, width);
        }
    } else if (isCodecUvPlannar && yuvBuffer.chromaStep == 1) {
        // U plane
        for (auto row = top/2; row < (top+height)/2; row++) {
            uint8_t *dst = codecBuffer->data() + imageInfo->mPlane[MediaImage2::U].mOffset +
                    imageInfo->mPlane[MediaImage2::U].mRowInc * (row - top/2);
            mFnCopyRow(yuvBuffer.dataCb+row*yuvBuffer.chromaStride+left/2, dst, width/2);
        }

        // V plane
        for (auto row = top/2; row < (top+height)/2; row++) {
            uint8_t *dst = codecBuffer->data() + imageInfo->mPlane[MediaImage2::V].mOffset +
                    imageInfo->mPlane[MediaImage2::V].mRowInc * (row - top/2);
            mFnCopyRow(yuvBuffer.dataCr+row*yuvBuffer.chromaStride+left/2, dst, width/2);
        }
    } else {
        // Convert between semiplannar and plannar, or when UV orders are
        // different.
        uint8_t *dst = codecBuffer->data();
        for (auto row = top/2; row < (top+height)/2; row++) {
            for (auto col = left/2; col < (left+width)/2; col++) {
                // U/Cb
                int32_t dstIndex = imageInfo->mPlane[MediaImage2::U].mOffset +
                        imageInfo->mPlane[MediaImage2::U].mRowInc * (row - top/2) +
                        imageInfo->mPlane[MediaImage2::U].mColInc * (col - left/2);
                int32_t srcIndex = row * yuvBuffer.chromaStride + yuvBuffer.chromaStep * col;
                dst[dstIndex] = yuvBuffer.dataCb[srcIndex];

                // V/Cr
                dstIndex = imageInfo->mPlane[MediaImage2::V].mOffset +
                        imageInfo->mPlane[MediaImage2::V].mRowInc * (row - top/2) +
                        imageInfo->mPlane[MediaImage2::V].mColInc * (col - left/2);
                srcIndex = row * yuvBuffer.chromaStride + yuvBuffer.chromaStep * col;
                dst[dstIndex] = yuvBuffer.dataCr[srcIndex];
            }
        }
    }
    return OK;
}

void HeicCompositeStream::initCopyRowFunction([[maybe_unused]] int32_t width)
{
    using namespace libyuv;

    mFnCopyRow = CopyRow_C;
#if defined(HAS_COPYROW_SSE2)
    if (TestCpuFlag(kCpuHasSSE2)) {
        mFnCopyRow = IS_ALIGNED(width, 32) ? CopyRow_SSE2 : CopyRow_Any_SSE2;
    }
#endif
#if defined(HAS_COPYROW_AVX)
    if (TestCpuFlag(kCpuHasAVX)) {
        mFnCopyRow = IS_ALIGNED(width, 64) ? CopyRow_AVX : CopyRow_Any_AVX;
    }
#endif
#if defined(HAS_COPYROW_ERMS)
    if (TestCpuFlag(kCpuHasERMS)) {
        mFnCopyRow = CopyRow_ERMS;
    }
#endif
#if defined(HAS_COPYROW_NEON)
    if (TestCpuFlag(kCpuHasNEON)) {
        mFnCopyRow = IS_ALIGNED(width, 32) ? CopyRow_NEON : CopyRow_Any_NEON;
    }
#endif
#if defined(HAS_COPYROW_MIPS)
    if (TestCpuFlag(kCpuHasMIPS)) {
        mFnCopyRow = CopyRow_MIPS;
    }
#endif
}

size_t HeicCompositeStream::calcAppSegmentMaxSize(const CameraMetadata& info) {
    camera_metadata_ro_entry_t entry = info.find(ANDROID_HEIC_INFO_MAX_JPEG_APP_SEGMENTS_COUNT);
    size_t maxAppsSegment = 1;
    if (entry.count > 0) {
        maxAppsSegment = entry.data.u8[0] < 1 ? 1 :
                entry.data.u8[0] > 16 ? 16 : entry.data.u8[0];
    }
    return maxAppsSegment * (2 + 0xFFFF) + sizeof(CameraBlob);
}

void HeicCompositeStream::updateCodecQualityLocked(int32_t quality) {
    if (quality != mQuality) {
        sp<AMessage> qualityParams = new AMessage;
        qualityParams->setInt32(PARAMETER_KEY_VIDEO_BITRATE, quality);
        status_t res = mCodec->setParameters(qualityParams);
        if (res != OK) {
            ALOGE("%s: Failed to set codec quality: %s (%d)",
                    __FUNCTION__, strerror(-res), res);
        } else {
            mQuality = quality;
        }
    }
}

bool HeicCompositeStream::threadLoop() {
    int64_t frameNumber = -1;
    bool newInputAvailable = false;

    {
        Mutex::Autolock l(mMutex);
        if (mErrorState) {
            // In case we landed in error state, return any pending buffers and
            // halt all further processing.
            compilePendingInputLocked();
            releaseInputFramesLocked();
            return false;
        }


        while (!newInputAvailable) {
            compilePendingInputLocked();
            newInputAvailable = getNextReadyInputLocked(&frameNumber);

            if (!newInputAvailable) {
                auto failingFrameNumber = getNextFailingInputLocked();
                if (failingFrameNumber >= 0) {
                    releaseInputFrameLocked(failingFrameNumber,
                            &mPendingInputFrames[failingFrameNumber]);

                    // It's okay to remove the entry from mPendingInputFrames
                    // because:
                    // 1. Only one internal stream (main input) is critical in
                    // backing the output stream.
                    // 2. If captureResult/appSegment arrives after the entry is
                    // removed, they are simply skipped.
                    mPendingInputFrames.erase(failingFrameNumber);
                    if (mPendingInputFrames.size() == 0) {
                        if (mSettingsByFrameNumber.size() == 0) {
                            markTrackerIdle();
                        }
                    }
                    return true;
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

    auto res = processInputFrame(frameNumber, mPendingInputFrames[frameNumber]);
    Mutex::Autolock l(mMutex);
    if (res != OK) {
        ALOGE("%s: Failed processing frame with timestamp: %" PRIu64 ", frameNumber: %"
                PRId64 ": %s (%d)", __FUNCTION__, mPendingInputFrames[frameNumber].timestamp,
                frameNumber, strerror(-res), res);
        mPendingInputFrames[frameNumber].error = true;
    }

    releaseInputFramesLocked();

    return true;
}

void HeicCompositeStream::flagAnExifErrorFrameNumber(int64_t frameNumber) {
    Mutex::Autolock l(mMutex);
    mExifErrorFrameNumbers.emplace(frameNumber);
    mInputReadyCondition.signal();
}

bool HeicCompositeStream::onStreamBufferError(const CaptureResultExtras& resultExtras) {
    bool res = false;
    int64_t frameNumber = resultExtras.frameNumber;

    // Buffer errors concerning internal composite streams should not be directly visible to
    // camera clients. They must only receive a single buffer error with the public composite
    // stream id.
    if (resultExtras.errorStreamId == mAppSegmentStreamId) {
        ALOGV("%s: APP_SEGMENT frameNumber: %" PRId64, __FUNCTION__, frameNumber);
        flagAnExifErrorFrameNumber(frameNumber);
        res = true;
    } else if (resultExtras.errorStreamId == mMainImageStreamId) {
        ALOGV("%s: YUV frameNumber: %" PRId64, __FUNCTION__, frameNumber);
        flagAnErrorFrameNumber(frameNumber);
        res = true;
    }

    return res;
}

void HeicCompositeStream::onResultError(const CaptureResultExtras& resultExtras) {
    // For result error, since the APPS_SEGMENT buffer already contains EXIF,
    // simply skip using the capture result metadata to override EXIF.
    Mutex::Autolock l(mMutex);

    int64_t timestamp = -1;
    for (const auto& fn : mSettingsByFrameNumber) {
        if (fn.first == resultExtras.frameNumber) {
            timestamp = fn.second.timestamp;
            break;
        }
    }
    if (timestamp == -1) {
        for (const auto& inputFrame : mPendingInputFrames) {
            if (inputFrame.first == resultExtras.frameNumber) {
                timestamp = inputFrame.second.timestamp;
                break;
            }
        }
    }

    if (timestamp == -1) {
        ALOGE("%s: Failed to find shutter timestamp for result error!", __FUNCTION__);
        return;
    }

    mCaptureResults.emplace(timestamp, std::make_tuple(resultExtras.frameNumber, CameraMetadata()));
    ALOGV("%s: timestamp %" PRId64 ", frameNumber %" PRId64, __FUNCTION__,
            timestamp, resultExtras.frameNumber);
    mInputReadyCondition.signal();
}

void HeicCompositeStream::onRequestError(const CaptureResultExtras& resultExtras) {
    auto frameNumber = resultExtras.frameNumber;
    ALOGV("%s: frameNumber: %" PRId64, __FUNCTION__, frameNumber);
    Mutex::Autolock l(mMutex);
    auto numRequests = mSettingsByFrameNumber.erase(frameNumber);
    if (numRequests == 0) {
        // Pending request has been populated into mPendingInputFrames
        mErrorFrameNumbers.emplace(frameNumber);
        mInputReadyCondition.signal();
    } else {
        // REQUEST_ERROR was received without onShutter.
    }
}

void HeicCompositeStream::markTrackerIdle() {
    sp<StatusTracker> statusTracker = mStatusTracker.promote();
    if (statusTracker != nullptr) {
        statusTracker->markComponentIdle(mStatusId, Fence::NO_FENCE);
        ALOGV("%s: Mark component as idle", __FUNCTION__);
    }
}

void HeicCompositeStream::CodecCallbackHandler::onMessageReceived(const sp<AMessage> &msg) {
    sp<HeicCompositeStream> parent = mParent.promote();
    if (parent == nullptr) return;

    switch (msg->what()) {
        case kWhatCallbackNotify: {
             int32_t cbID;
             if (!msg->findInt32("callbackID", &cbID)) {
                 ALOGE("kWhatCallbackNotify: callbackID is expected.");
                 break;
             }

             ALOGV("kWhatCallbackNotify: cbID = %d", cbID);

             switch (cbID) {
                 case MediaCodec::CB_INPUT_AVAILABLE: {
                     int32_t index;
                     if (!msg->findInt32("index", &index)) {
                         ALOGE("CB_INPUT_AVAILABLE: index is expected.");
                         break;
                     }
                     parent->onHeicInputFrameAvailable(index, mIsGainmap);
                     break;
                 }

                 case MediaCodec::CB_OUTPUT_AVAILABLE: {
                     int32_t index;
                     size_t offset;
                     size_t size;
                     int64_t timeUs;
                     int32_t flags;

                     if (!msg->findInt32("index", &index)) {
                         ALOGE("CB_OUTPUT_AVAILABLE: index is expected.");
                         break;
                     }
                     if (!msg->findSize("offset", &offset)) {
                         ALOGE("CB_OUTPUT_AVAILABLE: offset is expected.");
                         break;
                     }
                     if (!msg->findSize("size", &size)) {
                         ALOGE("CB_OUTPUT_AVAILABLE: size is expected.");
                         break;
                     }
                     if (!msg->findInt64("timeUs", &timeUs)) {
                         ALOGE("CB_OUTPUT_AVAILABLE: timeUs is expected.");
                         break;
                     }
                     if (!msg->findInt32("flags", &flags)) {
                         ALOGE("CB_OUTPUT_AVAILABLE: flags is expected.");
                         break;
                     }

                     CodecOutputBufferInfo bufferInfo = {
                         index,
                         (int32_t)offset,
                         (int32_t)size,
                         timeUs,
                         (uint32_t)flags};

                     parent->onHeicOutputFrameAvailable(bufferInfo, mIsGainmap);
                     break;
                 }

                 case MediaCodec::CB_OUTPUT_FORMAT_CHANGED: {
                     sp<AMessage> format;
                     if (!msg->findMessage("format", &format)) {
                         ALOGE("CB_OUTPUT_FORMAT_CHANGED: format is expected.");
                         break;
                     }
                     // Here format is MediaCodec's internal copy of output format.
                     // Make a copy since onHeicFormatChanged() might modify it.
                     sp<AMessage> formatCopy;
                     if (format != nullptr) {
                         formatCopy = format->dup();
                     }
                     parent->onHeicFormatChanged(formatCopy, mIsGainmap);
                     break;
                 }

                 case MediaCodec::CB_ERROR: {
                     status_t err;
                     int32_t actionCode;
                     AString detail;
                     if (!msg->findInt32("err", &err)) {
                         ALOGE("CB_ERROR: err is expected.");
                         break;
                     }
                     if (!msg->findInt32("action", &actionCode)) {
                         ALOGE("CB_ERROR: action is expected.");
                         break;
                     }
                     msg->findString("detail", &detail);
                     ALOGE("Codec reported error(0x%x), actionCode(%d), detail(%s)",
                             err, actionCode, detail.c_str());

                     parent->onHeicCodecError();
                     break;
                 }

                 case MediaCodec::CB_METRICS_FLUSHED:
                 case MediaCodec::CB_REQUIRED_RESOURCES_CHANGED:
                 {
                    // Nothing to do. Informational. Safe to ignore.
                    break;
                 }

                 case MediaCodec::CB_CRYPTO_ERROR:
                 // unexpected as we are not using crypto
                 case MediaCodec::CB_LARGE_FRAME_OUTPUT_AVAILABLE:
                 // unexpected as we are not using large frames
                 default: {
                     ALOGE("kWhatCallbackNotify: callbackID(%d) is unexpected.", cbID);
                     break;
                 }
             }
             break;
        }

        default:
            ALOGE("shouldn't be here");
            break;
    }
}

}; // namespace camera3
}; // namespace android
