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

#define LOG_TAG "Camera3-DepthCompositeStream"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0

#include "api1/client2/JpegProcessor.h"
#include "common/CameraProviderManager.h"

#include <dynamic_depth/camera.h>
#include <dynamic_depth/cameras.h>
#include <dynamic_depth/container.h>
#include <dynamic_depth/device.h>
#include <dynamic_depth/dimension.h>
#include <dynamic_depth/dynamic_depth.h>
#include <dynamic_depth/point.h>
#include <dynamic_depth/pose.h>
#include <dynamic_depth/profile.h>
#include <dynamic_depth/profiles.h>
#include <xmpmeta/xmp_data.h>
#include <xmpmeta/xmp_writer.h>

#include <jpeglib.h>
#include <math.h>

#include <gui/Surface.h>
#include <utils/Log.h>
#include <utils/Trace.h>

#include "DepthCompositeStream.h"

using dynamic_depth::Camera;
using dynamic_depth::Cameras;
using dynamic_depth::CameraParams;
using dynamic_depth::Container;
using dynamic_depth::DepthFormat;
using dynamic_depth::DepthMapParams;
using dynamic_depth::DepthUnits;
using dynamic_depth::Device;
using dynamic_depth::DeviceParams;
using dynamic_depth::Dimension;
using dynamic_depth::Image;
using dynamic_depth::ImagingModelParams;
using dynamic_depth::Pose;
using dynamic_depth::Profile;
using dynamic_depth::Profiles;

namespace android {
namespace camera3 {

DepthCompositeStream::DepthCompositeStream(wp<CameraDeviceBase> device,
        wp<hardware::camera2::ICameraDeviceCallbacks> cb) :
        CompositeStream(device, cb),
        mBlobStreamId(-1),
        mBlobSurfaceId(-1),
        mDepthStreamId(-1),
        mDepthSurfaceId(-1),
        mBlobWidth(0),
        mBlobHeight(0),
        mDepthBufferAcquired(false),
        mBlobBufferAcquired(false),
        mProducerListener(new ProducerListener()),
        mMaxJpegSize(-1),
        mIsLogicalCamera(false) {
    sp<CameraDeviceBase> cameraDevice = device.promote();
    if (cameraDevice.get() != nullptr) {
        CameraMetadata staticInfo = cameraDevice->info();
        auto entry = staticInfo.find(ANDROID_JPEG_MAX_SIZE);
        if (entry.count > 0) {
            mMaxJpegSize = entry.data.i32[0];
        } else {
            ALOGW("%s: Maximum jpeg size absent from camera characteristics", __FUNCTION__);
        }

        entry = staticInfo.find(ANDROID_LENS_INTRINSIC_CALIBRATION);
        if (entry.count == 5) {
            mInstrinsicCalibration.reserve(5);
            mInstrinsicCalibration.insert(mInstrinsicCalibration.end(), entry.data.f,
                    entry.data.f + 5);
        } else {
            ALOGW("%s: Intrinsic calibration absent from camera characteristics!", __FUNCTION__);
        }

        entry = staticInfo.find(ANDROID_LENS_DISTORTION);
        if (entry.count == 5) {
            mLensDistortion.reserve(5);
            mLensDistortion.insert(mLensDistortion.end(), entry.data.f, entry.data.f + 5);
        } else {
            ALOGW("%s: Lens distortion absent from camera characteristics!", __FUNCTION__);
        }

        entry = staticInfo.find(ANDROID_REQUEST_AVAILABLE_CAPABILITIES);
        for (size_t i = 0; i < entry.count; ++i) {
            uint8_t capability = entry.data.u8[i];
            if (capability == ANDROID_REQUEST_AVAILABLE_CAPABILITIES_LOGICAL_MULTI_CAMERA) {
                mIsLogicalCamera = true;
                break;
            }
        }

        getSupportedDepthSizes(staticInfo, &mSupportedDepthSizes);
    }
}

DepthCompositeStream::~DepthCompositeStream() {
    mBlobConsumer.clear(),
    mBlobSurface.clear(),
    mBlobStreamId = -1;
    mBlobSurfaceId = -1;
    mDepthConsumer.clear();
    mDepthSurface.clear();
    mDepthConsumer = nullptr;
    mDepthSurface = nullptr;
}

void DepthCompositeStream::compilePendingInputLocked() {
    CpuConsumer::LockedBuffer imgBuffer;

    while (!mInputJpegBuffers.empty() && !mBlobBufferAcquired) {
        auto it = mInputJpegBuffers.begin();
        auto res = mBlobConsumer->lockNextBuffer(&imgBuffer);
        if (res == NOT_ENOUGH_DATA) {
            // Can not lock any more buffers.
            break;
        } else if (res != OK) {
            ALOGE("%s: Error locking blob image buffer: %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            mPendingInputFrames[*it].error = true;
            mInputDepthBuffers.erase(it);
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

    while (!mInputDepthBuffers.empty() && !mDepthBufferAcquired) {
        auto it = mInputDepthBuffers.begin();
        auto res = mDepthConsumer->lockNextBuffer(&imgBuffer);
        if (res == NOT_ENOUGH_DATA) {
            // Can not lock any more buffers.
            break;
        } else if (res != OK) {
            ALOGE("%s: Error receiving depth image buffer: %s (%d)", __FUNCTION__,
                    strerror(-res), res);
            mPendingInputFrames[*it].error = true;
            mInputDepthBuffers.erase(it);
            continue;
        }

        if (*it != imgBuffer.timestamp) {
            ALOGW("%s: Expecting depth buffer with time stamp: %" PRId64 " received buffer with "
                    "time stamp: %" PRId64, __FUNCTION__, *it, imgBuffer.timestamp);
        }

        if ((mPendingInputFrames.find(imgBuffer.timestamp) != mPendingInputFrames.end()) &&
                (mPendingInputFrames[imgBuffer.timestamp].error)) {
            mDepthConsumer->unlockBuffer(imgBuffer);
        } else {
            mPendingInputFrames[imgBuffer.timestamp].depthBuffer = imgBuffer;
            mDepthBufferAcquired = true;
        }
        mInputDepthBuffers.erase(it);
    }

    while (!mCaptureResults.empty()) {
        auto it = mCaptureResults.begin();
        // Negative timestamp indicates that something went wrong during the capture result
        // collection process.
        if (it->first >= 0) {
            mPendingInputFrames[it->first].frameNumber = std::get<0>(it->second);
            mPendingInputFrames[it->first].result = std::get<1>(it->second);
        }
        mCaptureResults.erase(it);
    }

    while (!mFrameNumberMap.empty()) {
        auto it = mFrameNumberMap.begin();
        mPendingInputFrames[it->second].frameNumber = it->first;
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
            it = mErrorFrameNumbers.erase(it);
        } else {
            ALOGW("%s: Not able to find failing input with frame number: %" PRId64, __FUNCTION__,
                    *it);
            it++;
        }
    }
}

bool DepthCompositeStream::getNextReadyInputLocked(int64_t *currentTs /*inout*/) {
    if (currentTs == nullptr) {
        return false;
    }

    bool newInputAvailable = false;
    for (const auto& it : mPendingInputFrames) {
        if ((!it.second.error) && (it.second.depthBuffer.data != nullptr) &&
                (it.second.jpegBuffer.data != nullptr) && (it.first < *currentTs)) {
            *currentTs = it.first;
            newInputAvailable = true;
        }
    }

    return newInputAvailable;
}

int64_t DepthCompositeStream::getNextFailingInputLocked(int64_t *currentTs /*inout*/) {
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

status_t DepthCompositeStream::encodeGrayscaleJpeg(size_t width, size_t height, uint8_t *in,
        void *out, const size_t maxOutSize, uint8_t jpegQuality, size_t &actualSize) {
    status_t ret;
    // libjpeg is a C library so we use C-style "inheritance" by
    // putting libjpeg's jpeg_destination_mgr first in our custom
    // struct. This allows us to cast jpeg_destination_mgr* to
    // CustomJpegDestMgr* when we get it passed to us in a callback.
    struct CustomJpegDestMgr : public jpeg_destination_mgr {
        JOCTET *mBuffer;
        size_t mBufferSize;
        size_t mEncodedSize;
        bool mSuccess;
    } dmgr;

    jpeg_compress_struct cinfo = {};
    jpeg_error_mgr jerr;

    // Initialize error handling with standard callbacks, but
    // then override output_message (to print to ALOG) and
    // error_exit to set a flag and print a message instead
    // of killing the whole process.
    cinfo.err = jpeg_std_error(&jerr);

    cinfo.err->output_message = [](j_common_ptr cinfo) {
        char buffer[JMSG_LENGTH_MAX];

        /* Create the message */
        (*cinfo->err->format_message)(cinfo, buffer);
        ALOGE("libjpeg error: %s", buffer);
    };

    cinfo.err->error_exit = [](j_common_ptr cinfo) {
        (*cinfo->err->output_message)(cinfo);
        if(cinfo->client_data) {
            auto & dmgr = *static_cast<CustomJpegDestMgr*>(cinfo->client_data);
            dmgr.mSuccess = false;
        }
    };

    // Now that we initialized some callbacks, let's create our compressor
    jpeg_create_compress(&cinfo);
    dmgr.mBuffer = static_cast<JOCTET*>(out);
    dmgr.mBufferSize = maxOutSize;
    dmgr.mEncodedSize = 0;
    dmgr.mSuccess = true;
    cinfo.client_data = static_cast<void*>(&dmgr);

    // These lambdas become C-style function pointers and as per C++11 spec
    // may not capture anything.
    dmgr.init_destination = [](j_compress_ptr cinfo) {
        auto & dmgr = static_cast<CustomJpegDestMgr&>(*cinfo->dest);
        dmgr.next_output_byte = dmgr.mBuffer;
        dmgr.free_in_buffer = dmgr.mBufferSize;
        ALOGV("%s:%d jpeg start: %p [%zu]",
              __FUNCTION__, __LINE__, dmgr.mBuffer, dmgr.mBufferSize);
    };

    dmgr.empty_output_buffer = [](j_compress_ptr cinfo __unused) {
        ALOGV("%s:%d Out of buffer", __FUNCTION__, __LINE__);
        return 0;
    };

    dmgr.term_destination = [](j_compress_ptr cinfo) {
        auto & dmgr = static_cast<CustomJpegDestMgr&>(*cinfo->dest);
        dmgr.mEncodedSize = dmgr.mBufferSize - dmgr.free_in_buffer;
        ALOGV("%s:%d Done with jpeg: %zu", __FUNCTION__, __LINE__, dmgr.mEncodedSize);
    };
    cinfo.dest = reinterpret_cast<struct jpeg_destination_mgr*>(&dmgr);
    cinfo.image_width = width;
    cinfo.image_height = height;
    cinfo.input_components = 1;
    cinfo.in_color_space = JCS_GRAYSCALE;

    // Initialize defaults and then override what we want
    jpeg_set_defaults(&cinfo);

    jpeg_set_quality(&cinfo, jpegQuality, 1);
    jpeg_set_colorspace(&cinfo, JCS_GRAYSCALE);
    cinfo.raw_data_in = 0;
    cinfo.dct_method = JDCT_IFAST;

    cinfo.comp_info[0].h_samp_factor = 1;
    cinfo.comp_info[1].h_samp_factor = 1;
    cinfo.comp_info[2].h_samp_factor = 1;
    cinfo.comp_info[0].v_samp_factor = 1;
    cinfo.comp_info[1].v_samp_factor = 1;
    cinfo.comp_info[2].v_samp_factor = 1;

    jpeg_start_compress(&cinfo, TRUE);

    for (size_t i = 0; i < cinfo.image_height; i++) {
        auto currentRow  = static_cast<JSAMPROW>(in + i*width);
        jpeg_write_scanlines(&cinfo, &currentRow, /*num_lines*/1);
    }

    jpeg_finish_compress(&cinfo);

    actualSize = dmgr.mEncodedSize;
    if (dmgr.mSuccess) {
        ret = NO_ERROR;
    } else {
        ret = UNKNOWN_ERROR;
    }

    return ret;
}

std::unique_ptr<DepthMap> DepthCompositeStream::processDepthMapFrame(
        const CpuConsumer::LockedBuffer &depthMapBuffer, size_t maxJpegSize, uint8_t jpegQuality,
        std::vector<std::unique_ptr<Item>> *items /*out*/) {
    std::vector<float> points, confidence;

    size_t pointCount = depthMapBuffer.width * depthMapBuffer.height;
    points.reserve(pointCount);
    confidence.reserve(pointCount);
    float near = UINT16_MAX;
    float far = .0f;
    uint16_t *data = reinterpret_cast<uint16_t *> (depthMapBuffer.data);
    for (size_t i = 0; i < depthMapBuffer.height; i++) {
        for (size_t j = 0; j < depthMapBuffer.width; j++) {
            // Android densely packed depth map. The units for the range are in
            // millimeters and need to be scaled to meters.
            // The confidence value is encoded in the 3 most significant bits.
            // The confidence data needs to be additionally normalized with
            // values 1.0f, 0.0f representing maximum and minimum confidence
            // respectively.
            auto value = data[i*depthMapBuffer.stride + j];
            auto point = static_cast<float>(value & 0x1FFF) / 1000.f;
            points.push_back(point);

            auto conf = (value >> 13) & 0x7;
            float normConfidence = (conf == 0) ? 1.f : (static_cast<float>(conf) - 1) / 7.f;
            confidence.push_back(normConfidence);

            if (near > point) {
                near = point;
            }
            if (far < point) {
                far = point;
            }
        }
    }

    if (near == far) {
        ALOGE("%s: Near and far range values must not match!", __FUNCTION__);
        return nullptr;
    }

    std::vector<uint8_t> pointsQuantized, confidenceQuantized;
    pointsQuantized.reserve(pointCount); confidenceQuantized.reserve(pointCount);
    auto pointIt = points.begin();
    auto confidenceIt = confidence.begin();
    while ((pointIt != points.end()) && (confidenceIt != confidence.end())) {
        pointsQuantized.push_back(floorf(((far * (*pointIt - near)) /
                (*pointIt * (far - near))) * 255.0f));
        confidenceQuantized.push_back(floorf(*confidenceIt * 255.0f));
        confidenceIt++; pointIt++;
    }

    DepthMapParams depthParams(DepthFormat::kRangeInverse, near, far, DepthUnits::kMeters,
            "android/depthmap");
    depthParams.confidence_uri = "android/confidencemap";
    depthParams.mime = "image/jpeg";
    depthParams.depth_image_data.resize(maxJpegSize);
    depthParams.confidence_data.resize(maxJpegSize);
    size_t actualJpegSize;
    auto ret = encodeGrayscaleJpeg(depthMapBuffer.width, depthMapBuffer.height,
            pointsQuantized.data(), depthParams.depth_image_data.data(), maxJpegSize, jpegQuality,
            actualJpegSize);
    if (ret != NO_ERROR) {
        ALOGE("%s: Depth map compression failed!", __FUNCTION__);
        return nullptr;
    }
    depthParams.depth_image_data.resize(actualJpegSize);

    ret = encodeGrayscaleJpeg(depthMapBuffer.width, depthMapBuffer.height,
            confidenceQuantized.data(), depthParams.confidence_data.data(), maxJpegSize,
            jpegQuality, actualJpegSize);
    if (ret != NO_ERROR) {
        ALOGE("%s: Confidence map compression failed!", __FUNCTION__);
        return nullptr;
    }
    depthParams.confidence_data.resize(actualJpegSize);

    return DepthMap::FromData(depthParams, items);
}

status_t DepthCompositeStream::processInputFrame(const InputFrame &inputFrame) {
    status_t res;
    sp<ANativeWindow> outputANW = mOutputSurface;
    ANativeWindowBuffer *anb;
    int fenceFd;
    void *dstBuffer;
    auto imgBuffer = inputFrame.jpegBuffer;

    auto jpegSize = android::camera2::JpegProcessor::findJpegSize(inputFrame.jpegBuffer.data,
            inputFrame.jpegBuffer.width);
    if (jpegSize == 0) {
        ALOGW("%s: Failed to find input jpeg size, default to using entire buffer!", __FUNCTION__);
        jpegSize = inputFrame.jpegBuffer.width;
    }

    std::vector<std::unique_ptr<Item>> items;
    std::vector<std::unique_ptr<Camera>> cameraList;
    auto image = Image::FromDataForPrimaryImage("android/mainimage", &items);
    std::unique_ptr<CameraParams> cameraParams(new CameraParams(std::move(image)));
    if (cameraParams == nullptr) {
        ALOGE("%s: Failed to initialize camera parameters", __FUNCTION__);
        return BAD_VALUE;
    }

    size_t maxDepthJpegSize;
    if (mMaxJpegSize > 0) {
        maxDepthJpegSize = mMaxJpegSize;
    } else {
        maxDepthJpegSize = std::max<size_t> (jpegSize,
                inputFrame.depthBuffer.width * inputFrame.depthBuffer.height * 3 / 2);
    }
    uint8_t jpegQuality = 100;
    auto entry = inputFrame.result.find(ANDROID_JPEG_QUALITY);
    if (entry.count > 0) {
        jpegQuality = entry.data.u8[0];
    }
    cameraParams->depth_map = processDepthMapFrame(inputFrame.depthBuffer, maxDepthJpegSize,
            jpegQuality, &items);
    if (cameraParams->depth_map == nullptr) {
        ALOGE("%s: Depth map processing failed!", __FUNCTION__);
        return BAD_VALUE;
    }
    cameraParams->imaging_model = getImagingModel();

    if (mIsLogicalCamera) {
        cameraParams->trait = dynamic_depth::CameraTrait::LOGICAL;
    } else {
        cameraParams->trait = dynamic_depth::CameraTrait::PHYSICAL;
    }

    cameraList.emplace_back(Camera::FromData(std::move(cameraParams)));

    auto deviceParams = std::make_unique<DeviceParams> (Cameras::FromCameraArray(&cameraList));
    deviceParams->container = Container::FromItems(&items);
    std::vector<std::unique_ptr<Profile>> profileList;
    profileList.emplace_back(Profile::FromData("DepthPhoto", {0}));
    deviceParams->profiles = Profiles::FromProfileArray(&profileList);
    std::unique_ptr<Device> device = Device::FromData(std::move(deviceParams));
    if (device == nullptr) {
        ALOGE("%s: Failed to initialize camera device", __FUNCTION__);
        return BAD_VALUE;
    }

    std::istringstream inputJpegStream(std::string(reinterpret_cast<const char *> (imgBuffer.data),
            jpegSize));
    std::ostringstream outputJpegStream;
    if (!WriteImageAndMetadataAndContainer(&inputJpegStream, device.get(), &outputJpegStream)) {
        ALOGE("%s: Failed writing depth output", __FUNCTION__);
        return BAD_VALUE;
    }

    size_t finalJpegSize = static_cast<size_t> (outputJpegStream.tellp()) +
            sizeof(struct camera3_jpeg_blob);

    ALOGV("%s: Final jpeg size: %zu", __func__, finalJpegSize);
    if ((res = native_window_set_buffers_dimensions(mOutputSurface.get(), finalJpegSize, 1))
            != OK) {
        ALOGE("%s: Unable to configure stream buffer dimensions"
                " %zux%u for stream %d", __FUNCTION__, finalJpegSize, 1U, mBlobStreamId);
        return res;
    }

    res = outputANW->dequeueBuffer(mOutputSurface.get(), &anb, &fenceFd);
    if (res != OK) {
        ALOGE("%s: Error retrieving output buffer: %s (%d)", __FUNCTION__, strerror(-res),
                res);
        return res;
    }

    sp<GraphicBuffer> gb = GraphicBuffer::from(anb);
    res = gb->lockAsync(GRALLOC_USAGE_SW_WRITE_OFTEN, &dstBuffer, fenceFd);
    if (res != OK) {
        ALOGE("%s: Error trying to lock output buffer fence: %s (%d)", __FUNCTION__,
                strerror(-res), res);
        outputANW->cancelBuffer(mOutputSurface.get(), anb, /*fence*/ -1);
        return res;
    }

    if ((gb->getWidth() < finalJpegSize) || (gb->getHeight() != 1)) {
        ALOGE("%s: Blob buffer size mismatch, expected %dx%d received %zux%u", __FUNCTION__,
                gb->getWidth(), gb->getHeight(), finalJpegSize, 1U);
        outputANW->cancelBuffer(mOutputSurface.get(), anb, /*fence*/ -1);
        return BAD_VALUE;
    }

    // Copy final jpeg with embedded depth data in the composite stream output buffer
    uint8_t* header = static_cast<uint8_t *> (dstBuffer) +
        (gb->getWidth() - sizeof(struct camera3_jpeg_blob));
    struct camera3_jpeg_blob *blob = reinterpret_cast<struct camera3_jpeg_blob*> (header);
    blob->jpeg_blob_id = CAMERA3_JPEG_BLOB_ID;
    blob->jpeg_size = static_cast<uint32_t> (outputJpegStream.tellp());
    memcpy(dstBuffer, outputJpegStream.str().c_str(), blob->jpeg_size);
    outputANW->queueBuffer(mOutputSurface.get(), anb, /*fence*/ -1);

    return res;
}

void DepthCompositeStream::releaseInputFrameLocked(InputFrame *inputFrame /*out*/) {
    if (inputFrame == nullptr) {
        return;
    }

    if (inputFrame->depthBuffer.data != nullptr) {
        mDepthConsumer->unlockBuffer(inputFrame->depthBuffer);
        inputFrame->depthBuffer.data = nullptr;
        mDepthBufferAcquired = false;
    }

    if (inputFrame->jpegBuffer.data != nullptr) {
        mBlobConsumer->unlockBuffer(inputFrame->jpegBuffer);
        inputFrame->jpegBuffer.data = nullptr;
        mBlobBufferAcquired = false;
    }

    if ((inputFrame->error || mErrorState) && !inputFrame->errorNotified) {
        notifyError(inputFrame->frameNumber);
        inputFrame->errorNotified = true;
    }
}

void DepthCompositeStream::releaseInputFramesLocked(int64_t currentTs) {
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

bool DepthCompositeStream::threadLoop() {
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

    auto res = processInputFrame(mPendingInputFrames[currentTs]);
    Mutex::Autolock l(mMutex);
    if (res != OK) {
        ALOGE("%s: Failed processing frame with timestamp: %" PRIu64 ": %s (%d)", __FUNCTION__,
                currentTs, strerror(-res), res);
        mPendingInputFrames[currentTs].error = true;
    }

    releaseInputFramesLocked(currentTs);

    return true;
}

bool DepthCompositeStream::isDepthCompositeStream(const sp<Surface> &surface) {
    ANativeWindow *anw = surface.get();
    status_t err;
    int format;
    if ((err = anw->query(anw, NATIVE_WINDOW_FORMAT, &format)) != OK) {
        String8 msg = String8::format("Failed to query Surface format: %s (%d)", strerror(-err),
                err);
        ALOGE("%s: %s", __FUNCTION__, msg.string());
        return false;
    }

    int dataspace;
    if ((err = anw->query(anw, NATIVE_WINDOW_DEFAULT_DATASPACE, &dataspace)) != OK) {
        String8 msg = String8::format("Failed to query Surface dataspace: %s (%d)", strerror(-err),
                err);
        ALOGE("%s: %s", __FUNCTION__, msg.string());
        return false;
    }

    if ((format == HAL_PIXEL_FORMAT_BLOB) && (dataspace == HAL_DATASPACE_DYNAMIC_DEPTH)) {
        return true;
    }

    return false;
}

status_t DepthCompositeStream::createInternalStreams(const std::vector<sp<Surface>>& consumers,
        bool /*hasDeferredConsumer*/, uint32_t width, uint32_t height, int format,
        camera3_stream_rotation_t rotation, int *id, const String8& physicalCameraId,
        std::vector<int> *surfaceIds, int /*streamSetId*/, bool /*isShared*/) {
    if (mSupportedDepthSizes.empty()) {
        ALOGE("%s: This camera device doesn't support any depth map streams!", __FUNCTION__);
        return INVALID_OPERATION;
    }

    size_t depthWidth, depthHeight;
    auto ret = getMatchingDepthSize(width, height, mSupportedDepthSizes, &depthWidth, &depthHeight);
    if (ret != OK) {
        ALOGE("%s: Failed to find an appropriate depth stream size!", __FUNCTION__);
        return ret;
    }

    sp<CameraDeviceBase> device = mDevice.promote();
    if (!device.get()) {
        ALOGE("%s: Invalid camera device!", __FUNCTION__);
        return NO_INIT;
    }

    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);
    mBlobConsumer = new CpuConsumer(consumer, /*maxLockedBuffers*/1, /*controlledByApp*/ true);
    mBlobConsumer->setFrameAvailableListener(this);
    mBlobConsumer->setName(String8("Camera3-JpegCompositeStream"));
    mBlobSurface = new Surface(producer);

    ret = device->createStream(mBlobSurface, width, height, format, kJpegDataSpace, rotation,
            id, physicalCameraId, surfaceIds);
    if (ret == OK) {
        mBlobStreamId = *id;
        mBlobSurfaceId = (*surfaceIds)[0];
        mOutputSurface = consumers[0];
    } else {
        return ret;
    }

    BufferQueue::createBufferQueue(&producer, &consumer);
    mDepthConsumer = new CpuConsumer(consumer, /*maxLockedBuffers*/ 1, /*controlledByApp*/ true);
    mDepthConsumer->setFrameAvailableListener(this);
    mDepthConsumer->setName(String8("Camera3-DepthCompositeStream"));
    mDepthSurface = new Surface(producer);
    std::vector<int> depthSurfaceId;
    ret = device->createStream(mDepthSurface, depthWidth, depthHeight, kDepthMapPixelFormat,
            kDepthMapDataSpace, rotation, &mDepthStreamId, physicalCameraId, &depthSurfaceId);
    if (ret == OK) {
        mDepthSurfaceId = depthSurfaceId[0];
    } else {
        return ret;
    }

    ret = registerCompositeStreamListener(getStreamId());
    if (ret != OK) {
        ALOGE("%s: Failed to register blob stream listener!", __FUNCTION__);
        return ret;
    }

    ret = registerCompositeStreamListener(mDepthStreamId);
    if (ret != OK) {
        ALOGE("%s: Failed to register depth stream listener!", __FUNCTION__);
        return ret;
    }

    mBlobWidth = width;
    mBlobHeight = height;

    return ret;
}

status_t DepthCompositeStream::configureStream() {
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
                __FUNCTION__, mBlobStreamId);
        return res;
    }

    if ((res = native_window_set_buffers_format(mOutputSurface.get(), HAL_PIXEL_FORMAT_BLOB))
            != OK) {
        ALOGE("%s: Unable to configure stream buffer format for stream %d", __FUNCTION__,
                mBlobStreamId);
        return res;
    }

    int maxProducerBuffers;
    ANativeWindow *anw = mBlobSurface.get();
    if ((res = anw->query(anw, NATIVE_WINDOW_MIN_UNDEQUEUED_BUFFERS, &maxProducerBuffers)) != OK) {
        ALOGE("%s: Unable to query consumer undequeued"
                " buffer count for stream %d", __FUNCTION__, mBlobStreamId);
        return res;
    }

    ANativeWindow *anwConsumer = mOutputSurface.get();
    int maxConsumerBuffers;
    if ((res = anwConsumer->query(anwConsumer, NATIVE_WINDOW_MIN_UNDEQUEUED_BUFFERS,
                    &maxConsumerBuffers)) != OK) {
        ALOGE("%s: Unable to query consumer undequeued"
                " buffer count for stream %d", __FUNCTION__, mBlobStreamId);
        return res;
    }

    if ((res = native_window_set_buffer_count(
                    anwConsumer, maxProducerBuffers + maxConsumerBuffers)) != OK) {
        ALOGE("%s: Unable to set buffer count for stream %d", __FUNCTION__, mBlobStreamId);
        return res;
    }

    run("DepthCompositeStreamProc");

    return NO_ERROR;
}

status_t DepthCompositeStream::deleteInternalStreams() {
    // The 'CameraDeviceClient' parent will delete the blob stream
    requestExit();

    auto ret = join();
    if (ret != OK) {
        ALOGE("%s: Failed to join with the main processing thread: %s (%d)", __FUNCTION__,
                strerror(-ret), ret);
    }

    sp<CameraDeviceBase> device = mDevice.promote();
    if (!device.get()) {
        ALOGE("%s: Invalid camera device!", __FUNCTION__);
        return NO_INIT;
    }

    if (mDepthStreamId >= 0) {
        ret = device->deleteStream(mDepthStreamId);
        mDepthStreamId = -1;
    }

    return ret;
}

void DepthCompositeStream::onFrameAvailable(const BufferItem& item) {
    if (item.mDataSpace == kJpegDataSpace) {
        ALOGV("%s: Jpeg buffer with ts: %" PRIu64 " ms. arrived!",
                __func__, ns2ms(item.mTimestamp));

        Mutex::Autolock l(mMutex);
        if (!mErrorState) {
            mInputJpegBuffers.push_back(item.mTimestamp);
            mInputReadyCondition.signal();
        }
    } else if (item.mDataSpace == kDepthMapDataSpace) {
        ALOGV("%s: Depth buffer with ts: %" PRIu64 " ms. arrived!", __func__,
                ns2ms(item.mTimestamp));

        Mutex::Autolock l(mMutex);
        if (!mErrorState) {
            mInputDepthBuffers.push_back(item.mTimestamp);
            mInputReadyCondition.signal();
        }
    } else {
        ALOGE("%s: Unexpected data space: 0x%x", __FUNCTION__, item.mDataSpace);
    }
}

status_t DepthCompositeStream::insertGbp(SurfaceMap* /*out*/outSurfaceMap,
        Vector<int32_t> * /*out*/outputStreamIds, int32_t* /*out*/currentStreamId) {
    if (outSurfaceMap->find(mDepthStreamId) == outSurfaceMap->end()) {
        (*outSurfaceMap)[mDepthStreamId] = std::vector<size_t>();
        outputStreamIds->push_back(mDepthStreamId);
    }
    (*outSurfaceMap)[mDepthStreamId].push_back(mDepthSurfaceId);

    if (outSurfaceMap->find(mBlobStreamId) == outSurfaceMap->end()) {
        (*outSurfaceMap)[mBlobStreamId] = std::vector<size_t>();
        outputStreamIds->push_back(mBlobStreamId);
    }
    (*outSurfaceMap)[mBlobStreamId].push_back(mBlobSurfaceId);

    if (currentStreamId != nullptr) {
        *currentStreamId = mBlobStreamId;
    }

    return NO_ERROR;
}

void DepthCompositeStream::onResultError(const CaptureResultExtras& resultExtras) {
    // Processing can continue even in case of result errors.
    // At the moment depth composite stream processing relies mainly on static camera
    // characteristics data. The actual result data can be used for the jpeg quality but
    // in case it is absent we can default to maximum.
    eraseResult(resultExtras.frameNumber);
}

bool DepthCompositeStream::onStreamBufferError(const CaptureResultExtras& resultExtras) {
    bool ret = false;
    // Buffer errors concerning internal composite streams should not be directly visible to
    // camera clients. They must only receive a single buffer error with the public composite
    // stream id.
    if ((resultExtras.errorStreamId == mDepthStreamId) ||
            (resultExtras.errorStreamId == mBlobStreamId)) {
        flagAnErrorFrameNumber(resultExtras.frameNumber);
        ret = true;
    }

    return ret;
}

status_t DepthCompositeStream::getMatchingDepthSize(size_t width, size_t height,
        const std::vector<std::tuple<size_t, size_t>>& supporedDepthSizes,
        size_t *depthWidth /*out*/, size_t *depthHeight /*out*/) {
    if ((depthWidth == nullptr) || (depthHeight == nullptr)) {
        return BAD_VALUE;
    }

    float arTol = CameraProviderManager::kDepthARTolerance;
    *depthWidth = *depthHeight = 0;

    float aspectRatio = static_cast<float> (width) / static_cast<float> (height);
    for (const auto& it : supporedDepthSizes) {
        auto currentWidth = std::get<0>(it);
        auto currentHeight = std::get<1>(it);
        if ((currentWidth == width) && (currentHeight == height)) {
            *depthWidth = width;
            *depthHeight = height;
            break;
        } else {
            float currentRatio = static_cast<float> (currentWidth) /
                    static_cast<float> (currentHeight);
            auto currentSize = currentWidth * currentHeight;
            auto oldSize = (*depthWidth) * (*depthHeight);
            if ((fabs(aspectRatio - currentRatio) <= arTol) && (currentSize > oldSize)) {
                *depthWidth = currentWidth;
                *depthHeight = currentHeight;
            }
        }
    }

    return ((*depthWidth > 0) && (*depthHeight > 0)) ? OK : BAD_VALUE;
}

void DepthCompositeStream::getSupportedDepthSizes(const CameraMetadata& ch,
        std::vector<std::tuple<size_t, size_t>>* depthSizes /*out*/) {
    if (depthSizes == nullptr) {
        return;
    }

    auto entry = ch.find(ANDROID_DEPTH_AVAILABLE_DEPTH_STREAM_CONFIGURATIONS);
    if (entry.count > 0) {
        // Depth stream dimensions have four int32_t components
        // (pixelformat, width, height, type)
        size_t entryCount = entry.count / 4;
        depthSizes->reserve(entryCount);
        for (size_t i = 0; i < entry.count; i += 4) {
            if ((entry.data.i32[i] == kDepthMapPixelFormat) &&
                    (entry.data.i32[i+3] ==
                     ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT)) {
                depthSizes->push_back(std::make_tuple(entry.data.i32[i+1],
                            entry.data.i32[i+2]));
            }
        }
    }
}

status_t DepthCompositeStream::getCompositeStreamInfo(const OutputStreamInfo &streamInfo,
            const CameraMetadata& ch, std::vector<OutputStreamInfo>* compositeOutput /*out*/) {
    if (compositeOutput == nullptr) {
        return BAD_VALUE;
    }

    std::vector<std::tuple<size_t, size_t>> depthSizes;
    getSupportedDepthSizes(ch, &depthSizes);
    if (depthSizes.empty()) {
        ALOGE("%s: No depth stream configurations present", __FUNCTION__);
        return BAD_VALUE;
    }

    size_t depthWidth, depthHeight;
    auto ret = getMatchingDepthSize(streamInfo.width, streamInfo.height, depthSizes, &depthWidth,
            &depthHeight);
    if (ret != OK) {
        ALOGE("%s: No matching depth stream size found", __FUNCTION__);
        return ret;
    }

    compositeOutput->clear();
    compositeOutput->insert(compositeOutput->end(), 2, streamInfo);

    // Jpeg/Blob stream info
    (*compositeOutput)[0].dataSpace = kJpegDataSpace;
    (*compositeOutput)[0].consumerUsage = GRALLOC_USAGE_SW_READ_OFTEN;

    // Depth stream info
    (*compositeOutput)[1].width = depthWidth;
    (*compositeOutput)[1].height = depthHeight;
    (*compositeOutput)[1].format = kDepthMapPixelFormat;
    (*compositeOutput)[1].dataSpace = kDepthMapDataSpace;
    (*compositeOutput)[1].consumerUsage = GRALLOC_USAGE_SW_READ_OFTEN;

    return NO_ERROR;
}

std::unique_ptr<ImagingModel> DepthCompositeStream::getImagingModel() {
    // It is not possible to generate an imaging model without instrinsic calibration.
    if (mInstrinsicCalibration.empty() || mInstrinsicCalibration.size() != 5) {
        return nullptr;
    }

    // The camera intrinsic calibration layout is as follows:
    // [focalLengthX, focalLengthY, opticalCenterX, opticalCenterY, skew]
    const dynamic_depth::Point<double> focalLength(mInstrinsicCalibration[0],
            mInstrinsicCalibration[1]);
    const Dimension imageSize(mBlobWidth, mBlobHeight);
    ImagingModelParams params(focalLength, imageSize);
    params.principal_point.x = mInstrinsicCalibration[2];
    params.principal_point.y = mInstrinsicCalibration[3];
    params.skew = mInstrinsicCalibration[4];

    // The camera lens distortion contains the following lens correction coefficients.
    // [kappa_1, kappa_2, kappa_3 kappa_4, kappa_5]
    if (mLensDistortion.size() == 5) {
        // According to specification the lens distortion coefficients should be ordered
        // as [1, kappa_4, kappa_1, kappa_5, kappa_2, 0, kappa_3, 0]
        float distortionData[] = {1.f, mLensDistortion[3], mLensDistortion[0], mLensDistortion[4],
            mLensDistortion[1], 0.f, mLensDistortion[2], 0.f};
        auto distortionDataLength = sizeof(distortionData) / sizeof(distortionData[0]);
        params.distortion.reserve(distortionDataLength);
        params.distortion.insert(params.distortion.end(), distortionData,
                distortionData + distortionDataLength);
    }

    return ImagingModel::FromData(params);
}

}; // namespace camera3
}; // namespace android
