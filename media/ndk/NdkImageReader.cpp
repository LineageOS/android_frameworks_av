/*
 * Copyright (C) 2016 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "NdkImageReader"

#include "NdkImagePriv.h"
#include "NdkImageReaderPriv.h"

#include <cutils/atomic.h>
#include <utils/Log.h>
#include <android_media_Utils.h>
#include <android_runtime/android_view_Surface.h>
#include <android_runtime/android_hardware_HardwareBuffer.h>

using namespace android;

namespace {
    // Get an ID that's unique within this process.
    static int32_t createProcessUniqueId() {
        static volatile int32_t globalCounter = 0;
        return android_atomic_inc(&globalCounter);
    }
}

const int32_t AImageReader::kDefaultUsage = AHARDWAREBUFFER_USAGE0_CPU_READ_OFTEN;
const char* AImageReader::kCallbackFpKey = "Callback";
const char* AImageReader::kContextKey    = "Context";

bool
AImageReader::isSupportedFormat(int32_t format) {
    switch (format) {
        case AIMAGE_FORMAT_RGBA_8888:
        case AIMAGE_FORMAT_RGBX_8888:
        case AIMAGE_FORMAT_RGB_888:
        case AIMAGE_FORMAT_RGB_565:
        case AIMAGE_FORMAT_RGBA_FP16:
        case AIMAGE_FORMAT_YUV_420_888:
        case AIMAGE_FORMAT_JPEG:
        case AIMAGE_FORMAT_RAW16:
        case AIMAGE_FORMAT_RAW_PRIVATE:
        case AIMAGE_FORMAT_RAW10:
        case AIMAGE_FORMAT_RAW12:
        case AIMAGE_FORMAT_DEPTH16:
        case AIMAGE_FORMAT_DEPTH_POINT_CLOUD:
            return true;
        default:
            return false;
    }
}

int
AImageReader::getNumPlanesForFormat(int32_t format) {
    switch (format) {
        case AIMAGE_FORMAT_YUV_420_888:
            return 3;
        case AIMAGE_FORMAT_RGBA_8888:
        case AIMAGE_FORMAT_RGBX_8888:
        case AIMAGE_FORMAT_RGB_888:
        case AIMAGE_FORMAT_RGB_565:
        case AIMAGE_FORMAT_RGBA_FP16:
        case AIMAGE_FORMAT_JPEG:
        case AIMAGE_FORMAT_RAW16:
        case AIMAGE_FORMAT_RAW_PRIVATE:
        case AIMAGE_FORMAT_RAW10:
        case AIMAGE_FORMAT_RAW12:
        case AIMAGE_FORMAT_DEPTH16:
        case AIMAGE_FORMAT_DEPTH_POINT_CLOUD:
            return 1;
        default:
            return -1;
    }
}

void
AImageReader::FrameListener::onFrameAvailable(const BufferItem& /*item*/) {
    Mutex::Autolock _l(mLock);
    sp<AImageReader> reader = mReader.promote();
    if (reader == nullptr) {
        ALOGW("A frame is available after AImageReader closed!");
        return; // reader has been closed
    }
    if (mListener.onImageAvailable == nullptr) {
        return; // No callback registered
    }

    sp<AMessage> msg = new AMessage(AImageReader::kWhatImageAvailable, reader->mHandler);
    msg->setPointer(AImageReader::kCallbackFpKey, (void *) mListener.onImageAvailable);
    msg->setPointer(AImageReader::kContextKey, mListener.context);
    msg->post();
}

media_status_t
AImageReader::FrameListener::setImageListener(AImageReader_ImageListener* listener) {
    Mutex::Autolock _l(mLock);
    if (listener == nullptr) {
        mListener.context = nullptr;
        mListener.onImageAvailable = nullptr;
    } else {
        mListener = *listener;
    }
    return AMEDIA_OK;
}

media_status_t
AImageReader::setImageListenerLocked(AImageReader_ImageListener* listener) {
    return mFrameListener->setImageListener(listener);
}

media_status_t
AImageReader::setImageListener(AImageReader_ImageListener* listener) {
    Mutex::Autolock _l(mLock);
    return setImageListenerLocked(listener);
}

void AImageReader::CallbackHandler::onMessageReceived(
        const sp<AMessage> &msg) {
    switch (msg->what()) {
        case kWhatImageAvailable:
        {
            AImageReader_ImageCallback onImageAvailable;
            void* context;
            bool found = msg->findPointer(kCallbackFpKey, (void**) &onImageAvailable);
            if (!found || onImageAvailable == nullptr) {
                ALOGE("%s: Cannot find onImageAvailable callback fp!", __FUNCTION__);
                return;
            }
            found = msg->findPointer(kContextKey, &context);
            if (!found) {
                ALOGE("%s: Cannot find callback context!", __FUNCTION__);
                return;
            }
            (*onImageAvailable)(context, mReader);
            break;
        }
        default:
            ALOGE("%s: unknown message type %d", __FUNCTION__, msg->what());
            break;
    }
}

AImageReader::AImageReader(int32_t width,
                           int32_t height,
                           int32_t format,
                           uint64_t usage,
                           int32_t maxImages)
    : mWidth(width),
      mHeight(height),
      mFormat(format),
      mUsage(usage),
      mMaxImages(maxImages),
      mNumPlanes(getNumPlanesForFormat(format)),
      mFrameListener(new FrameListener(this)) {}

media_status_t
AImageReader::init() {
    PublicFormat publicFormat = static_cast<PublicFormat>(mFormat);
    mHalFormat = android_view_Surface_mapPublicFormatToHalFormat(publicFormat);
    mHalDataSpace = android_view_Surface_mapPublicFormatToHalDataspace(publicFormat);

    uint64_t producerUsage;
    uint64_t consumerUsage;
    android_hardware_HardwareBuffer_convertToGrallocUsageBits(
            &producerUsage, &consumerUsage, mUsage, 0);

    sp<IGraphicBufferProducer> gbProducer;
    sp<IGraphicBufferConsumer> gbConsumer;
    BufferQueue::createBufferQueue(&gbProducer, &gbConsumer);

    String8 consumerName = String8::format(
            "ImageReader-%dx%df%xu%" PRIu64 "m%d-%d-%d", mWidth, mHeight, mFormat, mUsage,
            mMaxImages, getpid(), createProcessUniqueId());

    mBufferItemConsumer =
            new BufferItemConsumer(gbConsumer, consumerUsage, mMaxImages, /*controlledByApp*/ true);
    if (mBufferItemConsumer == nullptr) {
        ALOGE("Failed to allocate BufferItemConsumer");
        return AMEDIA_ERROR_UNKNOWN;
    }

    mProducer = gbProducer;
    mBufferItemConsumer->setName(consumerName);
    mBufferItemConsumer->setFrameAvailableListener(mFrameListener);

    status_t res;
    res = mBufferItemConsumer->setDefaultBufferSize(mWidth, mHeight);
    if (res != OK) {
        ALOGE("Failed to set BufferItemConsumer buffer size");
        return AMEDIA_ERROR_UNKNOWN;
    }
    res = mBufferItemConsumer->setDefaultBufferFormat(mHalFormat);
    if (res != OK) {
        ALOGE("Failed to set BufferItemConsumer buffer format");
        return AMEDIA_ERROR_UNKNOWN;
    }
    res = mBufferItemConsumer->setDefaultBufferDataSpace(mHalDataSpace);
    if (res != OK) {
        ALOGE("Failed to set BufferItemConsumer buffer dataSpace");
        return AMEDIA_ERROR_UNKNOWN;
    }

    mSurface = new Surface(mProducer, /*controlledByApp*/true);
    if (mSurface == nullptr) {
        ALOGE("Failed to create surface");
        return AMEDIA_ERROR_UNKNOWN;
    }
    mWindow = static_cast<ANativeWindow*>(mSurface.get());

    for (int i = 0; i < mMaxImages; i++) {
        BufferItem* buffer = new BufferItem;
        mBuffers.push_back(buffer);
    }

    mCbLooper = new ALooper;
    mCbLooper->setName(consumerName.string());
    res = mCbLooper->start(
            /*runOnCallingThread*/false,
            /*canCallJava*/       true,
            PRIORITY_DEFAULT);
    if (res != OK) {
        ALOGE("Failed to start the looper");
        return AMEDIA_ERROR_UNKNOWN;
    }
    mHandler = new CallbackHandler(this);
    mCbLooper->registerHandler(mHandler);

    return AMEDIA_OK;
}

AImageReader::~AImageReader() {
    Mutex::Autolock _l(mLock);
    AImageReader_ImageListener nullListener = {nullptr, nullptr};
    setImageListenerLocked(&nullListener);

    if (mCbLooper != nullptr) {
        mCbLooper->unregisterHandler(mHandler->id());
        mCbLooper->stop();
    }
    mCbLooper.clear();
    mHandler.clear();

    // Close all previously acquired images
    for (auto it = mAcquiredImages.begin();
              it != mAcquiredImages.end(); it++) {
        AImage* image = *it;
        image->close();
    }

    // Delete Buffer Items
    for (auto it = mBuffers.begin();
              it != mBuffers.end(); it++) {
        delete *it;
    }

    if (mBufferItemConsumer != nullptr) {
        mBufferItemConsumer->abandon();
        mBufferItemConsumer->setFrameAvailableListener(nullptr);
    }
}

media_status_t
AImageReader::acquireImageLocked(/*out*/AImage** image) {
    *image = nullptr;
    BufferItem* buffer = getBufferItemLocked();
    if (buffer == nullptr) {
        ALOGW("Unable to acquire a lockedBuffer, very likely client tries to lock more than"
            " maxImages buffers");
        return AMEDIA_IMGREADER_MAX_IMAGES_ACQUIRED;
    }

    status_t res = mBufferItemConsumer->acquireBuffer(buffer, 0);
    if (res != NO_ERROR) {
        returnBufferItemLocked(buffer);
        if (res != BufferQueue::NO_BUFFER_AVAILABLE) {
            if (res == INVALID_OPERATION) {
                return AMEDIA_IMGREADER_MAX_IMAGES_ACQUIRED;
            } else {
                ALOGE("%s: Acquire image failed with some unknown error: %s (%d)",
                      __FUNCTION__, strerror(-res), res);
                return AMEDIA_ERROR_UNKNOWN;
            }
        }
        return AMEDIA_IMGREADER_NO_BUFFER_AVAILABLE;
    }

    const int bufferWidth = getBufferWidth(buffer);
    const int bufferHeight = getBufferHeight(buffer);
    const int bufferFmt = buffer->mGraphicBuffer->getPixelFormat();

    const int readerWidth = mWidth;
    const int readerHeight = mHeight;
    const int readerFmt = mHalFormat;

    // Check if the producer buffer configurations match what AImageReader configured. Add some
    // extra checks for non-opaque formats.
    if (!isFormatOpaque(readerFmt)) {
        // Check if the left-top corner of the crop rect is origin, we currently assume this point
        // is zero, will revisit this once this assumption turns out problematic.
        Point lt = buffer->mCrop.leftTop();
        if (lt.x != 0 || lt.y != 0) {
            ALOGE("Crop left top corner [%d, %d] not at origin", lt.x, lt.y);
            return AMEDIA_ERROR_UNKNOWN;
        }

        // Check if the producer buffer configurations match what ImageReader configured.
        if ((bufferFmt != HAL_PIXEL_FORMAT_BLOB) && (readerFmt != HAL_PIXEL_FORMAT_BLOB) &&
                (readerWidth != bufferWidth || readerHeight != bufferHeight)) {
            ALOGW("%s: Buffer size: %dx%d, doesn't match AImageReader configured size: %dx%d",
                    __FUNCTION__, bufferWidth, bufferHeight, readerWidth, readerHeight);
        }

        if (readerFmt != bufferFmt) {
            if (readerFmt == HAL_PIXEL_FORMAT_YCbCr_420_888 && isPossiblyYUV(bufferFmt)) {
                // Special casing for when producer switches to a format compatible with flexible
                // YUV.
                mHalFormat = bufferFmt;
                ALOGD("%s: Overriding buffer format YUV_420_888 to 0x%x.", __FUNCTION__, bufferFmt);
            } else {
                // Return the buffer to the queue. No need to provide fence, as this buffer wasn't
                // used anywhere yet.
                mBufferItemConsumer->releaseBuffer(*buffer);
                returnBufferItemLocked(buffer);

                ALOGE("%s: Output buffer format: 0x%x, ImageReader configured format: 0x%x",
                        __FUNCTION__, bufferFmt, readerFmt);

                return AMEDIA_ERROR_UNKNOWN;
            }
        }
    }

    if (mHalFormat == HAL_PIXEL_FORMAT_BLOB) {
        *image = new AImage(this, mFormat, mUsage, buffer, buffer->mTimestamp,
                            readerWidth, readerHeight, mNumPlanes);
    } else {
        *image = new AImage(this, mFormat, mUsage, buffer, buffer->mTimestamp,
                            bufferWidth, bufferHeight, mNumPlanes);
    }
    mAcquiredImages.push_back(*image);
    return AMEDIA_OK;
}

BufferItem*
AImageReader::getBufferItemLocked() {
    if (mBuffers.empty()) {
        return nullptr;
    }
    // Return a BufferItem pointer and remove it from the list
    auto it = mBuffers.begin();
    BufferItem* buffer = *it;
    mBuffers.erase(it);
    return buffer;
}

void
AImageReader::returnBufferItemLocked(BufferItem* buffer) {
    mBuffers.push_back(buffer);
}

void
AImageReader::releaseImageLocked(AImage* image) {
    BufferItem* buffer = image->mBuffer;
    if (buffer == nullptr) {
        // This should not happen, but is not fatal
        ALOGW("AImage %p has no buffer!", image);
        return;
    }

    int fenceFd = -1;
    media_status_t ret = image->unlockImageIfLocked(&fenceFd);
    if (ret < 0) {
        ALOGW("%s: AImage %p is cannot be unlocked.", __FUNCTION__, image);
        return;
    }

    sp<Fence> releaseFence = fenceFd > 0 ? new Fence(fenceFd) : Fence::NO_FENCE;
    mBufferItemConsumer->releaseBuffer(*buffer, releaseFence);
    returnBufferItemLocked(buffer);
    image->mBuffer = nullptr;

    bool found = false;
    // cleanup acquired image list
    for (auto it = mAcquiredImages.begin();
              it != mAcquiredImages.end(); it++) {
        AImage* readerCopy = *it;
        if (readerCopy == image) {
            found = true;
            mAcquiredImages.erase(it);
            break;
        }
    }
    if (!found) {
        ALOGE("Error: AImage %p is not generated by AImageReader %p",
                image, this);
    }
}

int
AImageReader::getBufferWidth(BufferItem* buffer) {
    if (buffer == NULL) return -1;

    if (!buffer->mCrop.isEmpty()) {
        return buffer->mCrop.getWidth();
    }

    return buffer->mGraphicBuffer->getWidth();
}

int
AImageReader::getBufferHeight(BufferItem* buffer) {
    if (buffer == NULL) return -1;

    if (!buffer->mCrop.isEmpty()) {
        return buffer->mCrop.getHeight();
    }

    return buffer->mGraphicBuffer->getHeight();
}

media_status_t
AImageReader::acquireNextImage(/*out*/AImage** image) {
    Mutex::Autolock _l(mLock);
    return acquireImageLocked(image);
}

media_status_t
AImageReader::acquireLatestImage(/*out*/AImage** image) {
    if (image == nullptr) {
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    Mutex::Autolock _l(mLock);
    *image = nullptr;
    AImage* prevImage = nullptr;
    AImage* nextImage = nullptr;
    media_status_t ret = acquireImageLocked(&prevImage);
    if (prevImage == nullptr) {
        return ret;
    }
    for (;;) {
        ret = acquireImageLocked(&nextImage);
        if (nextImage == nullptr) {
            *image = prevImage;
            return AMEDIA_OK;
        }
        prevImage->close();
        prevImage->free();
        prevImage = nextImage;
        nextImage = nullptr;
    }
}

EXPORT
media_status_t AImageReader_new(
        int32_t width, int32_t height, int32_t format, int32_t maxImages,
        /*out*/AImageReader** reader) {
    ALOGV("%s", __FUNCTION__);

    if (width < 1 || height < 1) {
        ALOGE("%s: image dimension must be positive: w:%d h:%d",
                __FUNCTION__, width, height);
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    if (maxImages < 1) {
        ALOGE("%s: max outstanding image count must be at least 1 (%d)",
                __FUNCTION__, maxImages);
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    if (maxImages > BufferQueueDefs::NUM_BUFFER_SLOTS) {
        ALOGE("%s: max outstanding image count (%d) cannot be larget than %d.",
              __FUNCTION__, maxImages, BufferQueueDefs::NUM_BUFFER_SLOTS);
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    if (!AImageReader::isSupportedFormat(format)) {
        ALOGE("%s: format %d is not supported by AImageReader",
                __FUNCTION__, format);
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    if (reader == nullptr) {
        ALOGE("%s: reader argument is null", __FUNCTION__);
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    // Set consumer usage to AHARDWAREBUFFER_USAGE0_CPU_READ_OFTEN by default so that
    // AImageReader_new behaves as if it's backed by CpuConsumer.
    AImageReader* tmpReader = new AImageReader(
        width, height, format, AImageReader::kDefaultUsage, maxImages);
    if (tmpReader == nullptr) {
        ALOGE("%s: AImageReader allocation failed", __FUNCTION__);
        return AMEDIA_ERROR_UNKNOWN;
    }
    media_status_t ret = tmpReader->init();
    if (ret != AMEDIA_OK) {
        ALOGE("%s: AImageReader initialization failed!", __FUNCTION__);
        delete tmpReader;
        return ret;
    }
    *reader = tmpReader;
    (*reader)->incStrong((void*) AImageReader_new);
    return AMEDIA_OK;
}

EXPORT
void AImageReader_delete(AImageReader* reader) {
    ALOGV("%s", __FUNCTION__);
    if (reader != nullptr) {
        reader->decStrong((void*) AImageReader_delete);
    }
    return;
}

EXPORT
media_status_t AImageReader_getWindow(AImageReader* reader, /*out*/ANativeWindow** window) {
    ALOGE("%s", __FUNCTION__);
    if (reader == nullptr || window == nullptr) {
        ALOGE("%s: invalid argument. reader %p, window %p",
                __FUNCTION__, reader, window);
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    *window = reader->getWindow();
    return AMEDIA_OK;
}

EXPORT
media_status_t AImageReader_getWidth(const AImageReader* reader, /*out*/int32_t* width) {
    ALOGV("%s", __FUNCTION__);
    if (reader == nullptr || width == nullptr) {
        ALOGE("%s: invalid argument. reader %p, width %p",
                __FUNCTION__, reader, width);
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    *width = reader->getWidth();
    return AMEDIA_OK;
}

EXPORT
media_status_t AImageReader_getHeight(const AImageReader* reader, /*out*/int32_t* height) {
    ALOGV("%s", __FUNCTION__);
    if (reader == nullptr || height == nullptr) {
        ALOGE("%s: invalid argument. reader %p, height %p",
                __FUNCTION__, reader, height);
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    *height = reader->getHeight();
    return AMEDIA_OK;
}

EXPORT
media_status_t AImageReader_getFormat(const AImageReader* reader, /*out*/int32_t* format) {
    ALOGV("%s", __FUNCTION__);
    if (reader == nullptr || format == nullptr) {
        ALOGE("%s: invalid argument. reader %p, format %p",
                __FUNCTION__, reader, format);
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    *format = reader->getFormat();
    return AMEDIA_OK;
}

EXPORT
media_status_t AImageReader_getMaxImages(const AImageReader* reader, /*out*/int32_t* maxImages) {
    ALOGV("%s", __FUNCTION__);
    if (reader == nullptr || maxImages == nullptr) {
        ALOGE("%s: invalid argument. reader %p, maxImages %p",
                __FUNCTION__, reader, maxImages);
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    *maxImages = reader->getMaxImages();
    return AMEDIA_OK;
}

EXPORT
media_status_t AImageReader_acquireNextImage(AImageReader* reader, /*out*/AImage** image) {
    ALOGV("%s", __FUNCTION__);
    if (reader == nullptr || image == nullptr) {
        ALOGE("%s: invalid argument. reader %p, image %p",
                __FUNCTION__, reader, image);
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    return reader->acquireNextImage(image);
}

EXPORT
media_status_t AImageReader_acquireLatestImage(AImageReader* reader, /*out*/AImage** image) {
    ALOGV("%s", __FUNCTION__);
    if (reader == nullptr || image == nullptr) {
        ALOGE("%s: invalid argument. reader %p, image %p",
                __FUNCTION__, reader, image);
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    return reader->acquireLatestImage(image);
}

EXPORT
media_status_t AImageReader_setImageListener(
        AImageReader* reader, AImageReader_ImageListener* listener) {
    ALOGV("%s", __FUNCTION__);
    if (reader == nullptr) {
        ALOGE("%s: invalid argument! reader %p", __FUNCTION__, reader);
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    reader->setImageListener(listener);
    return AMEDIA_OK;
}
