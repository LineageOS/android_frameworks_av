/*
 * Copyright (C) 2017 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "HeifDecoderImpl"

#include "HeifDecoderImpl.h"

#include <stdio.h>

#include <binder/IMemory.h>
#include <drm/drm_framework_common.h>
#include <media/IDataSource.h>
#include <media/mediametadataretriever.h>
#include <media/stagefright/MediaSource.h>
#include <private/media/VideoFrame.h>
#include <utils/Log.h>
#include <utils/RefBase.h>

HeifDecoder* createHeifDecoder() {
    return new android::HeifDecoderImpl();
}

namespace android {

/*
 * HeifDataSource
 *
 * Proxies data requests over IDataSource interface from MediaMetadataRetriever
 * to the HeifStream interface we received from the heif decoder client.
 */
class HeifDataSource : public BnDataSource {
public:
    /*
     * Constructs HeifDataSource; will take ownership of |stream|.
     */
    HeifDataSource(HeifStream* stream)
        : mStream(stream), mReadPos(0), mEOS(false) {}

    ~HeifDataSource() override {}

    /*
     * Initializes internal resources.
     */
    bool init();

    sp<IMemory> getIMemory() override { return mMemory; }
    ssize_t readAt(off64_t offset, size_t size) override;
    status_t getSize(off64_t* size) override ;
    void close() {}
    uint32_t getFlags() override { return 0; }
    String8 toString() override { return String8("HeifDataSource"); }
    sp<DecryptHandle> DrmInitialization(const char*) override {
        return nullptr;
    }

private:
    /*
     * Buffer size for passing the read data to mediaserver. Set to 64K
     * (which is what MediaDataSource Java API's jni implementation uses).
     */
    enum {
        kBufferSize = 64 * 1024,
    };
    sp<IMemory> mMemory;
    std::unique_ptr<HeifStream> mStream;
    off64_t mReadPos;
    bool mEOS;
};

bool HeifDataSource::init() {
    sp<MemoryDealer> memoryDealer =
            new MemoryDealer(kBufferSize, "HeifDataSource");
    mMemory = memoryDealer->allocate(kBufferSize);
    if (mMemory == nullptr) {
        ALOGE("Failed to allocate shared memory!");
        return false;
    }
    return true;
}

ssize_t HeifDataSource::readAt(off64_t offset, size_t size) {
    ALOGV("readAt: offset=%lld, size=%zu", (long long)offset, size);

    if (size == 0) {
        return mEOS ? ERROR_END_OF_STREAM : 0;
    }

    if (offset < mReadPos) {
        // try seek, then rewind/skip, fail if none worked
        if (mStream->seek(offset)) {
            ALOGV("readAt: seek to offset=%lld", (long long)offset);
            mReadPos = offset;
            mEOS = false;
        } else if (mStream->rewind()) {
            ALOGV("readAt: rewind to offset=0");
            mReadPos = 0;
            mEOS = false;
        } else {
            ALOGE("readAt: couldn't seek or rewind!");
            mEOS = true;
        }
    }

    if (mEOS) {
        ALOGV("readAt: EOS");
        return ERROR_END_OF_STREAM;
    }

    if (offset > mReadPos) {
        // skipping
        size_t skipSize = offset - mReadPos;
        size_t bytesSkipped = mStream->read(nullptr, skipSize);
        if (bytesSkipped <= skipSize) {
            mReadPos += bytesSkipped;
        }
        if (bytesSkipped != skipSize) {
            mEOS = true;
            return ERROR_END_OF_STREAM;
        }
    }

    if (size > kBufferSize) {
        size = kBufferSize;
    }
    size_t bytesRead = mStream->read(mMemory->pointer(), size);
    if (bytesRead > size || bytesRead == 0) {
        // bytesRead is invalid
        mEOS = true;
        return ERROR_END_OF_STREAM;
    } if (bytesRead < size) {
        // read some bytes but not all, set EOS and return ERROR_END_OF_STREAM next time
        mEOS = true;
    }
    mReadPos += bytesRead;
    return bytesRead;
}

status_t HeifDataSource::getSize(off64_t* size) {
    if (!mStream->hasLength()) {
        *size = -1;
        ALOGE("getSize: not supported!");
        return ERROR_UNSUPPORTED;
    }
    *size = mStream->getLength();
    ALOGV("getSize: size=%lld", (long long)*size);
    return OK;
}

/////////////////////////////////////////////////////////////////////////

HeifDecoderImpl::HeifDecoderImpl() :
    // output color format should always be set via setOutputColor(), in case
    // it's not, default to HAL_PIXEL_FORMAT_RGB_565.
    mOutputColor(HAL_PIXEL_FORMAT_RGB_565),
    mCurScanline(0) {
}

HeifDecoderImpl::~HeifDecoderImpl() {
}

bool HeifDecoderImpl::init(HeifStream* stream, HeifFrameInfo* frameInfo) {
    sp<HeifDataSource> dataSource = new HeifDataSource(stream);
    if (!dataSource->init()) {
        return false;
    }
    mDataSource = dataSource;

    mRetriever = new MediaMetadataRetriever();
    status_t err = mRetriever->setDataSource(mDataSource, "video/mp4");
    if (err != OK) {
        ALOGE("failed to set data source!");

        mRetriever.clear();
        mDataSource.clear();
        return false;
    }
    ALOGV("successfully set data source.");

    const char* hasVideo = mRetriever->extractMetadata(METADATA_KEY_HAS_VIDEO);
    if (!hasVideo || strcasecmp(hasVideo, "yes")) {
        ALOGE("no video: %s", hasVideo ? hasVideo : "null");
        return false;
    }

    mFrameMemory = mRetriever->getFrameAtTime(0,
            IMediaSource::ReadOptions::SEEK_PREVIOUS_SYNC,
            mOutputColor, true /*metaOnly*/);
    if (mFrameMemory == nullptr || mFrameMemory->pointer() == nullptr) {
        ALOGE("getFrameAtTime: videoFrame is a nullptr");
        return false;
    }

    VideoFrame* videoFrame = static_cast<VideoFrame*>(mFrameMemory->pointer());

    ALOGV("Meta dimension %dx%d, display %dx%d, angle %d, iccSize %d",
            videoFrame->mWidth,
            videoFrame->mHeight,
            videoFrame->mDisplayWidth,
            videoFrame->mDisplayHeight,
            videoFrame->mRotationAngle,
            videoFrame->mIccSize);

    if (frameInfo != nullptr) {
        frameInfo->set(
                videoFrame->mWidth,
                videoFrame->mHeight,
                videoFrame->mRotationAngle,
                videoFrame->mBytesPerPixel,
                videoFrame->mIccSize,
                videoFrame->getFlattenedIccData());
    }
    return true;
}

bool HeifDecoderImpl::getEncodedColor(HeifEncodedColor* /*outColor*/) const {
    ALOGW("getEncodedColor: not implemented!");
    return false;
}

bool HeifDecoderImpl::setOutputColor(HeifColorFormat heifColor) {
    switch(heifColor) {
        case kHeifColorFormat_RGB565:
        {
            mOutputColor = HAL_PIXEL_FORMAT_RGB_565;
            return true;
        }
        case kHeifColorFormat_RGBA_8888:
        {
            mOutputColor = HAL_PIXEL_FORMAT_RGBA_8888;
            return true;
        }
        case kHeifColorFormat_BGRA_8888:
        {
            mOutputColor = HAL_PIXEL_FORMAT_BGRA_8888;
            return true;
        }
        default:
            break;
    }
    ALOGE("Unsupported output color format %d", heifColor);
    return false;
}

bool HeifDecoderImpl::decode(HeifFrameInfo* frameInfo) {
    mFrameMemory = mRetriever->getFrameAtTime(0,
            IMediaSource::ReadOptions::SEEK_PREVIOUS_SYNC, mOutputColor);
    if (mFrameMemory == nullptr || mFrameMemory->pointer() == nullptr) {
        ALOGE("getFrameAtTime: videoFrame is a nullptr");
        return false;
    }

    VideoFrame* videoFrame = static_cast<VideoFrame*>(mFrameMemory->pointer());
    ALOGV("Decoded dimension %dx%d, display %dx%d, angle %d, rowbytes %d, size %d",
            videoFrame->mWidth,
            videoFrame->mHeight,
            videoFrame->mDisplayWidth,
            videoFrame->mDisplayHeight,
            videoFrame->mRotationAngle,
            videoFrame->mRowBytes,
            videoFrame->mSize);

    if (frameInfo != nullptr) {
        frameInfo->set(
                videoFrame->mWidth,
                videoFrame->mHeight,
                videoFrame->mRotationAngle,
                videoFrame->mBytesPerPixel,
                videoFrame->mIccSize,
                videoFrame->getFlattenedIccData());
    }
    return true;
}

bool HeifDecoderImpl::getScanline(uint8_t* dst) {
    if (mFrameMemory == nullptr || mFrameMemory->pointer() == nullptr) {
        return false;
    }
    VideoFrame* videoFrame = static_cast<VideoFrame*>(mFrameMemory->pointer());
    if (mCurScanline >= videoFrame->mHeight) {
        return false;
    }
    uint8_t* src = videoFrame->getFlattenedData() + videoFrame->mRowBytes * mCurScanline++;
    memcpy(dst, src, videoFrame->mBytesPerPixel * videoFrame->mWidth);
    return true;
}

size_t HeifDecoderImpl::skipScanlines(size_t count) {
    if (mFrameMemory == nullptr || mFrameMemory->pointer() == nullptr) {
        return 0;
    }
    VideoFrame* videoFrame = static_cast<VideoFrame*>(mFrameMemory->pointer());

    uint32_t oldScanline = mCurScanline;
    mCurScanline += count;
    if (mCurScanline >= videoFrame->mHeight) {
        mCurScanline = videoFrame->mHeight;
    }
    return (mCurScanline > oldScanline) ? (mCurScanline - oldScanline) : 0;
}

} // namespace android
