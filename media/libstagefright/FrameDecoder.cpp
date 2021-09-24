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
#define LOG_TAG "FrameDecoder"

#include "include/FrameDecoder.h"
#include "include/FrameCaptureLayer.h"
#include "include/HevcUtils.h"
#include <binder/MemoryBase.h>
#include <binder/MemoryHeapBase.h>
#include <gui/Surface.h>
#include <inttypes.h>
#include <mediadrm/ICrypto.h>
#include <media/IMediaSource.h>
#include <media/MediaCodecBuffer.h>
#include <media/stagefright/foundation/avc_utils.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/ColorUtils.h>
#include <media/stagefright/ColorConverter.h>
#include <media/stagefright/FrameCaptureProcessor.h>
#include <media/stagefright/MediaBuffer.h>
#include <media/stagefright/MediaCodec.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/Utils.h>
#include <private/media/VideoFrame.h>
#include <utils/Log.h>

namespace android {

static const int64_t kBufferTimeOutUs = 10000LL; // 10 msec
static const size_t kRetryCount = 100; // must be >0
static const int64_t kDefaultSampleDurationUs = 33333LL; // 33ms

sp<IMemory> allocVideoFrame(const sp<MetaData>& trackMeta,
        int32_t width, int32_t height, int32_t tileWidth, int32_t tileHeight,
        int32_t dstBpp, bool allocRotated, bool metaOnly) {
    int32_t rotationAngle;
    if (!trackMeta->findInt32(kKeyRotation, &rotationAngle)) {
        rotationAngle = 0;  // By default, no rotation
    }
    uint32_t type;
    const void *iccData;
    size_t iccSize;
    if (!trackMeta->findData(kKeyIccProfile, &type, &iccData, &iccSize)){
        iccData = NULL;
        iccSize = 0;
    }

    int32_t sarWidth, sarHeight;
    int32_t displayWidth, displayHeight;
    if (trackMeta->findInt32(kKeySARWidth, &sarWidth)
            && trackMeta->findInt32(kKeySARHeight, &sarHeight)
            && sarHeight != 0) {
        int32_t multVal;
        if (width < 0 || sarWidth < 0 ||
            __builtin_mul_overflow(width, sarWidth, &multVal)) {
            ALOGE("displayWidth overflow %dx%d", width, sarWidth);
            return NULL;
        }
        displayWidth = (width * sarWidth) / sarHeight;
        displayHeight = height;
    } else if (trackMeta->findInt32(kKeyDisplayWidth, &displayWidth)
                && trackMeta->findInt32(kKeyDisplayHeight, &displayHeight)
                && displayWidth > 0 && displayHeight > 0
                && width > 0 && height > 0) {
        ALOGV("found display size %dx%d", displayWidth, displayHeight);
    } else {
        displayWidth = width;
        displayHeight = height;
    }

    if (allocRotated && (rotationAngle == 90 || rotationAngle == 270)) {
        int32_t tmp;
        tmp = width; width = height; height = tmp;
        tmp = displayWidth; displayWidth = displayHeight; displayHeight = tmp;
        tmp = tileWidth; tileWidth = tileHeight; tileHeight = tmp;
        rotationAngle = 0;
    }

    if (!metaOnly) {
        int32_t multVal;
        if (width < 0 || height < 0 || dstBpp < 0 ||
            __builtin_mul_overflow(dstBpp, width, &multVal) ||
            __builtin_mul_overflow(multVal, height, &multVal)) {
            ALOGE("Frame size overflow %dx%d bpp %d", width, height, dstBpp);
            return NULL;
        }
    }

    VideoFrame frame(width, height, displayWidth, displayHeight,
            tileWidth, tileHeight, rotationAngle, dstBpp, !metaOnly, iccSize);

    size_t size = frame.getFlattenedSize();
    sp<MemoryHeapBase> heap = new MemoryHeapBase(size, 0, "MetadataRetrieverClient");
    if (heap == NULL) {
        ALOGE("failed to create MemoryDealer");
        return NULL;
    }
    sp<IMemory> frameMem = new MemoryBase(heap, 0, size);
    if (frameMem == NULL || frameMem->unsecurePointer() == NULL) {
        ALOGE("not enough memory for VideoFrame size=%zu", size);
        return NULL;
    }
    VideoFrame* frameCopy = static_cast<VideoFrame*>(frameMem->unsecurePointer());
    frameCopy->init(frame, iccData, iccSize);

    return frameMem;
}

sp<IMemory> allocVideoFrame(const sp<MetaData>& trackMeta,
        int32_t width, int32_t height, int32_t tileWidth, int32_t tileHeight,
        int32_t dstBpp, bool allocRotated = false) {
    return allocVideoFrame(trackMeta, width, height, tileWidth, tileHeight, dstBpp,
            allocRotated, false /*metaOnly*/);
}

sp<IMemory> allocMetaFrame(const sp<MetaData>& trackMeta,
        int32_t width, int32_t height, int32_t tileWidth, int32_t tileHeight,
        int32_t dstBpp) {
    return allocVideoFrame(trackMeta, width, height, tileWidth, tileHeight, dstBpp,
            false /*allocRotated*/, true /*metaOnly*/);
}

bool isAvif(const sp<MetaData> &trackMeta) {
    const char *mime;
    return trackMeta->findCString(kKeyMIMEType, &mime)
        && (!strcasecmp(mime, MEDIA_MIMETYPE_VIDEO_AV1)
            || !strcasecmp(mime, MEDIA_MIMETYPE_IMAGE_AVIF));
}

bool findThumbnailInfo(
        const sp<MetaData> &trackMeta, int32_t *width, int32_t *height,
        uint32_t *type = NULL, const void **data = NULL, size_t *size = NULL) {
    uint32_t dummyType;
    const void *dummyData;
    size_t dummySize;
    int codecConfigKey = isAvif(trackMeta) ? kKeyThumbnailAV1C : kKeyThumbnailHVCC;
    return trackMeta->findInt32(kKeyThumbnailWidth, width)
        && trackMeta->findInt32(kKeyThumbnailHeight, height)
        && trackMeta->findData(codecConfigKey,
                type ?: &dummyType, data ?: &dummyData, size ?: &dummySize);
}

bool findGridInfo(const sp<MetaData> &trackMeta,
        int32_t *tileWidth, int32_t *tileHeight, int32_t *gridRows, int32_t *gridCols) {
    return trackMeta->findInt32(kKeyTileWidth, tileWidth) && (*tileWidth > 0)
        && trackMeta->findInt32(kKeyTileHeight, tileHeight) && (*tileHeight > 0)
        && trackMeta->findInt32(kKeyGridRows, gridRows) && (*gridRows > 0)
        && trackMeta->findInt32(kKeyGridCols, gridCols) && (*gridCols > 0);
}

bool getDstColorFormat(
        android_pixel_format_t colorFormat,
        OMX_COLOR_FORMATTYPE *dstFormat,
        ui::PixelFormat *captureFormat,
        int32_t *dstBpp) {
    switch (colorFormat) {
        case HAL_PIXEL_FORMAT_RGB_565:
        {
            *dstFormat = OMX_COLOR_Format16bitRGB565;
            *captureFormat = ui::PixelFormat::RGB_565;
            *dstBpp = 2;
            return true;
        }
        case HAL_PIXEL_FORMAT_RGBA_8888:
        {
            *dstFormat = OMX_COLOR_Format32BitRGBA8888;
            *captureFormat = ui::PixelFormat::RGBA_8888;
            *dstBpp = 4;
            return true;
        }
        case HAL_PIXEL_FORMAT_BGRA_8888:
        {
            *dstFormat = OMX_COLOR_Format32bitBGRA8888;
            *captureFormat = ui::PixelFormat::BGRA_8888;
            *dstBpp = 4;
            return true;
        }
        default:
        {
            ALOGE("Unsupported color format: %d", colorFormat);
            break;
        }
    }
    return false;
}

//static
sp<IMemory> FrameDecoder::getMetadataOnly(
        const sp<MetaData> &trackMeta, int colorFormat, bool thumbnail) {
    OMX_COLOR_FORMATTYPE dstFormat;
    ui::PixelFormat captureFormat;
    int32_t dstBpp;
    if (!getDstColorFormat((android_pixel_format_t)colorFormat,
            &dstFormat, &captureFormat, &dstBpp)) {
        return NULL;
    }

    int32_t width, height, tileWidth = 0, tileHeight = 0;
    if (thumbnail) {
        if (!findThumbnailInfo(trackMeta, &width, &height)) {
            return NULL;
        }
    } else {
        CHECK(trackMeta->findInt32(kKeyWidth, &width));
        CHECK(trackMeta->findInt32(kKeyHeight, &height));

        int32_t gridRows, gridCols;
        if (!findGridInfo(trackMeta, &tileWidth, &tileHeight, &gridRows, &gridCols)) {
            tileWidth = tileHeight = 0;
        }
    }

    sp<IMemory> metaMem = allocMetaFrame(trackMeta, width, height, tileWidth, tileHeight, dstBpp);

    // try to fill sequence meta's duration based on average frame rate,
    // default to 33ms if frame rate is unavailable.
    int32_t frameRate;
    VideoFrame* meta = static_cast<VideoFrame*>(metaMem->unsecurePointer());
    if (trackMeta->findInt32(kKeyFrameRate, &frameRate) && frameRate > 0) {
        meta->mDurationUs = 1000000LL / frameRate;
    } else {
        meta->mDurationUs = kDefaultSampleDurationUs;
    }
    return metaMem;
}

FrameDecoder::FrameDecoder(
        const AString &componentName,
        const sp<MetaData> &trackMeta,
        const sp<IMediaSource> &source)
    : mComponentName(componentName),
      mTrackMeta(trackMeta),
      mSource(source),
      mDstFormat(OMX_COLOR_Format16bitRGB565),
      mDstBpp(2),
      mHaveMoreInputs(true),
      mFirstSample(true) {
}

FrameDecoder::~FrameDecoder() {
    if (mDecoder != NULL) {
        mDecoder->release();
        mSource->stop();
    }
}

bool isHDR(const sp<AMessage> &format) {
    uint32_t standard, range, transfer;
    if (!format->findInt32("color-standard", (int32_t*)&standard)) {
        standard = 0;
    }
    if (!format->findInt32("color-range", (int32_t*)&range)) {
        range = 0;
    }
    if (!format->findInt32("color-transfer", (int32_t*)&transfer)) {
        transfer = 0;
    }
    return standard == ColorUtils::kColorStandardBT2020 &&
            (transfer == ColorUtils::kColorTransferST2084 ||
            transfer == ColorUtils::kColorTransferHLG);
}

status_t FrameDecoder::init(
        int64_t frameTimeUs, int option, int colorFormat) {
    if (!getDstColorFormat((android_pixel_format_t)colorFormat,
            &mDstFormat, &mCaptureFormat, &mDstBpp)) {
        return ERROR_UNSUPPORTED;
    }

    sp<AMessage> videoFormat = onGetFormatAndSeekOptions(
            frameTimeUs, option, &mReadOptions, &mSurface);
    if (videoFormat == NULL) {
        ALOGE("video format or seek mode not supported");
        return ERROR_UNSUPPORTED;
    }

    status_t err;
    sp<ALooper> looper = new ALooper;
    looper->start();
    sp<MediaCodec> decoder = MediaCodec::CreateByComponentName(
            looper, mComponentName, &err);
    if (decoder.get() == NULL || err != OK) {
        ALOGW("Failed to instantiate decoder [%s]", mComponentName.c_str());
        return (decoder.get() == NULL) ? NO_MEMORY : err;
    }

    err = decoder->configure(
            videoFormat, mSurface, NULL /* crypto */, 0 /* flags */);
    if (err != OK) {
        ALOGW("configure returned error %d (%s)", err, asString(err));
        decoder->release();
        return err;
    }

    err = decoder->start();
    if (err != OK) {
        ALOGW("start returned error %d (%s)", err, asString(err));
        decoder->release();
        return err;
    }

    err = mSource->start();
    if (err != OK) {
        ALOGW("source failed to start: %d (%s)", err, asString(err));
        decoder->release();
        return err;
    }
    mDecoder = decoder;

    return OK;
}

sp<IMemory> FrameDecoder::extractFrame(FrameRect *rect) {
    status_t err = onExtractRect(rect);
    if (err == OK) {
        err = extractInternal();
    }
    if (err != OK) {
        return NULL;
    }

    return mFrameMemory;
}

status_t FrameDecoder::extractInternal() {
    status_t err = OK;
    bool done = false;
    size_t retriesLeft = kRetryCount;
    do {
        size_t index;
        int64_t ptsUs = 0LL;
        uint32_t flags = 0;

        // Queue as many inputs as we possibly can, then block on dequeuing
        // outputs. After getting each output, come back and queue the inputs
        // again to keep the decoder busy.
        while (mHaveMoreInputs) {
            err = mDecoder->dequeueInputBuffer(&index, 0);
            if (err != OK) {
                ALOGV("Timed out waiting for input");
                if (retriesLeft) {
                    err = OK;
                }
                break;
            }
            sp<MediaCodecBuffer> codecBuffer;
            err = mDecoder->getInputBuffer(index, &codecBuffer);
            if (err != OK) {
                ALOGE("failed to get input buffer %zu", index);
                break;
            }

            MediaBufferBase *mediaBuffer = NULL;

            err = mSource->read(&mediaBuffer, &mReadOptions);
            mReadOptions.clearSeekTo();
            if (err != OK) {
                mHaveMoreInputs = false;
                if (!mFirstSample && err == ERROR_END_OF_STREAM) {
                    (void)mDecoder->queueInputBuffer(
                            index, 0, 0, 0, MediaCodec::BUFFER_FLAG_EOS);
                    err = OK;
                } else {
                    ALOGW("Input Error: err=%d", err);
                }
                break;
            }

            if (mediaBuffer->range_length() > codecBuffer->capacity()) {
                ALOGE("buffer size (%zu) too large for codec input size (%zu)",
                        mediaBuffer->range_length(), codecBuffer->capacity());
                mHaveMoreInputs = false;
                err = BAD_VALUE;
            } else {
                codecBuffer->setRange(0, mediaBuffer->range_length());

                CHECK(mediaBuffer->meta_data().findInt64(kKeyTime, &ptsUs));
                memcpy(codecBuffer->data(),
                        (const uint8_t*)mediaBuffer->data() + mediaBuffer->range_offset(),
                        mediaBuffer->range_length());

                onInputReceived(codecBuffer, mediaBuffer->meta_data(), mFirstSample, &flags);
                mFirstSample = false;
            }

            mediaBuffer->release();

            if (mHaveMoreInputs) {
                ALOGV("QueueInput: size=%zu ts=%" PRId64 " us flags=%x",
                        codecBuffer->size(), ptsUs, flags);

                err = mDecoder->queueInputBuffer(
                        index,
                        codecBuffer->offset(),
                        codecBuffer->size(),
                        ptsUs,
                        flags);

                if (flags & MediaCodec::BUFFER_FLAG_EOS) {
                    mHaveMoreInputs = false;
                }
            }
        }

        while (err == OK) {
            size_t offset, size;
            // wait for a decoded buffer
            err = mDecoder->dequeueOutputBuffer(
                    &index,
                    &offset,
                    &size,
                    &ptsUs,
                    &flags,
                    kBufferTimeOutUs);

            if (err == INFO_FORMAT_CHANGED) {
                ALOGV("Received format change");
                err = mDecoder->getOutputFormat(&mOutputFormat);
            } else if (err == INFO_OUTPUT_BUFFERS_CHANGED) {
                ALOGV("Output buffers changed");
                err = OK;
            } else {
                if (err == -EAGAIN /* INFO_TRY_AGAIN_LATER */ && --retriesLeft > 0) {
                    ALOGV("Timed-out waiting for output.. retries left = %zu", retriesLeft);
                    err = OK;
                } else if (err == OK) {
                    // If we're seeking with CLOSEST option and obtained a valid targetTimeUs
                    // from the extractor, decode to the specified frame. Otherwise we're done.
                    ALOGV("Received an output buffer, timeUs=%lld", (long long)ptsUs);
                    sp<MediaCodecBuffer> videoFrameBuffer;
                    err = mDecoder->getOutputBuffer(index, &videoFrameBuffer);
                    if (err != OK) {
                        ALOGE("failed to get output buffer %zu", index);
                        break;
                    }
                    if (mSurface != nullptr) {
                        mDecoder->renderOutputBufferAndRelease(index);
                        err = onOutputReceived(videoFrameBuffer, mOutputFormat, ptsUs, &done);
                    } else {
                        err = onOutputReceived(videoFrameBuffer, mOutputFormat, ptsUs, &done);
                        mDecoder->releaseOutputBuffer(index);
                    }
                } else {
                    ALOGW("Received error %d (%s) instead of output", err, asString(err));
                    done = true;
                }
                break;
            }
        }
    } while (err == OK && !done);

    if (err != OK) {
        ALOGE("failed to get video frame (err %d)", err);
    }

    return err;
}

//////////////////////////////////////////////////////////////////////

VideoFrameDecoder::VideoFrameDecoder(
        const AString &componentName,
        const sp<MetaData> &trackMeta,
        const sp<IMediaSource> &source)
    : FrameDecoder(componentName, trackMeta, source),
      mFrame(NULL),
      mIsAvc(false),
      mIsHevc(false),
      mSeekMode(MediaSource::ReadOptions::SEEK_PREVIOUS_SYNC),
      mTargetTimeUs(-1LL),
      mDefaultSampleDurationUs(0) {
}

sp<AMessage> VideoFrameDecoder::onGetFormatAndSeekOptions(
        int64_t frameTimeUs, int seekMode,
        MediaSource::ReadOptions *options,
        sp<Surface> *window) {
    mSeekMode = static_cast<MediaSource::ReadOptions::SeekMode>(seekMode);
    if (mSeekMode < MediaSource::ReadOptions::SEEK_PREVIOUS_SYNC ||
            mSeekMode > MediaSource::ReadOptions::SEEK_FRAME_INDEX) {
        ALOGE("Unknown seek mode: %d", mSeekMode);
        return NULL;
    }

    const char *mime;
    if (!trackMeta()->findCString(kKeyMIMEType, &mime)) {
        ALOGE("Could not find mime type");
        return NULL;
    }

    mIsAvc = !strcasecmp(mime, MEDIA_MIMETYPE_VIDEO_AVC);
    mIsHevc = !strcasecmp(mime, MEDIA_MIMETYPE_VIDEO_HEVC);

    if (frameTimeUs < 0) {
        int64_t thumbNailTime = -1ll;
        if (!trackMeta()->findInt64(kKeyThumbnailTime, &thumbNailTime)
                || thumbNailTime < 0) {
            thumbNailTime = 0;
        }
        options->setSeekTo(thumbNailTime, mSeekMode);
    } else {
        options->setSeekTo(frameTimeUs, mSeekMode);
    }

    sp<AMessage> videoFormat;
    if (convertMetaDataToMessage(trackMeta(), &videoFormat) != OK) {
        ALOGE("b/23680780");
        ALOGW("Failed to convert meta data to message");
        return NULL;
    }

    // TODO: Use Flexible color instead
    videoFormat->setInt32("color-format", OMX_COLOR_FormatYUV420Planar);

    // For the thumbnail extraction case, try to allocate single buffer in both
    // input and output ports, if seeking to a sync frame. NOTE: This request may
    // fail if component requires more than that for decoding.
    bool isSeekingClosest = (mSeekMode == MediaSource::ReadOptions::SEEK_CLOSEST)
            || (mSeekMode == MediaSource::ReadOptions::SEEK_FRAME_INDEX);
    if (!isSeekingClosest) {
        videoFormat->setInt32("android._num-input-buffers", 1);
        videoFormat->setInt32("android._num-output-buffers", 1);
    }

    if (isHDR(videoFormat)) {
        *window = initSurface();
        if (*window == NULL) {
            ALOGE("Failed to init surface control for HDR, fallback to non-hdr");
        } else {
            videoFormat->setInt32("color-format", OMX_COLOR_FormatAndroidOpaque);
        }
    }

    int32_t frameRate;
    if (trackMeta()->findInt32(kKeyFrameRate, &frameRate) && frameRate > 0) {
        mDefaultSampleDurationUs = 1000000LL / frameRate;
    } else {
        mDefaultSampleDurationUs = kDefaultSampleDurationUs;
    }

    return videoFormat;
}

status_t VideoFrameDecoder::onInputReceived(
        const sp<MediaCodecBuffer> &codecBuffer,
        MetaDataBase &sampleMeta, bool firstSample, uint32_t *flags) {
    bool isSeekingClosest = (mSeekMode == MediaSource::ReadOptions::SEEK_CLOSEST)
            || (mSeekMode == MediaSource::ReadOptions::SEEK_FRAME_INDEX);

    if (firstSample && isSeekingClosest) {
        sampleMeta.findInt64(kKeyTargetTime, &mTargetTimeUs);
        ALOGV("Seeking closest: targetTimeUs=%lld", (long long)mTargetTimeUs);
    }

    if (!isSeekingClosest
            && ((mIsAvc && IsIDR(codecBuffer->data(), codecBuffer->size()))
            || (mIsHevc && IsIDR(
            codecBuffer->data(), codecBuffer->size())))) {
        // Only need to decode one IDR frame, unless we're seeking with CLOSEST
        // option, in which case we need to actually decode to targetTimeUs.
        *flags |= MediaCodec::BUFFER_FLAG_EOS;
    }
    int64_t durationUs;
    if (sampleMeta.findInt64(kKeyDuration, &durationUs)) {
        mSampleDurations.push_back(durationUs);
    } else {
        mSampleDurations.push_back(mDefaultSampleDurationUs);
    }
    return OK;
}

status_t VideoFrameDecoder::onOutputReceived(
        const sp<MediaCodecBuffer> &videoFrameBuffer,
        const sp<AMessage> &outputFormat,
        int64_t timeUs, bool *done) {
    int64_t durationUs = mDefaultSampleDurationUs;
    if (!mSampleDurations.empty()) {
        durationUs = *mSampleDurations.begin();
        mSampleDurations.erase(mSampleDurations.begin());
    }
    bool shouldOutput = (mTargetTimeUs < 0LL) || (timeUs >= mTargetTimeUs);

    // If this is not the target frame, skip color convert.
    if (!shouldOutput) {
        *done = false;
        return OK;
    }

    *done = true;

    if (outputFormat == NULL) {
        return ERROR_MALFORMED;
    }

    int32_t width, height, stride, srcFormat;
    if (!outputFormat->findInt32("width", &width) ||
            !outputFormat->findInt32("height", &height) ||
            !outputFormat->findInt32("color-format", &srcFormat)) {
        ALOGE("format missing dimension or color: %s",
                outputFormat->debugString().c_str());
        return ERROR_MALFORMED;
    }

    if (!outputFormat->findInt32("stride", &stride)) {
        if (mCaptureLayer == NULL) {
            ALOGE("format must have stride for byte buffer mode: %s",
                    outputFormat->debugString().c_str());
            return ERROR_MALFORMED;
        }
        // for surface output, set stride to width, we don't actually need it.
        stride = width;
    }

    int32_t crop_left, crop_top, crop_right, crop_bottom;
    if (!outputFormat->findRect("crop", &crop_left, &crop_top, &crop_right, &crop_bottom)) {
        crop_left = crop_top = 0;
        crop_right = width - 1;
        crop_bottom = height - 1;
    }

    if (mFrame == NULL) {
        sp<IMemory> frameMem = allocVideoFrame(
                trackMeta(),
                (crop_right - crop_left + 1),
                (crop_bottom - crop_top + 1),
                0,
                0,
                dstBpp(),
                mCaptureLayer != nullptr /*allocRotated*/);
        if (frameMem == nullptr) {
            return NO_MEMORY;
        }

        mFrame = static_cast<VideoFrame*>(frameMem->unsecurePointer());

        setFrame(frameMem);
    }

    mFrame->mDurationUs = durationUs;

    if (mCaptureLayer != nullptr) {
        return captureSurface();
    }

    ColorConverter converter((OMX_COLOR_FORMATTYPE)srcFormat, dstFormat());

    uint32_t standard, range, transfer;
    if (!outputFormat->findInt32("color-standard", (int32_t*)&standard)) {
        standard = 0;
    }
    if (!outputFormat->findInt32("color-range", (int32_t*)&range)) {
        range = 0;
    }
    if (!outputFormat->findInt32("color-transfer", (int32_t*)&transfer)) {
        transfer = 0;
    }
    converter.setSrcColorSpace(standard, range, transfer);

    if (converter.isValid()) {
        converter.convert(
                (const uint8_t *)videoFrameBuffer->data(),
                width, height, stride,
                crop_left, crop_top, crop_right, crop_bottom,
                mFrame->getFlattenedData(),
                mFrame->mWidth, mFrame->mHeight, mFrame->mRowBytes,
                // since the frame is allocated with top-left adjusted,
                // the dst rect should start at {0,0} as well.
                0, 0, mFrame->mWidth - 1, mFrame->mHeight - 1);
        return OK;
    }

    ALOGE("Unable to convert from format 0x%08x to 0x%08x",
                srcFormat, dstFormat());
    return ERROR_UNSUPPORTED;
}

sp<Surface> VideoFrameDecoder::initSurface() {
    // create the consumer listener interface, and hold sp so that this
    // interface lives as long as the GraphicBufferSource.
    sp<FrameCaptureLayer> captureLayer = new FrameCaptureLayer();
    if (captureLayer->init() != OK) {
        ALOGE("failed to init capture layer");
        return nullptr;
    }
    mCaptureLayer = captureLayer;

    return captureLayer->getSurface();
}

status_t VideoFrameDecoder::captureSurface() {
    sp<GraphicBuffer> outBuffer;
    status_t err = mCaptureLayer->capture(
            captureFormat(), Rect(0, 0, mFrame->mWidth, mFrame->mHeight), &outBuffer);

    if (err != OK) {
        ALOGE("failed to capture layer (err %d)", err);
        return err;
    }

    ALOGV("capture: %dx%d, format %d, stride %d",
            outBuffer->getWidth(),
            outBuffer->getHeight(),
            outBuffer->getPixelFormat(),
            outBuffer->getStride());

    uint8_t *base;
    int32_t outBytesPerPixel, outBytesPerStride;
    err = outBuffer->lock(
            GraphicBuffer::USAGE_SW_READ_OFTEN,
            reinterpret_cast<void**>(&base),
            &outBytesPerPixel,
            &outBytesPerStride);
    if (err != OK) {
        ALOGE("failed to lock graphic buffer: err %d", err);
        return err;
    }

    uint8_t *dst = mFrame->getFlattenedData();
    for (size_t y = 0 ; y < fmin(mFrame->mHeight, outBuffer->getHeight()) ; y++) {
        memcpy(dst, base, fmin(mFrame->mWidth, outBuffer->getWidth()) * mFrame->mBytesPerPixel);
        dst += mFrame->mRowBytes;
        base += outBuffer->getStride() * mFrame->mBytesPerPixel;
    }
    outBuffer->unlock();
    return OK;
}

////////////////////////////////////////////////////////////////////////

MediaImageDecoder::MediaImageDecoder(
        const AString &componentName,
        const sp<MetaData> &trackMeta,
        const sp<IMediaSource> &source)
    : FrameDecoder(componentName, trackMeta, source),
      mFrame(NULL),
      mWidth(0),
      mHeight(0),
      mGridRows(1),
      mGridCols(1),
      mTileWidth(0),
      mTileHeight(0),
      mTilesDecoded(0),
      mTargetTiles(0) {
}

sp<AMessage> MediaImageDecoder::onGetFormatAndSeekOptions(
        int64_t frameTimeUs, int /*seekMode*/,
        MediaSource::ReadOptions *options, sp<Surface> * /*window*/) {
    sp<MetaData> overrideMeta;
    if (frameTimeUs < 0) {
        uint32_t type;
        const void *data;
        size_t size;

        // if we have a stand-alone thumbnail, set up the override meta,
        // and set seekTo time to -1.
        if (!findThumbnailInfo(trackMeta(), &mWidth, &mHeight, &type, &data, &size)) {
            ALOGE("Thumbnail not available");
            return NULL;
        }
        overrideMeta = new MetaData(*(trackMeta()));
        overrideMeta->remove(kKeyDisplayWidth);
        overrideMeta->remove(kKeyDisplayHeight);
        overrideMeta->setInt32(kKeyWidth, mWidth);
        overrideMeta->setInt32(kKeyHeight, mHeight);
        // The AV1 codec configuration data is passed via CSD0 to the AV1
        // decoder.
        const int codecConfigKey = isAvif(trackMeta()) ? kKeyOpaqueCSD0 : kKeyHVCC;
        overrideMeta->setData(codecConfigKey, type, data, size);
        options->setSeekTo(-1);
    } else {
        CHECK(trackMeta()->findInt32(kKeyWidth, &mWidth));
        CHECK(trackMeta()->findInt32(kKeyHeight, &mHeight));

        options->setSeekTo(frameTimeUs);
    }

    mGridRows = mGridCols = 1;
    if (overrideMeta == NULL) {
        // check if we're dealing with a tiled heif
        int32_t tileWidth, tileHeight, gridRows, gridCols;
        if (findGridInfo(trackMeta(), &tileWidth, &tileHeight, &gridRows, &gridCols)) {
            if (mWidth <= tileWidth * gridCols && mHeight <= tileHeight * gridRows) {
                ALOGV("grid: %dx%d, tile size: %dx%d, picture size: %dx%d",
                        gridCols, gridRows, tileWidth, tileHeight, mWidth, mHeight);

                overrideMeta = new MetaData(*(trackMeta()));
                overrideMeta->setInt32(kKeyWidth, tileWidth);
                overrideMeta->setInt32(kKeyHeight, tileHeight);
                mTileWidth = tileWidth;
                mTileHeight = tileHeight;
                mGridCols = gridCols;
                mGridRows = gridRows;
            } else {
                ALOGW("ignore bad grid: %dx%d, tile size: %dx%d, picture size: %dx%d",
                        gridCols, gridRows, tileWidth, tileHeight, mWidth, mHeight);
            }
        }
        if (overrideMeta == NULL) {
            overrideMeta = trackMeta();
        }
    }
    mTargetTiles = mGridCols * mGridRows;

    sp<AMessage> videoFormat;
    if (convertMetaDataToMessage(overrideMeta, &videoFormat) != OK) {
        ALOGE("b/23680780");
        ALOGW("Failed to convert meta data to message");
        return NULL;
    }

    // TODO: Use Flexible color instead
    videoFormat->setInt32("color-format", OMX_COLOR_FormatYUV420Planar);

    if ((mGridRows == 1) && (mGridCols == 1)) {
        videoFormat->setInt32("android._num-input-buffers", 1);
        videoFormat->setInt32("android._num-output-buffers", 1);
    }
    return videoFormat;
}

status_t MediaImageDecoder::onExtractRect(FrameRect *rect) {
    // TODO:
    // This callback is for verifying whether we can decode the rect,
    // and if so, set up the internal variables for decoding.
    // Currently, rect decoding is restricted to sequentially decoding one
    // row of tiles at a time. We can't decode arbitrary rects, as the image
    // track doesn't yet support seeking by tiles. So all we do here is to
    // verify the rect against what we expect.
    // When seeking by tile is supported, this code should be updated to
    // set the seek parameters.
    if (rect == NULL) {
        if (mTilesDecoded > 0) {
            return ERROR_UNSUPPORTED;
        }
        mTargetTiles = mGridRows * mGridCols;
        return OK;
    }

    if (mTileWidth <= 0 || mTileHeight <=0) {
        return ERROR_UNSUPPORTED;
    }

    int32_t row = mTilesDecoded / mGridCols;
    int32_t expectedTop = row * mTileHeight;
    int32_t expectedBot = (row + 1) * mTileHeight;
    if (expectedBot > mHeight) {
        expectedBot = mHeight;
    }
    if (rect->left != 0 || rect->top != expectedTop
            || rect->right != mWidth || rect->bottom != expectedBot) {
        ALOGE("currently only support sequential decoding of slices");
        return ERROR_UNSUPPORTED;
    }

    // advance one row
    mTargetTiles = mTilesDecoded + mGridCols;
    return OK;
}

status_t MediaImageDecoder::onOutputReceived(
        const sp<MediaCodecBuffer> &videoFrameBuffer,
        const sp<AMessage> &outputFormat, int64_t /*timeUs*/, bool *done) {
    if (outputFormat == NULL) {
        return ERROR_MALFORMED;
    }

    int32_t width, height, stride;
    if (outputFormat->findInt32("width", &width) == false) {
        ALOGE("MediaImageDecoder::onOutputReceived:width is missing in outputFormat");
        return ERROR_MALFORMED;
    }
    if (outputFormat->findInt32("height", &height) == false) {
        ALOGE("MediaImageDecoder::onOutputReceived:height is missing in outputFormat");
        return ERROR_MALFORMED;
    }
    if (outputFormat->findInt32("stride", &stride) == false) {
        ALOGE("MediaImageDecoder::onOutputReceived:stride is missing in outputFormat");
        return ERROR_MALFORMED;
    }

    if (mFrame == NULL) {
        sp<IMemory> frameMem = allocVideoFrame(
                trackMeta(), mWidth, mHeight, mTileWidth, mTileHeight, dstBpp());

        if (frameMem == nullptr) {
            return NO_MEMORY;
        }

        mFrame = static_cast<VideoFrame*>(frameMem->unsecurePointer());

        setFrame(frameMem);
    }

    int32_t srcFormat;
    CHECK(outputFormat->findInt32("color-format", &srcFormat));

    ColorConverter converter((OMX_COLOR_FORMATTYPE)srcFormat, dstFormat());

    uint32_t standard, range, transfer;
    if (!outputFormat->findInt32("color-standard", (int32_t*)&standard)) {
        standard = 0;
    }
    if (!outputFormat->findInt32("color-range", (int32_t*)&range)) {
        range = 0;
    }
    if (!outputFormat->findInt32("color-transfer", (int32_t*)&transfer)) {
        transfer = 0;
    }
    converter.setSrcColorSpace(standard, range, transfer);

    int32_t crop_left, crop_top, crop_right, crop_bottom;
    if (!outputFormat->findRect("crop", &crop_left, &crop_top, &crop_right, &crop_bottom)) {
        crop_left = crop_top = 0;
        crop_right = width - 1;
        crop_bottom = height - 1;
    }

    int32_t crop_width, crop_height;
    crop_width = crop_right - crop_left + 1;
    crop_height = crop_bottom - crop_top + 1;

    int32_t dstLeft, dstTop, dstRight, dstBottom;
    dstLeft = mTilesDecoded % mGridCols * crop_width;
    dstTop = mTilesDecoded / mGridCols * crop_height;
    dstRight = dstLeft + crop_width - 1;
    dstBottom = dstTop + crop_height - 1;

    // apply crop on bottom-right
    // TODO: need to move this into the color converter itself.
    if (dstRight >= mWidth) {
        crop_right = crop_left + mWidth - dstLeft - 1;
        dstRight = mWidth - 1;
    }
    if (dstBottom >= mHeight) {
        crop_bottom = crop_top + mHeight - dstTop - 1;
        dstBottom = mHeight - 1;
    }

    *done = (++mTilesDecoded >= mTargetTiles);

    if (converter.isValid()) {
        converter.convert(
                (const uint8_t *)videoFrameBuffer->data(),
                width, height, stride,
                crop_left, crop_top, crop_right, crop_bottom,
                mFrame->getFlattenedData(),
                mFrame->mWidth, mFrame->mHeight, mFrame->mRowBytes,
                dstLeft, dstTop, dstRight, dstBottom);
        return OK;
    }

    ALOGE("Unable to convert from format 0x%08x to 0x%08x",
                srcFormat, dstFormat());
    return ERROR_UNSUPPORTED;
}

}  // namespace android
