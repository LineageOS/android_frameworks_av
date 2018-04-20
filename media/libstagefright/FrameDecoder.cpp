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

#include <inttypes.h>

#include <utils/Log.h>
#include <gui/Surface.h>

#include "include/FrameDecoder.h"
#include <media/ICrypto.h>
#include <media/IMediaSource.h>
#include <media/MediaCodecBuffer.h>
#include <media/stagefright/foundation/avc_utils.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/ColorConverter.h>
#include <media/stagefright/MediaBuffer.h>
#include <media/stagefright/MediaCodec.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/Utils.h>
#include <private/media/VideoFrame.h>

namespace android {

static const int64_t kBufferTimeOutUs = 10000ll; // 10 msec
static const size_t kRetryCount = 50; // must be >0

//static
VideoFrame *allocVideoFrame(const sp<MetaData> &trackMeta,
        int32_t width, int32_t height, int32_t dstBpp, bool metaOnly = false) {
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

    return new VideoFrame(width, height, displayWidth, displayHeight,
            rotationAngle, dstBpp, !metaOnly, iccData, iccSize);
}

//static
bool findThumbnailInfo(
        const sp<MetaData> &trackMeta, int32_t *width, int32_t *height,
        uint32_t *type = NULL, const void **data = NULL, size_t *size = NULL) {
    uint32_t dummyType;
    const void *dummyData;
    size_t dummySize;
    return trackMeta->findInt32(kKeyThumbnailWidth, width)
        && trackMeta->findInt32(kKeyThumbnailHeight, height)
        && trackMeta->findData(kKeyThumbnailHVCC,
                type ?: &dummyType, data ?: &dummyData, size ?: &dummySize);
}

//static
VideoFrame* FrameDecoder::getMetadataOnly(
        const sp<MetaData> &trackMeta, int colorFormat, bool thumbnail) {
    OMX_COLOR_FORMATTYPE dstFormat;
    int32_t dstBpp;
    if (!getDstColorFormat(
            (android_pixel_format_t)colorFormat, &dstFormat, &dstBpp)) {
        return NULL;
    }

    int32_t width, height;
    if (thumbnail) {
        if (!findThumbnailInfo(trackMeta, &width, &height)) {
            return NULL;
        }
    } else {
        CHECK(trackMeta->findInt32(kKeyWidth, &width));
        CHECK(trackMeta->findInt32(kKeyHeight, &height));
    }
    return allocVideoFrame(trackMeta, width, height, dstBpp, true /*metaOnly*/);
}

//static
bool FrameDecoder::getDstColorFormat(
        android_pixel_format_t colorFormat,
        OMX_COLOR_FORMATTYPE *dstFormat,
        int32_t *dstBpp) {
    switch (colorFormat) {
        case HAL_PIXEL_FORMAT_RGB_565:
        {
            *dstFormat = OMX_COLOR_Format16bitRGB565;
            *dstBpp = 2;
            return true;
        }
        case HAL_PIXEL_FORMAT_RGBA_8888:
        {
            *dstFormat = OMX_COLOR_Format32BitRGBA8888;
            *dstBpp = 4;
            return true;
        }
        case HAL_PIXEL_FORMAT_BGRA_8888:
        {
            *dstFormat = OMX_COLOR_Format32bitBGRA8888;
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

VideoFrame* FrameDecoder::extractFrame(
        int64_t frameTimeUs, int option, int colorFormat) {
    if (!getDstColorFormat(
            (android_pixel_format_t)colorFormat, &mDstFormat, &mDstBpp)) {
        return NULL;
    }

    status_t err = extractInternal(frameTimeUs, 1, option);
    if (err != OK) {
        return NULL;
    }

    return mFrames.size() > 0 ? mFrames[0].release() : NULL;
}

status_t FrameDecoder::extractFrames(
        int64_t frameTimeUs, size_t numFrames, int option, int colorFormat,
        std::vector<VideoFrame*>* frames) {
    if (!getDstColorFormat(
            (android_pixel_format_t)colorFormat, &mDstFormat, &mDstBpp)) {
        return ERROR_UNSUPPORTED;
    }

    status_t err = extractInternal(frameTimeUs, numFrames, option);
    if (err != OK) {
        return err;
    }

    for (size_t i = 0; i < mFrames.size(); i++) {
        frames->push_back(mFrames[i].release());
    }
    return OK;
}

status_t FrameDecoder::extractInternal(
        int64_t frameTimeUs, size_t numFrames, int option) {

    MediaSource::ReadOptions options;
    sp<AMessage> videoFormat = onGetFormatAndSeekOptions(
            frameTimeUs, numFrames, option, &options);
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

    err = decoder->configure(videoFormat, NULL /* surface */, NULL /* crypto */, 0 /* flags */);
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

    Vector<sp<MediaCodecBuffer> > inputBuffers;
    err = decoder->getInputBuffers(&inputBuffers);
    if (err != OK) {
        ALOGW("failed to get input buffers: %d (%s)", err, asString(err));
        decoder->release();
        mSource->stop();
        return err;
    }

    Vector<sp<MediaCodecBuffer> > outputBuffers;
    err = decoder->getOutputBuffers(&outputBuffers);
    if (err != OK) {
        ALOGW("failed to get output buffers: %d (%s)", err, asString(err));
        decoder->release();
        mSource->stop();
        return err;
    }

    sp<AMessage> outputFormat = NULL;
    bool haveMoreInputs = true;
    size_t index, offset, size;
    int64_t timeUs;
    size_t retriesLeft = kRetryCount;
    bool done = false;
    bool firstSample = true;
    do {
        size_t inputIndex = -1;
        int64_t ptsUs = 0ll;
        uint32_t flags = 0;
        sp<MediaCodecBuffer> codecBuffer = NULL;

        // Queue as many inputs as we possibly can, then block on dequeuing
        // outputs. After getting each output, come back and queue the inputs
        // again to keep the decoder busy.
        while (haveMoreInputs) {
            err = decoder->dequeueInputBuffer(&inputIndex, 0);
            if (err != OK) {
                ALOGV("Timed out waiting for input");
                if (retriesLeft) {
                    err = OK;
                }
                break;
            }
            codecBuffer = inputBuffers[inputIndex];

            MediaBufferBase *mediaBuffer = NULL;

            err = mSource->read(&mediaBuffer, &options);
            options.clearSeekTo();
            if (err != OK) {
                ALOGW("Input Error or EOS");
                haveMoreInputs = false;
                if (!firstSample && err == ERROR_END_OF_STREAM) {
                    err = OK;
                }
                break;
            }

            if (mediaBuffer->range_length() > codecBuffer->capacity()) {
                ALOGE("buffer size (%zu) too large for codec input size (%zu)",
                        mediaBuffer->range_length(), codecBuffer->capacity());
                haveMoreInputs = false;
                err = BAD_VALUE;
            } else {
                codecBuffer->setRange(0, mediaBuffer->range_length());

                CHECK(mediaBuffer->meta_data().findInt64(kKeyTime, &ptsUs));
                memcpy(codecBuffer->data(),
                        (const uint8_t*)mediaBuffer->data() + mediaBuffer->range_offset(),
                        mediaBuffer->range_length());

                onInputReceived(codecBuffer, mediaBuffer->meta_data(), firstSample, &flags);
                firstSample = false;
            }

            mediaBuffer->release();

            if (haveMoreInputs && inputIndex < inputBuffers.size()) {
                ALOGV("QueueInput: size=%zu ts=%" PRId64 " us flags=%x",
                        codecBuffer->size(), ptsUs, flags);

                err = decoder->queueInputBuffer(
                        inputIndex,
                        codecBuffer->offset(),
                        codecBuffer->size(),
                        ptsUs,
                        flags);

                if (flags & MediaCodec::BUFFER_FLAG_EOS) {
                    haveMoreInputs = false;
                }
            }
        }

        while (err == OK) {
            // wait for a decoded buffer
            err = decoder->dequeueOutputBuffer(
                    &index,
                    &offset,
                    &size,
                    &timeUs,
                    &flags,
                    kBufferTimeOutUs);

            if (err == INFO_FORMAT_CHANGED) {
                ALOGV("Received format change");
                err = decoder->getOutputFormat(&outputFormat);
            } else if (err == INFO_OUTPUT_BUFFERS_CHANGED) {
                ALOGV("Output buffers changed");
                err = decoder->getOutputBuffers(&outputBuffers);
            } else {
                if (err == -EAGAIN /* INFO_TRY_AGAIN_LATER */ && --retriesLeft > 0) {
                    ALOGV("Timed-out waiting for output.. retries left = %zu", retriesLeft);
                    err = OK;
                } else if (err == OK) {
                    // If we're seeking with CLOSEST option and obtained a valid targetTimeUs
                    // from the extractor, decode to the specified frame. Otherwise we're done.
                    ALOGV("Received an output buffer, timeUs=%lld", (long long)timeUs);
                    sp<MediaCodecBuffer> videoFrameBuffer = outputBuffers.itemAt(index);

                    err = onOutputReceived(videoFrameBuffer, outputFormat, timeUs, &done);

                    decoder->releaseOutputBuffer(index);
                } else {
                    ALOGW("Received error %d (%s) instead of output", err, asString(err));
                    done = true;
                }
                break;
            }
        }
    } while (err == OK && !done);

    mSource->stop();
    decoder->release();

    if (err != OK) {
        ALOGE("failed to get video frame (err %d)", err);
    }

    return err;
}

sp<AMessage> VideoFrameDecoder::onGetFormatAndSeekOptions(
        int64_t frameTimeUs, size_t numFrames, int seekMode, MediaSource::ReadOptions *options) {
    mSeekMode = static_cast<MediaSource::ReadOptions::SeekMode>(seekMode);
    if (mSeekMode < MediaSource::ReadOptions::SEEK_PREVIOUS_SYNC ||
            mSeekMode > MediaSource::ReadOptions::SEEK_FRAME_INDEX) {
        ALOGE("Unknown seek mode: %d", mSeekMode);
        return NULL;
    }
    mNumFrames = numFrames;

    const char *mime;
    if (!trackMeta()->findCString(kKeyMIMEType, &mime)) {
        ALOGE("Could not find mime type");
        return NULL;
    }

    mIsAvcOrHevc = !strcasecmp(mime, MEDIA_MIMETYPE_VIDEO_AVC)
            || !strcasecmp(mime, MEDIA_MIMETYPE_VIDEO_HEVC);

    if (frameTimeUs < 0) {
        int64_t thumbNailTime;
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

    if (mIsAvcOrHevc && !isSeekingClosest
            && IsIDR(codecBuffer->data(), codecBuffer->size())) {
        // Only need to decode one IDR frame, unless we're seeking with CLOSEST
        // option, in which case we need to actually decode to targetTimeUs.
        *flags |= MediaCodec::BUFFER_FLAG_EOS;
    }
    return OK;
}

status_t VideoFrameDecoder::onOutputReceived(
        const sp<MediaCodecBuffer> &videoFrameBuffer,
        const sp<AMessage> &outputFormat,
        int64_t timeUs, bool *done) {
    bool shouldOutput = (mTargetTimeUs < 0ll) || (timeUs >= mTargetTimeUs);

    // If this is not the target frame, skip color convert.
    if (!shouldOutput) {
        *done = false;
        return OK;
    }

    *done = (++mNumFramesDecoded >= mNumFrames);

    if (outputFormat == NULL) {
        return ERROR_MALFORMED;
    }

    int32_t width, height;
    CHECK(outputFormat->findInt32("width", &width));
    CHECK(outputFormat->findInt32("height", &height));

    int32_t crop_left, crop_top, crop_right, crop_bottom;
    if (!outputFormat->findRect("crop", &crop_left, &crop_top, &crop_right, &crop_bottom)) {
        crop_left = crop_top = 0;
        crop_right = width - 1;
        crop_bottom = height - 1;
    }

    VideoFrame *frame = allocVideoFrame(
            trackMeta(),
            (crop_right - crop_left + 1),
            (crop_bottom - crop_top + 1),
            dstBpp());
    addFrame(frame);

    int32_t srcFormat;
    CHECK(outputFormat->findInt32("color-format", &srcFormat));

    ColorConverter converter((OMX_COLOR_FORMATTYPE)srcFormat, dstFormat());

    if (converter.isValid()) {
        converter.convert(
                (const uint8_t *)videoFrameBuffer->data(),
                width, height,
                crop_left, crop_top, crop_right, crop_bottom,
                frame->mData,
                frame->mWidth,
                frame->mHeight,
                crop_left, crop_top, crop_right, crop_bottom);
        return OK;
    }

    ALOGE("Unable to convert from format 0x%08x to 0x%08x",
                srcFormat, dstFormat());
    return ERROR_UNSUPPORTED;
}

sp<AMessage> ImageDecoder::onGetFormatAndSeekOptions(
        int64_t frameTimeUs, size_t /*numFrames*/,
        int /*seekMode*/, MediaSource::ReadOptions *options) {
    sp<MetaData> overrideMeta;
    mThumbnail = false;
    if (frameTimeUs < 0) {
        uint32_t type;
        const void *data;
        size_t size;
        int32_t thumbWidth, thumbHeight;

        // if we have a stand-alone thumbnail, set up the override meta,
        // and set seekTo time to -1.
        if (!findThumbnailInfo(trackMeta(),
                &thumbWidth, &thumbHeight, &type, &data, &size)) {
            ALOGE("Thumbnail not available");
            return NULL;
        }
        overrideMeta = new MetaData(*(trackMeta()));
        overrideMeta->remove(kKeyDisplayWidth);
        overrideMeta->remove(kKeyDisplayHeight);
        overrideMeta->setInt32(kKeyWidth, thumbWidth);
        overrideMeta->setInt32(kKeyHeight, thumbHeight);
        overrideMeta->setData(kKeyHVCC, type, data, size);
        options->setSeekTo(-1);
        mThumbnail = true;
    } else {
        options->setSeekTo(frameTimeUs);
    }

    mGridRows = mGridCols = 1;
    if (overrideMeta == NULL) {
        // check if we're dealing with a tiled heif
        int32_t tileWidth, tileHeight, gridRows, gridCols;
        if (trackMeta()->findInt32(kKeyTileWidth, &tileWidth) && tileWidth > 0
         && trackMeta()->findInt32(kKeyTileHeight, &tileHeight) && tileHeight > 0
         && trackMeta()->findInt32(kKeyGridRows, &gridRows) && gridRows > 0
         && trackMeta()->findInt32(kKeyGridCols, &gridCols) && gridCols > 0) {
            int32_t width, height;
            CHECK(trackMeta()->findInt32(kKeyWidth, &width));
            CHECK(trackMeta()->findInt32(kKeyHeight, &height));

            if (width <= tileWidth * gridCols && height <= tileHeight * gridRows) {
                ALOGV("grid: %dx%d, tile size: %dx%d, picture size: %dx%d",
                        gridCols, gridRows, tileWidth, tileHeight, width, height);

                overrideMeta = new MetaData(*(trackMeta()));
                overrideMeta->setInt32(kKeyWidth, tileWidth);
                overrideMeta->setInt32(kKeyHeight, tileHeight);
                mGridCols = gridCols;
                mGridRows = gridRows;
            } else {
                ALOGE("bad grid: %dx%d, tile size: %dx%d, picture size: %dx%d",
                        gridCols, gridRows, tileWidth, tileHeight, width, height);
            }
        }
        if (overrideMeta == NULL) {
            overrideMeta = trackMeta();
        }
    }

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

status_t ImageDecoder::onOutputReceived(
        const sp<MediaCodecBuffer> &videoFrameBuffer,
        const sp<AMessage> &outputFormat, int64_t /*timeUs*/, bool *done) {
    if (outputFormat == NULL) {
        return ERROR_MALFORMED;
    }

    int32_t width, height;
    CHECK(outputFormat->findInt32("width", &width));
    CHECK(outputFormat->findInt32("height", &height));

    int32_t imageWidth, imageHeight;
    if (mThumbnail) {
        CHECK(trackMeta()->findInt32(kKeyThumbnailWidth, &imageWidth));
        CHECK(trackMeta()->findInt32(kKeyThumbnailHeight, &imageHeight));
    } else {
        CHECK(trackMeta()->findInt32(kKeyWidth, &imageWidth));
        CHECK(trackMeta()->findInt32(kKeyHeight, &imageHeight));
    }

    if (mFrame == NULL) {
        mFrame = allocVideoFrame(trackMeta(), imageWidth, imageHeight, dstBpp());

        addFrame(mFrame);
    }

    int32_t srcFormat;
    CHECK(outputFormat->findInt32("color-format", &srcFormat));

    ColorConverter converter((OMX_COLOR_FORMATTYPE)srcFormat, dstFormat());

    int32_t dstLeft, dstTop, dstRight, dstBottom;
    int32_t numTiles = mGridRows * mGridCols;

    dstLeft = mTilesDecoded % mGridCols * width;
    dstTop = mTilesDecoded / mGridCols * height;
    dstRight = dstLeft + width - 1;
    dstBottom = dstTop + height - 1;

    int32_t crop_left, crop_top, crop_right, crop_bottom;
    if (!outputFormat->findRect("crop", &crop_left, &crop_top, &crop_right, &crop_bottom)) {
        crop_left = crop_top = 0;
        crop_right = width - 1;
        crop_bottom = height - 1;
    }

    // apply crop on bottom-right
    // TODO: need to move this into the color converter itself.
    if (dstRight >= imageWidth) {
        crop_right = imageWidth - dstLeft - 1;
        dstRight = dstLeft + crop_right;
    }
    if (dstBottom >= imageHeight) {
        crop_bottom = imageHeight - dstTop - 1;
        dstBottom = dstTop + crop_bottom;
    }

    *done = (++mTilesDecoded >= numTiles);

    if (converter.isValid()) {
        converter.convert(
                (const uint8_t *)videoFrameBuffer->data(),
                width, height,
                crop_left, crop_top, crop_right, crop_bottom,
                mFrame->mData,
                mFrame->mWidth,
                mFrame->mHeight,
                dstLeft, dstTop, dstRight, dstBottom);
        return OK;
    }

    ALOGE("Unable to convert from format 0x%08x to 0x%08x",
                srcFormat, dstFormat());
    return ERROR_UNSUPPORTED;
}

}  // namespace android
