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

#ifndef FRAME_DECODER_H_
#define FRAME_DECODER_H_

#include <memory>
#include <vector>

#include <media/stagefright/foundation/AString.h>
#include <media/stagefright/foundation/ABase.h>
#include <media/MediaSource.h>
#include <media/openmax/OMX_Video.h>
#include <system/graphics-base.h>

namespace android {

struct AMessage;
class MediaCodecBuffer;
class IMediaSource;
class VideoFrame;

struct FrameDecoder {
    FrameDecoder(
            const AString &componentName,
            const sp<MetaData> &trackMeta,
            const sp<IMediaSource> &source) :
                mComponentName(componentName),
                mTrackMeta(trackMeta),
                mSource(source),
                mDstFormat(OMX_COLOR_Format16bitRGB565),
                mDstBpp(2) {}

    VideoFrame* extractFrame(int64_t frameTimeUs, int option, int colorFormat);

    status_t extractFrames(
            int64_t frameTimeUs,
            size_t numFrames,
            int option,
            int colorFormat,
            std::vector<VideoFrame*>* frames);

    static VideoFrame* getMetadataOnly(
            const sp<MetaData> &trackMeta, int colorFormat, bool thumbnail = false);

protected:
    virtual ~FrameDecoder() {}

    virtual sp<AMessage> onGetFormatAndSeekOptions(
            int64_t frameTimeUs,
            size_t numFrames,
            int seekMode,
            MediaSource::ReadOptions *options) = 0;

    virtual status_t onInputReceived(
            const sp<MediaCodecBuffer> &codecBuffer,
            MetaDataBase &sampleMeta,
            bool firstSample,
            uint32_t *flags) = 0;

    virtual status_t onOutputReceived(
            const sp<MediaCodecBuffer> &videoFrameBuffer,
            const sp<AMessage> &outputFormat,
            int64_t timeUs,
            bool *done) = 0;

    sp<MetaData> trackMeta()     const      { return mTrackMeta; }
    OMX_COLOR_FORMATTYPE dstFormat() const  { return mDstFormat; }
    int32_t dstBpp()             const      { return mDstBpp; }

    void addFrame(VideoFrame *frame) {
        mFrames.push_back(std::unique_ptr<VideoFrame>(frame));
    }

private:
    AString mComponentName;
    sp<MetaData> mTrackMeta;
    sp<IMediaSource> mSource;
    OMX_COLOR_FORMATTYPE mDstFormat;
    int32_t mDstBpp;
    std::vector<std::unique_ptr<VideoFrame> > mFrames;

    static bool getDstColorFormat(
            android_pixel_format_t colorFormat,
            OMX_COLOR_FORMATTYPE *dstFormat,
            int32_t *dstBpp);

    status_t extractInternal(int64_t frameTimeUs, size_t numFrames, int option);

    DISALLOW_EVIL_CONSTRUCTORS(FrameDecoder);
};

struct VideoFrameDecoder : public FrameDecoder {
    VideoFrameDecoder(
            const AString &componentName,
            const sp<MetaData> &trackMeta,
            const sp<IMediaSource> &source) :
                FrameDecoder(componentName, trackMeta, source),
                mIsAvcOrHevc(false),
                mSeekMode(MediaSource::ReadOptions::SEEK_PREVIOUS_SYNC),
                mTargetTimeUs(-1ll),
                mNumFrames(0),
                mNumFramesDecoded(0) {}

protected:
    virtual sp<AMessage> onGetFormatAndSeekOptions(
            int64_t frameTimeUs,
            size_t numFrames,
            int seekMode,
            MediaSource::ReadOptions *options) override;

    virtual status_t onInputReceived(
            const sp<MediaCodecBuffer> &codecBuffer,
            MetaDataBase &sampleMeta,
            bool firstSample,
            uint32_t *flags) override;

    virtual status_t onOutputReceived(
            const sp<MediaCodecBuffer> &videoFrameBuffer,
            const sp<AMessage> &outputFormat,
            int64_t timeUs,
            bool *done) override;

private:
    bool mIsAvcOrHevc;
    MediaSource::ReadOptions::SeekMode mSeekMode;
    int64_t mTargetTimeUs;
    size_t mNumFrames;
    size_t mNumFramesDecoded;
};

struct ImageDecoder : public FrameDecoder {
    ImageDecoder(
            const AString &componentName,
            const sp<MetaData> &trackMeta,
            const sp<IMediaSource> &source) :
                FrameDecoder(componentName, trackMeta, source),
                mFrame(NULL), mGridRows(1), mGridCols(1),
                mTilesDecoded(0), mThumbnail(false) {}

protected:
    virtual sp<AMessage> onGetFormatAndSeekOptions(
            int64_t frameTimeUs,
            size_t numFrames,
            int seekMode,
            MediaSource::ReadOptions *options) override;

    virtual status_t onInputReceived(
            const sp<MediaCodecBuffer> &codecBuffer __unused,
            MetaDataBase &sampleMeta __unused,
            bool firstSample __unused,
            uint32_t *flags __unused) override { return OK; }

    virtual status_t onOutputReceived(
            const sp<MediaCodecBuffer> &videoFrameBuffer,
            const sp<AMessage> &outputFormat,
            int64_t timeUs,
            bool *done) override;

private:
    VideoFrame *mFrame;
    int32_t mGridRows;
    int32_t mGridCols;
    int32_t mTilesDecoded;
    bool mThumbnail;
};

}  // namespace android

#endif  // FRAME_DECODER_H_
