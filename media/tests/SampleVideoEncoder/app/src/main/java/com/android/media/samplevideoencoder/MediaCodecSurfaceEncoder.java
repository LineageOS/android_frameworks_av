/*
 * Copyright (C) 2020 The Android Open Source Project
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

package com.android.media.samplevideoencoder;

import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.media.MediaCodec;
import android.media.MediaCodecInfo;
import android.media.MediaExtractor;
import android.media.MediaFormat;
import android.media.MediaMuxer;
import android.os.Build;
import android.util.Log;
import android.util.Pair;
import android.view.Surface;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;

public class MediaCodecSurfaceEncoder {
    private static final String TAG = MediaCodecSurfaceEncoder.class.getSimpleName();

    private static final boolean DEBUG = false;
    private static final int VIDEO_BITRATE = 8000000  /*8 Mbps*/;
    private static final int VIDEO_FRAMERATE = 30;
    private final Context mActivityContext;
    private final int mResID;
    private final int mMaxBFrames;
    private final String mMime;
    private final String mOutputPath;
    private int mTrackID = -1;

    private Surface mSurface;
    private MediaExtractor mExtractor;
    private MediaCodec mDecoder;
    private MediaCodec mEncoder;
    private MediaMuxer mMuxer;

    private final boolean mIsCodecSoftware;
    private boolean mSawDecInputEOS;
    private boolean mSawDecOutputEOS;
    private boolean mSawEncOutputEOS;
    private int mDecOutputCount;
    private int mEncOutputCount;

    private final CodecAsyncHandler mAsyncHandleEncoder = new CodecAsyncHandler();
    private final CodecAsyncHandler mAsyncHandleDecoder = new CodecAsyncHandler();

    public MediaCodecSurfaceEncoder(Context context, int resId, String mime, boolean isSoftware,
                                    String outputPath, int maxBFrames) {
        mActivityContext = context;
        mResID = resId;
        mMime = mime;
        mIsCodecSoftware = isSoftware;
        mOutputPath = outputPath;
        mMaxBFrames = maxBFrames;
    }

    public MediaCodecSurfaceEncoder(Context context, int resId, String mime, boolean isSoftware,
                                    String outputPath) {
        // Default value of MediaFormat.KEY_MAX_B_FRAMES is set to 1, if not passed as a parameter.
        this(context, resId, mime, isSoftware, outputPath, 1);
    }

    public int startEncodingSurface() throws IOException, InterruptedException {
        MediaFormat decoderFormat = setUpSource();
        if (decoderFormat == null) {
            return -1;
        }

        String decoderMime = decoderFormat.getString(MediaFormat.KEY_MIME);
        ArrayList<String> listOfDeocders =
                MediaCodecBase.selectCodecs(decoderMime, null, null, false, mIsCodecSoftware);
        if (listOfDeocders.isEmpty()) {
            Log.e(TAG, "No suitable decoder found for mime: " + decoderMime);
            return -1;
        }
        mDecoder = MediaCodec.createByCodecName(listOfDeocders.get(0));

        MediaFormat encoderFormat = setUpEncoderFormat(decoderFormat);
        ArrayList<String> listOfEncoders =
                MediaCodecBase.selectCodecs(mMime, null, null, true, mIsCodecSoftware);
        if (listOfEncoders.isEmpty()) {
            Log.e(TAG, "No suitable encoder found for mime: " + mMime);
            return -1;
        }

        boolean muxOutput = true;
        for (String encoder : listOfEncoders) {
            mEncoder = MediaCodec.createByCodecName(encoder);
            mExtractor.seekTo(0, MediaExtractor.SEEK_TO_CLOSEST_SYNC);
            if (muxOutput) {
                int muxerFormat = MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4;
                mMuxer = new MediaMuxer(mOutputPath, muxerFormat);
            }
            configureCodec(decoderFormat, encoderFormat);
            mEncoder.start();
            mDecoder.start();
            doWork(Integer.MAX_VALUE);
            queueEOS();
            waitForAllEncoderOutputs();
            if (muxOutput) {
                if (mTrackID != -1) {
                    mMuxer.stop();
                    mTrackID = -1;
                }
                if (mMuxer != null) {
                    mMuxer.release();
                    mMuxer = null;
                }
            }
            mDecoder.reset();
            mEncoder.reset();
            mSurface.release();
            mSurface = null;
        }

        mEncoder.release();
        mDecoder.release();
        mExtractor.release();
        return 0;
    }

    private MediaFormat setUpSource() throws IOException {
        mExtractor = new MediaExtractor();
        AssetFileDescriptor fd = mActivityContext.getResources().openRawResourceFd(mResID);
        mExtractor.setDataSource(fd.getFileDescriptor(), fd.getStartOffset(), fd.getLength());
        for (int trackID = 0; trackID < mExtractor.getTrackCount(); trackID++) {
            MediaFormat format = mExtractor.getTrackFormat(trackID);
            String mime = format.getString(MediaFormat.KEY_MIME);
            if (mime.startsWith("video/")) {
                mExtractor.selectTrack(trackID);
                format.setInteger(MediaFormat.KEY_COLOR_FORMAT,
                        MediaCodecInfo.CodecCapabilities.COLOR_FormatYUV420Flexible);
                return format;
            }
        }
        mExtractor.release();
        return null;
    }

    private MediaFormat setUpEncoderFormat(MediaFormat decoderFormat) {
        MediaFormat encoderFormat = new MediaFormat();
        encoderFormat.setString(MediaFormat.KEY_MIME, mMime);
        encoderFormat
                .setInteger(MediaFormat.KEY_WIDTH, decoderFormat.getInteger(MediaFormat.KEY_WIDTH));
        encoderFormat.setInteger(MediaFormat.KEY_HEIGHT,
                decoderFormat.getInteger(MediaFormat.KEY_HEIGHT));
        encoderFormat.setInteger(MediaFormat.KEY_FRAME_RATE, VIDEO_FRAMERATE);
        encoderFormat.setInteger(MediaFormat.KEY_BIT_RATE, VIDEO_BITRATE);
        encoderFormat.setFloat(MediaFormat.KEY_I_FRAME_INTERVAL, 1.0f);
        encoderFormat.setInteger(MediaFormat.KEY_COLOR_FORMAT,
                MediaCodecInfo.CodecCapabilities.COLOR_FormatSurface);
        if (mMime.equals(MediaFormat.MIMETYPE_VIDEO_HEVC)) {
            encoderFormat.setInteger(MediaFormat.KEY_PROFILE,
                    MediaCodecInfo.CodecProfileLevel.HEVCProfileMain);
            encoderFormat.setInteger(MediaFormat.KEY_LEVEL,
                    MediaCodecInfo.CodecProfileLevel.HEVCMainTierLevel4);
        } else {
            encoderFormat.setInteger(MediaFormat.KEY_PROFILE,
                    MediaCodecInfo.CodecProfileLevel.AVCProfileMain);
            encoderFormat
                    .setInteger(MediaFormat.KEY_LEVEL, MediaCodecInfo.CodecProfileLevel.AVCLevel4);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            encoderFormat.setInteger(MediaFormat.KEY_MAX_B_FRAMES, mMaxBFrames);
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            encoderFormat.setInteger(MediaFormat.KEY_LATENCY, 1);
        }
        return encoderFormat;
    }

    private void resetContext() {
        mAsyncHandleDecoder.resetContext();
        mAsyncHandleEncoder.resetContext();
        mSawDecInputEOS = false;
        mSawDecOutputEOS = false;
        mSawEncOutputEOS = false;
        mDecOutputCount = 0;
        mEncOutputCount = 0;
    }

    private void configureCodec(MediaFormat decFormat, MediaFormat encFormat) {
        resetContext();
        mAsyncHandleEncoder.setCallBack(mEncoder, true);
        mEncoder.configure(encFormat, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE);
        mSurface = mEncoder.createInputSurface();
        if (!mSurface.isValid()) {
            Log.e(TAG, "Surface is not valid");
            return;
        }
        mAsyncHandleDecoder.setCallBack(mDecoder, true);
        mDecoder.configure(decFormat, mSurface, null, 0);
        Log.d(TAG, "Codec configured");
        if (DEBUG) {
            Log.d(TAG, "Encoder Output format: " + mEncoder.getOutputFormat());
        }
    }

    private void dequeueDecoderOutput(int bufferIndex, MediaCodec.BufferInfo info) {
        if ((info.flags & MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0) {
            mSawDecOutputEOS = true;
        }
        if (DEBUG) {
            Log.d(TAG,
                    "output: id: " + bufferIndex + " flags: " + info.flags + " size: " + info.size +
                            " timestamp: " + info.presentationTimeUs);
        }
        if (info.size > 0 && (info.flags & MediaCodec.BUFFER_FLAG_CODEC_CONFIG) == 0) {
            mDecOutputCount++;
        }
        mDecoder.releaseOutputBuffer(bufferIndex, mSurface != null);
    }

    private void enqueueDecoderInput(int bufferIndex) {
        ByteBuffer inputBuffer = mDecoder.getInputBuffer(bufferIndex);
        int size = mExtractor.readSampleData(inputBuffer, 0);
        if (size < 0) {
            enqueueDecoderEOS(bufferIndex);
        } else {
            long pts = mExtractor.getSampleTime();
            int extractorFlags = mExtractor.getSampleFlags();
            int codecFlags = 0;
            if ((extractorFlags & MediaExtractor.SAMPLE_FLAG_SYNC) != 0) {
                codecFlags |= MediaCodec.BUFFER_FLAG_KEY_FRAME;
            }
            if ((extractorFlags & MediaExtractor.SAMPLE_FLAG_PARTIAL_FRAME) != 0) {
                codecFlags |= MediaCodec.BUFFER_FLAG_PARTIAL_FRAME;
            }
            if (!mExtractor.advance()) {
                codecFlags |= MediaCodec.BUFFER_FLAG_END_OF_STREAM;
                mSawDecInputEOS = true;
            }
            if (DEBUG) {
                Log.d(TAG, "input: id: " + bufferIndex + " size: " + size + " pts: " + pts +
                        " flags: " + codecFlags);
            }
            mDecoder.queueInputBuffer(bufferIndex, 0, size, pts, codecFlags);
        }
    }

    private void doWork(int frameLimit) throws InterruptedException {
        int frameCount = 0;
        while (!hasSeenError() && !mSawDecInputEOS && frameCount < frameLimit) {
            Pair<Integer, MediaCodec.BufferInfo> element = mAsyncHandleDecoder.getWork();
            if (element != null) {
                int bufferID = element.first;
                MediaCodec.BufferInfo info = element.second;
                if (info != null) {
                    // <id, info> corresponds to output callback.
                    dequeueDecoderOutput(bufferID, info);
                } else {
                    // <id, null> corresponds to input callback.
                    enqueueDecoderInput(bufferID);
                    frameCount++;
                }
            }
            // check decoder EOS
            if (mSawDecOutputEOS) mEncoder.signalEndOfInputStream();
            // encoder output
            if (mDecOutputCount - mEncOutputCount > mMaxBFrames) {
                tryEncoderOutput();
            }
        }
    }

    private void queueEOS() throws InterruptedException {
        while (!mAsyncHandleDecoder.hasSeenError() && !mSawDecInputEOS) {
            Pair<Integer, MediaCodec.BufferInfo> element = mAsyncHandleDecoder.getWork();
            if (element != null) {
                int bufferID = element.first;
                MediaCodec.BufferInfo info = element.second;
                if (info != null) {
                    dequeueDecoderOutput(bufferID, info);
                } else {
                    enqueueDecoderEOS(element.first);
                }
            }
        }

        while (!hasSeenError() && !mSawDecOutputEOS) {
            Pair<Integer, MediaCodec.BufferInfo> decOp = mAsyncHandleDecoder.getOutput();
            if (decOp != null) dequeueDecoderOutput(decOp.first, decOp.second);
            if (mSawDecOutputEOS) mEncoder.signalEndOfInputStream();
            if (mDecOutputCount - mEncOutputCount > mMaxBFrames) {
                tryEncoderOutput();
            }
        }
    }

    private void tryEncoderOutput() throws InterruptedException {
        if (!hasSeenError() && !mSawEncOutputEOS) {
            Pair<Integer, MediaCodec.BufferInfo> element = mAsyncHandleEncoder.getOutput();
            if (element != null) {
                dequeueEncoderOutput(element.first, element.second);
            }
        }
    }

    private void waitForAllEncoderOutputs() throws InterruptedException {
        while (!hasSeenError() && !mSawEncOutputEOS) {
            tryEncoderOutput();
        }
    }

    private void enqueueDecoderEOS(int bufferIndex) {
        if (!mSawDecInputEOS) {
            mDecoder.queueInputBuffer(bufferIndex, 0, 0, 0, MediaCodec.BUFFER_FLAG_END_OF_STREAM);
            mSawDecInputEOS = true;
            Log.d(TAG, "Queued End of Stream");
        }
    }

    private void dequeueEncoderOutput(int bufferIndex, MediaCodec.BufferInfo info) {
        if (DEBUG) {
            Log.d(TAG, "encoder output: id: " + bufferIndex + " flags: " + info.flags + " size: " +
                    info.size + " timestamp: " + info.presentationTimeUs);
        }
        if ((info.flags & MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0) {
            mSawEncOutputEOS = true;
        }
        if (info.size > 0) {
            ByteBuffer buf = mEncoder.getOutputBuffer(bufferIndex);
            if (mMuxer != null) {
                if (mTrackID == -1) {
                    mTrackID = mMuxer.addTrack(mEncoder.getOutputFormat());
                    mMuxer.start();
                }
                mMuxer.writeSampleData(mTrackID, buf, info);
            }
            if ((info.flags & MediaCodec.BUFFER_FLAG_CODEC_CONFIG) == 0) {
                mEncOutputCount++;
            }
        }
        mEncoder.releaseOutputBuffer(bufferIndex, false);
    }

    private boolean hasSeenError() {
        return mAsyncHandleDecoder.hasSeenError() || mAsyncHandleEncoder.hasSeenError();
    }
}
