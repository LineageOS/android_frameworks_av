/*
 * Copyright (C) 2025 The Android Open Source Project
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

package com.android.media.benchmark.library;

import android.graphics.ImageFormat;
import android.hardware.HardwareBuffer;
import android.media.Image;
import android.media.ImageReader;
import android.media.ImageWriter;
import android.media.MediaCodec;
import android.media.MediaCodecInfo;
import android.util.Log;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class FrameProducer {
    private static final String TAG = "FrameProducer";

    // Limits how many frames we can cache in RAM
    private static final int MAX_NUM_FRAMES_TO_LOAD = 30;

    private final MediaCodec mCodec;
    private final BlockingQueue<Integer> mInputIndexQueue;

    private final int mWidth;
    private final int mHeight;
    private final int mFps;

    // TODO(b/298699053): Support 10bit, RGB, and compressed formats
    private static class PixelFormat {
        final int mFormat;

        PixelFormat(int codecFormat) {
            switch (codecFormat) {
                case MediaCodecInfo.CodecCapabilities.COLOR_FormatYUV420Flexible:
                    mFormat = ImageFormat.YUV_420_888;
                    break;
                case MediaCodecInfo.CodecCapabilities.COLOR_Format32bitABGR8888:
                    mFormat = android.graphics.PixelFormat.RGBA_8888;
                    break;
                case MediaCodecInfo.CodecCapabilities.COLOR_FormatYUVP010:
                    mFormat = ImageFormat.YCBCR_P010;
                    break;
                case MediaCodecInfo.CodecCapabilities.COLOR_Format32bitABGR2101010:
                    mFormat = android.graphics.PixelFormat.RGBA_1010102;
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported format: " + codecFormat);
            }
        }
    }

    private final PixelFormat mPixelFormat;

    private ImageReader mReader;
    private ImageWriter mWriter;

    private final List<Image> mFrameList = new ArrayList<>();

    public FrameProducer(
            MediaCodec codec,
            BlockingQueue<Integer> inputIndexQueue,
            int width,
            int height,
            int fps,
            int codecFormat) {
        mCodec = codec;
        mInputIndexQueue = inputIndexQueue;
        mWidth = width;
        mHeight = height;
        mFps = fps;
        mPixelFormat = new PixelFormat(codecFormat);
        initializeAllocators();
    }

    private void initializeAllocators() {
        long usageFlags = HardwareBuffer.USAGE_VIDEO_ENCODE | HardwareBuffer.USAGE_CPU_WRITE_OFTEN;
        mReader =
                ImageReader.newInstance(
                        mWidth, mHeight, mPixelFormat.mFormat, MAX_NUM_FRAMES_TO_LOAD, usageFlags);
        mWriter = ImageWriter.newInstance(mReader.getSurface(), MAX_NUM_FRAMES_TO_LOAD);
    }

    public void loadFrames(FileInputStream fileStream, int numFramesToLoad) throws IOException {
        if (numFramesToLoad > MAX_NUM_FRAMES_TO_LOAD) {
            throw new IllegalArgumentException(
                    "Requested "
                            + numFramesToLoad
                            + " frames but MAX_NUM_FRAMES_TO_LOAD is only "
                            + MAX_NUM_FRAMES_TO_LOAD);
        }

        FileChannel channel = fileStream.getChannel();
        int framesLoaded = 0;

        Log.i(TAG, "Populating " + numFramesToLoad + " frames");

        try {
            for (int i = 0; i < numFramesToLoad; i++) {
                Image inputImage = mWriter.dequeueInputImage();
                if (inputImage == null) {
                    break;
                }

                if (!fillImageFromFile(inputImage, channel)) {
                    break;
                }

                inputImage.setTimestamp(i * 1000000000L / mFps);
                mWriter.queueInputImage(inputImage);

                Image readableImage = mReader.acquireNextImage();
                if (readableImage != null) {
                    mFrameList.add(readableImage);
                    framesLoaded++;
                }
            }
        } finally {
            Log.i(TAG, "Populated " + framesLoaded + " frames");
        }
    }

    public ExecutorService encodeFrames(int totalFramesToSubmit) {
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

        if (mFrameList.isEmpty()) {
            Log.e(TAG, "No frames to encode");
            scheduler.shutdown();
            return scheduler;
        }

        AtomicInteger frameIndex = new AtomicInteger(0);
        long periodUs = 1_000_000 / mFps;

        var unused = scheduler.scheduleAtFixedRate(
                () -> {
                    int i = frameIndex.getAndIncrement();
                    try {
                        if (i >= totalFramesToSubmit) {
                            scheduler.shutdown();
                            return;
                        }

                        Integer index = mInputIndexQueue.poll(1, TimeUnit.SECONDS);
                        if (index == null) {
                            scheduler.shutdown();
                            return;
                        }

                        Image frame = mFrameList.get(i % mFrameList.size());
                        long ptsUs = i * 1_000_000L / mFps;
                        int flags =
                                (i == totalFramesToSubmit - 1)
                                        ? MediaCodec.BUFFER_FLAG_END_OF_STREAM
                                        : 0;

                        if (flags != 0) {
                            Log.i(TAG, "Sending EOS on frame " + i);
                        }

                        mCodec.getQueueRequest(index)
                                .setHardwareBuffer(frame.getHardwareBuffer())
                                .setPresentationTimeUs(ptsUs)
                                .setFlags(flags)
                                .queue();
                    } catch (Exception e) {
                        Log.e(TAG, "Encoding failed on frame " + i, e);
                        scheduler.shutdown();
                        throw new RuntimeException(e);
                    }
                },
                0,
                periodUs,
                TimeUnit.MICROSECONDS);

        return scheduler;
    }

    private boolean fillImageFromFile(Image image, FileChannel channel) throws IOException {
        Image.Plane[] planes = image.getPlanes();
        int width = image.getWidth();
        int height = image.getHeight();

        if (mPixelFormat.mFormat == ImageFormat.YUV_420_888) {
            ByteBuffer yBuf = planes[0].getBuffer();
            int yStride = planes[0].getRowStride();
            ByteBuffer rowData = ByteBuffer.allocate(width);

            for (int row = 0; row < height; row++) {
                rowData.clear();
                if (channel.read(rowData) < width) {
                    return false;
                }
                rowData.flip();
                yBuf.position(row * yStride);
                yBuf.put(rowData);
            }

            ByteBuffer uBuf = planes[1].getBuffer();
            ByteBuffer vBuf = planes[2].getBuffer();
            int uStride = planes[1].getRowStride();
            int vStride = planes[2].getRowStride();
            int uPixelStride = planes[1].getPixelStride();
            int vPixelStride = planes[2].getPixelStride();

            int uvHeight = height / 2;
            int uvWidth = width / 2;

            byte[] rowBytes = new byte[width];

            for (int row = 0; row < uvHeight; row++) {
                rowData.clear();
                if (channel.read(rowData) < width) {
                    return false;
                }
                rowData.flip();
                rowData.get(rowBytes);

                for (int col = 0; col < uvWidth; col++) {
                    byte uVal = rowBytes[col * 2];
                    byte vVal = rowBytes[col * 2 + 1];

                    uBuf.put(row * uStride + col * uPixelStride, uVal);
                    vBuf.put(row * vStride + col * vPixelStride, vVal);
                }
            }

            return true;
        } else if (mPixelFormat.mFormat == ImageFormat.YCBCR_P010) {
            ByteBuffer yBuf = planes[0].getBuffer();
            int yStride = planes[0].getRowStride();
            int rowSize = width * 2;
            ByteBuffer rowData = ByteBuffer.allocate(rowSize);

            for (int row = 0; row < height; row++) {
                rowData.clear();
                if (channel.read(rowData) < rowSize) {
                    return false;
                }
                rowData.flip();
                yBuf.position(row * yStride);
                yBuf.put(rowData);
            }

            ByteBuffer uvBuf = planes[1].getBuffer();
            int uvStride = planes[1].getRowStride();
            int uvHeight = height / 2;

            for (int row = 0; row < uvHeight; row++) {
                rowData.clear();
                if (channel.read(rowData) < rowSize) {
                    return false;
                }
                rowData.flip();
                uvBuf.position(row * uvStride);
                uvBuf.put(rowData);
            }
            return true;
        } else if (mPixelFormat.mFormat == android.graphics.PixelFormat.RGBA_8888
                || mPixelFormat.mFormat == android.graphics.PixelFormat.RGBA_1010102) {
            ByteBuffer buffer = planes[0].getBuffer();
            int rowStride = planes[0].getRowStride();
            int pixelStride = planes[0].getPixelStride();
            int bytesPerPixel = 4;
            int bytesPerRow = width * bytesPerPixel;
            ByteBuffer rowData = ByteBuffer.allocate(bytesPerRow);

            for (int row = 0; row < height; row++) {
                rowData.clear();
                if (channel.read(rowData) < bytesPerRow) {
                    return false;
                }
                rowData.flip();

                if (pixelStride == bytesPerPixel) {
                    buffer.position(row * rowStride);
                    buffer.put(rowData);
                } else {
                    byte[] rowBytes = rowData.array();
                    int rowOffset = row * rowStride;
                    for (int col = 0; col < width; col++) {
                        int srcIdx = col * bytesPerPixel;
                        int dstIdx = rowOffset + col * pixelStride;
                        buffer.put(dstIdx, rowBytes[srcIdx]);
                        buffer.put(dstIdx + 1, rowBytes[srcIdx + 1]);
                        buffer.put(dstIdx + 2, rowBytes[srcIdx + 2]);
                        buffer.put(dstIdx + 3, rowBytes[srcIdx + 3]);
                    }
                }
            }
            return true;
        }

        return false;
    }

    public void release() {
        for (Image image : mFrameList) {
            image.close();
        }
        mFrameList.clear();
        if (mWriter != null) {
            mWriter.close();
        }
        if (mReader != null) {
            mReader.close();
        }
    }
}
