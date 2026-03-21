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

    private static class PixelFormat {
        final int mFormat;

        PixelFormat(int codecFormat) {
            mFormat = switch (codecFormat) {
                case MediaCodecInfo.CodecCapabilities.COLOR_FormatYUV420Flexible ->
                        ImageFormat.YUV_420_888;
                case MediaCodecInfo.CodecCapabilities.COLOR_Format32bitABGR8888 ->
                        android.graphics.PixelFormat.RGBA_8888;
                case MediaCodecInfo.CodecCapabilities.COLOR_FormatYUVP010 ->
                        ImageFormat.YCBCR_P010;
                case MediaCodecInfo.CodecCapabilities.COLOR_Format32bitABGR2101010 ->
                        android.graphics.PixelFormat.RGBA_1010102;
                default -> throw new IllegalArgumentException(
                        "Unsupported format: 0x" + Integer.toHexString(codecFormat));
            };
        }
    }

    private final PixelFormat mPixelFormat;
    private final boolean mIsPvricFrameFormat;

    private ImageReader mReader;
    private ImageWriter mWriter;

    private final List<Image> mFrameList = new ArrayList<>();
    private final Native mNative = new Native();

    public FrameProducer(
            MediaCodec codec,
            BlockingQueue<Integer> inputIndexQueue,
            int width,
            int height,
            int fps,
            int codecFormat,
            boolean isPvricFrameFormat) {
        mCodec = codec;
        mInputIndexQueue = inputIndexQueue;
        mWidth = width;
        mHeight = height;
        mFps = fps;
        mPixelFormat = new PixelFormat(codecFormat);
        mIsPvricFrameFormat = isPvricFrameFormat;
        initializeAllocators();
    }

    private void initializeAllocators() {
        long usageFlags = HardwareBuffer.USAGE_VIDEO_ENCODE;

        // Add CPU flags if PVRIC is disabled since the CPU flags are disabling PVRIC in gralloc
        // layer.
        if (!mIsPvricFrameFormat) {
            usageFlags |=
                    HardwareBuffer.USAGE_CPU_READ_OFTEN | HardwareBuffer.USAGE_CPU_WRITE_OFTEN;
        }
        mReader =
                ImageReader.newInstance(
                        mWidth, mHeight, mPixelFormat.mFormat, MAX_NUM_FRAMES_TO_LOAD, usageFlags);
        mWriter =
                new ImageWriter.Builder(mReader.getSurface())
                        .setMaxImages(MAX_NUM_FRAMES_TO_LOAD)
                        .setUsage(usageFlags)
                        .build();
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
        if (mIsPvricFrameFormat) {
            int frameSize =
                    (int)getCompressedSize(
                                    getPvricFormat(),
                                    PvricTile.Tile_8x8,
                                    mWidth,
                                    mHeight,
                                    /* lossy= */ false);
            ByteBuffer data = ByteBuffer.allocateDirect(frameSize);
            while (data.hasRemaining()) {
                if (channel.read(data) == -1) {
                    Log.e(TAG, "Reached end of stream before filling frame buffer.");
                    return false;
                }
            }
            data.rewind();

            // Image.getPlanes() is disabled when PVRIC is enabled (by disabling CPU usage flags).
            // Therefore, using a native method to copy the data into the buffer instead of using
            // getPlanes().
            int status = mNative.NativeMemCopy(image.getHardwareBuffer(), data, frameSize);
            if (status < 0) {
                Log.e(TAG, "NativeMemCopy failed with status: " + status);
                return false;
            }
            return true;
        }
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

    // PVRIC Translation Helpers
    private enum PvricFormat {
        RGBA,
        NV12,
        P010,
        RGB16,
        RGB565
    }

    private enum PvricTile {
        Tile_8x8,
        Tile_16x4,
        Tile_32x2
    }

    private static class PvricPlaneDetail {
        final int width_subsampling;
        final int height_subsampling;
        final int compressed_body_bytes_per_sample;

        PvricPlaneDetail(int w, int h, int b, int c) {
            this.width_subsampling = w;
            this.height_subsampling = h;
            this.compressed_body_bytes_per_sample = c;
        }
    }

    private static class PvricCompressedPlaneDetail {
        final int width_alignment;
        final int height_alignment;

        PvricCompressedPlaneDetail(int w, int h) {
            this.width_alignment = w;
            this.height_alignment = h;
        }
    }

    private static class PvricCompressedDetail {
        long body_size;
        long unaligned_header_size;
        long header_size;
    }

    private PvricFormat getPvricFormat() {
        if (mPixelFormat.mFormat == ImageFormat.YUV_420_888) return PvricFormat.NV12;
        if (mPixelFormat.mFormat == android.graphics.PixelFormat.RGBA_8888) return PvricFormat.RGBA;
        if (mPixelFormat.mFormat == ImageFormat.YCBCR_P010) return PvricFormat.P010;
        throw new IllegalArgumentException(
                "Unsupported format for PVRIC: 0x" + Integer.toHexString(mPixelFormat.mFormat));
    }

    private static int align(int x, int y) {
        return x + (y - x % y) % y;
    }

    private static List<PvricPlaneDetail> getPlaneDetails(PvricFormat f) {
        List<PvricPlaneDetail> list = new ArrayList<>();
        switch (f) {
            case RGBA -> list.add(new PvricPlaneDetail(1, 1, 4, 4));
            case NV12 -> {
                list.add(new PvricPlaneDetail(1, 1, 1, 1));
                list.add(new PvricPlaneDetail(2, 2, 2, 2));
            }
            case P010 -> {
                list.add(new PvricPlaneDetail(1, 1, 2, 2));
                list.add(new PvricPlaneDetail(2, 2, 4, 4));
            }
            case RGB16 -> list.add(new PvricPlaneDetail(1, 1, 6, 8));
            case RGB565 -> list.add(new PvricPlaneDetail(1, 1, 2, 2));
        }
        return list;
    }

    private static List<PvricCompressedPlaneDetail> getCompressedPlaneDetails(
            PvricFormat f, PvricTile t) {
        List<PvricCompressedPlaneDetail> list = new ArrayList<>();
        switch (f) {
            case RGBA -> {
                if (t == PvricTile.Tile_8x8) list.add(new PvricCompressedPlaneDetail(8, 8));
                else if (t == PvricTile.Tile_16x4) list.add(new PvricCompressedPlaneDetail(16, 4));
            }
            case NV12 -> {
                if (t == PvricTile.Tile_8x8) {
                    list.add(new PvricCompressedPlaneDetail(32, 8));
                    list.add(new PvricCompressedPlaneDetail(16, 8));
                } else if (t == PvricTile.Tile_16x4) {
                    list.add(new PvricCompressedPlaneDetail(64, 4));
                    list.add(new PvricCompressedPlaneDetail(32, 4));
                }
            }
            case P010 -> {
                if (t == PvricTile.Tile_8x8) {
                    list.add(new PvricCompressedPlaneDetail(16, 8));
                    list.add(new PvricCompressedPlaneDetail(8, 8));
                } else if (t == PvricTile.Tile_16x4) {
                    list.add(new PvricCompressedPlaneDetail(32, 4));
                    list.add(new PvricCompressedPlaneDetail(16, 4));
                }
            }
            case RGB16 -> {
                if (t == PvricTile.Tile_32x2) list.add(new PvricCompressedPlaneDetail(32, 2));
            }
            case RGB565 -> {
                if (t == PvricTile.Tile_16x4) list.add(new PvricCompressedPlaneDetail(32, 4));
            }
        }
        return list;
    }

    private static List<PvricCompressedDetail> getCompressedDetails(
            PvricFormat format, PvricTile tile, int width, int height, boolean lossy) {
        final int kBytesInAHeader = 1;
        final int kBodyBytesPerHeader = 256;
        final int kHeaderAlignment = 256;
        final int kLosslessBodyBytesPerTile = kBodyBytesPerHeader;
        final int kLossyBodyBytesPerTile = 128;
        final int kLossyBodyBytesPerTileYuv10Pack16 = 96;

        int bodyBytesPerTile;
        if (!lossy) {
            bodyBytesPerTile = kLosslessBodyBytesPerTile;
        } else if (format == PvricFormat.P010) {
            bodyBytesPerTile = kLossyBodyBytesPerTileYuv10Pack16;
        } else {
            bodyBytesPerTile = kLossyBodyBytesPerTile;
        }

        List<PvricPlaneDetail> planeDetails = getPlaneDetails(format);
        List<PvricCompressedPlaneDetail> compressedPlaneDetails =
                getCompressedPlaneDetails(format, tile);

        if (planeDetails.size() != compressedPlaneDetails.size()) {
            throw new IllegalArgumentException(
                    "Plane details count does not match compressed plane details count for format "
                            + format
                            + " and tile "
                            + tile);
        }

        List<PvricCompressedDetail> out = new ArrayList<>();
        for (int idx = 0; idx < planeDetails.size(); idx++) {
            PvricPlaneDetail pd = planeDetails.get(idx);
            PvricCompressedPlaneDetail cpd = compressedPlaneDetails.get(idx);

            int thisWidth = align(width / pd.width_subsampling, cpd.width_alignment);
            int thisHeight = align(height / pd.height_subsampling, cpd.height_alignment);

            int tiles =
                    (thisWidth * thisHeight * pd.compressed_body_bytes_per_sample)
                            / kBodyBytesPerHeader;

            PvricCompressedDetail cd = new PvricCompressedDetail();
            cd.unaligned_header_size = (long) tiles * kBytesInAHeader;
            cd.header_size = align((int) cd.unaligned_header_size, kHeaderAlignment);
            cd.body_size = (long) tiles * bodyBytesPerTile;
            out.add(cd);
        }
        return out;
    }

    private static long getCompressedSize(
            PvricFormat format, PvricTile tile, int width, int height, boolean lossy) {
        long size = 0;
        for (PvricCompressedDetail cd : getCompressedDetails(format, tile, width, height, lossy)) {
            size += cd.header_size + cd.body_size;
        }
        return size;
    }
}
