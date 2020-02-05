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

package com.android.media.benchmark.library;

import android.media.MediaCodec;
import android.media.MediaCodec.BufferInfo;
import android.media.MediaFormat;
import android.util.Log;

import androidx.annotation.NonNull;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;

public class Decoder {
    private static final String TAG = "Decoder";
    private static final boolean DEBUG = false;
    private static final int kQueueDequeueTimeoutUs = 1000;

    private final Object mLock = new Object();
    private MediaCodec mCodec;
    private ArrayList<BufferInfo> mInputBufferInfo;
    private Stats mStats;

    private boolean mSawInputEOS;
    private boolean mSawOutputEOS;
    private boolean mSignalledError;

    private int mNumOutputFrame;
    private int mIndex;

    private ArrayList<ByteBuffer> mInputBuffer;
    private FileOutputStream mOutputStream;

    public Decoder() { mStats = new Stats(); }

    /**
     * Setup of decoder
     *
     * @param outputStream Will dump the output in this stream if not null.
     */
    public void setupDecoder(FileOutputStream outputStream) {
        mSignalledError = false;
        mOutputStream = outputStream;
    }

    private MediaCodec createCodec(String codecName, MediaFormat format) throws IOException {
        String mime = format.getString(MediaFormat.KEY_MIME);
        try {
            MediaCodec codec;
            if (codecName.isEmpty()) {
                Log.i(TAG, "File mime type: " + mime);
                if (mime != null) {
                    codec = MediaCodec.createDecoderByType(mime);
                    Log.i(TAG, "Decoder created for mime type " + mime);
                    return codec;
                } else {
                    Log.e(TAG, "Mime type is null, please specify a mime type to create decoder");
                    return null;
                }
            } else {
                codec = MediaCodec.createByCodecName(codecName);
                Log.i(TAG, "Decoder created with codec name: " + codecName + " mime: " + mime);
                return codec;
            }
        } catch (IllegalArgumentException ex) {
            ex.printStackTrace();
            Log.e(TAG, "Failed to create decoder for " + codecName + " mime:" + mime);
            return null;
        }
    }

    /**
     * Decodes the given input buffer,
     * provided valid list of buffer info and format are passed as inputs.
     *
     * @param inputBuffer     Decode the provided list of ByteBuffers
     * @param inputBufferInfo List of buffer info corresponding to provided input buffers
     * @param asyncMode       Will run on async implementation if true
     * @param format          For creating the decoder if codec name is empty and configuring it
     * @param codecName       Will create the decoder with codecName
     * @return 0 if decode was successful , -1 for fail, -2 for decoder not created
     * @throws IOException if the codec cannot be created.
     */
    public int decode(@NonNull ArrayList<ByteBuffer> inputBuffer,
            @NonNull ArrayList<BufferInfo> inputBufferInfo, final boolean asyncMode,
            @NonNull MediaFormat format, String codecName) throws IOException {
        mInputBuffer = new ArrayList<>(inputBuffer.size());
        mInputBuffer.addAll(inputBuffer);
        mInputBufferInfo = new ArrayList<>(inputBufferInfo.size());
        mInputBufferInfo.addAll(inputBufferInfo);
        mSawInputEOS = false;
        mSawOutputEOS = false;
        mNumOutputFrame = 0;
        mIndex = 0;
        long sTime = mStats.getCurTime();
        mCodec = createCodec(codecName, format);
        if (mCodec == null) {
            return -2;
        }
        if (asyncMode) {
            mCodec.setCallback(new MediaCodec.Callback() {
                @Override
                public void onInputBufferAvailable(
                        @NonNull MediaCodec mediaCodec, int inputBufferId) {
                    try {
                        mStats.addInputTime();
                        onInputAvailable(inputBufferId, mediaCodec);
                    } catch (Exception e) {
                        e.printStackTrace();
                        Log.e(TAG, e.toString());
                    }
                }

                @Override
                public void onOutputBufferAvailable(@NonNull MediaCodec mediaCodec,
                        int outputBufferId, @NonNull MediaCodec.BufferInfo bufferInfo) {
                    mStats.addOutputTime();
                    onOutputAvailable(mediaCodec, outputBufferId, bufferInfo);
                    if (mSawOutputEOS) {
                        synchronized (mLock) { mLock.notify(); }
                    }
                }

                @Override
                public void onOutputFormatChanged(
                        @NonNull MediaCodec mediaCodec, @NonNull MediaFormat format) {
                    Log.i(TAG, "Output format changed. Format: " + format.toString());
                }

                @Override
                public void onError(
                        @NonNull MediaCodec mediaCodec, @NonNull MediaCodec.CodecException e) {
                    mSignalledError = true;
                    Log.e(TAG, "Codec Error: " + e.toString());
                    e.printStackTrace();
                    synchronized (mLock) { mLock.notify(); }
                }
            });
        }
        int isEncoder = 0;
        if (DEBUG) {
            Log.d(TAG, "Media Format : " + format.toString());
        }
        mCodec.configure(format, null, null, isEncoder);
        mCodec.start();
        Log.i(TAG, "Codec started ");
        long eTime = mStats.getCurTime();
        mStats.setInitTime(mStats.getTimeDiff(sTime, eTime));
        mStats.setStartTime();
        if (asyncMode) {
            try {
                synchronized (mLock) { mLock.wait(); }
                if (mSignalledError) {
                    return -1;
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        } else {
            while (!mSawOutputEOS && !mSignalledError) {
                /* Queue input data */
                if (!mSawInputEOS) {
                    int inputBufferId = mCodec.dequeueInputBuffer(kQueueDequeueTimeoutUs);
                    if (inputBufferId < 0 && inputBufferId != MediaCodec.INFO_TRY_AGAIN_LATER) {
                        Log.e(TAG,
                                "MediaCodec.dequeueInputBuffer "
                                        + " returned invalid index : " + inputBufferId);
                        return -1;
                    }
                    mStats.addInputTime();
                    onInputAvailable(inputBufferId, mCodec);
                }
                /* Dequeue output data */
                BufferInfo outputBufferInfo = new BufferInfo();
                int outputBufferId =
                        mCodec.dequeueOutputBuffer(outputBufferInfo, kQueueDequeueTimeoutUs);
                if (outputBufferId < 0) {
                    if (outputBufferId == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
                        MediaFormat outFormat = mCodec.getOutputFormat();
                        Log.i(TAG, "Output format changed. Format: " + outFormat.toString());
                    } else if (outputBufferId == MediaCodec.INFO_OUTPUT_BUFFERS_CHANGED) {
                        Log.i(TAG, "Ignoring deprecated flag: INFO_OUTPUT_BUFFERS_CHANGED");
                    } else if (outputBufferId != MediaCodec.INFO_TRY_AGAIN_LATER) {
                        Log.e(TAG,
                                "MediaCodec.dequeueOutputBuffer"
                                        + " returned invalid index " + outputBufferId);
                        return -1;
                    }
                } else {
                    mStats.addOutputTime();
                    if (DEBUG) {
                        Log.d(TAG, "Dequeue O/P buffer with BufferID " + outputBufferId);
                    }
                    onOutputAvailable(mCodec, outputBufferId, outputBufferInfo);
                }
            }
        }
        mInputBuffer.clear();
        mInputBufferInfo.clear();
        return 0;
    }

    /**
     * Stops the codec and releases codec resources.
     */
    public void deInitCodec() {
        long sTime = mStats.getCurTime();
        if (mCodec != null) {
            mCodec.stop();
            mCodec.release();
            mCodec = null;
        }
        long eTime = mStats.getCurTime();
        mStats.setDeInitTime(mStats.getTimeDiff(sTime, eTime));
    }

    /**
     * Prints out the statistics in the information log
     *
     * @param inputReference The operation being performed, in this case decode
     * @param componentName  Name of the component/codec
     * @param mode           The operating mode: Sync/Async
     * @param durationUs     Duration of the clip in microseconds
     * @param statsFile      The output file where the stats data is written
     */
    public void dumpStatistics(String inputReference, String componentName, String mode,
            long durationUs, String statsFile) throws IOException {
        String operation = "decode";
        mStats.dumpStatistics(
                inputReference, operation, componentName, mode, durationUs, statsFile);
    }

    /**
     * Resets the stats
     */
    public void resetDecoder() { mStats.reset(); }

    /**
     * Returns the format of the output buffers
     */
    public MediaFormat getFormat() {
        return mCodec.getOutputFormat();
    }

    private void onInputAvailable(int inputBufferId, MediaCodec mediaCodec) {
        if ((inputBufferId >= 0) && !mSawInputEOS) {
            ByteBuffer inputCodecBuffer = mediaCodec.getInputBuffer(inputBufferId);
            BufferInfo bufInfo = mInputBufferInfo.get(mIndex);
            inputCodecBuffer.put(mInputBuffer.get(mIndex).array());
            mIndex++;
            mSawInputEOS = (bufInfo.flags & MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0;
            if (mSawInputEOS) {
                Log.i(TAG, "Saw input EOS");
            }
            mStats.addFrameSize(bufInfo.size);
            mediaCodec.queueInputBuffer(inputBufferId, bufInfo.offset, bufInfo.size,
                    bufInfo.presentationTimeUs, bufInfo.flags);
            if (DEBUG) {
                Log.d(TAG,
                        "Codec Input: "
                                + "flag = " + bufInfo.flags + " timestamp = "
                                + bufInfo.presentationTimeUs + " size = " + bufInfo.size);
            }
        }
    }

    private void onOutputAvailable(
            MediaCodec mediaCodec, int outputBufferId, BufferInfo outputBufferInfo) {
        if (mSawOutputEOS || outputBufferId < 0) {
            return;
        }
        mNumOutputFrame++;
        if (DEBUG) {
            Log.d(TAG,
                    "In OutputBufferAvailable ,"
                            + " output frame number = " + mNumOutputFrame);
        }
        if (mOutputStream != null) {
            try {
                ByteBuffer outputBuffer = mediaCodec.getOutputBuffer(outputBufferId);
                byte[] bytesOutput = new byte[outputBuffer.remaining()];
                outputBuffer.get(bytesOutput);
                mOutputStream.write(bytesOutput);
            } catch (IOException e) {
                e.printStackTrace();
                Log.d(TAG, "Error Dumping File: Exception " + e.toString());
            }
        }
        mediaCodec.releaseOutputBuffer(outputBufferId, false);
        mSawOutputEOS = (outputBufferInfo.flags & MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0;
        if (mSawOutputEOS) {
            Log.i(TAG, "Saw output EOS");
        }
    }
}
