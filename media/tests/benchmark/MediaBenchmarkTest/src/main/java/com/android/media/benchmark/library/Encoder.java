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
import android.media.MediaCodec.CodecException;
import android.media.MediaFormat;
import android.media.MediaMuxer;
import android.util.Log;
import android.view.Surface;

import androidx.annotation.NonNull;

import com.android.media.benchmark.library.BlockModelDecoder.LinearBlockWrapper;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class Encoder implements IBufferXfer.IConsumer {
    // Change in AUDIO_ENCODE_DEFAULT_MAX_INPUT_SIZE should also be taken to
    // kDefaultAudioEncodeFrameSize present in BenchmarkCommon.h
    private static final int TIMEOUT_IN_SEC_FOR_TASK = 2;
    private static final int AUDIO_ENCODE_DEFAULT_MAX_INPUT_SIZE = 4096;
    private static final String TAG = "Encoder";
    private static final boolean DEBUG = false;
    private static final int kQueueDequeueTimeoutUs = 1000;
    private final Object mLock = new Object();
    private final Object mFuturesLock = new Object();
    private MediaFormat mConfiguredInputFormat = null;
    private MediaCodec mCodec = null;
    private Muxer mMuxer = null;
    int mTrackIndex = -1;
    private String mMime;
    private Stats mStats;
    private long mInitTimeFragment = 0;
    private int mFlags = 0;

    private int mOffset;
    private int mFrameSize;
    private int mNumInputFrame;
    private int mNumFrames = 0;
    private int mFrameRate;
    private int mSampleRate;
    private long mInputBufferSize = 0;
    private int mMaxInputSizeForBlockModel = 4096;

    private int mMinOutputBuffers = 0;
    private int mNumOutputBuffers = 0;
    private boolean mUseSurface = false;

    private boolean mSawInputEOS;
    private boolean mSawOutputEOS;
    private boolean mSignalledError;

    private FileInputStream mInputStream = null;
    private FileOutputStream mOutputStream = null;

    private boolean mHandleSingleInfo = true;
    private boolean mFeederActive = false;
    final private ArrayDeque<MediaCodec.BufferInfo> mPendingInfos = new ArrayDeque<>();
    private final ArrayDeque<IBufferXfer.IProducerData> mReturnBuffers = new ArrayDeque<>();
    private final ArrayDeque<QueueData> mQueueDeque = new ArrayDeque<>();
    private final ArrayDeque<IBufferXfer.IProducerData> mProducerDataQueue = new ArrayDeque<>();
    private final ArrayDeque<Integer> mEncoderInputBufferQueue = new ArrayDeque<>();
    private final ArrayDeque<Future<?>> mSchedulerFutures = new ArrayDeque<>();
    private IBufferXfer.IProducer mProducer = null;

    // Need a thread to make sure that this works independently
    private final ExecutorService mScheduler = Executors.newFixedThreadPool(1);

    private final LinkedBlockingQueue<Integer> mInputIndexQueue = new LinkedBlockingQueue<>();
    private boolean mFrameProducerMode = false;

    /* success for encoder */
    public static final int ENCODE_SUCCESS = 0;
    /* some error happened during encoding */
    public static final int ENCODE_ENCODER_ERROR = -1;
    /* error while creating an encoder */
    public static final int ENCODE_CREATE_ERROR = -2;
    public Encoder() {
        mStats = new Stats();
        mNumInputFrame = 0;
        mSawInputEOS = false;
        mSawOutputEOS = false;
        mSignalledError = false;
    }

    private boolean isCodecInBlockModel() {
            return ((mFlags & MediaCodec.CONFIGURE_FLAG_USE_BLOCK_MODEL) != 0);
    }

    private class CodecBuffer {
        private LinearBlockWrapper mLinearBlock = null;
        private int mIdx = -1;
        private ByteBuffer mBuffer = null;

        CodecBuffer(int idx, int size) {
            recycle(idx, size);
        }

        public int getId() {
            return mIdx;
        }

        public LinearBlockWrapper getLinearBlock() {
            return mLinearBlock;
        }

        public int remaining() {
            if (isCodecInBlockModel()) {
                return isBufferValidInBlockModel() ? mLinearBlock.getBuffer().remaining() : 0;
            } else if (mBuffer != null) {
                return mBuffer.remaining();
            }
            return 0;
        }

        public void recycle(int bufferIdx, int size) {
            if (mLinearBlock != null) {
                release();
            }
            setBuffer(bufferIdx, size);
        }

        public void release() {
            if (mLinearBlock != null) {
                mLinearBlock.recycle();
            }
            mLinearBlock = null;
            mBuffer = null;
            mIdx = -1;
        }

        public boolean put(ByteBuffer buffer) {
            if (buffer == null) {
                return true;
            }
            if (isCodecInBlockModel()) {
                if (isBufferValidInBlockModel()) {
                    int size = buffer.remaining();
                    mLinearBlock.getBuffer().put(buffer);
                    mLinearBlock.setOffset(mLinearBlock.getOffset() + size);
                    return true;
                }

            } else if (mBuffer != null) {
                mBuffer.put(buffer);
                return true;
            }
            return false;
        }

        public boolean put(byte[] buffer, int offset, int size) {
            if (buffer == null) {
                return true;
            }
            if (isCodecInBlockModel()) {
                if (isBufferValidInBlockModel()) {
                    mLinearBlock.getBuffer().put(buffer, offset, size);
                    mLinearBlock.setOffset(offset + size);
                    return true;
                }

            } else if (mBuffer != null) {
                mBuffer.put(buffer, offset, size);
                return true;
            }
            return false;
        }

        private void setBuffer(int bufferIdx, int size) {
            if (isCodecInBlockModel()) {
                if (isBufferValidInBlockModel() == false) {
                    mLinearBlock = new LinearBlockWrapper();
                }
                if ((mLinearBlock.getBufferCapacity() - mLinearBlock.getOffset()) < size) {
                    mLinearBlock.allocateBlock(mCodec.getCanonicalName(), size);
                }
            } else {
                mBuffer = mCodec.getInputBuffer(bufferIdx);
            }
            mIdx = bufferIdx;
        }

        private boolean isBufferValidInBlockModel() {
            return (mLinearBlock != null);
        }
    }

    public void handleFuture(Future<?> future) {
        synchronized(mFuturesLock) {
            if (future != null) {
                mSchedulerFutures.add(future);
            }
            while (mSchedulerFutures.isEmpty() == false
                && mSchedulerFutures.peekFirst().isDone() == true) {
                Future<?> task = mSchedulerFutures.pollFirst();
                try {
                    task.get();
                } catch(Exception e) {
                    Log.d (TAG, "Scheduler encountered an exception " + e.toString());
                }
            }
        }
    }

    private static class QueueData {
        public CodecBuffer mBuffer;
        public ArrayDeque<MediaCodec.BufferInfo> mInfo;
    }

    @Override
    public boolean setProducer(@NonNull IBufferXfer.IProducer producer) {
        mProducer = producer;
        return true;
    }

    @Override
    public boolean consume(final ArrayDeque<IBufferXfer.IProducerData> buffers) {
        boolean shouldSchedule = false;
        synchronized(mLock) {
            mProducerDataQueue.addAll(buffers);
            shouldSchedule = (mEncoderInputBufferQueue.isEmpty() == false)
                    && (mFeederActive == false);
            if (shouldSchedule) {
                mFeederActive = true;
            }
        }
        if (shouldSchedule == true) {
            Future<?> future = mScheduler.submit(() -> { feedBuffersToEncoder(); });
            handleFuture(future);
        }
        return true;
    }

    private boolean queueBuffersArrayToCodec(ArrayDeque<QueueData> buffers) {
        if (buffers == null) {
            return false;
        }
        for (QueueData buffer : buffers) {
            queueBuffersToCodec(buffer.mBuffer, buffer.mInfo);
        }
        return true;
    }

    private boolean queueBuffersToCodec(
            CodecBuffer buffer, ArrayDeque<MediaCodec.BufferInfo> infos) {
        if (infos == null || infos.isEmpty()) {
            Log.d(TAG, "Problem with infos Cannot send buffers to codec");
            return false;
        }
        int nBuffers = infos.size();
        if (nBuffers == 1) {
            MediaCodec.BufferInfo info = infos.getFirst();
            if (isCodecInBlockModel()) {
                MediaCodec.QueueRequest request = mCodec.getQueueRequest(buffer.getId());
                request.setLinearBlock(
                        buffer.getLinearBlock().getBlock(), info.offset, info.size);
                request.setPresentationTimeUs(info.presentationTimeUs);
                request.setFlags(info.flags);
                request.queue();
            } else {
                mCodec.queueInputBuffer(
                        buffer.getId(),
                        info.offset,
                        info.size,
                        info.presentationTimeUs,
                        info.flags);
            }
         } else {
            if (isCodecInBlockModel()) {
                MediaCodec.QueueRequest request = mCodec.getQueueRequest(buffer.getId());
                request.setMultiFrameLinearBlock(buffer.getLinearBlock().getBlock(), infos);
                request.queue();
            } else {
                mCodec.queueInputBuffers(buffer.getId(), infos);
            }
         }
         mNumInputFrame += nBuffers;
         return true;
    }

    // Called from a thread
    private void feedBuffersToEncoder() {
        int processedBuffers = 0;
        synchronized(mLock) {
            mFeederActive = false;
            mQueueDeque.clear();
            mReturnBuffers.clear();
            if (mProducerDataQueue.isEmpty() == true
                    || mEncoderInputBufferQueue.isEmpty() == true) {
                Log.d(TAG, "Nothing to process, produced " + mProducerDataQueue.size()
                        + " # codec buffers " + mEncoderInputBufferQueue.size());
                return;
            }
            ArrayDeque<MediaCodec.BufferInfo> codecInfos = new ArrayDeque<>();
            IBufferXfer.IProducerData pData = null;
            ByteBuffer pBuffer = null;
            Iterator<MediaCodec.BufferInfo> pInfoCheck = null;
            Iterator<Integer> encoderBufIt = mEncoderInputBufferQueue.iterator();
            // first handle any pending infos
            if (mPendingInfos.isEmpty() == false) {
                // Log.d(TAG, "loading with pending size " + mPendingInfos.size());
                pData = mProducerDataQueue.peekFirst();
                pBuffer = pData.getBuffer();
                pInfoCheck = (pData != null && mPendingInfos.isEmpty() == false) ?
                        mPendingInfos.iterator() : null;
            } else {
                pData = mProducerDataQueue.peekFirst();
                pInfoCheck = (pData != null && pData.getInfo().isEmpty() == false) ?
                        pData.getInfo().iterator() : null;
                // Log.d(TAG, "loading with normal " + pData.getInfo().size());
                pBuffer = pData.getBuffer();
            }
            if (pInfoCheck == null || pInfoCheck.hasNext() == false) {
                Log.d(TAG, "Something wrong with input data, no infos found");
                return;
            }
            int encoderIdx = encoderBufIt.next();
            encoderBufIt.remove();
            //TODO for blockmodel
            if (pBuffer != null) {
                mMaxInputSizeForBlockModel = Math.max(
                        mMaxInputSizeForBlockModel, pBuffer.remaining());
            }
            CodecBuffer codecBuffer = new CodecBuffer(encoderIdx, mMaxInputSizeForBlockModel);
            if (DEBUG) {
                Log.d(TAG, "MaxInputSize for BlockModel " + mMaxInputSizeForBlockModel);
            }
            MediaCodec.BufferInfo currentPInfo = null;
            while (encoderIdx != -1) {
                int toCopy = 0;
                boolean handleSingleInfo = mHandleSingleInfo;
                boolean isArrayBackedBuffer =
                        (pBuffer != null && pBuffer.hasArray()) ? true : false;
                codecInfos.clear();
                if (currentPInfo == null && pInfoCheck.hasNext()) {
                    currentPInfo = pInfoCheck.next();
                }
                if (isArrayBackedBuffer == false) {
                    handleSingleInfo = false;
                }
                while (currentPInfo != null &&
                        ((toCopy + currentPInfo.size) <= codecBuffer.remaining())) {
                    toCopy += currentPInfo.size;
                    codecInfos.add(currentPInfo);
                    if (mPendingInfos.isEmpty() == false) {
                        pInfoCheck.remove();
                    }
                    currentPInfo = null;
                    if (handleSingleInfo == false && pInfoCheck.hasNext()) {
                        currentPInfo = pInfoCheck.next();
                    }
                }
                if (toCopy > 0) {
                    if (isArrayBackedBuffer == true) {
                        codecBuffer.put(pBuffer.array(), pBuffer.arrayOffset(), toCopy);
                    } else {
                        if (currentPInfo != null) {
                            Log.d(TAG,"Butter without backing size " + currentPInfo.size
                                    + "cannot fit into codec buffer size "
                                    + codecBuffer.remaining());
                            return;
                        }
                        codecBuffer.put(pBuffer);
                    }
                }
                if (codecInfos.isEmpty()) {
                    Log.d(TAG, "Cannot find any infos for codec id " + encoderIdx
                        + ", problem with input."
                        + " Codec Buffer size " + codecBuffer.remaining()
                        + " toCopy " + toCopy);
                    return;
                }
                QueueData qData = new QueueData();
                qData.mBuffer = codecBuffer;
                qData.mInfo = codecInfos.clone();
                mQueueDeque.add(qData);
                codecInfos.clear(); encoderIdx = -1;

                if (currentPInfo == null && pInfoCheck.hasNext() == false) {
                    mReturnBuffers.add(pData);
                    mProducerDataQueue.removeFirst();
                    processedBuffers++;
                }

                if (mPendingInfos.isEmpty() == true && encoderBufIt.hasNext() == false) {
                    if (currentPInfo != null) {
                        mPendingInfos.add(currentPInfo);
                        currentPInfo = null;
                    }
                    while (pInfoCheck.hasNext()) {
                        currentPInfo = pInfoCheck.next();
                        mPendingInfos.add(currentPInfo);
                        currentPInfo = null;
                    }
                }

                if (mProducerDataQueue.isEmpty() == false && encoderBufIt.hasNext() == true) {
                    // Continue if we have more producer and encoder buffer
                    encoderIdx = encoderBufIt.hasNext() ? encoderBufIt.next() : -1;
                    if (encoderIdx != -1) {
                        codecBuffer = new CodecBuffer(encoderIdx, mMaxInputSizeForBlockModel);
                        encoderBufIt.remove();
                        pData = mProducerDataQueue.peekFirst();
                        pBuffer = pData.getBuffer();
                        if (pData.getInfo() == null) {
                            Log.d(TAG, "Corrupted input data, wrong infos");
                            return;
                        }
                        if (currentPInfo == null && pInfoCheck.hasNext() == false) {
                            pInfoCheck = pData.getInfo().iterator();
                        }
                    }
                }
            }
        }
        if (mQueueDeque.isEmpty() == false) {
            queueBuffersArrayToCodec(mQueueDeque);
            for (QueueData data : mQueueDeque) {
                data.mBuffer.release();
            }
            mQueueDeque.clear();
        }
        if (mReturnBuffers.isEmpty() == false) {
            if (DEBUG) {
                Log.d(TAG, "Returning " + mReturnBuffers.size() + " buffers to producer");
            }
            mProducer.returnBuffers(mReturnBuffers);
        }
        if (DEBUG) {
            Log.d(TAG, "Processed " + processedBuffers + " during this call "
                    +  "remain: " + mProducerDataQueue.size());
        }
    }

    public Stats getStats() { return mStats; };

    /**
     * Setup of encoder
     *
     * @param encoderOutputStream Will dump the encoder output in this stream if not null.
     * @param fileInputStream     Will read the decoded output from this stream
     */
    public void setupEncoder(FileOutputStream encoderOutputStream,
                             FileInputStream fileInputStream) {
        this.mInputStream = fileInputStream;
        this.mOutputStream = encoderOutputStream;
    }
    /**
     * Setup of encoder
     *
     * @param useSurface, indicates that application is using surface for input
     * @param numOutputBuffers indicate the minimum buffers to signal Output
     * end of stream
     */
    public void setupEncoder(boolean useSurface, int numOutputBuffers) {
        this.mUseSurface = useSurface;
        this.mMinOutputBuffers = numOutputBuffers;
    }

    private MediaCodec createCodec_l(String codecName, String mime) throws IOException {
        try {
            MediaCodec codec;
            if (codecName.isEmpty()) {
                Log.i(TAG, "Mime type: " + mime);
                if (mime != null) {
                    codec = MediaCodec.createEncoderByType(mime);
                    Log.i(TAG, "Encoder created for mime type " + mime);
                    return codec;
                } else {
                    Log.e(TAG, "Mime type is null, please specify a mime type to create encoder");
                    return null;
                }
            } else {
                codec = MediaCodec.createByCodecName(codecName);
                Log.i(TAG, "Encoder created with codec name: " + codecName + " and mime: " + mime);
                return codec;
            }
        } catch (IllegalArgumentException ex) {
            ex.printStackTrace();
            Log.e(TAG, "Failed to create encoder for " + codecName + " mime: " + mime);
            return null;
        }
    }
    /**
     * Creates and configures the encoder with the given name, format and mime.
     * provided a valid list of parameters are passed as inputs. This is needed
     * to first configure the codec and then may be get surface etc and then
     * use for encode.
     *
     * @param codecName    Will create the encoder with codecName
     * @param mime         For creating encode format
     * @return ENCODE_SUCCESS if encode was successful,
     *         ENCODE_CREATE_ERROR for encoder not created
     * @throws IOException If the codec cannot be created.
     */

    public int createCodec(String codecName, String mime) throws IOException {
        if (mCodec == null) {
            long sTime = mStats.getCurTime();
            mMime = mime;
            mCodec = createCodec_l(codecName, mime);
            if (mCodec == null) {
                return ENCODE_CREATE_ERROR;
            }
            mInitTimeFragment += mStats.getTimeDiff(sTime, mStats.getCurTime());
        }
        return ENCODE_SUCCESS;
    }
    public MediaFormat getInputFormat() {
        return mConfiguredInputFormat;
    }
    public int configureCodec(MediaFormat encodeFormat, boolean asyncMode, int flags) {
        mFlags = flags;
        return configureCodec(encodeFormat, asyncMode);
    }
    public int configureCodec(MediaFormat encodeFormat, boolean asyncMode) {
        if (mCodec == null) {
            Log.d(TAG, "Cannot configure without a valid codec");
            return ENCODE_CREATE_ERROR;
        }
        long sTime = mStats.getCurTime();
        if (asyncMode) {
            setCallback();
        }
        /*Configure Codec*/
        try {
            mCodec.configure(encodeFormat, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE | mFlags);
        } catch(IllegalArgumentException
              | IllegalStateException
              | MediaCodec.CryptoException e) {
            Log.e(TAG, "Failed to configure " + mCodec.getName() + " encoder.");
            e.printStackTrace();
            return ENCODE_CREATE_ERROR;
        }
        mInitTimeFragment += mStats.getTimeDiff(sTime, mStats.getCurTime());
        mConfiguredInputFormat = mCodec.getInputFormat();
        return ENCODE_SUCCESS;
    }
    public void setCallback() {
        mCodec.setCallback(new MediaCodec.Callback() {
            @Override
            public void onInputBufferAvailable(@NonNull MediaCodec mediaCodec,
                                               int inputBufferId) {
                try {
                    mStats.addInputTime();
                    onInputAvailable(mediaCodec, inputBufferId);
                } catch (Exception e) {
                    e.printStackTrace();
                    Log.e(TAG, e.toString());
                }
            }

            @Override
            public void onOutputBufferAvailable(@NonNull MediaCodec mediaCodec,
                                                int outputBufferId,
                                                @NonNull MediaCodec.BufferInfo bufferInfo) {
                mStats.addOutputTime();
                onOutputAvailable(mediaCodec, outputBufferId, bufferInfo);
                if (mSawOutputEOS) {
                    Log.i(TAG, "Saw output EOS");
                    synchronized (mLock) { mLock.notify(); }
                }
            }

            @Override
            public void onOutputBuffersAvailable(@NonNull MediaCodec mediaCodec,
                                                int outputBufferId,
                                                @NonNull ArrayDeque<MediaCodec.BufferInfo> infos) {
                mStats.addOutputTime(infos.size());
                onOutputsAvailable(mediaCodec, outputBufferId, infos);
                if (mSawOutputEOS) {
                    Log.i(TAG, "Saw output EOS");
                    synchronized (mLock) { mLock.notify(); }
                }
            }

            @Override
            public void onError(@NonNull MediaCodec mediaCodec, @NonNull CodecException e) {
                mSignalledError = true;
                Log.e(TAG, "Codec Error: " + e.toString());
                e.printStackTrace();
                synchronized (mLock) { mLock.notify(); }
            }

            @Override
            public void onOutputFormatChanged(@NonNull MediaCodec mediaCodec,
                                              @NonNull MediaFormat format) {
                Log.i(TAG, "Output format changed. Format: " + format.toString());
                if (format != null) {
                    if (format.containsKey(MediaFormat.KEY_BUFFER_BATCH_MAX_OUTPUT_SIZE)) {
                        int maxOutputSize = format.getInteger(
                                MediaFormat.KEY_BUFFER_BATCH_MAX_OUTPUT_SIZE);
                        if (maxOutputSize > 0) {
                            Log.d(TAG, "Output format Large Audio max " + maxOutputSize);
                            mHandleSingleInfo = false;
                        }
                    }
                    if (mMuxer != null) {
                        try {
                            mTrackIndex = mMuxer.setUpMuxer(mOutputStream.getFD(),
                                    MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4, format);
                        } catch (IOException e) {
                            Log.d(TAG, "Muxer initialization failed.");
                            mTrackIndex = -1;
                            mMuxer.deInitMuxer();
                            mMuxer = null;
                        }
                    }
                }
            }
        });
    }
    /**
     * Requests the surface to use as input to the encoder
     * @return a valid surface or null if not called after configure.
     */
    public Surface getInputSurface() {
        if (mCodec == null) {
            Log.d(TAG, "Codec is null, cannot get input surface");
            return null;
        }
        return mCodec.createInputSurface();
    }
    /**
     * Encodes the given raw input file and measures the performance of encode operation,
     * provided a valid list of parameters are passed as inputs.
     *
     * @param codecName    Will create the encoder with codecName
     * @param mime         For creating encode format
     * @param encodeFormat Format of the output data
     * @param frameSize    Size of the frame
     * @param asyncMode    Will run on async implementation if true
     * @return ENCODE_SUCCESS if encode was successful ,ENCODE_ENCODER_ERROR for fail,
     *         ENCODE_CREATE_ERROR for encoder not created
     * @throws IOException If the codec cannot be created.
     */
    public int encode(String codecName, MediaFormat encodeFormat, String mime, int frameRate,
            int sampleRate, int frameSize, boolean asyncMode)
            throws IOException, InterruptedException {
        mInputBufferSize = (mInputStream != null) ? mInputStream.getChannel().size() : 0;
        mOffset = 0;
        mFrameRate = frameRate;
        mSampleRate = sampleRate;
        if (mCodec == null) {
            long sTime = mStats.getCurTime();
            int status = createCodec(codecName, mime);
            if(status != ENCODE_SUCCESS) {
              return status;
            }
            if (asyncMode) {
                setCallback();
            }
            status = configureCodec(encodeFormat, asyncMode);
            if (status != ENCODE_SUCCESS) {
                return status;
            }
            mInitTimeFragment += mStats.getTimeDiff(sTime, mStats.getCurTime());

        }
        if (mOutputStream != null) {
            mMuxer = new Muxer();
        }
        if (!mUseSurface) {
            if (mMime.startsWith("video/")) {
                mFrameSize = frameSize;
            } else {
                int maxInputSize = AUDIO_ENCODE_DEFAULT_MAX_INPUT_SIZE;
                MediaFormat format = mCodec.getInputFormat();
                if (format.containsKey(MediaFormat.KEY_MAX_INPUT_SIZE)) {
                    maxInputSize = format.getInteger(MediaFormat.KEY_MAX_INPUT_SIZE);
                }
                mFrameSize = frameSize;
                if (mFrameSize > maxInputSize && maxInputSize > 0) {
                    mFrameSize = maxInputSize;
                }
            }
            mNumFrames = (int) ((mInputBufferSize + mFrameSize - 1) / mFrameSize);
        }
        mCodec.start();
        if (mInitTimeFragment != 0) {
            mStats.setInitTime(mInitTimeFragment);
            mInitTimeFragment = 0;
        }
        mStats.setStartTime();
        if (asyncMode) {
            try {
                synchronized (mLock) {
                    while (!mSawOutputEOS && !mSignalledError) {
                        mLock.wait();
                    }
                    if (mSignalledError) {
                        return ENCODE_ENCODER_ERROR;
                    }
                }
            } catch (InterruptedException e) {
                throw e;
            }
        } else {
            while (!mSawOutputEOS && !mSignalledError) {
                /* Queue input data */
                if (!mSawInputEOS && !mUseSurface) {
                    int inputBufferId = mCodec.dequeueInputBuffer(kQueueDequeueTimeoutUs);
                    if (inputBufferId < 0 && inputBufferId != MediaCodec.INFO_TRY_AGAIN_LATER) {
                        Log.e(TAG, "MediaCodec.dequeueInputBuffer " + "returned invalid index : " +
                                inputBufferId);
                        return ENCODE_ENCODER_ERROR;
                    }
                    mStats.addInputTime();
                    onInputAvailable(mCodec, inputBufferId);
                }
                /* Dequeue output data */
                MediaCodec.BufferInfo outputBufferInfo = new MediaCodec.BufferInfo();
                int outputBufferId =
                        mCodec.dequeueOutputBuffer(outputBufferInfo, kQueueDequeueTimeoutUs);
                if (outputBufferId < 0) {
                    if (outputBufferId == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
                        MediaFormat outFormat = mCodec.getOutputFormat();
                        if (mMuxer != null) {
                            try {
                                mTrackIndex = mMuxer.setUpMuxer(mOutputStream.getFD(),
                                    MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4, outFormat);
                            } catch (IOException e) {
                                Log.d(TAG, "Muxer initialization failed.");
                                mTrackIndex = -1;
                                mMuxer.deInitMuxer();
                                mMuxer = null;
                            }
                        }
                        Log.i(TAG, "Output format changed. Format: " + outFormat.toString());
                    } else if (outputBufferId != MediaCodec.INFO_TRY_AGAIN_LATER) {
                        Log.e(TAG, "MediaCodec.dequeueOutputBuffer" + " returned invalid index " +
                                outputBufferId);
                        return ENCODE_ENCODER_ERROR;
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
        if (mMuxer != null && mTrackIndex != -1) {
            mMuxer.deInitMuxer();
            mMuxer.resetMuxer();
        }
        return ENCODE_SUCCESS;
    }

    /**
     * Encodes the given raw input file using FrameProducer, which loads the raw frames into RAM,
     * then feeds them to the encoder using QueueRequest.
     *
     * @param codecName Will create the encoder with codecName
     * @param encodeFormat Format of the output data
     * @param mime For creating encode format
     * @param frameRate Frame rate of the input file
     * @param inputStream Input stream of the raw file
     * @param numFramesToLoad Number of frames to load into RAM
     * @param loopTime Time to loop the input file
     * @return ENCODE_SUCCESS if encode was successful, ENCODE_ENCODER_ERROR for fail,
     *     ENCODE_CREATE_ERROR for encoder not created
     * @throws IOException If the codec cannot be created
     */
    public int encodeWithFrameProducer(
            String codecName,
            MediaFormat encodeFormat,
            String mime,
            int frameRate,
            FileInputStream inputStream,
            int numFramesToLoad,
            double loopTime,
            boolean isPvricFrameFormat)
            throws IOException, InterruptedException {
        mInputBufferSize = inputStream.getChannel().size();
        mFrameRate = frameRate;
        mFrameProducerMode = true;
        mInputIndexQueue.clear();

        if (mCodec == null) {
            int status = createCodec(codecName, mime);
            if (status != ENCODE_SUCCESS) return status;
        }

        if (mOutputStream != null) {
            mMuxer = new Muxer();
        }

        int status = configureCodec(encodeFormat, true, MediaCodec.CONFIGURE_FLAG_USE_BLOCK_MODEL);
        if (status != ENCODE_SUCCESS) return status;

        mCodec.start();
        mStats.setStartTime();

        int width = encodeFormat.getInteger(MediaFormat.KEY_WIDTH);
        int height = encodeFormat.getInteger(MediaFormat.KEY_HEIGHT);
        int inputFormat = encodeFormat.getInteger(MediaFormat.KEY_COLOR_FORMAT);

        FrameProducer producer =
                new FrameProducer(
                        mCodec,
                        mInputIndexQueue,
                        width,
                        height,
                        mFrameRate,
                        inputFormat,
                        isPvricFrameFormat);

        try {
            producer.loadFrames(inputStream, numFramesToLoad);

            int numFramesToFeed = (int) (loopTime * frameRate);
            ExecutorService producerExecutor = producer.encodeFrames(numFramesToFeed);

            synchronized (mLock) {
                while (!mSawOutputEOS && !mSignalledError) {
                    mLock.wait();
                }
            }
            producerExecutor.awaitTermination(10, TimeUnit.SECONDS);
            if (mSignalledError) return ENCODE_ENCODER_ERROR;
        } finally {
            mFrameProducerMode = false;
            producer.release();
        }

        if (mMuxer != null && mTrackIndex != -1) {
            mMuxer.deInitMuxer();
            mMuxer.resetMuxer();
        }

        return ENCODE_SUCCESS;
    }

    private void onOutputsAvailable(MediaCodec mediaCodec, int outputBufferId,
                                   ArrayDeque<MediaCodec.BufferInfo> infos) {
        if (mSawOutputEOS || outputBufferId < 0) {
            if (mSawOutputEOS) {
                Log.i(TAG, "Saw output EOS");
            }
            return;
        }
        ByteBuffer outputBuffer = null;
        MediaCodec.OutputFrame outFrame = null;
        if (isCodecInBlockModel()) {
            outFrame = mediaCodec.getOutputFrame(outputBufferId);
            try {
                if (outFrame.getLinearBlock() != null) {
                    outputBuffer = outFrame.getLinearBlock().map();
                }
            } catch(IllegalStateException e) {
                // buffer may not be linear, this is ok
                // as we are handling non-linear buffers below.
            }

        } else {
            outputBuffer = mediaCodec.getOutputBuffer(outputBufferId);
        }
        if (outputBuffer != null) {
            mStats.addFrameSize(outputBuffer.remaining());
            if (DEBUG) {
                Log.d(TAG,
                        "In OutputBufferAvailable ,"
                        + " info size = " + infos.size()
                        + " info first ts " + infos.getFirst().presentationTimeUs
                        + " total size = " + outputBuffer.remaining());
            }
        }

        if (mOutputStream != null) {
            if (mMuxer != null && mTrackIndex != -1) {
                mMuxer.mux(mTrackIndex, outputBuffer, infos);
            } else {
                try {
                    if (outputBuffer != null) {
                        byte[] bytesOutput = new byte[outputBuffer.remaining()];
                        outputBuffer.get(bytesOutput);
                        mOutputStream.write(bytesOutput);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    Log.d(TAG, "Error Dumping File: Exception " + e.toString());
                    return;
                }
            }
        }
        if (outFrame != null && (outFrame.getLinearBlock() != null)) {
            outFrame.getLinearBlock().recycle();
        }
        mNumOutputBuffers += infos.size();
        int flag = 0;
        if (!infos.isEmpty()) {
            flag = infos.peekLast().flags;
        }

        mediaCodec.releaseOutputBuffer(outputBufferId, false);
        mSawOutputEOS = (flag & MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0;
        if (mUseSurface && !mSawOutputEOS) {
            mSawOutputEOS = (mNumOutputBuffers >= mMinOutputBuffers) ? true : false;
        }
    }

    private void onOutputAvailable(MediaCodec mediaCodec, int outputBufferId,
                                   MediaCodec.BufferInfo outputBufferInfo) {
        if (mSawOutputEOS || outputBufferId < 0) {
            if (mSawOutputEOS) {
                Log.i(TAG, "Saw output EOS");
            }
            return;
        }
        ByteBuffer outputBuffer = null;
        MediaCodec.OutputFrame outFrame = null;
        if (isCodecInBlockModel()) {
            outFrame = mediaCodec.getOutputFrame(outputBufferId);
            try {
                if (outFrame.getLinearBlock() != null) {
                    outputBuffer = outFrame.getLinearBlock().map();
                }
            } catch(IllegalStateException e) {
                // buffer may not be linear, this is ok
                // as we are handling non-linear buffers below.
            }
        } else {
            outputBuffer = mediaCodec.getOutputBuffer(outputBufferId);
        }
        if (outputBuffer != null) {
            mStats.addFrameSize(outputBuffer.remaining());
        }
        if (mOutputStream != null) {
            if (mMuxer != null && mTrackIndex != -1) {
                ArrayDeque<MediaCodec.BufferInfo> infos = new ArrayDeque<>();
                infos.add(outputBufferInfo);
                mMuxer.mux(mTrackIndex, outputBuffer, infos);
            } else {
                try {
                    byte[] bytesOutput = new byte[outputBuffer.remaining()];
                    outputBuffer.get(bytesOutput);
                    mOutputStream.write(bytesOutput);
                } catch (IOException e) {
                    e.printStackTrace();
                    Log.d(TAG, "Error Dumping File: Exception " + e.toString());
                    return;
                }
            }

        }
        if ((outFrame != null) && (outFrame.getLinearBlock() != null)) {
            outFrame.getLinearBlock().recycle();
        }

        mNumOutputBuffers++;
        if (DEBUG) {
            Log.d(TAG,
                    "In OutputBufferAvailable ,"
                    + " timestamp = " + outputBufferInfo.presentationTimeUs
                    + " size = " + outputBufferInfo.size
                    + " flags = " + outputBufferInfo.flags);
        }

        mediaCodec.releaseOutputBuffer(outputBufferId, false);
        mSawOutputEOS = (outputBufferInfo.flags & MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0;
        if (mUseSurface && !mSawOutputEOS) {
            mSawOutputEOS = (mNumOutputBuffers >= mMinOutputBuffers) ? true : false;
        }
    }

    private void onInputAvailable(MediaCodec mediaCodec, int inputBufferId) throws IOException {
        if (mFrameProducerMode) {
            mInputIndexQueue.offer(inputBufferId);
            return;
        }
        if (mSawInputEOS || inputBufferId < 0 || this.mUseSurface) {
            if (mSawInputEOS) {
                Log.i(TAG, "Saw input EOS");
            }
            return;
        }
        if (mInputBufferSize < mOffset) {
            Log.e(TAG, "Out of bound access of input buffer");
            mSignalledError = true;
            return;
        }
        if (DEBUG) {
            Log.d(TAG, "onInputAvailable ID " + inputBufferId);
        }

        if (mProducer != null) {
            boolean shouldSchedule = false;
            synchronized(mLock) {
                mEncoderInputBufferQueue.add(inputBufferId);
                if ((mProducerDataQueue.isEmpty() == false)
                        && (mFeederActive == false)) {
                    shouldSchedule = true;
                    mFeederActive = true;
                }
            }
            if (shouldSchedule == true) {
                Future<?> future = mScheduler.submit(() -> { feedBuffersToEncoder(); });
                handleFuture(future);
            }
            return;
        }
        ByteBuffer inputBuffer = mCodec.getInputBuffer(inputBufferId);
        if (inputBuffer == null) {
            mSignalledError = true;
            return;
        }
        int bufSize = inputBuffer.capacity();
        int bytesToRead = mFrameSize;
        if (mInputBufferSize - mOffset < mFrameSize) {
            bytesToRead = (int) (mInputBufferSize - mOffset);
        }
        //b/148655275 - Update Frame size, as Format value may not be valid
        if (bufSize < bytesToRead) {
            if(mNumInputFrame == 0) {
                mFrameSize = bufSize;
                bytesToRead = bufSize;
                mNumFrames = (int) ((mInputBufferSize + mFrameSize - 1) / mFrameSize);
            } else {
                mSignalledError = true;
                return;
            }
        }

        byte[] inputArray = new byte[bytesToRead];
        mInputStream.read(inputArray, 0, bytesToRead);
        inputBuffer.put(inputArray);
        int flag = 0;
        if (mNumInputFrame >= mNumFrames - 1 || bytesToRead == 0) {
            Log.i(TAG, "Sending EOS on input last frame");
            mSawInputEOS = true;
            flag = MediaCodec.BUFFER_FLAG_END_OF_STREAM;
        }
        int presentationTimeUs;
        if (mMime.startsWith("video/")) {
            presentationTimeUs = mNumInputFrame * (1000000 / mFrameRate);
        } else {
            presentationTimeUs = mNumInputFrame * mFrameSize * 1000000 / mSampleRate;
        }
        mediaCodec.queueInputBuffer(inputBufferId, 0, bytesToRead, presentationTimeUs, flag);
        mNumInputFrame++;
        mOffset += bytesToRead;
    }

    /**
     * Stops the codec and releases codec resources.
     */
    public void deInitEncoder() {
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
        String operation = "encode";
        mStats.dumpStatistics(
                inputReference, operation, componentName, mode, durationUs, statsFile);
    }

    /**
     * Resets the stats
     */
    public void resetEncoder() {
        mOffset = 0;
        mInputBufferSize = 0;
        mNumInputFrame = 0;
        mMinOutputBuffers = 0;
        mSawInputEOS = false;
        mSawOutputEOS = false;
        mSignalledError = false;
        mUseSurface = false;
        mStats.reset();
        synchronized(mFuturesLock) {
            while (mSchedulerFutures.isEmpty() == false) {
                Future<?> future = mSchedulerFutures.pollFirst();
                try {
                    future.get(TIMEOUT_IN_SEC_FOR_TASK, TimeUnit.SECONDS);
                } catch (TimeoutException e) {
                    Log.d(TAG, "Future timed-out in scheduler " +  e.toString());
                    future.cancel(true);
                } catch (InterruptedException | ExecutionException e) {
                    Log.d(TAG, "Future exception in scheduler " + e.toString());
                }
            }
        }
        if (mScheduler != null) {
            mScheduler.shutdownNow();
        }
    }
}
