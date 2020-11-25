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

import android.media.MediaCodec;
import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.media.MediaFormat;
import android.os.Build;
import android.util.Log;
import android.util.Pair;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

class CodecAsyncHandler extends MediaCodec.Callback {
    private static final String TAG = CodecAsyncHandler.class.getSimpleName();
    private final Lock mLock = new ReentrantLock();
    private final Condition mCondition = mLock.newCondition();
    private final LinkedList<Pair<Integer, MediaCodec.BufferInfo>> mCbInputQueue;
    private final LinkedList<Pair<Integer, MediaCodec.BufferInfo>> mCbOutputQueue;
    private volatile boolean mSignalledError;

    CodecAsyncHandler() {
        mCbInputQueue = new LinkedList<>();
        mCbOutputQueue = new LinkedList<>();
        mSignalledError = false;
    }

    void clearQueues() {
        mLock.lock();
        mCbInputQueue.clear();
        mCbOutputQueue.clear();
        mLock.unlock();
    }

    void resetContext() {
        clearQueues();
        mSignalledError = false;
    }

    @Override
    public void onInputBufferAvailable(MediaCodec codec, int bufferIndex) {
        mLock.lock();
        mCbInputQueue.add(new Pair<>(bufferIndex, (MediaCodec.BufferInfo) null));
        mCondition.signalAll();
        mLock.unlock();
    }

    @Override
    public void onOutputBufferAvailable(MediaCodec codec, int bufferIndex,
                                        MediaCodec.BufferInfo info) {
        mLock.lock();
        mCbOutputQueue.add(new Pair<>(bufferIndex, info));
        mCondition.signalAll();
        mLock.unlock();
    }

    @Override
    public void onError(MediaCodec codec, MediaCodec.CodecException e) {
        mLock.lock();
        mSignalledError = true;
        mCondition.signalAll();
        mLock.unlock();
        Log.e(TAG, "Received media codec error : " + e.getMessage());
    }

    @Override
    public void onOutputFormatChanged(MediaCodec codec, MediaFormat format) {
        Log.i(TAG, "Output format changed: " + format.toString());
    }

    void setCallBack(MediaCodec codec, boolean isCodecInAsyncMode) {
        if (isCodecInAsyncMode) {
            codec.setCallback(this);
        }
    }

    Pair<Integer, MediaCodec.BufferInfo> getOutput() throws InterruptedException {
        Pair<Integer, MediaCodec.BufferInfo> element = null;
        mLock.lock();
        while (!mSignalledError) {
            if (mCbOutputQueue.isEmpty()) {
                mCondition.await();
            } else {
                element = mCbOutputQueue.remove(0);
                break;
            }
        }
        mLock.unlock();
        return element;
    }

    Pair<Integer, MediaCodec.BufferInfo> getWork() throws InterruptedException {
        Pair<Integer, MediaCodec.BufferInfo> element = null;
        mLock.lock();
        while (!mSignalledError) {
            if (mCbInputQueue.isEmpty() && mCbOutputQueue.isEmpty()) {
                mCondition.await();
            } else {
                if (!mCbOutputQueue.isEmpty()) {
                    element = mCbOutputQueue.remove(0);
                    break;
                }
                if (!mCbInputQueue.isEmpty()) {
                    element = mCbInputQueue.remove(0);
                    break;
                }
            }
        }
        mLock.unlock();
        return element;
    }

    boolean hasSeenError() {
        return mSignalledError;
    }
}

abstract public class MediaCodecBase {
    static ArrayList<String> selectCodecs(String mime, ArrayList<MediaFormat> formats,
                                          String[] features, boolean isEncoder,
                                          boolean isSoftware) {

        MediaCodecList codecList = new MediaCodecList(MediaCodecList.REGULAR_CODECS);
        MediaCodecInfo[] codecInfos = codecList.getCodecInfos();
        ArrayList<String> listOfCodecs = new ArrayList<>();
        for (MediaCodecInfo codecInfo : codecInfos) {
            if (isEncoder) {
                if (!codecInfo.isEncoder()) continue;
            } else {
                if (codecInfo.isEncoder()) continue;
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && codecInfo.isAlias()) continue;
            String[] types = codecInfo.getSupportedTypes();
            for (String type : types) {
                if (type.equalsIgnoreCase(mime)) {
                    boolean isOk = true;
                    MediaCodecInfo.CodecCapabilities codecCapabilities =
                            codecInfo.getCapabilitiesForType(type);
                    if (formats != null) {
                        for (MediaFormat format : formats) {
                            if (!codecCapabilities.isFormatSupported(format)) {
                                isOk = false;
                                break;
                            }
                        }
                    }
                    if (features != null) {
                        for (String feature : features) {
                            if (!codecCapabilities.isFeatureSupported(feature)) {
                                isOk = false;
                                break;
                            }
                        }
                    }
                    if (isSoftware) {
                        if (codecInfo.getName().contains("software") ||
                                codecInfo.getName().contains("android") ||
                                codecInfo.getName().contains("google")) {
                            if (isOk) listOfCodecs.add(codecInfo.getName());
                        }
                    } else {
                        if (codecInfo.getName().contains("software") ||
                                codecInfo.getName().contains("android") ||
                                codecInfo.getName().contains("google")) {
                            continue;
                        } else {
                            if (isOk) listOfCodecs.add(codecInfo.getName());
                        }
                    }
                }
            }
        }
        return listOfCodecs;
    }
}
