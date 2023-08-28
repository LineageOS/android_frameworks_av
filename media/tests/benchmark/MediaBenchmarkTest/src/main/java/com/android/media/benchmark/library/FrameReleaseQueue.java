/*
 * Copyright (C) 2022 The Android Open Source Project
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
import android.util.Log;
import androidx.annotation.NonNull;
import java.nio.ByteBuffer;
import java.util.concurrent.LinkedBlockingQueue;

public class FrameReleaseQueue {
    private static final String TAG = "FrameReleaseQueue";

    private MediaCodec mCodec;
    private LinkedBlockingQueue<FrameInfo> mFrameInfoQueue;
    private ReleaseThread mReleaseThread;
    private boolean doFrameRelease = false;
    private boolean mRender = false;
    private int mWaitTime = 40; // milliseconds per frame
    private int mWaitTimeCorrection = 0;
    private int mCorrectionLoopCount;
    private int firstReleaseTime = -1;
    private int THRESHOLD_TIME = 5;

    private static class FrameInfo {
        private int number;
        private int bufferId;
        private int displayTime;
        public FrameInfo(int frameNumber, int frameBufferId, int frameDisplayTime) {
            this.number = frameNumber;
            this.bufferId = frameBufferId;
            this.displayTime = frameDisplayTime;
        }
    }

    private class ReleaseThread extends Thread {
        public void run() {
            int nextReleaseTime = 0;
            int loopCount = 0;
            while (doFrameRelease || mFrameInfoQueue.size() > 0) {
                FrameInfo curFrameInfo = mFrameInfoQueue.peek();
                if (curFrameInfo == null) {
                    nextReleaseTime += mWaitTime;
                } else {
                    if (curFrameInfo.displayTime == 0) {
                        // first frame of loop
                        firstReleaseTime = getCurSysTime();
                        nextReleaseTime = firstReleaseTime + mWaitTime;
                        popAndRelease(curFrameInfo, true);
                    } else if (!doFrameRelease && mFrameInfoQueue.size() == 1) {
                        // EOS
                        Log.i(TAG, "EOS");
                        popAndRelease(curFrameInfo, false);
                    } else {
                        nextReleaseTime += mWaitTime;
                        int curSysTime = getCurSysTime();
                        int curMediaTime = curSysTime - firstReleaseTime;
                        while (curFrameInfo != null && curFrameInfo.displayTime > 0 &&
                                curFrameInfo.displayTime <= curMediaTime) {
                            if (!((curMediaTime - curFrameInfo.displayTime) < THRESHOLD_TIME)) {
                                Log.d(TAG, "Dropping expired frame " + curFrameInfo.number +
                                    " display time " + curFrameInfo.displayTime +
                                    " current time " + curMediaTime);
                                popAndRelease(curFrameInfo, false);
                            } else {
                                popAndRelease(curFrameInfo, true);
                            }
                            curFrameInfo = mFrameInfoQueue.peek();
                        }
                        if (curFrameInfo != null && curFrameInfo.displayTime > curMediaTime) {
                            if ((curFrameInfo.displayTime - curMediaTime) < THRESHOLD_TIME) {
                                popAndRelease(curFrameInfo, true);
                            }
                        }
                    }
                }
                int sleepTime = nextReleaseTime - getCurSysTime();
                if (sleepTime > 0) {
                    try {
                        mReleaseThread.sleep(sleepTime);
                    } catch (InterruptedException e) {
                        Log.e(TAG, "Threw InterruptedException on sleep");
                    }
                } else {
                    Log.d(TAG, "Thread sleep time less than 1");
                }
                if (loopCount % mCorrectionLoopCount == 0) {
                    nextReleaseTime += mWaitTimeCorrection;
                }
                loopCount += 1;
            }
        }
    }

    public FrameReleaseQueue(boolean render, int frameRate) {
        this.mFrameInfoQueue = new LinkedBlockingQueue();
        this.mReleaseThread = new ReleaseThread();
        this.doFrameRelease = true;
        this.mRender = render;
        this.mWaitTime = 1000 / frameRate; // wait time in milliseconds per frame
        int waitTimeRemainder = 1000 % frameRate;
        int gcd = gcd(frameRate, waitTimeRemainder);
        this.mCorrectionLoopCount = frameRate / gcd;
        this.mWaitTimeCorrection = waitTimeRemainder / gcd;
        Log.i(TAG, "Constructed FrameReleaseQueue with wait time " + this.mWaitTime + " ms");
    }

    private static int gcd(int a, int b) {
        return b == 0 ? a : gcd(b, a % b);
    }

    public void setMediaCodec(MediaCodec mediaCodec) {
        this.mCodec = mediaCodec;
    }

    public boolean pushFrame(int frameNumber, int frameBufferId, long frameDisplayTime) {
        int frameDisplayTimeMs = (int)(frameDisplayTime/1000);
        FrameInfo curFrameInfo = new FrameInfo(frameNumber, frameBufferId, frameDisplayTimeMs);
        boolean pushSuccess = mFrameInfoQueue.offer(curFrameInfo);
        if (!pushSuccess) {
            Log.e(TAG, "Failed to push frame with buffer id " + curFrameInfo.bufferId);
            return false;
        }
        if (!mReleaseThread.isAlive()) {
            mReleaseThread.start();
            Log.i(TAG, "Started frame release thread");
        }
        return true;
    }

    private int getCurSysTime() {
        return (int)(System.nanoTime()/1000000);
    }

    private void popAndRelease(FrameInfo curFrameInfo, boolean renderThisFrame) {
        try {
            curFrameInfo = mFrameInfoQueue.take();
        } catch (InterruptedException e) {
            Log.e(TAG, "Threw InterruptedException on take");
        }
        boolean actualRender = (renderThisFrame && mRender);
        try {
            mCodec.releaseOutputBuffer(curFrameInfo.bufferId, actualRender);
        } catch (IllegalStateException e) {
            Log.e(TAG,
                    "Threw IllegalStateException on releaseOutputBuffer for frame "
                            + curFrameInfo.number);
        }
    }

    public void stopFrameRelease() {
        doFrameRelease = false;
        try {
            mReleaseThread.join();
            Log.i(TAG, "Joined frame release thread");
        } catch (InterruptedException e) {
            Log.e(TAG, "Threw InterruptedException on thread join");
        }
    }
}

