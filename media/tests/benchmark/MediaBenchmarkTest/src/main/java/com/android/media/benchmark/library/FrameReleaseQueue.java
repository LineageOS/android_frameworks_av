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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class FrameReleaseQueue {
    private static final String TAG = "FrameReleaseQueue";
    private final String MIME_AV1 = "video/av01";
    private final int AV1_SUPERFRAME_DELAY = 6;
    private final int THRESHOLD_TIME = 5;

    private MediaCodec mCodec;
    private LinkedBlockingQueue<FrameInfo> mFrameInfoQueue;
    private ReleaseThread mReleaseThread;
    private AtomicBoolean doFrameRelease = new AtomicBoolean(false);
    private boolean mReleaseJobStarted = false;
    private boolean mRender = false;
    private int mWaitTime = 40; // milliseconds per frame
    private int mWaitTimeCorrection = 0;
    private int mCorrectionLoopCount;
    private int firstReleaseTime = -1;
    private int mAllowedDelayTime = THRESHOLD_TIME;
    private int mFrameDelay = 0;
    private final ScheduledExecutorService mScheduler = Executors.newScheduledThreadPool(1);


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
        private int mLoopCount = 0;
        private int mNextReleaseTime = 0;

        @SuppressWarnings("FutureReturnValueIgnored")
        public void run() {
            /* Check if the release thread wakes up too late */
            if (mLoopCount != 0) {
                int delta = getCurSysTime() - mNextReleaseTime;
                if (delta >= THRESHOLD_TIME) {
                    Log.d(TAG, "Release thread wake up late by " + delta);
                    /* For accidental late wake up, we should relax the timestamp
                       check for display time */
                    mAllowedDelayTime = 1 + delta;
                } else {
                    mAllowedDelayTime = THRESHOLD_TIME;
                }
            }
            if (doFrameRelease.get() || mFrameInfoQueue.size() > 0) {
                FrameInfo curFrameInfo = mFrameInfoQueue.peek();
                if (curFrameInfo == null) {
                    mNextReleaseTime += mWaitTime;
                } else {
                    if (firstReleaseTime == -1 || curFrameInfo.displayTime <= 0) {
                        // first frame of loop
                        firstReleaseTime = getCurSysTime();
                        mNextReleaseTime = firstReleaseTime + mWaitTime;
                        popAndRelease(true);
                    } else if (!doFrameRelease.get() && mFrameInfoQueue.size() == 1) {
                        // EOS
                        Log.i(TAG, "EOS");
                        popAndRelease(false);
                    } else {
                        mNextReleaseTime += mWaitTime;
                        int curSysTime = getCurSysTime();
                        int curMediaTime = curSysTime - firstReleaseTime;
                        while (curFrameInfo != null && curFrameInfo.displayTime > 0 &&
                                curFrameInfo.displayTime <= curMediaTime) {
                            if (!((curMediaTime - curFrameInfo.displayTime) <= mAllowedDelayTime)) {
                                Log.d(TAG, "Dropping expired frame " + curFrameInfo.number +
                                    " display time " + curFrameInfo.displayTime +
                                    " current time " + curMediaTime);
                                popAndRelease(false);
                            } else {
                                popAndRelease(true);
                            }
                            curFrameInfo = mFrameInfoQueue.peek();
                        }
                        if (curFrameInfo != null && curFrameInfo.displayTime > curMediaTime) {
                            if ((curFrameInfo.displayTime - curMediaTime) < THRESHOLD_TIME) {
                                // release the frame now as we are already there
                                popAndRelease(true);
                            }
                        }
                    }
                }

                long sleepTime = (long)(mNextReleaseTime - getCurSysTime());
                mScheduler.schedule(mReleaseThread, sleepTime, TimeUnit.MILLISECONDS);

                if (mLoopCount % mCorrectionLoopCount == 0) {
                    mNextReleaseTime += mWaitTimeCorrection;
                }
                mLoopCount += 1;
            }
        }
    }

    public FrameReleaseQueue(boolean render, int frameRate) {
        this.mFrameInfoQueue = new LinkedBlockingQueue();
        this.mReleaseThread = new ReleaseThread();
        this.doFrameRelease.set(true);
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

    public void setMime(String mime) {
        if (mime.equals(MIME_AV1)) {
            mFrameDelay = AV1_SUPERFRAME_DELAY;
        }
    }

    public boolean pushFrame(int frameNumber, int frameBufferId, long frameDisplayTime) {
        int frameDisplayTimeMs = (int)(frameDisplayTime/1000);
        FrameInfo curFrameInfo = new FrameInfo(frameNumber, frameBufferId, frameDisplayTimeMs);
        boolean pushSuccess = mFrameInfoQueue.offer(curFrameInfo);
        if (!pushSuccess) {
            Log.e(TAG, "Failed to push frame with buffer id " + curFrameInfo.bufferId);
            return false;
        }

        if (!mReleaseJobStarted && frameNumber >= mFrameDelay) {
            mScheduler.execute(mReleaseThread);
            mReleaseJobStarted = true;
            Log.i(TAG, "Started frame release thread");
        }
        return true;
    }

    private int getCurSysTime() {
        return (int)(System.nanoTime()/1000000);
    }

    @SuppressWarnings("FutureReturnValueIgnored")
    private void popAndRelease(boolean renderThisFrame) {
        final boolean actualRender = (renderThisFrame && mRender);
        try {
            final FrameInfo curFrameInfo = mFrameInfoQueue.take();

            CompletableFuture.runAsync(() -> {
                try {
                    mCodec.releaseOutputBuffer(curFrameInfo.bufferId, actualRender);
                } catch (IllegalStateException e) {
                    e.printStackTrace();
                }
            });

        } catch (InterruptedException e) {
            Log.e(TAG, "Threw InterruptedException on take");
        }
    }

    public void stopFrameRelease() {
        doFrameRelease.set(false);
        while (mFrameInfoQueue.size() > 0) {
            try {
                TimeUnit.SECONDS.sleep(1);
            } catch (InterruptedException e) {
                Log.e(TAG, "Threw InterruptedException on sleep");
            }
        }
    }
}

