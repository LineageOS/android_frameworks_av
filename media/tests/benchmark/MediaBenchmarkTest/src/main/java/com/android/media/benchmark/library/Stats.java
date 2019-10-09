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

import android.util.Log;

import java.util.ArrayList;

/**
 * Measures Performance.
 */
public class Stats {
    private static final String TAG = "Stats";
    private long mInitTimeNs;
    private long mDeInitTimeNs;
    private long mStartTimeNs;
    private ArrayList<Integer> mFrameSizes;
    private ArrayList<Long> mInputTimer;
    private ArrayList<Long> mOutputTimer;

    public Stats() {
        mFrameSizes = new ArrayList<>();
        mInputTimer = new ArrayList<>();
        mOutputTimer = new ArrayList<>();
        mInitTimeNs = 0;
        mDeInitTimeNs = 0;
    }

    public long getCurTime() { return System.nanoTime(); }

    public void setInitTime(long initTime) { mInitTimeNs = initTime; }

    public void setDeInitTime(long deInitTime) { mDeInitTimeNs = deInitTime; }

    public void setStartTime() { mStartTimeNs = System.nanoTime(); }

    public void addFrameSize(int size) { mFrameSizes.add(size); }

    public void addInputTime() { mInputTimer.add(System.nanoTime()); }

    public void addOutputTime() { mOutputTimer.add(System.nanoTime()); }

    public void reset() {
        if (mFrameSizes.size() != 0) {
            mFrameSizes.clear();
        }

        if (mInputTimer.size() != 0) {
            mInputTimer.clear();
        }

        if (mOutputTimer.size() != 0) {
            mOutputTimer.clear();
        }
    }

    public long getInitTime() { return mInitTimeNs; }

    public long getDeInitTime() { return mDeInitTimeNs; }

    public long getTimeDiff(long sTime, long eTime) { return (eTime - sTime); }

    private long getTotalTime() {
        if (mOutputTimer.size() == 0) {
            return -1;
        }
        long lastTime = mOutputTimer.get(mOutputTimer.size() - 1);
        return lastTime - mStartTimeNs;
    }

    private long getTotalSize() {
        long totalSize = 0;
        for (long size : mFrameSizes) {
            totalSize += size;
        }
        return totalSize;
    }

    /**
     * Dumps the stats of the operation for a given input media.
     * <p>
     * \param operation      describes the operation performed on the input media
     * (i.e. extract/mux/decode/encode)
     * \param inputReference input media
     * \param durationUs    is a duration of the input media in microseconds.
     */
    public void dumpStatistics(String operation, String inputReference, long durationUs) {
        if (mOutputTimer.size() == 0) {
            Log.e(TAG, "No output produced");
            return;
        }
        long totalTimeTakenNs = getTotalTime();
        long timeTakenPerSec = (totalTimeTakenNs * 1000000) / durationUs;
        long timeToFirstFrameNs = mOutputTimer.get(0) - mStartTimeNs;
        long size = getTotalSize();
        // get min and max output intervals.
        long intervalNs;
        long minTimeTakenNs = Long.MAX_VALUE;
        long maxTimeTakenNs = 0;
        long prevIntervalNs = mStartTimeNs;
        for (int idx = 0; idx < mOutputTimer.size() - 1; idx++) {
            intervalNs = mOutputTimer.get(idx) - prevIntervalNs;
            prevIntervalNs = mOutputTimer.get(idx);
            if (minTimeTakenNs > intervalNs) {
                minTimeTakenNs = intervalNs;
            } else if (maxTimeTakenNs < intervalNs) {
                maxTimeTakenNs = intervalNs;
            }
        }
        // Print the Stats
        Log.i(TAG, "Input Reference : " + inputReference);
        Log.i(TAG, "Setup Time in nano sec : " + mInitTimeNs);
        Log.i(TAG, "Average Time in nano sec : " + totalTimeTakenNs / mOutputTimer.size());
        Log.i(TAG, "Time to first frame in nano sec : " + timeToFirstFrameNs);
        Log.i(TAG, "Time taken (in nano sec) to " + operation + " 1 sec of content : " +
                timeTakenPerSec);
        Log.i(TAG, "Total bytes " + operation + "ed : " + size);
        Log.i(TAG, "Number of bytes " + operation + "ed per second : " +
                (size * 1000000000) / totalTimeTakenNs);
        Log.i(TAG, "Minimum Time in nano sec : " + minTimeTakenNs);
        Log.i(TAG, "Maximum Time in nano sec : " + maxTimeTakenNs);
        Log.i(TAG, "Destroy Time in nano sec : " + mDeInitTimeNs);
    }
}