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

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
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
     * Writes the stats header to a file
     * <p>
     * \param statsFile    file where the stats data is to be written
     **/
    public boolean writeStatsHeader(String statsFile) throws IOException {
        File outputFile = new File(statsFile);
        FileOutputStream out = new FileOutputStream(outputFile, true);
        if (!outputFile.exists())
            return false;
        String statsHeader =
                "currentTime, fileName, operation, componentName, NDK/SDK, sync/async, setupTime, "
                        + "destroyTime, minimumTime, maximumTime, "
                        + "averageTime, timeToProcess1SecContent, totalBytesProcessedPerSec, "
                        + "timeToFirstFrame, totalSizeInBytes, totalTime\n";
        out.write(statsHeader.getBytes());
        out.close();
        return true;
    }

    /**
     * Dumps the stats of the operation for a given input media.
     * <p>
     * \param inputReference input media
     * \param operation      describes the operation performed on the input media
     * (i.e. extract/mux/decode/encode)
     * \param componentName  name of the codec/muxFormat/mime
     * \param mode           the operating mode: sync/async.
     * \param durationUs     is a duration of the input media in microseconds.
     * \param statsFile      the file where the stats data is to be written.
     */
    public void dumpStatistics(String inputReference, String operation, String componentName,
            String mode, long durationUs, String statsFile) throws IOException {
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

        // Write the stats row data to file
        String rowData = "";
        rowData += System.nanoTime() + ", ";
        rowData += inputReference + ", ";
        rowData += operation + ", ";
        rowData += componentName + ", ";
        rowData += "SDK, ";
        rowData += mode + ", ";
        rowData += mInitTimeNs + ", ";
        rowData += mDeInitTimeNs + ", ";
        rowData += minTimeTakenNs + ", ";
        rowData += maxTimeTakenNs + ", ";
        rowData += totalTimeTakenNs / mOutputTimer.size() + ", ";
        rowData += timeTakenPerSec + ", ";
        rowData += (size * 1000000000) / totalTimeTakenNs + ", ";
        rowData += timeToFirstFrameNs + ", ";
        rowData += size + ", ";
        rowData += totalTimeTakenNs + "\n";

        File outputFile = new File(statsFile);
        FileOutputStream out = new FileOutputStream(outputFile, true);
        assert outputFile.exists() : "Failed to open the stats file for writing!";
        out.write(rowData.getBytes());
        out.close();
    }
}
