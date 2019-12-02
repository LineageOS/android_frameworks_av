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

import android.content.Context;
import android.media.MediaCodec;
import android.media.MediaFormat;
import android.media.MediaMuxer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;

public class Muxer {
    private Stats mStats;
    private MediaMuxer mMuxer;

    /**
     * Creates a Media Muxer for the specified path
     *
     * @param context      App context to specify the output file path
     * @param outputFormat Format of the output media file
     * @param trackFormat  Format of the current track
     * @return Returns the track index of the newly added track, -1 otherwise
     */
    public int setUpMuxer(Context context, int outputFormat, MediaFormat trackFormat) {
        try {
            mStats = new Stats();
            long sTime = mStats.getCurTime();
            mMuxer = new MediaMuxer(context.getFilesDir().getPath() + "/mux.out.", outputFormat);
            int trackIndex = mMuxer.addTrack(trackFormat);
            mMuxer.start();
            long eTime = mStats.getCurTime();
            long timeTaken = mStats.getTimeDiff(sTime, eTime);
            mStats.setInitTime(timeTaken);
            return trackIndex;
        } catch (IllegalArgumentException | IOException e) {
            e.printStackTrace();
            return -1;
        }
    }

    /**
     * Performs the Mux operation
     *
     * @param trackIndex           Track index of the sample
     * @param inputExtractedBuffer Buffer containing encoded samples
     * @param inputBufferInfo      Buffer information related to these samples
     * @return Returns Status as 0 if write operation is successful, -1 otherwise
     */
    public int mux(int trackIndex, ArrayList<ByteBuffer> inputExtractedBuffer,
                   ArrayList<MediaCodec.BufferInfo> inputBufferInfo) {
        mStats.setStartTime();
        for (int sampleCount = 0; sampleCount < inputExtractedBuffer.size(); sampleCount++) {
            try {
                mMuxer.writeSampleData(trackIndex, inputExtractedBuffer.get(sampleCount),
                        inputBufferInfo.get(sampleCount));
                mStats.addOutputTime();
                mStats.addFrameSize(inputBufferInfo.get(sampleCount).size);
            } catch (IllegalArgumentException | IllegalStateException e) {
                e.printStackTrace();
                return -1;
            }
        }
        return 0;
    }

    /**
     * Stops the muxer and free up the resources
     */
    public void deInitMuxer() {
        long sTime = mStats.getCurTime();
        mMuxer.stop();
        mMuxer.release();
        long eTime = mStats.getCurTime();
        long timeTaken = mStats.getTimeDiff(sTime, eTime);
        mStats.setDeInitTime(timeTaken);
    }

    /**
     * Resets the stats
     */
    public void resetMuxer() {
        mStats.reset();
    }

    /**
     * Write the benchmark logs for the given input file
     *
     * @param inputReference Name of the input file
     * @param muxFormat      Format of the muxed output
     * @param clipDuration   Duration of the given inputReference file
     * @param statsFile      The output file where the stats data is written
     */
    public void dumpStatistics(String inputReference, String muxFormat, long clipDuration,
                               String statsFile) throws IOException {
        String operation = "mux";
        mStats.dumpStatistics(inputReference, operation, muxFormat, "", clipDuration, statsFile);
    }
}
