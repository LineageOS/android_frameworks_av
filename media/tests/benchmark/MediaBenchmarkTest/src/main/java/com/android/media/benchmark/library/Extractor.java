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
import android.media.MediaExtractor;
import android.media.MediaFormat;
import android.util.Log;

import java.io.FileDescriptor;
import java.io.IOException;
import java.nio.ByteBuffer;

public class Extractor {
    private static final String TAG = "Extractor";
    private static final int kMaxBufSize = 1024 * 1024 * 16;
    private MediaExtractor mExtractor;
    private ByteBuffer mFrameBuffer;
    private MediaCodec.BufferInfo mBufferInfo;
    private Stats mStats;
    private long mDurationUs;

    public Extractor() {
        mFrameBuffer = ByteBuffer.allocate(kMaxBufSize);
        mBufferInfo = new MediaCodec.BufferInfo();
        mStats = new Stats();
    }

    /**
     * Creates a Media Extractor and sets data source(FileDescriptor)to use
     *
     * @param fileDescriptor FileDescriptor for the file which is to be extracted
     * @return TrackCount of the sample
     * @throws IOException If FileDescriptor is null
     */
    public int setUpExtractor(FileDescriptor fileDescriptor) throws IOException {
        long sTime = mStats.getCurTime();
        mExtractor = new MediaExtractor();
        mExtractor.setDataSource(fileDescriptor);
        long eTime = mStats.getCurTime();
        long timeTaken = mStats.getTimeDiff(sTime, eTime);
        mStats.setInitTime(timeTaken);
        return mExtractor.getTrackCount();
    }

    /**
     * Returns the track format of the specified index
     *
     * @param trackID Index of the track
     * @return Format of the track
     */
    public MediaFormat getFormat(int trackID) { return mExtractor.getTrackFormat(trackID); }

    /**
     * Returns the extracted buffer for the input clip
     */
    public ByteBuffer getFrameBuffer() { return this.mFrameBuffer; }

    /**
     * Returns the information of buffer related to sample
     */
    public MediaCodec.BufferInfo getBufferInfo() { return this.mBufferInfo; }

    /**
     * Returns the duration of the sample
     */
    public long getClipDuration() { return this.mDurationUs; }

    /**
     * Retrieve the current sample and store it in the byte buffer
     * Also, sets the information related to extracted sample and store it in buffer info
     *
     * @return Sample size of the extracted sample
     */
    public int getFrameSample() {
        int sampleSize = mExtractor.readSampleData(mFrameBuffer, 0);
        if (sampleSize < 0) {
            mBufferInfo.flags = MediaCodec.BUFFER_FLAG_END_OF_STREAM;
            mBufferInfo.size = 0;
        } else {
            mBufferInfo.size = sampleSize;
            mBufferInfo.offset = 0;
            mBufferInfo.flags = mExtractor.getSampleFlags();
            mBufferInfo.presentationTimeUs = mExtractor.getSampleTime();
            mExtractor.advance();
        }
        return sampleSize;
    }

    /**
     * Setup the track format and get the duration of the sample
     * Track is selected here for extraction
     *
     * @param trackId Track index to be selected
     * @return 0 for valid track, otherwise -1
     */
    public int selectExtractorTrack(int trackId) {
        MediaFormat trackFormat = mExtractor.getTrackFormat(trackId);
        mDurationUs = trackFormat.getLong(MediaFormat.KEY_DURATION);
        if (mDurationUs < 0) {
            Log.e(TAG, "Invalid Clip");
            return -1;
        }
        mExtractor.selectTrack(trackId);
        return 0;
    }

    /**
     * Unselect the track
     *
     * @param trackId Track Index to be unselected
     */
    public void unselectExtractorTrack(int trackId) { mExtractor.unselectTrack(trackId); }

    /**
     * Free up the resources
     */
    public void deinitExtractor() {
        long sTime = mStats.getCurTime();
        mExtractor.release();
        long eTime = mStats.getCurTime();
        long timeTaken = mStats.getTimeDiff(sTime, eTime);
        mStats.setDeInitTime(timeTaken);
    }

    /**
     * Performs extract operation
     *
     * @param currentTrack Track index to be extracted
     * @return Status as 0 if extraction is successful, -1 otherwise
     */
    public int extractSample(int currentTrack) {
        int status;
        status = selectExtractorTrack(currentTrack);
        if (status == -1) {
            Log.e(TAG, "Failed to select track");
            return -1;
        }
        mStats.setStartTime();
        while (true) {
            int readSampleSize = getFrameSample();
            if (readSampleSize <= 0) {
                break;
            }
            mStats.addOutputTime();
            mStats.addFrameSize(readSampleSize);
        }
        unselectExtractorTrack(currentTrack);
        return 0;
    }

    /**
     * Write the benchmark logs for the given input file
     *
     * @param inputReference Name of the input file
     * @param mimeType       Mime type of the muxed file
     * @param statsFile      The output file where the stats data is written
     */
    public void dumpStatistics(String inputReference, String mimeType, String statsFile)
            throws IOException {
        String operation = "extract";
        mStats.dumpStatistics(inputReference, operation, mimeType, "", mDurationUs, statsFile);
    }
}
