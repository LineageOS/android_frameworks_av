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
package com.android.media.benchmark.tests;

import com.android.media.benchmark.R;
import com.android.media.benchmark.library.Extractor;
import com.android.media.benchmark.library.Muxer;

import androidx.test.platform.app.InstrumentationRegistry;

import android.content.Context;
import android.media.MediaCodec;
import android.media.MediaFormat;
import android.media.MediaMuxer;
import android.util.Log;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Map;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(Parameterized.class)
public class MuxerTest {
    private static Context mContext =
            InstrumentationRegistry.getInstrumentation().getTargetContext();
    private static final String mInputFilePath = mContext.getString(R.string.input_file_path);
    private static final String TAG = "MuxerTest";
    private static final Map<String, Integer> mMapFormat = new Hashtable<String, Integer>() {
        {
            put("mp4", MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4);
            put("webm", MediaMuxer.OutputFormat.MUXER_OUTPUT_WEBM);
            put("3gpp", MediaMuxer.OutputFormat.MUXER_OUTPUT_3GPP);
            put("ogg", MediaMuxer.OutputFormat.MUXER_OUTPUT_OGG);
        }
    };
    private String mInputFileName;
    private String mFormat;

    @Parameterized.Parameters
    public static Collection<Object[]> inputFiles() {
        return Arrays.asList(new Object[][]{
                /* Parameters: filename, format */
                {"crowd_1920x1080_25fps_4000kbps_vp8.webm", "webm"},
                {"crowd_1920x1080_25fps_4000kbps_vp9.webm", "webm"},
                {"crowd_1920x1080_25fps_6000kbps_mpeg4.mp4", "mp4"},
                {"crowd_352x288_25fps_6000kbps_h263.3gp", "mp4"},
                {"crowd_1920x1080_25fps_6700kbps_h264.ts", "mp4"},
                {"crowd_1920x1080_25fps_4000kbps_h265.mkv", "mp4"},
                {"crowd_1920x1080_25fps_6000kbps_mpeg4.mp4", "3gpp"},
                {"crowd_352x288_25fps_6000kbps_h263.3gp", "3gpp"},
                {"crowd_1920x1080_25fps_6700kbps_h264.ts", "3gpp"},
                {"crowd_1920x1080_25fps_4000kbps_h265.mkv", "3gpp"},
                {"bbb_48000hz_2ch_100kbps_opus_5mins.webm", "ogg"},
                {"bbb_44100hz_2ch_80kbps_vorbis_5mins.mp4", "webm"},
                {"bbb_48000hz_2ch_100kbps_opus_5mins.webm", "webm"},
                {"bbb_44100hz_2ch_128kbps_aac_5mins.mp4", "mp4"},
                {"bbb_8000hz_1ch_8kbps_amrnb_5mins.3gp", "mp4"},
                {"bbb_16000hz_1ch_9kbps_amrwb_5mins.3gp", "mp4"},
                {"bbb_44100hz_2ch_128kbps_aac_5mins.mp4", "3gpp"},
                {"bbb_8000hz_1ch_8kbps_amrnb_5mins.3gp", "3gpp"},
                {"bbb_16000hz_1ch_9kbps_amrwb_5mins.3gp", "3gpp"}});
    }

    public MuxerTest(String filename, String outputFormat) {
        this.mInputFileName = filename;
        this.mFormat = outputFormat;
    }

    @Test
    public void sampleMuxerTest() throws IOException {
        int status = -1;
        File inputFile = new File(mInputFilePath + mInputFileName);
        if (inputFile.exists()) {
            FileInputStream fileInput = new FileInputStream(inputFile);
            FileDescriptor fileDescriptor = fileInput.getFD();
            ArrayList<ByteBuffer> inputBuffer = new ArrayList<>();
            ArrayList<MediaCodec.BufferInfo> inputBufferInfo = new ArrayList<>();
            Extractor extractor = new Extractor();
            int trackCount = extractor.setUpExtractor(fileDescriptor);
            for (int currentTrack = 0; currentTrack < trackCount; currentTrack++) {
                extractor.selectExtractorTrack(currentTrack);
                while (true) {
                    int sampleSize = extractor.getFrameSample();
                    MediaCodec.BufferInfo bufferInfo = extractor.getBufferInfo();
                    MediaCodec.BufferInfo tempBufferInfo = new MediaCodec.BufferInfo();
                    tempBufferInfo
                            .set(bufferInfo.offset, bufferInfo.size, bufferInfo.presentationTimeUs,
                                    bufferInfo.flags);
                    inputBufferInfo.add(tempBufferInfo);
                    ByteBuffer tempSampleBuffer = ByteBuffer.allocate(tempBufferInfo.size);
                    tempSampleBuffer.put(extractor.getFrameBuffer().array(), 0, bufferInfo.size);
                    inputBuffer.add(tempSampleBuffer);
                    if (sampleSize < 0) {
                        break;
                    }
                }
                MediaFormat format = extractor.getFormat(currentTrack);
                int outputFormat = mMapFormat.getOrDefault(mFormat, -1);
                if (outputFormat != -1) {
                    Muxer muxer = new Muxer();
                    int trackIndex = muxer.setUpMuxer(mContext, outputFormat, format);
                    status = muxer.mux(trackIndex, inputBuffer, inputBufferInfo);
                    if (status != 0) {
                        Log.e(TAG, "Cannot perform write operation for " + mInputFileName);
                    }
                    muxer.deInitMuxer();
                    muxer.dumpStatistics(mInputFileName, extractor.getClipDuration());
                    muxer.resetMuxer();
                    extractor.unselectExtractorTrack(currentTrack);
                    inputBufferInfo.clear();
                    inputBuffer.clear();
                } else {
                    Log.e(TAG, "Test failed for " + mInputFileName + ". Returned invalid " +
                            "output format for given " + mFormat + " format.");
                }
            }
            extractor.deinitExtractor();
            fileInput.close();
        } else {
            Log.w(TAG, "Warning: Test Skipped. Cannot find " + mInputFileName + " in directory " +
                    mInputFilePath);
        }
        assertThat(status, is(equalTo(0)));
    }
}
