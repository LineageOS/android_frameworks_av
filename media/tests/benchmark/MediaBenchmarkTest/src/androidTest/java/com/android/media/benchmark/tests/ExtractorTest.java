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
import com.android.media.benchmark.library.Native;
import com.android.media.benchmark.library.Stats;

import android.content.Context;
import android.media.MediaFormat;
import android.util.Log;

import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class ExtractorTest {
    private static Context mContext =
            InstrumentationRegistry.getInstrumentation().getTargetContext();
    private static final String mInputFilePath = mContext.getString(R.string.input_file_path);
    private static final String mStatsFile = mContext.getExternalFilesDir(null) + "/Extractor."
            + System.currentTimeMillis() + ".csv";
    private static final String TAG = "ExtractorTest";
    private String mInputFileName;
    private int mTrackId;

    @Parameterized.Parameters
    public static Collection<Object[]> inputFiles() {
        return Arrays.asList(new Object[][]{/* Parameters: filename, trackId*/
                {"crowd_1920x1080_25fps_6000kbps_mpeg4.mp4", 0},
                {"crowd_1920x1080_25fps_6700kbps_h264.ts", 0},
                {"crowd_1920x1080_25fps_7300kbps_mpeg2.mp4", 0},
                {"crowd_1920x1080_25fps_4000kbps_av1.webm", 0},
                {"crowd_1920x1080_25fps_4000kbps_h265.mkv", 0},
                {"crowd_1920x1080_25fps_4000kbps_vp8.webm", 0},
                {"bbb_44100hz_2ch_128kbps_aac_5mins.mp4", 0},
                {"bbb_44100hz_2ch_128kbps_mp3_5mins.mp3", 0},
                {"bbb_44100hz_2ch_600kbps_flac_5mins.flac", 0},
                {"bbb_8000hz_1ch_8kbps_amrnb_5mins.3gp", 0},
                {"bbb_16000hz_1ch_9kbps_amrwb_5mins.3gp", 0},
                {"bbb_44100hz_2ch_80kbps_vorbis_5mins.webm", 0},
                {"bbb_48000hz_2ch_100kbps_opus_5mins.webm", 0}});
    }

    public ExtractorTest(String filename, int track) {
        this.mInputFileName = filename;
        this.mTrackId = track;
    }

    @BeforeClass
    public static void writeStatsHeaderToFile() throws IOException {
        Stats mStats = new Stats();
        boolean status = mStats.writeStatsHeader(mStatsFile);
        assertTrue("Unable to open stats file for writing!", status);
        Log.d(TAG, "Saving Benchmark results in: " + mStatsFile);
    }

    @Test
    public void testExtractor() throws IOException {
        File inputFile = new File(mInputFilePath + mInputFileName);
        assertTrue("Cannot find " + mInputFileName + " in directory " + mInputFilePath,
                inputFile.exists());
        FileInputStream fileInput = new FileInputStream(inputFile);
        FileDescriptor fileDescriptor = fileInput.getFD();
        Extractor extractor = new Extractor();
        extractor.setUpExtractor(fileDescriptor);
        MediaFormat format = extractor.getFormat(mTrackId);
        String mime = format.getString(MediaFormat.KEY_MIME);
        int status = extractor.extractSample(mTrackId);
        assertEquals("Extraction failed for " + mInputFileName, 0, status);
        Log.i(TAG, "Extracted " + mInputFileName + " successfully.");
        extractor.deinitExtractor();
        extractor.dumpStatistics(mInputFileName, mime, mStatsFile);
        fileInput.close();
    }

    @Test
    public void testNativeExtractor() throws IOException {
        Native nativeExtractor = new Native();
        File inputFile = new File(mInputFilePath + mInputFileName);
        assertTrue("Cannot find " + mInputFileName + " in directory " + mInputFilePath,
                inputFile.exists());
        FileInputStream fileInput = new FileInputStream(inputFile);
        int status = nativeExtractor.Extract(mInputFilePath, mInputFileName, mStatsFile);
        fileInput.close();
        assertEquals("Extraction failed for " + mInputFileName, 0, status);
        Log.i(TAG, "Extracted " + mInputFileName + " successfully.");
    }
}
