/*
 * Copyright (C) 2021 The Android Open Source Project
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
package com.android.media.samplevideoencoder.tests;

import androidx.test.platform.app.InstrumentationRegistry;

import android.content.Context;
import android.media.MediaFormat;
import android.util.Log;

import com.android.media.samplevideoencoder.MediaCodecSurfaceEncoder;
import com.android.media.samplevideoencoder.R;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThat;

@RunWith(Parameterized.class)
public class SampleVideoEncoderTest {
    private static final String TAG = SampleVideoEncoderTest.class.getSimpleName();
    private final Context mContext;
    private int mMaxBFrames;
    private int mInputResId;
    private String mMime;
    private boolean mIsSoftwareEncoder;

    @Parameterized.Parameters
    public static Collection<Object[]> inputFiles() {
        return Arrays.asList(new Object[][]{
                // Parameters: MimeType, isSoftwareEncoder, maxBFrames
                {MediaFormat.MIMETYPE_VIDEO_AVC, false, 1},
                {MediaFormat.MIMETYPE_VIDEO_AVC, true, 1},
                {MediaFormat.MIMETYPE_VIDEO_HEVC, false, 1},
                {MediaFormat.MIMETYPE_VIDEO_HEVC, true, 1}});
    }

    public SampleVideoEncoderTest(String mimeType, boolean isSoftwareEncoder, int maxBFrames) {
        this.mContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
        this.mInputResId = R.raw.crowd_1920x1080_25fps_4000kbps_h265;
        this.mMime = mimeType;
        this.mIsSoftwareEncoder = isSoftwareEncoder;
        this.mMaxBFrames = maxBFrames;
    }

    private String getOutputPath() {
        File dir = mContext.getExternalFilesDir(null);
        if (dir == null) {
            Log.e(TAG, "Cannot get external directory path to save output video");
            return null;
        }
        String videoPath = dir.getAbsolutePath() + "/Video-" + System.currentTimeMillis() + ".mp4";
        Log.i(TAG, "Output video is saved at: " + videoPath);
        return videoPath;
    }

    @Test
    public void testMediaSurfaceEncoder() throws IOException, InterruptedException {
        String outputFilePath = getOutputPath();
        MediaCodecSurfaceEncoder surfaceEncoder =
                new MediaCodecSurfaceEncoder(mContext, mInputResId, mMime, mIsSoftwareEncoder,
                        outputFilePath, mMaxBFrames);
        int encodingStatus = surfaceEncoder.startEncodingSurface();
        assertThat(encodingStatus, is(equalTo(0)));
        int[] frameNumArray = surfaceEncoder.getFrameTypes();
        Log.i(TAG, "Results: I-Frames: " + frameNumArray[0] + "; P-Frames: " + frameNumArray[1] +
                "\n " + "; B-Frames:" + frameNumArray[2]);
        assertNotEquals("Encoder mime: " + mMime + " isSoftware: " + mIsSoftwareEncoder +
                " failed to generate B Frames", frameNumArray[2], 0);
    }
}
