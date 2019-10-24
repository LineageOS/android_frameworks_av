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

import android.content.Context;
import android.media.MediaCodec;
import android.media.MediaFormat;
import android.util.Log;

import androidx.test.platform.app.InstrumentationRegistry;

import com.android.media.benchmark.R;
import com.android.media.benchmark.library.CodecUtils;
import com.android.media.benchmark.library.Decoder;
import com.android.media.benchmark.library.Encoder;
import com.android.media.benchmark.library.Extractor;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class EncoderTest {
    private static final Context mContext =
            InstrumentationRegistry.getInstrumentation().getTargetContext();
    private static final String mInputFilePath = mContext.getString(R.string.input_file_path);
    private static final String mOutputFilePath = mContext.getString(R.string.output_file_path);
    private static final String TAG = "EncoderTest";
    private static final long PER_TEST_TIMEOUT_MS = 120000;
    private static final boolean DEBUG = false;
    private static final boolean WRITE_OUTPUT = false;
    private static final int ENCODE_DEFAULT_FRAME_RATE = 25;
    private static final int ENCODE_DEFAULT_BIT_RATE = 8000000 /* 8 Mbps */;
    private static final int ENCODE_MIN_BIT_RATE = 600000 /* 600 Kbps */;

    private String mInputFile;

    @Parameterized.Parameters
    public static Collection<Object[]> inputFiles() {
        return Arrays.asList(new Object[][]{
                // Audio Test
                {"bbb_44100hz_2ch_128kbps_aac_30sec.mp4"},
                {"bbb_8000hz_1ch_8kbps_amrnb_30sec.3gp"},
                {"bbb_16000hz_1ch_9kbps_amrwb_30sec.3gp"},
                {"bbb_44100hz_2ch_600kbps_flac_30sec.mp4"},
                {"bbb_48000hz_2ch_100kbps_opus_30sec.webm"},
                // Video Test
                {"crowd_1920x1080_25fps_4000kbps_vp8.webm"},
                {"crowd_1920x1080_25fps_6700kbps_h264.ts"},
                {"crowd_1920x1080_25fps_4000kbps_h265.mkv"},
                {"crowd_1920x1080_25fps_4000kbps_vp9.webm"},
                {"crowd_176x144_25fps_6000kbps_mpeg4.mp4"},
                {"crowd_176x144_25fps_6000kbps_h263.3gp"}});
    }

    public EncoderTest(String inputFileName) {
        this.mInputFile = inputFileName;
    }

    @Test(timeout = PER_TEST_TIMEOUT_MS)
    public void sampleEncoderTest() throws Exception {
        int status;
        int frameSize;

        //Parameters for video
        int width = 0;
        int height = 0;
        int profile = 0;
        int level = 0;
        int frameRate = 0;

        //Parameters for audio
        int bitRate = 0;
        int sampleRate = 0;
        int numChannels = 0;

        File inputFile = new File(mInputFilePath + mInputFile);
        if (inputFile.exists()) {
            FileInputStream fileInput = new FileInputStream(inputFile);
            FileDescriptor fileDescriptor = fileInput.getFD();
            Extractor extractor = new Extractor();
            int trackCount = extractor.setUpExtractor(fileDescriptor);
            if (trackCount <= 0) {
                Log.e(TAG, "Extraction failed. No tracks for file: " + mInputFile);
                return;
            }
            ArrayList<ByteBuffer> inputBuffer = new ArrayList<>();
            ArrayList<MediaCodec.BufferInfo> frameInfo = new ArrayList<>();
            for (int currentTrack = 0; currentTrack < trackCount; currentTrack++) {
                extractor.selectExtractorTrack(currentTrack);
                MediaFormat format = extractor.getFormat(currentTrack);
                // Get samples from extractor
                int sampleSize;
                do {
                    sampleSize = extractor.getFrameSample();
                    MediaCodec.BufferInfo bufInfo = new MediaCodec.BufferInfo();
                    MediaCodec.BufferInfo info = extractor.getBufferInfo();
                    ByteBuffer dataBuffer = ByteBuffer.allocate(info.size);
                    dataBuffer.put(extractor.getFrameBuffer().array(), 0, info.size);
                    bufInfo.set(info.offset, info.size, info.presentationTimeUs, info.flags);
                    inputBuffer.add(dataBuffer);
                    frameInfo.add(bufInfo);
                    if (DEBUG) {
                        Log.d(TAG, "Extracted bufInfo: flag = " + bufInfo.flags + " timestamp = " +
                                bufInfo.presentationTimeUs + " size = " + bufInfo.size);
                    }
                } while (sampleSize > 0);

                int tid = android.os.Process.myTid();
                File decodedFile = new File(mContext.getFilesDir() + "/decoder_" + tid + ".out");
                FileOutputStream decodeOutputStream = new FileOutputStream(decodedFile);
                Decoder decoder = new Decoder();
                decoder.setupDecoder(decodeOutputStream);
                status = decoder.decode(inputBuffer, frameInfo, false, format, "");
                if (status == 0) {
                    Log.i(TAG, "Decoding complete.");
                } else {
                    Log.e(TAG, "Decode returned error. Encoding did not take place." + status);
                    return;
                }
                decoder.deInitCodec();
                extractor.unselectExtractorTrack(currentTrack);
                inputBuffer.clear();
                frameInfo.clear();
                if (decodeOutputStream != null) {
                    decodeOutputStream.close();
                }
                String mime = format.getString(MediaFormat.KEY_MIME);
                ArrayList<String> mediaCodecs = CodecUtils.selectCodecs(mime, true);
                if (mediaCodecs.size() <= 0) {
                    Log.e(TAG, "No suitable codecs found for file: " + mInputFile + " track : " +
                            currentTrack + " mime: " + mime);
                    return;
                }
                Boolean[] encodeMode = {true, false};
                /* Encoding the decoder's output */
                for (Boolean asyncMode : encodeMode) {
                    for (String codecName : mediaCodecs) {
                        FileOutputStream encodeOutputStream = null;
                        if (WRITE_OUTPUT) {
                            File outEncodeFile = new File(mOutputFilePath + "encoder.out");
                            if (outEncodeFile.exists()) {
                                if (!outEncodeFile.delete()) {
                                    Log.e(TAG, "Unable to delete existing file" +
                                            decodedFile.toString());
                                }
                            }
                            if (outEncodeFile.createNewFile()) {
                                encodeOutputStream = new FileOutputStream(outEncodeFile);
                            } else {
                                Log.e(TAG, "Unable to create file to write encoder output: " +
                                        outEncodeFile.toString());
                            }
                        }
                        File rawFile =
                                new File(mContext.getFilesDir() + "/decoder_" + tid + ".out");
                        if (rawFile.exists()) {
                            if (DEBUG) {
                                Log.i(TAG, "Path of decoded input file: " + rawFile.toString());
                            }
                            FileInputStream eleStream = new FileInputStream(rawFile);
                            if (mime.startsWith("video/")) {
                                width = format.getInteger(MediaFormat.KEY_WIDTH);
                                height = format.getInteger(MediaFormat.KEY_HEIGHT);
                                if (format.containsKey(MediaFormat.KEY_FRAME_RATE)) {
                                    frameRate = format.getInteger(MediaFormat.KEY_FRAME_RATE);
                                } else if (frameRate <= 0) {
                                    frameRate = ENCODE_DEFAULT_FRAME_RATE;
                                }
                                if (format.containsKey(MediaFormat.KEY_BIT_RATE)) {
                                    bitRate = format.getInteger(MediaFormat.KEY_BIT_RATE);
                                } else if (bitRate <= 0) {
                                    if (mime.contains("video/3gpp") ||
                                            mime.contains("video/mp4v-es")) {
                                        bitRate = ENCODE_MIN_BIT_RATE;
                                    } else {
                                        bitRate = ENCODE_DEFAULT_BIT_RATE;
                                    }
                                }
                                if (format.containsKey(MediaFormat.KEY_PROFILE)) {
                                    profile = format.getInteger(MediaFormat.KEY_PROFILE);
                                }
                                if (format.containsKey(MediaFormat.KEY_PROFILE)) {
                                    level = format.getInteger(MediaFormat.KEY_LEVEL);
                                }
                            } else {
                                sampleRate = format.getInteger(MediaFormat.KEY_SAMPLE_RATE);
                                numChannels = format.getInteger(MediaFormat.KEY_CHANNEL_COUNT);
                                bitRate = sampleRate * numChannels * 16;
                            }
                            /*Setup Encode Format*/
                            MediaFormat encodeFormat;
                            if (mime.startsWith("video/")) {
                                frameSize = width * height * 3 / 2;
                                encodeFormat = MediaFormat.createVideoFormat(mime, width, height);
                                encodeFormat.setInteger(MediaFormat.KEY_FRAME_RATE, frameRate);
                                encodeFormat.setInteger(MediaFormat.KEY_BIT_RATE, bitRate);
                                encodeFormat.setInteger(MediaFormat.KEY_PROFILE, profile);
                                encodeFormat.setInteger(MediaFormat.KEY_LEVEL, level);
                                encodeFormat.setInteger(MediaFormat.KEY_I_FRAME_INTERVAL, 1);
                                encodeFormat.setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, frameSize);
                            } else {
                                encodeFormat = MediaFormat
                                        .createAudioFormat(mime, sampleRate, numChannels);
                                encodeFormat.setInteger(MediaFormat.KEY_BIT_RATE, bitRate);
                                frameSize = 4096;
                            }
                            Encoder encoder = new Encoder();
                            encoder.setupEncoder(encodeOutputStream, eleStream);
                            status = encoder.encode(codecName, encodeFormat, mime, frameRate,
                                    sampleRate, frameSize, asyncMode);
                            encoder.deInitEncoder();
                            if (status == 0) {
                                encoder.dumpStatistics(mInputFile + "with " + codecName + " for " +
                                        "aSyncMode = " + asyncMode, extractor.getClipDuration());
                                Log.i(TAG, "Encoding complete for file: " + mInputFile +
                                        " with codec: " + codecName + " for aSyncMode = " +
                                        asyncMode);
                            } else {
                                Log.e(TAG,
                                        codecName + " encoder returned error " + status + " for " +
                                                "file:" + " " + mInputFile);
                            }
                            encoder.resetEncoder();
                            eleStream.close();
                            if (encodeOutputStream != null) {
                                encodeOutputStream.close();
                            }
                        }
                    }
                }
                //Cleanup temporary input file
                if (decodedFile.exists()) {
                    if (decodedFile.delete()) {
                        Log.i(TAG, "Successfully deleted decoded file");
                    } else {
                        Log.e(TAG, "Unable to delete decoded file");
                    }
                }
            }
            extractor.deinitExtractor();
            fileInput.close();
        } else {
            Log.w(TAG, "Warning: Test Skipped. Cannot find " + mInputFile + " in directory " +
                    mInputFilePath);
        }
    }
}
