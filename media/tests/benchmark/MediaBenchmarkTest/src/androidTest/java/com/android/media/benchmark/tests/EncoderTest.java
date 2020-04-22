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

import static android.media.MediaCodecInfo.CodecCapabilities.COLOR_FormatYUV420Flexible;

import android.util.Log;

import androidx.test.platform.app.InstrumentationRegistry;

import com.android.media.benchmark.R;
import com.android.media.benchmark.library.CodecUtils;
import com.android.media.benchmark.library.Decoder;
import com.android.media.benchmark.library.Encoder;
import com.android.media.benchmark.library.Extractor;
import com.android.media.benchmark.library.Native;
import com.android.media.benchmark.library.Stats;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class EncoderTest {
    private static final Context mContext =
            InstrumentationRegistry.getInstrumentation().getTargetContext();
    private static final String mFileDirPath = mContext.getFilesDir() + "/";
    private static final String mInputFilePath = mContext.getString(R.string.input_file_path);
    private static final String mOutputFilePath = mContext.getString(R.string.output_file_path);
    private static final String mStatsFile =
            mContext.getExternalFilesDir(null) + "/Encoder." + System.currentTimeMillis() + ".csv";
    private static final String TAG = "EncoderTest";
    private static final boolean DEBUG = false;
    private static final boolean WRITE_OUTPUT = false;
    private static final long PER_TEST_TIMEOUT_MS = 120000;
    private static final int ENCODE_DEFAULT_FRAME_RATE = 25;
    private static final int ENCODE_DEFAULT_VIDEO_BIT_RATE = 8000000 /* 8 Mbps */;
    private static final int ENCODE_MIN_VIDEO_BIT_RATE = 600000 /* 600 Kbps */;
    private static final int ENCODE_DEFAULT_AUDIO_BIT_RATE = 128000 /* 128 Kbps */;
    private static int mColorFormat = COLOR_FormatYUV420Flexible;
    private static File mDecodedFileQcif;
    private static File mDecodedFileFullHd;
    private static File mDecodedFileAudio;
    private String mInputFile;
    private String mMime;
    private int mBitRate;
    private int mIFrameInterval;
    private int mWidth;
    private int mHeight;
    private int mProfile;
    private int mLevel;
    private int mSampleRate;
    private int mNumChannel;
    private static final String DECODE_FULLHD_INPUT = "crowd_1920x1080_25fps_4000kbps_h265.mkv";
    private static final String DECODE_QCIF_INPUT = "crowd_176x144_25fps_6000kbps_mpeg4.mp4";
    private static final String DECODE_AUDIO_INPUT = "bbb_48000hz_2ch_100kbps_opus_30sec.webm";
    private static final String DECODE_FULLHD_UNPACKED = "crowd_1920x1080_25fps_4000kbps_h265.yuv";
    private static final String DECODE_QCIF_UNPACKED = "crowd_176x144_25fps_6000kbps_mpeg4.yuv";
    private static final String DECODE_AUDIO_UNPACKED = "bbb_48000hz_2ch_100kbps_opus_30sec.raw";

    @Parameterized.Parameters
    public static Collection<Object[]> inputFiles() {
        return Arrays.asList(new Object[][]{
                // Audio Test
                // Parameters: Filename, mimeType, bitrate, width, height, iFrameInterval,
                // profile, level, sampleRate, channelCount
                {DECODE_AUDIO_UNPACKED, MediaFormat.MIMETYPE_AUDIO_AAC,
                        ENCODE_DEFAULT_AUDIO_BIT_RATE, -1, -1, -1, -1, -1, 44100, 2},
                {DECODE_AUDIO_UNPACKED, MediaFormat.MIMETYPE_AUDIO_AMR_NB,
                        ENCODE_DEFAULT_AUDIO_BIT_RATE, -1, -1, -1, -1, -1, 8000, 1},
                {DECODE_AUDIO_UNPACKED, MediaFormat.MIMETYPE_AUDIO_AMR_WB,
                        ENCODE_DEFAULT_AUDIO_BIT_RATE, -1, -1, -1, -1, -1, 16000, 1},
                {DECODE_AUDIO_UNPACKED, MediaFormat.MIMETYPE_AUDIO_FLAC,
                        ENCODE_DEFAULT_AUDIO_BIT_RATE, -1, -1, -1, -1, -1, 44100, 2},
                {DECODE_AUDIO_UNPACKED, MediaFormat.MIMETYPE_AUDIO_OPUS,
                        ENCODE_DEFAULT_AUDIO_BIT_RATE, -1, -1, -1, -1, -1, 48000, 2},

                // Video Test
                // Parameters: Filename, mimeType, bitrate, width, height, iFrameInterval,
                // profile, level, sampleRate, channelCount
                {DECODE_FULLHD_UNPACKED, MediaFormat.MIMETYPE_VIDEO_VP8,
                        ENCODE_DEFAULT_VIDEO_BIT_RATE, 1920, 1080, 1, -1, -1, -1, -1},
                {DECODE_FULLHD_UNPACKED, MediaFormat.MIMETYPE_VIDEO_AVC,
                        ENCODE_DEFAULT_VIDEO_BIT_RATE, 1920, 1080, 1, -1, -1, -1, -1},
                {DECODE_FULLHD_UNPACKED, MediaFormat.MIMETYPE_VIDEO_HEVC,
                        ENCODE_DEFAULT_VIDEO_BIT_RATE, 1920, 1080, 1, -1, -1, -1, -1},
                {DECODE_FULLHD_UNPACKED, MediaFormat.MIMETYPE_VIDEO_VP9,
                        ENCODE_DEFAULT_VIDEO_BIT_RATE, 1920, 1080, 1, -1, -1, -1, -1},
                {DECODE_QCIF_UNPACKED, MediaFormat.MIMETYPE_VIDEO_MPEG4, ENCODE_MIN_VIDEO_BIT_RATE,
                        176, 144, 1, -1, -1, -1, -1},
                {DECODE_QCIF_UNPACKED, MediaFormat.MIMETYPE_VIDEO_H263, ENCODE_MIN_VIDEO_BIT_RATE,
                        176, 144, 1, -1, -1, -1, -1}});
    }

    public EncoderTest(String filename, String mime, int bitrate, int width, int height,
                       int frameInterval, int profile, int level, int samplerate,
                       int channelCount) {
        this.mInputFile = filename;
        this.mMime = mime;
        this.mBitRate = bitrate;
        this.mIFrameInterval = frameInterval;
        this.mWidth = width;
        this.mHeight = height;
        this.mProfile = profile;
        this.mLevel = level;
        this.mSampleRate = samplerate;
        this.mNumChannel = channelCount;
    }

    @BeforeClass
    public static void writeStatsHeaderToFile() throws IOException {
        Stats mStats = new Stats();
        boolean status = mStats.writeStatsHeader(mStatsFile);
        assertTrue("Unable to open stats file for writing!", status);
        Log.d(TAG, "Saving Benchmark results in: " + mStatsFile);
    }

    @BeforeClass
    public static void prepareInput() throws IOException {

        mDecodedFileFullHd = new File(mFileDirPath + DECODE_FULLHD_UNPACKED);
        int status = decodeFile(mInputFilePath + DECODE_FULLHD_INPUT, mDecodedFileFullHd);
        assertEquals("Decoder returned error " + status, 0, status);

        mDecodedFileQcif = new File(mFileDirPath + DECODE_QCIF_UNPACKED);
        status = decodeFile(mInputFilePath + DECODE_QCIF_INPUT, mDecodedFileQcif);
        assertEquals("Decoder returned error " + status, 0, status);

        mDecodedFileAudio = new File(mFileDirPath + DECODE_AUDIO_UNPACKED);
        status = decodeFile(mInputFilePath + DECODE_AUDIO_INPUT, mDecodedFileAudio);
        assertEquals("Decoder returned error " + status, 0, status);
    }

    private static int decodeFile(String inputFileName, File outputDecodeFile) throws IOException {
        int status = -1;
        File inputFile = new File(inputFileName);
        assertTrue("Cannot open input file " + inputFileName, inputFile.exists());
        FileInputStream fileInput = new FileInputStream(inputFile);
        FileDescriptor fileDescriptor = fileInput.getFD();
        FileOutputStream decodeOutputStream = new FileOutputStream(outputDecodeFile);

        Extractor extractor = new Extractor();
        int trackCount = extractor.setUpExtractor(fileDescriptor);
        assertTrue("Extraction failed. No tracks for the given input file", (trackCount > 0));
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
            Decoder decoder = new Decoder();
            decoder.setupDecoder(decodeOutputStream);
            status = decoder.decode(inputBuffer, frameInfo, false, format, "");
            MediaFormat decoderFormat = decoder.getFormat();
            if (decoderFormat.containsKey(MediaFormat.KEY_COLOR_FORMAT)) {
                mColorFormat = decoderFormat.getInteger(MediaFormat.KEY_COLOR_FORMAT);
            }
            decoder.deInitCodec();
            extractor.unselectExtractorTrack(currentTrack);
            inputBuffer.clear();
            frameInfo.clear();
        }
        extractor.deinitExtractor();
        fileInput.close();
        decodeOutputStream.close();
        return status;
    }

    @Test(timeout = PER_TEST_TIMEOUT_MS)
    public void testEncoder() throws Exception {
        int status;
        int frameSize;

        ArrayList<String> mediaCodecs = CodecUtils.selectCodecs(mMime, true);
        assertTrue("No suitable codecs found for mimetype: " + mMime, (mediaCodecs.size() > 0));
        Boolean[] encodeMode = {true, false};
        // Encoding the decoded input file
        for (Boolean asyncMode : encodeMode) {
            for (String codecName : mediaCodecs) {
                FileOutputStream encodeOutputStream = null;
                if (WRITE_OUTPUT) {
                    File outEncodeFile = new File(mOutputFilePath + "encoder.out");
                    if (outEncodeFile.exists()) {
                        assertTrue(" Unable to delete existing file" + outEncodeFile.toString(),
                                outEncodeFile.delete());
                    }
                    assertTrue("Unable to create file to write encoder output: " +
                            outEncodeFile.toString(), outEncodeFile.createNewFile());
                    encodeOutputStream = new FileOutputStream(outEncodeFile);
                }
                File rawFile = new File(mFileDirPath + mInputFile);
                assertTrue("Cannot open decoded input file", rawFile.exists());
                if (DEBUG) {
                    Log.i(TAG, "Path of decoded input file: " + rawFile.toString());
                }
                FileInputStream eleStream = new FileInputStream(rawFile);
                // Setup Encode Format
                MediaFormat encodeFormat;
                if (mMime.startsWith("video/")) {
                    frameSize = mWidth * mHeight * 3 / 2;
                    encodeFormat = MediaFormat.createVideoFormat(mMime, mWidth, mHeight);
                    encodeFormat.setInteger(MediaFormat.KEY_FRAME_RATE, ENCODE_DEFAULT_FRAME_RATE);
                    encodeFormat.setInteger(MediaFormat.KEY_I_FRAME_INTERVAL, mIFrameInterval);
                    encodeFormat.setInteger(MediaFormat.KEY_BIT_RATE, mBitRate);
                    encodeFormat.setInteger(MediaFormat.KEY_COLOR_FORMAT, mColorFormat);
                    if (mProfile != -1 && mLevel != -1) {
                        encodeFormat.setInteger(MediaFormat.KEY_PROFILE, mProfile);
                        encodeFormat.setInteger(MediaFormat.KEY_LEVEL, mLevel);
                    }
                } else {
                    frameSize = 4096;
                    encodeFormat = MediaFormat.createAudioFormat(mMime, mSampleRate, mNumChannel);
                    encodeFormat.setInteger(MediaFormat.KEY_BIT_RATE, mBitRate);
                }
                Encoder encoder = new Encoder();
                encoder.setupEncoder(encodeOutputStream, eleStream);
                status = encoder.encode(codecName, encodeFormat, mMime, ENCODE_DEFAULT_FRAME_RATE,
                        mSampleRate, frameSize, asyncMode);
                encoder.deInitEncoder();
                assertEquals(
                        codecName + " encoder returned error " + status + " for " + "mime:" + " " +
                                mMime, 0, status);
                String inputReference;
                long durationUs;
                if (mMime.startsWith("video/")) {
                    inputReference =
                            mInputFile + "_" + mWidth + "x" + mHeight + "_" + mBitRate + "bps";
                    durationUs = (((eleStream.getChannel().size() + frameSize - 1) / frameSize) /
                            ENCODE_DEFAULT_FRAME_RATE) * 1000000;
                } else {
                    inputReference = mInputFile + "_" + mSampleRate + "hz_" + mNumChannel + "ch_" +
                            mBitRate + "bps";
                    durationUs =
                            (eleStream.getChannel().size() / (mSampleRate * mNumChannel)) * 1000000;
                }
                encoder.dumpStatistics(inputReference, codecName, (asyncMode ? "async" : "sync"),
                        durationUs, mStatsFile);
                Log.i(TAG, "Encoding complete for mime: " + mMime + " with codec: " + codecName +
                        " for aSyncMode = " + asyncMode);
                encoder.resetEncoder();
                eleStream.close();
                if (encodeOutputStream != null) {
                    encodeOutputStream.close();
                }
            }
        }
    }

    @Test(timeout = PER_TEST_TIMEOUT_MS)
    public void testNativeEncoder() {
        ArrayList<String> mediaCodecs = CodecUtils.selectCodecs(mMime, true);
        assertTrue("No suitable codecs found for mimetype: " + mMime, (mediaCodecs.size() > 0));
        for (String codecName : mediaCodecs) {
            Native nativeEncoder = new Native();
            int status = nativeEncoder
                    .Encode(mFileDirPath, mInputFile, mStatsFile, codecName, mMime, mBitRate,
                            mColorFormat, mIFrameInterval, mWidth, mHeight, mProfile, mLevel,
                            mSampleRate, mNumChannel);
            assertEquals(codecName + " encoder returned error " + status + " for " + "mime:" + " " +
                    mMime, 0, status);
        }
    }

    @AfterClass
    public static void deleteDecodedFiles() {
        if (mDecodedFileFullHd.exists()) {
            assertTrue(" Unable to delete decoded file" + mDecodedFileFullHd.toString(),
                    mDecodedFileFullHd.delete());
            Log.i(TAG, "Successfully deleted decoded file" + mDecodedFileFullHd.toString());
        }
        if (mDecodedFileQcif.exists()) {
            assertTrue(" Unable to delete decoded file" + mDecodedFileQcif.toString(),
                    mDecodedFileQcif.delete());
            Log.i(TAG, "Successfully deleted decoded file" + mDecodedFileQcif.toString());
        }
        if (mDecodedFileAudio.exists()) {
            assertTrue(" Unable to delete decoded file" + mDecodedFileAudio.toString(),
                    mDecodedFileAudio.delete());
            Log.i(TAG, "Successfully deleted decoded file" + mDecodedFileAudio.toString());
        }
    }
}
