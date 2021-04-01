/*
 * Copyright (C) 2020 The Android Open Source Project
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

package com.android.media.samplevideoencoder;

import android.util.Log;

import java.nio.ByteBuffer;

import static com.android.media.samplevideoencoder.MainActivity.FRAME_TYPE_B;
import static com.android.media.samplevideoencoder.MainActivity.FRAME_TYPE_I;
import static com.android.media.samplevideoencoder.MainActivity.FRAME_TYPE_P;

public class NalUnitUtil {
    private static final String TAG = MediaCodecSurfaceEncoder.class.getSimpleName();
    private static final boolean DEBUG = false;

    public static int findNalUnit(byte[] dataArray, int pos, int limit) {
        int startOffset = 0;
        if (limit - pos < 4) {
            return startOffset;
        }
        if (dataArray[pos] == 0 && dataArray[pos + 1] == 0 && dataArray[pos + 2] == 1) {
            startOffset = 3;
        } else {
            if (dataArray[pos] == 0 && dataArray[pos + 1] == 0 && dataArray[pos + 2] == 0 &&
                    dataArray[pos + 3] == 1) {
                startOffset = 4;
            }
        }
        return startOffset;
    }

    private static int getAVCNalUnitType(byte[] dataArray, int nalUnitOffset) {
        return dataArray[nalUnitOffset] & 0x1F;
    }

    private static int parseAVCNALUnitData(byte[] dataArray, int offset, int limit) {
        ParsableBitArray bitArray = new ParsableBitArray(dataArray);
        bitArray.reset(dataArray, offset, limit);

        bitArray.skipBit(); // forbidden_zero_bit
        bitArray.readBits(2); // nal_ref_idc
        bitArray.skipBits(5); // nal_unit_type

        bitArray.readUEV(); // first_mb_in_slice
        if (!bitArray.canReadUEV()) {
            return -1;
        }
        int sliceType = bitArray.readUEV();
        if (DEBUG) Log.d(TAG, "slice_type = " + sliceType);
        if (sliceType == 0) {
            return FRAME_TYPE_P;
        } else if (sliceType == 1) {
            return FRAME_TYPE_B;
        } else if (sliceType == 2) {
            return FRAME_TYPE_I;
        } else {
            return -1;
        }
    }

    private static int getHEVCNalUnitType(byte[] dataArray, int nalUnitOffset) {
        return (dataArray[nalUnitOffset] & 0x7E) >> 1;
    }

    private static int parseHEVCNALUnitData(byte[] dataArray, int offset, int limit,
                                            int nalUnitType) {
        // nal_unit_type values from H.265/HEVC Table 7-1.
        final int BLA_W_LP = 16;
        final int RSV_IRAP_VCL23 = 23;

        ParsableBitArray bitArray = new ParsableBitArray(dataArray);
        bitArray.reset(dataArray, offset, limit);

        bitArray.skipBit(); // forbidden zero bit
        bitArray.readBits(6); // nal_unit_header
        bitArray.readBits(6); // nuh_layer_id
        bitArray.readBits(3); // nuh_temporal_id_plus1

        // Parsing slice_segment_header values from H.265/HEVC Table 7.3.6.1
        boolean first_slice_segment = bitArray.readBit(); // first_slice_segment_in_pic_flag
        if (!first_slice_segment) return -1;
        if (nalUnitType >= BLA_W_LP && nalUnitType <= RSV_IRAP_VCL23) {
            bitArray.readBit();  // no_output_of_prior_pics_flag
        }
        bitArray.readUEV(); // slice_pic_parameter_set_id
        // Assume num_extra_slice_header_bits element of PPS data to be 0
        int sliceType = bitArray.readUEV();
        if (DEBUG) Log.d(TAG, "slice_type = " + sliceType);
        if (sliceType == 0) {
            return FRAME_TYPE_B;
        } else if (sliceType == 1) {
            return FRAME_TYPE_P;
        } else if (sliceType == 2) {
            return FRAME_TYPE_I;
        } else {
            return -1;
        }
    }

    public static int getStandardizedFrameTypesFromAVC(ByteBuffer buf) {
        int limit = buf.limit();
        byte[] dataArray = new byte[buf.remaining()];
        buf.get(dataArray);
        int frameType = -1;
        for (int pos = 0; pos + 3 < limit; ) {
            int startOffset = NalUnitUtil.findNalUnit(dataArray, pos, limit);
            if (startOffset != 0) {
                int nalUnitType = getAVCNalUnitType(dataArray, (pos + startOffset));
                if (DEBUG) {
                    Log.d(TAG, "NalUnitOffset = " + (pos + startOffset));
                    Log.d(TAG, "NalUnitType = " + nalUnitType);
                }
                // SLICE_NAL = 1; IDR_SLICE_NAL = 5
                if (nalUnitType == 1 || nalUnitType == 5) {
                    frameType = parseAVCNALUnitData(dataArray, (pos + startOffset),
                            (limit - pos - startOffset));
                    break;
                }
                pos += 3;
            } else {
                pos++;
            }
        }
        return frameType;
    }

    public static int getStandardizedFrameTypesFromHEVC(ByteBuffer buf) {
        int limit = buf.limit();
        byte[] dataArray = new byte[buf.remaining()];
        buf.get(dataArray);
        int frameType = -1;
        for (int pos = 0; pos + 3 < limit; ) {
            int startOffset = NalUnitUtil.findNalUnit(dataArray, pos, limit);
            if (startOffset != 0) {
                int nalUnitType = NalUnitUtil.getHEVCNalUnitType(dataArray, (pos + startOffset));
                if (DEBUG) {
                    Log.d(TAG, "NalUnitOffset = " + (pos + startOffset));
                    Log.d(TAG, "NalUnitType = " + nalUnitType);
                }
                // Parse NALUnits containing slice_headers which lies in the range of 0 to 21
                if (nalUnitType >= 0 && nalUnitType <= 21) {
                    frameType = parseHEVCNALUnitData(dataArray, (pos + startOffset),
                            (limit - pos - startOffset), nalUnitType);
                    break;
                }
                pos += 3;
            } else {
                pos++;
            }
        }
        return frameType;
    }
}
