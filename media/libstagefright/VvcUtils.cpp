/*
 * Copyright (C) 2025 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "VvcUtils"

#include <cstdint>
#include <math.h>
#include <cstring>
#include <utility>

#include "include/VvcUtils.h"

#include <media/stagefright/foundation/ABitReader.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/avc_utils.h>
#include <media/stagefright/foundation/hexdump.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/Utils.h>

#define UNUSED_PARAM __attribute__((unused))

namespace android {

// Refer to ISO/IEC 14496-15:2021(E) Chapter 11.2.4.2.1
// It is recommended that the arrays be
// in the order DCI, OPI, VPS, SPS, PPS, prefix APS, prefix SEI.
static const uint8_t kVvcNalUnitTypes[8] = {
    kVvcNalUnitTypeDci,
    kVvcNalUnitTypeOpi,
    kVvcNalUnitTypeVps,
    kVvcNalUnitTypeSps,
    kVvcNalUnitTypePps,
    kVvcNalUnitTypePrefixAps,
    kVvcNalUnitTypePrefixSei,
};

VvcParameterSets::VvcParameterSets()
    : mInfo(kInfoNone),
      mPtrRecord(nullptr) {
}

status_t VvcParameterSets::addNalUnit(const uint8_t* data, size_t size) {
    if (size < 1) {
        ALOGE("empty NAL b/35467107");
        return ERROR_MALFORMED;
    }
    // Rec. ITU-T H.266 (V3)
    uint8_t nalUnitType = (data[1] & 0xF8) >> 3;
    ALOGV("add nalUnitType: %u", nalUnitType);
    status_t err = OK;
    switch (nalUnitType) {
        case 15:  // SPS
            if (size < 2) {
                ALOGE("invalid NAL/SPS size b/35467107");
                return ERROR_MALFORMED;
            }
            err = parseSps(data + 2, size - 2);
            break;
        case 12:  // OPI
        case 13:  // DCI
        case 14:  // VPS
        case 16:  // PPS
        case 17:  // Prefix APS
        case 23:  // Prefix SEI
            // Ignore
            break;
        default:
            ALOGE("Unrecognized NAL unit type.");
            return ERROR_MALFORMED;
    }

    if (err != OK) {
        ALOGE("error %d while parsing VPS or SPS or PPS", err);
        return err;
    }

    std::unique_ptr<ABuffer> buffer = ABuffer::CreateAsUniqueCopy(data, size);
    buffer->setInt32Data(nalUnitType);
    mNalUnits.push_back(std::move(buffer));
    return OK;
}

template <typename T>
static bool findParam(uint32_t key, T &param,
        std::map<uint32_t, uint64_t> &params) {
    auto res = params.find(key);
    if (res == params.end()) {
        return false;
    }
    param = (T) res->second;
    return true;
}

bool VvcParameterSets::findParam8(uint32_t key, uint8_t &param) {
    return findParam(key, param, mParams);
}

bool VvcParameterSets::findParam16(uint32_t key, uint16_t &param) {
    return findParam(key, param, mParams);
}

bool VvcParameterSets::findParam32(uint32_t key, uint32_t &param) {
    return findParam(key, param, mParams);
}

bool VvcParameterSets::findParam64(uint32_t key, uint64_t &param) {
    return findParam(key, param, mParams);
}

size_t VvcParameterSets::getNumNalUnitsOfType(uint8_t type) {
    size_t num = 0;
    for (size_t i = 0; i < mNalUnits.size(); ++i) {
        if (getNalUnitType(i) == type) {
            ++num;
        }
    }
    return num;
}

uint8_t VvcParameterSets::getNalUnitType(size_t index) {
    CHECK_LT(index, mNalUnits.size());
    return mNalUnits[index]->int32Data();
}

size_t VvcParameterSets::getNalUnitSize(size_t index) {
    CHECK_LT(index, mNalUnits.size());
    return mNalUnits[index]->size();
}

bool VvcParameterSets::writeNalUnit(size_t index, uint8_t* dest, size_t size) {
    CHECK_LT(index, mNalUnits.size());
    const auto& nalUnit = mNalUnits[index];
    if (size < nalUnit->size()) {
        ALOGE("dest buffer size too small: %zu vs. %zu to be written",
                size, nalUnit->size());
        return false;
    }
    memcpy(dest, nalUnit->data(), nalUnit->size());
    return true;
}

status_t VvcParameterSets::makeVvcc(uint8_t *vvcc, size_t &vvccSize, size_t nalSizeLength) {
    if (vvcc == NULL || (nalSizeLength != 4 && nalSizeLength != 2)) {
        return BAD_VALUE;
    }
    // See ISO/IEC 14496-15 11.2.4.3 VVC configuration box for reference
    // header size except PTLRecord and arrays
    size_t size = 15;
    if (mPtrRecord != NULL) {
        // mPtrRecord doesn't contain
        // bit(2) reserved = 0 and unsigned int(6) num_bytes_constraint_info
        // So its size should plus 1 byte
        size += (mPtrRecord->size() + 1);
    }
    ALOGV("Vvcc header size:%zu PtrRecord size:%zu", size, mPtrRecord->size());
    size_t numOfArrays = 0;
    const size_t numNalUnits = getNumNalUnits();
    for (size_t i = 0; i < ARRAY_SIZE(kVvcNalUnitTypes); ++i) {
        uint8_t type = kVvcNalUnitTypes[i];
        size_t numNalUnitsOfType = getNumNalUnitsOfType(type);
        if (numNalUnitsOfType == 0) {
            continue;
        }
        ++numOfArrays;
        if (type != kVvcNalUnitTypeDci && type != kVvcNalUnitTypeOpi) {
            size += 3;
        } else {
            // DCI and OPI nal type doesn't have num_nalus
            size += 1;
        }

        for (size_t j = 0; j < numNalUnits; ++j) {
            if (getNalUnitType(j) != type) {
                continue;
            }
            size += 2 + getNalUnitSize(j);
        }
    }
    uint8_t num_sublayers, chroma_format_idc, bit_depth_minus8;
    uint32_t max_picture_width, max_picture_height, num_bytes_constraint_info;
    if (!findParam8(kNumSubLayers, num_sublayers)
        || !findParam8(kChromaFormatIdc, chroma_format_idc)
        || !findParam8(kBitDepthChromaMinus8,  bit_depth_minus8)
        || !findParam32(kMaxPictureWidth, max_picture_width)
        || !findParam32(kMaxPictureHeight, max_picture_height)
        || !findParam32(kNumBytesConstraintInfo, num_bytes_constraint_info)) {
        ALOGE("missing key parameters");
        return ERROR_MALFORMED;
    }

    if (size > vvccSize) {
        return NO_MEMORY;
    }
    vvccSize = size;
    uint8_t ptl_present_flag = (mPtrRecord == NULL ? 0 : 1);
    uint8_t *header = vvcc;
    // Header according to VvcConfigurationBox
    // Please see ISO / IEC 14496 - 15 : 2024 section 11.2.4.3.2
    header[0] = 0; // version(8)
    header[1] = 0; // Flags(24)
    header[2] = 0;
    header[3] = 0;

    // Header according to VvcDecoderConfigurationRecord
    // Please see ISO / IEC 14496 - 15 : 2024 section 11.2.4.2.2
    // Reserved '11111'b, LengthSizeMinusOne, ptl_present_flag 1
    header[4] = 0xf8 | ((nalSizeLength - 1) << 1) | ptl_present_flag;
    size_t off = 5;
    if (ptl_present_flag) {
        // Parser doesn't support non-zero OLS
        header[5] = 0; // ols(9), set it to 0
        // Parser only supports constant frame rate
        // set constant_frame_rate to 1 currently
        header[6] = (num_sublayers << 4) | 0x04 | chroma_format_idc;
        header[7] = (bit_depth_minus8 << 5) | 0x1f;

        off = 8;
        if (mPtrRecord != NULL) {
            header[off++] = num_bytes_constraint_info;
            for (size_t i = 0; i < mPtrRecord->size(); i++) {
                header[off++] = mPtrRecord->data()[i];
            }
        }

        header[off++] = (max_picture_width >> 8) & 0xff;
        header[off++] = max_picture_width & 0xff;
        header[off++] = (max_picture_height >> 8) & 0xff;
        header[off++] = max_picture_height;
        // setting avg_frame_rate to 0
        header[off++] = 0;
        header[off++] = 0;
    }
    header[off++] = numOfArrays;

    header += off;
    for (size_t i = 0; i < ARRAY_SIZE(kVvcNalUnitTypes); ++i) {
        uint8_t type = kVvcNalUnitTypes[i];
        size_t numNalus = getNumNalUnitsOfType(type);
        if (numNalus == 0) {
            continue;
        }
        // array_completeness set to 1.
        header[0] = type | 0x80;
        if (type != kVvcNalUnitTypeDci && type != kVvcNalUnitTypeOpi) {
            header[1] = (numNalus >> 8) & 0xff;
            header[2] = numNalus & 0xff;
            header += 2;
        }
        header += 1;

        for (size_t j = 0; j < numNalUnits; ++j) {
            if (getNalUnitType(j) != type) {
                continue;
            }
            header[0] = (getNalUnitSize(j) >> 8) & 0xff;
            header[1] = getNalUnitSize(j) & 0xff;
            if (!writeNalUnit(j, header + 2, size - (header - (uint8_t *)vvcc))) {
                return NO_MEMORY;
            }
            header += (2 + getNalUnitSize(j));
        }
    }
    ALOGV("vvcc size:%zu", size);
    CHECK_EQ(header - size, vvcc);

    return OK;
}

status_t VvcParameterSets::parseSps(const uint8_t* data, size_t size) {
    // See Rec. ITU-T H.266 v3 (09/2023) Chapter 7.3.2.4 for reference
    NALBitReader reader(data, size);
    // Skip sps_seq_parameter_set_id
    reader.skipBits(4);

    // We are using getBitsWithFallback from now on (fallback value of '0') to avoid many
    // "overRead" calls. In case of malformed content we will detect this in the end of this
    // function and correctly return ERR_MALFORMED
    uint8_t sps_video_parameter_set_id = reader.getBitsWithFallback(4, 0);
    uint8_t sps_max_sublayers_minus1 = reader.getBitsWithFallback(3, 0);
    uint8_t sps_chroma_format_idc = reader.getBitsWithFallback(2, 0);
    mParams[kChromaFormatIdc] = sps_chroma_format_idc;
    mParams[kNumSubLayers] = sps_max_sublayers_minus1 + 1;
    ALOGV("sps_max_sublayers_minus1:%u, sps_chroma_format_idc: %u",
            sps_max_sublayers_minus1, sps_chroma_format_idc);
    // sps_log2_ctu_size_minus5 plus 5 specifies the luma coding tree block size of each CTU.
    // The value of sps_log2_ctu_size_minus5 shall be in the range of 0 to 2, inclusive.
    // The value 3 for sps_log2_ctu_size_minus5 is reserved for future use by ITU-T | ISO/IEC.
    // Decoders conforming to this version of this Specification shall ignore the CLVSs with
    // sps_log2_ctu_size_minus5 equal to 3.
    // The variables CtbLog2SizeY and CtbSizeY are derived as follows:
    // CtbLog2SizeY = sps_log2_ctu_size_minus5 + 5 (35)
    // CtbSizeY = 1 << CtbLog2SizeY (36)
    uint8_t sps_log2_ctu_size_minus5 = reader.getBitsWithFallback(2, 0);
    uint32_t ctbSizeY = (1 << (sps_log2_ctu_size_minus5 + 5));
    bool sps_ptl_dpb_hrd_params_present_flag = reader.getBitsWithFallback(1, 0);
    if (sps_ptl_dpb_hrd_params_present_flag) {
        // PTR is short of profile_tier_level
        // There are 2 bytes before PTR and profile_tier_level is bytes align
        // so numBitsLeft can be used to calculate PTL size
        size_t leftBitsBeforePTL = reader.numBitsLeft();
        profileTierLevel(reader, 1, sps_max_sublayers_minus1);
        size_t leftBitsAfterPTL = reader.numBitsLeft();
        size_t ptl_size = (leftBitsBeforePTL - leftBitsAfterPTL)/8;
        mPtrRecord = ABuffer::CreateAsUniqueCopy((void*)(data + 2), ptl_size);
    }
    // Skip sps_gdr_enabled_flag
    reader.skipBits(1);
    if (reader.getBitsWithFallback(1, 0)) { //sps_ref_pic_resampling_enabled_flag
        // Skip sps_res_change_in_clvs_allowed_flag
        reader.skipBits(1);
    }
    // sps_pic_width_max_in_luma_samples specifies the maximum width,
    // in units of luma samples, of each decoded picture referring to the SPS.
    // sps_pic_width_max_in_luma_samples shall not be equal to 0
    // and shall be an integer multiple of Max( 8, MinCbSizeY )
    uint32_t sps_pic_width_max_in_luma_samples = parseUEWithFallback(&reader, 0);
    uint32_t sps_pic_height_max_in_luma_samples = parseUEWithFallback(&reader, 0);
    mParams[kMaxPictureWidth] = sps_pic_width_max_in_luma_samples;
    mParams[kMaxPictureHeight] = sps_pic_height_max_in_luma_samples;
    // Let the variable tmpWidthVal be set equal to
    // ( sps_pic_width_max_in_luma_samples + CtbSizeY − 1 ) / CtbSizeY,
    // and the variable tmpHeightVal be set equal to
    // ( sps_pic_height_max_in_luma_samples + CtbSizeY − 1 ) / CtbSizeY.
    uint32_t tmpWidthVal  = (sps_pic_width_max_in_luma_samples + ctbSizeY - 1) / ctbSizeY;
    uint32_t tmpHeightVal  =  (sps_pic_height_max_in_luma_samples + ctbSizeY - 1) / ctbSizeY;
    ALOGV("sps_pic_width_max_in_luma_samples:%u, sps_pic_height_max_in_luma_samples:%u,",
            sps_pic_width_max_in_luma_samples, sps_pic_height_max_in_luma_samples);
    if (reader.getBitsWithFallback(1, 0)) { //sps_conformance_window_flag
        // Skip sps_conf_win_left_offset
        skipUE(&reader);
        // Skip sps_conf_win_right_offset
        skipUE(&reader);
        // Skip sps_conf_win_top_offset
        skipUE(&reader);
        // Skip sps_conf_win_bottom_offset
        skipUE(&reader);
    }
    if (reader.getBitsWithFallback(1, 0)) { //sps_subpic_info_present_flag
        uint32_t sps_num_subpics_minus1 = parseUEWithFallback(&reader, 0);
        bool sps_independent_subpics_flag = true;
        bool sps_subpic_same_size_flag = false;
        if (sps_num_subpics_minus1 > 0) {
            sps_independent_subpics_flag = reader.getBitsWithFallback(1, 0);
            sps_subpic_same_size_flag = reader.getBitsWithFallback(1, 0);
        }

        // sps_subpic_ctu_top_left_x[i] specifies horizontal position of
        // top-left CTU of i-th subpicture in unit of CtbSizeY.
        // The length of the syntax element is Ceil( Log2( tmpWidthVal ) ) bits.
        // sps_subpic_ctu_top_left_y[i] specifies vertical position of
        // top-left CTU of i-th subpicture in unit of CtbSizeY.
        // The length of the syntax element is Ceil( Log2( tmpHeightVal ) ) bits
        size_t subpicSyntaxElementLengthX = (size_t)ceil(log2(tmpWidthVal));
        size_t subpicSyntaxElementLengthY = (size_t)ceil(log2(tmpHeightVal));
        ALOGV("sps_num_subpics_minus1:%u", sps_num_subpics_minus1);
        ALOGV("subpicSyntaxElementLengthX:%zu, subpicSyntaxElementLengthY:%zu",
               subpicSyntaxElementLengthX, subpicSyntaxElementLengthY);
        for (int i = 0; sps_num_subpics_minus1 > 0 && i <= sps_num_subpics_minus1; i++) {
            if (!sps_subpic_same_size_flag || i == 0) {
                if (i > 0 && sps_pic_width_max_in_luma_samples > ctbSizeY){
                    //sps_subpic_ctu_top_left_x[i]
                    reader.skipBits(subpicSyntaxElementLengthX);
                }
                if (i > 0 && sps_pic_height_max_in_luma_samples > ctbSizeY) {
                    //sps_subpic_ctu_top_left_y[i]
                    reader.skipBits(subpicSyntaxElementLengthY);
                }

                if (i < sps_num_subpics_minus1 && sps_pic_width_max_in_luma_samples > ctbSizeY) {
                    // sps_subpic_width_minus1[i]
                    reader.skipBits(subpicSyntaxElementLengthX);
                }

                if (i < sps_num_subpics_minus1 && sps_pic_height_max_in_luma_samples > ctbSizeY) {
                    // sps_subpic_height_minus1[i]
                    reader.skipBits(subpicSyntaxElementLengthY);
                }
            }
            if (!sps_independent_subpics_flag) {
                // sps_subpic_treated_as_pic_flag[i]
                reader.skipBits(1);
                // sps_loop_filter_across_subpic_enabled_flag[i]
                reader.skipBits(1);
            }
        }
        uint32_t sps_subpic_id_len_minus1 = parseUEWithFallback(&reader, 0);
        // sps_subpic_id_mapping_explicitly_signalled_flag
        if (reader.getBitsWithFallback(1, 0)) {
            // sps_subpic_id_mapping_present_flag
            if (reader.getBitsWithFallback(1, 0)) {
                for (int i = 0; i <= sps_num_subpics_minus1; i++) {
                    // sps_subpic_id[i] specifies the subpicture ID of the i-th subpicture.
                    // The length of the sps_subpic_id[ i] syntax element
                    // is sps_subpic_id_len_minus1 + 1 bits
                    reader.skipBits(sps_subpic_id_len_minus1 + 1);
                }
            }
        }
    }

    uint32_t sps_bitdepth_minus8 = parseUEWithFallback(&reader, 0);
    ALOGV("sps_bitdepth_minus8: %u", sps_bitdepth_minus8);
    mParams[kBitDepthChromaMinus8] = sps_bitdepth_minus8;
    // Skip sps_entropy_coding_sync_enabled_flag
    reader.skipBits(1);
    // Skip sps_entry_point_offsets_present_flag
    reader.skipBits(1);
    uint8_t sps_log2_max_pic_order_cnt_lsb_minus4 = reader.getBitsWithFallback(4, 0);

    if (reader.getBitsWithFallback(1, 0)) { //sps_poc_msb_cycle_flag
        // Skip sps_poc_msb_cycle_len_minus1
        skipUE(&reader);
    }
    uint8_t sps_num_extra_ph_bytes = reader.getBitsWithFallback(2, 0);
    // Skip sps_extra_ph_bit_present_flag bits
    reader.skipBits(sps_num_extra_ph_bytes * 8);
    uint8_t sps_num_extra_sh_bytes = reader.getBitsWithFallback(2, 0);
    // Skip sps_extra_sh_bit_present_flag bits
    reader.skipBits(sps_num_extra_sh_bytes * 8);

    if (sps_ptl_dpb_hrd_params_present_flag) {
        bool sps_sublayer_dpb_params_flag = false;
        if (sps_max_sublayers_minus1 > 0) {
            sps_sublayer_dpb_params_flag = reader.getBitsWithFallback(1, 0);
        }
        skipDpbParameters(&reader, sps_max_sublayers_minus1, sps_sublayer_dpb_params_flag);
    }
    // Skip sps_log2_min_luma_coding_block_size_minus2
    skipUE(&reader);
    // Skip sps_partition_constraints_override_enabled_flag
    reader.skipBits(1);
    // Skip sps_log2_diff_min_qt_min_cb_intra_slice_luma
    skipUE(&reader);
    if (parseUEWithFallback(&reader, 0)) { //sps_max_mtt_hierarchy_depth_intra_slice_luma
        // Skip sps_log2_diff_max_bt_min_qt_intra_slice_luma
        skipUE(&reader);
        // Skip sps_log2_diff_max_tt_min_qt_intra_slice_luma
        skipUE(&reader);
    }
    bool sps_qtbtt_dual_tree_intra_flag = false;
    if (sps_chroma_format_idc != 0) {
        sps_qtbtt_dual_tree_intra_flag = reader.getBitsWithFallback(1, 0);
    }
    if (sps_qtbtt_dual_tree_intra_flag) {
        // Skip sps_log2_diff_min_qt_min_cb_intra_slice_chroma
        skipUE(&reader);
        if (parseUEWithFallback(&reader, 0)) { //sps_max_mtt_hierarchy_depth_intra_slice_chroma
            // Skip sps_log2_diff_max_bt_min_qt_intra_slice_chroma
            skipUE(&reader);
            // Skip sps_log2_diff_max_tt_min_qt_intra_slice_chroma
            skipUE(&reader);
        }
    }
    // Skip sps_log2_diff_min_qt_min_cb_inter_slice
    skipUE(&reader);
    if (parseUEWithFallback(&reader, 0)) { //sps_max_mtt_hierarchy_depth_inter_slice
        // Skip sps_log2_diff_max_bt_min_qt_inter_slice
        skipUE(&reader);
        // Skip sps_log2_diff_max_tt_min_qt_inter_slice
        skipUE(&reader);
    }
    bool sps_max_luma_transform_size_64_flag = false;
    if (ctbSizeY > 32) {
        sps_max_luma_transform_size_64_flag = reader.getBitsWithFallback(1, 0);
    }
    bool sps_transform_skip_enabled_flag = reader.getBitsWithFallback(1, 0);
    if (sps_transform_skip_enabled_flag) {
        // Skip sps_log2_transform_skip_max_size_minus2
        skipUE(&reader);
        // Skip sps_bdpcm_enabled_flag
        reader.skipBits(1);
    }
    if (reader.getBitsWithFallback(1, 0)) { //sps_mts_enabled_flag
        // Skip sps_explicit_mts_intra_enabled_flag and sps_explicit_mts_inter_enabled_flag
        reader.skipBits(2);
    }
    bool sps_lfnst_enabled_flag = reader.getBitsWithFallback(1, 0);
    if (sps_chroma_format_idc) {
        bool sps_joint_cbcr_enabled_flag = reader.getBitsWithFallback(1, 0);
        bool sps_same_qp_table_for_chroma_flag = reader.getBitsWithFallback(1, 0);

        uint32_t numQpTables =
            sps_same_qp_table_for_chroma_flag ? 1 : (sps_joint_cbcr_enabled_flag ? 3 : 2);
        ALOGV("numQpTables:%u", numQpTables);
        for (uint32_t i = 0; i < numQpTables; i++) {
            // sps_qp_table_start_minus26[i]
            skipSE(&reader);
            // sps_num_points_in_qp_table_minus1[i]
            uint32_t sps_num_points_in_qp_table_minus1 = parseUEWithFallback(&reader, 0);
            ALOGV("sps_num_points_in_qp_table_minus1:%u", sps_num_points_in_qp_table_minus1);
            for (uint32_t j = 0; j <= sps_num_points_in_qp_table_minus1; j++) {
                // sps_delta_qp_in_val_minus1[i][j]
                skipUE(&reader);
                // sps_delta_qp_diff_val[i][j]
                skipUE(&reader);
            }
        }
    }
    // Skip sps_sao_enabled_flag
    reader.skipBits(1);
    if (reader.getBitsWithFallback(1, 0) && sps_chroma_format_idc) { //sps_alf_enabled_flag
        // Skip sps_ccalf_enabled_flag
        reader.skipBits(1);
    }
    // Skip sps_lmcs_enabled_flag
    reader.skipBits(1);
    bool sps_weighted_pred_flag = reader.getBitsWithFallback(1, 0);
    bool sps_weighted_bipred_flag = reader.getBitsWithFallback(1, 0);
    // sps_long_term_ref_pics_flag
    bool sps_long_term_ref_pics_flag = reader.getBitsWithFallback(1, 0);
    bool sps_inter_layer_prediction_enabled_flag = false;
    if (sps_video_parameter_set_id) {
        //sps_inter_layer_prediction_enabled_flag
        sps_inter_layer_prediction_enabled_flag = reader.getBitsWithFallback(1, 0);
    }
    // Skip sps_idr_rpl_present_flag
    reader.skipBits(1);
    bool sps_rpl1_same_as_rpl0_flag = reader.getBitsWithFallback(1, 0);
    for (uint32_t i = 0; i < (sps_rpl1_same_as_rpl0_flag ? 1 : 2); i++) {
        // sps_num_ref_pic_lists[i];
        uint32_t sps_num_ref_pic_lists = parseUEWithFallback(&reader, 0);
        ALOGV("sps_num_ref_pic_lists:%u", sps_num_ref_pic_lists);
        for (uint32_t j = 0; j < sps_num_ref_pic_lists; j++) {
            skipRefPicListStruct(&reader, j, sps_num_ref_pic_lists,
                                    sps_long_term_ref_pics_flag,
                                    sps_inter_layer_prediction_enabled_flag,
                                    sps_weighted_pred_flag,
                                    sps_weighted_bipred_flag,
                                    sps_log2_max_pic_order_cnt_lsb_minus4);
        }
    }
    // Skip sps_ref_wraparound_enabled_flag
    reader.skipBits(1);
    if (reader.getBitsWithFallback(1, 0)) { //sps_temporal_mvp_enabled_flag
        // Skip sps_sbtmvp_enabled_flag
        reader.skipBits(1);
    }
    bool sps_amvr_enabled_flag = reader.getBitsWithFallback(1, 0);
    if (reader.getBitsWithFallback(1, 0)) { //sps_bdof_enabled_flag
        // Skip sps_bdof_control_present_in_ph_flag
        reader.skipBits(1);
    }
    // Skip sps_smvd_enabled_flag
    reader.skipBits(1);
    if (reader.getBitsWithFallback(1, 0)) { //sps_dmvr_enabled_flag
        // Skip sps_dmvr_control_present_in_ph_flag
        reader.skipBits(1);
    }
    if (reader.getBitsWithFallback(1, 0)) { //sps_mmvd_enabled_flag
        // Skip sps_mmvd_fullpel_only_enabled_flag
        reader.skipBits(1);
    }
    uint32_t sps_six_minus_max_num_merge_cand = parseUEWithFallback(&reader, 0);
    // Skip sps_sbt_enabled_flag
    reader.skipBits(1);
    if (reader.getBitsWithFallback(1, 0)) { //sps_affine_enabled_flag
        // Skip sps_five_minus_max_num_subblock_merge_cand
        skipUE(&reader);
        // Skip sps_6param_affine_enabled_flag
        reader.skipBits(1);
        if (sps_amvr_enabled_flag) {
            // Skip sps_affine_amvr_enabled_flag
            reader.skipBits(1);
        }
        if (reader.getBitsWithFallback(1, 0)) { //sps_affine_prof_enabled_flag
            // Skip sps_prof_control_present_in_ph_flag
            reader.skipBits(1);
        }
    }
    // Skip sps_bcw_enabled_flag
    reader.skipBits(1);
    // Skip sps_ciip_enabled_flag
    reader.skipBits(1);
    uint32_t MaxNumMergeCand = 6 - sps_six_minus_max_num_merge_cand;
    if (MaxNumMergeCand >= 2) {
        if (reader.getBitsWithFallback(1, 0) && MaxNumMergeCand >= 3) { //sps_gpm_enabled_flag
            // Skip sps_max_num_merge_cand_minus_max_num_gpm_cand
            skipUE(&reader);
        }
    }
    // Skip sps_log2_parallel_merge_level_minus2
    skipUE(&reader);
    // Skip sps_isp_enabled_flag
    reader.skipBits(1);
    // Skip sps_mrl_enabled_flag
    reader.skipBits(1);
    // Skip sps_mip_enabled_flag
    reader.skipBits(1);
    if (sps_chroma_format_idc) {
        // Skip sps_chroma_format_idc
        reader.skipBits(1);
    }
    if (sps_chroma_format_idc == 1) {
        // Skip sps_chroma_horizontal_collocated_flag
        reader.skipBits(1);
        // Skip sps_chroma_vertical_collocated_flag
        reader.skipBits(1);
    }
    bool sps_palette_enabled_flag = reader.getBitsWithFallback(1, 0);
    bool sps_act_enabled_flag = false;
    if (sps_chroma_format_idc == 3 && !sps_max_luma_transform_size_64_flag) {
        sps_act_enabled_flag = reader.getBitsWithFallback(1, 0);
    }
    if (sps_transform_skip_enabled_flag || sps_palette_enabled_flag){
        // Skip sps_min_qp_prime_ts
        skipUE(&reader);
    }
    if (reader.getBitsWithFallback(1, 0)) { //sps_ibc_enabled_flag
        // Skip sps_six_minus_max_num_ibc_merge_cand
        skipUE(&reader);
    }
    if (reader.getBitsWithFallback(1, 0)) { //sps_ladf_enabled_flag
        uint8_t sps_num_ladf_intervals_minus2 = reader.getBitsWithFallback(2, 0);
        // Skip sps_ladf_lowest_interval_qp_offset
        skipSE(&reader);
        for (int i = 0; i < sps_num_ladf_intervals_minus2 + 1; i++) {
            // Skip sps_ladf_qp_offset[i]
            skipSE(&reader);
            // Skip sps_ladf_delta_threshold_minus1[i]
            skipUE(&reader);
        }
    }
    bool sps_explicit_scaling_list_enabled_flag = reader.getBitsWithFallback(1, 0);
    if (sps_lfnst_enabled_flag && sps_explicit_scaling_list_enabled_flag) {
        // Skip sps_scaling_matrix_for_lfnst_disabled_flag
        reader.skipBits(1);
    }
    bool sps_scaling_matrix_for_alternative_colour_space_disabled_flag = false;
    if (sps_act_enabled_flag && sps_explicit_scaling_list_enabled_flag) {
        sps_scaling_matrix_for_alternative_colour_space_disabled_flag =
            reader.getBitsWithFallback(1, 0);
    }
    if (sps_scaling_matrix_for_alternative_colour_space_disabled_flag) {
        // Skip sps_scaling_matrix_designated_colour_space_flag
        reader.skipBits(1);
    }
    // Skip sps_dep_quant_enabled_flag
    reader.skipBits(1);
    // Skip sps_sign_data_hiding_enabled_flag
    reader.skipBits(1);
    if (reader.getBitsWithFallback(1, 0)) { //sps_virtual_boundaries_enabled_flag
        if (reader.getBitsWithFallback(1, 0)) { //sps_virtual_boundaries_present_flag
            uint32_t sps_num_ver_virtual_boundaries = parseUEWithFallback(&reader, 0);
            for (int i = 0; i < sps_num_ver_virtual_boundaries; i++) {
                // Skip sps_virtual_boundary_pos_x_minus1[i]
                skipUE(&reader);
            }
            uint32_t sps_num_hor_virtual_boundaries = parseUEWithFallback(&reader, 0);
            for (int i = 0; i < sps_num_hor_virtual_boundaries; i++) {
                // Skip sps_virtual_boundary_pos_y_minus1[i]
                 skipUE(&reader);
            }
        }
    }
    if (sps_ptl_dpb_hrd_params_present_flag) {
        if (reader.getBitsWithFallback(1, 0)) { // sps_timing_hrd_params_present_flag
            // general_timing_hrd_parameters begin
            // See ITU-T H.266 section 7.3.5.1
            // Skip num_units_in_tick
            reader.skipBits(32);
            // Skip time_scale
            reader.skipBits(32);

            // Read the flags for NAL and VCL HRD parameters presence
            bool general_nal_hrd_params_present_flag = reader.getBitsWithFallback(1, 0);
            bool general_vcl_hrd_params_present_flag = reader.getBitsWithFallback(1, 0);
            uint32_t hrd_cpb_cnt_minus1 = 0;
            bool general_du_hrd_params_present_flag = false;
            // Check if either NAL or VCL HRD parameters are present
            if (general_nal_hrd_params_present_flag || general_vcl_hrd_params_present_flag) {
                // Skip general_same_pic_timing_in_all_ols_flag
                reader.skipBits(1);
                general_du_hrd_params_present_flag = reader.getBitsWithFallback(1, 0);
                // If general_du_hrd_params_present_flag is true, skip tick_divisor_minus2
                if (general_du_hrd_params_present_flag) {
                    reader.skipBits(8); // Skip tick_divisor_minus2
                }

                // Skip bit_rate_scale and cpb_size_scale
                reader.skipBits(8);

                if (general_du_hrd_params_present_flag) {
                    reader.skipBits(4); // Skip cpb_size_du_scale
                }

                // hrd_cpb_cnt_minus1
                hrd_cpb_cnt_minus1 = parseUEWithFallback(&reader, 0);
            }
            // general_timing_hrd_parameters end
            bool sps_sublayer_cpb_params_present_flag = false;
            if (sps_max_sublayers_minus1 > 0) {
                sps_sublayer_cpb_params_present_flag = reader.getBitsWithFallback(1, 0);
            }
            uint8_t firstSubLayer =
                sps_sublayer_cpb_params_present_flag ? 0 : sps_max_sublayers_minus1;
            // ols_timing_hrd_parameters begin
            for (uint32_t i = firstSubLayer; i <= sps_max_sublayers_minus1; i++) {
                bool fixed_pic_rate_within_cvs_flag = 0;

                // fixed_pic_rate_general_flag
                if (!reader.getBitsWithFallback(1, 0)) {
                    fixed_pic_rate_within_cvs_flag = reader.getBitsWithFallback(1, 0);
                }

                if (fixed_pic_rate_within_cvs_flag) {
                    skipUE(&reader); // Skip elemental_duration_in_tc_minus1[i]
                } else if ((general_nal_hrd_params_present_flag
                                || general_vcl_hrd_params_present_flag)
                            && hrd_cpb_cnt_minus1 == 0) {
                    reader.skipBits(1); // Skip low_delay_hrd_flag[i]
                }

                if (general_nal_hrd_params_present_flag) {
                    skipSublayerHrdParameters(&reader,
                                            general_du_hrd_params_present_flag,
                                            hrd_cpb_cnt_minus1);
                }

                if (general_vcl_hrd_params_present_flag) {
                    skipSublayerHrdParameters(&reader,
                                            general_du_hrd_params_present_flag,
                                            hrd_cpb_cnt_minus1);
                }
            }
            // ols_timing_hrd_parameters end
        }
    }
    // Skip sps_field_seq_flag
    reader.skipBits(1);
    if (reader.getBitsWithFallback(1, 0)) { // sps_vui_parameters_present_flag
        // Skip sps_vui_payload_size_minus1
        skipUE(&reader);
        while(reader.numBitsLeft() > 0 && reader.numBitsLeft() % 8 != 0) {
            // Skip sps_vui_alignment_zero_bit
            reader.skipBits(1);
        }
        // vui_parameters Specified in Rec. ITU-T H.274 | ISO/IEC 23002-7 section 7.2
        reader.skipBits(1); // Skip vui_progressive_source_flag
        reader.skipBits(1); // Skip vui_interlaced_source_flag
        reader.skipBits(1); // Skip vui_non_packed_constraint_flag
        reader.skipBits(1); // Skip vui_non_projected_constraint_flag
        if (reader.getBitsWithFallback(1, 0)) { // vui_aspect_ratio_info_present_flag
            reader.skipBits(1);                 // Skip vui_aspect_ratio_constant_flag
            uint8_t vui_aspect_ratio_idc = reader.getBitsWithFallback(8, 0);
            if (vui_aspect_ratio_idc == 255) {
                reader.skipBits(16); // Skip vui_sar_width
                reader.skipBits(16); // Skip vui_sar_height
            }
        }
        if (reader.getBitsWithFallback(1, 0)) { // vui_overscan_info_present_flag
            reader.skipBits(1); // Skip vui_overscan_appropriate_flag
        }
        if (reader.getBitsWithFallback(1, 0)) { // vui_colour_description_present_flag
            mInfo = (Info)(mInfo | kInfoHasColorDescription);
            uint32_t colourPrimaries, transferCharacteristics, matrixCoeffs, videoFullRangeFlag;
            if (reader.getBitsGraceful(8, &colourPrimaries)) {
                mParams[kColourPrimaries] = colourPrimaries;
            }
            if (reader.getBitsGraceful(8, &transferCharacteristics)) {
                mParams[kTransferCharacteristics] = transferCharacteristics;
                if (transferCharacteristics == 16 /* ST 2084 */
                        || transferCharacteristics == 18 /* ARIB STD-B67 HLG */) {
                    mInfo = (Info)(mInfo | kInfoIsHdr);
                }
            }
            if (reader.getBitsGraceful(8, &matrixCoeffs)) {
                mParams[kMatrixCoeffs] = matrixCoeffs;
            }
            if (reader.getBitsGraceful(1, &videoFullRangeFlag)) {
                mParams[kVideoFullRangeFlag] = videoFullRangeFlag;
            }
        }
        // skip rest of VUI
    }

    return reader.overRead() ? ERROR_MALFORMED : OK;
}

// Rec. ITU-T H.266 (V3) Chapter 7.3.3.1 General profile, tier, and level syntax
void VvcParameterSets::profileTierLevel(NALBitReader &br,
                                            uint32_t profileTierPresentFlag,
                                            int MaxNumSubLayersMinus1) {
    uint8_t general_profile_idc = 0;
    uint8_t general_tier_flag = 0;
    if (profileTierPresentFlag) {
        // general_profile_idc(u(7)) and general_tier_flag (u(1))
        general_profile_idc = br.getBitsWithFallback(7, 0);
        general_tier_flag = br.getBitsWithFallback(1, 0);
    }

    // general_level_idc u(8)
    uint8_t general_level_idc = br.getBitsWithFallback(8, 0);
    ALOGV("general_profile_idc:%u, general_tier_flag:%u, general_level_idc:%u",
        general_profile_idc, general_tier_flag, general_level_idc);
    // Skip ptl_frame_only_constraint_flag and ptl_multilayer_enabled_flag
    br.skipBits(2);
    if (profileTierPresentFlag) {
        skipGeneralConstraintsInfo(br);
    }

    // Assuming ptl_sublayer_level_present_flag is an array of uint8_t
    uint8_t ptl_sublayer_level_present_flag[MaxNumSubLayersMinus1];
    for (int i = MaxNumSubLayersMinus1 - 1; i >= 0; i--) {
        ptl_sublayer_level_present_flag[i] = br.getBitsWithFallback(1, 0);
    }

    while (br.numBitsLeft() > 0 && br.numBitsLeft() % 8 != 0) {
        br.getBitsWithFallback(1, 0); // ptl_reserved_zero_bit
    }

    for (int i = MaxNumSubLayersMinus1 - 1; i >= 0; i--) {
        if (ptl_sublayer_level_present_flag[i]) {
            // sublayer_level_idc[i]
            br.skipBits(8);
        }
    }

    if (profileTierPresentFlag) {
        uint32_t ptl_num_sub_profiles = br.getBitsWithFallback(8, 0);
        for (uint32_t i = 0; i < ptl_num_sub_profiles; i++) {
            // general_sub_profile_idc[i]
            br.skipBits(32);
        }
    }
}

void VvcParameterSets::skipGeneralConstraintsInfo(NALBitReader &br) {
    size_t leftBitsBeforeGCI = br.numBitsLeft();
    bool gci_present_flag = br.getBitsWithFallback(1, 0);
    if (gci_present_flag) {
        // Skip general constraint flags
        br.skipBits(3);

        // Skip picture format constraint flags
        br.skipBits(6);

        // Skip NAL unit type related constraint flags
        br.skipBits(10);

        // Skip tile, slice, subpicture partitioning constraint flags
        br.skipBits(6);

        // Skip CTU and block partitioning constraint flags
        br.skipBits(5);

        // Skip intra constraint flags
        br.skipBits(6);

        // Skip inter constraint flags
        br.skipBits(16);

        // Skip transform, quantization, residual constraint flags
        br.skipBits(13);

        // Skip loop filter constraint flags
        br.skipBits(6);

        uint32_t gci_num_additional_bits = br.getBitsWithFallback(8, 0);
        uint32_t numAdditionalBitsUsed = 0;

        if (gci_num_additional_bits > 5) {
            // Skip additional constraint flags if gci_num_additional_bits > 5
            br.skipBits(6);
            numAdditionalBitsUsed = 6;
        }

        // Skip any remaining reserved bits
        br.skipBits(gci_num_additional_bits - numAdditionalBitsUsed);
    }

    // Skip any alignment bits until the next byte boundary
    while (br.numBitsLeft() > 0 && br.numBitsLeft() % 8 != 0) {
        br.getBitsWithFallback(1, 0); // Skip gci_alignment_zero_bit
    }
    size_t leftBitsAfterGCI = br.numBitsLeft();

    uint32_t num_bytes_constraint_info = (leftBitsBeforeGCI - leftBitsAfterGCI + 2)/8;
    mParams[kNumBytesConstraintInfo] = num_bytes_constraint_info;
}

void VvcParameterSets::skipDpbParameters(ABitReader* br,
                                        uint32_t maxSubLayersMinus1,
                                        uint32_t subLayerInfoFlag)  {
    // Parsing dpbParameters as in ITU-T H.266 secion 7.3.4
    for (uint32_t i = (subLayerInfoFlag ? 0 : maxSubLayersMinus1); i <= maxSubLayersMinus1; i++) {
        // dpb_max_dec_pic_buffering_minus1[i]
        skipUE(br);
        // dpb_max_num_reorder_pics[i]
        skipUE(br);
        // dpb_max_latency_increase_plus1[i]
        skipUE(br);
    }
}

void VvcParameterSets::skipRefPicListStruct(ABitReader* br,
                                            uint32_t rplsIdx,
                                            uint32_t sps_num_ref_pic_lists,
                                            bool sps_long_term_ref_pics_flag,
                                            bool sps_inter_layer_prediction_enabled_flag,
                                            bool sps_weighted_pred_flag,
                                            bool sps_weighted_bipred_flag,
                                            uint8_t sps_log2_max_pic_order_cnt_lsb_minus4) {
    // parsing ref_pic_list as in ITU-T H.266 section 7.3.9
    uint32_t num_ref_entries = parseUEWithFallback(br, 0);
    ALOGV("num_ref_entries:%u", num_ref_entries);
    bool ltrp_in_header_flag = false;
    if (sps_long_term_ref_pics_flag) {
        // When sps_long_term_ref_pics_flag is equal to 1 and
        // rplsIdx is equal to sps_num_ref_pic_lists[ listIdx ], the value of
        // ltrp_in_header_flag[ listIdx ][ rplsIdx ] is inferred to be equal to 1
        if (rplsIdx == sps_num_ref_pic_lists) {
            ltrp_in_header_flag = true;
        }
        if (rplsIdx < sps_num_ref_pic_lists && num_ref_entries > 0) {
            ltrp_in_header_flag = br->getBitsWithFallback(1, 0);
        }
    }

    for (uint32_t i = 0; i < num_ref_entries; i++) {
        bool inter_layer_ref_pic_flag = false;
        if (sps_inter_layer_prediction_enabled_flag) {
            inter_layer_ref_pic_flag = br->getBitsWithFallback(1, 0);
        }

        if (!inter_layer_ref_pic_flag) {
            // When inter_layer_ref_pic_flag[listIdx][rplsIdx [i] is equal to 0
            // and st_ref_pic_flag[ listIdx ][ rplsIdx ][ i ] is not present, the
            // value of st_ref_pic_flag[ listIdx ][ rplsIdx ][ i ] is inferred to be equal to 1.
            bool st_ref_pic_flag = true;
            if (sps_long_term_ref_pics_flag) {
                st_ref_pic_flag = br->getBitsWithFallback(1, 0);
            }

            if (st_ref_pic_flag) {
                uint32_t abs_delta_poc_st = parseUEWithFallback(br, 0);
                // abs_delta_poc_st[listIdx][rplsIdx][i] specifies the value
                // of the variable AbsDeltaPocSt[listIdx][rplsIdx][i] as follows:
                // if((sps_weighted_pred_flag || sps_weighted_bipred_flag) && i != 0 )
                // AbsDeltaPocSt[listIdx][rplsIdx][i] = abs_delta_poc_st[listIdx][rplsIdx][i]
                // else
                // AbsDeltaPocSt[listIdx][rplsIdx][i] = abs_delta_poc_st[listIdx][rplsIdx][i] + 1
                uint32_t absDeltaPocSt = 0;
                if ((sps_weighted_pred_flag || sps_weighted_bipred_flag) && i != 0) {
                    absDeltaPocSt = abs_delta_poc_st;
                } else {
                    absDeltaPocSt = abs_delta_poc_st + 1;
                }
                if (absDeltaPocSt > 0) {
                    // Skip strp_entry_sign_flag
                    br->skipBits(1);
                }
            } else if (!ltrp_in_header_flag) {
                // Skip rpls_poc_lsb_lt[listIdx][rplsIdx][i]
                // The length of the rpls_poc_lsb_lt[listIdx][rplsIdx][i] syntax element
                // is sps_log2_max_pic_order_cnt_lsb_minus4 + 4 bits
                br->skipBits(sps_log2_max_pic_order_cnt_lsb_minus4 + 4);
            }
        } else {
            // Skip ilrp_idx
            skipUE(br);
        }
    }
}

void VvcParameterSets::skipSublayerHrdParameters(ABitReader* br,
                                                bool general_du_hrd_params_present_flag,
                                                uint32_t hrd_cpb_cnt_minus1) {
    for (uint32_t j = 0; j <= hrd_cpb_cnt_minus1; j++) {
        skipUE(br); // Skip bit_rate_value_minus1[subLayerId][j]
        skipUE(br); // Skip cpb_size_value_minus1[subLayerId][j]

        if (general_du_hrd_params_present_flag) {
            skipUE(br); // Skip cpb_size_du_value_minus1[subLayerId][j]
            skipUE(br); // Skip bit_rate_du_value_minus1[subLayerId][j]
        }

        br->skipBits(1); // Skip cbr_flag[subLayerId][j]
    }
}


}  // namespace android
