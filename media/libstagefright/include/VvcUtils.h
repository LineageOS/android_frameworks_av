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

#ifndef VVC_UTILS_H_

#define VVC_UTILS_H_

#include <map>
#include <memory>
#include <vector>

#include <stdint.h>
#include "include/HevcUtils.h"
#include <media/stagefright/foundation/ABase.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ABitReader.h>
#include <utils/Errors.h>
#include <utils/StrongPointer.h>

namespace android {

enum {
    kVvcNalUnitTypeCodedSliceTrail = 0,   // 0
    kVvcNalUnitTypeCodedSliceStsa,        // 1
    kVvcNalUnitTypeCodedSliceRadl,        // 2
    kVvcNalUnitTypeCodedSliceRasl,        // 3

    kVvcNalUnitTypeReservedVcl4,
    kVvcNalUnitTypeReservedVcl5,
    kVvcNalUnitTypeReservedVcl6,

    kVvcNalUnitTypeCodedSliceIdrWRadl,    // 7
    kVvcNalUnitTypeCodedSliceIdrNoLp,     // 8
    kVvcNalUnitTypeCodedSliceCra,         // 9
    kVvcNalUnitTypeCodedSliceGdr,         // 10

    kVvcNalUnitTypeReservedIrapVcl11,
    kVvcNalUnitTypeOpi,                   // 12
    kVvcNalUnitTypeDci,                   // 13
    kVvcNalUnitTypeVps,                   // 14
    kVvcNalUnitTypeSps,                   // 15
    kVvcNalUnitTypePps,                   // 16
    kVvcNalUnitTypePrefixAps,             // 17
    kVvcNalUnitTypeSuffixAps,             // 18
    kVvcNalUnitTypePh,                    // 19
    kVvcNalUnitTypeAccessUntiDelimiter,   // 20
    kVvcNalUnitTypeEos,                   // 21
    kVvcNalUnitTypeEob,                   // 22
    kVvcNalUnitTypePrefixSei,             // 23
    kVvcNalUnitTypeSuffixSei,             // 24
    kVvcNalUnitTypeFd,                    // 25

    kVvcNalUnitTypeReservedNvcl26,
    kVvcNalUnitTypeReservedNvcl27,

    kVvcNalUnitTypeUnspecified28,
    kVvcNalUnitTypeUnspecified29,
    kVvcNalUnitTypeUnspecified30,
    kVvcNalUnitTypeUnspecified31,
    kVvcNalUnitTypeInvalid,
};

enum {
    // uint8_t
    kNumSubLayers,
    // uint32_t
    kMaxPictureWidth,
    // uint32_t
    kMaxPictureHeight,
    // uint32_t
    kNumBytesConstraintInfo,
};

class VvcParameterSets {
public:
    enum Info : uint32_t {
        kInfoNone                = 0,
        kInfoIsHdr               = 1 << 0,
        kInfoHasColorDescription = 1 << 1,
    };

    VvcParameterSets();

    status_t addNalUnit(const uint8_t* data, size_t size);

    bool findParam8(uint32_t key, uint8_t &param);
    bool findParam16(uint32_t key, uint16_t &param);
    bool findParam32(uint32_t key, uint32_t &param);
    bool findParam64(uint32_t key, uint64_t &param);

    inline size_t getNumNalUnits() { return mNalUnits.size(); }
    size_t getNumNalUnitsOfType(uint8_t type);
    uint8_t getNalUnitType(size_t index);
    size_t getNalUnitSize(size_t index);
    // Note that this method does not write the start code.
    bool writeNalUnit(size_t index, uint8_t* dest, size_t size);
    status_t makeVvcc(uint8_t *vvcc, size_t &vvccSize, size_t nalSizeLength);

    Info getInfo() const { return mInfo; }

private:
    status_t parseVps(const uint8_t* data, size_t size);
    status_t parseSps(const uint8_t* data, size_t size);
    status_t parsePps(const uint8_t* data, size_t size);

    void profileTierLevel(NALBitReader &br,
                                uint32_t profileTierPresentFlag,
                                int MaxNumSubLayersMinus1);
    void skipGeneralConstraintsInfo(NALBitReader &br);
    void skipDpbParameters(ABitReader* br,
                            uint32_t MaxSubLayersMinus1,
                            uint32_t subLayerInfoFlag);
    void skipRefPicListStruct(ABitReader* br,
                                uint32_t rplsIdx,
                                uint32_t sps_num_ref_pic_lists,
                                bool sps_long_term_ref_pics_flag,
                                bool sps_inter_layer_prediction_enabled_flag,
                                bool sps_weighted_pred_flag,
                                bool sps_weighted_bipred_flag,
                                uint8_t sps_log2_max_pic_order_cnt_lsb_minus4);
    void skipSublayerHrdParameters(ABitReader* br,
                                    bool general_du_hrd_params_present_flag,
                                    uint32_t hrd_cpb_cnt_minus1);
    std::map<uint32_t, uint64_t> mParams;
    std::vector<std::unique_ptr<ABuffer>> mNalUnits;
    Info mInfo;
    std::unique_ptr<ABuffer> mPtrRecord;
    DISALLOW_EVIL_CONSTRUCTORS(VvcParameterSets);
};

}  // namespace android

#endif  // Vvc_UTILS_H_