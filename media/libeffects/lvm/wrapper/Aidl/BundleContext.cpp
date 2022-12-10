/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <cstddef>
#define LOG_TAG "BundleContext"
#include <Utils.h>

#include "BundleContext.h"
#include "BundleTypes.h"

namespace aidl::android::hardware::audio::effect {

RetCode BundleContext::init() {
    std::lock_guard lg(mMutex);
    // init with pre-defined preset NORMAL
    for (std::size_t i = 0; i < lvm::MAX_NUM_BANDS; i++) {
        mBandGaindB[i] = lvm::kSoftPresets[0 /* normal */][i];
    }

    // allocate lvm instance
    LVM_ReturnStatus_en status;
    LVM_InstParams_t params = {.BufferMode = LVM_UNMANAGED_BUFFERS,
                               .MaxBlockSize = lvm::MAX_CALL_SIZE,
                               .EQNB_NumBands = lvm::MAX_NUM_BANDS,
                               .PSA_Included = LVM_PSA_ON};
    status = LVM_GetInstanceHandle(&mInstance, &params);
    GOTO_IF_LVM_ERROR(status, deinit, "LVM_GetInstanceHandleFailed");

    // set control
    LVM_ControlParams_t controlParams;
    initControlParameter(controlParams);
    status = LVM_SetControlParameters(mInstance, &controlParams);
    GOTO_IF_LVM_ERROR(status, deinit, "LVM_SetControlParametersFailed");

    /* Set the headroom parameters */
    LVM_HeadroomParams_t headroomParams;
    initHeadroomParameter(headroomParams);
    status = LVM_SetHeadroomParams(mInstance, &headroomParams);
    GOTO_IF_LVM_ERROR(status, deinit, "LVM_SetHeadroomParamsFailed");

    return RetCode::SUCCESS;

deinit:
    deInit();
    return RetCode::ERROR_EFFECT_LIB_ERROR;
}

void BundleContext::deInit() {
    std::lock_guard lg(mMutex);
    if (mInstance) {
        LVM_DelInstanceHandle(&mInstance);
        mInstance = nullptr;
    }
}

RetCode BundleContext::enable() {
    LVM_ControlParams_t params;
    {
        std::lock_guard lg(mMutex);
        RETURN_VALUE_IF(LVM_SUCCESS != LVM_GetControlParameters(mInstance, &params),
                        RetCode::ERROR_EFFECT_LIB_ERROR, "failGetControlParams");
        if (mType == lvm::BundleEffectType::EQUALIZER) {
            LOG(DEBUG) << __func__ << " enable bundle EQ";
            params.EQNB_OperatingMode = LVM_EQNB_ON;
        }
        RETURN_VALUE_IF(LVM_SUCCESS != LVM_SetControlParameters(mInstance, &params),
                        RetCode::ERROR_EFFECT_LIB_ERROR, "failSetControlParams");
    }
    mEnabled = true;
    // LvmEffect_limitLevel(pContext);
    return RetCode::SUCCESS;
}

RetCode BundleContext::disable() {
    LVM_ControlParams_t params;
    {
        std::lock_guard lg(mMutex);
        RETURN_VALUE_IF(LVM_SUCCESS != LVM_GetControlParameters(mInstance, &params),
                        RetCode::ERROR_EFFECT_LIB_ERROR, "failGetControlParams");
        if (mType == lvm::BundleEffectType::EQUALIZER) {
            LOG(DEBUG) << __func__ << " disable bundle EQ";
            params.EQNB_OperatingMode = LVM_EQNB_OFF;
        }
        RETURN_VALUE_IF(LVM_SUCCESS != LVM_SetControlParameters(mInstance, &params),
                        RetCode::ERROR_EFFECT_LIB_ERROR, "failSetControlParams");
    }
    mEnabled = false;
    // LvmEffect_limitLevel(pContext);
    return RetCode::SUCCESS;
}

LVM_INT16 BundleContext::LVC_ToDB_s32Tos16(LVM_INT32 Lin_fix) const {
    LVM_INT16 db_fix;
    LVM_INT16 Shift;
    LVM_INT16 SmallRemainder;
    LVM_UINT32 Remainder = (LVM_UINT32)Lin_fix;

    /* Count leading bits, 1 cycle in assembly*/
    for (Shift = 0; Shift < 32; Shift++) {
        if ((Remainder & 0x80000000U) != 0) {
            break;
        }
        Remainder = Remainder << 1;
    }

    /*
     * Based on the approximation equation (for Q11.4 format):
     *
     * dB = -96 * Shift + 16 * (8 * Remainder - 2 * Remainder^2)
     */
    db_fix = (LVM_INT16)(-96 * Shift); /* Six dB steps in Q11.4 format*/
    SmallRemainder = (LVM_INT16)((Remainder & 0x7fffffff) >> 24);
    db_fix = (LVM_INT16)(db_fix + SmallRemainder);
    SmallRemainder = (LVM_INT16)(SmallRemainder * SmallRemainder);
    db_fix = (LVM_INT16)(db_fix - (LVM_INT16)((LVM_UINT16)SmallRemainder >> 9));

    /* Correct for small offset */
    db_fix = (LVM_INT16)(db_fix - 5);

    return db_fix;
}

// TODO: replace with more generic approach, like: audio_utils_power_from_amplitude
int16_t BundleContext::VolToDb(uint32_t vol) const {
    int16_t dB;

    dB = LVC_ToDB_s32Tos16(vol << 7);
    dB = (dB + 8) >> 4;
    dB = (dB < -96) ? -96 : dB;

    return dB;
}

RetCode BundleContext::setVolumeStereo(const Parameter::VolumeStereo& volume) {
    LVM_ControlParams_t params;
    LVM_ReturnStatus_en status = LVM_SUCCESS;

    // Convert volume to dB
    int leftdB = VolToDb(volume.left);
    int rightdB = VolToDb(volume.right);
    int maxdB = std::max(leftdB, rightdB);
    int pandB = rightdB - leftdB;
    // TODO: add volume effect implementation here:
    // android::VolumeSetVolumeLevel(pContext, (int16_t)(maxdB * 100));
    LOG(DEBUG) << __func__ << " pandB: " << pandB << " maxdB " << maxdB;

    {
        std::lock_guard lg(mMutex);
        RETURN_VALUE_IF(LVM_SUCCESS != LVM_GetControlParameters(mInstance, &params),
                        RetCode::ERROR_EFFECT_LIB_ERROR, "");
        params.VC_Balance = pandB;

        RETURN_VALUE_IF(LVM_SUCCESS != LVM_SetControlParameters(mInstance, &params),
                        RetCode::ERROR_EFFECT_LIB_ERROR, "");
    }
    mVolumeStereo = volume;
    return RetCode::SUCCESS;
}

RetCode BundleContext::setEqualizerPreset(const std::size_t presetIdx) {
    if (presetIdx < 0 || presetIdx >= lvm::MAX_NUM_PRESETS) {
        return RetCode::ERROR_ILLEGAL_PARAMETER;
    }

    std::vector<Equalizer::BandLevel> bandLevels;
    bandLevels.reserve(lvm::MAX_NUM_BANDS);
    for (std::size_t i = 0; i < lvm::MAX_NUM_BANDS; i++) {
        bandLevels.emplace_back(
                Equalizer::BandLevel{static_cast<int32_t>(i), lvm::kSoftPresets[presetIdx][i]});
    }

    RetCode ret = updateControlParameter(bandLevels);
    if (RetCode::SUCCESS == ret) {
        mCurPresetIdx = presetIdx;
        LOG(INFO) << __func__ << " success with " << presetIdx;
    } else {
        LOG(ERROR) << __func__ << " failed to setPreset " << presetIdx;
    }
    return ret;
}

RetCode BundleContext::setEqualizerBandLevels(const std::vector<Equalizer::BandLevel>& bandLevels) {
    RETURN_VALUE_IF(bandLevels.size() > lvm::MAX_NUM_BANDS || bandLevels.empty(),
                    RetCode::ERROR_ILLEGAL_PARAMETER, "sizeExceedMax");
    RetCode ret = updateControlParameter(bandLevels);
    if (RetCode::SUCCESS == ret) {
        mCurPresetIdx = lvm::PRESET_CUSTOM;
        LOG(INFO) << __func__ << " succeed with " << ::android::internal::ToString(bandLevels);
    } else {
        LOG(ERROR) << __func__ << " failed with " << ::android::internal::ToString(bandLevels);
    }
    return ret;
}

std::vector<Equalizer::BandLevel> BundleContext::getEqualizerBandLevels() const {
    std::vector<Equalizer::BandLevel> bandLevels;
    bandLevels.reserve(lvm::MAX_NUM_BANDS);
    for (std::size_t i = 0; i < lvm::MAX_NUM_BANDS; i++) {
        bandLevels.emplace_back(Equalizer::BandLevel{static_cast<int32_t>(i), mBandGaindB[i]});
    }
    return bandLevels;
}

bool BundleContext::isBandLevelIndexInRange(
        const std::vector<Equalizer::BandLevel>& bandLevels) const {
    const auto [min, max] =
            std::minmax_element(bandLevels.begin(), bandLevels.end(),
                                [](const auto& a, const auto& b) { return a.index < b.index; });
    return min->index >= 0 && max->index < lvm::MAX_NUM_BANDS;
}

RetCode BundleContext::updateControlParameter(const std::vector<Equalizer::BandLevel>& bandLevels) {
    RETURN_VALUE_IF(!isBandLevelIndexInRange(bandLevels), RetCode::ERROR_ILLEGAL_PARAMETER,
                    "indexOutOfRange");

    std::array<int, lvm::MAX_NUM_BANDS> tempLevel;
    for (const auto& it : bandLevels) {
        tempLevel[it.index] = it.levelMb;
    }

    LVM_ControlParams_t params;
    {
        std::lock_guard lg(mMutex);
        RETURN_VALUE_IF(LVM_SUCCESS != LVM_GetControlParameters(mInstance, &params),
                        RetCode::ERROR_EFFECT_LIB_ERROR, " getControlParamFailed");

        for (std::size_t i = 0; i < lvm::MAX_NUM_BANDS; i++) {
            params.pEQNB_BandDefinition[i].Frequency = lvm::kPresetsFrequencies[i];
            params.pEQNB_BandDefinition[i].QFactor = lvm::kPresetsQFactors[i];
            params.pEQNB_BandDefinition[i].Gain = tempLevel[i];
        }

        RETURN_VALUE_IF(LVM_SUCCESS != LVM_SetControlParameters(mInstance, &params),
                        RetCode::ERROR_EFFECT_LIB_ERROR, " setControlParamFailed");
    }
    mBandGaindB = tempLevel;
    LOG(INFO) << __func__ << " update bandGain to " << ::android::internal::ToString(mBandGaindB);

    return RetCode::SUCCESS;
}

void BundleContext::initControlParameter(LVM_ControlParams_t& params) const {
    /* General parameters */
    params.OperatingMode = LVM_MODE_ON;
    params.SampleRate = LVM_FS_44100;
    params.SourceFormat = LVM_STEREO;
    params.SpeakerType = LVM_HEADPHONES;

    /* Concert Sound parameters */
    params.VirtualizerOperatingMode = LVM_MODE_OFF;
    params.VirtualizerType = LVM_CONCERTSOUND;
    params.VirtualizerReverbLevel = 100;
    params.CS_EffectLevel = LVM_CS_EFFECT_NONE;

    params.EQNB_OperatingMode = LVM_EQNB_OFF;
    params.EQNB_NBands = lvm::MAX_NUM_BANDS;
    params.pEQNB_BandDefinition = getDefaultEqualizerBandDefs();

    /* Volume Control parameters */
    params.VC_EffectLevel = 0;
    params.VC_Balance = 0;

    /* Treble Enhancement parameters */
    params.TE_OperatingMode = LVM_TE_OFF;
    params.TE_EffectLevel = 0;

    /* PSA Control parameters */
    params.PSA_Enable = LVM_PSA_OFF;
    params.PSA_PeakDecayRate = (LVM_PSA_DecaySpeed_en)0;

    /* Bass Enhancement parameters */
    params.BE_OperatingMode = LVM_BE_OFF;
    params.BE_EffectLevel = 0;
    params.BE_CentreFreq = LVM_BE_CENTRE_90Hz;
    params.BE_HPF = LVM_BE_HPF_ON;

    /* PSA Control parameters */
    params.PSA_Enable = LVM_PSA_OFF;
    params.PSA_PeakDecayRate = LVM_PSA_SPEED_MEDIUM;

    /* TE Control parameters */
    params.TE_OperatingMode = LVM_TE_OFF;
    params.TE_EffectLevel = 0;

    params.NrChannels = audio_channel_count_from_out_mask(AUDIO_CHANNEL_OUT_STEREO);
    params.ChMask = AUDIO_CHANNEL_OUT_STEREO;
    params.SourceFormat = LVM_STEREO;
}

void BundleContext::initHeadroomParameter(LVM_HeadroomParams_t& params) const {
    params.pHeadroomDefinition = getDefaultEqualizerHeadroomBanDefs();
    params.NHeadroomBands = 2;
    params.Headroom_OperatingMode = LVM_HEADROOM_OFF;
}

LVM_EQNB_BandDef_t *BundleContext::getDefaultEqualizerBandDefs() {
    static LVM_EQNB_BandDef_t* BandDefs = []() {
        static LVM_EQNB_BandDef_t tempDefs[lvm::MAX_NUM_BANDS];
        /* N-Band Equaliser parameters */
        for (std::size_t i = 0; i < lvm::MAX_NUM_BANDS; i++) {
            tempDefs[i].Frequency = lvm::kPresetsFrequencies[i];
            tempDefs[i].QFactor = lvm::kPresetsQFactors[i];
            tempDefs[i].Gain = lvm::kSoftPresets[0/* normal */][i];
        }
        return tempDefs;
    }();

    return BandDefs;
}

LVM_HeadroomBandDef_t *BundleContext::getDefaultEqualizerHeadroomBanDefs() {
    static LVM_HeadroomBandDef_t HeadroomBandDef[LVM_HEADROOM_MAX_NBANDS] = {
            {
                    .Limit_Low = 20,
                    .Limit_High = 4999,
                    .Headroom_Offset = 0,
            },
            {
                    .Limit_Low = 5000,
                    .Limit_High = 24000,
                    .Headroom_Offset = 0,
            },
    };
    return HeadroomBandDef;
}

IEffect::Status BundleContext::lvmProcess(float* in, float* out, int samples) {
    IEffect::Status status = {EX_NULL_POINTER, 0, 0};

    auto frameSize = getInputFrameSize();
    RETURN_VALUE_IF(0== frameSize, status, "nullContext");

    LOG(DEBUG) << __func__ << " start processing";
    LVM_UINT16 frames = samples * sizeof(float) / frameSize;
    LVM_ReturnStatus_en lvmStatus;
    {
        std::lock_guard lg(mMutex);
        lvmStatus = LVM_Process(mInstance, in, out, frames, 0);
    }

    if (lvmStatus != LVM_SUCCESS) {
        LOG(ERROR) << __func__ << lvmStatus;
        return {EX_UNSUPPORTED_OPERATION, 0, 0};
    }
    LOG(DEBUG) << __func__ << " done processing";
    return {STATUS_OK, samples, samples};
}

}  // namespace aidl::android::hardware::audio::effect
