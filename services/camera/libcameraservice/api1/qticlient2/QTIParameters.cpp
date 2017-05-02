/* Copyright (c) 2017, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#define LOG_TAG "Camera2-QTIParameters"
#define ATRACE_TAG ATRACE_TAG_CAMERA
#define LOG_NDEBUG 0

#include <utils/Log.h>
#include <utils/Trace.h>
#include <utils/Vector.h>
#include <utils/SortedVector.h>

#include <math.h>
#include <stdlib.h>
#include <cutils/properties.h>

#include "QTIParameters.h"
#include "Parameters.h"
#include "system/camera.h"
#include "hardware/camera_common.h"
#include <android/hardware/ICamera.h>
#include <media/MediaProfiles.h>
#include <media/mediarecorder.h>
#include "api1/Camera2Client.h"

namespace android {
namespace camera2 {

//Sharpness
const char KEY_QTI_VENDOR_SHARPNESS_RANGE[] = "org.codeaurora.qcamera3.sharpness.range";
const char KEY_QTI_VENDOR_SHARPNESS_STRENGTH[] = "org.codeaurora.qcamera3.sharpness.strength";
const char KEY_QTI_MAX_SHARPNESS[] = "max-sharpness";
const char KEY_QTI_SHARPNESS[] = "sharpness";

//saturation
const char KEY_QTI_VENDOR_SATURATION_RANGE[] = "org.codeaurora.qcamera3.saturation.range";
const char KEY_QTI_VENDOR_SATURATION[] = "org.codeaurora.qcamera3.saturation.use_saturation";
const char KEY_QTI_MAX_SATURATION[] = "max-saturation";
const char KEY_QTI_SATURATION[] = "saturation";

//instant aec
const char KEY_QTI_VENDOR_INSTANT_MODE[] = "org.codeaurora.qcamera3.instant_aec.instant_aec_mode";
const char KEY_QTI_VENDOR_INSTANT_MODES[] =
        "org.codeaurora.qcamera3.instant_aec.instant_aec_available_modes";
const char KEY_QTI_INSTANT_AEC_SUPPORTED_MODES[] = "instant-aec-values";
const char KEY_QTI_INSTANT_AEC[] = "instant-aec";
// Values for instant AEC modes
const char KEY_QTI_INSTANT_AEC_DISABLE[] = "0";
const char KEY_QTI_INSTANT_AEC_AGGRESSIVE_AEC[] = "1";
const char KEY_QTI_INSTANT_AEC_FAST_AEC[] = "2";

//exposure metering
const char KEY_QTI_VENDOR_EXPOSURE_METER_MODES[] =
        "org.codeaurora.qcamera3.exposure_metering.available_modes";
const char KEY_QTI_VENDOR_EXPOSURE_METER[] =
        "org.codeaurora.qcamera3.exposure_metering.exposure_metering_mode";
const char KEY_QTI_AUTO_EXPOSURE_VALUES[] = "auto-exposure-values";
const char KEY_QTI_AUTO_EXPOSURE[] = "auto-exposure";
//values for exposure metering
const char AUTO_EXPOSURE_FRAME_AVG[] = "frame-average";
const char AUTO_EXPOSURE_CENTER_WEIGHTED[] = "center-weighted";
const char AUTO_EXPOSURE_SPOT_METERING[] = "spot-metering";
const char AUTO_EXPOSURE_SMART_METERING[] = "smart-metering";
const char AUTO_EXPOSURE_USER_METERING[] = "user-metering";
const char AUTO_EXPOSURE_SPOT_METERING_ADV[] = "spot-metering-adv";
const char AUTO_EXPOSURE_CENTER_WEIGHTED_ADV[] = "center-weighted-adv";

//iso-exp priority
const char KEY_QTI_VENDOR_ISO_EXP_SELECT_PRIORITY[]  =
        "org.codeaurora.qcamera3.iso_exp_priority.select_priority";
const char KEY_QTI_VENDOR_ISO_EXP_USE_VALUE[]  =
        "org.codeaurora.qcamera3.iso_exp_priority.use_iso_exp_priority";
//Manual Exposure
const char KEY_QTI_SUPPORTED_MANUAL_EXPOSURE_MODES[] = "manual-exposure-modes";
const char KEY_QTI_EXP_TIME_PRIORITY[] = "exp-time-priority";
const char KEY_QTI_MIN_EXPOSURE_TIME[] = "min-exposure-time";
const char KEY_QTI_MAX_EXPOSURE_TIME[] = "max-exposure-time";
const char KEY_QTI_EXPOSURE_TIME[] = "exposure-time";
const char KEY_QTI_USER_SETTING[] = "user-setting";
const char KEY_QTI_MIN_ISO[] = "min-iso";
const char KEY_QTI_MAX_ISO[] = "max-iso";
const char KEY_QTI_ISO_PRIORITY[] = "iso-priority";
const char KEY_QTI_SUPPORTED_ISO_MODES[] = "iso-values";
const char KEY_QTI_ISO_MODE[] = "iso";
const char ISO_MANUAL[] = "manual";
const char KEY_QTI_CONTINUOUS_ISO[] = "continuous-iso";
// Values for ISO Settings
const char ISO_AUTO[] = "auto";
const char ISO_100[] = "ISO100";
const char ISO_200[] = "ISO200";
const char ISO_400[] = "ISO400";
const char ISO_800[] = "ISO800";
const char ISO_1600[] = "ISO1600";
const char ISO_3200[] = "ISO3200";
const char VALUE_OFF[] = "off";
const char VALUE_ON[] = "on";

//Manual White Balance
const char KEY_QTI_WB_CCT_MODE[] = "color-temperature";
const char KEY_QTI_WB_GAIN_MODE[] = "rbgb-gains";
const char KEY_QTI_MIN_WB_CCT[] = "min-wb-cct";
const char KEY_QTI_MAX_WB_CCT[] = "max-wb-cct";
const char KEY_QTI_MIN_WB_GAIN[] = "min-wb-gain";
const char KEY_QTI_MAX_WB_GAIN[] = "max-wb-gain";
const char KEY_QTI_SUPPORTED_MANUAL_WB_MODES[] = "manual-wb-modes";
const char KEY_WHITE_BALANCE[] = "whitebalance";
const char WHITE_BALANCE_MANUAL[] = "manual";
const char KEY_QTI_MANUAL_WB_TYPE[] = "manual-wb-type";
const char KEY_QTI_MANUAL_WB_VALUE[] = "manual-wb-value";
const char KEY_QTI_MANUAL_WB_GAINS[] = "manual-wb-gains";

//redeye-reduction
const char KEY_QTI_REDEYE_REDUCTION[] = "redeye-reduction";
//face-detection
const char  KEY_QTI_FACE_DETECTION_MODES[] = "face-detection-values";

//Video-HDR
const char KEY_QTI_VENDOR_VIDEO_HDR_MODES[] =
        "org.codeaurora.qcamera3.video_hdr_mode.vhdr_supported_modes";
const char KEY_QTI_VENDOR_VIDEO_HDR_MODE[] =
        "org.codeaurora.qcamera3.video_hdr_mode.vhdr_mode";
const char KEY_QTI_VIDEO_HDR[] = "video-hdr";
const char KEY_QTI_SUPPORTED_VIDEO_HDR_MODES[] = "video-hdr-values";

//Sensor-HDR
const char KEY_SNAPCAM_SUPPORTED_HDR_MODES[] = "hdr-mode-values";
const char HDR_MODE_SENSOR[] = "hdr-mode-sensor";
const char HDR_MODE_MULTIFRAME[] = "hdr-mode-multiframe";
const char KEY_SNAPCAM_HDR_MODE[] = "hdr-mode";

camera_metadata_ro_entry_t g_availableSensitivityRange;
double minExposureTime;
double maxExposureTime;
const char minWbGain[] = "1.0";
const char maxWbGain[] = "4.0";

const char KEY_QTI_ZSL[] = "zsl";
const char KEY_QTI_SUPPORTED_ZSL_MODES[] = "zsl-values";

// AE bracketing
const char KEY_QTI_SUPPORTED_AE_BRACKET_MODES[] = "ae-bracket-hdr-values";
const char KEY_QTI_CAPTURE_BURST_EXPOSURE[] = "capture-burst-exposures";
const char KEY_QTI_AE_BRACKET_HDR[] = "ae-bracket-hdr";

const char AE_BRACKET_OFF[] = "Off";
const char AE_BRACKET[] = "AE-Bracket";

// HFR
const char KEY_QTI_VIDEO_HIGH_FRAME_RATE[] = "video-hfr";
const char KEY_QTI_VIDEO_HIGH_SPEED_RECORDING[] = "video-hsr";
const char KEY_QTI_SUPPORTED_VIDEO_HIGH_FRAME_RATE_MODES[] = "video-hfr-values";
const char KEY_QTI_SUPPORTED_HFR_SIZES[] = "hfr-size-values";

// HDR need 1x frame(one non-HDR extra frame).
const char KEY_QTI_SUPPORTED_HDR_NEED_1X[] = "hdr-need-1x-values";
const char KEY_QTI_HDR_NEED_1X[] = "hdr-need-1x";
// AUTO HDR
const char KEY_QTI_AUTO_HDR_SUPPORTED[] = "auto-hdr-supported";
const char KEY_QTI_AUTO_HDR_ENABLE [] = "auto-hdr-enable";
const char VALUE_TRUE[] = "true";
const char VALUE_FALSE[] = "false";

//Histogram
const char KEY_QTI_VENDOR_HISTOGRAM[] = "org.codeaurora.qcamera3.histogram.enable";
const char KEY_QTI_HISTOGRAM_MODES[] = "histogram-values";
const char KEY_QTI_HISTOGRAM[] = "histogram";
const char HISTOGRAM_ENABLE[] = "enable";
const char HISTOGRAM_DISABLE[] = "disable";

// DIS
const char KEY_QTI_SUPPORTED_DIS_MODES[] = "dis-values";
const char KEY_QTI_DIS[] = "dis";

// Values for raw image formats
const char QTIParameters::QC_PIXEL_FORMAT_BAYER_MIPI_RAW_10RGGB[] = "bayer-mipi-10rggb";

status_t QTIParameters::initialize(void *parametersParent,
            sp<CameraDeviceBase> device, sp<CameraProviderManager> manager) {
    status_t res = OK;

    Parameters* ParentParams = (Parameters*)parametersParent;
    vendorTagId = manager->getProviderTagIdLocked(device->getId().string());
    sp<VendorTagDescriptor> vTags =
        VendorTagDescriptor::getGlobalVendorTagDescriptor();
    if ((nullptr == vTags.get()) || (0 >= vTags->getTagCount())) {
        sp<VendorTagDescriptorCache> cache =
                VendorTagDescriptorCache::getGlobalVendorTagCache();
        if (cache.get()) {
            cache->getVendorTagDescriptor(vendorTagId, &vTags);
        }
    }
    uint32_t tag = 0;
    isoValue = -1;
    exposureTime = -1;
    isRawPlusYuv = false;

    // Temp Initialize
    ParentParams->params.set("max-contrast", 10);

    ParentParams->params.set("redeye-reduction-values",
            "disable,enable");

    ParentParams->params.set(KEY_QTI_REDEYE_REDUCTION,
            "disable");

    ParentParams->params.set(KEY_QTI_SUPPORTED_ZSL_MODES,
            "on,off");

    ParentParams->params.set("num-snaps-per-shutter", 1);

    ParentParams->params.set("ae-bracket-hdr-values","Off,AE-Bracket");
    ParentParams->params.set("ae-bracket-hdr","Off");

    ParentParams->params.set(KEY_QTI_SUPPORTED_HDR_NEED_1X,"true,false");
    ParentParams->params.set(KEY_QTI_HDR_NEED_1X,"false");
    Hdr1xEnable = false;
    HdrSceneEnable = false;

    //Video-Hdr, Sensor-Hdr
    res = CameraMetadata::getTagFromName(KEY_QTI_VENDOR_VIDEO_HDR_MODES, vTags.get(), &tag);
    camera_metadata_ro_entry_t availableVideoHdrModes = ParentParams->staticInfo(tag);
    if (availableVideoHdrModes.count == 2) {
        String8 supportedVideoHdrModes(VALUE_OFF);
        supportedVideoHdrModes += ",";
        supportedVideoHdrModes += VALUE_ON;

        ParentParams->params.set(KEY_QTI_SUPPORTED_VIDEO_HDR_MODES,
                supportedVideoHdrModes);
        ParentParams->params.set(KEY_QTI_VIDEO_HDR,VALUE_OFF);

        String8 supportedSnapHdrModes(HDR_MODE_SENSOR);
        supportedSnapHdrModes += ",";
        supportedSnapHdrModes += HDR_MODE_MULTIFRAME;
        ParentParams->params.set(KEY_SNAPCAM_SUPPORTED_HDR_MODES,
                supportedSnapHdrModes);
    }

    // ISO
    // Get the supported sensitivity range from device3 static info
    camera_metadata_ro_entry_t availableSensitivityRange =
        ParentParams->staticInfo(ANDROID_SENSOR_INFO_SENSITIVITY_RANGE);
    if (availableSensitivityRange.count == 2) {
        int32_t isoMin = availableSensitivityRange.data.i32[0];
        int32_t isoMax = availableSensitivityRange.data.i32[1];
        g_availableSensitivityRange = availableSensitivityRange;

        String8 supportedIsoModes;
        supportedIsoModes += ISO_AUTO;
        if (100 > isoMin && 100 <= isoMax) {
            supportedIsoModes += ",";
            supportedIsoModes += ISO_100;
        }
        if (200 > isoMin && 200 <= isoMax) {
            supportedIsoModes += ",";
            supportedIsoModes += ISO_200;
        }
        if (400 > isoMin && 400 <= isoMax) {
            supportedIsoModes += ",";
            supportedIsoModes += ISO_400;
        }
        if (800 > isoMin && 800 <= isoMax) {
            supportedIsoModes += ",";
            supportedIsoModes += ISO_800;
        }
        if (1600 > isoMin && 1600 <= isoMax) {
            supportedIsoModes += ",";
            supportedIsoModes += ISO_1600;
        }
        if (3200 > isoMin && 3200 <= isoMax) {
            supportedIsoModes += ",";
            supportedIsoModes += ISO_3200;
        }
        ParentParams->params.set(KEY_QTI_SUPPORTED_ISO_MODES,
                supportedIsoModes);
        // Set default value
        ParentParams->params.set(KEY_QTI_ISO_MODE,
                ISO_AUTO);
    }

    String8 supportedPicutreFormats;
    SortedVector<int32_t> outputFormats = ParentParams->getAvailableOutputFormats();
    bool addComma = false;
    for (size_t i=0; i < outputFormats.size(); i++) {
        if (addComma)
            supportedPicutreFormats += ",";
        addComma = true;
        switch (outputFormats[i]) {
            case HAL_PIXEL_FORMAT_RAW10:
                supportedPicutreFormats += PictureFormatEnumToString(outputFormats[i]);
                break;
            case HAL_PIXEL_FORMAT_BLOB:
                supportedPicutreFormats += CameraParameters::PIXEL_FORMAT_JPEG;
                break;

            default:
                ALOGW("%s: Camera %d: Unknown preview format: %x",
                        __FUNCTION__, ParentParams->cameraId, outputFormats[i]);
                addComma = false;
                break;
        }
    }

    ParentParams->params.set(CameraParameters::KEY_SUPPORTED_PICTURE_FORMATS,
        supportedPicutreFormats);
    ParentParams->params.set(CameraParameters::KEY_PICTURE_FORMAT,
        CameraParameters::PIXEL_FORMAT_JPEG);
    pictureFormat = PictureFormatStringToEnum(ParentParams->params.getPictureFormat());

    //Sharpness
    res = CameraMetadata::getTagFromName(KEY_QTI_VENDOR_SHARPNESS_RANGE, vTags.get(), &tag);
    camera_metadata_ro_entry_t availableSharpnessRange = ParentParams->staticInfo(tag);
    if (availableSharpnessRange.count == 2) {
        ParentParams->params.set(KEY_QTI_MAX_SHARPNESS,availableSharpnessRange.data.i32[1]);
        //Default value
        ParentParams->params.set(KEY_QTI_SHARPNESS,availableSharpnessRange.data.i32[1]);
    }

    //Saturation
    res = CameraMetadata::getTagFromName(KEY_QTI_VENDOR_SATURATION_RANGE, vTags.get(), &tag);
    camera_metadata_ro_entry_t availableSaturationRange =
            ParentParams->staticInfo(tag);
    if (availableSaturationRange.count == 4) {
        ParentParams->params.set(KEY_QTI_MAX_SATURATION,availableSaturationRange.data.i32[1]);
        //Default value
        ParentParams->params.set(KEY_QTI_SATURATION,availableSaturationRange.data.i32[2]);
    }

    //Exposure Metering
    tag=0;
    res = CameraMetadata::getTagFromName(KEY_QTI_VENDOR_EXPOSURE_METER_MODES, vTags.get(), &tag);
    camera_metadata_ro_entry_t availableMeteringModes =
            ParentParams->staticInfo(tag);

    String8 MeteringModes;
    for(int meterModes=0;meterModes<(int)availableMeteringModes.count;meterModes++) {
        if((availableMeteringModes.data.i32[meterModes] < 0) ||
                (availableMeteringModes.data.i32[meterModes] > 6))
            continue;

        if(meterModes != 0) {
            MeteringModes += ",";
        }

        if(availableMeteringModes.data.i32[meterModes] == 0 ) {
            MeteringModes += AUTO_EXPOSURE_FRAME_AVG;
        }
        else if(availableMeteringModes.data.i32[meterModes] == 1 ) {
            MeteringModes += AUTO_EXPOSURE_CENTER_WEIGHTED;
        }
        else if(availableMeteringModes.data.i32[meterModes] == 2 ) {
            MeteringModes += AUTO_EXPOSURE_SPOT_METERING;
        }
        else if(availableMeteringModes.data.i32[meterModes] == 3 ) {
            MeteringModes += AUTO_EXPOSURE_SMART_METERING;
        }
        else if(availableMeteringModes.data.i32[meterModes] == 4 ) {
            MeteringModes += AUTO_EXPOSURE_USER_METERING;
        }
        else if(availableMeteringModes.data.i32[meterModes] == 5 ) {
            MeteringModes += AUTO_EXPOSURE_SPOT_METERING_ADV;
        }
        else if(availableMeteringModes.data.i32[meterModes] == 6 ) {
            MeteringModes += AUTO_EXPOSURE_CENTER_WEIGHTED_ADV;
        }
    }

    ParentParams->params.set(KEY_QTI_AUTO_EXPOSURE_VALUES,
                    MeteringModes);

    ParentParams->params.set(KEY_QTI_AUTO_EXPOSURE,
                    AUTO_EXPOSURE_FRAME_AVG);

    //Instant AEC
    tag=0;
    res = CameraMetadata::getTagFromName(KEY_QTI_VENDOR_INSTANT_MODES, vTags.get(), &tag);
    camera_metadata_ro_entry_t availableInstantAecModes =
            ParentParams->staticInfo(tag);
    String8 instantAecModes;
    for(int aecModes=0;aecModes<(int)availableInstantAecModes.count;aecModes++) {
        if((availableInstantAecModes.data.i32[aecModes] < 0) ||
                (availableInstantAecModes.data.i32[aecModes] > 2))
            continue;

        if(aecModes != 0) {
            instantAecModes += ",";
        }

        if(availableInstantAecModes.data.i32[aecModes] == 0) {
            instantAecModes += KEY_QTI_INSTANT_AEC_DISABLE;
        } else if(availableInstantAecModes.data.i32[aecModes] == 1) {
            instantAecModes += KEY_QTI_INSTANT_AEC_AGGRESSIVE_AEC;
        } else if(availableInstantAecModes.data.i32[aecModes] == 2) {
            instantAecModes += KEY_QTI_INSTANT_AEC_FAST_AEC;
        }
    }
    if (availableInstantAecModes.count > 0) {
        ParentParams->params.set(KEY_QTI_INSTANT_AEC_SUPPORTED_MODES, instantAecModes);
        //default Instance AEC
        ParentParams->params.set(KEY_QTI_INSTANT_AEC, KEY_QTI_INSTANT_AEC_DISABLE);
    }

    //Manual Exposure
    String8 manualExpModes(VALUE_OFF);
    manualExpModes += ",";
    manualExpModes += KEY_QTI_EXP_TIME_PRIORITY;
    manualExpModes += ",";
    manualExpModes += KEY_QTI_ISO_PRIORITY;
    manualExpModes += ",";
    manualExpModes += KEY_QTI_USER_SETTING;

    if (availableSensitivityRange.count == 2) {
        ParentParams->params.set(KEY_QTI_MIN_ISO,availableSensitivityRange.data.i32[0]);
        ParentParams->params.set(KEY_QTI_MAX_ISO,availableSensitivityRange.data.i32[1]);
    }

    tag=0;
    camera_metadata_ro_entry_t availableExposureTimeRange =
            ParentParams->staticInfo(ANDROID_SENSOR_INFO_EXPOSURE_TIME_RANGE);
    if (availableExposureTimeRange.count == 2) {
        char expTimeStr[30];
        //values are in nano sec, convert to milli sec for upper layers
        minExposureTime = (double) availableExposureTimeRange.data.i64[0] / 1000000.0;
        maxExposureTime = (double) availableExposureTimeRange.data.i64[1] / 1000000.0;
        snprintf(expTimeStr, sizeof(expTimeStr), "%f", minExposureTime);
        ParentParams->params.set(KEY_QTI_MIN_EXPOSURE_TIME,expTimeStr);
        snprintf(expTimeStr, sizeof(expTimeStr), "%f", maxExposureTime);
        ParentParams->params.set(KEY_QTI_MAX_EXPOSURE_TIME,expTimeStr);
        ParentParams->params.set(KEY_QTI_SUPPORTED_MANUAL_EXPOSURE_MODES,manualExpModes.string());
    }

    //Manual White Balance
    String8 supportedWbModes;
    const char *awbModes= ParentParams->params.get(CameraParameters::KEY_SUPPORTED_WHITE_BALANCE);
    supportedWbModes += WHITE_BALANCE_MANUAL;
    supportedWbModes += ",";
    supportedWbModes += awbModes;
    ParentParams->params.set(CameraParameters::KEY_SUPPORTED_WHITE_BALANCE,
            supportedWbModes.string());

    String8 manualWbModes(VALUE_OFF);
    manualWbModes += ",";
    manualWbModes += KEY_QTI_WB_CCT_MODE;
    manualWbModes += ",";
    manualWbModes += KEY_QTI_WB_GAIN_MODE;
    ParentParams->params.set(KEY_QTI_MIN_WB_CCT,"2000");
    ParentParams->params.set(KEY_QTI_MAX_WB_CCT,"8000");
    ParentParams->params.set(KEY_QTI_MIN_WB_GAIN,minWbGain);
    ParentParams->params.set(KEY_QTI_MAX_WB_GAIN,maxWbGain);
    ParentParams->params.set(KEY_QTI_SUPPORTED_MANUAL_WB_MODES, manualWbModes.string());

    //Face detection
    String8 faceDetectionModes(VALUE_OFF);
    faceDetectionModes += ",";
    faceDetectionModes += VALUE_ON;
    ParentParams->params.set(KEY_QTI_FACE_DETECTION_MODES,faceDetectionModes.string());

    char burstValue[PROPERTY_VALUE_MAX];
    property_get("persist.camera.burstcount", burstValue, "1");

    ParentParams->params.set("num-snaps-per-shutter", burstValue);
    burstCount = atoi(burstValue);
    ALOGV("burstcount = %d", burstCount);

    // Get AEbracketing values
    String8 supportedBracketingValues(AE_BRACKET_OFF);
    supportedBracketingValues += ",";
    supportedBracketingValues += AE_BRACKET;
    ParentParams->params.set(KEY_QTI_SUPPORTED_AE_BRACKET_MODES, supportedBracketingValues);
    // Default
    ParentParams->params.set(KEY_QTI_AE_BRACKET_HDR, AE_BRACKET_OFF);
    aeBracketEnable = false;

    char prop[PROPERTY_VALUE_MAX];
    memset(prop, 0, sizeof(prop));
    property_get("persist.capture.burst.exposures", prop, "");
    if (strlen(prop) > 0) {
        ParentParams->params.set(KEY_QTI_CAPTURE_BURST_EXPOSURE, prop);
    } else {
        ParentParams->params.remove(KEY_QTI_CAPTURE_BURST_EXPOSURE);
    }

    // HFR
    camera_metadata_ro_entry_t availableHfrConfigs =
            ParentParams->staticInfo(ANDROID_CONTROL_AVAILABLE_HIGH_SPEED_VIDEO_CONFIGURATIONS);
    if (availableHfrConfigs.count >= 10) {
        // Retrieve Hfr Configurations.
        // The elements of config are (width, height, fps_min, fps_max, batch_size_max)
        // Two sets of such config are available
        // One for preview and the second one for video.

        String8 hfrValues;
        String8 hfrSizeValues;
        int32_t width = 0;
        int32_t height = 0;
        int32_t fps_max = 0;

        for (size_t i = 0; i < availableHfrConfigs.count &&
                availableHfrConfigs.count >= (i+10); i += 10) {
            width = availableHfrConfigs.data.i32[i+0];
            height = availableHfrConfigs.data.i32[i+1];
            // Check if previous fps is same as current fps.
            // Advertize the max resolution for each high FPS mode.
            // Each FPS mode, like 120 FPS, will be advertised for max resolution.
            if (fps_max != availableHfrConfigs.data.i32[i+3]) {
                fps_max = availableHfrConfigs.data.i32[i+3];

                if (i != 0 ) {
                    hfrValues += ",";
                    hfrSizeValues += ",";
                }
                hfrValues += String8::format("%d",fps_max);
                hfrSizeValues += String8::format("%dx%d",width,height);

            }
        }

        ParentParams->params.set(KEY_QTI_SUPPORTED_VIDEO_HIGH_FRAME_RATE_MODES, hfrValues.string());
        ParentParams->params.set(KEY_QTI_SUPPORTED_HFR_SIZES, hfrSizeValues.string());

        // Default
        ParentParams->params.set(KEY_QTI_VIDEO_HIGH_SPEED_RECORDING, "off");
        ParentParams->params.set(KEY_QTI_VIDEO_HIGH_FRAME_RATE, "off");

    }

    // Video stabilization, DIS
    camera_metadata_ro_entry_t availableVideoStabilizationModes =
        ParentParams->staticInfo(ANDROID_CONTROL_AVAILABLE_VIDEO_STABILIZATION_MODES, 0, 0,
                false);

    if (availableVideoStabilizationModes.count > 1) {
        ParentParams->params.set(KEY_QTI_SUPPORTED_DIS_MODES,"disable,enable");
    } else {
        ParentParams->params.set(KEY_QTI_SUPPORTED_DIS_MODES,"disable");
    }
    // Default
    ParentParams->params.set(KEY_QTI_DIS, "disable");

    // Support for auto HDR scene mode detection
    String8 supportedAutoHDRValue(VALUE_FALSE);
    //Default Auto Hdr is Enabled.
    supportedAutoHDRValue = VALUE_TRUE;
    ParentParams->params.set(KEY_QTI_AUTO_HDR_SUPPORTED, supportedAutoHDRValue);
    //Default value
    ParentParams->params.set(KEY_QTI_AUTO_HDR_ENABLE, "disable");
    isHdrScene = false;

    //Default histogram values
    String8 availableHistogramModes;
    availableHistogramModes += HISTOGRAM_ENABLE;
    availableHistogramModes += ",";
    availableHistogramModes += HISTOGRAM_DISABLE;
    availableHistogramModes += ",";
    ParentParams->params.set(KEY_QTI_HISTOGRAM_MODES,availableHistogramModes);
    ParentParams->params.set(KEY_QTI_HISTOGRAM,HISTOGRAM_DISABLE);
    tag=0;
    res = CameraMetadata::getTagFromName("org.codeaurora.qcamera3.histogram.buckets", vTags.get(), &tag);
    camera_metadata_ro_entry_t histogramBuckets = ParentParams->staticInfo(tag);
    if (histogramBuckets.count > 0) {
        histogramBucketSize = histogramBuckets.data.i32[0];
    }

    return res;
}

status_t QTIParameters::set(CameraParameters2& newParams, void *parametersParent) {
    status_t res = OK;
    char prop[PROPERTY_VALUE_MAX];
    Parameters* ParentParams = (Parameters*)parametersParent;

    //restore previously burst count
    burstCount = 1;
    newParams.set("num-snaps-per-shutter",burstCount);

    // ISO
    const char *isoMode = newParams.get(KEY_QTI_ISO_MODE);
    if (isoMode) {
        if (!strcmp(isoMode, ISO_MANUAL)) {
            const char *str = newParams.get(KEY_QTI_CONTINUOUS_ISO);
            if (str != NULL) {
                res = setContinuousISO(str,newParams);
                if(res !=OK){
                    return res;
                }
            }
        } else if (!strcmp(isoMode, ISO_100)) {
            isoValue = 100;
        } else if (!strcmp(isoMode, ISO_200)) {
            isoValue = 200;
        } else if (!strcmp(isoMode, ISO_400)) {
            isoValue = 400;
        } else if (!strcmp(isoMode, ISO_800)) {
            isoValue = 800;
        } else if (!strcmp(isoMode, ISO_1600)) {
            isoValue = 1600;
        } else if (!strcmp(isoMode, ISO_3200)) {
            isoValue = 3200;
        } else {
            isoValue = 0;
        }
    }

    //Video-Hdr
    const char *videoHdrMode = newParams.get(KEY_QTI_VIDEO_HDR);
    int32_t vidHDR = 0;
    if(videoHdrMode) {
        if (!strcmp(videoHdrMode, VALUE_OFF)) {
            vidHDR = 0;
        } else {
            vidHDR = 1;
        }
    }
    //Sensor-HDR
    const char *HdrMode = newParams.get(KEY_SNAPCAM_HDR_MODE);
    int32_t sensHDR = 0;
    if(HdrMode) {
        if(!strcmp(HdrMode,"hdr-mode-sensor")) {
            sensHDR = 1;
        }
        if(!strcmp(HdrMode,"hdr-mode-multiframe")) {
            sensHDR = 0;
        }
    }
    prevVideoHdr = videoHdr;
    videoHdr = vidHDR|sensHDR;

    //exposure time
    const char *str = newParams.get(KEY_QTI_EXPOSURE_TIME);

    if (str != NULL) {
        res = setExposureTime(str,newParams);
        if(res !=OK){
            return res;
        }
    }

    //Sharpness value
    const char *sharpness=newParams.get(KEY_QTI_SHARPNESS);
    if(sharpness != NULL) {
        sharpnessValue= atoi(sharpness);
    }

    //Saturation
    const char *saturation=newParams.get(KEY_QTI_SATURATION);
    if(saturation != NULL) {
        saturationValue= atoi(saturation);
    }

    //Exposure Metering
    const char *exmeter=newParams.get(KEY_QTI_AUTO_EXPOSURE);
    if(!strcmp(exmeter,AUTO_EXPOSURE_FRAME_AVG)) {
        exposureMetering = 0;
    } else if (!strcmp(exmeter,AUTO_EXPOSURE_CENTER_WEIGHTED)) {
        exposureMetering = 1;
    } else if(!strcmp(exmeter,AUTO_EXPOSURE_SPOT_METERING)) {
        exposureMetering = 2;
    } else if(!strcmp(exmeter,AUTO_EXPOSURE_SMART_METERING)) {
        exposureMetering = 3;
    } else if(!strcmp(exmeter,AUTO_EXPOSURE_USER_METERING)) {
        exposureMetering = 4;
    } else if(!strcmp(exmeter,AUTO_EXPOSURE_SPOT_METERING_ADV)) {
        exposureMetering = 5;
    } else if(!strcmp(exmeter,AUTO_EXPOSURE_CENTER_WEIGHTED_ADV)) {
        exposureMetering = 6;
    }

    //Instant AEC
    const char *instantAec=newParams.get(KEY_QTI_INSTANT_AEC);
    if(instantAec != NULL) {
        instantAecValue= atoi(instantAec);
    } else {
        memset(prop, 0, sizeof(prop));
        property_get("persist.camera.instant.aec", prop, "0");
        instantAecValue= (int32_t)atoi(prop);
    }

    //Manual White Balance
    const char *whiteBalance = newParams.get(KEY_WHITE_BALANCE);
    if(whiteBalance) {
        if (!strcmp(whiteBalance, WHITE_BALANCE_MANUAL)) {
            const char *value = newParams.get(KEY_QTI_MANUAL_WB_VALUE);
            const char *type = newParams.get(KEY_QTI_MANUAL_WB_TYPE);
            if ((value != NULL) && (type != NULL)) {
                newParams.set(KEY_QTI_MANUAL_WB_TYPE, type);
                newParams.set(KEY_QTI_MANUAL_WB_VALUE, value);
                int32_t wbType = atoi(type);

                if (wbType == CAM_MANUAL_WB_MODE_GAIN) {
                    res = setManualWBGains(value,newParams);
                    if(res != OK) {
                        return res;
                    }
                } else {
                    res = BAD_VALUE;
                }
            }
        }
    }

    //redeye-reduction
    if(!strcmp(newParams.get(KEY_QTI_REDEYE_REDUCTION),"enable")) {
        flashMode = (flashMode_t)Parameters::FLASH_MODE_RED_EYE;
        newParams.set(CameraParameters::KEY_FLASH_MODE,flashModeEnumToString(flashMode));
    }
    else {
        flashMode = (flashMode_t)Parameters::FLASH_MODE_INVALID;
    }

    // AE bracketing
    // Get if Ae bracketing is enabled first
    const char *aeBracketMode = newParams.get(KEY_QTI_AE_BRACKET_HDR);
    if (aeBracketMode != NULL) {
        if (!strcmp(aeBracketMode, AE_BRACKET)) {
            aeBracketEnable = true;
        } else {
            aeBracketEnable = false;
        }
    }
    ALOGV("aeBracketEnable = %d, aeBracketMode = %s", aeBracketEnable, aeBracketMode);

    // If Ae bracketing enabled. read bracketing values
    if (aeBracketEnable) {
        const char *aeBracketStr = newParams.get(KEY_QTI_CAPTURE_BURST_EXPOSURE);
        int32_t expNum = 0;
        if((aeBracketStr != NULL) && (strlen(aeBracketStr) > 0)) {
            char prop[32];
            memset(prop, 0, sizeof(prop));
            strlcpy(prop, aeBracketStr, 32);
            char *saveptr = NULL;
            char *token = strtok_r(prop, ",", &saveptr);
            while ((token != NULL) &&
                    (expNum != MAX_BURST_COUNT_AE_BRACKETING)) {
                aeBracketValues[expNum++] = atoi(token);
                token = strtok_r(NULL, ",", &saveptr);
            }
            newParams.set("num-snaps-per-shutter", String8::format("%d", expNum));
            ALOGV("aeBracketvalues = %s", aeBracketStr);
        }
    }

    // Read the burstcount
    const char* burstValue = newParams.get("num-snaps-per-shutter");
    burstCount = atoi(burstValue);
    ALOGV("burstcount = %d", burstCount);

    // ZSL
    bool prevAllowZslMode = ParentParams->allowZslMode;
    // Reset to FALSE, and check below only for true condition.
    ParentParams->allowZslMode = false;
    const char *qtiZslMode = newParams.get(KEY_QTI_ZSL);
    if (qtiZslMode != NULL) {
        if (!strcmp(qtiZslMode, VALUE_ON)) {
            ParentParams->allowZslMode = true;
        }
    } else {
        String8 defaultZslMode = String8::format("%d", prevAllowZslMode);
        memset(prop, 0, sizeof(prop));
        property_get("persist.camera.zsl.mode", prop, defaultZslMode.string());
        ParentParams->allowZslMode = (bool)atoi(prop);
    }
    if (ParentParams->allowZslMode) {
        newParams.set(KEY_QTI_ZSL, VALUE_ON);
        ParentParams->slowJpegMode = false;
    } else {
        newParams.set(KEY_QTI_ZSL, VALUE_OFF);
    }
    mNeedRestart = (prevAllowZslMode != ParentParams->allowZslMode);
    ALOGV("%s mNeedRestart = %d, prevAllowZslMode = %d, allowZslMode = %d",
            __FUNCTION__, mNeedRestart, prevAllowZslMode, ParentParams->allowZslMode);

    const char *qtiHfrMode = newParams.get(KEY_QTI_VIDEO_HIGH_FRAME_RATE);
    ALOGV("HFR mode = %s", qtiHfrMode);
    if (qtiHfrMode != NULL && strcmp(qtiHfrMode, "off")) {
        ParentParams->qtiParams->hfrMode = true;
        ParentParams->qtiParams->hfrPreviewFpsRange[0] = atoi(qtiHfrMode);
        ParentParams->qtiParams->hfrPreviewFpsRange[1] = atoi(qtiHfrMode);
    } else {
        ParentParams->qtiParams->hfrMode = false;
    }

    // AUTO HDR
    const char *qtiAutoHdrMode = newParams.get(KEY_QTI_AUTO_HDR_ENABLE);
    autoHDREnabled = false;
    if (qtiAutoHdrMode != NULL) {
        if (!strcmp(qtiAutoHdrMode, "enable")) {
           autoHDREnabled = true;
        }
    } else {
        memset(prop, 0, sizeof(prop));
        property_get("persist.camera.auto.hdr.enable", prop, "disable");
        if (!strcmp(prop, "enable")) {
            autoHDREnabled = true;
        }
   }

    //hdr_need_1x
    const char *Hdr1x = newParams.get(KEY_QTI_HDR_NEED_1X);
    const char *HdrSceneMode = newParams.get(CameraParameters::KEY_SCENE_MODE);
    if(HdrSceneMode != NULL && !strcmp(HdrSceneMode, CameraParameters::SCENE_MODE_HDR)) {
        HdrSceneEnable = true;
    } else {
        HdrSceneEnable = false;
    }
    if(Hdr1x != NULL && !strcmp(Hdr1x,"true")) {
        Hdr1xEnable = true;
    } else {
        Hdr1xEnable = false;
    }

    if(Hdr1xEnable && (HdrSceneEnable||(isHdrScene && autoHDREnabled))) {
        burstCount = 2;
        newParams.set("num-snaps-per-shutter", String8::format("%d", burstCount));
    }

    // VIDEO_STABILIZATION, DIS
    const char *disValue = newParams.get(KEY_QTI_DIS);
    if (disValue != NULL && !strcmp(disValue, "enable")) {
        ParentParams->videoStabilization = true;
    } else {
        ParentParams->videoStabilization = false;
    }

    camera_metadata_ro_entry_t availableVideoStabilizationModes =
        ParentParams->staticInfo(ANDROID_CONTROL_AVAILABLE_VIDEO_STABILIZATION_MODES, 0, 0,
                false);
    if (ParentParams->videoStabilization &&
            availableVideoStabilizationModes.count == 1) {
        ALOGE("%s: Video stabilization not supported", __FUNCTION__);
        ParentParams->videoStabilization = false;
    }

    return res;
}

const char *QTIParameters::flashModeEnumToString(flashMode_t flashMode) {
    switch (flashMode) {
        case FLASH_MODE_RED_EYE:
            return CameraParameters::FLASH_MODE_RED_EYE;
        default:
            ALOGE("%s: Unknown flash mode enum %d",
                    __FUNCTION__, flashMode);
            return "unknown";
    }
}

int QTIParameters::sceneModeStringToEnum(const char *sceneMode) {
       return
           !strcmp(sceneMode, "asd") ?
               ANDROID_CONTROL_SCENE_MODE_FACE_PRIORITY :
           -1;
}

int QTIParameters::wbModeStringToEnum(const char *wbMode) {
    return
        !strcmp(wbMode, WHITE_BALANCE_MANUAL) ?
            ANDROID_CONTROL_AWB_MODE_OFF :
        -1;
}

const char* QTIParameters::wbModeEnumToString(uint8_t wbMode) {
    switch (wbMode) {
        case ANDROID_CONTROL_AWB_MODE_OFF:
            return WHITE_BALANCE_MANUAL;
        default:
            ALOGE("%s: Unknown wb mode enum %d",
                    __FUNCTION__, wbMode);
            return "unknown";
    }
}

status_t QTIParameters::updateRequest(CameraMetadata *request) const {
    status_t res = OK;
    uint32_t tag = 0;
    int64_t isoVal;
    sp<VendorTagDescriptor> vTags =
        VendorTagDescriptor::getGlobalVendorTagDescriptor();
    if ((nullptr == vTags.get()) || (0 >= vTags->getTagCount())) {
        sp<VendorTagDescriptorCache> cache =
                VendorTagDescriptorCache::getGlobalVendorTagCache();
        if (cache.get()) {
            cache->getVendorTagDescriptor(vendorTagId, &vTags);
        }
    }

    if (!request) {
       return BAD_VALUE;
    }

    if(autoHDREnabled) {
        uint8_t reqControlMode = ANDROID_CONTROL_MODE_USE_SCENE_MODE;
        res = request->update(ANDROID_CONTROL_MODE,
              &reqControlMode, 1);
        if (res != OK) return res;

        uint8_t reqSceneMode = ANDROID_CONTROL_SCENE_MODE_FACE_PRIORITY;
        res = request->update(ANDROID_CONTROL_SCENE_MODE,
        &reqSceneMode, 1);
        if (res != OK) {
            return res;
        }
    }

    if (isoValue != -1) {
        int32_t selectPriority = 0; // 0 for iso, 1 for exp.
        isoVal = isoValue;

        res = CameraMetadata::getTagFromName(KEY_QTI_VENDOR_ISO_EXP_SELECT_PRIORITY,
                vTags.get(), &tag);
        res = request->update(tag, &selectPriority, 1);
        res = CameraMetadata::getTagFromName(KEY_QTI_VENDOR_ISO_EXP_USE_VALUE, vTags.get(), &tag);
        res = request->update(tag, &(isoVal),  1);
        if (res != OK) {
            return res;
        }

        //erase the default value of construct_default_setting.
        res = request->erase(ANDROID_SENSOR_SENSITIVITY);
        if (res != OK) {
            return res;
        }
        res = request->erase(ANDROID_SENSOR_EXPOSURE_TIME);
        if (res != OK) {
            return res;
        }

    }

    //Video-Hdr
    res = CameraMetadata::getTagFromName(KEY_QTI_VENDOR_VIDEO_HDR_MODE, vTags.get(), &tag);
    res = request->update(tag,&videoHdr, 1);
    if (res != OK) {
        return res;
    }

    if (exposureTime > 0) {
        int32_t selectPriority = 1; // 0 for iso, 1 for exp.
        res = CameraMetadata::getTagFromName(KEY_QTI_VENDOR_ISO_EXP_SELECT_PRIORITY,
                vTags.get(), &tag);
        res = request->update(tag, &selectPriority, 1);
        res = CameraMetadata::getTagFromName(KEY_QTI_VENDOR_ISO_EXP_USE_VALUE, vTags.get(), &tag);
        res = request->update(tag, &(exposureTime),  1);
        if (res != OK) {
            return res;
        }

        //erase the default value of construct_default_setting.
        res = request->erase(ANDROID_SENSOR_SENSITIVITY);
        if (res != OK) {
            return res;
        }
        res = request->erase(ANDROID_SENSOR_EXPOSURE_TIME);
        if (res != OK) {
            return res;
        }
    }

    //Sharpness value
    res = CameraMetadata::getTagFromName(KEY_QTI_VENDOR_SHARPNESS_STRENGTH, vTags.get(), &tag);
    res = request->update(tag,&sharpnessValue, 1);
    if (res != OK) {
        return res;
    }

    //Saturation value
    res = CameraMetadata::getTagFromName(KEY_QTI_VENDOR_SATURATION, vTags.get(), &tag);
    res = request->update(tag,&saturationValue, 1);
    if (res != OK) {
        return res;
    }

    //Exposure Metering
    res = CameraMetadata::getTagFromName(KEY_QTI_VENDOR_EXPOSURE_METER, vTags.get(), &tag);
    res = request->update(tag,&exposureMetering, 1);
    if (res != OK) {
        return res;
    }

    //Instant AEC
    res = CameraMetadata::getTagFromName(KEY_QTI_VENDOR_INSTANT_MODE, vTags.get(), &tag);
    res = request->update(tag,&instantAecValue, 1);
    if (res != OK) {
        return res;
    }

    //Color Correction gains
    res = request->update(ANDROID_COLOR_CORRECTION_GAINS,(float *)&(manualWb.gains),4);
    if (res != OK) {
        return res;
    }

    //redeye-reduction
    if(flashMode == (flashMode_t)Parameters::FLASH_MODE_RED_EYE) {
        uint8_t reqFlashMode = ANDROID_FLASH_MODE_OFF;
        uint8_t reqAeMode = flashMode;

        res = request->update(ANDROID_FLASH_MODE, &reqFlashMode, 1);
        if (res != OK) return res;
        res = request->update(ANDROID_CONTROL_AE_MODE, &reqAeMode, 1);
        if (res != OK) return res;
    }

    //Histogram
    res = CameraMetadata::getTagFromName(KEY_QTI_VENDOR_HISTOGRAM, vTags.get(), &tag);
    res = request->update(tag, &histogramMode, 1);
    if (res != OK) {
        return res;
    }

    return res;
}

status_t QTIParameters::updateRequestForQTICapture(Vector<CameraMetadata> *requests) const {
    status_t res = OK;
    sp<VendorTagDescriptor> vTags =
        VendorTagDescriptor::getGlobalVendorTagDescriptor();

    if (!requests) {
       return BAD_VALUE;
    }

    // Check if any Capture request settings need to be changed for QTI features

    // For HDR need one extra frame.
    if(Hdr1xEnable && (HdrSceneEnable||(isHdrScene && autoHDREnabled))){
        for (size_t i = 0; i < burstCount; i++) {
            CameraMetadata &request = requests->editItemAt(i);
            uint8_t reqSceneMode;
            uint8_t reqControlMode;
            if(i==0) {
                reqSceneMode = ANDROID_CONTROL_SCENE_MODE_DISABLED;
                reqControlMode = ANDROID_CONTROL_MODE_AUTO;
            }
            else {
                reqSceneMode = ANDROID_CONTROL_SCENE_MODE_HDR;
                reqControlMode = ANDROID_CONTROL_MODE_USE_SCENE_MODE;
            }
            res = request.update(ANDROID_CONTROL_MODE,
                    &reqControlMode, 1);
            if (res != OK) {
                return res;
            }

            res = request.update(ANDROID_CONTROL_SCENE_MODE,
                    &reqSceneMode, 1);
            if (res != OK) {
                return res;
            }
        }
    }
    else {
        if(autoHDREnabled && isHdrScene) {
            CameraMetadata &request = requests->editItemAt(0);
            uint8_t reqSceneMode;
            uint8_t reqControlMode;
            reqSceneMode = ANDROID_CONTROL_SCENE_MODE_HDR;
            reqControlMode = ANDROID_CONTROL_MODE_USE_SCENE_MODE;

            res = request.update(ANDROID_CONTROL_MODE, &reqControlMode, 1);
            if (res != OK) {
                return res;
            }
            res = request.update(ANDROID_CONTROL_SCENE_MODE, &reqSceneMode, 1);
            if (res != OK) {
                return res;
            }
        }
    }

    // For AE bracketing
    if (aeBracketEnable) {
        // If AE bracketing is enabled, then burstCount is the number of bracket values.
        for (size_t i = 0; i < burstCount; i++) {
            CameraMetadata &request = requests->editItemAt(i);
            res = request.update(ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION,
                    &aeBracketValues[i], 1);
            if (res != OK) {
                return res;
            }
        }
    }

    return res;
}

int32_t QTIParameters::setManualWBGains(const char *gainStr, CameraParameters2& newParams)
{
    int32_t res = OK;
    if (gainStr != NULL) {
        double rGain,gGain,bGain;
        res = parseGains(gainStr, rGain, gGain, bGain);
        if (res != OK) {
            return res;
        }

        double minGain = atof(minWbGain);
        double maxGain = atof(maxWbGain);

        if (rGain >= minGain && rGain <= maxGain &&
                gGain >= minGain && gGain <= maxGain &&
                bGain >= minGain && bGain <= maxGain) {
            newParams.set(KEY_QTI_MANUAL_WB_GAINS, gainStr);

            manualWb.type = CAM_MANUAL_WB_MODE_GAIN;
            manualWb.gains.rGain = rGain;
            manualWb.gains.gEvenGain = gGain;
            manualWb.gains.gOddGain = gGain;
            manualWb.gains.bGain = bGain;
            return res;
        }
        return BAD_VALUE;
    }
    return BAD_VALUE;
}

int32_t QTIParameters::parseGains(const char *gainStr, double &rGain,
                                          double &gGain, double &bGain)
{
    int32_t res = OK;
    char *saveptr = NULL;
    size_t gainsSize = strlen(gainStr) + 1;
    char* gains = (char*) calloc(1, gainsSize);
    if (NULL == gains) {
        ALOGE("No memory for gains");
        return NO_MEMORY;
    }
    strlcpy(gains, gainStr, gainsSize);
    char *token = strtok_r(gains, ",", &saveptr);

    if (NULL != token) {
        rGain = (float) atof(token);
        token = strtok_r(NULL, ",", &saveptr);
    }

    if (NULL != token) {
        gGain = (float) atof(token);
        token = strtok_r(NULL, ",", &saveptr);
    }

    if (NULL != token) {
        bGain = (float) atof(token);
    } else {
        ALOGE("Malformed string for gains");
        res = BAD_VALUE;
    }

    free(gains);
    return res;
}


int32_t  QTIParameters::setExposureTime(const char *expTimeStr, CameraParameters2& newParams)
{
    double expTimeMs = atof(expTimeStr);
    //input is in milli seconds. Convert to nano sec
    int64_t expTimeNs = (int64_t)(expTimeMs*1000000L);

    // expTime == 0 means not to use manual exposure time.
    if ((0 <= expTimeMs) &&
            ((expTimeMs == 0) ||
            ((expTimeMs >= (int64_t) minExposureTime) &&
            (expTimeMs <= (int64_t) maxExposureTime)))) {
        newParams.set(KEY_QTI_EXPOSURE_TIME, expTimeStr);
        exposureTime = expTimeNs;

        return OK;
    }
    return BAD_VALUE;
}

int32_t  QTIParameters::setContinuousISO(const char *isoVal, CameraParameters2& newParams)
{
    char iso[PROPERTY_VALUE_MAX];
    int32_t continousIso = 0;

    // Check if continuous ISO is set through setproperty
    property_get("persist.camera.continuous.iso", iso, "");
    if (strlen(iso) > 0) {
        continousIso = atoi(iso);
    } else {
        continousIso = atoi(isoVal);
    }

    if ((continousIso >= 0) &&
            (continousIso <= g_availableSensitivityRange.data.i32[1])) {
        newParams.set(KEY_QTI_CONTINUOUS_ISO, isoVal);
        isoValue = continousIso;
        return OK;
    }
    ALOGE("Invalid iso value: %d", continousIso);
    return BAD_VALUE;
}

const char*  QTIParameters::PictureFormatEnumToString(int format)
{
    switch (format) {
        case HAL_PIXEL_FORMAT_RAW10:
            return QC_PIXEL_FORMAT_BAYER_MIPI_RAW_10RGGB;
        default:
            ALOGE("%s: Unknown picuture format enum %d",
                    __FUNCTION__, format);
            return "unknown";
        }
}

int QTIParameters::PictureFormatStringToEnum(const char * format)
{
        return
        !strcmp(format, CameraParameters::PIXEL_FORMAT_JPEG) ?
                HAL_PIXEL_FORMAT_BLOB :    // jpeg
        !strcmp(format, QC_PIXEL_FORMAT_BAYER_MIPI_RAW_10RGGB) ?
            HAL_PIXEL_FORMAT_RAW10 :    // RGB10
        -1;
}

}; // namespace camera2
}; // namespace android

