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

#ifndef ANDROID_SERVERS_CAMERA_QTICAMERA2PARAMETERS_H
#define ANDROID_SERVERS_CAMERA_QTICAMERA2PARAMETERS_H

#include <system/graphics.h>
#include <utils/RefBase.h>

#include <utils/Compat.h>
#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/Mutex.h>
#include <utils/String8.h>
#include <utils/Vector.h>

#include <camera/CameraParameters.h>
#include <camera/CameraParameters2.h>
#include <camera/CameraMetadata.h>
#include <camera/VendorTagDescriptor.h>
#include <CameraService.h>

namespace android {

class CameraDeviceBase;

namespace camera2 {

#define QTIAMERA_MAX_EXP_TIME_LEVEL1      100
#define MAX_BURST_COUNT_AE_BRACKETING     8

typedef enum {
    CAM_MANUAL_WB_MODE_CCT,
    CAM_MANUAL_WB_MODE_GAIN,
    CAM_MANUAL_WB_MODE_MAX
}cam_manual_wb_mode_type;

typedef struct {
    float rGain;
    float gEvenGain;
    float gOddGain;
    float bGain;
} cam_awb_gain_t;

typedef struct {
    cam_manual_wb_mode_type type;
    union{
        int32_t cct;
        cam_awb_gain_t gains;
    };
} cam_manual_wb_parm_t;

struct Parameters;

class QTIParameters: public virtual RefBase{
    /**
     * QTI specific parameters and other info
     */
private:
    int32_t isoValue;
    int32_t sharpnessValue;
    int32_t saturationValue;
    int32_t exposureMetering;
    int32_t instantAecValue;
    int64_t exposureTime;
    cam_manual_wb_parm_t manualWb;
    int32_t aeBracketValues[MAX_BURST_COUNT_AE_BRACKETING];

    enum flashMode_t {
        FLASH_MODE_RED_EYE = ANDROID_CONTROL_AE_MODE_ON_AUTO_FLASH_REDEYE,
        FLASH_MODE_INVALID = -1
    } flashMode;

public:
    int32_t videoHdr;
    int32_t prevVideoHdr;
    uint8_t histogramMode;
    int32_t histogramBucketSize;
    bool isHdrScene;
    bool autoHDREnabled;
    bool mNeedRestart;
    uint8_t burstCount;
    uint8_t lastBurstCount;
    bool aeBracketEnable;
    bool hfrMode;
    int32_t hfrPreviewFpsRange[2];
    int32_t nonHfrPreviewFpsRange[2];
    bool Hdr1xEnable;
    bool HdrSceneEnable;
    metadata_vendor_id_t vendorTagId;
    // Sets up default QTI parameters
    status_t initialize(void *parametersParent, sp<CameraDeviceBase> device, sp<CameraProviderManager> manager);
    // Validate and update camera parameters based on new settings
    status_t set(CameraParameters2& newParams, void *parametersParent);
    // Update passed-in request for common parameters
    status_t updateRequest(CameraMetadata *request) const;
    status_t updateRequestForQTICapture(Vector<CameraMetadata> *requests) const;
    static const char* wbModeEnumToString(uint8_t wbMode);
    static int wbModeStringToEnum(const char *wbMode);
    static int sceneModeStringToEnum(const char *sceneMode);

private:
    int32_t setContinuousISO(const char *isoValue, CameraParameters2& newParams);
    int32_t setExposureTime(const char *expTimeStr, CameraParameters2& newParams);
    int32_t setManualWBGains(const char *gainStr, CameraParameters2& newParams);
    int32_t parseGains(const char *gainStr, double &r_gain,
            double &g_gain, double &b_gain);
    const char *flashModeEnumToString(flashMode_t flashMode);
};

}; // namespace camera2
}; // namespace android

#endif
