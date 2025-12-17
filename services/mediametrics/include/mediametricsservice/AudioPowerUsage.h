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

#pragma once

#include <android-base/thread_annotations.h>
#include <media/MediaMetricsItem.h>
#include <deque>
#include <mutex>
#include <thread>

#include "StatsdLog.h"

namespace android::mediametrics {

class AudioAnalytics;

class AudioPowerUsage {
  public:
    AudioPowerUsage(AudioAnalytics* audioAnalytics, const std::shared_ptr<StatsdLog>& statsdLog);
    ~AudioPowerUsage();

    void checkTrackRecord(const std::shared_ptr<const mediametrics::Item>& item, bool isTrack);
    void checkMode(const std::shared_ptr<const mediametrics::Item>& item);
    void checkVoiceVolume(const std::shared_ptr<const mediametrics::Item>& item);
    void checkCreatePatch(const std::shared_ptr<const mediametrics::Item>& item);
    void clear();

    /**
     * Returns a pair consisting of the dump string, and the number of lines in the string.
     *
     * The number of lines in the returned pair is used as an optimization
     * for subsequent line limiting.
     *
     * \param lines the maximum number of lines in the string returned.
     */
    std::pair<std::string, int32_t> dump(int32_t lines = INT32_MAX) const;

    enum AudioDevice {
        UNKNOWN_DEVICE = 0,
        // Output Devices
        OUTPUT_EARPIECE = 0x00000001u,
        OUTPUT_SPEAKER = 0x00000002u,
        OUTPUT_WIRED_HEADSET = 0x00000004u,
        OUTPUT_WIRED_HEADPHONE = 0x00000008u,
        OUTPUT_BLUETOOTH_SCO = 0x00000010u,
        OUTPUT_BLUETOOTH_SCO_HEADSET = 0x00000020u,
        OUTPUT_BLUETOOTH_SCO_CARKIT = 0x00000040u,
        OUTPUT_BLUETOOTH_A2DP = 0x00000080u,
        OUTPUT_BLUETOOTH_A2DP_HEADPHONES = 0x00000100u,
        OUTPUT_BLUETOOTH_A2DP_SPEAKER = 0x00000200u,
        OUTPUT_HDMI = 0x00000400u,
        OUTPUT_ANLG_DOCK_HEADSET = 0x00000800u,
        OUTPUT_DGTL_DOCK_HEADSET = 0x00001000u,
        OUTPUT_USB_ACCESSORY = 0x00002000u,
        OUTPUT_USB_DEVICE = 0x00004000u,
        OUTPUT_REMOTE_SUBMIX = 0x00008000u,
        OUTPUT_TELEPHONY_TX = 0x00010000u,
        OUTPUT_LINE = 0x00020000u,
        OUTPUT_HDMI_ARC = 0x00040000u,
        OUTPUT_HDMI_EARC = 0x00040001u,
        OUTPUT_SPDIF = 0x00080000u,
        OUTPUT_FM = 0x00100000u,
        OUTPUT_AUX_LINE = 0x00200000u,
        OUTPUT_SPEAKER_SAFE = 0x00400000u,
        OUTPUT_IP = 0x00800000u,
        OUTPUT_MULTICHANNEL_GROUP = 0x00800001u,
        OUTPUT_BUS = 0x01000000u,
        OUTPUT_PROXY = 0x02000000u,
        OUTPUT_USB_HEADSET = 0x04000000u,
        OUTPUT_HEARING_AID = 0x08000000u,
        OUTPUT_ECHO_CANCELLER = 0x10000000u,
        OUTPUT_BLE_HEADSET = 0x20000000u,
        OUTPUT_BLE_SPEAKER = 0x20000001u,
        OUTPUT_BLE_BROADCAST = 0x20000002u,
        OUTPUT_BLE_HEARING_AID = 0x20000004u,
        OUTPUT_BLE_CENTRAL = 0x20000008u,
        // Input Devices
        INPUT_DEVICE_BIT = 0x40000000,
        INPUT_COMMUNICATION = 0x80000001u,
        INPUT_AMBIENT = 0x80000002u,
        INPUT_BUILTIN_MIC = 0x80000004u,
        INPUT_BLUETOOTH_SCO_HEADSET = 0x80000008u,
        INPUT_WIRED_HEADSET = 0x80000010u,
        INPUT_HDMI = 0x80000020u,
        INPUT_TELEPHONY_RX = 0x80000040u,
        INPUT_BACK_MIC = 0x80000080u,
        INPUT_REMOTE_SUBMIX = 0x80000100u,
        INPUT_ANLG_DOCK_HEADSET = 0x80000200u,
        INPUT_DGTL_DOCK_HEADSET = 0x80000400u,
        INPUT_USB_ACCESSORY = 0x80000800u,
        INPUT_USB_DEVICE = 0x80001000u,
        INPUT_FM_TUNER = 0x80002000u,
        INPUT_TV_TUNER = 0x80004000u,
        INPUT_LINE = 0x80008000u,
        INPUT_SPDIF = 0x80010000u,
        INPUT_BLUETOOTH_A2DP = 0x80020000u,
        INPUT_LOOPBACK = 0x80040000u,
        INPUT_IP = 0x80080000u,
        INPUT_BUS = 0x80100000u,
        INPUT_PROXY = 0x81000000u,
        INPUT_USB_HEADSET = 0x82000000u,
        INPUT_BLUETOOTH_BLE = 0x84000000u,
        INPUT_HDMI_ARC = 0x88000000u,
        INPUT_HDMI_EARC = 0x88000001u,
        INPUT_ECHO_REFERENCE = 0x90000000u,
        INPUT_BLE_HEADSET = 0xA0000000u,
        INPUT_BLE_HEARING_AID = 0xA0000001u,
        INPUT_BLE_CENTRAL = 0xA0000002u,
        INPUT_BLE_CENTRAL_BROADCAST = 0xA0000004u,
    };

    static bool deviceFromString(const std::string& device_string, int32_t& device);
    static int32_t deviceFromStringPairs(const std::string& device_strings);

  private:
    bool saveAsItem_l(int32_t device, int64_t duration, int32_t stream_type, int32_t source,
                      int32_t usage, int32_t content_type, double average_vol,
                      int64_t max_volume_duration, double max_volume, int64_t min_volume_duration,
                      double min_volume) REQUIRES(mLock);
    void sendItem(const std::shared_ptr<const mediametrics::Item>& item) const;
    void collect();
    bool saveAsItems_l(int32_t device, int64_t duration, int32_t stream_type, int32_t source,
                       int32_t usage, int32_t content_type, double average_vol,
                       int64_t max_volume_duration, double max_volume, int64_t min_volume_duration,
                       double min_volume) REQUIRES(mLock);
    void updateMinMaxVolumeAndDuration(const int64_t cur_max_volume_duration_ns,
                                       const double cur_max_volume,
                                       const int64_t cur_min_volume_duration_ns,
                                       const double cur_min_volume,
                                       int64_t& f_max_volume_duration_ns, double& f_max_volume,
                                       int64_t& f_min_volume_duration_ns, double& f_min_volume);
    AudioAnalytics* const mAudioAnalytics;
    const std::shared_ptr<StatsdLog> mStatsdLog;  // mStatsdLog is internally locked
    const bool mDisabled;
    const int32_t mIntervalHours;

    mutable std::mutex mLock;
    std::deque<std::shared_ptr<mediametrics::Item>> mItems GUARDED_BY(mLock);

    double mVoiceVolume GUARDED_BY(mLock) = 0.;
    double mDeviceVolume GUARDED_BY(mLock) = 0.;
    double mMaxVoiceVolume GUARDED_BY(mLock) = AMEDIAMETRICS_INITIAL_MAX_VOLUME;
    double mMinVoiceVolume GUARDED_BY(mLock) = AMEDIAMETRICS_INITIAL_MIN_VOLUME;
    int64_t mMaxVoiceVolumeDurationNs GUARDED_BY(mLock) = 0;
    int64_t mMinVoiceVolumeDurationNs GUARDED_BY(mLock) = 0;
    int64_t mStartCallNs GUARDED_BY(mLock) = 0;  // advisory only
    int64_t mVolumeTimeNs GUARDED_BY(mLock) = 0;
    int64_t mDeviceTimeNs GUARDED_BY(mLock) = 0;
    int32_t mPrimaryDevice GUARDED_BY(mLock) = OUTPUT_SPEAKER;
    std::string mMode GUARDED_BY(mLock){"AUDIO_MODE_NORMAL"};
};

}  // namespace android::mediametrics
