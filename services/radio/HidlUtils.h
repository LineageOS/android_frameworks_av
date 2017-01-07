/*
 * Copyright (C) 2016 The Android Open Source Project
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
#ifndef ANDROID_HARDWARE_RADIO_HAL_HIDL_UTILS_H
#define ANDROID_HARDWARE_RADIO_HAL_HIDL_UTILS_H

#include <android/hardware/broadcastradio/1.0/types.h>
#include <hardware/radio.h>

namespace android {

using android::hardware::hidl_vec;
using android::hardware::broadcastradio::V1_0::Result;
using android::hardware::broadcastradio::V1_0::Properties;
using android::hardware::broadcastradio::V1_0::BandConfig;
using android::hardware::broadcastradio::V1_0::ProgramInfo;
using android::hardware::broadcastradio::V1_0::MetaData;

class HidlUtils {
public:
    static int convertHalResult(Result result);
    static void convertBandConfigFromHal(radio_hal_band_config_t *config,
                                         const BandConfig *halConfig);
    static void convertPropertiesFromHal(radio_hal_properties_t *properties,
                                         const Properties *halProperties);
    static void convertBandConfigToHal(BandConfig *halConfig,
                                       const radio_hal_band_config_t *config);
    static void convertProgramInfoFromHal(radio_program_info_t *info,
                                          const ProgramInfo *halInfo);
    static void convertMetaDataFromHal(radio_metadata_t **metadata,
                                       const hidl_vec<MetaData>& halMetadata,
                                       uint32_t channel,
                                       uint32_t subChannel);
};

}  // namespace android

#endif  // ANDROID_HARDWARE_RADIO_HAL_HIDL_UTILS_H
