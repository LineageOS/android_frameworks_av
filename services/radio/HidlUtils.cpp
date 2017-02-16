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
#define LOG_TAG "HidlUtils"
//#define LOG_NDEBUG 0

#include <utils/Log.h>
#include <utils/misc.h>
#include <system/radio_metadata.h>

#include "HidlUtils.h"

namespace android {

using android::hardware::broadcastradio::V1_0::MetadataType;
using android::hardware::broadcastradio::V1_0::Band;
using android::hardware::broadcastradio::V1_0::Deemphasis;
using android::hardware::broadcastradio::V1_0::Rds;

//static
int HidlUtils::convertHalResult(Result result)
{
    switch (result) {
        case Result::OK:
            return 0;
        case Result::INVALID_ARGUMENTS:
            return -EINVAL;
        case Result::INVALID_STATE:
            return -ENOSYS;
        case Result::TIMEOUT:
            return -ETIMEDOUT;
        case Result::NOT_INITIALIZED:
        default:
            return -ENODEV;
    }
}


//static
void HidlUtils::convertBandConfigToHal(BandConfig *halConfig,
                                       const radio_hal_band_config_t *config)
{
    halConfig->type = static_cast<Band>(config->type);
    halConfig->antennaConnected = config->antenna_connected;
    halConfig->lowerLimit = config->lower_limit;
    halConfig->upperLimit = config->upper_limit;
    halConfig->spacings.setToExternal(const_cast<unsigned int *>(&config->spacings[0]),
                                       config->num_spacings * sizeof(uint32_t));
    // FIXME: transfer buffer ownership. should have a method for that in hidl_vec
    halConfig->spacings.resize(config->num_spacings);

    if (halConfig->type == Band::FM) {
        halConfig->ext.fm.deemphasis = static_cast<Deemphasis>(config->fm.deemphasis);
        halConfig->ext.fm.stereo = config->fm.stereo;
        halConfig->ext.fm.rds = static_cast<Rds>(config->fm.rds);
        halConfig->ext.fm.ta = config->fm.ta;
        halConfig->ext.fm.af = config->fm.af;
        halConfig->ext.fm.ea = config->fm.ea;
    } else {
        halConfig->ext.am.stereo = config->am.stereo;
    }
}

//static
void HidlUtils::convertPropertiesFromHal(radio_hal_properties_t *properties,
                                         const Properties *halProperties)
{
    properties->class_id = static_cast<radio_class_t>(halProperties->classId);
    strlcpy(properties->implementor, halProperties->implementor.c_str(), RADIO_STRING_LEN_MAX);
    strlcpy(properties->product, halProperties->product.c_str(), RADIO_STRING_LEN_MAX);
    strlcpy(properties->version, halProperties->version.c_str(), RADIO_STRING_LEN_MAX);
    strlcpy(properties->serial, halProperties->serial.c_str(), RADIO_STRING_LEN_MAX);
    properties->num_tuners = halProperties->numTuners;
    properties->num_audio_sources = halProperties->numAudioSources;
    properties->supports_capture = halProperties->supportsCapture;
    properties->num_bands = halProperties->bands.size();

    for (size_t i = 0; i < halProperties->bands.size(); i++) {
        convertBandConfigFromHal(&properties->bands[i], &halProperties->bands[i]);
    }
}

//static
void HidlUtils::convertBandConfigFromHal(radio_hal_band_config_t *config,
                                         const BandConfig *halConfig)
{
    config->type = static_cast<radio_band_t>(halConfig->type);
    config->antenna_connected = halConfig->antennaConnected;
    config->lower_limit = halConfig->lowerLimit;
    config->upper_limit = halConfig->upperLimit;
    config->num_spacings = halConfig->spacings.size();
    if (config->num_spacings > RADIO_NUM_SPACINGS_MAX) {
        config->num_spacings = RADIO_NUM_SPACINGS_MAX;
    }
    memcpy(config->spacings, halConfig->spacings.data(),
           sizeof(uint32_t) * config->num_spacings);

    if (halConfig->type == Band::FM) {
        config->fm.deemphasis = static_cast<radio_deemphasis_t>(halConfig->ext.fm.deemphasis);
        config->fm.stereo = halConfig->ext.fm.stereo;
        config->fm.rds = static_cast<radio_rds_t>(halConfig->ext.fm.rds);
        config->fm.ta = halConfig->ext.fm.ta;
        config->fm.af = halConfig->ext.fm.af;
        config->fm.ea = halConfig->ext.fm.ea;
    } else {
        config->am.stereo = halConfig->ext.am.stereo;
    }
}


//static
void HidlUtils::convertProgramInfoFromHal(radio_program_info_t *info,
                                          const ProgramInfo *halInfo)
{
    info->channel = halInfo->channel;
    info->sub_channel = halInfo->subChannel;
    info->tuned = halInfo->tuned;
    info->stereo = halInfo->stereo;
    info->digital = halInfo->digital;
    info->signal_strength = halInfo->signalStrength;
    convertMetaDataFromHal(&info->metadata, halInfo->metadata,
                           halInfo->channel, halInfo->subChannel);
}

// TODO(twasilczyk): drop unnecessary channel info
//static
void HidlUtils::convertMetaDataFromHal(radio_metadata_t **metadata,
                                       const hidl_vec<MetaData>& halMetadata,
                                       uint32_t channel __unused,
                                       uint32_t subChannel __unused)
{

    if (metadata == nullptr || *metadata == nullptr) {
        ALOGE("destination metadata buffer is a nullptr");
        return;
    }
    for (size_t i = 0; i < halMetadata.size(); i++) {
        radio_metadata_key_t key = static_cast<radio_metadata_key_t>(halMetadata[i].key);
        radio_metadata_type_t type = static_cast<radio_metadata_key_t>(halMetadata[i].type);
        radio_metadata_clock_t clock;

        switch (type) {
        case RADIO_METADATA_TYPE_INT:
            radio_metadata_add_int(metadata, key, halMetadata[i].intValue);
            break;
        case RADIO_METADATA_TYPE_TEXT:
            radio_metadata_add_text(metadata, key, halMetadata[i].stringValue.c_str());
            break;
        case RADIO_METADATA_TYPE_RAW:
            radio_metadata_add_raw(metadata, key,
                                   halMetadata[i].rawValue.data(),
                                   halMetadata[i].rawValue.size());
            break;
        case RADIO_METADATA_TYPE_CLOCK:
            clock.utc_seconds_since_epoch =
                    halMetadata[i].clockValue.utcSecondsSinceEpoch;
            clock.timezone_offset_in_minutes =
                    halMetadata[i].clockValue.timezoneOffsetInMinutes;
            radio_metadata_add_clock(metadata, key, &clock);
            break;
        default:
            ALOGW("%s invalid metadata type %u",__FUNCTION__, halMetadata[i].type);
            break;
        }
    }
}

}  // namespace android
