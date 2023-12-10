/*
 * Copyright (C) 2006-2011 The Android Open Source Project
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

#define LOG_TAG "AudioParameter"
//#define LOG_NDEBUG 0

#include <utils/Log.h>

#include <media/AudioParameter.h>
#include <hardware/audio.h>
#include <system/audio.h>

namespace android {

// static
const char * const AudioParameter::keyRouting = AUDIO_PARAMETER_STREAM_ROUTING;
const char * const AudioParameter::keySamplingRate = AUDIO_PARAMETER_STREAM_SAMPLING_RATE;
const char * const AudioParameter::keyFormat = AUDIO_PARAMETER_STREAM_FORMAT;
const char * const AudioParameter::keyChannels = AUDIO_PARAMETER_STREAM_CHANNELS;
const char * const AudioParameter::keyFrameCount = AUDIO_PARAMETER_STREAM_FRAME_COUNT;
const char * const AudioParameter::keyInputSource = AUDIO_PARAMETER_STREAM_INPUT_SOURCE;
const char * const AudioParameter::keyScreenState = AUDIO_PARAMETER_KEY_SCREEN_STATE;
const char * const AudioParameter::keyScreenRotation = AUDIO_PARAMETER_KEY_ROTATION;
const char * const AudioParameter::keyClosing = AUDIO_PARAMETER_KEY_CLOSING;
const char * const AudioParameter::keyExiting = AUDIO_PARAMETER_KEY_EXITING;
const char * const AudioParameter::keyBtSco = AUDIO_PARAMETER_KEY_BT_SCO;
const char * const AudioParameter::keyBtScoHeadsetName = AUDIO_PARAMETER_KEY_BT_SCO_HEADSET_NAME;
const char * const AudioParameter::keyBtNrec = AUDIO_PARAMETER_KEY_BT_NREC;
const char * const AudioParameter::keyBtScoWb = AUDIO_PARAMETER_KEY_BT_SCO_WB;
const char * const AudioParameter::keyBtHfpEnable = AUDIO_PARAMETER_KEY_HFP_ENABLE;
const char * const AudioParameter::keyBtHfpSamplingRate = AUDIO_PARAMETER_KEY_HFP_SET_SAMPLING_RATE;
const char * const AudioParameter::keyBtHfpVolume = AUDIO_PARAMETER_KEY_HFP_VOLUME;
#ifndef __ANDROID_VNDK__
const char * const AudioParameter::keyTtyMode = AUDIO_PARAMETER_KEY_TTY_MODE;
const char * const AudioParameter::valueTtyModeOff = AUDIO_PARAMETER_VALUE_TTY_OFF;
const char * const AudioParameter::valueTtyModeFull = AUDIO_PARAMETER_VALUE_TTY_FULL;
const char * const AudioParameter::valueTtyModeHco = AUDIO_PARAMETER_VALUE_TTY_HCO;
const char * const AudioParameter::valueTtyModeVco = AUDIO_PARAMETER_VALUE_TTY_VCO;
const char * const AudioParameter::keyHacSetting = AUDIO_PARAMETER_KEY_HAC;
const char * const AudioParameter::valueHacOff = AUDIO_PARAMETER_VALUE_HAC_OFF;
const char * const AudioParameter::valueHacOn = AUDIO_PARAMETER_VALUE_HAC_ON;
#endif  // __ANDROID_VNDK__
const char * const AudioParameter::keyHwAvSync = AUDIO_PARAMETER_HW_AV_SYNC;
const char * const AudioParameter::keyPresentationId = AUDIO_PARAMETER_STREAM_PRESENTATION_ID;
const char * const AudioParameter::keyProgramId = AUDIO_PARAMETER_STREAM_PROGRAM_ID;
const char * const AudioParameter::keyAudioLanguagePreferred =
        AUDIO_PARAMETER_KEY_AUDIO_LANGUAGE_PREFERRED;
const char * const AudioParameter::keyMonoOutput = AUDIO_PARAMETER_MONO_OUTPUT;
const char * const AudioParameter::keyStreamHwAvSync = AUDIO_PARAMETER_STREAM_HW_AV_SYNC;
const char * const AudioParameter::keyDeviceConnect = AUDIO_PARAMETER_DEVICE_CONNECT;
const char * const AudioParameter::keyDeviceDisconnect = AUDIO_PARAMETER_DEVICE_DISCONNECT;
const char * const AudioParameter::keyStreamConnect = AUDIO_PARAMETER_DEVICE_CONNECT;
const char * const AudioParameter::keyStreamDisconnect = AUDIO_PARAMETER_DEVICE_DISCONNECT;
const char * const AudioParameter::keyStreamSupportedFormats = AUDIO_PARAMETER_STREAM_SUP_FORMATS;
const char * const AudioParameter::keyStreamSupportedChannels = AUDIO_PARAMETER_STREAM_SUP_CHANNELS;
const char * const AudioParameter::keyStreamSupportedSamplingRates =
        AUDIO_PARAMETER_STREAM_SUP_SAMPLING_RATES;
const char * const AudioParameter::valueOn = AUDIO_PARAMETER_VALUE_ON;
const char * const AudioParameter::valueOff = AUDIO_PARAMETER_VALUE_OFF;
const char * const AudioParameter::valueTrue = AUDIO_PARAMETER_VALUE_TRUE;
const char * const AudioParameter::valueFalse = AUDIO_PARAMETER_VALUE_FALSE;
const char * const AudioParameter::valueListSeparator = AUDIO_PARAMETER_VALUE_LIST_SEPARATOR;
const char * const AudioParameter::keyBtA2dpSuspended = AUDIO_PARAMETER_KEY_BT_A2DP_SUSPENDED;
const char * const AudioParameter::keyReconfigA2dp = AUDIO_PARAMETER_RECONFIG_A2DP;
const char * const AudioParameter::keyReconfigA2dpSupported = AUDIO_PARAMETER_A2DP_RECONFIG_SUPPORTED;
const char * const AudioParameter::keyBtLeSuspended = AUDIO_PARAMETER_KEY_BT_LE_SUSPENDED;
// const char * const AudioParameter::keyDeviceSupportedEncapsulationModes =
//        AUDIO_PARAMETER_DEVICE_SUP_ENCAPSULATION_MODES;
// const char * const AudioParameter::keyDeviceSupportedEncapsulationMetadataTypes =
//        AUDIO_PARAMETER_DEVICE_SUP_ENCAPSULATION_METADATA_TYPES;
const char * const AudioParameter::keyAdditionalOutputDeviceDelay =
        AUDIO_PARAMETER_DEVICE_ADDITIONAL_OUTPUT_DELAY;
const char * const AudioParameter::keyMaxAdditionalOutputDeviceDelay =
        AUDIO_PARAMETER_DEVICE_MAX_ADDITIONAL_OUTPUT_DELAY;
const char * const AudioParameter::keyOffloadCodecAverageBitRate = AUDIO_OFFLOAD_CODEC_AVG_BIT_RATE;
const char * const AudioParameter::keyOffloadCodecSampleRate = AUDIO_OFFLOAD_CODEC_SAMPLE_RATE;
const char * const AudioParameter::keyOffloadCodecChannels = AUDIO_OFFLOAD_CODEC_NUM_CHANNEL;
const char * const AudioParameter::keyOffloadCodecDelaySamples = AUDIO_OFFLOAD_CODEC_DELAY_SAMPLES;
const char * const AudioParameter::keyOffloadCodecPaddingSamples =
        AUDIO_OFFLOAD_CODEC_PADDING_SAMPLES;

AudioParameter::AudioParameter(const String8& keyValuePairs)
{
    char *str = new char[keyValuePairs.length()+1];
    mKeyValuePairs = keyValuePairs;
    char *last;

    strcpy(str, keyValuePairs.string());
    char *pair = strtok_r(str, ";", &last);
    while (pair != NULL) {
        if (strlen(pair) != 0) {
            size_t eqIdx = strcspn(pair, "=");
            String8 key = String8(pair, eqIdx);
            String8 value;
            if (eqIdx == strlen(pair)) {
                value = String8("");
            } else {
                value = String8(pair + eqIdx + 1);
            }
            if (mParameters.indexOfKey(key) < 0) {
                mParameters.add(key, value);
            } else {
                mParameters.replaceValueFor(key, value);
            }
        } else {
            ALOGV("AudioParameter() cstor empty key value pair");
        }
        pair = strtok_r(NULL, ";", &last);
    }

    delete[] str;
}

AudioParameter::~AudioParameter()
{
    mParameters.clear();
}

String8 AudioParameter::toStringImpl(bool useValues) const
{
    String8 str = String8("");

    size_t size = mParameters.size();
    for (size_t i = 0; i < size; i++) {
        str += mParameters.keyAt(i);
        if (useValues) {
            str += "=";
            str += mParameters.valueAt(i);
        }
        if (i < (size - 1)) str += ";";
    }
    return str;
}

status_t AudioParameter::add(const String8& key, const String8& value)
{
    if (mParameters.indexOfKey(key) < 0) {
        mParameters.add(key, value);
        return NO_ERROR;
    } else {
        mParameters.replaceValueFor(key, value);
        return ALREADY_EXISTS;
    }
}

status_t AudioParameter::addKey(const String8& key)
{
    return add(key, String8());
}

status_t AudioParameter::addInt(const String8& key, const int value)
{
    char str[12];
    if (snprintf(str, 12, "%d", value) > 0) {
        String8 str8 = String8(str);
        return add(key, str8);
    } else {
        return BAD_VALUE;
    }
}

status_t AudioParameter::addFloat(const String8& key, const float value)
{
    char str[23];
    if (snprintf(str, 23, "%.10f", value) > 0) {
        String8 str8 = String8(str);
        return add(key, str8);
    } else {
        return BAD_VALUE;
    }
}

status_t AudioParameter::remove(const String8& key)
{
    if (mParameters.indexOfKey(key) >= 0) {
        mParameters.removeItem(key);
        return NO_ERROR;
    } else {
        return BAD_VALUE;
    }
}

status_t AudioParameter::get(const String8& key, String8& value) const
{
    if (mParameters.indexOfKey(key) >= 0) {
        value = mParameters.valueFor(key);
        return NO_ERROR;
    } else {
        return BAD_VALUE;
    }
}

status_t AudioParameter::getInt(const String8& key, int& value) const
{
    String8 str8;
    status_t result = get(key, str8);
    value = 0;
    if (result == NO_ERROR) {
        int val;
        if (sscanf(str8.string(), "%d", &val) == 1) {
            value = val;
        } else {
            result = INVALID_OPERATION;
        }
    }
    return result;
}

status_t AudioParameter::getFloat(const String8& key, float& value) const
{
    String8 str8;
    status_t result = get(key, str8);
    value = 0;
    if (result == NO_ERROR) {
        float val;
        if (sscanf(str8.string(), "%f", &val) == 1) {
            value = val;
        } else {
            result = INVALID_OPERATION;
        }
    }
    return result;
}

status_t AudioParameter::getAt(size_t index, String8& key) const
{
    if (mParameters.size() > index) {
        key = mParameters.keyAt(index);
        return NO_ERROR;
    } else {
        return BAD_VALUE;
    }
}

status_t AudioParameter::getAt(size_t index, String8& key, String8& value) const
{
    if (mParameters.size() > index) {
        key = mParameters.keyAt(index);
        value = mParameters.valueAt(index);
        return NO_ERROR;
    } else {
        return BAD_VALUE;
    }
}

bool AudioParameter::containsKey(const String8& key) const
{
    return mParameters.indexOfKey(key) >= 0;
}

} // namespace android
