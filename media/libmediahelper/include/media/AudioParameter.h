/*
 * Copyright (C) 2008-2011 The Android Open Source Project
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

#ifndef ANDROID_AUDIOPARAMETER_H_
#define ANDROID_AUDIOPARAMETER_H_

#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/String8.h>

namespace android {

class AudioParameter {

public:
    AudioParameter() {}
    AudioParameter(const String8& keyValuePairs);
    virtual ~AudioParameter();

    // reserved parameter keys for changing standard parameters with setParameters() function.
    // Using these keys is mandatory for AudioFlinger to properly monitor audio output/input
    // configuration changes and act accordingly.
    //  keyRouting: to change audio routing, value is an int in audio_devices_t
    //  keySamplingRate: to change sampling rate routing, value is an int
    //  keyFormat: to change audio format, value is an int in audio_format_t
    //  keyChannels: to change audio channel configuration, value is an int in audio_channels_t
    //  keyFrameCount: to change audio output frame count, value is an int
    //  keyInputSource: to change audio input source, value is an int in audio_source_t
    //     (defined in media/mediarecorder.h)
    //  keyScreenState: either "on" or "off"
    //  keyScreenRotation: one of: 0, 90, 180, 270
    static const char * const keyRouting;
    static const char * const keySamplingRate;
    static const char * const keyFormat;
    static const char * const keyChannels;
    static const char * const keyFrameCount;
    static const char * const keyInputSource;
    static const char * const keyScreenState;
    static const char * const keyScreenRotation;

    // keyClosing: "true" on AudioFlinger Thread preExit.  Used by A2DP HAL.
    // keyExiting: "1" on AudioFlinger Thread preExit.  Used by remote_submix and A2DP HAL.
    static const char * const keyClosing;
    static const char * const keyExiting;

    //  keyBtSco: Whether BT SCO is 'on' or 'off'
    //  keyBtScoHeadsetName: BT SCO headset name (for debugging)
    //  keyBtNrec: BT SCO Noise Reduction + Echo Cancellation parameters
    //  keyBtScoWb: BT SCO NR wideband mode
    //  keyHfp...: Parameters of the Hands-Free Profile
    static const char * const keyBtSco;
    static const char * const keyBtScoHeadsetName;
    static const char * const keyBtNrec;
    static const char * const keyBtScoWb;
    static const char * const keyBtHfpEnable;
    static const char * const keyBtHfpSamplingRate;
    static const char * const keyBtHfpVolume;

#ifndef __ANDROID_VNDK__
    // These static fields are not used by vendor code, they were added to make
    // the framework code consistent. There is no plan to expose them to vendors
    // because they were used by HIDL get/setParameters interface which does not
    // exist in the AIDL HAL interface.
    static const char * const keyTtyMode;
    static const char * const valueTtyModeOff;
    static const char * const valueTtyModeFull;
    static const char * const valueTtyModeHco;
    static const char * const valueTtyModeVco;

    static const char * const keyHacSetting;
    static const char * const valueHacOff;
    static const char * const valueHacOn;
#endif  // __ANDROID_VNDK__

    //  keyHwAvSync: get HW synchronization source identifier from a device
    //  keyMonoOutput: Enable mono audio playback
    //  keyStreamHwAvSync: set HW synchronization source identifier on a stream
    static const char * const keyHwAvSync;
    static const char * const keyMonoOutput;
    static const char * const keyStreamHwAvSync;

    //  keys for presentation selection
    //  keyPresentationId: Audio presentation identifier
    //  keyProgramId: Audio presentation program identifier
    static const char * const keyPresentationId;
    static const char * const keyProgramId;

    //  keyAudioLanguagePreferred: Preferred audio language
    static const char * const keyAudioLanguagePreferred;

    //  keyDeviceConnect / Disconnect: value is an int in audio_devices_t
    static const char * const keyDeviceConnect;
    static const char * const keyDeviceDisconnect;
    //  Need to be here because vendors still use them.
    static const char * const keyStreamConnect;  // Deprecated: DO NOT USE.
    static const char * const keyStreamDisconnect;  // Deprecated: DO NOT USE.

    // For querying stream capabilities. All the returned values are lists.
    //   keyStreamSupportedFormats: audio_format_t
    //   keyStreamSupportedChannels: audio_channel_mask_t
    //   keyStreamSupportedSamplingRates: sampling rate values
    static const char * const keyStreamSupportedFormats;
    static const char * const keyStreamSupportedChannels;
    static const char * const keyStreamSupportedSamplingRates;

    static const char * const valueOn;
    static const char * const valueOff;
    static const char * const valueTrue;
    static const char * const valueFalse;

    static const char * const valueListSeparator;

    // keyBtA2dpSuspended: 'true' or 'false'
    // keyReconfigA2dp: Ask HwModule to reconfigure A2DP offloaded codec
    // keyReconfigA2dpSupported: Query if HwModule supports A2DP offload codec config
    // keyBtLeSuspended: 'true' or 'false'
    static const char * const keyBtA2dpSuspended;
    static const char * const keyReconfigA2dp;
    static const char * const keyReconfigA2dpSupported;
    static const char * const keyBtLeSuspended;

    // For querying device supported encapsulation capabilities. All returned values are integer,
    // which are bit fields composed from using encapsulation capability values as position bits.
    // Encapsulation capability values are defined in audio_encapsulation_mode_t and
    // audio_encapsulation_metadata_type_t. For instance, if the supported encapsulation mode is
    // AUDIO_ENCAPSULATION_MODE_ELEMENTARY_STREAM, the returned value is
    // "supEncapsulationModes=1 << AUDIO_ENCAPSULATION_MODE_HANDLE".
    // When querying device supported encapsulation capabilities, the key should use with device
    // type and address so that it is able to identify the device. The device will be a key. The
    // device type will be the value of key AUDIO_PARAMETER_STREAM_ROUTING.
    // static const char * const keyDeviceSupportedEncapsulationModes;
    // static const char * const keyDeviceSupportedEncapsulationMetadataTypes;

    static const char * const keyAdditionalOutputDeviceDelay;
    static const char * const keyMaxAdditionalOutputDeviceDelay;

    static const char * const keyOffloadCodecAverageBitRate;
    static const char * const keyOffloadCodecSampleRate;
    static const char * const keyOffloadCodecChannels;
    static const char * const keyOffloadCodecDelaySamples;
    static const char * const keyOffloadCodecPaddingSamples;

    String8 toString() const { return toStringImpl(true); }
    String8 keysToString() const { return toStringImpl(false); }

    status_t add(const String8& key, const String8& value);
    status_t addInt(const String8& key, const int value);
    status_t addKey(const String8& key);
    status_t addFloat(const String8& key, const float value);

    status_t remove(const String8& key);

    status_t get(const String8& key, int& value) const {
        return getInt(key, value);
    }
    status_t get(const String8& key, float& value) const {
        return getFloat(key, value);
    }
    status_t get(const String8& key, String8& value) const;
    status_t getInt(const String8& key, int& value) const;
    status_t getFloat(const String8& key, float& value) const;
    status_t getAt(size_t index, String8& key) const;
    status_t getAt(size_t index, String8& key, String8& value) const;

    size_t size() const { return mParameters.size(); }

    bool containsKey(const String8& key) const;
private:
    String8 mKeyValuePairs;
    KeyedVector <String8, String8> mParameters;

    String8 toStringImpl(bool useValues) const;
};

};  // namespace android

#endif  /*ANDROID_AUDIOPARAMETER_H_*/
