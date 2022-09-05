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

package android.media;

import android.media.AppVolumeData;
import android.media.AudioPatchFw;
import android.media.AudioPolicyConfig;
import android.media.AudioPortFw;
import android.media.AudioPortConfigFw;
import android.media.AudioUniqueIdUse;
import android.media.AudioVibratorInfo;
import android.media.CreateEffectRequest;
import android.media.CreateEffectResponse;
import android.media.CreateRecordRequest;
import android.media.CreateRecordResponse;
import android.media.CreateTrackRequest;
import android.media.CreateTrackResponse;
import android.media.DeviceConnectedState;
import android.media.OpenInputRequest;
import android.media.OpenInputResponse;
import android.media.OpenOutputRequest;
import android.media.OpenOutputResponse;
import android.media.EffectDescriptor;
import android.media.IAudioFlingerClient;
import android.media.IAudioRecord;
import android.media.IAudioTrack;
import android.media.ISoundDose;
import android.media.ISoundDoseCallback;
import android.media.MicrophoneInfoFw;
import android.media.RenderPosition;
import android.media.TrackSecondaryOutputInfo;
import android.media.audio.common.AudioChannelLayout;
import android.media.audio.common.AudioFormatDescription;
import android.media.audio.common.AudioLatencyMode;
import android.media.audio.common.AudioMMapPolicyInfo;
import android.media.audio.common.AudioMMapPolicyType;
import android.media.audio.common.AudioMode;
import android.media.audio.common.AudioStreamType;
import android.media.audio.common.AudioUuid;

/**
 * {@hide}
 */
interface IAudioFlingerService {
    /**
     * Creates an audio track and registers it with AudioFlinger, or null if the track cannot be
     * created.
     */
    CreateTrackResponse createTrack(in CreateTrackRequest request);

    CreateRecordResponse createRecord(in CreateRecordRequest request);

    // FIXME Surprisingly, format/latency don't work for input handles

    /**
     * Queries the audio hardware state. This state never changes, and therefore can be cached.
     */
    int sampleRate(int /* audio_io_handle_t */ ioHandle);

    AudioFormatDescription format(int /* audio_io_handle_t */ output);

    long frameCount(int /* audio_io_handle_t */ ioHandle);

    /**
     * Return the estimated latency in milliseconds.
     */
    int latency(int  /* audio_io_handle_t */ output);

    /*
     * Sets/gets the audio hardware state. This will probably be used by
     * the preference panel, mostly.
     */
    void setMasterVolume(float value);
    void setMasterMute(boolean muted);

    float masterVolume();
    boolean masterMute();

    void setMasterBalance(float balance);
    float getMasterBalance();

    void setAppVolume(@utf8InCpp String packageName, float value);
    void setAppMute(@utf8InCpp String packageName, boolean muted);
    AppVolumeData[] listAppVolumes();

    /*
     * Set/gets stream type state. This will probably be used by
     * the preference panel, mostly.
     */
    void setStreamVolume(AudioStreamType stream, float value, int /* audio_io_handle_t */ output);
    void setStreamMute(AudioStreamType stream, boolean muted);
    float streamVolume(AudioStreamType stream, int /* audio_io_handle_t */ output);
    boolean streamMute(AudioStreamType stream);

    // set audio mode.
    void setMode(AudioMode mode);

    // mic mute/state
    void setMicMute(boolean state);
    boolean getMicMute();
    void setRecordSilenced(int /* audio_port_handle_t */ portId,
                           boolean silenced);

    void setParameters(int /* audio_io_handle_t */ ioHandle,
                       @utf8InCpp String keyValuePairs);
    @utf8InCpp String getParameters(int /* audio_io_handle_t */ ioHandle,
                                    @utf8InCpp String keys);

    // Register an object to receive audio input/output change and track notifications.
    // For a given calling pid, AudioFlinger disregards any registrations after the first.
    // Thus the IAudioFlingerClient must be a singleton per process.
    void registerClient(IAudioFlingerClient client);

    // Retrieve the audio recording buffer size in bytes.
    // FIXME This API assumes a route, and so should be deprecated.
    long getInputBufferSize(int sampleRate,
                            in AudioFormatDescription format,
                            in AudioChannelLayout channelMask);

    OpenOutputResponse openOutput(in OpenOutputRequest request);
    int /* audio_io_handle_t */ openDuplicateOutput(int /* audio_io_handle_t */ output1,
                                                    int /* audio_io_handle_t */ output2);
    void closeOutput(int /* audio_io_handle_t */ output);
    void suspendOutput(int /* audio_io_handle_t */ output);
    void restoreOutput(int /* audio_io_handle_t */ output);

    OpenInputResponse openInput(in OpenInputRequest request);
    void closeInput(int /* audio_io_handle_t */ input);

    void setVoiceVolume(float volume);

    RenderPosition getRenderPosition(int /* audio_io_handle_t */ output);

    int getInputFramesLost(int /* audio_io_handle_t */ ioHandle);

    int /* audio_unique_id_t */ newAudioUniqueId(AudioUniqueIdUse use);

    void acquireAudioSessionId(int /* audio_session_t */ audioSession,
                               int /* pid_t */ pid,
                               int /* uid_t */ uid);
    void releaseAudioSessionId(int /* audio_session_t */ audioSession,
                               int /* pid_t */ pid);

    int queryNumberEffects();

    EffectDescriptor queryEffect(int index);

    /** preferredTypeFlag is interpreted as a uint32_t with the "effect flag" format. */
    EffectDescriptor getEffectDescriptor(in AudioUuid effectUUID,
                                         in AudioUuid typeUUID,
                                         int preferredTypeFlag);

    CreateEffectResponse createEffect(in CreateEffectRequest request);

    void moveEffects(int /* audio_session_t */ session,
                     int /* audio_io_handle_t */ srcOutput,
                     int /* audio_io_handle_t */ dstOutput);

    void setEffectSuspended(int effectId,
                            int /* audio_session_t */ sessionId,
                            boolean suspended);

    int /* audio_module_handle_t */ loadHwModule(@utf8InCpp String name);

    // helpers for android.media.AudioManager.getProperty(), see description there for meaning
    // FIXME move these APIs to AudioPolicy to permit a more accurate implementation
    // that looks on primary device for a stream with fast flag, primary flag, or first one.
    int getPrimaryOutputSamplingRate();
    long getPrimaryOutputFrameCount();

    // Intended for AudioService to inform AudioFlinger of device's low RAM attribute,
    // and should be called at most once.  For a definition of what "low RAM" means, see
    // android.app.ActivityManager.isLowRamDevice().  The totalMemory parameter
    // is obtained from android.app.ActivityManager.MemoryInfo.totalMem.
    void setLowRamDevice(boolean isLowRamDevice, long totalMemory);

    /* Get attributes for a given audio port */
    AudioPortFw getAudioPort(in AudioPortFw port);

    /* Create an audio patch between several source and sink ports */
    int /* audio_patch_handle_t */ createAudioPatch(in AudioPatchFw patch);

    /* Release an audio patch */
    void releaseAudioPatch(int /* audio_patch_handle_t */ handle);

    /* List existing audio patches */
    AudioPatchFw[] listAudioPatches(int maxCount);
    /* Set audio port configuration */
    void setAudioPortConfig(in AudioPortConfigFw config);

    /* Get the HW synchronization source used for an audio session */
    int /* audio_hw_sync_t */ getAudioHwSyncForSession(int /* audio_session_t */ sessionId);

    /* Indicate JAVA services are ready (scheduling, power management ...) */
    oneway void systemReady();

    /* Indicate audio policy service is ready */
    oneway void audioPolicyReady();

    // Returns the number of frames per audio HAL buffer.
    long frameCountHAL(int /* audio_io_handle_t */ ioHandle);

    /* List available microphones and their characteristics */
    MicrophoneInfoFw[] getMicrophones();

    void setAudioHalPids(in int[] /* pid_t[] */ pids);

    // Set vibrators' information.
    // The value will be used to initialize HapticGenerator.
    void setVibratorInfos(in AudioVibratorInfo[] vibratorInfos);

    // Update secondary outputs.
    // This usually happens when there is a dynamic policy registered.
    void updateSecondaryOutputs(
            in TrackSecondaryOutputInfo[] trackSecondaryOutputInfos);

    AudioMMapPolicyInfo[] getMmapPolicyInfos(AudioMMapPolicyType policyType);

    int getAAudioMixerBurstCount();

    int getAAudioHardwareBurstMinUsec();

    void setDeviceConnectedState(in AudioPortFw devicePort, DeviceConnectedState state);

    // Used for tests only. Requires AIDL HAL to work.
    void setSimulateDeviceConnections(boolean enabled);

    /**
     * Requests a given latency mode (See AudioLatencyMode.aidl) on an output stream.
     * This can be used when some use case on a given mixer/stream can only be enabled
     * if a specific latency mode is selected on the audio path below the HAL.
     * For instance spatial audio with head tracking.
     * output is the I/O handle of the output stream for which the request is made.
     * latencyMode is the requested latency mode.
     */
     void setRequestedLatencyMode(int output, AudioLatencyMode latencyMode);

    /**
     * Queries the list of latency modes (See LatencyMode.aidl) supported by an output stream.
     * output is the I/O handle of the output stream to which the query applies.
     * returns the list of supported latency modes.
     */
    AudioLatencyMode[] getSupportedLatencyModes(int output);

    /**
     * Requests if the implementation supports controlling the latency modes
     * over the Bluetooth A2DP or LE Audio links. If it does,
     * setRequestedLatencyMode() and getSupportedLatencyModes() APIs can also be used
     * for streams routed to Bluetooth and not just for the spatializer output.
     */
     boolean supportsBluetoothVariableLatency();

    /**
     * Enables or disables the variable Bluetooth latency control mechanism in the
     * audio framework and the audio HAL. This does not apply to the latency mode control
     * on the spatializer output as this is a built-in feature.
     */
    void setBluetoothVariableLatencyEnabled(boolean enabled);

    /**
     * Indicates if the variable Bluetooth latency control mechanism is enabled or disabled.
     */
    boolean isBluetoothVariableLatencyEnabled();

    /**
     * Registers the sound dose callback and returns the interface for executing
     * sound dose methods on the audio server.
     */
    ISoundDose getSoundDoseInterface(in ISoundDoseCallback callback);

    /**
     * Invalidate all tracks with given port ids.
     */
    void invalidateTracks(in int[] /* audio_port_handle_t[] */ portIds);

    /**
     * Only implemented for AIDL. Provides the APM configuration which
     * used to be in the XML file.
     */
    AudioPolicyConfig getAudioPolicyConfig();

    /**
     * Get the attributes of the mix port when connecting to the given device port.
     */
    AudioPortFw getAudioMixPort(in AudioPortFw devicePort, in AudioPortFw mixPort);

    // When adding a new method, please review and update
    // IAudioFlinger.h AudioFlingerServerAdapter::Delegate::TransactionCode
    // AudioFlinger.cpp AudioFlinger::onTransactWrapper()
    // AudioFlinger.cpp IAUDIOFLINGER_BINDER_METHOD_MACRO_LIST
}
