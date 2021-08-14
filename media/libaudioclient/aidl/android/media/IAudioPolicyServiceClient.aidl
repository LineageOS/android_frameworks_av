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

import android.media.AudioConfigBase;
import android.media.AudioSourceType;
import android.media.EffectDescriptor;
import android.media.RecordClientInfo;

/**
 * {@hide}
 */
oneway interface IAudioPolicyServiceClient {
    /** Notifies a change of volume group. */
    void onAudioVolumeGroupChanged(int /* volume_group_t */ group,
                                   int flags);
    /** Notifies a change of audio port configuration. */
    void onAudioPortListUpdate();
    /** Notifies a change of audio patch configuration. */
    void onAudioPatchListUpdate();
    /** Notifies a change in the mixing state of a specific mix in a dynamic audio policy. */
    void onDynamicPolicyMixStateUpdate(@utf8InCpp String regId,
                                       int state);
    /** Notifies a change of audio recording configuration. */
    void onRecordingConfigurationUpdate(int event,
                                        in RecordClientInfo clientInfo,
                                        in AudioConfigBase clientConfig,
                                        in EffectDescriptor[] clientEffects,
                                        in AudioConfigBase deviceConfig,
                                        in EffectDescriptor[] effects,
                                        int /* audio_patch_handle_t */ patchHandle,
                                        AudioSourceType source);
     /** Notifies a change of audio routing */
     void onRoutingUpdated();
}
