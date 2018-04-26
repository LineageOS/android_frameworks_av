/*
**
** Copyright 2014, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#ifndef INCLUDING_FROM_AUDIOFLINGER_H
    #error This header file should only be included from AudioFlinger.h
#endif

// PatchPanel is concealed within AudioFlinger, their lifetimes are the same.
class PatchPanel {
public:
    explicit PatchPanel(AudioFlinger* audioFlinger) : mAudioFlinger(*audioFlinger) {}

    /* List connected audio ports and their attributes */
    status_t listAudioPorts(unsigned int *num_ports,
                                    struct audio_port *ports);

    /* Get supported attributes for a given audio port */
    status_t getAudioPort(struct audio_port *port);

    /* Create a patch between several source and sink ports */
    status_t createAudioPatch(const struct audio_patch *patch,
                                       audio_patch_handle_t *handle);

    /* Release a patch */
    status_t releaseAudioPatch(audio_patch_handle_t handle);

    /* List connected audio devices and they attributes */
    status_t listAudioPatches(unsigned int *num_patches,
                                      struct audio_patch *patches);

private:
    class Patch {
    public:
        explicit Patch(const struct audio_patch &patch) : mAudioPatch(patch) {}

        status_t createConnections(PatchPanel *panel);
        void clearConnections(PatchPanel *panel);

        // Note that audio_patch::id is only unique within a HAL module
        struct audio_patch              mAudioPatch;
        // handle for audio HAL patch handle present only when the audio HAL version is >= 3.0
        audio_patch_handle_t            mHalHandle = AUDIO_PATCH_HANDLE_NONE;
        // below members are used by a software audio patch connecting a source device from a
        // given audio HW module to a sink device on an other audio HW module.
        // the objects are created by createConnections() and released by clearConnections()
        // playback thread is created if no existing playback thread can be used
        sp<PlaybackThread>              mPlaybackThread;
        sp<PlaybackThread::PatchTrack>  mPatchTrack;
        sp<RecordThread>                mRecordThread;
        sp<RecordThread::PatchRecord>   mPatchRecord;
        // handle for audio patch connecting source device to record thread input.
        audio_patch_handle_t            mRecordPatchHandle = AUDIO_PATCH_HANDLE_NONE;
        // handle for audio patch connecting playback thread output to sink device
        audio_patch_handle_t            mPlaybackPatchHandle = AUDIO_PATCH_HANDLE_NONE;

    };

    AudioFlinger &mAudioFlinger;
    std::map<audio_patch_handle_t, Patch> mPatches;
};
