/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef __ANDROID_TRACK_PLAYER_BASE_H__
#define __ANDROID_TRACK_PLAYER_BASE_H__

#include <media/AudioTrack.h>
#include <media/PlayerBase.h>
#include <mediautils/Synchronization.h>

namespace android {

class TrackPlayerBase : public PlayerBase
{
public:
    explicit TrackPlayerBase();
    ~TrackPlayerBase() override;

    void init(const sp<AudioTrack>& pat, const sp<AudioTrack::IAudioTrackCallback>& callback,
              player_type_t playerType, audio_usage_t usage, audio_session_t sessionId);
    void destroy() override;

    //IPlayer implementation
    binder::Status applyVolumeShaper(
            const media::VolumeShaperConfiguration& configuration,
            const media::VolumeShaperOperation& operation) override;

    sp<AudioTrack> getAudioTrack() { return mAudioTrack.load(); }

    void clearAudioTrack() { mAudioTrack.store(nullptr); }

    void setPlayerVolume(float vl, float vr) EXCLUDES(mSettingsMutex);

protected:

    //PlayerBase virtuals
    status_t playerStart() override;
    status_t playerPause() override;
    status_t playerStop() override;
    status_t playerSetVolume() override;

private:
            void doDestroy();
    status_t doSetVolume() EXCLUDES(mSettingsMutex);

            class SelfAudioDeviceCallback : public AudioSystem::AudioDeviceCallback {
            public:
                SelfAudioDeviceCallback(PlayerBase& self);
                virtual void onAudioDeviceUpdate(audio_io_handle_t audioIo,
                                                 const DeviceIdVector& deviceIds);
            private:
                virtual ~SelfAudioDeviceCallback();
                PlayerBase& mSelf;
            };

    // volume coming from the player volume API
    float mPlayerVolumeL GUARDED_BY(mSettingsMutex);
    float mPlayerVolumeR GUARDED_BY(mSettingsMutex);
    sp<AudioTrack::IAudioTrackCallback> mCallbackHandle;   // set in init()
    sp<SelfAudioDeviceCallback> mSelfAudioDeviceCallback;  // set in init() cleared in doDestroy()
    mediautils::atomic_sp<AudioTrack> mAudioTrack;
};

} // namespace android

#endif /* __ANDROID_TRACK_PLAYER_BASE_H__ */
