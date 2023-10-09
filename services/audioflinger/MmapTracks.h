/*
**
** Copyright 2017, The Android Open Source Project
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

#pragma once

#include "TrackBase.h"

#include <android/content/AttributionSourceState.h>

namespace android {

// playback track
class MmapTrack : public TrackBase, public IAfMmapTrack {
public:
    MmapTrack(IAfThreadBase* thread,
                            const audio_attributes_t& attr,
                            uint32_t sampleRate,
                            audio_format_t format,
                            audio_channel_mask_t channelMask,
                            audio_session_t sessionId,
                            bool isOut,
                            const android::content::AttributionSourceState& attributionSource,
                            pid_t creatorPid,
                            audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE);
    ~MmapTrack() override;

    status_t initCheck() const final;
    status_t start(
            AudioSystem::sync_event_t event, audio_session_t triggerSession) final;
    void stop() final;
    bool isFastTrack() const final { return false; }
    bool isDirect() const final { return true; }

    void appendDumpHeader(String8& result) const final;
    void appendDump(String8& result, bool active) const final;

                        // protected by MMapThread::mLock
    void setSilenced_l(bool silenced) final { mSilenced = silenced;
                                                       mSilencedNotified = false;}
                        // protected by MMapThread::mLock
    bool isSilenced_l() const final { return mSilenced; }
                        // protected by MMapThread::mLock
    bool getAndSetSilencedNotified_l() final { bool silencedNotified = mSilencedNotified;
                                                        mSilencedNotified = true;
                                                        return silencedNotified; }

    /**
     * Updates the mute state and notifies the audio service. Call this only when holding player
     * thread lock.
     */
    void processMuteEvent_l(const sp<IAudioManager>& audioManager,
                            mute_state_t muteState)
                            /* REQUIRES(MmapPlaybackThread::mLock) */ final;
private:
    DISALLOW_COPY_AND_ASSIGN(MmapTrack);

    // AudioBufferProvider interface
    virtual status_t getNextBuffer(AudioBufferProvider::Buffer* buffer);
    // releaseBuffer() not overridden

    // ExtendedAudioBufferProvider interface
    size_t framesReady() const final;
    int64_t framesReleased() const final;
    void onTimestamp(const ExtendedTimestamp &timestamp) final;

    const pid_t mPid;
    bool  mSilenced;            // protected by MMapThread::mLock
    bool  mSilencedNotified;    // protected by MMapThread::mLock

    // TODO: replace PersistableBundle with own struct
    // access these two variables only when holding player thread lock.
    std::unique_ptr<os::PersistableBundle> mMuteEventExtras
            /* GUARDED_BY(MmapPlaybackThread::mLock) */;
    mute_state_t mMuteState
            /* GUARDED_BY(MmapPlaybackThread::mLock) */;
};  // end of Track

} // namespace android