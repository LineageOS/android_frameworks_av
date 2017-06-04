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

#include <binder/IServiceManager.h>
#include <media/PlayerBase.h>

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

namespace android {

//--------------------------------------------------------------------------------------------------
PlayerBase::PlayerBase() : BnPlayer(),
        mPanMultiplierL(1.0f), mPanMultiplierR(1.0f),
        mVolumeMultiplierL(1.0f), mVolumeMultiplierR(1.0f),
        mPIId(PLAYER_PIID_INVALID), mLastReportedEvent(PLAYER_STATE_UNKNOWN)
{
    ALOGD("PlayerBase::PlayerBase()");
    // use checkService() to avoid blocking if audio service is not up yet
    sp<IBinder> binder = defaultServiceManager()->checkService(String16("audio"));
    if (binder == 0) {
        ALOGE("PlayerBase(): binding to audio service failed, service up?");
    } else {
        mAudioManager = interface_cast<IAudioManager>(binder);
    }
}


PlayerBase::~PlayerBase() {
    ALOGD("PlayerBase::~PlayerBase()");
    baseDestroy();
}

void PlayerBase::init(player_type_t playerType, audio_usage_t usage) {
    if (mAudioManager == 0) {
                ALOGE("AudioPlayer realize: no audio service, player will not be registered");
    } else {
        mPIId = mAudioManager->trackPlayer(playerType, usage, AUDIO_CONTENT_TYPE_UNKNOWN, this);
    }
}

void PlayerBase::baseDestroy() {
    serviceReleasePlayer();
    if (mAudioManager != 0) {
        mAudioManager.clear();
    }
}

//------------------------------------------------------------------------------
void PlayerBase::servicePlayerEvent(player_state_t event) {
    if (mAudioManager != 0) {
        // only report state change
        Mutex::Autolock _l(mPlayerStateLock);
        if (event != mLastReportedEvent
                && mPIId != PLAYER_PIID_INVALID) {
            mLastReportedEvent = event;
            mAudioManager->playerEvent(mPIId, event);
        }
    }
}

void PlayerBase::serviceReleasePlayer() {
    if (mAudioManager != 0
            && mPIId != PLAYER_PIID_INVALID) {
        mAudioManager->releasePlayer(mPIId);
    }
}

//FIXME temporary method while some AudioTrack state is outside of this class
void PlayerBase::reportEvent(player_state_t event) {
    servicePlayerEvent(event);
}

status_t PlayerBase::startWithStatus() {
    status_t status = playerStart();
    if (status == NO_ERROR) {
        ALOGD("PlayerBase::start() from IPlayer");
        servicePlayerEvent(PLAYER_STATE_STARTED);
    } else {
        ALOGD("PlayerBase::start() no AudioTrack to start from IPlayer");
    }
    return status;
}

//------------------------------------------------------------------------------
// Implementation of IPlayer
void PlayerBase::start() {
    (void)startWithStatus();
}

void PlayerBase::pause() {
    if (playerPause() == NO_ERROR) {
        ALOGD("PlayerBase::pause() from IPlayer");
        servicePlayerEvent(PLAYER_STATE_PAUSED);
    } else {
        ALOGD("PlayerBase::pause() no AudioTrack to pause from IPlayer");
    }
}


void PlayerBase::stop() {
    if (playerStop() == NO_ERROR) {
        ALOGD("PlayerBase::stop() from IPlayer");
        servicePlayerEvent(PLAYER_STATE_STOPPED);
    } else {
        ALOGD("PlayerBase::stop() no AudioTrack to stop from IPlayer");
    }
}

void PlayerBase::setVolume(float vol) {
    {
        Mutex::Autolock _l(mSettingsLock);
        mVolumeMultiplierL = vol;
        mVolumeMultiplierR = vol;
    }
    if (playerSetVolume() == NO_ERROR) {
        ALOGD("PlayerBase::setVolume() from IPlayer");
    } else {
        ALOGD("PlayerBase::setVolume() no AudioTrack for volume control from IPlayer");
    }
}

void PlayerBase::setPan(float pan) {
    {
        Mutex::Autolock _l(mSettingsLock);
        pan = min(max(-1.0f, pan), 1.0f);
        if (pan >= 0.0f) {
            mPanMultiplierL = 1.0f - pan;
            mPanMultiplierR = 1.0f;
        } else {
            mPanMultiplierL = 1.0f;
            mPanMultiplierR = 1.0f + pan;
        }
    }
    if (playerSetVolume() == NO_ERROR) {
        ALOGD("PlayerBase::setPan() from IPlayer");
    } else {
        ALOGD("PlayerBase::setPan() no AudioTrack for volume control from IPlayer");
    }
}

void PlayerBase::setStartDelayMs(int32_t delayMs __unused) {
    ALOGW("setStartDelay() is not supported");
}

void PlayerBase::applyVolumeShaper(
        const sp<VolumeShaper::Configuration>& configuration  __unused,
        const sp<VolumeShaper::Operation>& operation __unused) {
    ALOGW("applyVolumeShaper() is not supported");
}

status_t PlayerBase::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    return BnPlayer::onTransact(code, data, reply, flags);
}

} // namespace android
