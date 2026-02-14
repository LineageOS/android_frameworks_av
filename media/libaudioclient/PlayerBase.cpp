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
#include <media/AidlConversionUtil.h>
#include <media/PlayerBase.h>

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

namespace android {
using aidl_utils::binderStatusFromStatusT;
using media::VolumeShaperConfiguration;
using media::VolumeShaperOperation;

static sp<IAudioManager> getAudioManager() {
    // use checkService() to avoid blocking if audio service is not up yet
    const sp<IBinder> binder = defaultServiceManager()->checkService(String16("audio"));
    if (!binder) {
        ALOGE("%s: cannot access IAudioManager", __func__);
        return {};
    } else {
        return interface_cast<IAudioManager>(binder);
    }
}

//--------------------------------------------------------------------------------------------------
PlayerBase::PlayerBase() : BnPlayer(),
    mAudioManager{getAudioManager()},
        mPanMultiplierL(1.0f), mPanMultiplierR(1.0f),
        mVolumeMultiplierL(1.0f), mVolumeMultiplierR(1.0f),
        mPIId(PLAYER_PIID_INVALID), mLastReportedEvent(PLAYER_STATE_UNKNOWN)
{
    ALOGD("PlayerBase::PlayerBase()");
}

PlayerBase::~PlayerBase() {
    ALOGD("PlayerBase::~PlayerBase()");
    baseDestroy();
}

void PlayerBase::init(player_type_t playerType, audio_usage_t usage, audio_session_t sessionId) {
    if (!mAudioManager) {
                ALOGE("AudioPlayer realize: no audio service, player will not be registered");
    } else {
        mPIId = mAudioManager->trackPlayer(playerType, usage, AUDIO_CONTENT_TYPE_UNKNOWN, this,
                sessionId);
    }
}

void PlayerBase::triggerPortIdUpdate(audio_port_handle_t portId) const {
    if (!mAudioManager) {
        ALOGE("%s: no audio service, player %d will not update portId %d",
              __func__,
              mPIId,
              portId);
        return;
    }

    if (mPIId != PLAYER_PIID_INVALID && portId != AUDIO_PORT_HANDLE_NONE) {
        mAudioManager->playerEvent(mPIId, android::PLAYER_UPDATE_PORT_ID, { portId });
    }
}

void PlayerBase::baseDestroy() {
    serviceReleasePlayer();
}

//------------------------------------------------------------------------------
void PlayerBase::servicePlayerEvent(player_state_t event, const DeviceIdVector& deviceIds) {
    if (mAudioManager) {
        bool changed = false;
        {
            std::lock_guard _l(mDeviceIdMutex);
            changed = !areDeviceIdsEqual(deviceIds, mLastReportedDeviceIds);
            mLastReportedDeviceIds = deviceIds;
        }

        {
            std::lock_guard _l(mPlayerStateMutex);
            // PLAYER_UPDATE_DEVICE_ID is not saved as an actual state, instead it is used to update
            // device ID only.
            if ((event != PLAYER_UPDATE_DEVICE_ID) && (event != mLastReportedEvent)) {
                mLastReportedEvent = event;
                changed = true;
            }
        }
        if (changed && (mPIId != PLAYER_PIID_INVALID)) {
            mAudioManager->playerEvent(mPIId, event, deviceIds);
        }
    }
}

void PlayerBase::serviceReleasePlayer() {
    if (mAudioManager
            && mPIId != PLAYER_PIID_INVALID) {
        mAudioManager->releasePlayer(mPIId);
    }
}

//FIXME temporary method while some player state is outside of this class
void PlayerBase::reportEvent(player_state_t event, const DeviceIdVector& deviceIds) {
    servicePlayerEvent(event, deviceIds);
}

void PlayerBase::baseUpdateDeviceIds(const DeviceIdVector& deviceIds) {
    servicePlayerEvent(PLAYER_UPDATE_DEVICE_ID, deviceIds);
}

status_t PlayerBase::startWithStatus(const DeviceIdVector& deviceIds) {
    status_t status = playerStart();
    if (status == NO_ERROR) {
        servicePlayerEvent(PLAYER_STATE_STARTED, deviceIds);
    } else {
        ALOGW("PlayerBase::start() error %d", status);
    }
    return status;
}

status_t PlayerBase::pauseWithStatus() {
    status_t status = playerPause();
    if (status == NO_ERROR) {
        servicePlayerEvent(PLAYER_STATE_PAUSED, {});
    } else {
        ALOGW("PlayerBase::pause() error %d", status);
    }
    return status;
}

status_t PlayerBase::stopWithStatus() {
    status_t status = playerStop();

    if (status == NO_ERROR) {
        servicePlayerEvent(PLAYER_STATE_STOPPED, {});
    } else {
        ALOGW("PlayerBase::stop() error %d", status);
    }
    return status;
}

//------------------------------------------------------------------------------
// Implementation of IPlayer
binder::Status PlayerBase::start() {
    ALOGD("PlayerBase::start() from IPlayer");
    DeviceIdVector deviceIds;
    {
        std::lock_guard _l(mDeviceIdMutex);
        deviceIds = mLastReportedDeviceIds;
    }
    (void)startWithStatus(deviceIds);
    return binder::Status::ok();
}

binder::Status PlayerBase::pause() {
    ALOGD("PlayerBase::pause() from IPlayer");
    (void)pauseWithStatus();
    return binder::Status::ok();
}


binder::Status PlayerBase::stop() {
    ALOGD("PlayerBase::stop() from IPlayer");
    (void)stopWithStatus();
    return binder::Status::ok();
}

binder::Status PlayerBase::setVolume(float vol) {
    ALOGD("PlayerBase::setVolume() from IPlayer");
    {
        std::lock_guard _l(mSettingsMutex);
        mVolumeMultiplierL = vol;
        mVolumeMultiplierR = vol;
    }
    status_t status = playerSetVolume();
    if (status != NO_ERROR) {
        ALOGW("PlayerBase::setVolume() error %d", status);
    }
    return binderStatusFromStatusT(status);
}

binder::Status PlayerBase::setPan(float pan) {
    ALOGD("PlayerBase::setPan() from IPlayer");
    {
        std::lock_guard _l(mSettingsMutex);
        pan = min(max(-1.0f, pan), 1.0f);
        if (pan >= 0.0f) {
            mPanMultiplierL = 1.0f - pan;
            mPanMultiplierR = 1.0f;
        } else {
            mPanMultiplierL = 1.0f;
            mPanMultiplierR = 1.0f + pan;
        }
    }
    status_t status = playerSetVolume();
    if (status != NO_ERROR) {
        ALOGW("PlayerBase::setPan() error %d", status);
    }
    return binderStatusFromStatusT(status);
}

binder::Status PlayerBase::setStartDelayMs(int32_t delayMs __unused) {
    ALOGW("setStartDelay() is not supported");
    return binder::Status::ok();
}

binder::Status PlayerBase::applyVolumeShaper(
            const VolumeShaperConfiguration& configuration __unused,
            const VolumeShaperOperation& operation __unused) {
    ALOGW("applyVolumeShaper() is not supported");
    return binder::Status::ok();
}

} // namespace android
