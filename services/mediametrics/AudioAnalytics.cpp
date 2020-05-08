/*
 * Copyright (C) 2019 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "AudioAnalytics"
#include <utils/Log.h>

#include "AudioAnalytics.h"
#include "MediaMetricsService.h"  // package info
#include <audio_utils/clock.h>    // clock conversions
#include <statslog.h>             // statsd

// Enable for testing of delivery to statsd
// #define STATSD

namespace android::mediametrics {

AudioAnalytics::AudioAnalytics()
{
    ALOGD("%s", __func__);

    // Add action to save AnalyticsState if audioserver is restarted.
    // This triggers on an item of "audio.flinger"
    // with a property "event" set to "AudioFlinger" (the constructor).
    mActions.addAction(
        AMEDIAMETRICS_KEY_AUDIO_FLINGER "." AMEDIAMETRICS_PROP_EVENT,
        std::string(AMEDIAMETRICS_PROP_EVENT_VALUE_CTOR),
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                ALOGW("(key=%s) Audioflinger constructor event detected", item->getKey().c_str());
                mPreviousAnalyticsState.set(std::make_shared<AnalyticsState>(
                        *mAnalyticsState.get()));
                // Note: get returns shared_ptr temp, whose lifetime is extended
                // to end of full expression.
                mAnalyticsState->clear();  // TODO: filter the analytics state.
                // Perhaps report this.
            }));

    // Check underruns
    mActions.addAction(
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_THREAD "*." AMEDIAMETRICS_PROP_EVENT,
        std::string(AMEDIAMETRICS_PROP_EVENT_VALUE_UNDERRUN),
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                std::string threadId = item->getKey().substr(
                        sizeof(AMEDIAMETRICS_KEY_PREFIX_AUDIO_THREAD) - 1);
                std::string outputDevices;
                mAnalyticsState->timeMachine().get(
                        item->getKey(), AMEDIAMETRICS_PROP_OUTPUTDEVICES, &outputDevices);
                ALOGD("(key=%s) Thread underrun event detected on io handle:%s device:%s",
                        item->getKey().c_str(), threadId.c_str(), outputDevices.c_str());
                if (outputDevices.find("AUDIO_DEVICE_OUT_BLUETOOTH") != std::string::npos) {
                    // report this for Bluetooth
                }
            }));

    // Check latencies, playback and startup
    mActions.addAction(
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_TRACK "*." AMEDIAMETRICS_PROP_LATENCYMS,
        std::monostate{},  // accept any value
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                double latencyMs{};
                double startupMs{};
                if (!item->get(AMEDIAMETRICS_PROP_LATENCYMS, &latencyMs)
                        || !item->get(AMEDIAMETRICS_PROP_STARTUPMS, &startupMs)) return;

                std::string trackId = item->getKey().substr(
                        sizeof(AMEDIAMETRICS_KEY_PREFIX_AUDIO_TRACK) - 1);
                std::string thread = getThreadFromTrack(item->getKey());
                std::string outputDevices;
                mAnalyticsState->timeMachine().get(
                        thread, AMEDIAMETRICS_PROP_OUTPUTDEVICES, &outputDevices);
                ALOGD("(key=%s) Track latencyMs:%lf startupMs:%lf detected on port:%s device:%s",
                        item->getKey().c_str(), latencyMs, startupMs,
                        trackId.c_str(), outputDevices.c_str());
                if (outputDevices.find("AUDIO_DEVICE_OUT_BLUETOOTH") != std::string::npos) {
                    // report this for Bluetooth
                }
            }));

    // Handle device use thread statistics
    mActions.addAction(
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_THREAD "*." AMEDIAMETRICS_PROP_EVENT,
        std::string(AMEDIAMETRICS_PROP_EVENT_VALUE_ENDAUDIOINTERVALGROUP),
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                mDeviceUse.endAudioIntervalGroup(item, false /* isTrack */);
            }));

    // Handle device use track statistics
    mActions.addAction(
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_TRACK "*." AMEDIAMETRICS_PROP_EVENT,
        std::string(AMEDIAMETRICS_PROP_EVENT_VALUE_ENDAUDIOINTERVALGROUP),
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                mDeviceUse.endAudioIntervalGroup(item, true /* isTrack */);
            }));

    // Handle device routing statistics

    // We track connections (not disconnections) for the time to connect.
    // TODO: consider BT requests in their A2dp service
    // AudioManager.setBluetoothA2dpDeviceConnectionStateSuppressNoisyIntent
    // AudioDeviceBroker.postBluetoothA2dpDeviceConnectionStateSuppressNoisyIntent
    // AudioDeviceBroker.postA2dpActiveDeviceChange
    mActions.addAction(
        "audio.device.a2dp.state",
        std::string("connected"),
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                mDeviceConnection.a2dpConnected(item);
            }));
    // If audio is active, we expect to see a createAudioPatch after the device is connected.
    mActions.addAction(
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_THREAD "*." AMEDIAMETRICS_PROP_EVENT,
        std::string("createAudioPatch"),
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                mDeviceConnection.createPatch(item);
            }));

    // Handle power usage
    mActions.addAction(
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_TRACK "*." AMEDIAMETRICS_PROP_EVENT,
        std::string(AMEDIAMETRICS_PROP_EVENT_VALUE_ENDAUDIOINTERVALGROUP),
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                mAudioPowerUsage.checkTrackRecord(item, true /* isTrack */);
            }));

    mActions.addAction(
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_RECORD "*." AMEDIAMETRICS_PROP_EVENT,
        std::string(AMEDIAMETRICS_PROP_EVENT_VALUE_ENDAUDIOINTERVALGROUP),
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                mAudioPowerUsage.checkTrackRecord(item, false /* isTrack */);
            }));

    mActions.addAction(
        AMEDIAMETRICS_KEY_AUDIO_FLINGER "." AMEDIAMETRICS_PROP_EVENT,
        std::string(AMEDIAMETRICS_PROP_EVENT_VALUE_SETMODE),
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                // ALOGD("(key=%s) Audioflinger setMode", item->getKey().c_str());
                mAudioPowerUsage.checkMode(item);
            }));

    mActions.addAction(
        AMEDIAMETRICS_KEY_AUDIO_FLINGER "." AMEDIAMETRICS_PROP_EVENT,
        std::string(AMEDIAMETRICS_PROP_EVENT_VALUE_SETVOICEVOLUME),
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                // ALOGD("(key=%s) Audioflinger setVoiceVolume", item->getKey().c_str());
                mAudioPowerUsage.checkVoiceVolume(item);
            }));

    mActions.addAction(
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_THREAD "*." AMEDIAMETRICS_PROP_EVENT,
        std::string("createAudioPatch"),
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                mAudioPowerUsage.checkCreatePatch(item);
            }));
}

AudioAnalytics::~AudioAnalytics()
{
    ALOGD("%s", __func__);
    mTimedAction.quit(); // ensure no deferred access during destructor.
}

status_t AudioAnalytics::submit(
        const std::shared_ptr<const mediametrics::Item>& item, bool isTrusted)
{
    if (!startsWith(item->getKey(), AMEDIAMETRICS_KEY_PREFIX_AUDIO)) return BAD_VALUE;
    status_t status = mAnalyticsState->submit(item, isTrusted);
    if (status != NO_ERROR) return status;  // may not be permitted.

    // Only if the item was successfully submitted (permission)
    // do we check triggered actions.
    checkActions(item);
    return NO_ERROR;
}

std::pair<std::string, int32_t> AudioAnalytics::dump(
        int32_t lines, int64_t sinceNs, const char *prefix) const
{
    std::stringstream ss;
    int32_t ll = lines;

    if (ll > 0) {
        auto [s, l] = mAnalyticsState->dump(ll, sinceNs, prefix);
        ss << s;
        ll -= l;
    }
    if (ll > 0) {
        ss << "Prior audioserver state:\n";
        --ll;
    }
    if (ll > 0) {
        auto [s, l] = mPreviousAnalyticsState->dump(ll, sinceNs, prefix);
        ss << s;
        ll -= l;
    }

    if (ll > 0 && prefix == nullptr) {
        auto [s, l] = mAudioPowerUsage.dump(ll);
        ss << s;
        ll -= l;
    }
    return { ss.str(), lines - ll };
}

void AudioAnalytics::checkActions(const std::shared_ptr<const mediametrics::Item>& item)
{
    auto actions = mActions.getActionsForItem(item); // internally locked.
    // Execute actions with no lock held.
    for (const auto& action : actions) {
        (*action)(item);
    }
}

// HELPER METHODS

std::string AudioAnalytics::getThreadFromTrack(const std::string& track) const
{
    int32_t threadId_int32{};
    if (mAnalyticsState->timeMachine().get(
            track, AMEDIAMETRICS_PROP_THREADID, &threadId_int32) != NO_ERROR) {
        return {};
    }
    return std::string(AMEDIAMETRICS_KEY_PREFIX_AUDIO_THREAD) + std::to_string(threadId_int32);
}

// DeviceUse helper class.
void AudioAnalytics::DeviceUse::endAudioIntervalGroup(
       const std::shared_ptr<const android::mediametrics::Item> &item, bool isTrack) const {
    const std::string& key = item->getKey();
    const std::string id = key.substr(
            (isTrack ? sizeof(AMEDIAMETRICS_KEY_PREFIX_AUDIO_TRACK)
            : sizeof(AMEDIAMETRICS_KEY_PREFIX_AUDIO_THREAD))
             - 1);
    // deliver statistics
    int64_t deviceTimeNs = 0;
    mAudioAnalytics.mAnalyticsState->timeMachine().get(
            key, AMEDIAMETRICS_PROP_DEVICETIMENS, &deviceTimeNs);
    std::string encoding;
    mAudioAnalytics.mAnalyticsState->timeMachine().get(
            key, AMEDIAMETRICS_PROP_ENCODING, &encoding);
    int32_t frameCount = 0;
    mAudioAnalytics.mAnalyticsState->timeMachine().get(
            key, AMEDIAMETRICS_PROP_FRAMECOUNT, &frameCount);
    int32_t intervalCount = 0;
    mAudioAnalytics.mAnalyticsState->timeMachine().get(
            key, AMEDIAMETRICS_PROP_INTERVALCOUNT, &intervalCount);
    std::string outputDevices;
    mAudioAnalytics.mAnalyticsState->timeMachine().get(
            key, AMEDIAMETRICS_PROP_OUTPUTDEVICES, &outputDevices);
    int32_t sampleRate = 0;
    mAudioAnalytics.mAnalyticsState->timeMachine().get(
            key, AMEDIAMETRICS_PROP_SAMPLERATE, &sampleRate);
    int32_t underrun = 0;
    mAudioAnalytics.mAnalyticsState->timeMachine().get(
            key, AMEDIAMETRICS_PROP_UNDERRUN, &underrun);

    // Get connected device name if from bluetooth.
    bool isBluetooth = false;
    std::string name;
    if (outputDevices.find("AUDIO_DEVICE_OUT_BLUETOOTH") != std::string::npos) {
        isBluetooth = true;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
            "audio.device.bt_a2dp", AMEDIAMETRICS_PROP_NAME, &name);
    }

    // We may have several devices.  We only list the first device.
    // TODO: consider whether we should list all the devices separated by |
    std::string firstDevice = "unknown";
    auto devaddrvec = MediaMetricsService::getDeviceAddressPairs(outputDevices);
    if (devaddrvec.size() != 0) {
        firstDevice = devaddrvec[0].first;
        // DO NOT show the address.
    }

    if (isTrack) {
        std::string callerName;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_CALLERNAME, &callerName);
        std::string contentType;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_CONTENTTYPE, &contentType);
        double deviceLatencyMs = 0.;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_DEVICELATENCYMS, &deviceLatencyMs);
        double deviceStartupMs = 0.;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_DEVICESTARTUPMS, &deviceStartupMs);
        double deviceVolume = 0.;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_DEVICEVOLUME, &deviceVolume);
        std::string packageName;
        int64_t versionCode = 0;
        int32_t uid = -1;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_ALLOWUID, &uid);
        if (uid != -1) {
            std::tie(packageName, versionCode) =
                    MediaMetricsService::getSanitizedPackageNameAndVersionCode(uid);
        }
        double playbackPitch = 0.;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_PLAYBACK_PITCH, &playbackPitch);
        double playbackSpeed = 0.;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_PLAYBACK_SPEED, &playbackSpeed);
        int32_t selectedDeviceId = 0;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_SELECTEDDEVICEID, &selectedDeviceId);

        std::string usage;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_USAGE, &usage);

        ALOGD("(key=%s) id:%s endAudioIntervalGroup device:%s name:%s "
                 "deviceTimeNs:%lld encoding:%s frameCount:%d intervalCount:%d "
                 "sampleRate:%d underrun:%d "
                 "callerName:%s contentType:%s "
                 "deviceLatencyMs:%lf deviceStartupMs:%lf deviceVolume:%lf"
                 "packageName:%s playbackPitch:%lf playbackSpeed:%lf "
                 "selectedDevceId:%d usage:%s",
                key.c_str(), id.c_str(), firstDevice.c_str(), name.c_str(),
                (long long)deviceTimeNs, encoding.c_str(), frameCount, intervalCount,
                sampleRate, underrun,
                callerName.c_str(), contentType.c_str(),
                deviceLatencyMs, deviceStartupMs, deviceVolume,
                packageName.c_str(), playbackPitch, playbackSpeed,
                selectedDeviceId, usage.c_str());
#ifdef STATSD
        if (mAudioAnalytics.mDeliverStatistics) {
            (void)android::util::stats_write(
                    android::util::MEDIAMETRICS_AUDIOTRACKDEVICEUSAGE_REPORTED
                    /* timestamp, */
                    /* mediaApexVersion, */
                    , firstDevice.c_str()
                    , name.c_str()
                    , deviceTimeNs
                    , encoding.c_str()
                    , frameCount
                    , intervalCount
                    , sampleRate
                    , underrun

                    , packageName.c_str()
                    , (float)deviceLatencyMs
                    , (float)deviceStartupMs
                    , (float)deviceVolume
                    , selectedDeviceId
                    , usage.c_str()
                    , contentType.c_str()
                    , callerName.c_str()
                    );
        }
#endif
    } else {

        std::string flags;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_FLAGS, &flags);

        ALOGD("(key=%s) id:%s endAudioIntervalGroup device:%s name:%s "
                 "deviceTimeNs:%lld encoding:%s frameCount:%d intervalCount:%d "
                 "sampleRate:%d underrun:%d "
                 "flags:%s",
                key.c_str(), id.c_str(), firstDevice.c_str(), name.c_str(),
                (long long)deviceTimeNs, encoding.c_str(), frameCount, intervalCount,
                sampleRate, underrun,
                flags.c_str());
#ifdef STATSD
        if (mAudioAnalytics.mDeliverStatistics) {
            (void)android::util::stats_write(
                android::util::MEDIAMETRICS_AUDIOTHREADDEVICEUSAGE_REPORTED
                /* timestamp, */
                /* mediaApexVersion, */
                , firstDevice.c_str()
                , name.c_str()
                , deviceTimeNs
                , encoding.c_str()
                , frameCount
                , intervalCount
                , sampleRate
                , underrun
            );
        }
#endif
    }

    // Report this as needed.
    if (isBluetooth) {
        // report this for Bluetooth
    }
}

// DeviceConnection helper class.
void AudioAnalytics::DeviceConnection::a2dpConnected(
       const std::shared_ptr<const android::mediametrics::Item> &item) {
    const std::string& key = item->getKey();

    const int64_t connectedAtNs = item->getTimestamp();
    {
        std::lock_guard l(mLock);
        mA2dpTimeConnectedNs = connectedAtNs;
         ++mA2dpConnectedAttempts;
    }
    std::string name;
    item->get(AMEDIAMETRICS_PROP_NAME, &name);
    ALOGD("(key=%s) a2dp connected device:%s "
             "connectedAtNs:%lld",
            key.c_str(), name.c_str(),
            (long long)connectedAtNs);
    // Note - we need to be able to cancel a timed event
    mAudioAnalytics.mTimedAction.postIn(std::chrono::seconds(5), [this](){ expire(); });
    // This sets the time we were connected.  Now we look for the delta in the future.
}

void AudioAnalytics::DeviceConnection::createPatch(
       const std::shared_ptr<const android::mediametrics::Item> &item) {
    std::lock_guard l(mLock);
    if (mA2dpTimeConnectedNs == 0) return; // ignore
    const std::string& key = item->getKey();
    std::string outputDevices;
    item->get(AMEDIAMETRICS_PROP_OUTPUTDEVICES, &outputDevices);
    if (outputDevices.find("AUDIO_DEVICE_OUT_BLUETOOTH") != std::string::npos) {
        // TODO compare address
        const int64_t timeDiff = item->getTimestamp() - mA2dpTimeConnectedNs;
        ALOGD("(key=%s) A2DP device connection time: %lld", key.c_str(), (long long)timeDiff);
        mA2dpTimeConnectedNs = 0; // reset counter.
        ++mA2dpConnectedSuccesses;
    }
}

void AudioAnalytics::DeviceConnection::expire() {
    std::lock_guard l(mLock);
    if (mA2dpTimeConnectedNs == 0) return; // ignore

    // An expiration may occur because there is no audio playing.
    // TODO: disambiguate this case.
    ALOGD("A2DP device connection expired");
    ++mA2dpConnectedFailures; // this is not a true failure.
    mA2dpTimeConnectedNs = 0;
}

} // namespace android
