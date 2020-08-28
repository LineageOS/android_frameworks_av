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
#include <android-base/logging.h>
#include <utils/Log.h>

#include "AudioAnalytics.h"

#include <audio_utils/clock.h>    // clock conversions
#include <cutils/properties.h>
#include <statslog.h>             // statsd

#include "AudioTypes.h"           // string to int conversions
#include "MediaMetricsService.h"  // package info
#include "StringUtils.h"

#define PROP_AUDIO_ANALYTICS_CLOUD_ENABLED "persist.audio.analytics.cloud.enabled"

namespace android::mediametrics {

// Enable for testing of delivery to statsd. Caution if this is enabled, all protos MUST exist.
#define STATSD_ENABLE

#ifdef STATSD_ENABLE
#define CONDITION(INT_VALUE) (INT_VALUE)  // allow value
#else
#define CONDITION(INT_VALUE) (int(0))     // mask value since the proto may not be defined yet.
#endif

// Maximum length of a device name.
// static constexpr size_t STATSD_DEVICE_NAME_MAX_LENGTH = 32; // unused since we suppress

// Transmit Enums to statsd in integer or strings  (this must match the atoms.proto)
static constexpr bool STATSD_USE_INT_FOR_ENUM = false;

// derive types based on integer or strings.
using short_enum_type_t = std::conditional_t<STATSD_USE_INT_FOR_ENUM, int32_t, std::string>;
using long_enum_type_t = std::conditional_t<STATSD_USE_INT_FOR_ENUM, int64_t, std::string>;

// Convert std::string to char *
template <typename T>
auto ENUM_EXTRACT(const T& x) {
    if constexpr (std::is_same_v<std::decay_t<T>, std::string>) {
        return x.c_str();
    } else {
        return x;
    }
}

static constexpr const auto LOG_LEVEL = android::base::VERBOSE;

static constexpr int PREVIOUS_STATE_EXPIRE_SEC = 60 * 60; // 1 hour.

static constexpr const char * SUPPRESSED = "SUPPRESSED";

/*
 * For logging purposes, we list all of the MediaMetrics atom fields,
 * which can then be associated with consecutive arguments to the statsd write.
 */

static constexpr const char * const AudioRecordDeviceUsageFields[] = {
    "mediametrics_audiorecorddeviceusage_reported", // proto number
    "devices",
    "device_names",
    "device_time_nanos",
    "encoding",
    "frame_count",
    "interval_count",
    "sample_rate",
    "flags",
    "package_name",
    "selected_device_id",
    "caller",
    "source",
};

static constexpr const char * const AudioThreadDeviceUsageFields[] = {
    "mediametrics_audiothreaddeviceusage_reported",
    "devices",
    "device_names",
    "device_time_nanos",
    "encoding",
    "frame_count",
    "interval_count",
    "sample_rate",
    "flags",
    "xruns",
    "type",
};

static constexpr const char * const AudioTrackDeviceUsageFields[] = {
    "mediametrics_audiotrackdeviceusage_reported",
    "devices",
    "device_names",
    "device_time_nanos",
    "encoding",
    "frame_count",
    "interval_count",
    "sample_rate",
    "flags",
    "xruns",
    "package_name",
    "device_latency_millis",
    "device_startup_millis",
    "device_volume",
    "selected_device_id",
    "stream_type",
    "usage",
    "content_type",
    "caller",
    "traits",
};

static constexpr const char * const AudioDeviceConnectionFields[] = {
    "mediametrics_audiodeviceconnection_reported",
    "input_devices",
    "output_devices",
    "device_names",
    "result",
    "time_to_connect_millis",
    "connection_count",
};

/**
 * sendToStatsd is a helper method that sends the arguments to statsd
 * and returns a pair { result, summary_string }.
 */
template <size_t N, typename ...Types>
std::pair<int, std::string> sendToStatsd(const char * const (& fields)[N], Types ... args)
{
    int result = 0;
    std::stringstream ss;

#ifdef STATSD_ENABLE
    result = android::util::stats_write(args...);
    ss << "result:" << result;
#endif
    ss << " { ";
    stringutils::fieldPrint(ss, fields, args...);
    ss << "}";
    return { result, ss.str() };
}

AudioAnalytics::AudioAnalytics()
    : mDeliverStatistics(property_get_bool(PROP_AUDIO_ANALYTICS_CLOUD_ENABLED, true))
{
    SetMinimumLogSeverity(android::base::DEBUG); // for LOG().
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

                // Set up a timer to expire the previous audio state to save space.
                // Use the transaction log size as a cookie to see if it is the
                // same as before.  A benign race is possible where a state is cleared early.
                const size_t size = mPreviousAnalyticsState->transactionLog().size();
                mTimedAction.postIn(
                        std::chrono::seconds(PREVIOUS_STATE_EXPIRE_SEC), [this, size](){
                    if (mPreviousAnalyticsState->transactionLog().size() == size) {
                        ALOGD("expiring previous audio state after %d seconds.",
                                PREVIOUS_STATE_EXPIRE_SEC);
                        mPreviousAnalyticsState->clear();  // removes data from the state.
                    }
                });
            }));

    // Handle device use record statistics
    mActions.addAction(
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_RECORD "*." AMEDIAMETRICS_PROP_EVENT,
        std::string(AMEDIAMETRICS_PROP_EVENT_VALUE_ENDAUDIOINTERVALGROUP),
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                mDeviceUse.endAudioIntervalGroup(item, DeviceUse::RECORD);
            }));

    // Handle device use thread statistics
    mActions.addAction(
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_THREAD "*." AMEDIAMETRICS_PROP_EVENT,
        std::string(AMEDIAMETRICS_PROP_EVENT_VALUE_ENDAUDIOINTERVALGROUP),
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                mDeviceUse.endAudioIntervalGroup(item, DeviceUse::THREAD);
            }));

    // Handle device use track statistics
    mActions.addAction(
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_TRACK "*." AMEDIAMETRICS_PROP_EVENT,
        std::string(AMEDIAMETRICS_PROP_EVENT_VALUE_ENDAUDIOINTERVALGROUP),
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                mDeviceUse.endAudioIntervalGroup(item, DeviceUse::TRACK);
            }));


    // Handle device connection statistics

    // We track connections (not disconnections) for the time to connect.
    // TODO: consider BT requests in their A2dp service
    // AudioManager.setBluetoothA2dpDeviceConnectionStateSuppressNoisyIntent
    // AudioDeviceBroker.postBluetoothA2dpDeviceConnectionStateSuppressNoisyIntent
    // AudioDeviceBroker.postA2dpActiveDeviceChange
    mActions.addAction(
        "audio.device.a2dp.state",
        "connected",
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

    // Called from BT service
    mActions.addAction(
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_DEVICE
        "postBluetoothA2dpDeviceConnectionStateSuppressNoisyIntent"
        "." AMEDIAMETRICS_PROP_STATE,
        "connected",
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                mDeviceConnection.postBluetoothA2dpDeviceConnectionStateSuppressNoisyIntent(item);
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

    if (ll > 0) {
        // Print the statsd atoms we sent out.
        const std::string statsd = mStatsdLog.dumpToString("  " /* prefix */, ll - 1);
        const size_t n = std::count(statsd.begin(), statsd.end(), '\n') + 1; // we control this.
        if ((size_t)ll >= n) {
            if (n == 1) {
                ss << "Statsd atoms: empty or truncated\n";
            } else {
                ss << "Statsd atoms:\n" << statsd;
            }
            ll -= n;
        }
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
       const std::shared_ptr<const android::mediametrics::Item> &item, ItemType itemType) const {
    const std::string& key = item->getKey();
    const std::string id = key.substr(
            (itemType == THREAD ? sizeof(AMEDIAMETRICS_KEY_PREFIX_AUDIO_THREAD)
            : itemType == TRACK ? sizeof(AMEDIAMETRICS_KEY_PREFIX_AUDIO_TRACK)
            : sizeof(AMEDIAMETRICS_KEY_PREFIX_AUDIO_RECORD))
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
    std::string inputDevicePairs;
    mAudioAnalytics.mAnalyticsState->timeMachine().get(
            key, AMEDIAMETRICS_PROP_INPUTDEVICES, &inputDevicePairs);
    int32_t intervalCount = 0;
    mAudioAnalytics.mAnalyticsState->timeMachine().get(
            key, AMEDIAMETRICS_PROP_INTERVALCOUNT, &intervalCount);
    std::string outputDevicePairs;
    mAudioAnalytics.mAnalyticsState->timeMachine().get(
            key, AMEDIAMETRICS_PROP_OUTPUTDEVICES, &outputDevicePairs);
    int32_t sampleRate = 0;
    mAudioAnalytics.mAnalyticsState->timeMachine().get(
            key, AMEDIAMETRICS_PROP_SAMPLERATE, &sampleRate);
    std::string flags;
    mAudioAnalytics.mAnalyticsState->timeMachine().get(
            key, AMEDIAMETRICS_PROP_FLAGS, &flags);

    // We may have several devices.
    // Accumulate the bit flags for input and output devices.
    std::stringstream oss;
    long_enum_type_t outputDeviceBits{};
    {   // compute outputDevices
        const auto devaddrvec = stringutils::getDeviceAddressPairs(outputDevicePairs);
        for (const auto& [device, addr] : devaddrvec) {
            if (oss.tellp() > 0) oss << "|";  // delimit devices with '|'.
            oss << device;
            outputDeviceBits += types::lookup<types::OUTPUT_DEVICE, long_enum_type_t>(device);
        }
    }
    const std::string outputDevices = oss.str();

    std::stringstream iss;
    long_enum_type_t inputDeviceBits{};
    {   // compute inputDevices
        const auto devaddrvec = stringutils::getDeviceAddressPairs(inputDevicePairs);
        for (const auto& [device, addr] : devaddrvec) {
            if (iss.tellp() > 0) iss << "|";  // delimit devices with '|'.
            iss << device;
            inputDeviceBits += types::lookup<types::INPUT_DEVICE, long_enum_type_t>(device);
        }
    }
    const std::string inputDevices = iss.str();

    // Get connected device name if from bluetooth.
    bool isBluetooth = false;

    std::string inputDeviceNames;  // not filled currently.
    std::string outputDeviceNames;
    if (outputDevices.find("AUDIO_DEVICE_OUT_BLUETOOTH") != std::string::npos) {
        isBluetooth = true;
        outputDeviceNames = SUPPRESSED;
#if 0   // TODO(b/161554630) sanitize name
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
            "audio.device.bt_a2dp", AMEDIAMETRICS_PROP_NAME, &outputDeviceNames);
        // Remove | if present
        stringutils::replace(outputDeviceNames, "|", '?');
        if (outputDeviceNames.size() > STATSD_DEVICE_NAME_MAX_LENGTH) {
            outputDeviceNames.resize(STATSD_DEVICE_NAME_MAX_LENGTH); // truncate
        }
#endif
    }

    switch (itemType) {
    case RECORD: {
        std::string callerName;
        const bool clientCalled = mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_CALLERNAME, &callerName) == OK;

        std::string packageName;
        int64_t versionCode = 0;
        int32_t uid = -1;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_ALLOWUID, &uid);
        if (uid != -1) {
            std::tie(packageName, versionCode) =
                    MediaMetricsService::getSanitizedPackageNameAndVersionCode(uid);
        }

        int32_t selectedDeviceId = 0;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_SELECTEDDEVICEID, &selectedDeviceId);
        std::string source;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_SOURCE, &source);

        const auto callerNameForStats =
                types::lookup<types::CALLER_NAME, short_enum_type_t>(callerName);
        const auto encodingForStats = types::lookup<types::ENCODING, short_enum_type_t>(encoding);
        const auto flagsForStats = types::lookup<types::INPUT_FLAG, short_enum_type_t>(flags);
        const auto sourceForStats = types::lookup<types::SOURCE_TYPE, short_enum_type_t>(source);

        LOG(LOG_LEVEL) << "key:" << key
              << " id:" << id
              << " inputDevices:" << inputDevices << "(" << inputDeviceBits
              << ") inputDeviceNames:" << inputDeviceNames
              << " deviceTimeNs:" << deviceTimeNs
              << " encoding:" << encoding << "(" << encodingForStats
              << ") frameCount:" << frameCount
              << " intervalCount:" << intervalCount
              << " sampleRate:" << sampleRate
              << " flags:" << flags << "(" << flagsForStats
              << ") packageName:" << packageName
              << " selectedDeviceId:" << selectedDeviceId
              << " callerName:" << callerName << "(" << callerNameForStats
              << ") source:" << source << "(" << sourceForStats << ")";
        if (clientCalled  // only log if client app called AudioRecord.
                && mAudioAnalytics.mDeliverStatistics) {
            const auto [ result, str ] = sendToStatsd(AudioRecordDeviceUsageFields,
                    CONDITION(android::util::MEDIAMETRICS_AUDIORECORDDEVICEUSAGE_REPORTED)
                    , ENUM_EXTRACT(inputDeviceBits)
                    , inputDeviceNames.c_str()
                    , deviceTimeNs
                    , ENUM_EXTRACT(encodingForStats)
                    , frameCount
                    , intervalCount
                    , sampleRate
                    , ENUM_EXTRACT(flagsForStats)

                    , packageName.c_str()
                    , selectedDeviceId
                    , ENUM_EXTRACT(callerNameForStats)
                    , ENUM_EXTRACT(sourceForStats)
                    );
            ALOGV("%s: statsd %s", __func__, str.c_str());
            mAudioAnalytics.mStatsdLog.log("%s", str.c_str());
        }
    } break;
    case THREAD: {
        std::string type;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_TYPE, &type);
        int32_t underrun = 0; // zero for record types
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_UNDERRUN, &underrun);

        const bool isInput = types::isInputThreadType(type);
        const auto encodingForStats = types::lookup<types::ENCODING, short_enum_type_t>(encoding);
        const auto flagsForStats =
                (isInput ? types::lookup<types::INPUT_FLAG, short_enum_type_t>(flags)
                        : types::lookup<types::OUTPUT_FLAG, short_enum_type_t>(flags));
        const auto typeForStats = types::lookup<types::THREAD_TYPE, short_enum_type_t>(type);

        LOG(LOG_LEVEL) << "key:" << key
              << " id:" << id
              << " inputDevices:" << inputDevices << "(" << inputDeviceBits
              << ") outputDevices:" << outputDevices << "(" << outputDeviceBits
              << ") inputDeviceNames:" << inputDeviceNames
              << " outputDeviceNames:" << outputDeviceNames
              << " deviceTimeNs:" << deviceTimeNs
              << " encoding:" << encoding << "(" << encodingForStats
              << ") frameCount:" << frameCount
              << " intervalCount:" << intervalCount
              << " sampleRate:" << sampleRate
              << " underrun:" << underrun
              << " flags:" << flags << "(" << flagsForStats
              << ") type:" << type << "(" << typeForStats
              << ")";
        if (mAudioAnalytics.mDeliverStatistics) {
            const auto [ result, str ] = sendToStatsd(AudioThreadDeviceUsageFields,
                CONDITION(android::util::MEDIAMETRICS_AUDIOTHREADDEVICEUSAGE_REPORTED)
                , isInput ? ENUM_EXTRACT(inputDeviceBits) : ENUM_EXTRACT(outputDeviceBits)
                , isInput ? inputDeviceNames.c_str() : outputDeviceNames.c_str()
                , deviceTimeNs
                , ENUM_EXTRACT(encodingForStats)
                , frameCount
                , intervalCount
                , sampleRate
                , ENUM_EXTRACT(flagsForStats)
                , underrun
                , ENUM_EXTRACT(typeForStats)
            );
            ALOGV("%s: statsd %s", __func__, str.c_str());
            mAudioAnalytics.mStatsdLog.log("%s", str.c_str());
        }
    } break;
    case TRACK: {
        std::string callerName;
        const bool clientCalled = mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_CALLERNAME, &callerName) == OK;

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
        std::string streamType;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_STREAMTYPE, &streamType);
        std::string traits;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_TRAITS, &traits);
        int32_t underrun = 0;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_UNDERRUN, &underrun);
        std::string usage;
        mAudioAnalytics.mAnalyticsState->timeMachine().get(
                key, AMEDIAMETRICS_PROP_USAGE, &usage);

        const auto callerNameForStats =
                types::lookup<types::CALLER_NAME, short_enum_type_t>(callerName);
        const auto contentTypeForStats =
                types::lookup<types::CONTENT_TYPE, short_enum_type_t>(contentType);
        const auto encodingForStats = types::lookup<types::ENCODING, short_enum_type_t>(encoding);
        const auto flagsForStats = types::lookup<types::OUTPUT_FLAG, short_enum_type_t>(flags);
        const auto streamTypeForStats =
                types::lookup<types::STREAM_TYPE, short_enum_type_t>(streamType);
        const auto traitsForStats =
                 types::lookup<types::TRACK_TRAITS, short_enum_type_t>(traits);
        const auto usageForStats = types::lookup<types::USAGE, short_enum_type_t>(usage);

        LOG(LOG_LEVEL) << "key:" << key
              << " id:" << id
              << " outputDevices:" << outputDevices << "(" << outputDeviceBits
              << ") outputDeviceNames:" << outputDeviceNames
              << " deviceTimeNs:" << deviceTimeNs
              << " encoding:" << encoding << "(" << encodingForStats
              << ") frameCount:" << frameCount
              << " intervalCount:" << intervalCount
              << " sampleRate:" << sampleRate
              << " underrun:" << underrun
              << " flags:" << flags << "(" << flagsForStats
              << ") callerName:" << callerName << "(" << callerNameForStats
              << ") contentType:" << contentType << "(" << contentTypeForStats
              << ") deviceLatencyMs:" << deviceLatencyMs
              << " deviceStartupMs:" << deviceStartupMs
              << " deviceVolume:" << deviceVolume
              << " packageName:" << packageName
              << " playbackPitch:" << playbackPitch
              << " playbackSpeed:" << playbackSpeed
              << " selectedDeviceId:" << selectedDeviceId
              << " streamType:" << streamType << "(" << streamTypeForStats
              << ") traits:" << traits << "(" << traitsForStats
              << ") usage:" << usage << "(" << usageForStats
              << ")";
        if (clientCalled // only log if client app called AudioTracks
                && mAudioAnalytics.mDeliverStatistics) {
            const auto [ result, str ] = sendToStatsd(AudioTrackDeviceUsageFields,
                    CONDITION(android::util::MEDIAMETRICS_AUDIOTRACKDEVICEUSAGE_REPORTED)
                    , ENUM_EXTRACT(outputDeviceBits)
                    , outputDeviceNames.c_str()
                    , deviceTimeNs
                    , ENUM_EXTRACT(encodingForStats)
                    , frameCount
                    , intervalCount
                    , sampleRate
                    , ENUM_EXTRACT(flagsForStats)
                    , underrun
                    , packageName.c_str()
                    , (float)deviceLatencyMs
                    , (float)deviceStartupMs
                    , (float)deviceVolume
                    , selectedDeviceId
                    , ENUM_EXTRACT(streamTypeForStats)
                    , ENUM_EXTRACT(usageForStats)
                    , ENUM_EXTRACT(contentTypeForStats)
                    , ENUM_EXTRACT(callerNameForStats)
                    , ENUM_EXTRACT(traitsForStats)
                    );
            ALOGV("%s: statsd %s", __func__, str.c_str());
            mAudioAnalytics.mStatsdLog.log("%s", str.c_str());
        }
        } break;
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
    const int64_t atNs = item->getTimestamp();
    {
        std::lock_guard l(mLock);
        mA2dpConnectionServiceNs = atNs;
        ++mA2dpConnectionServices;

        if (mA2dpConnectionRequestNs == 0) {
            mAudioAnalytics.mTimedAction.postIn(std::chrono::seconds(5), [this](){ expire(); });
        }
        // This sets the time we were connected.  Now we look for the delta in the future.
    }
    std::string name;
    item->get(AMEDIAMETRICS_PROP_NAME, &name);
    ALOGD("(key=%s) a2dp connected device:%s atNs:%lld",
            key.c_str(), name.c_str(), (long long)atNs);
}

void AudioAnalytics::DeviceConnection::createPatch(
       const std::shared_ptr<const android::mediametrics::Item> &item) {
    std::lock_guard l(mLock);
    if (mA2dpConnectionServiceNs == 0) return; // patch unrelated to us.
    const std::string& key = item->getKey();
    std::string outputDevices;
    item->get(AMEDIAMETRICS_PROP_OUTPUTDEVICES, &outputDevices);
    if (outputDevices.find("AUDIO_DEVICE_OUT_BLUETOOTH_A2DP") != std::string::npos) {
        // TODO compare address
        int64_t timeDiffNs = item->getTimestamp();
        if (mA2dpConnectionRequestNs == 0) {
            ALOGD("%s: A2DP create patch didn't see a connection request", __func__);
            timeDiffNs -= mA2dpConnectionServiceNs;
        } else {
            timeDiffNs -= mA2dpConnectionRequestNs;
        }

        mA2dpConnectionRequestNs = 0;
        mA2dpConnectionServiceNs = 0;
        ++mA2dpConnectionSuccesses;

        const auto connectionTimeMs = float(timeDiffNs * 1e-6);

        const auto outputDeviceBits = types::lookup<types::OUTPUT_DEVICE, long_enum_type_t>(
                "AUDIO_DEVICE_OUT_BLUETOOTH_A2DP");

        LOG(LOG_LEVEL) << "key:" << key
                << " A2DP SUCCESS"
                << " outputDevices:" << outputDeviceBits
                << " deviceName:" << mA2dpDeviceName
                << " connectionTimeMs:" <<  connectionTimeMs;
        if (mAudioAnalytics.mDeliverStatistics) {
            const long_enum_type_t inputDeviceBits{};

            const auto [ result, str ] = sendToStatsd(AudioDeviceConnectionFields,
                    CONDITION(android::util::MEDIAMETRICS_AUDIODEVICECONNECTION_REPORTED)
                    , ENUM_EXTRACT(inputDeviceBits)
                    , ENUM_EXTRACT(outputDeviceBits)
                    , mA2dpDeviceName.c_str()
                    , types::DEVICE_CONNECTION_RESULT_SUCCESS
                    , connectionTimeMs
                    , /* connection_count */ 1
                    );
            ALOGV("%s: statsd %s", __func__, str.c_str());
            mAudioAnalytics.mStatsdLog.log("%s", str.c_str());
        }
    }
}

// Called through AudioManager when the BT service wants to enable
void AudioAnalytics::DeviceConnection::postBluetoothA2dpDeviceConnectionStateSuppressNoisyIntent(
        const std::shared_ptr<const android::mediametrics::Item> &item) {
    const int64_t atNs = item->getTimestamp();
    const std::string& key = item->getKey();
    std::string state;
    item->get(AMEDIAMETRICS_PROP_STATE, &state);
    if (state != "connected") return;

    std::string name;
    item->get(AMEDIAMETRICS_PROP_NAME, &name);
    {
        std::lock_guard l(mLock);
        mA2dpConnectionRequestNs = atNs;
        ++mA2dpConnectionRequests;
        mA2dpDeviceName = SUPPRESSED; // TODO(b/161554630) sanitize name
    }
    ALOGD("(key=%s) a2dp connection name:%s request atNs:%lld",
            key.c_str(), name.c_str(), (long long)atNs);
    // TODO: attempt to cancel a timed event, rather than let it expire.
    mAudioAnalytics.mTimedAction.postIn(std::chrono::seconds(5), [this](){ expire(); });
}

void AudioAnalytics::DeviceConnection::expire() {
    std::lock_guard l(mLock);
    if (mA2dpConnectionRequestNs == 0) return; // ignore (this was an internal connection).

    const long_enum_type_t inputDeviceBits{};
    const auto outputDeviceBits = types::lookup<types::OUTPUT_DEVICE, long_enum_type_t>(
            "AUDIO_DEVICE_OUT_BLUETOOTH_A2DP");

    if (mA2dpConnectionServiceNs == 0) {
        ++mA2dpConnectionJavaServiceCancels;  // service did not connect to A2DP

        LOG(LOG_LEVEL) << "A2DP CANCEL"
                << " outputDevices:" << outputDeviceBits
                << " deviceName:" << mA2dpDeviceName;
        if (mAudioAnalytics.mDeliverStatistics) {
            const auto [ result, str ] = sendToStatsd(AudioDeviceConnectionFields,
                    CONDITION(android::util::MEDIAMETRICS_AUDIODEVICECONNECTION_REPORTED)
                    , ENUM_EXTRACT(inputDeviceBits)
                    , ENUM_EXTRACT(outputDeviceBits)
                    , mA2dpDeviceName.c_str()
                    , types::DEVICE_CONNECTION_RESULT_JAVA_SERVICE_CANCEL
                    , /* connection_time_ms */ 0.f
                    , /* connection_count */ 1
                    );
            ALOGV("%s: statsd %s", __func__, str.c_str());
            mAudioAnalytics.mStatsdLog.log("%s", str.c_str());
        }
        return;
    }

    // AudioFlinger didn't play - an expiration may occur because there is no audio playing.
    // Should we check elsewhere?
    // TODO: disambiguate this case.
    mA2dpConnectionRequestNs = 0;
    mA2dpConnectionServiceNs = 0;
    ++mA2dpConnectionUnknowns;  // connection result unknown

    LOG(LOG_LEVEL) << "A2DP UNKNOWN"
            << " outputDevices:" << outputDeviceBits
            << " deviceName:" << mA2dpDeviceName;
    if (mAudioAnalytics.mDeliverStatistics) {
        const auto [ result, str ] = sendToStatsd(AudioDeviceConnectionFields,
                CONDITION(android::util::MEDIAMETRICS_AUDIODEVICECONNECTION_REPORTED)
                , ENUM_EXTRACT(inputDeviceBits)
                , ENUM_EXTRACT(outputDeviceBits)
                , mA2dpDeviceName.c_str()
                , types::DEVICE_CONNECTION_RESULT_UNKNOWN
                , /* connection_time_ms */ 0.f
                , /* connection_count */ 1
                );
        ALOGV("%s: statsd %s", __func__, str.c_str());
        mAudioAnalytics.mStatsdLog.log("%s", str.c_str());
    }
}

} // namespace android::mediametrics
