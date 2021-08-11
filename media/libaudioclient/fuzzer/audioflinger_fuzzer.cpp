/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/**
 * NOTE
 * 1) The input to AudioFlinger binder calls are fuzzed in this fuzzer
 * 2) AudioFlinger crashes due to the fuzzer are detected by the
      Binder DeathRecipient, where the fuzzer aborts if AudioFlinger dies
 */

#include <android_audio_policy_configuration_V7_0-enums.h>
#include <android/content/AttributionSourceState.h>
#include <binder/IServiceManager.h>
#include <binder/MemoryDealer.h>
#include <media/AidlConversion.h>
#include <media/AudioEffect.h>
#include <media/AudioRecord.h>
#include <media/AudioSystem.h>
#include <media/AudioTrack.h>
#include <media/IAudioFlinger.h>
#include "fuzzer/FuzzedDataProvider.h"

#define MAX_STRING_LENGTH 256
#define MAX_ARRAY_LENGTH 256

constexpr int32_t kMinSampleRateHz = 4000;
constexpr int32_t kMaxSampleRateHz = 192000;
constexpr int32_t kSampleRateUnspecified = 0;

using namespace std;
using namespace android;

namespace xsd {
using namespace ::android::audio::policy::configuration::V7_0;
}

using android::content::AttributionSourceState;

constexpr audio_unique_id_use_t kUniqueIds[] = {
    AUDIO_UNIQUE_ID_USE_UNSPECIFIED, AUDIO_UNIQUE_ID_USE_SESSION, AUDIO_UNIQUE_ID_USE_MODULE,
    AUDIO_UNIQUE_ID_USE_EFFECT,      AUDIO_UNIQUE_ID_USE_PATCH,   AUDIO_UNIQUE_ID_USE_OUTPUT,
    AUDIO_UNIQUE_ID_USE_INPUT,       AUDIO_UNIQUE_ID_USE_CLIENT,  AUDIO_UNIQUE_ID_USE_MAX,
};

constexpr audio_mode_t kModes[] = {
    AUDIO_MODE_INVALID, AUDIO_MODE_CURRENT,          AUDIO_MODE_NORMAL,     AUDIO_MODE_RINGTONE,
    AUDIO_MODE_IN_CALL, AUDIO_MODE_IN_COMMUNICATION, AUDIO_MODE_CALL_SCREEN};

constexpr audio_session_t kSessionId[] = {AUDIO_SESSION_NONE, AUDIO_SESSION_OUTPUT_STAGE,
                                          AUDIO_SESSION_DEVICE};

constexpr audio_encapsulation_mode_t kEncapsulation[] = {
    AUDIO_ENCAPSULATION_MODE_NONE,
    AUDIO_ENCAPSULATION_MODE_ELEMENTARY_STREAM,
    AUDIO_ENCAPSULATION_MODE_HANDLE,
};

constexpr audio_port_role_t kPortRoles[] = {
    AUDIO_PORT_ROLE_NONE,
    AUDIO_PORT_ROLE_SOURCE,
    AUDIO_PORT_ROLE_SINK,
};

constexpr audio_port_type_t kPortTypes[] = {
    AUDIO_PORT_TYPE_NONE,
    AUDIO_PORT_TYPE_DEVICE,
    AUDIO_PORT_TYPE_MIX,
    AUDIO_PORT_TYPE_SESSION,
};

template <typename T, typename X, typename FUNC>
std::vector<T> getFlags(const xsdc_enum_range<X> &range, const FUNC &func,
                        const std::string &findString = {}) {
    std::vector<T> vec;
    for (const auto &xsdEnumVal : range) {
        T enumVal;
        std::string enumString = toString(xsdEnumVal);
        if (enumString.find(findString) != std::string::npos &&
            func(enumString.c_str(), &enumVal)) {
            vec.push_back(enumVal);
        }
    }
    return vec;
}

static const std::vector<audio_stream_type_t> kStreamtypes =
    getFlags<audio_stream_type_t, xsd::AudioStreamType, decltype(audio_stream_type_from_string)>(
        xsdc_enum_range<xsd::AudioStreamType>{}, audio_stream_type_from_string);

static const std::vector<audio_format_t> kFormats =
    getFlags<audio_format_t, xsd::AudioFormat, decltype(audio_format_from_string)>(
        xsdc_enum_range<xsd::AudioFormat>{}, audio_format_from_string);

static const std::vector<audio_channel_mask_t> kChannelMasks =
    getFlags<audio_channel_mask_t, xsd::AudioChannelMask, decltype(audio_channel_mask_from_string)>(
        xsdc_enum_range<xsd::AudioChannelMask>{}, audio_channel_mask_from_string);

static const std::vector<audio_usage_t> kUsages =
    getFlags<audio_usage_t, xsd::AudioUsage, decltype(audio_usage_from_string)>(
        xsdc_enum_range<xsd::AudioUsage>{}, audio_usage_from_string);

static const std::vector<audio_content_type_t> kContentType =
    getFlags<audio_content_type_t, xsd::AudioContentType, decltype(audio_content_type_from_string)>(
        xsdc_enum_range<xsd::AudioContentType>{}, audio_content_type_from_string);

static const std::vector<audio_source_t> kInputSources =
    getFlags<audio_source_t, xsd::AudioSource, decltype(audio_source_from_string)>(
        xsdc_enum_range<xsd::AudioSource>{}, audio_source_from_string);

static const std::vector<audio_gain_mode_t> kGainModes =
    getFlags<audio_gain_mode_t, xsd::AudioGainMode, decltype(audio_gain_mode_from_string)>(
        xsdc_enum_range<xsd::AudioGainMode>{}, audio_gain_mode_from_string);

static const std::vector<audio_devices_t> kDevices =
    getFlags<audio_devices_t, xsd::AudioDevice, decltype(audio_device_from_string)>(
        xsdc_enum_range<xsd::AudioDevice>{}, audio_device_from_string);

static const std::vector<audio_input_flags_t> kInputFlags =
    getFlags<audio_input_flags_t, xsd::AudioInOutFlag, decltype(audio_input_flag_from_string)>(
        xsdc_enum_range<xsd::AudioInOutFlag>{}, audio_input_flag_from_string, "_INPUT_");

static const std::vector<audio_output_flags_t> kOutputFlags =
    getFlags<audio_output_flags_t, xsd::AudioInOutFlag, decltype(audio_output_flag_from_string)>(
        xsdc_enum_range<xsd::AudioInOutFlag>{}, audio_output_flag_from_string, "_OUTPUT_");

template <typename T, size_t size>
T getValue(FuzzedDataProvider *fdp, const T (&arr)[size]) {
    return arr[fdp->ConsumeIntegralInRange<int32_t>(0, size - 1)];
}

template <typename T>
T getValue(FuzzedDataProvider *fdp, std::vector<T> vec) {
    return vec[fdp->ConsumeIntegralInRange<int32_t>(0, vec.size() - 1)];
}

int32_t getSampleRate(FuzzedDataProvider *fdp) {
    if (fdp->ConsumeBool()) {
        return fdp->ConsumeIntegralInRange<int32_t>(kMinSampleRateHz, kMaxSampleRateHz);
    }
    return kSampleRateUnspecified;
}

class DeathNotifier : public IBinder::DeathRecipient {
   public:
    void binderDied(const wp<IBinder> &) { abort(); }
};

class AudioFlingerFuzzer {
   public:
    AudioFlingerFuzzer(const uint8_t *data, size_t size);
    void process();

   private:
    FuzzedDataProvider mFdp;
    void invokeAudioTrack();
    void invokeAudioRecord();
    status_t invokeAudioEffect();
    void invokeAudioSystem();
    status_t invokeAudioInputDevice();
    status_t invokeAudioOutputDevice();
    void invokeAudioPatch();

    sp<DeathNotifier> mDeathNotifier;
};

AudioFlingerFuzzer::AudioFlingerFuzzer(const uint8_t *data, size_t size) : mFdp(data, size) {
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("media.audio_flinger"));
    if (binder == nullptr) {
        return;
    }
    mDeathNotifier = new DeathNotifier();
    binder->linkToDeath(mDeathNotifier);
}

void AudioFlingerFuzzer::invokeAudioTrack() {
    uint32_t sampleRate = getSampleRate(&mFdp);
    audio_format_t format = getValue(&mFdp, kFormats);
    audio_channel_mask_t channelMask = getValue(&mFdp, kChannelMasks);
    size_t frameCount = static_cast<size_t>(mFdp.ConsumeIntegral<uint32_t>());
    int32_t notificationFrames = mFdp.ConsumeIntegral<int32_t>();
    uint32_t useSharedBuffer = mFdp.ConsumeBool();
    audio_output_flags_t flags = getValue(&mFdp, kOutputFlags);
    audio_session_t sessionId = getValue(&mFdp, kSessionId);
    audio_usage_t usage = getValue(&mFdp, kUsages);
    audio_content_type_t contentType = getValue(&mFdp, kContentType);
    audio_attributes_t attributes = {};
    sp<IMemory> sharedBuffer;
    sp<MemoryDealer> heap = nullptr;
    audio_offload_info_t offloadInfo = AUDIO_INFO_INITIALIZER;

    bool offload = false;
    bool fast = ((flags & AUDIO_OUTPUT_FLAG_FAST) != 0);

    if (useSharedBuffer != 0) {
        size_t heapSize = audio_channel_count_from_out_mask(channelMask) *
                          audio_bytes_per_sample(format) * frameCount;
        heap = new MemoryDealer(heapSize, "AudioTrack Heap Base");
        sharedBuffer = heap->allocate(heapSize);
        frameCount = 0;
        notificationFrames = 0;
    }
    if ((flags & AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD) != 0) {
        offloadInfo.sample_rate = sampleRate;
        offloadInfo.channel_mask = channelMask;
        offloadInfo.format = format;
        offload = true;
    }

    attributes.content_type = contentType;
    attributes.usage = usage;
    sp<AudioTrack> track = new AudioTrack();

    // TODO b/182392769: use attribution source util
    AttributionSourceState attributionSource;
    attributionSource.uid = VALUE_OR_FATAL(legacy2aidl_uid_t_int32_t(getuid()));
    attributionSource.pid = VALUE_OR_FATAL(legacy2aidl_pid_t_int32_t(getpid()));
    attributionSource.token = sp<BBinder>::make();
    track->set(AUDIO_STREAM_DEFAULT, sampleRate, format, channelMask, frameCount, flags, nullptr,
               nullptr, notificationFrames, sharedBuffer, false, sessionId,
               ((fast && sharedBuffer == 0) || offload) ? AudioTrack::TRANSFER_CALLBACK
                                                        : AudioTrack::TRANSFER_DEFAULT,
               offload ? &offloadInfo : nullptr, attributionSource, &attributes, false, 1.0f,
               AUDIO_PORT_HANDLE_NONE);

    status_t status = track->initCheck();
    if (status != NO_ERROR) {
        track.clear();
        return;
    }
    track->getSampleRate();
    track->latency();
    track->getUnderrunCount();
    track->streamType();
    track->channelCount();
    track->getNotificationPeriodInFrames();
    uint32_t bufferSizeInFrames = mFdp.ConsumeIntegral<uint32_t>();
    track->setBufferSizeInFrames(bufferSizeInFrames);
    track->getBufferSizeInFrames();

    int64_t duration = mFdp.ConsumeIntegral<int64_t>();
    track->getBufferDurationInUs(&duration);
    sp<IMemory> sharedBuffer2 = track->sharedBuffer();
    track->setCallerName(mFdp.ConsumeRandomLengthString(MAX_STRING_LENGTH));

    track->setVolume(mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>());
    track->setVolume(mFdp.ConsumeFloatingPoint<float>());
    track->setAuxEffectSendLevel(mFdp.ConsumeFloatingPoint<float>());

    float auxEffectSendLevel;
    track->getAuxEffectSendLevel(&auxEffectSendLevel);
    track->setSampleRate(getSampleRate(&mFdp));
    track->getSampleRate();
    track->getOriginalSampleRate();

    AudioPlaybackRate playbackRate = {};
    playbackRate.mSpeed = mFdp.ConsumeFloatingPoint<float>();
    playbackRate.mPitch = mFdp.ConsumeFloatingPoint<float>();
    track->setPlaybackRate(playbackRate);
    track->getPlaybackRate();
    track->setLoop(mFdp.ConsumeIntegral<uint32_t>(), mFdp.ConsumeIntegral<uint32_t>(),
                   mFdp.ConsumeIntegral<uint32_t>());
    track->setMarkerPosition(mFdp.ConsumeIntegral<uint32_t>());

    uint32_t marker = {};
    track->getMarkerPosition(&marker);
    track->setPositionUpdatePeriod(mFdp.ConsumeIntegral<uint32_t>());

    uint32_t updatePeriod = {};
    track->getPositionUpdatePeriod(&updatePeriod);
    track->setPosition(mFdp.ConsumeIntegral<uint32_t>());
    uint32_t position = {};
    track->getPosition(&position);
    track->getBufferPosition(&position);
    track->reload();
    track->start();
    track->pause();
    track->flush();
    track->stop();
    track->stopped();
}

void AudioFlingerFuzzer::invokeAudioRecord() {
    int32_t notificationFrames = mFdp.ConsumeIntegral<int32_t>();
    uint32_t sampleRate = getSampleRate(&mFdp);
    size_t frameCount = static_cast<size_t>(mFdp.ConsumeIntegral<uint32_t>());
    audio_format_t format = getValue(&mFdp, kFormats);
    audio_channel_mask_t channelMask = getValue(&mFdp, kChannelMasks);
    audio_input_flags_t flags = getValue(&mFdp, kInputFlags);
    audio_session_t sessionId = getValue(&mFdp, kSessionId);
    audio_source_t inputSource = getValue(&mFdp, kInputSources);

    audio_attributes_t attributes = {};
    bool fast = ((flags & AUDIO_OUTPUT_FLAG_FAST) != 0);

    attributes.source = inputSource;

    // TODO b/182392769: use attribution source util
    AttributionSourceState attributionSource;
    attributionSource.packageName = std::string(mFdp.ConsumeRandomLengthString().c_str());
    attributionSource.token = sp<BBinder>::make();
    sp<AudioRecord> record = new AudioRecord(attributionSource);
    record->set(AUDIO_SOURCE_DEFAULT, sampleRate, format, channelMask, frameCount, nullptr, nullptr,
                notificationFrames, false, sessionId,
                fast ? AudioRecord::TRANSFER_CALLBACK : AudioRecord::TRANSFER_DEFAULT, flags,
                getuid(), getpid(), &attributes, AUDIO_PORT_HANDLE_NONE);
    status_t status = record->initCheck();
    if (status != NO_ERROR) {
        return;
    }
    record->latency();
    record->format();
    record->channelCount();
    record->frameCount();
    record->frameSize();
    record->inputSource();
    record->getNotificationPeriodInFrames();
    record->start();
    record->stop();
    record->stopped();

    uint32_t marker = mFdp.ConsumeIntegral<uint32_t>();
    record->setMarkerPosition(marker);
    record->getMarkerPosition(&marker);

    uint32_t updatePeriod = mFdp.ConsumeIntegral<uint32_t>();
    record->setPositionUpdatePeriod(updatePeriod);
    record->getPositionUpdatePeriod(&updatePeriod);

    uint32_t position;
    record->getPosition(&position);

    ExtendedTimestamp timestamp;
    record->getTimestamp(&timestamp);
    record->getSessionId();
    record->getCallerName();
    android::AudioRecord::Buffer audioBuffer;
    int32_t waitCount = mFdp.ConsumeIntegral<int32_t>();
    size_t nonContig = static_cast<size_t>(mFdp.ConsumeIntegral<uint32_t>());
    audioBuffer.frameCount = static_cast<size_t>(mFdp.ConsumeIntegral<uint32_t>());
    record->obtainBuffer(&audioBuffer, waitCount, &nonContig);
    bool blocking = false;
    record->read(audioBuffer.raw, audioBuffer.size, blocking);
    record->getInputFramesLost();
    record->getFlags();

    std::vector<media::MicrophoneInfo> activeMicrophones;
    record->getActiveMicrophones(&activeMicrophones);
    record->releaseBuffer(&audioBuffer);

    audio_port_handle_t deviceId =
        static_cast<audio_port_handle_t>(mFdp.ConsumeIntegral<int32_t>());
    record->setInputDevice(deviceId);
    record->getInputDevice();
    record->getRoutedDeviceId();
    record->getPortId();
}

struct EffectClient : public android::media::BnEffectClient {
    EffectClient() {}
    binder::Status controlStatusChanged(bool controlGranted __unused) override {
        return binder::Status::ok();
    }
    binder::Status enableStatusChanged(bool enabled __unused) override {
        return binder::Status::ok();
    }
    binder::Status commandExecuted(int32_t cmdCode __unused,
                                   const std::vector<uint8_t> &cmdData __unused,
                                   const std::vector<uint8_t> &replyData __unused) override {
        return binder::Status::ok();
    }
    binder::Status framesProcessed(int32_t frames __unused) override {
        return binder::Status::ok();
    }
};

status_t AudioFlingerFuzzer::invokeAudioEffect() {
    effect_uuid_t type;
    type.timeLow = mFdp.ConsumeIntegral<uint32_t>();
    type.timeMid = mFdp.ConsumeIntegral<uint16_t>();
    type.timeHiAndVersion = mFdp.ConsumeIntegral<uint16_t>();
    type.clockSeq = mFdp.ConsumeIntegral<uint16_t>();
    for (int i = 0; i < 6; ++i) {
        type.node[i] = mFdp.ConsumeIntegral<uint8_t>();
    }

    effect_descriptor_t descriptor = {};
    descriptor.type = type;
    descriptor.uuid = *EFFECT_UUID_NULL;

    sp<EffectClient> effectClient(new EffectClient());

    const int32_t priority = mFdp.ConsumeIntegral<int32_t>();
    audio_session_t sessionId = static_cast<audio_session_t>(mFdp.ConsumeIntegral<int32_t>());
    const audio_io_handle_t io = mFdp.ConsumeIntegral<int32_t>();
    std::string opPackageName = static_cast<std::string>(mFdp.ConsumeRandomLengthString().c_str());
    AudioDeviceTypeAddr device;

    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (!af) {
        return NO_ERROR;
    }

    media::CreateEffectRequest request{};
    request.desc =
        VALUE_OR_RETURN_STATUS(legacy2aidl_effect_descriptor_t_EffectDescriptor(descriptor));
    request.client = effectClient;
    request.priority = priority;
    request.output = io;
    request.sessionId = sessionId;
    request.device = VALUE_OR_RETURN_STATUS(legacy2aidl_AudioDeviceTypeAddress(device));
    // TODO b/182392769: use attribution source util
    request.attributionSource.packageName = opPackageName;
    request.attributionSource.pid = VALUE_OR_RETURN_STATUS(legacy2aidl_pid_t_int32_t(getpid()));
    request.probe = false;
    request.notifyFramesProcessed = false;

    media::CreateEffectResponse response{};
    status_t status = af->createEffect(request, &response);

    if (status != OK) {
        return NO_ERROR;
    }

    descriptor =
        VALUE_OR_RETURN_STATUS(aidl2legacy_EffectDescriptor_effect_descriptor_t(response.desc));

    uint32_t numEffects;
    af->queryNumberEffects(&numEffects);

    uint32_t queryIndex = mFdp.ConsumeIntegral<uint32_t>();
    af->queryEffect(queryIndex, &descriptor);

    effect_descriptor_t getDescriptor;
    uint32_t preferredTypeFlag = mFdp.ConsumeIntegral<int32_t>();
    af->getEffectDescriptor(&descriptor.uuid, &descriptor.type, preferredTypeFlag, &getDescriptor);

    sessionId = static_cast<audio_session_t>(mFdp.ConsumeIntegral<int32_t>());
    audio_io_handle_t srcOutput = mFdp.ConsumeIntegral<int32_t>();
    audio_io_handle_t dstOutput = mFdp.ConsumeIntegral<int32_t>();
    af->moveEffects(sessionId, srcOutput, dstOutput);

    int effectId = mFdp.ConsumeIntegral<int32_t>();
    sessionId = static_cast<audio_session_t>(mFdp.ConsumeIntegral<int32_t>());
    af->setEffectSuspended(effectId, sessionId, mFdp.ConsumeBool());
    return NO_ERROR;
}

void AudioFlingerFuzzer::invokeAudioSystem() {
    AudioSystem::muteMicrophone(mFdp.ConsumeBool());
    AudioSystem::setMasterMute(mFdp.ConsumeBool());
    AudioSystem::setMasterVolume(mFdp.ConsumeFloatingPoint<float>());
    AudioSystem::setMasterBalance(mFdp.ConsumeFloatingPoint<float>());
    AudioSystem::setVoiceVolume(mFdp.ConsumeFloatingPoint<float>());

    float volume;
    AudioSystem::getMasterVolume(&volume);

    bool state;
    AudioSystem::getMasterMute(&state);
    AudioSystem::isMicrophoneMuted(&state);

    audio_stream_type_t stream = getValue(&mFdp, kStreamtypes);
    AudioSystem::setStreamMute(getValue(&mFdp, kStreamtypes), mFdp.ConsumeBool());

    stream = getValue(&mFdp, kStreamtypes);
    AudioSystem::setStreamVolume(stream, mFdp.ConsumeFloatingPoint<float>(),
                                 mFdp.ConsumeIntegral<int32_t>());

    audio_mode_t mode = getValue(&mFdp, kModes);
    AudioSystem::setMode(mode);

    size_t frameCount;
    stream = getValue(&mFdp, kStreamtypes);
    AudioSystem::getOutputFrameCount(&frameCount, stream);

    uint32_t latency;
    stream = getValue(&mFdp, kStreamtypes);
    AudioSystem::getOutputLatency(&latency, stream);

    stream = getValue(&mFdp, kStreamtypes);
    AudioSystem::getStreamVolume(stream, &volume, mFdp.ConsumeIntegral<int32_t>());

    stream = getValue(&mFdp, kStreamtypes);
    AudioSystem::getStreamMute(stream, &state);

    uint32_t samplingRate;
    AudioSystem::getSamplingRate(mFdp.ConsumeIntegral<int32_t>(), &samplingRate);

    AudioSystem::getFrameCount(mFdp.ConsumeIntegral<int32_t>(), &frameCount);
    AudioSystem::getLatency(mFdp.ConsumeIntegral<int32_t>(), &latency);
    AudioSystem::setVoiceVolume(mFdp.ConsumeFloatingPoint<float>());

    uint32_t halFrames;
    uint32_t dspFrames;
    AudioSystem::getRenderPosition(mFdp.ConsumeIntegral<int32_t>(), &halFrames, &dspFrames);

    AudioSystem::getInputFramesLost(mFdp.ConsumeIntegral<int32_t>());
    AudioSystem::getInputFramesLost(mFdp.ConsumeIntegral<int32_t>());

    audio_unique_id_use_t uniqueIdUse = getValue(&mFdp, kUniqueIds);
    AudioSystem::newAudioUniqueId(uniqueIdUse);

    audio_session_t sessionId = getValue(&mFdp, kSessionId);
    pid_t pid = mFdp.ConsumeBool() ? getpid() : mFdp.ConsumeIntegral<int32_t>();
    uid_t uid = mFdp.ConsumeBool() ? getuid() : mFdp.ConsumeIntegral<int32_t>();
    AudioSystem::acquireAudioSessionId(sessionId, pid, uid);

    pid = mFdp.ConsumeBool() ? getpid() : mFdp.ConsumeIntegral<int32_t>();
    sessionId = getValue(&mFdp, kSessionId);
    AudioSystem::releaseAudioSessionId(sessionId, pid);

    sessionId = getValue(&mFdp, kSessionId);
    AudioSystem::getAudioHwSyncForSession(sessionId);

    AudioSystem::systemReady();
    AudioSystem::getFrameCountHAL(mFdp.ConsumeIntegral<int32_t>(), &frameCount);

    size_t buffSize;
    uint32_t sampleRate = getSampleRate(&mFdp);
    audio_format_t format = getValue(&mFdp, kFormats);
    audio_channel_mask_t channelMask = getValue(&mFdp, kChannelMasks);
    AudioSystem::getInputBufferSize(sampleRate, format, channelMask, &buffSize);

    AudioSystem::getPrimaryOutputSamplingRate();
    AudioSystem::getPrimaryOutputFrameCount();
    AudioSystem::setLowRamDevice(mFdp.ConsumeBool(), mFdp.ConsumeIntegral<int64_t>());

    std::vector<media::MicrophoneInfo> microphones;
    AudioSystem::getMicrophones(&microphones);

    std::vector<pid_t> pids;
    pids.insert(pids.begin(), getpid());
    for (int i = 1; i < mFdp.ConsumeIntegralInRange<int32_t>(2, MAX_ARRAY_LENGTH); ++i) {
        pids.insert(pids.begin() + i, static_cast<pid_t>(mFdp.ConsumeIntegral<int32_t>()));
    }
    AudioSystem::setAudioHalPids(pids);
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (!af) {
        return;
    }
    af->setRecordSilenced(mFdp.ConsumeIntegral<uint32_t>(), mFdp.ConsumeBool());

    float balance = mFdp.ConsumeFloatingPoint<float>();
    af->getMasterBalance(&balance);
    af->invalidateStream(static_cast<audio_stream_type_t>(mFdp.ConsumeIntegral<uint32_t>()));
}

status_t AudioFlingerFuzzer::invokeAudioInputDevice() {
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (!af) {
        return NO_ERROR;
    }

    audio_config_t config = {};
    audio_module_handle_t module = mFdp.ConsumeIntegral<int32_t>();
    audio_io_handle_t input = mFdp.ConsumeIntegral<int32_t>();
    config.frame_count = mFdp.ConsumeIntegral<uint32_t>();
    String8 address = static_cast<String8>(mFdp.ConsumeRandomLengthString().c_str());

    config.channel_mask = getValue(&mFdp, kChannelMasks);
    config.format = getValue(&mFdp, kFormats);

    config.offload_info = AUDIO_INFO_INITIALIZER;
    config.offload_info.bit_rate = mFdp.ConsumeIntegral<uint32_t>();
    config.offload_info.bit_width = mFdp.ConsumeIntegral<uint32_t>();
    config.offload_info.content_id = mFdp.ConsumeIntegral<uint32_t>();
    config.offload_info.channel_mask = getValue(&mFdp, kChannelMasks);
    config.offload_info.duration_us = mFdp.ConsumeIntegral<int64_t>();
    config.offload_info.encapsulation_mode = getValue(&mFdp, kEncapsulation);
    config.offload_info.format = getValue(&mFdp, kFormats);
    config.offload_info.has_video = mFdp.ConsumeBool();
    config.offload_info.is_streaming = mFdp.ConsumeBool();
    config.offload_info.sample_rate = getSampleRate(&mFdp);
    config.offload_info.sync_id = mFdp.ConsumeIntegral<uint32_t>();
    config.offload_info.stream_type = getValue(&mFdp, kStreamtypes);
    config.offload_info.usage = getValue(&mFdp, kUsages);

    config.sample_rate = getSampleRate(&mFdp);

    audio_devices_t device = getValue(&mFdp, kDevices);
    audio_source_t source = getValue(&mFdp, kInputSources);
    audio_input_flags_t flags = getValue(&mFdp, kInputFlags);

    AudioDeviceTypeAddr deviceTypeAddr(device, address.c_str());

    media::OpenInputRequest request{};
    request.module = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_module_handle_t_int32_t(module));
    request.input = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(input));
    request.config = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_config_t_AudioConfig(config));
    request.device = VALUE_OR_RETURN_STATUS(legacy2aidl_AudioDeviceTypeAddress(deviceTypeAddr));
    request.source = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_source_t_AudioSourceType(source));
    request.flags = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_input_flags_t_int32_t_mask(flags));

    media::OpenInputResponse response{};
    status_t status = af->openInput(request, &response);
    if (status != NO_ERROR) {
        return NO_ERROR;
    }

    input = VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_audio_module_handle_t(response.input));
    af->closeInput(input);
    return NO_ERROR;
}

status_t AudioFlingerFuzzer::invokeAudioOutputDevice() {
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (!af) {
        return NO_ERROR;
    }

    audio_config_t config = {};
    audio_module_handle_t module = mFdp.ConsumeIntegral<int32_t>();
    audio_io_handle_t output = mFdp.ConsumeIntegral<int32_t>();
    config.frame_count = mFdp.ConsumeIntegral<uint32_t>();
    String8 address = static_cast<String8>(mFdp.ConsumeRandomLengthString().c_str());

    config.channel_mask = getValue(&mFdp, kChannelMasks);

    config.offload_info = AUDIO_INFO_INITIALIZER;
    config.offload_info.bit_rate = mFdp.ConsumeIntegral<uint32_t>();
    config.offload_info.bit_width = mFdp.ConsumeIntegral<uint32_t>();
    config.offload_info.channel_mask = getValue(&mFdp, kChannelMasks);
    config.offload_info.content_id = mFdp.ConsumeIntegral<uint32_t>();
    config.offload_info.duration_us = mFdp.ConsumeIntegral<int64_t>();
    config.offload_info.encapsulation_mode = getValue(&mFdp, kEncapsulation);
    config.offload_info.format = getValue(&mFdp, kFormats);
    config.offload_info.has_video = mFdp.ConsumeBool();
    config.offload_info.is_streaming = mFdp.ConsumeBool();
    config.offload_info.sample_rate = getSampleRate(&mFdp);
    config.offload_info.stream_type = getValue(&mFdp, kStreamtypes);
    config.offload_info.sync_id = mFdp.ConsumeIntegral<uint32_t>();
    config.offload_info.usage = getValue(&mFdp, kUsages);

    config.format = getValue(&mFdp, kFormats);
    config.sample_rate = getSampleRate(&mFdp);

    sp<DeviceDescriptorBase> device = new DeviceDescriptorBase(getValue(&mFdp, kDevices));
    audio_output_flags_t flags = getValue(&mFdp, kOutputFlags);

    audio_config_base_t mixerConfig = AUDIO_CONFIG_BASE_INITIALIZER;

    media::OpenOutputRequest request{};
    media::OpenOutputResponse response{};

    request.module = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_module_handle_t_int32_t(module));
    request.halConfig = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_config_t_AudioConfig(config));
    request.mixerConfig =
            VALUE_OR_RETURN_STATUS(legacy2aidl_audio_config_base_t_AudioConfigBase(mixerConfig));
    request.device = VALUE_OR_RETURN_STATUS(legacy2aidl_DeviceDescriptorBase(device));
    request.flags = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_output_flags_t_int32_t_mask(flags));

    status_t status = af->openOutput(request, &response);
    if (status != NO_ERROR) {
        return NO_ERROR;
    }
    output = VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_audio_io_handle_t(response.output));

    audio_io_handle_t output1 = mFdp.ConsumeIntegral<int32_t>();
    af->openDuplicateOutput(output, output1);
    af->suspendOutput(output);
    af->restoreOutput(output);
    af->closeOutput(output);
    return NO_ERROR;
}

void AudioFlingerFuzzer::invokeAudioPatch() {
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (!af) {
        return;
    }
    struct audio_patch patch = {};
    audio_patch_handle_t handle = mFdp.ConsumeIntegral<int32_t>();

    patch.id = mFdp.ConsumeIntegral<int32_t>();
    patch.num_sources = mFdp.ConsumeIntegral<uint32_t>();
    patch.num_sinks = mFdp.ConsumeIntegral<uint32_t>();

    for (int i = 0; i < AUDIO_PATCH_PORTS_MAX; ++i) {
        patch.sources[i].config_mask = mFdp.ConsumeIntegral<uint32_t>();
        patch.sources[i].channel_mask = getValue(&mFdp, kChannelMasks);
        patch.sources[i].format = getValue(&mFdp, kFormats);
        patch.sources[i].gain.channel_mask = getValue(&mFdp, kChannelMasks);
        patch.sources[i].gain.index = mFdp.ConsumeIntegral<int32_t>();
        patch.sources[i].gain.mode = getValue(&mFdp, kGainModes);
        patch.sources[i].gain.ramp_duration_ms = mFdp.ConsumeIntegral<uint32_t>();
        patch.sources[i].id = static_cast<audio_format_t>(mFdp.ConsumeIntegral<int32_t>());
        patch.sources[i].role = getValue(&mFdp, kPortRoles);
        patch.sources[i].sample_rate = getSampleRate(&mFdp);
        patch.sources[i].type = getValue(&mFdp, kPortTypes);

        patch.sinks[i].config_mask = mFdp.ConsumeIntegral<uint32_t>();
        patch.sinks[i].channel_mask = getValue(&mFdp, kChannelMasks);
        patch.sinks[i].format = getValue(&mFdp, kFormats);
        patch.sinks[i].gain.channel_mask = getValue(&mFdp, kChannelMasks);
        patch.sinks[i].gain.index = mFdp.ConsumeIntegral<int32_t>();
        patch.sinks[i].gain.mode = getValue(&mFdp, kGainModes);
        patch.sinks[i].gain.ramp_duration_ms = mFdp.ConsumeIntegral<uint32_t>();
        patch.sinks[i].id = static_cast<audio_format_t>(mFdp.ConsumeIntegral<int32_t>());
        patch.sinks[i].role = getValue(&mFdp, kPortRoles);
        patch.sinks[i].sample_rate = getSampleRate(&mFdp);
        patch.sinks[i].type = getValue(&mFdp, kPortTypes);
    }

    status_t status = af->createAudioPatch(&patch, &handle);
    if (status != NO_ERROR) {
        return;
    }

    unsigned int num_patches = mFdp.ConsumeIntegral<uint32_t>();
    struct audio_patch patches = {};
    af->listAudioPatches(&num_patches, &patches);
    af->releaseAudioPatch(handle);
}

void AudioFlingerFuzzer::process() {
    invokeAudioEffect();
    invokeAudioInputDevice();
    invokeAudioOutputDevice();
    invokeAudioPatch();
    invokeAudioRecord();
    invokeAudioSystem();
    invokeAudioTrack();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    AudioFlingerFuzzer audioFuzzer(data, size);
    audioFuzzer.process();
    return 0;
}
