/*
 * Copyright (C) 2026 The Android Open Source Project
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
#define LOG_TAG "AudioTrackMmap"

// go/keep-sorted start
#include <android-base/stringprintf.h>
#include <audio_utils/clock.h>
#include <audio_utils/mutex.h>
#include <binding/AAudioBinderClient.h>
#include <core/AAudioStreamOpenRequest.h>
#include <media/AudioSystem.h>
#include <media/AudioTrackMmap.h>
#include <utility/AAudioUtilities.h>
#include <utils/Log.h>
// go/keep-sorted end

using ::android::base::StringPrintf;

namespace android {

AudioTrackMmap::AudioTrackMmap(SetParams&& params)
        : AudioTrack() {
    // Defer AudioTrack::set to onFirstRef
    mSetParams = std::make_unique<SetParams>(std::move(params));
}

status_t AudioTrackMmap::validateParameters() {
    if (mTransfer != TRANSFER_SYNC_NOTIF_CALLBACK) {
        // The only usage now is from JAVA AudioTrack, which must be using
        // TRANSFER_SYNC_NOTIF_CALLBACK for offload playback.
        return logIfErrorAndReturnStatus(
                BAD_VALUE,
                StringPrintf("Invalid transfer type: %d for using AudioTrackMmap", mTransfer));
    }
    if (!audio_is_linear_pcm(mFormat)) {
        return logIfErrorAndReturnStatus(BAD_VALUE, "AudioTrackMmap only support PCM format");
    }
    if ((mFlags & AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD) == AUDIO_OUTPUT_FLAG_NONE) {
        return logIfErrorAndReturnStatus(BAD_VALUE, "AudioTrackMmap only support offload playback");
    }
    return NO_ERROR;
}

status_t AudioTrackMmap::createTrack_l() {
    if (validateParameters() != NO_ERROR) {
        return mStatus;
    }

    aaudio::AAudioStreamOpenRequest request(nullptr /*parameters*/,
                                            true /*isSharingModeMatchRequired*/);
    request.setFormat(mFormat);
    request.setSampleRate(mSampleRate);
    request.setChannelMask(AAudioConvert_androidToAAudioChannelLayoutMask(
            mChannelMask, false /*isInput*/));
    // Only support offload mode.
    request.setSharingMode(AAUDIO_SHARING_MODE_EXCLUSIVE);
    request.setPerformanceMode(AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED);
    auto attr = mAttributes;
    if (mOriginalStreamType != AUDIO_STREAM_DEFAULT) {
        // Legacy: This is based on original parameters even if the track is recreated.
        AudioSystem::getAttributesForStreamType(mOriginalStreamType, attr);
    }
    request.setUsage(static_cast<aaudio_usage_t>(attr.usage));
    request.setContentType(static_cast<aaudio_content_type_t>(attr.content_type));
    request.setSessionId(mSessionId);
    if (mSelectedDeviceId != AUDIO_PORT_HANDLE_NONE) {
        request.setDeviceIds({mSelectedDeviceId});
    }
    // Always setup data callback. If the transfer type is TRANSFER_SYNC_NOTIF_CALLBACK,
    // it will be set later to convert the callback to a data available callback.
    request.setPartialDataCallbackProcVoid(&aaudioPartialDataCallback);
    request.setDataCallbackUserDataVoid(this);
    request.setPresentationEndCallbackProcVoid(&aaudioPresentationEndCallback);
    request.setPresentationEndCallbackUserDataVoid(this);

    mStream = sp<aaudio::AudioStreamInternalPlay>::make(
            aaudio::AAudioBinderClient::getInstance(), false /*inService*/);
    if (auto result = mStream->open(request) != AAUDIO_OK) {
        return logIfErrorAndReturnStatus(AAudioConvert_aaudioToAndroidStatus(result),
                                         "Failed to open aaudio stream");
    }

    // AudioTrackMmap is only used for Java AudioTrack, which may need data available callback.
    mStream->setUseDataAvailableCallback();

    mFrameSize = mStream->getBytesPerFrame();

    mLatency = 1000LL * mStream->getBufferCapacity() / mStream->getSampleRate();
    mPortId = mStream->getPortId();
    mOutput = mStream->getIoHandle();
    mSessionId = static_cast<audio_session_t>(mStream->getSessionId());
    audio_attributes_t attributes = AUDIO_ATTRIBUTES_INITIALIZER;
    attributes.usage = static_cast<audio_usage_t>(mStream->getUsage());
    attributes.content_type = static_cast<audio_content_type_t>(mStream->getContentType());
    AudioSystem::getStreamTypeForAttributes(attributes, mStreamType);
    mFrameCount = mStream->getBufferCapacity();
    mRoutedDeviceIds = mStream->getDeviceIds();

    mMetricsId = std::string(AMEDIAMETRICS_KEY_PREFIX_AUDIO_TRACK) + std::to_string(mPortId);
    mediametrics::LogItem(mMetricsId)
            .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_CREATE)
                    // the following are immutable
            .set(AMEDIAMETRICS_PROP_FLAGS, toString(mFlags).c_str())
            .set(AMEDIAMETRICS_PROP_ORIGINALFLAGS, toString(mOrigFlags).c_str())
            .set(AMEDIAMETRICS_PROP_SESSIONID, (int32_t)mSessionId)
            .set(AMEDIAMETRICS_PROP_LOGSESSIONID, mLogSessionId)
            .set(AMEDIAMETRICS_PROP_PLAYERIID, mPlayerIId)
            .set(AMEDIAMETRICS_PROP_TRACKID, mPortId) // dup from key
            .set(AMEDIAMETRICS_PROP_CONTENTTYPE, toString(mAttributes.content_type).c_str())
            .set(AMEDIAMETRICS_PROP_USAGE, toString(mAttributes.usage).c_str())
            .set(AMEDIAMETRICS_PROP_THREADID, (int32_t)mOutput)
            .set(AMEDIAMETRICS_PROP_SELECTEDDEVICEID, (int32_t)mSelectedDeviceId)
            .set(AMEDIAMETRICS_PROP_ROUTEDDEVICEID, (int32_t)(getFirstDeviceId(mRoutedDeviceIds)))
            .set(AMEDIAMETRICS_PROP_ROUTEDDEVICEIDS, toString(mRoutedDeviceIds).c_str())
            .set(AMEDIAMETRICS_PROP_ENCODING, toString(mFormat).c_str())
            .set(AMEDIAMETRICS_PROP_CHANNELMASK, (int32_t)mChannelMask)
            .set(AMEDIAMETRICS_PROP_FRAMECOUNT, (int32_t)mFrameCount)
            .set(AMEDIAMETRICS_PROP_CODECPROVENANCE, mCodecProvenance.c_str())
                    // the following are NOT immutable
            .set(AMEDIAMETRICS_PROP_VOLUME_LEFT, (double)mVolume[AUDIO_INTERLEAVE_LEFT])
            .set(AMEDIAMETRICS_PROP_VOLUME_RIGHT, (double)mVolume[AUDIO_INTERLEAVE_RIGHT])
            .set(AMEDIAMETRICS_PROP_STATE, stateToString(mState))
            .set(AMEDIAMETRICS_PROP_STATUS, (int32_t)NO_ERROR)
            .set(AMEDIAMETRICS_PROP_AUXEFFECTID, (int32_t)mAuxEffectId)
            .set(AMEDIAMETRICS_PROP_SAMPLERATE, (int32_t)mSampleRate)
            .set(AMEDIAMETRICS_PROP_PLAYBACK_SPEED, (double)mPlaybackRate.mSpeed)
            .set(AMEDIAMETRICS_PROP_PLAYBACK_PITCH, (double)mPlaybackRate.mPitch)
            .set(AMEDIAMETRICS_PROP_PREFIX_EFFECTIVE
                    AMEDIAMETRICS_PROP_SAMPLERATE, (int32_t)mSampleRate)
            .set(AMEDIAMETRICS_PROP_PREFIX_EFFECTIVE
                    AMEDIAMETRICS_PROP_PLAYBACK_SPEED, (double)mPlaybackRate.mSpeed)
            .set(AMEDIAMETRICS_PROP_PREFIX_EFFECTIVE
                    AMEDIAMETRICS_PROP_PLAYBACK_PITCH, (double)mPlaybackRate.mPitch)
            .record();

    return NO_ERROR;
}

AudioTrackMmap::~AudioTrackMmap() {
    reportUnderrunFrames();
    stopAndJoinCallbacks();
    if (mStream != nullptr) {
        mStream->safeReleaseClose();
        mStream.clear();
    }
}

uint32_t AudioTrackMmap::getSampleRate() const {
    AutoMutex lock(mLock);
    return mStream->getSampleRate();
}

status_t AudioTrackMmap::start() {
    const int64_t beginNs = systemTime();
    status_t status = NO_ERROR;
    mediametrics::Defer defer([&] {
        mediametrics::LogItem(mMetricsId)
                .set(AMEDIAMETRICS_PROP_CALLERNAME,
                     mCallerName.empty()
                     ? AMEDIAMETRICS_PROP_CALLERNAME_VALUE_UNKNOWN
                     : mCallerName.c_str())
                .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_START)
                .set(AMEDIAMETRICS_PROP_EXECUTIONTIMENS, (int64_t)(systemTime() - beginNs))
                .set(AMEDIAMETRICS_PROP_STATE, stateToString(mState))
                .set(AMEDIAMETRICS_PROP_STATUS, (int32_t)status)
                .record(); });
    AutoMutex lock(mLock);
    status = mStream->systemStart() == AAUDIO_OK ? OK :
            logIfErrorAndReturnStatus(DEAD_OBJECT, "Failed to start aaudio stream");
    mState = STATE_ACTIVE;
    // resume or pause the callback thread as needed.
    sp<AudioTrackThread> t = mAudioTrackThread;
    if (t != nullptr) {
        if (status == NO_ERROR) {
            t->resume();
        } else {
            t->pause();
        }
    }
    return status;
}

void AudioTrackMmap::stop() {
    const int64_t beginNs = systemTime();
    mediametrics::Defer defer([&]() {
        mediametrics::LogItem(mMetricsId)
                .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_STOP)
                .set(AMEDIAMETRICS_PROP_EXECUTIONTIMENS, (int64_t)(systemTime() - beginNs))
                .set(AMEDIAMETRICS_PROP_STATE, stateToString(mState))
                .set(AMEDIAMETRICS_PROP_BUFFERSIZEFRAMES, (int32_t)getBufferSizeInFrames())
                .set(AMEDIAMETRICS_PROP_UNDERRUN, (int32_t) getUnderrunCount_l())
                .record();
    });
    AutoMutex lock(mLock);
    if (mState != STATE_ACTIVE && mState != STATE_PAUSED) {
        return;
    }
    mState = STATE_STOPPING;
    mStream->systemStopFromApp();
    sp<AudioTrackThread> t = mAudioTrackThread;
    if (t != nullptr) {
        // causes wake up of the playback thread, that will callback the client for
        // stream end callback in processAudioBuffer()
        t->wake();
    }
}

void AudioTrackMmap::pause() {
    const int64_t beginNs = systemTime();
    mediametrics::Defer defer([&]() {
    mediametrics::LogItem(mMetricsId)
            .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_PAUSE)
            .set(AMEDIAMETRICS_PROP_EXECUTIONTIMENS, (int64_t)(systemTime() - beginNs))
            .set(AMEDIAMETRICS_PROP_STATE, stateToString(mState))
            .record(); });
    AutoMutex lock(mLock);
    mStream->systemPause();
    mState = mState == STATE_STOPPING ? STATE_PAUSED_STOPPING : STATE_PAUSED;
}

void AudioTrackMmap::flush() {
    const int64_t beginNs = systemTime();
    mediametrics::Defer defer([&]() {
        mediametrics::LogItem(mMetricsId)
                .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_FLUSH)
                .set(AMEDIAMETRICS_PROP_EXECUTIONTIMENS, (int64_t)(systemTime() - beginNs))
                .set(AMEDIAMETRICS_PROP_STATE, stateToString(mState))
                .record(); });
    AutoMutex lock(mLock);
    if (mState == STATE_ACTIVE) {
        return;
    }
    mStream->safeFlush();
    mState = STATE_FLUSHED;
}

ssize_t AudioTrackMmap::getBufferSizeInFrames() {
    AutoMutex lock(mLock);
    return mStream->getBufferSize();
}

ssize_t AudioTrackMmap::setBufferSizeInFrames(size_t size) {
    AutoMutex lock(mLock);
    return mStream->setBufferSize(size);
}

const AudioPlaybackRate& AudioTrackMmap::getPlaybackRate() {
    AAudioPlaybackParameters parameters;
    aaudio_result_t result = AAUDIO_OK;
    AutoMutex lock(mLock);
    if (result = mStream->getPlaybackParameters(&parameters); result != AAUDIO_OK) {
        return mPlaybackRate;
    }
    AudioPlaybackRate playbackRate;
    if (result = AAudioConvert_aaudioToAndroidPlaybackParameters(parameters, &playbackRate);
        result != AAUDIO_OK) {
        return mPlaybackRate;
    }
    mPlaybackRate = playbackRate;
    return mPlaybackRate;
}

status_t AudioTrackMmap::setPlaybackRate(const AudioPlaybackRate &playbackRate) {
    AAudioPlaybackParameters parameters;
    if (const auto result = AAudioConvert_androidToAAudioPlaybackParameters(
                playbackRate, &parameters);
            result != AAUDIO_OK) {
        ALOGE("%s, failed to set playback rate due to conversion failure", __func__);
        return AAudioConvert_aaudioToAndroidStatus(result);
    }
    AutoMutex lock(mLock);
    if (auto result = mStream->setPlaybackParameters(&parameters); result == AAUDIO_OK) {
        mPlaybackRate = playbackRate;
        return NO_ERROR;
    } else {
        return AAudioConvert_aaudioToAndroidStatus(result);
    }
}

int64_t AudioTrackMmap::getWrittenFramesCount() const {
    AutoMutex lock(mLock);
    return mStream->getFramesWritten() + mFramesWrittenOffset;
}

status_t AudioTrackMmap::getPosition(uint32_t* position) {
    AutoMutex lock(mLock);
    *position = mStream->getFramesRead() + mFramesReadOffset;
    return NO_ERROR;
}

uint32_t AudioTrackMmap::latency() {
    AutoMutex lock(mLock);
    return mLatency;
}

uint32_t AudioTrackMmap::getUnderrunCount() const {
    AutoMutex lock(mLock);
    return getUnderrunCount_l();
}

uint32_t AudioTrackMmap::getUnderrunCount_l() const {
    return mStream->getXRunCount();
}

audio_output_flags_t AudioTrackMmap::getFlags() const {
    static const audio_output_flags_t kMmapOffloadFlags = static_cast<audio_output_flags_t>(
            AUDIO_OUTPUT_FLAG_DIRECT | AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD
            | AUDIO_OUTPUT_FLAG_MMAP_NOIRQ);
    return kMmapOffloadFlags;
}

status_t AudioTrackMmap::getTimestamp(AudioTimestamp& timestamp) {
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    int64_t nanos = 0;
    int64_t position = 0;
    aaudio_result_t result = AAUDIO_OK;
    {
        AutoMutex lock(mLock);
        result = mStream->getTimestamp(CLOCK_MONOTONIC, &position, &nanos);
    }
    if (result == AAUDIO_OK) {
        timestamp.mTime.tv_sec = static_cast<time_t>(nanos / NANOS_PER_SECOND);
        timestamp.mTime.tv_nsec = static_cast<int64_t>(nanos % NANOS_PER_SECOND);
        timestamp.mPosition = position;
        AutoMutex lock(mLock);
        mLastReportedPosition = position;
    } else {
        // AAudio will only have valid timestamp when there is timestamp reported from the HAL.
        // In that case, at the beginning of a stream, there may not be any valid timestamp and
        // aaudio will return error. Use current time and last reported position in this case.
        (void) clock_gettime(CLOCK_MONOTONIC, &timestamp.mTime);
        AutoMutex lock(mLock);
        timestamp.mPosition = mLastReportedPosition;
    }
    return NO_ERROR;
}

status_t AudioTrackMmap::setOutputDevice(audio_port_handle_t deviceId) {
    const int64_t beginNs = systemTime();
    mediametrics::Defer defer([&] {
        mediametrics::LogItem(mMetricsId)
                .set(AMEDIAMETRICS_PROP_CALLERNAME,
                     mCallerName.empty()
                     ? AMEDIAMETRICS_PROP_CALLERNAME_VALUE_UNKNOWN
                     : mCallerName.c_str())
                .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_SETPREFERREDDEVICE)
                .set(AMEDIAMETRICS_PROP_EXECUTIONTIMENS, (int64_t)(systemTime() - beginNs))
                .set(AMEDIAMETRICS_PROP_SELECTEDDEVICEID, (int32_t)deviceId)
                .record(); });
    if (mSelectedDeviceId == deviceId) {
        return NO_ERROR;
    }
    if (mStatus != NO_ERROR || mStream->isActive()) {
        return INVALID_OPERATION;
    }
    mSelectedDeviceId = deviceId;
    {
        AutoMutex lock(mLock);
        mFramesWrittenOffset += mStream->getFramesWritten();
        mFramesReadOffset += mStream->getFramesRead();
        createTrack_l();
    }
    return mStatus;
}

DeviceIdVector AudioTrackMmap::getRoutedDeviceIds() {
    AutoMutex lock(mLock);
    mRoutedDeviceIds = mStream->getDeviceIds();
    return mRoutedDeviceIds;
}

ssize_t AudioTrackMmap::write(const void* buffer, size_t size, bool blocking) {
    const int32_t numFrames= size / mFrameSize;
    int64_t timeoutNanos = blocking ? numFrames * NANOS_PER_SECOND / mStream->getSampleRate() : 0;
    AutoMutex lock(mLock);
    aaudio_result_t result = mStream->write(buffer, numFrames, timeoutNanos);
    if (result < 0) {
        return logIfErrorAndReturnStatus(AAudioConvert_aaudioToAndroidStatus(result),
                                  "Failed to write to aaudio stream");
    }

    if (result >= 0) {
        const sp <AudioTrackThread> t = mAudioTrackThread;
        if (t != 0) {
            // causes wake up of the playback thread, that will callback the client for
            // more data in processAudioBuffer()
            t->wake();
        }
        result *= mFrameSize;
    }
    return result;
}

nsecs_t AudioTrackMmap::processAudioBuffer() {
    sp<IAudioTrackCallback> callback = nullptr;
    {
        AutoMutex lock(mLock);
        callback = mCallback.promote();
        if (callback == nullptr) {
            mCallback = nullptr;
            return NS_NEVER;
        }
    }
    audio_utils::unique_lock ul(mMmapCbMutex);
    mMmapCbCond.wait(ul);
    while (!mCbEvents.empty()) {
        const auto& event = mCbEvents.front();
        switch (event.mEvent) {
            case EVENT_MORE_DATA_AVAILABLE: {
                Buffer buffer;
                buffer.frameCount = std::get<int32_t>(event.mParams);
                buffer.mSize = buffer.frameCount * mFrameSize;
                // onCanWriteMoreData doesn't process data, it should be safe to use nullptr here.
                buffer.raw = nullptr;
                callback->onCanWriteMoreData(buffer);
            } break;
            case EVENT_STREAM_END: {
                callback->onStreamEnd();
                {
                    AutoMutex lock(mLock);
                    if (mState == STATE_STOPPING) {
                        mState = STATE_STOPPED;
                    }
                }
            } break;
            case EVENT_ROUTED_DEVICE_CHANGED: {
                sp<AudioSystem::AudioDeviceCallback> callback;
                {
                    AutoMutex lock(mLock);
                    callback = mDeviceCallback.promote();
                }
                if (callback != nullptr) {
                    callback->onAudioDeviceUpdate(mOutput, std::get<DeviceIdVector>(event.mParams));
                }
            }
        }
        mCbEvents.pop_front();
    }
    return NS_WHENEVER;
}
void AudioTrackMmap::stopAndJoinCallbacks() {
    {
        AutoMutex lock(mLock);
        if (mStream != nullptr) {
            mStream->systemStopFromApp();
        }
    }
    if (mAudioTrackThread != nullptr) {
        mAudioTrackThread->requestExit();
        mMmapCbCond.notify_one();
        mAudioTrackThread->requestExitAndWait();
        mAudioTrackThread.clear();
    }
}

ssize_t AudioTrackMmap::getStartThresholdInFrames() const {
    return 0;
}

ssize_t AudioTrackMmap::setStartThresholdInFrames(size_t /*startThresholdInFrames*/) {
    // AAudio always start when there is data available.
    return 0;
}

uint32_t AudioTrackMmap::getUnderrunFrames() const {
    return getUnderrunCount();
}

void AudioTrackMmap::reportUnderrunFrames() {
    AutoMutex lock(mLock);
    mUnderrunFramesReported = getUnderrunCount_l();
}

//=============================================================================

// static
int32_t AudioTrackMmap::aaudioPartialDataCallback(
        AAudioStream* /*stream*/, void* userData, void* /*audioData*/, int32_t numFrames) {
    // The AudioTrackMmap must be alive when there is a data callback fired as the stream
    // is not closed when the data callback is active.
    AudioTrackMmap* audioTrackMmap = reinterpret_cast<AudioTrackMmap*>(userData);
    return audioTrackMmap->aaudioPartialDataCallbackImpl(numFrames);
}

int32_t AudioTrackMmap::aaudioPartialDataCallbackImpl(int32_t numFrames) {
    std::lock_guard _l(mMmapCbMutex);
    CallbackEvent event = {
            .mEvent = EVENT_MORE_DATA_AVAILABLE,
            .mParams = numFrames,
    };
    mCbEvents.push_back(std::move(event));
    mMmapCbCond.notify_one();
    return 0;
}

// static
void AudioTrackMmap::aaudioPresentationEndCallback(AAudioStream* /*stream*/, void* userData) {
    AudioTrackMmap* audioTrackMmap = reinterpret_cast<AudioTrackMmap*>(userData);
    audioTrackMmap->aaudioPresentationEndCallbackImpl();
}

void AudioTrackMmap::aaudioPresentationEndCallbackImpl() {
    std::lock_guard _l(mMmapCbMutex);
    CallbackEvent event = {
            .mEvent = EVENT_STREAM_END,
    };
    mCbEvents.push_back(std::move(event));
    mMmapCbCond.notify_one();
}

//======================= Unsupported functions ===============================

status_t AudioTrackMmap::setVolume(float /*left*/, float /*right*/) {
    return INVALID_OPERATION;
}

status_t AudioTrackMmap::setSampleRate(uint32_t /*sampleRate*/) {
    return INVALID_OPERATION;
}

status_t AudioTrackMmap::setMarkerPosition(uint32_t /*marker*/) {
    return INVALID_OPERATION;
}

status_t AudioTrackMmap::getMarkerPosition(uint32_t* /*marker*/) const {
    return INVALID_OPERATION;
}

status_t AudioTrackMmap::setPositionUpdatePeriod(uint32_t /*updatePeriod*/) {
    return INVALID_OPERATION;
}

status_t AudioTrackMmap::getPositionUpdatePeriod(uint32_t* /*updatePeriod*/) const {
    return INVALID_OPERATION;
}

status_t AudioTrackMmap::setPosition(uint32_t /*position*/) {
    return INVALID_OPERATION;
}

status_t AudioTrackMmap::setLoop(uint32_t /*loopStart*/, uint32_t /*loopEnd*/, int /*loopCount*/) {
    return INVALID_OPERATION;
}

status_t AudioTrackMmap::reload() {
    return INVALID_OPERATION;
}

status_t AudioTrackMmap::setAuxEffectSendLevel(float /*level*/) {
    return INVALID_OPERATION;
}

status_t AudioTrackMmap::attachAuxEffect(int /*effectId*/) {
    return INVALID_OPERATION;
}

media::VolumeShaper::Status AudioTrackMmap::applyVolumeShaper(
        const sp<media::VolumeShaper::Configuration>& /*configuration*/,
        const sp<media::VolumeShaper::Operation>& /*operation*/) {
    return INVALID_OPERATION;
}

sp<media::VolumeShaper::State> AudioTrackMmap::getVolumeShaperState(int /*id*/) {
    return nullptr;
}

status_t AudioTrackMmap::selectPresentation(int /*presentationId*/, int /*programId*/) {
    return INVALID_OPERATION;
}

status_t AudioTrackMmap::setParameters(const String8& /*keyValuePairs*/) {
    return INVALID_OPERATION;
}

status_t AudioTrackMmap::setAudioDescriptionMixLevel(float /*leveldB*/) {
    return INVALID_OPERATION;
}

status_t AudioTrackMmap::getAudioDescriptionMixLevel(float* /*leveldB*/) const {
    return INVALID_OPERATION;
}

status_t AudioTrackMmap::setDualMonoMode(audio_dual_mono_mode_t /*mode*/) {
    return INVALID_OPERATION;
}

status_t AudioTrackMmap::getDualMonoMode(audio_dual_mono_mode_t* /*mode*/) const {
    return INVALID_OPERATION;
}

} // namespace android
