/*
 * Copyright (C) 2021 The Android Open Source Project
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
#define LOG_TAG "AudioTestUtils"

#include <android-base/file.h>
#include <system/audio_config.h>
#include <utils/Log.h>

#include "audio_test_utils.h"

#define WAIT_PERIOD_MS 10  // from AudioTrack.cpp
#define MAX_WAIT_TIME_MS 5000

void OnAudioDeviceUpdateNotifier::onAudioDeviceUpdate(audio_io_handle_t audioIo,
                                                      audio_port_handle_t deviceId) {
    std::unique_lock<std::mutex> lock{mMutex};
    ALOGI("%s: audioIo=%d deviceId=%d", __func__, audioIo, deviceId);
    mAudioIo = audioIo;
    mDeviceId = deviceId;
    mCondition.notify_all();
}

status_t OnAudioDeviceUpdateNotifier::waitForAudioDeviceCb(audio_port_handle_t expDeviceId) {
    std::unique_lock<std::mutex> lock{mMutex};
    if (mAudioIo == AUDIO_IO_HANDLE_NONE ||
        (expDeviceId != AUDIO_PORT_HANDLE_NONE && expDeviceId != mDeviceId)) {
        mCondition.wait_for(lock, std::chrono::milliseconds(500));
        if (mAudioIo == AUDIO_IO_HANDLE_NONE ||
            (expDeviceId != AUDIO_PORT_HANDLE_NONE && expDeviceId != mDeviceId))
            return TIMED_OUT;
    }
    return OK;
}

AudioPlayback::AudioPlayback(uint32_t sampleRate, audio_format_t format,
                             audio_channel_mask_t channelMask, audio_output_flags_t flags,
                             audio_session_t sessionId, AudioTrack::transfer_type transferType,
                             audio_attributes_t* attributes, audio_offload_info_t* info)
    : mSampleRate(sampleRate),
      mFormat(format),
      mChannelMask(channelMask),
      mFlags(flags),
      mSessionId(sessionId),
      mTransferType(transferType),
      mAttributes(attributes),
      mOffloadInfo(info) {
    mStopPlaying = false;
    mBytesUsedSoFar = 0;
    mState = PLAY_NO_INIT;
    mMemCapacity = 0;
    mMemoryDealer = nullptr;
    mMemory = nullptr;
}

AudioPlayback::~AudioPlayback() {
    stop();
}

status_t AudioPlayback::create() {
    if (mState != PLAY_NO_INIT) return INVALID_OPERATION;
    std::string packageName{"AudioPlayback"};
    AttributionSourceState attributionSource;
    attributionSource.packageName = packageName;
    attributionSource.uid = VALUE_OR_FATAL(legacy2aidl_uid_t_int32_t(getuid()));
    attributionSource.pid = VALUE_OR_FATAL(legacy2aidl_pid_t_int32_t(getpid()));
    attributionSource.token = sp<BBinder>::make();
    if (mTransferType == AudioTrack::TRANSFER_OBTAIN) {
        mTrack = new AudioTrack(attributionSource);
        mTrack->set(AUDIO_STREAM_MUSIC, mSampleRate, mFormat, mChannelMask, 0 /* frameCount */,
                    mFlags, nullptr /* callback */, 0 /* notificationFrames */,
                    nullptr /* sharedBuffer */, false /*canCallJava */, mSessionId, mTransferType,
                    mOffloadInfo, attributionSource, mAttributes);
    } else if (mTransferType == AudioTrack::TRANSFER_SHARED) {
        mTrack = new AudioTrack(AUDIO_STREAM_MUSIC, mSampleRate, mFormat, mChannelMask, mMemory,
                                mFlags, wp<AudioTrack::IAudioTrackCallback>::fromExisting(this), 0,
                                mSessionId, mTransferType, nullptr, attributionSource, mAttributes);
    } else {
        ALOGE("Test application is not handling transfer type %s",
              AudioTrack::convertTransferToText(mTransferType));
        return INVALID_OPERATION;
    }
    mTrack->setCallerName(packageName);
    status_t status = mTrack->initCheck();
    if (NO_ERROR == status) mState = PLAY_READY;
    return status;
}

status_t AudioPlayback::loadResource(const char* name) {
    status_t status = OK;
    FILE* fp = fopen(name, "rbe");
    struct stat buf {};
    if (fp && !fstat(fileno(fp), &buf)) {
        mMemCapacity = buf.st_size;
        mMemoryDealer = new MemoryDealer(mMemCapacity, "AudioPlayback");
        if (nullptr == mMemoryDealer.get()) {
            ALOGE("couldn't get MemoryDealer!");
            fclose(fp);
            return NO_MEMORY;
        }
        mMemory = mMemoryDealer->allocate(mMemCapacity);
        if (nullptr == mMemory.get()) {
            ALOGE("couldn't get IMemory!");
            fclose(fp);
            return NO_MEMORY;
        }
        uint8_t* ipBuffer = static_cast<uint8_t*>(static_cast<void*>(mMemory->unsecurePointer()));
        fread(ipBuffer, sizeof(uint8_t), mMemCapacity, fp);
    } else {
        ALOGE("unable to open input file %s", name);
        status = NAME_NOT_FOUND;
    }
    if (fp) fclose(fp);
    return status;
}

sp<AudioTrack> AudioPlayback::getAudioTrackHandle() {
    return (PLAY_NO_INIT != mState) ? mTrack : nullptr;
}

status_t AudioPlayback::start() {
    status_t status;
    if (PLAY_READY != mState) {
        return INVALID_OPERATION;
    } else {
        status = mTrack->start();
        if (OK == status) {
            mState = PLAY_STARTED;
            LOG_FATAL_IF(false != mTrack->stopped());
        }
    }
    return status;
}

void AudioPlayback::onBufferEnd() {
    std::unique_lock<std::mutex> lock{mMutex};
    mStopPlaying = true;
    mCondition.notify_all();
}

status_t AudioPlayback::fillBuffer() {
    if (PLAY_STARTED != mState) return INVALID_OPERATION;
    const int maxTries = MAX_WAIT_TIME_MS / WAIT_PERIOD_MS;
    int counter = 0;
    uint8_t* ipBuffer = static_cast<uint8_t*>(static_cast<void*>(mMemory->unsecurePointer()));
    size_t nonContig = 0;
    size_t bytesAvailable = mMemCapacity - mBytesUsedSoFar;
    while (bytesAvailable > 0) {
        AudioTrack::Buffer trackBuffer;
        trackBuffer.frameCount = mTrack->frameCount() * 2;
        status_t status = mTrack->obtainBuffer(&trackBuffer, 1, &nonContig);
        if (OK == status) {
            size_t bytesToCopy = std::min(bytesAvailable, trackBuffer.size());
            if (bytesToCopy > 0) {
                memcpy(trackBuffer.data(), ipBuffer + mBytesUsedSoFar, bytesToCopy);
            }
            mTrack->releaseBuffer(&trackBuffer);
            mBytesUsedSoFar += bytesToCopy;
            bytesAvailable = mMemCapacity - mBytesUsedSoFar;
            counter = 0;
        } else if (WOULD_BLOCK == status) {
            // if not received a buffer for MAX_WAIT_TIME_MS, something has gone wrong
            if (counter == maxTries) return TIMED_OUT;
            counter++;
        }
    }
    return OK;
}

status_t AudioPlayback::waitForConsumption(bool testSeek) {
    if (PLAY_STARTED != mState) return INVALID_OPERATION;

    const int maxTries = MAX_WAIT_TIME_MS / WAIT_PERIOD_MS;
    int counter = 0;
    size_t totalFrameCount = mMemCapacity / mTrack->frameSize();
    while (!mStopPlaying && counter < maxTries) {
        uint32_t currPosition;
        mTrack->getPosition(&currPosition);
        if (currPosition >= totalFrameCount) counter++;

        if (testSeek && (currPosition > totalFrameCount * 0.6)) {
            testSeek = false;
            if (!mTrack->hasStarted()) return BAD_VALUE;
            mTrack->pauseAndWait(std::chrono::seconds(2));
            if (mTrack->hasStarted()) return BAD_VALUE;
            mTrack->reload();
            mTrack->getPosition(&currPosition);
            if (currPosition != 0) return BAD_VALUE;
            mTrack->start();
            while (currPosition < totalFrameCount * 0.3) {
                mTrack->getPosition(&currPosition);
            }
            mTrack->pauseAndWait(std::chrono::seconds(2));
            uint32_t setPosition = totalFrameCount * 0.9;
            mTrack->setPosition(setPosition);
            uint32_t bufferPosition;
            mTrack->getBufferPosition(&bufferPosition);
            if (bufferPosition != setPosition) return BAD_VALUE;
            mTrack->start();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_PERIOD_MS));
    }
    if (!mStopPlaying && counter == maxTries) return TIMED_OUT;
    return OK;
}

status_t AudioPlayback::onProcess(bool testSeek) {
    if (mTransferType == AudioTrack::TRANSFER_SHARED)
        return waitForConsumption(testSeek);
    else if (mTransferType == AudioTrack::TRANSFER_OBTAIN)
        return fillBuffer();
    else
        return INVALID_OPERATION;
}

void AudioPlayback::stop() {
    std::unique_lock<std::mutex> lock{mMutex};
    mStopPlaying = true;
    if (mState != PLAY_STOPPED && mState != PLAY_NO_INIT) {
        int32_t msec = 0;
        (void)mTrack->pendingDuration(&msec);
        mTrack->stopAndJoinCallbacks();
        LOG_FATAL_IF(true != mTrack->stopped());
        mState = PLAY_STOPPED;
        if (msec > 0) {
            ALOGD("deleting recycled track, waiting for data drain (%d msec)", msec);
            usleep(msec * 1000LL);
        }
    }
}

// hold pcm data sent by AudioRecord
RawBuffer::RawBuffer(int64_t ptsPipeline, int64_t ptsManual, int32_t capacity)
    : mData(capacity > 0 ? new uint8_t[capacity] : nullptr),
      mPtsPipeline(ptsPipeline),
      mPtsManual(ptsManual),
      mCapacity(capacity) {}

// Simple AudioCapture
size_t AudioCapture::onMoreData(const AudioRecord::Buffer& buffer) {
    if (mState != REC_STARTED) {
        ALOGE("Unexpected Callback from audiorecord, not reading data");
        return 0;
    }

    // no more frames to read
    if (mNumFramesReceived >= mNumFramesToRecord || mStopRecording) {
        mStopRecording = true;
        return 0;
    }

    int64_t timeUs = 0, position = 0, timeNs = 0;
    ExtendedTimestamp ts;
    ExtendedTimestamp::Location location;
    const int32_t usPerSec = 1000000;

    if (mRecord->getTimestamp(&ts) == OK &&
        ts.getBestTimestamp(&position, &timeNs, ExtendedTimestamp::TIMEBASE_MONOTONIC, &location) ==
                OK) {
        // Use audio timestamp.
        timeUs = timeNs / 1000 -
                 (position - mNumFramesReceived + mNumFramesLost) * usPerSec / mSampleRate;
    } else {
        // This should not happen in normal case.
        ALOGW("Failed to get audio timestamp, fallback to use systemclock");
        timeUs = systemTime() / 1000LL;
        // Estimate the real sampling time of the 1st sample in this buffer
        // from AudioRecord's latency. (Apply this adjustment first so that
        // the start time logic is not affected.)
        timeUs -= mRecord->latency() * 1000LL;
    }

    ALOGV("dataCallbackTimestamp: %" PRId64 " us", timeUs);

    const size_t frameSize = mRecord->frameSize();
    uint64_t numLostBytes = (uint64_t)mRecord->getInputFramesLost() * frameSize;
    if (numLostBytes > 0) {
        ALOGW("Lost audio record data: %" PRIu64 " bytes", numLostBytes);
    }
    std::deque<RawBuffer> tmpQueue;
    while (numLostBytes > 0) {
        uint64_t bufferSize = numLostBytes;
        if (numLostBytes > mMaxBytesPerCallback) {
            numLostBytes -= mMaxBytesPerCallback;
            bufferSize = mMaxBytesPerCallback;
        } else {
            numLostBytes = 0;
        }
        const int64_t timestampUs =
                ((1000000LL * mNumFramesReceived) + (mRecord->getSampleRate() >> 1)) /
                mRecord->getSampleRate();
        RawBuffer emptyBuffer{timeUs, timestampUs, static_cast<int32_t>(bufferSize)};
        memset(emptyBuffer.mData.get(), 0, bufferSize);
        mNumFramesLost += bufferSize / frameSize;
        mNumFramesReceived += bufferSize / frameSize;
        tmpQueue.push_back(std::move(emptyBuffer));
    }

    if (buffer.size() == 0) {
        ALOGW("Nothing is available from AudioRecord callback buffer");
    } else {
        const size_t bufferSize = buffer.size();
        const int64_t timestampUs =
                ((1000000LL * mNumFramesReceived) + (mRecord->getSampleRate() >> 1)) /
                mRecord->getSampleRate();
        RawBuffer audioBuffer{timeUs, timestampUs, static_cast<int32_t>(bufferSize)};
        memcpy(audioBuffer.mData.get(), buffer.data(), bufferSize);
        mNumFramesReceived += bufferSize / frameSize;
        tmpQueue.push_back(std::move(audioBuffer));
    }

    if (tmpQueue.size() > 0) {
        std::unique_lock<std::mutex> lock{mMutex};
        for (auto it = tmpQueue.begin(); it != tmpQueue.end(); it++)
            mBuffersReceived.push_back(std::move(*it));
        mCondition.notify_all();
    }
    return buffer.size();
}

void AudioCapture::onOverrun() {
    ALOGV("received event overrun");
    mBufferOverrun = true;
}

void AudioCapture::onMarker(uint32_t markerPosition) {
    ALOGV("received Callback at position %d", markerPosition);
    mReceivedCbMarkerAtPosition = markerPosition;
}

void AudioCapture::onNewPos(uint32_t markerPosition) {
    ALOGV("received Callback at position %d", markerPosition);
    mReceivedCbMarkerCount++;
}

void AudioCapture::onNewIAudioRecord() {
    ALOGV("IAudioRecord is re-created");
}

AudioCapture::AudioCapture(audio_source_t inputSource, uint32_t sampleRate, audio_format_t format,
                           audio_channel_mask_t channelMask, audio_input_flags_t flags,
                           audio_session_t sessionId, AudioRecord::transfer_type transferType,
                           const audio_attributes_t* attributes)
    : mInputSource(inputSource),
      mSampleRate(sampleRate),
      mFormat(format),
      mChannelMask(channelMask),
      mFlags(flags),
      mSessionId(sessionId),
      mTransferType(transferType),
      mAttributes(attributes) {
    mFrameCount = 0;
    mNotificationFrames = 0;
    mNumFramesToRecord = 0;
    mNumFramesReceived = 0;
    mNumFramesLost = 0;
    mBufferOverrun = false;
    mMarkerPosition = 0;
    mMarkerPeriod = 0;
    mReceivedCbMarkerAtPosition = -1;
    mReceivedCbMarkerCount = 0;
    mState = REC_NO_INIT;
    mStopRecording = false;
}

AudioCapture::~AudioCapture() {
    if (mOutFileFd > 0) close(mOutFileFd);
    stop();
}

status_t AudioCapture::create() {
    if (mState != REC_NO_INIT) return INVALID_OPERATION;
    // get Min Frame Count
    size_t minFrameCount;
    status_t status =
            AudioRecord::getMinFrameCount(&minFrameCount, mSampleRate, mFormat, mChannelMask);
    if (NO_ERROR != status) return status;
    // Limit notificationFrames basing on client bufferSize
    const int samplesPerFrame = audio_channel_count_from_in_mask(mChannelMask);
    const int bytesPerSample = audio_bytes_per_sample(mFormat);
    mNotificationFrames = mMaxBytesPerCallback / (samplesPerFrame * bytesPerSample);
    // select frameCount to be at least minFrameCount
    mFrameCount = 2 * mNotificationFrames;
    while (mFrameCount < minFrameCount) {
        mFrameCount += mNotificationFrames;
    }
    if (mFlags & AUDIO_INPUT_FLAG_FAST) {
        ALOGW("Overriding all previous computations");
        mFrameCount = 0;
        mNotificationFrames = 0;
    }
    mNumFramesToRecord = (mSampleRate * 0.25);  // record .25 sec
    std::string packageName{"AudioCapture"};
    AttributionSourceState attributionSource;
    attributionSource.packageName = packageName;
    attributionSource.uid = VALUE_OR_FATAL(legacy2aidl_uid_t_int32_t(getuid()));
    attributionSource.pid = VALUE_OR_FATAL(legacy2aidl_pid_t_int32_t(getpid()));
    attributionSource.token = sp<BBinder>::make();
    if (mTransferType == AudioRecord::TRANSFER_OBTAIN) {
        if (mSampleRate == 48000) {  // test all available constructors
            mRecord = new AudioRecord(mInputSource, mSampleRate, mFormat, mChannelMask,
                                      attributionSource, mFrameCount, nullptr /* callback */,
                                      mNotificationFrames, mSessionId, mTransferType, mFlags,
                                      mAttributes);
        } else {
            mRecord = new AudioRecord(attributionSource);
            status = mRecord->set(mInputSource, mSampleRate, mFormat, mChannelMask, mFrameCount,
                                  nullptr /* callback */, 0 /* notificationFrames */,
                                  false /* canCallJava */, mSessionId, mTransferType, mFlags,
                                  attributionSource.uid, attributionSource.pid, mAttributes);
        }
        if (NO_ERROR != status) return status;
    } else if (mTransferType == AudioRecord::TRANSFER_CALLBACK) {
        mRecord = new AudioRecord(mInputSource, mSampleRate, mFormat, mChannelMask,
                                  attributionSource, mFrameCount, this, mNotificationFrames,
                                  mSessionId, mTransferType, mFlags, mAttributes);
    } else {
        ALOGE("Test application is not handling transfer type %s",
              AudioRecord::convertTransferToText(mTransferType));
        return NO_INIT;
    }
    mRecord->setCallerName(packageName);
    status = mRecord->initCheck();
    if (NO_ERROR == status) mState = REC_READY;
    if (mFlags & AUDIO_INPUT_FLAG_FAST) {
        mFrameCount = mRecord->frameCount();
        mNotificationFrames = mRecord->getNotificationPeriodInFrames();
        mMaxBytesPerCallback = mNotificationFrames * samplesPerFrame * bytesPerSample;
    }
    return status;
}

status_t AudioCapture::setRecordDuration(float durationInSec) {
    if (REC_READY != mState) {
        return INVALID_OPERATION;
    }
    uint32_t sampleRate = mSampleRate == 0 ? mRecord->getSampleRate() : mSampleRate;
    mNumFramesToRecord = (sampleRate * durationInSec);
    return OK;
}

status_t AudioCapture::enableRecordDump() {
    if (mOutFileFd != -1) {
        return INVALID_OPERATION;
    }
    TemporaryFile tf("/data/local/tmp");
    tf.DoNotRemove();
    mOutFileFd = tf.release();
    mFileName = std::string{tf.path};
    return OK;
}

sp<AudioRecord> AudioCapture::getAudioRecordHandle() {
    return (REC_NO_INIT == mState) ? nullptr : mRecord;
}

status_t AudioCapture::start(AudioSystem::sync_event_t event, audio_session_t triggerSession) {
    status_t status;
    if (REC_READY != mState) {
        return INVALID_OPERATION;
    } else {
        status = mRecord->start(event, triggerSession);
        if (OK == status) {
            mState = REC_STARTED;
            LOG_FATAL_IF(false != mRecord->stopped());
        }
    }
    return status;
}

status_t AudioCapture::stop() {
    status_t status = OK;
    mStopRecording = true;
    if (mState != REC_STOPPED && mState != REC_NO_INIT) {
        if (mInputSource != AUDIO_SOURCE_DEFAULT) {
            bool state = false;
            status = AudioSystem::isSourceActive(mInputSource, &state);
            if (status == OK && !state) status = BAD_VALUE;
        }
        mRecord->stopAndJoinCallbacks();
        mState = REC_STOPPED;
        LOG_FATAL_IF(true != mRecord->stopped());
    }
    return status;
}

status_t AudioCapture::obtainBuffer(RawBuffer& buffer) {
    if (REC_STARTED != mState) return INVALID_OPERATION;
    const int maxTries = MAX_WAIT_TIME_MS / WAIT_PERIOD_MS;
    int counter = 0;
    size_t nonContig = 0;
    while (mNumFramesReceived < mNumFramesToRecord) {
        AudioRecord::Buffer recordBuffer;
        recordBuffer.frameCount = mNotificationFrames;
        status_t status = mRecord->obtainBuffer(&recordBuffer, 1, &nonContig);
        if (OK == status) {
            const int64_t timestampUs =
                    ((1000000LL * mNumFramesReceived) + (mRecord->getSampleRate() >> 1)) /
                    mRecord->getSampleRate();
            RawBuffer buff{-1, timestampUs, static_cast<int32_t>(recordBuffer.size())};
            memcpy(buff.mData.get(), recordBuffer.data(), recordBuffer.size());
            buffer = std::move(buff);
            mNumFramesReceived += recordBuffer.size() / mRecord->frameSize();
            mRecord->releaseBuffer(&recordBuffer);
            counter = 0;
        } else if (WOULD_BLOCK == status) {
            // if not received a buffer for MAX_WAIT_TIME_MS, something has gone wrong
            if (counter == maxTries) return TIMED_OUT;
            counter++;
        }
    }
    return OK;
}

status_t AudioCapture::obtainBufferCb(RawBuffer& buffer) {
    if (REC_STARTED != mState) return INVALID_OPERATION;
    const int maxTries = MAX_WAIT_TIME_MS / WAIT_PERIOD_MS;
    int counter = 0;
    std::unique_lock<std::mutex> lock{mMutex};
    while (mBuffersReceived.empty() && !mStopRecording && counter < maxTries) {
        mCondition.wait_for(lock, std::chrono::milliseconds(WAIT_PERIOD_MS));
        counter++;
    }
    if (!mBuffersReceived.empty()) {
        auto it = mBuffersReceived.begin();
        buffer = std::move(*it);
        mBuffersReceived.erase(it);
    } else {
        if (!mStopRecording && counter == maxTries) return TIMED_OUT;
    }
    return OK;
}

status_t AudioCapture::audioProcess() {
    RawBuffer buffer;
    status_t status = OK;
    while (mNumFramesReceived < mNumFramesToRecord && status == OK) {
        if (mTransferType == AudioRecord::TRANSFER_CALLBACK)
            status = obtainBufferCb(buffer);
        else
            status = obtainBuffer(buffer);
        if (OK == status && mOutFileFd > 0) {
            const char* ptr = static_cast<const char*>(static_cast<void*>(buffer.mData.get()));
            write(mOutFileFd, ptr, buffer.mCapacity);
        }
    }
    return OK;
}

status_t listAudioPorts(std::vector<audio_port_v7>& portsVec) {
    int attempts = 5;
    status_t status;
    unsigned int generation1, generation;
    unsigned int numPorts;
    do {
        if (attempts-- < 0) {
            status = TIMED_OUT;
            break;
        }
        // query for number of ports.
        numPorts = 0;
        status = AudioSystem::listAudioPorts(AUDIO_PORT_ROLE_NONE, AUDIO_PORT_TYPE_NONE, &numPorts,
                                             nullptr, &generation1);
        if (status != NO_ERROR) {
            ALOGE("AudioSystem::listAudioPorts returned error %d", status);
            break;
        }
        portsVec.resize(numPorts);
        status = AudioSystem::listAudioPorts(AUDIO_PORT_ROLE_NONE, AUDIO_PORT_TYPE_NONE, &numPorts,
                                             portsVec.data(), &generation);
    } while (generation1 != generation && status == NO_ERROR);
    if (status != NO_ERROR) {
        numPorts = 0;
        portsVec.clear();
    }
    return status;
}

status_t getPortById(const audio_port_handle_t portId, audio_port_v7& port) {
    std::vector<struct audio_port_v7> ports;
    status_t status = listAudioPorts(ports);
    if (status != OK) return status;
    for (auto i = 0; i < ports.size(); i++) {
        if (ports[i].id == portId) {
            port = ports[i];
            return OK;
        }
    }
    return BAD_VALUE;
}

status_t getPortByAttributes(audio_port_role_t role, audio_port_type_t type,
                             audio_devices_t deviceType, const std::string& address,
                             audio_port_v7& port) {
    std::vector<struct audio_port_v7> ports;
    status_t status = listAudioPorts(ports);
    if (status != OK) return status;
    for (auto i = 0; i < ports.size(); i++) {
        if (ports[i].role == role && ports[i].type == type &&
            ports[i].ext.device.type == deviceType &&
            !strncmp(ports[i].ext.device.address, address.c_str(), AUDIO_DEVICE_MAX_ADDRESS_LEN)) {
            port = ports[i];
            return OK;
        }
    }
    return BAD_VALUE;
}

status_t listAudioPatches(std::vector<struct audio_patch>& patchesVec) {
    int attempts = 5;
    status_t status;
    unsigned int generation1, generation;
    unsigned int numPatches;
    do {
        if (attempts-- < 0) {
            status = TIMED_OUT;
            break;
        }
        // query for number of patches.
        numPatches = 0;
        status = AudioSystem::listAudioPatches(&numPatches, nullptr, &generation1);
        if (status != NO_ERROR) {
            ALOGE("AudioSystem::listAudioPatches returned error %d", status);
            break;
        }
        patchesVec.resize(numPatches);
        status = AudioSystem::listAudioPatches(&numPatches, patchesVec.data(), &generation);
    } while (generation1 != generation && status == NO_ERROR);
    if (status != NO_ERROR) {
        numPatches = 0;
        patchesVec.clear();
    }
    return status;
}

status_t getPatchForOutputMix(audio_io_handle_t audioIo, audio_patch& patch) {
    std::vector<struct audio_patch> patches;
    status_t status = listAudioPatches(patches);
    if (status != OK) return status;

    for (auto i = 0; i < patches.size(); i++) {
        for (auto j = 0; j < patches[i].num_sources; j++) {
            if (patches[i].sources[j].type == AUDIO_PORT_TYPE_MIX &&
                patches[i].sources[j].ext.mix.handle == audioIo) {
                patch = patches[i];
                return OK;
            }
        }
    }
    return BAD_VALUE;
}

status_t getPatchForInputMix(audio_io_handle_t audioIo, audio_patch& patch) {
    std::vector<struct audio_patch> patches;
    status_t status = listAudioPatches(patches);
    if (status != OK) return status;

    for (auto i = 0; i < patches.size(); i++) {
        for (auto j = 0; j < patches[i].num_sinks; j++) {
            if (patches[i].sinks[j].type == AUDIO_PORT_TYPE_MIX &&
                patches[i].sinks[j].ext.mix.handle == audioIo) {
                patch = patches[i];
                return OK;
            }
        }
    }
    return BAD_VALUE;
}

bool patchContainsOutputDevice(audio_port_handle_t deviceId, audio_patch patch) {
    for (auto j = 0; j < patch.num_sinks; j++) {
        if (patch.sinks[j].type == AUDIO_PORT_TYPE_DEVICE && patch.sinks[j].id == deviceId) {
            return true;
        }
    }
    return false;
}

bool patchContainsInputDevice(audio_port_handle_t deviceId, audio_patch patch) {
    for (auto j = 0; j < patch.num_sources; j++) {
        if (patch.sources[j].type == AUDIO_PORT_TYPE_DEVICE && patch.sources[j].id == deviceId) {
            return true;
        }
    }
    return false;
}

bool checkPatchPlayback(audio_io_handle_t audioIo, audio_port_handle_t deviceId) {
    struct audio_patch patch;
    if (getPatchForOutputMix(audioIo, patch) == OK) {
        return patchContainsOutputDevice(deviceId, patch);
    }
    return false;
}

bool checkPatchCapture(audio_io_handle_t audioIo, audio_port_handle_t deviceId) {
    struct audio_patch patch;
    if (getPatchForInputMix(audioIo, patch) == OK) {
        return patchContainsInputDevice(deviceId, patch);
    }
    return false;
}

std::string dumpPortConfig(const audio_port_config& port) {
    auto aidlPortConfig = legacy2aidl_audio_port_config_AudioPortConfigFw(port);
    return aidlPortConfig.ok() ? aidlPortConfig.value().toString()
                               : "Error while converting audio port config to AIDL";
}

std::string dumpPatch(const audio_patch& patch) {
    auto aidlPatch = legacy2aidl_audio_patch_AudioPatchFw(patch);
    return aidlPatch.ok() ? aidlPatch.value().toString() : "Error while converting patch to AIDL";
}

std::string dumpPort(const audio_port_v7& port) {
    auto aidlPort = legacy2aidl_audio_port_v7_AudioPortFw(port);
    return aidlPort.ok() ? aidlPort.value().toString() : "Error while converting port to AIDL";
}
