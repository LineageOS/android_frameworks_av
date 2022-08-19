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

#include <utils/Log.h>

#include "audio_test_utils.h"

// Generates a random string.
void CreateRandomFile(int& fd) {
    std::string filename = "/data/local/tmp/record-XXXXXX";
    fd = mkstemp(filename.data());
}

void OnAudioDeviceUpdateNotifier::onAudioDeviceUpdate(audio_io_handle_t audioIo,
                                                      audio_port_handle_t deviceId) {
    std::unique_lock<std::mutex> lock{mMutex};
    ALOGD("%s  audioIo=%d deviceId=%d", __func__, audioIo, deviceId);
    mAudioIo = audioIo;
    mDeviceId = deviceId;
    mCondition.notify_all();
}

status_t OnAudioDeviceUpdateNotifier::waitForAudioDeviceCb() {
    std::unique_lock<std::mutex> lock{mMutex};
    if (mAudioIo == AUDIO_IO_HANDLE_NONE) {
        mCondition.wait_for(lock, std::chrono::milliseconds(500));
        if (mAudioIo == AUDIO_IO_HANDLE_NONE) return TIMED_OUT;
    }
    return OK;
}

// AudioTrack callback function.
static void AudioTrackCallBackFunction(int event, void* user, void* info __unused) {
    switch (event) {
        case AudioTrack::EVENT_BUFFER_END: {
            AudioPlayback* ap = (AudioPlayback*)user;
            std::unique_lock<std::mutex> lock{ap->mMutex};
            ap->mStopPlaying = true;
            ap->mCondition.notify_all();
            break;
        }
        default:
            ALOGV("received audiotrack callback %d", event);
            break;
    }
}

AudioPlayback::AudioPlayback(uint32_t sampleRate, audio_format_t format,
                             audio_channel_mask_t channelMask, audio_output_flags_t flags,
                             audio_session_t sessionId, AudioTrack::transfer_type transferType,
                             audio_attributes_t* attributes)
    : mSampleRate(sampleRate),
      mFormat(format),
      mChannelMask(channelMask),
      mFlags(flags),
      mSessionId(sessionId),
      mTransferType(transferType),
      mAttributes(attributes) {
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
        mTrack->set(AUDIO_STREAM_MUSIC, mSampleRate, mFormat, mChannelMask, 0, mFlags, nullptr,
                    nullptr, 0, 0, false, mSessionId, mTransferType, nullptr, attributionSource,
                    mAttributes);
    } else if (mTransferType == AudioTrack::TRANSFER_SHARED) {
        mTrack = new AudioTrack(AUDIO_STREAM_MUSIC, mSampleRate, mFormat, mChannelMask, mMemory,
                                mFlags, AudioTrackCallBackFunction, this, 0, mSessionId,
                                mTransferType, nullptr, attributionSource, mAttributes);
    } else {
        ALOGE("Required Transfer type not existed");
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

status_t AudioPlayback::fillBuffer() {
    if (PLAY_STARTED != mState && PLAY_STOPPED != mState) return INVALID_OPERATION;
    int retry = 25;
    uint8_t* ipBuffer = static_cast<uint8_t*>(static_cast<void*>(mMemory->unsecurePointer()));
    size_t nonContig = 0;
    size_t bytesAvailable = mMemCapacity - mBytesUsedSoFar;
    while (bytesAvailable > 0) {
        AudioTrack::Buffer trackBuffer;
        trackBuffer.frameCount = mTrack->frameCount() * 2;
        status_t status = mTrack->obtainBuffer(&trackBuffer, retry, &nonContig);
        if (OK == status) {
            size_t bytesToCopy = std::min(bytesAvailable, trackBuffer.size());
            if (bytesToCopy > 0) {
                memcpy(trackBuffer.data(), ipBuffer + mBytesUsedSoFar, bytesToCopy);
            }
            mTrack->releaseBuffer(&trackBuffer);
            mBytesUsedSoFar += bytesToCopy;
            bytesAvailable = mMemCapacity - mBytesUsedSoFar;
            if (bytesAvailable == 0) {
                stop();
            }
        } else if (WOULD_BLOCK == status) {
            if (mStopPlaying)
                return OK;
            else
                return TIMED_OUT;
        }
    }
    return OK;
}

status_t AudioPlayback::waitForConsumption(bool testSeek) {
    if (PLAY_STARTED != mState) return INVALID_OPERATION;
    // in static buffer mode, lets not play clips with duration > 30 sec
    int retry = 30;
    // Total number of frames in the input file.
    size_t totalFrameCount = mMemCapacity / mTrack->frameSize();
    while (!mStopPlaying && retry > 0) {
        // Get the total numbers of frames played.
        uint32_t currPosition;
        mTrack->getPosition(&currPosition);
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
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        retry--;
    }
    if (!mStopPlaying) return TIMED_OUT;
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
    if (mState != PLAY_STOPPED) {
        mTrack->stopAndJoinCallbacks();
        LOG_FATAL_IF(true != mTrack->stopped());
        mState = PLAY_STOPPED;
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
    if (mNumFramesReceived > mNumFramesToRecord || mStopRecording) {
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
                           audio_session_t sessionId, AudioRecord::transfer_type transferType)
    : mInputSource(inputSource),
      mSampleRate(sampleRate),
      mFormat(format),
      mChannelMask(channelMask),
      mFlags(flags),
      mSessionId(sessionId),
      mTransferType(transferType) {
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
#if RECORD_TO_FILE
    CreateRandomFile(mOutFileFd);
#endif
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
        const uint32_t kMinNormalCaptureBufferSizeMs = 12;
        size_t maxFrameCount = kMinNormalCaptureBufferSizeMs * mSampleRate / 1000;
        mMaxBytesPerCallback = maxFrameCount * samplesPerFrame * bytesPerSample / 2;
        mNotificationFrames = maxFrameCount / 2;
        mFrameCount = 2 * mNotificationFrames;
    }
    mNumFramesToRecord = (mSampleRate * 0.25);  // record .25 sec
    std::string packageName{"AudioCapture"};
    AttributionSourceState attributionSource;
    attributionSource.packageName = packageName;
    attributionSource.uid = VALUE_OR_FATAL(legacy2aidl_uid_t_int32_t(getuid()));
    attributionSource.pid = VALUE_OR_FATAL(legacy2aidl_pid_t_int32_t(getpid()));
    attributionSource.token = sp<BBinder>::make();
    if (mTransferType == AudioRecord::TRANSFER_OBTAIN) {
        mRecord = new AudioRecord(attributionSource);
        status = mRecord->set(mInputSource, mSampleRate, mFormat, mChannelMask, mFrameCount,
                              nullptr, nullptr, 0, false, mSessionId, mTransferType, mFlags,
                              attributionSource.uid, attributionSource.pid);
        if (NO_ERROR != status) return status;
    } else if (mTransferType == AudioRecord::TRANSFER_CALLBACK) {
        mRecord = new AudioRecord(mInputSource, mSampleRate, mFormat, mChannelMask,
                                  attributionSource, mFrameCount, this, mNotificationFrames,
                                  mSessionId, mTransferType, mFlags);
    } else {
        ALOGE("Test application is not handling transfer type %s",
              AudioRecord::convertTransferToText(mTransferType));
        return NO_INIT;
    }
    mRecord->setCallerName(packageName);
    status = mRecord->initCheck();
    if (NO_ERROR == status) mState = REC_READY;
    return status;
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
    if (mState != REC_STOPPED) {
        uint32_t position;
        status = mRecord->getPosition(&position);
        if (OK == status && mTransferType == AudioRecord::TRANSFER_CALLBACK) {
            if (position - mNumFramesToRecord > mFrameCount)
                if (mBufferOverrun == false) status = BAD_VALUE;
        }
        mRecord->stopAndJoinCallbacks();
        mState = REC_STOPPED;
        LOG_FATAL_IF(true != mRecord->stopped());
    }
    return status;
}

status_t AudioCapture::obtainBuffer(RawBuffer& buffer) {
    if (REC_STARTED != mState && REC_STOPPED != mState) return INVALID_OPERATION;
    int retry = 25;
    AudioRecord::Buffer recordBuffer;
    recordBuffer.frameCount = mNotificationFrames;
    size_t nonContig = 0;
    status_t status = mRecord->obtainBuffer(&recordBuffer, retry, &nonContig);
    if (OK == status) {
        const int64_t timestampUs =
                ((1000000LL * mNumFramesReceived) + (mRecord->getSampleRate() >> 1)) /
                mRecord->getSampleRate();
        RawBuffer buff{-1, timestampUs, static_cast<int32_t>(recordBuffer.size())};
        memcpy(buff.mData.get(), recordBuffer.data(), recordBuffer.size());
        buffer = std::move(buff);
        mNumFramesReceived += recordBuffer.size() / mRecord->frameSize();
        mRecord->releaseBuffer(&recordBuffer);
        if (mNumFramesReceived > mNumFramesToRecord) {
            stop();
        }
    } else if (status == WOULD_BLOCK) {
        if (mStopRecording)
            return WOULD_BLOCK;
        else
            return TIMED_OUT;
    }
    return OK;
}

status_t AudioCapture::obtainBufferCb(RawBuffer& buffer) {
    if (REC_STARTED != mState) return INVALID_OPERATION;
    int retry = 10;
    std::unique_lock<std::mutex> lock{mMutex};
    while (mBuffersReceived.empty() && !mStopRecording && retry > 0) {
        mCondition.wait_for(lock, std::chrono::milliseconds(100));
        retry--;
    }
    if (!mBuffersReceived.empty()) {
        auto it = mBuffersReceived.begin();
        buffer = std::move(*it);
        mBuffersReceived.erase(it);
    } else {
        if (retry == 0) return TIMED_OUT;
        if (mStopRecording)
            return WOULD_BLOCK;
        else
            return UNKNOWN_ERROR;
    }
    return OK;
}

status_t AudioCapture::audioProcess() {
    RawBuffer buffer;
    while (true) {
        status_t status;
        if (mTransferType == AudioRecord::TRANSFER_CALLBACK)
            status = obtainBufferCb(buffer);
        else
            status = obtainBuffer(buffer);
        switch (status) {
            case OK:
                if (mOutFileFd > 0) {
                    const char* ptr =
                            static_cast<const char*>(static_cast<void*>(buffer.mData.get()));
                    write(mOutFileFd, ptr, buffer.mCapacity);
                }
                break;
            case WOULD_BLOCK:
                return OK;
            case TIMED_OUT:          // "recorder application timed out from receiving buffers"
            case NO_INIT:            // "recorder not initialized"
            case INVALID_OPERATION:  // "recorder not started"
            case UNKNOWN_ERROR:      // "Unknown error"
            default:
                return status;
        }
    }
}
