/*
 * Copyright (C) 2020 The Android Open Source Project
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

// #define LOG_NDEBUG 0
#define LOG_TAG "PassthroughTrackTranscoder"

#include <android-base/logging.h>
#include <media/PassthroughTrackTranscoder.h>
#include <sys/prctl.h>

namespace android {

PassthroughTrackTranscoder::BufferPool::~BufferPool() {
    for (auto it = mAddressSizeMap.begin(); it != mAddressSizeMap.end(); ++it) {
        delete[] it->first;
    }
}

uint8_t* PassthroughTrackTranscoder::BufferPool::getBufferWithSize(size_t minimumBufferSize)
        NO_THREAD_SAFETY_ANALYSIS {
    std::unique_lock lock(mMutex);

    // Wait if maximum number of buffers are allocated but none are free.
    while (mAddressSizeMap.size() >= mMaxBufferCount && mFreeBufferMap.empty() && !mAborted) {
        mCondition.wait(lock);
    }

    if (mAborted) {
        return nullptr;
    }

    // Check if the free list contains a large enough buffer.
    auto it = mFreeBufferMap.lower_bound(minimumBufferSize);
    if (it != mFreeBufferMap.end()) {
        uint8_t* buffer = it->second;
        mFreeBufferMap.erase(it);
        return buffer;
    }

    // If the maximum buffer count is reached, remove an existing free buffer.
    if (mAddressSizeMap.size() >= mMaxBufferCount) {
        auto it = mFreeBufferMap.begin();
        mAddressSizeMap.erase(it->second);
        delete[] it->second;
        mFreeBufferMap.erase(it);
    }

    // Allocate a new buffer.
    uint8_t* buffer = new (std::nothrow) uint8_t[minimumBufferSize];
    if (buffer == nullptr) {
        LOG(ERROR) << "Unable to allocate new buffer of size: " << minimumBufferSize;
        return nullptr;
    }

    // Add the buffer to the tracking set.
    mAddressSizeMap.emplace(buffer, minimumBufferSize);
    return buffer;
}

void PassthroughTrackTranscoder::BufferPool::returnBuffer(uint8_t* buffer) {
    std::scoped_lock lock(mMutex);

    if (buffer == nullptr || mAddressSizeMap.find(buffer) == mAddressSizeMap.end()) {
        LOG(WARNING) << "Ignoring untracked buffer " << buffer;
        return;
    }

    mFreeBufferMap.emplace(mAddressSizeMap[buffer], buffer);
    mCondition.notify_one();
}

void PassthroughTrackTranscoder::BufferPool::abort() {
    std::scoped_lock lock(mMutex);
    mAborted = true;
    mCondition.notify_all();
}

media_status_t PassthroughTrackTranscoder::configureDestinationFormat(
        const std::shared_ptr<AMediaFormat>& destinationFormat __unused) {
    // Called by MediaTrackTranscoder. Passthrough doesn't care about destination so just return ok.
    return AMEDIA_OK;
}

media_status_t PassthroughTrackTranscoder::runTranscodeLoop(bool* stopped) {
    prctl(PR_SET_NAME, (unsigned long)"PassthruThread", 0, 0, 0);

    MediaSampleInfo info;
    std::shared_ptr<MediaSample> sample;
    bool eosReached = false;

    // Notify the track format as soon as we start. It's same as the source format.
    notifyTrackFormatAvailable();

    MediaSample::OnSampleReleasedCallback bufferReleaseCallback =
            [bufferPool = mBufferPool](MediaSample* sample) {
                bufferPool->returnBuffer(const_cast<uint8_t*>(sample->buffer));
            };

    // Move samples until EOS is reached or transcoding is stopped.
    while (mStopRequest != STOP_NOW && !eosReached) {
        media_status_t status = mMediaSampleReader->getSampleInfoForTrack(mTrackIndex, &info);

        if (status == AMEDIA_OK) {
            uint8_t* buffer = mBufferPool->getBufferWithSize(info.size);
            if (buffer == nullptr) {
                if (mStopRequest == STOP_NOW) {
                    break;
                }

                LOG(ERROR) << "Unable to get buffer from pool";
                return AMEDIA_ERROR_UNKNOWN;
            }

            sample = MediaSample::createWithReleaseCallback(
                    buffer, 0 /* offset */, 0 /* bufferId */, bufferReleaseCallback);

            status = mMediaSampleReader->readSampleDataForTrack(mTrackIndex, buffer, info.size);
            if (status != AMEDIA_OK) {
                LOG(ERROR) << "Unable to read next sample data. Aborting transcode.";
                return status;
            }

        } else if (status == AMEDIA_ERROR_END_OF_STREAM) {
            sample = std::make_shared<MediaSample>();
            eosReached = true;
        } else {
            LOG(ERROR) << "Unable to get next sample info. Aborting transcode.";
            return status;
        }

        sample->info = info;
        onOutputSampleAvailable(sample);

        if (mStopRequest == STOP_ON_SYNC && info.flags & SAMPLE_FLAG_SYNC_SAMPLE) {
            break;
        }
    }

    if (mStopRequest != NONE && !eosReached) {
        *stopped = true;
    }
    return AMEDIA_OK;
}

void PassthroughTrackTranscoder::abortTranscodeLoop() {
    if (mStopRequest == STOP_NOW) {
        mBufferPool->abort();
    }
}

std::shared_ptr<AMediaFormat> PassthroughTrackTranscoder::getOutputFormat() const {
    return mSourceFormat;
}
}  // namespace android
