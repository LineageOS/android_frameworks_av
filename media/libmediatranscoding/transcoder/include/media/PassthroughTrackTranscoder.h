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

#ifndef ANDROID_PASSTHROUGH_TRACK_TRANSCODER_H
#define ANDROID_PASSTHROUGH_TRACK_TRANSCODER_H

#include <media/MediaTrackTranscoder.h>
#include <media/NdkMediaFormat.h>

#include <condition_variable>
#include <map>
#include <mutex>
#include <unordered_map>

namespace android {

/**
 * Track transcoder for passthrough mode. Passthrough mode copies sample data from a track unchanged
 * from source file to destination file. This track transcoder uses an internal pool of buffers.
 * When the maximum number of buffers are allocated and all of them are waiting on the output queue
 * the transcoder will stall until samples are dequeued from the output queue and released.
 */
class PassthroughTrackTranscoder : public MediaTrackTranscoder {
public:
    /** Maximum number of buffers to be allocated at a given time. */
    static constexpr int kMaxBufferCountDefault = 16;

    PassthroughTrackTranscoder(
            const std::weak_ptr<MediaTrackTranscoderCallback>& transcoderCallback)
          : MediaTrackTranscoder(transcoderCallback),
            mBufferPool(std::make_shared<BufferPool>(kMaxBufferCountDefault)){};
    virtual ~PassthroughTrackTranscoder() override = default;

private:
    friend class BufferPoolTests;

    /** Class to pool and reuse buffers. */
    class BufferPool {
    public:
        explicit BufferPool(int maxBufferCount) : mMaxBufferCount(maxBufferCount){};
        ~BufferPool();

        /**
         * Retrieve a buffer from the pool. Buffers are allocated on demand. This method will block
         * if the maximum number of buffers is reached and there are no free buffers available.
         * @param minimumBufferSize The minimum size of the buffer.
         * @return The buffer or nullptr if allocation failed or the pool was aborted.
         */
        uint8_t* getBufferWithSize(size_t minimumBufferSize);

        /**
         * Return a buffer to the pool.
         * @param buffer The buffer to return.
         */
        void returnBuffer(uint8_t* buffer);

        /** Wakes up threads waiting on buffers and prevents new buffers from being returned. */
        void abort();

    private:
        // Maximum number of active buffers at a time.
        const int mMaxBufferCount;

        // Map containing all tracked buffers.
        std::unordered_map<uint8_t*, size_t> mAddressSizeMap GUARDED_BY(mMutex);

        // Map containing the currently free buffers.
        std::multimap<size_t, uint8_t*> mFreeBufferMap GUARDED_BY(mMutex);

        std::mutex mMutex;
        std::condition_variable mCondition;
        bool mAborted GUARDED_BY(mMutex) = false;
    };

    // MediaTrackTranscoder
    media_status_t runTranscodeLoop(bool* stopped) override;
    void abortTranscodeLoop() override;
    media_status_t configureDestinationFormat(
            const std::shared_ptr<AMediaFormat>& destinationFormat) override;
    std::shared_ptr<AMediaFormat> getOutputFormat() const override;
    // ~MediaTrackTranscoder

    std::shared_ptr<BufferPool> mBufferPool;
};

}  // namespace android
#endif  // ANDROID_PASSTHROUGH_TRACK_TRANSCODER_H
