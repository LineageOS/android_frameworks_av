/*
 * Copyright 2016 The Android Open Source Project
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

#ifndef UTILITY_AAUDIO_UTILITIES_H
#define UTILITY_AAUDIO_UTILITIES_H

#include <algorithm>
#include <functional>
#include <vector>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include <android/media/audio/common/AudioMMapPolicyInfo.h>
#include <utils/Errors.h>
#include <system/audio.h>

#include "aaudio/AAudio.h"
#include "aaudio/AAudioTesting.h"

/**
 * Convert an AAudio result into the closest matching Android status.
 */
android::status_t AAudioConvert_aaudioToAndroidStatus(aaudio_result_t result);

/**
 * Convert an Android status into the closest matching AAudio result.
 */
aaudio_result_t AAudioConvert_androidToAAudioResult(android::status_t status);

/**
 * Convert an aaudio_session_id_t to a value that is safe to pass to AudioFlinger.
 * @param sessionId
 * @return safe value
 */
audio_session_t AAudioConvert_aaudioToAndroidSessionId(aaudio_session_id_t sessionId);

/**
 * Calculate the number of bytes and prevent numeric overflow.
 * The *sizeInBytes will be set to zero if there is an error.
 *
 * @param numFrames frame count
 * @param bytesPerFrame size of a frame in bytes
 * @param sizeInBytes pointer to a variable to receive total size in bytes
 * @return AAUDIO_OK or negative error, eg. AAUDIO_ERROR_OUT_OF_RANGE
 */
int32_t AAudioConvert_framesToBytes(int32_t numFrames,
                                    int32_t bytesPerFrame,
                                    int32_t *sizeInBytes);

audio_format_t AAudioConvert_aaudioToAndroidDataFormat(aaudio_format_t aaudio_format);

aaudio_format_t AAudioConvert_androidToAAudioDataFormat(audio_format_t format);

aaudio_format_t AAudioConvert_androidToNearestAAudioDataFormat(audio_format_t format);

/**
 * Note that this function does not validate the passed in value.
 * That is done somewhere else.
 * @return internal value
 */

audio_usage_t AAudioConvert_usageToInternal(aaudio_usage_t usage);

/**
 * Note that this function does not validate the passed in value.
 * That is done somewhere else.
 * @return internal value
 */
audio_content_type_t AAudioConvert_contentTypeToInternal(aaudio_content_type_t contentType);

/**
 * Note that this function does not validate the passed in value.
 * That is done somewhere else.
 * @return internal audio source
 */
audio_source_t AAudioConvert_inputPresetToAudioSource(aaudio_input_preset_t preset);

/**
 * Note that this function does not validate the passed in value.
 * That is done somewhere else.
 * @return internal audio flags mask
 */
audio_flags_mask_t AAudio_computeAudioFlagsMask(
        aaudio_allowed_capture_policy_t policy,
        aaudio_spatialization_behavior_t spatializationBehavior,
        bool isContentSpatialized,
        audio_output_flags_t outputFlags);

audio_flags_mask_t AAudioConvert_privacySensitiveToAudioFlagsMask(
        bool privacySensitive);

audio_channel_mask_t AAudioConvert_aaudioToAndroidChannelLayoutMask(
        aaudio_channel_mask_t channelMask, bool isInput);

aaudio_channel_mask_t AAudioConvert_androidToAAudioChannelLayoutMask(
        audio_channel_mask_t channelMask, bool isInput);

aaudio_channel_mask_t AAudioConvert_androidToAAudioChannelIndexMask(
        audio_channel_mask_t channelMask);

audio_channel_mask_t AAudioConvert_aaudioToAndroidChannelIndexMask(
        aaudio_channel_mask_t channelMask);

aaudio_channel_mask_t AAudioConvert_androidToAAudioChannelMask(
        audio_channel_mask_t channelMask, bool isInput, bool indexMaskRequired);

audio_channel_mask_t AAudioConvert_aaudioToAndroidChannelMask(
        aaudio_channel_mask_t channelMask, bool isInput);

bool AAudio_isChannelIndexMask(aaudio_channel_mask_t channelMask);

int32_t AAudioConvert_channelMaskToCount(aaudio_channel_mask_t channelMask);

aaudio_channel_mask_t AAudioConvert_channelCountToMask(int32_t channelCount);

audio_channel_mask_t AAudio_getChannelMaskForOpen(
        aaudio_channel_mask_t channelMask, int32_t samplesPerFrame, bool isInput);

// Note that this code may be replaced by Settings or by some other system configuration tool.

/**
 * Read a system property that specifies the number of extra microseconds that a thread
 * should sleep when waiting for another thread to service a FIFO. This is used
 * to avoid the waking thread from being overly optimistic about the other threads
 * wakeup timing. This value should be set high enough to cover typical scheduling jitter
 * for a real-time thread.
 *
 * @return number of microseconds to delay the wakeup.
 */
int32_t AAudioProperty_getWakeupDelayMicros();
#define AAUDIO_PROP_WAKEUP_DELAY_USEC      "aaudio.wakeup_delay_usec"

/**
 * Read a system property that specifies the minimum sleep time when polling the FIFO.
 *
 * @return minimum number of microseconds to sleep.
 */
int32_t AAudioProperty_getMinimumSleepMicros();
#define AAUDIO_PROP_MINIMUM_SLEEP_USEC      "aaudio.minimum_sleep_usec"

/**
 * Read a system property that specifies an offset that will be added to MMAP timestamps.
 * This can be used to correct bias in the timestamp.
 * It can also be used to analyze the time distribution of the timestamp
 * by progressively modifying the offset and listening for glitches.
 *
 * @return number of microseconds to offset the time part of an MMAP timestamp
 */
int32_t AAudioProperty_getInputMMapOffsetMicros();
#define AAUDIO_PROP_INPUT_MMAP_OFFSET_USEC    "aaudio.in_mmap_offset_usec"

int32_t AAudioProperty_getOutputMMapOffsetMicros();
#define AAUDIO_PROP_OUTPUT_MMAP_OFFSET_USEC   "aaudio.out_mmap_offset_usec"

// These are powers of two that can be combined as a bit mask.
// AAUDIO_LOG_CLOCK_MODEL_HISTOGRAM must be enabled before the stream is opened.
#define AAUDIO_LOG_CLOCK_MODEL_HISTOGRAM   1
#define AAUDIO_LOG_RESERVED_2              2
#define AAUDIO_LOG_RESERVED_4              4
#define AAUDIO_LOG_RESERVED_8              8

/**
 * Use a mask to enable various logs in AAudio.
 * @return mask that enables various AAudio logs, such as AAUDIO_LOG_CLOCK_MODEL_HISTOGRAM
 */
int32_t AAudioProperty_getLogMask();
#define AAUDIO_PROP_LOG_MASK   "aaudio.log_mask"

/**
 * Is flush allowed for the given state?
 * @param state
 * @return AAUDIO_OK if allowed or an error
 */
aaudio_result_t AAudio_isFlushAllowed(aaudio_stream_state_t state);

/**
 * Try a function f until it returns true.
 *
 * The function is always called at least once.
 *
 * @param f the function to evaluate, which returns a bool.
 * @param times the number of times to evaluate f.
 * @param sleepMs the sleep time per check of f, if greater than 0.
 * @return true if f() eventually returns true.
 */
static inline bool AAudio_tryUntilTrue(
        const std::function<bool()>& f, int times, int sleepMs) {
    static const useconds_t US_PER_MS = 1000;

    sleepMs = std::max(sleepMs, 0);
    for (;;) {
        if (f()) return true;
        if (times <= 1) return false;
        --times;
        usleep(sleepMs * US_PER_MS);
    }
}


/**
 * Simple double buffer for a structure that can be written occasionally and read occasionally.
 * This allows a SINGLE writer with multiple readers.
 *
 * It is OK if the FIFO overflows and we lose old values.
 * It is also OK if we read an old value.
 * Thread may return a non-atomic result if the other thread is rapidly writing
 * new values on another core.
 */
template <class T>
class SimpleDoubleBuffer {
public:
    SimpleDoubleBuffer()
            : mValues() {}

    __attribute__((no_sanitize("integer")))
    void write(T value) {
        int index = mCounter.load() & 1;
        mValues[index] = value;
        mCounter++; // Increment AFTER updating storage, OK if it wraps.
    }

    /**
     * This should only be called by the same thread that calls write() or when
     * no other thread is calling write.
     */
    void clear() {
        mCounter.store(0);
    }

    T read() const {
        T result;
        int before;
        int after;
        int timeout = 3;
        do {
            // Check to see if a write occurred while were reading.
            before = mCounter.load();
            int index = (before & 1) ^ 1;
            result = mValues[index];
            after = mCounter.load();
        } while ((after != before) && (after > 0) && (--timeout > 0));
        return result;
    }

    /**
     * @return true if at least one value has been written
     */
    bool isValid() const {
        return mCounter.load() > 0;
    }

private:
    T                    mValues[2];
    std::atomic<int>     mCounter{0};
};

class Timestamp {
public:
    Timestamp() = default;
    Timestamp(int64_t position, int64_t nanoseconds)
            : mPosition(position)
            , mNanoseconds(nanoseconds) {}

    int64_t getPosition() const { return mPosition; }

    int64_t getNanoseconds() const { return mNanoseconds; }

private:
    // These cannot be const because we need to implement the copy assignment operator.
    int64_t mPosition{0};
    int64_t mNanoseconds{0};
};


/**
 * Pass a request to another thread.
 * This is used when one thread, A, wants another thread, B, to do something.
 * A naive approach would be for A to set a flag and for B to clear it when done.
 * But that creates a race condition. This technique avoids the race condition.
 *
 * Assumes only one requester and one acknowledger.
 */
class AtomicRequestor {
public:

    __attribute__((no_sanitize("integer")))
    void request() {
        mRequested++;
    }

    __attribute__((no_sanitize("integer")))
    bool isRequested() {
        return (mRequested.load() - mAcknowledged.load()) > 0;
    }

    __attribute__((no_sanitize("integer")))
    void acknowledge() {
        mAcknowledged++;
    }

private:
    std::atomic<int> mRequested{0};
    std::atomic<int> mAcknowledged{0};
};

enum {
    /**
     * Audio channel index mask, only used internally.
     */
    AAUDIO_CHANNEL_BIT_INDEX = 0x80000000,
    AAUDIO_CHANNEL_INDEX_MASK_1 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 1) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_2 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 2) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_3 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 3) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_4 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 4) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_5 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 5) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_6 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 6) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_7 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 7) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_8 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 8) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_9 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 9) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_10 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 10) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_11 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 11) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_12 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 12) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_13 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 13) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_14 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 14) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_15 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 15) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_16 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 16) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_17 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 17) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_18 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 18) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_19 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 19) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_20 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 20) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_21 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 21) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_22 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 22) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_23 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 23) - 1,
    AAUDIO_CHANNEL_INDEX_MASK_24 = AAUDIO_CHANNEL_BIT_INDEX | (1 << 24) - 1,
};

/**
 * Returns the aaudio mmap policy based on the vector of mmap policy info. The rule as
 * 1. Returns AUTO if any of the policy is AUTO or ALWAYS
 * 2. Returns NEVER if all of the policies are NEVER or UNSPECIFIED
 * 3. Returns default policy if all of the policies are UNSPECIFIED
 *
 * @param policyInfos
 * @param defaultPolicy
 * @return
 */
aaudio_policy_t AAudio_getAAudioPolicy(
        const std::vector<android::media::audio::common::AudioMMapPolicyInfo>& policyInfos,
        android::media::audio::common::AudioMMapPolicy defaultPolicy =
                android::media::audio::common::AudioMMapPolicy::NEVER);

#endif //UTILITY_AAUDIO_UTILITIES_H
