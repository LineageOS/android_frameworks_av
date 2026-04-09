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

//#define LOG_NDEBUG 0

#define ATRACE_TAG ATRACE_TAG_AUDIO

#include "AudioStreamInternalPlay.h"

// go/keep-sorted start
#include <audio_utils/mutex.h>
#include <media/MediaMetricsItem.h>
#include <mediautils/Runnable.h>
#include <utility/AudioClock.h>
#include <utils/Log.h>
#include <utils/SystemClock.h>
#include <utils/Trace.h>
// go/keep-sorted end

// go/keep-sorted start
#include <algorithm>
#include <chrono>
#include <thread>
// go/keep-sorted end

// We do this after the #includes because if a header uses ALOG.
// it would fail on the reference to mInService.
#undef LOG_TAG
// This file is used in both client and server processes.
// This is needed to make sense of the logs more easily.
#define LOG_TAG (mInService ? "AudioStreamInternalPlay_Service" \
                            : "AudioStreamInternalPlay_Client")

using android::status_t;
using android::WrappingBuffer;

using namespace aaudio;

using android::audio_utils::TimerQueue;

AudioStreamInternalPlay::AudioStreamInternalPlay(AAudioServiceInterface  &serviceInterface,
                                                       bool inService)
        : AudioStreamInternal(serviceInterface, inService) {
}

constexpr int kRampMSec = 10; // time to apply a change in volume

aaudio_result_t AudioStreamInternalPlay::open(const AAudioStreamOpenRequest& openRequest) {
    aaudio_result_t result = AudioStreamInternal::open(openRequest);
    const bool useVolumeRamps = (getSharingMode() == AAUDIO_SHARING_MODE_EXCLUSIVE);
    if (result == AAUDIO_OK) {
        mNanosPerBurst =
                getDeviceFramesPerBurst() * AAUDIO_NANOS_PER_SECOND / getDeviceSampleRate();
        LOG_ALWAYS_FATAL_IF(
                mNanosPerBurst < 0 , "Nanos per burst is negative, %jd", mNanosPerBurst);
        result = mFlowGraph.configure(getFormat(),
                             getSamplesPerFrame(),
                             getSampleRate(),
                             getDeviceFormat(),
                             getDeviceSamplesPerFrame(),
                             getDeviceSampleRate(),
                             getRequireMonoBlend(),
                             useVolumeRamps,
                             getAudioBalance(),
                             aaudio::resampler::MultiChannelResampler::Quality::Medium);

        if (result != AAUDIO_OK) {
            safeReleaseClose();
        }
        // Sample rate is constrained to common values by now and should not overflow.
        int32_t numFrames = kRampMSec * getSampleRate() / AAUDIO_MILLIS_PER_SECOND;
        mFlowGraph.setRampLengthInFrames(numFrames);
    }
    // Use 1s + burst size as a safe margin to wake up the callback thread for writing more
    // data to avoid glitch.
    mOffloadSafeMarginInFrames =
            getDeviceSampleRate() * kOffloadSafeMarginMs / AAUDIO_MILLIS_PER_SECOND +
            getDeviceFramesPerBurst();
    // Use 100ms + burst size as a safe margin when calculating the safe position to flush from.
    mOffloadFlushFromSafeMarginInFrames =
            getDeviceSampleRate() * kOffloadFlushFromSafeMarginMs / AAUDIO_MILLIS_PER_SECOND +
            getDeviceFramesPerBurst();
    return result;
}

// This must be called under mStreamMutex.
aaudio_result_t AudioStreamInternalPlay::requestPause_l()
{
    aaudio_result_t result = stopCallback_l();
    if (result != AAUDIO_OK) {
        return result;
    }
    if (getServiceHandle() == AAUDIO_HANDLE_INVALID) {
        ALOGW("%s() mServiceStreamHandle invalid", __func__);
        return AAUDIO_ERROR_INVALID_STATE;
    }

    mClockModel.stop(AudioClock::getNanoseconds());
    setState(AAUDIO_STREAM_STATE_PAUSING);
    mAtomicInternalTimestamp.clear();

    // When pause is called, the service will notify the HAL so that no more data will be consumed.
    // In that case, it is no longer needed to wait for stream end.
    dropPresentationEndCallback_l();

    if (getPerformanceMode() == AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED) {
        if (result = mServiceInterface.updateTimestamp(mServiceStreamHandleInfo);
            result != AAUDIO_OK) {
            ALOGE("%s, failed to update timestamp, error=%d", __func__, result);
            return result;
        } else {
            // After successfully updating the timestamp, the service side is not draining any more.
            // In that case, always clear the mWakeUpHandle here to indicate that wakeup callback
            // is not expected.
            mWakeUpHandle = TimerQueue::INVALID_HANDLE;
        }
        if (result = processCommands(); result != AAUDIO_OK) {
            ALOGE("%s, failed to process commands, error=%d", __func__, result);
            return result;
        }
        // Setting a most accurate read counter so that when resuming, we know if we need to copy
        // unprocessed data or not. For the most accurate read counter, it is the minimum value
        // between write counter and estimated read counter plus one burst size. Adding one extra
        // burst size as the DSP may read to next burst after reporting the position.
        int64_t readPosition = std::min(mAudioEndpoint->getDataWriteCounter(),
                mClockModel.convertTimeToPosition(AudioClock::getNanoseconds())
                        + getDeviceFramesPerBurst());
        mAudioEndpoint->setDataReadCounter(readPosition);
    }

    return mServiceInterface.pauseStream(mServiceStreamHandleInfo);
}

aaudio_result_t AudioStreamInternalPlay::requestFlush_l() {
    if (getServiceHandle() == AAUDIO_HANDLE_INVALID) {
        ALOGW("%s() mServiceStreamHandle invalid", __func__);
        return AAUDIO_ERROR_INVALID_STATE;
    }

    setState(AAUDIO_STREAM_STATE_FLUSHING);

    // When flush is called, the service will notify the HAL so that no more data will be consumed.
    // In that case, it is no longer needed to wait for stream end.
    dropPresentationEndCallback_l();

    return mServiceInterface.flushStream(mServiceStreamHandleInfo);
}

void AudioStreamInternalPlay::prepareBuffersForStart_l(StartType startType) {
    // Reset volume ramps to avoid a starting noise.
    // This was called here instead of AudioStreamInternal so that
    // it will be easier to backport.
    mFlowGraph.reset();
    if (startType == RESUME_WITH_UNPROCESSED_DATA_TO_COPY) {
        // There are stale data that needs to be played. Copy them to a temporary buffer and
        // rewrite them to mmap buffer when there is position reported from the HAL.
        mUnprocessedFrames = mAudioEndpoint->getFullFramesAvailable();
        mUnprocessedBuffer = std::make_unique<uint8_t[]>(mUnprocessedFrames * getBytesPerFrame());
        mUnprocessedFrames = mAudioEndpoint->read(mUnprocessedBuffer.get(), mUnprocessedFrames);
    }
    // Prevent stale data from being played.
    mAudioEndpoint->eraseDataMemory();
    // All data has been erased. To avoid mixer for the shared stream use stale
    // counters, which may cause the service side thinking stream starts flowing before
    // the client actually writes data, advance the client to match server position.
    advanceClientToMatchServerPosition(0 /*serverMargin*/);
}

aaudio_result_t AudioStreamInternalPlay::prepareBuffersForStop_l() {
    // If this is a shared stream and the FIFO is being read by the mixer then
    // we don't have to worry about the DSP reading past the valid data. We can skip all this.
    if(!mAudioEndpoint->isFreeRunning()) {
        return AAUDIO_OK;
    }
    if (getPerformanceMode() == AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED) {
        if (mWakeUpHandle != TimerQueue::INVALID_HANDLE) {
            // The stream is draining. For offload stream, it should drain all data and then stop.
            ALOGD("%s, the stream is already draining", __func__);
            return AAUDIO_ERROR_WOULD_BLOCK;
        }
        const int64_t streamEndNanosBootTime = mClockModel.convertPositionToBootTime(
                mAudioEndpoint->getDataWriteCounter() - getDeviceFramesPerBurst());
        if (android::elapsedRealtimeNano() >= streamEndNanosBootTime) {
            ALOGD("No need to drain as it is closed to play all data");
            return AAUDIO_OK;
        }
        drainStream_l(streamEndNanosBootTime, DrainType::DRAIN_ALL_DATA);
        return AAUDIO_ERROR_WOULD_BLOCK;
    }
    // Sleep until the DSP has read all of the data written.
    int64_t validFramesInBuffer =
            mAudioEndpoint->getDataWriteCounter() - mAudioEndpoint->getDataReadCounter();
    if (validFramesInBuffer >= 0) {
        int64_t emptyFramesInBuffer = ((int64_t) getDeviceBufferCapacity()) - validFramesInBuffer;

        // Prevent stale data from being played if the DSP is still running.
        // Erase some of the FIFO memory in front of the DSP read cursor.
        // Subtract one burst so we do not accidentally erase data that the DSP might be using.
        int64_t framesToErase = std::max((int64_t) 0,
                                         emptyFramesInBuffer - getDeviceFramesPerBurst());
        mAudioEndpoint->eraseEmptyDataMemory(framesToErase);

        // Sleep until we are confident the DSP has consumed all of the valid data.
        // Sleep for one extra burst as a safety margin because the IsochronousClockModel
        // is not perfectly accurate.
        // The ClockModel uses the server frame position so do not use getFramesWritten().
        int64_t positionInEmptyMemory = mAudioEndpoint->getDataWriteCounter() + getDeviceFramesPerBurst();
        int64_t timeAllConsumed = mClockModel.convertPositionToTime(positionInEmptyMemory);
        int64_t durationAllConsumed = timeAllConsumed - AudioClock::getNanoseconds();
        // Prevent sleeping for too long.
        durationAllConsumed = std::min(200 * AAUDIO_NANOS_PER_MILLISECOND, durationAllConsumed);
        AudioClock::sleepForNanos(durationAllConsumed);
    }

    // Erase all of the memory in case the DSP keeps going and wraps around.
    mAudioEndpoint->eraseDataMemory();

    // Wait for the last buffer to reach the DAC.
    // This is because the expected behavior of stop() is that all data written to the stream
    // should be played before the hardware actually shuts down.
    // This is different than pause(), where we just end as soon as possible.
    // This can be important when, for example, playing car navigation and
    // you want the user to hear the complete instruction.
    if (mAtomicInternalTimestamp.isValid()) {
        // Use timestamps to calculate the latency between the DSP reading
        // a frame and when it reaches the DAC.
        // This code assumes that timestamps are accurate.
        Timestamp timestamp = mAtomicInternalTimestamp.read();
        int64_t dacPosition = timestamp.getPosition();
        int64_t hardwareReadTime = mClockModel.convertPositionToTime(dacPosition);
        int64_t hardwareLatencyNanos = timestamp.getNanoseconds() - hardwareReadTime;
        ALOGD("%s() hardwareLatencyNanos = %lld", __func__,
              (long long) hardwareLatencyNanos);
        // Prevent sleeping for too long.
        hardwareLatencyNanos = std::min(30 * AAUDIO_NANOS_PER_MILLISECOND,
                                        hardwareLatencyNanos);
        AudioClock::sleepForNanos(hardwareLatencyNanos);
    }
    return AAUDIO_OK;
}

void AudioStreamInternalPlay::advanceClientToMatchServerPosition(int32_t serverMargin) {
    int64_t readCounter = mAudioEndpoint->getDataReadCounter() + serverMargin;
    int64_t writeCounter = mAudioEndpoint->getDataWriteCounter();

    // Bump offset so caller does not see the retrograde motion in getFramesRead().
    int64_t offset = writeCounter - readCounter;
    mFramesOffsetFromService += offset;
    ALOGV("%s() readN = %lld, writeN = %lld, offset = %lld", __func__,
          (long long)readCounter, (long long)writeCounter, (long long)mFramesOffsetFromService);

    // Force writeCounter to match readCounter.
    // This is because we cannot change the read counter in the hardware.
    mAudioEndpoint->setDataWriteCounter(readCounter);
}

void AudioStreamInternalPlay::onFlushFromServer() {
    advanceClientToMatchServerPosition(0 /*serverMargin*/);
}

// Write the data, block if needed and timeoutMillis > 0
aaudio_result_t AudioStreamInternalPlay::write(const void *buffer, int32_t numFrames,
                                               int64_t timeoutNanoseconds) {
    if (mayNeedToDrain() && (!isDataCallbackSet() || mUseDataAvailableCallback)) {
        std::lock_guard _l(mStreamMutex);
        if (mDraining) {
            if (aaudio_result_t result = activateStream_l(); result != AAUDIO_OK) {
                return result;
            }
            mDraining = false;
        }
    }
    aaudio_result_t result = AAUDIO_OK;
    if (getPerformanceMode() == AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED) {
        // For offload mode, the counters can also be updated when calling flushFromFrame.
        // We document apps must not provide data when calling flushFromFrame. But to avoid
        // app's misbehavior, adding a lock here to protect the counters. Without any competitor,
        // locking should not be too expensive.
        std::lock_guard _l(mEndpointMutex);
        result = processData((void *) buffer, numFrames, timeoutNanoseconds);
    } else {
        // For non-offload mode, the counters will only be updated from one thread.
        // It should be fine to access it without locking.
        result = processData((void *) buffer, numFrames, timeoutNanoseconds);
    }
    if (isDataCallbackSet() && result != numFrames) {
        // For callback case, it must always be able to write all data
        if (result >= 0) {
            // Only wrote some of the frames requested. The stream can be disconnected
            // or timed out.
            ALOGW("%s from callback thread, %d frames written, %d frames provided",
                  __func__, result, numFrames);
            processCommands();
            result = isDisconnected() ? AAUDIO_ERROR_DISCONNECTED : AAUDIO_ERROR_TIMEOUT;
        }
        maybeCallErrorCallback(result);
        return result;
    }
    if (result >= 0 && mayNeedToDrain()) {
        // If it is buffer size is big and the buffer is pretty full, sleep to drain data
        // to save battery.
        int32_t fullFrames = mAudioEndpoint->getFullFramesAvailable();
        if (fullFrames > getDeviceBufferSize() - mOffloadSafeMarginInFrames &&
            fullFrames > getDeviceSampleRate() * 1 + mOffloadSafeMarginInFrames) {
            if (aaudio_result_t drainResult = drainStream(
                    isDataCallbackSet() ? DrainType::DRAIN_ALL_ALLOW_SOFT_WAKEUP
                                        : DrainType::DRAIN_ALL_DATA);
                drainResult != AAUDIO_OK) {
                ALOGE("%s() failed to drain, error=%d", __func__, drainResult);
                return drainResult;
            }
        }
    }
    return result;
}

// Write as much data as we can without blocking.
aaudio_result_t AudioStreamInternalPlay::processDataNow(void *buffer, int32_t numFrames,
                                              int64_t currentNanoTime, int64_t *wakeTimePtr) {
    aaudio_result_t result = processCommands();
    if (result != AAUDIO_OK) {
        return result;
    }

    const char *traceName = "aaWrNow";
    ATRACE_BEGIN(traceName);

    if (mClockModel.isStarting()) {
        // Still haven't got any timestamps from server.
        // Keep waiting until we get some valid timestamps then start writing to the
        // current buffer position.
        ALOGV("%s() wait for valid timestamps", __func__);
        // Sleep very briefly and hope we get a timestamp soon.
        *wakeTimePtr = currentNanoTime + (2000 * AAUDIO_NANOS_PER_MICROSECOND);
        ATRACE_END();
        return 0;
    }
    // If we have gotten this far then we have at least one timestamp from server.

    // If a DMA channel or DSP is reading the other end then we have to update the readCounter.
    if (mAudioEndpoint->isFreeRunning()) {
        updateReadCounter(currentNanoTime);
    }

    if (mNeedCatchUp.isRequested()) {
        // Catch an MMAP pointer that is already advancing.
        // This will avoid initial underruns caused by a slow cold start.
        // We add a one burst margin in case the DSP advances before we can write the data.
        // This can help prevent the beginning of the stream from being skipped.
        advanceClientToMatchServerPosition(getDeviceFramesPerBurst());
        // Write data from previous data buffer to new endpoint.
        if (mUnprocessedFrames != 0 && mUnprocessedBuffer != nullptr) {
            if (const android::fifo_frames_t framesWritten =
                        mAudioEndpoint->write(mUnprocessedBuffer.get(), mUnprocessedFrames);
                    framesWritten != mUnprocessedFrames) {
                ALOGW("Some data lost after exiting standby, frames written: %d, "
                      "frames to write: %d", framesWritten, mUnprocessedFrames);
            }
        }
        mUnprocessedFrames = 0;
        mUnprocessedBuffer.reset();
        mNeedCatchUp.acknowledge();
    }

    // If the read index passed the write index then consider it an underrun.
    // For shared streams, the xRunCount is passed up from the service.
    if (mAudioEndpoint->isFreeRunning() && mAudioEndpoint->getFullFramesAvailable() < 0) {
        mXRunCount++;
        if (ATRACE_ENABLED()) {
            ATRACE_INT("aaUnderRuns", mXRunCount);
        }
    }

    // Write some data to the buffer.
    //ALOGD("AudioStreamInternal::processDataNow() - writeNowWithConversion(%d)", numFrames);
    int32_t framesWritten = writeNowWithConversion(buffer, numFrames);
    //ALOGD("AudioStreamInternal::processDataNow() - tried to write %d frames, wrote %d",
    //    numFrames, framesWritten);
    if (ATRACE_ENABLED()) {
        ATRACE_INT("aaWrote", framesWritten);
    }

    // Sleep if there is too much data in the buffer.
    // Calculate an ideal time to wake up.
    if (wakeTimePtr != nullptr
            && (mAudioEndpoint->getFullFramesAvailable() >= getDeviceBufferSize())) {
        // By default wake up a few milliseconds from now.  // TODO review
        int64_t wakeTime = currentNanoTime + (1 * AAUDIO_NANOS_PER_MILLISECOND);
        aaudio_stream_state_t state = getState();
        //ALOGD("AudioStreamInternal::processDataNow() - wakeTime based on %s",
        //      AAudio_convertStreamStateToText(state));
        switch (state) {
            case AAUDIO_STREAM_STATE_OPEN:
            case AAUDIO_STREAM_STATE_STARTING:
                if (framesWritten != 0) {
                    // Don't wait to write more data. Just prime the buffer.
                    wakeTime = currentNanoTime;
                }
                break;
            case AAUDIO_STREAM_STATE_STARTED:
            {
                // Calculate when there will be room available to write to the buffer.
                // If the appBufferSize is smaller than the endpointBufferSize then
                // we will have room to write data beyond the appBufferSize.
                // That is a technique used to reduce glitches without adding latency.
                const int64_t appBufferSize = getDeviceBufferSize();
                // The endpoint buffer size is set to the maximum that can be written.
                // If we use it then we must carve out some room to write data when we wake up.
                const int64_t endBufferSize = mAudioEndpoint->getBufferSizeInFrames()
                        - getDeviceFramesPerBurst();
                const int64_t bestBufferSize = std::min(appBufferSize, endBufferSize);
                int64_t targetReadPosition = mAudioEndpoint->getDataWriteCounter() - bestBufferSize;
                wakeTime = mClockModel.convertPositionToTime(targetReadPosition);
            }
                break;
            default:
                break;
        }
        *wakeTimePtr = wakeTime;

    }

    ATRACE_END();
    return framesWritten;
}

aaudio_result_t AudioStreamInternalPlay::writeNowWithConversion(
        const void* buffer, int32_t numFrames) {
    if (getSampleRate() == getDeviceSampleRate()) {
        return writeNowWithConversionMatchedSampleRate(buffer, numFrames);
    } else {
        return writeNowWithConversionFull(buffer, numFrames);
    }
}

aaudio_result_t AudioStreamInternalPlay::writeNowWithConversionMatchedSampleRate(
        const void* buffer, int32_t numFrames) {
    WrappingBuffer wrappingBuffer;
    auto byteBuffer = static_cast<const uint8_t*>(buffer);
    mAudioEndpoint->getEmptyFramesAvailable(&wrappingBuffer);

    if (getSampleRate() != getDeviceSampleRate()) {
        return AAUDIO_ERROR_INVALID_STATE;
    }

    int32_t framesLeft = numFrames;
    // Write data in one or two parts.
    int partIndex = 0;
    while (framesLeft > 0 && partIndex < WrappingBuffer::SIZE) {
        int32_t framesToWrite = framesLeft;
        int32_t framesAvailable = wrappingBuffer.numFrames[partIndex];
        if (framesAvailable > 0) {
            if (framesToWrite > framesAvailable) {
                framesToWrite = framesAvailable;
            }

            int32_t numBytes = getBytesPerFrame() * framesToWrite;

            mFlowGraph.process(byteBuffer,
                               framesToWrite,
                               wrappingBuffer.data[partIndex],
                               framesToWrite);

            byteBuffer += numBytes;
            framesLeft -= framesToWrite;
        } else {
            break;
        }
        partIndex++;
    }
    int32_t framesWritten = numFrames - framesLeft;
    mAudioEndpoint->advanceWriteIndex(framesWritten);

    return framesWritten;
}

aaudio_result_t AudioStreamInternalPlay::writeNowWithConversionFull(
        const void* buffer, int32_t numFrames) {
    WrappingBuffer wrappingBuffer;
    auto byteBuffer = static_cast<const uint8_t*>(buffer);
    mAudioEndpoint->getEmptyFramesAvailable(&wrappingBuffer);

    int32_t framesLeftInByteBuffer = numFrames;
    // Write data in one or two parts.
    int partIndex = 0;
    int framesWrittenToAudioEndpoint = 0;
    while (framesLeftInByteBuffer > 0 && partIndex < WrappingBuffer::SIZE) {
        int32_t framesAvailableInWrappingBuffer = wrappingBuffer.numFrames[partIndex];
        auto currentWrappingBuffer = static_cast<uint8_t*>(wrappingBuffer.data[partIndex]);

        if (framesAvailableInWrappingBuffer > 0) {
            // Pull data from the flowgraph in case there is residual data.
            const int32_t framesActuallyWrittenToWrappingBuffer = mFlowGraph.pull(
                    currentWrappingBuffer,
                    framesAvailableInWrappingBuffer);

            const int32_t numBytesActuallyWrittenToWrappingBuffer =
                    framesActuallyWrittenToWrappingBuffer * getBytesPerDeviceFrame();
            currentWrappingBuffer += numBytesActuallyWrittenToWrappingBuffer;
            framesAvailableInWrappingBuffer -= framesActuallyWrittenToWrappingBuffer;
            framesWrittenToAudioEndpoint += framesActuallyWrittenToWrappingBuffer;
        } else {
            break;
        }

        // Put data from byteBuffer into the flowgraph one buffer (8 frames) at a time.
        // Continuously pull as much data as possible from the flowgraph into the wrapping buffer.
        // The return value of mFlowGraph.process is the number of frames actually pulled.
        while (framesAvailableInWrappingBuffer > 0 && framesLeftInByteBuffer > 0) {
            int32_t framesToWriteFromByteBuffer = std::min(flowgraph::kDefaultBufferSize,
                                                           framesLeftInByteBuffer);
            // If the wrapping buffer is running low, write one frame at a time.
            if (framesAvailableInWrappingBuffer < flowgraph::kDefaultBufferSize) {
                framesToWriteFromByteBuffer = 1;
            }

            const int32_t numBytesToWriteFromByteBuffer = getBytesPerFrame() *
                    framesToWriteFromByteBuffer;

            //ALOGD("%s() framesLeftInByteBuffer %d, framesAvailableInWrappingBuffer %d, "
            //      "framesToWriteFromByteBuffer %d, numBytesToWriteFromByteBuffer %d"
            //      , __func__, framesLeftInByteBuffer, framesAvailableInWrappingBuffer,
            //      framesToWriteFromByteBuffer, numBytesToWriteFromByteBuffer);

            const int32_t framesActuallyWrittenToWrappingBuffer = mFlowGraph.process(
                    byteBuffer,
                    framesToWriteFromByteBuffer,
                    currentWrappingBuffer,
                    framesAvailableInWrappingBuffer);

            byteBuffer += numBytesToWriteFromByteBuffer;
            framesLeftInByteBuffer -= framesToWriteFromByteBuffer;
            const int32_t numBytesActuallyWrittenToWrappingBuffer =
                    framesActuallyWrittenToWrappingBuffer * getBytesPerDeviceFrame();
            currentWrappingBuffer += numBytesActuallyWrittenToWrappingBuffer;
            framesAvailableInWrappingBuffer -= framesActuallyWrittenToWrappingBuffer;
            framesWrittenToAudioEndpoint += framesActuallyWrittenToWrappingBuffer;

            //ALOGD("%s() numBytesActuallyWrittenToWrappingBuffer %d, "
            //      "framesLeftInByteBuffer %d, "
            //      "framesActuallyWrittenToWrappingBuffer %d, "
            //      "numBytesToWriteFromByteBuffer %d, "
            //      "framesWrittenToAudioEndpoint %d"
            //      , __func__, numBytesActuallyWrittenToWrappingBuffer,
            //      framesLeftInByteBuffer,
            //      framesActuallyWrittenToWrappingBuffer,
            //      numBytesToWriteFromByteBuffer,
            //      framesWrittenToAudioEndpoint);
        }
        partIndex++;
    }
    //ALOGD("%s() framesWrittenToAudioEndpoint %d, numFrames %d, "
    //      "framesLeftInByteBuffer %d"
    //      , __func__, framesWrittenToAudioEndpoint, numFrames,
    //      framesLeftInByteBuffer);

    // The audio endpoint should reference the number of frames written to the wrapping buffer.
    mAudioEndpoint->advanceWriteIndex(framesWrittenToAudioEndpoint);

    // The internal code should use the number of frames read from the app.
    return numFrames - framesLeftInByteBuffer;
}

int64_t AudioStreamInternalPlay::getFramesRead() {
    if (mAudioEndpoint) {
        const int64_t framesReadHardware = isClockModelInControl()
                ? mClockModel.convertTimeToPosition(AudioClock::getNanoseconds())
                : mAudioEndpoint->getDataReadCounter();
        // Add service offset and prevent retrograde motion.
        mLastFramesRead = std::max(mLastFramesRead, framesReadHardware + mFramesOffsetFromService);
    }
    return mLastFramesRead;
}

int64_t AudioStreamInternalPlay::getFramesWritten() {
    if (mAudioEndpoint) {
        mLastFramesWritten = std::max(
                mLastFramesWritten,
                mAudioEndpoint->getDataWriteCounter() + mFramesOffsetFromService);
    }
    return mLastFramesWritten;
}

aaudio_result_t AudioStreamInternalPlay::setOffloadEndOfStream() {
    if (getPerformanceMode() != AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED ||
        getSharingMode() != AAUDIO_SHARING_MODE_EXCLUSIVE) {
        // Offload end of stream callback is only available for offload playback.
        // Offload playback must be exclusive mode.
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }
    std::lock_guard<std::mutex> lock(mStreamMutex);
    if ((getState() != AAUDIO_STREAM_STATE_STARTED && getState() != AAUDIO_STREAM_STATE_STOPPING)
        || mClockModel.isStarting()) {
        // If the stream is not running or there is not timestamp from the service side,
        // it is not possible to set offload end of stream.
        return AAUDIO_ERROR_INVALID_STATE;
    }
    mOffloadEosPending = true;
    if (!isDataCallbackSet() && mPresentationEndCallbackProc != nullptr) {
        mOffloadEosNanosBoottime = mClockModel.convertPositionToBootTime(
                mAudioEndpoint->getDataWriteCounter() - getDeviceFramesPerBurst());
        if (android::elapsedRealtimeNano() >= mOffloadEosNanosBoottime) {
            ALOGD("%s no need to drain, all data is played", __func__);
            maybeCallPresentationEndCallback_l();
            mOffloadEosPending = false;
        } else {
            // When clients set offload end of stream, they may not want to write more data
            // before the presentation end callback is called. In that case, DO NOT allow
            // soft wake up here so that it only wakes up after draining all data.
            return drainStream_l(mOffloadEosNanosBoottime, DrainType::DRAIN_ALL_DATA);
        }
    }
    return AAUDIO_OK;
}

bool AudioStreamInternalPlay::shouldStopStream() {
    if (getPerformanceMode() != AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED) {
        return true;
    }
    std::lock_guard _l(mStreamMutex);
    return !mOffloadEosPending;
}

void AudioStreamInternalPlay::maybeCallPresentationEndCallback_l() {
    if (mPresentationEndCallbackProc != nullptr) {
        pid_t expected = CALLBACK_THREAD_NONE;
        if (mPresentationEndCallbackThread.compare_exchange_strong(expected, gettid())) {
            (*mPresentationEndCallbackProc)(
                    reinterpret_cast<AAudioStream*>(dynamic_cast<AudioStream*>(this)),
                    mPresentationEndCallbackUserData);
            mPresentationEndCallbackThread.store(CALLBACK_THREAD_NONE);
        } else {
            ALOGW("%s() presentation end callback already running!", __func__);
        }
    }
}

void AudioStreamInternalPlay::dropPresentationEndCallback_l() {
    mOffloadEosPending = false;
    mStreamEndCV.notify_one();
}

aaudio_result_t AudioStreamInternalPlay::requestStart_l() {
    StartType startType = DEFAULT;
    if (mPendingStop) {
        // Receive start while the stream is draining but not yet stopped. Restart the stream
        startType = RESUME_WHILE_DRAINING;
        mPendingStop = false;
    } else if (getPerformanceMode() == AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED) {
        if (mAudioEndpoint != nullptr &&
            mAudioEndpoint->getFullFramesAvailable() > getDeviceFramesPerBurst()) {
            startType = RESUME_WITH_UNPROCESSED_DATA_TO_COPY;
        }
    }
    return AudioStreamInternal::requestStart_l(startType);
}

aaudio_result_t AudioStreamInternalPlay::requestStop_l() {
    if (mDraining && mDrainType == DrainType::DRAIN_ALL_DATA) {
        mPendingStop = true;
    } else if (getPerformanceMode() == AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED) {
        if (mDraining) {
            activateStream_l();
        }
        // For offload stream, force draining all to avoid original drain allows soft wakeup.
        int64_t offloadSafeMarginInFrames =
                getDeviceSampleRate() * 100 / AAUDIO_MILLIS_PER_SECOND;
        // Use BootTime for wakeup time as the device may have be suspended.
        const int64_t wakeUpNanosBootTime = mClockModel.convertPositionToBootTime(
                mAudioEndpoint->getDataWriteCounter() - offloadSafeMarginInFrames);
        drainStream_l(wakeUpNanosBootTime, DrainType::DRAIN_ALL_DATA);
        mPendingStop = true;
    }
    // When stop is called, the service will notify the HAL so that no more data will be consumed.
    // In that case, it is no longer needed to wait for stream end.
    dropPresentationEndCallback_l();
    return AudioStreamInternal::requestStop_l();
}

void AudioStreamInternalPlay::wakeupCallbackThread_l() {
    if (!isDataCallbackSet()) {
        if (mOffloadEosPending) {
            // Reset `mOffloadEosPending` as it doesn't allow soft wake up when draining for
            // presentation end callback.
            mOffloadEosPending = false;
            if (android::elapsedRealtimeNano() >= mOffloadEosNanosBoottime) {
                maybeCallPresentationEndCallback_l();
            }
        }
        return;
    }
    mOffloadEosPending = false;
    mDraining = false;
    mDrainingNanos = 0;
    mNeedCallbackWakeup = true;
    mStreamEndCV.notify_one();
    mCallbackCV.notify_all();
}

aaudio_result_t AudioStreamInternalPlay::flushFromFrame_l(
        AAudio_FlushFromAccuracy accuracy, int64_t* position) {
    if (getServiceHandle() == AAUDIO_HANDLE_INVALID) {
        ALOGD("%s() mServiceStreamHandle invalid", __func__);
        return AAUDIO_ERROR_DISCONNECTED;
    }
    if (isDisconnected()) {
        ALOGD("%s() but DISCONNECTED", __func__);
        return AAUDIO_ERROR_DISCONNECTED;
    }

    aaudio_result_t result = AAUDIO_OK;
    {
        std::lock_guard _endpointLock(mEndpointMutex);
        int64_t framesWritten = getFramesWritten();
        if (framesWritten < *position) {
            ALOGE("%s(), the requested position is not yet written", __func__);
            result = AAUDIO_ERROR_OUT_OF_RANGE;
        }

        // The position is updated from the server, it may not be very accurate if the stream has
        // been active for a while. In that case, updates the latest timestamp and then get the
        // actual rewind position again.
        if (aaudio_result_t res = mServiceInterface.updateTimestamp(mServiceStreamHandleInfo);
                res != AAUDIO_OK) {
            ALOGE("%s() failed to update timestamp, error=%d", __func__, res);
            return res;
        }
        processCommands();
        const int64_t safePosition = getFramesRead() + mOffloadFlushFromSafeMarginInFrames;
        if (safePosition > framesWritten) {
            ALOGE("%s() do not have enough data, safePosition=%jd, frameWritten=%jd",
                  __func__, safePosition, framesWritten);
            return AAUDIO_ERROR_OUT_OF_RANGE;
        }
        int64_t actualPosition = std::max(safePosition, *position);
        if (accuracy == AAUDIO_FLUSH_FROM_FRAME_ACCURATE && actualPosition != *position) {
            result = AAUDIO_ERROR_OUT_OF_RANGE;
        }
        *position = actualPosition;
        if (result != AAUDIO_OK) {
            return result;
        }

        // Rewind successfully, update the written position as the rewound position.
        mLastFramesWritten = actualPosition;
        mAudioEndpoint->setDataWriteCounter(actualPosition - mFramesOffsetFromService);
        updateReadCounter(AudioClock::getNanoseconds());
    }
    wakeupCallbackThread_l();
    return result;
}

aaudio_result_t AudioStreamInternalPlay::drainStream(DrainType drainType) {
    int64_t offloadSafeMarginInFrames =
            drainType == DrainType::DRAIN_ALL_WITHOUT_WAKEUP_CALLBACK ? getDeviceFramesPerBurst()
                                                                      : mOffloadSafeMarginInFrames;
    // Use BootTime for wakeup time as the device may have be suspended.
    const int64_t wakeUpNanosBootTime = mClockModel.convertPositionToBootTime(
            mAudioEndpoint->getDataWriteCounter() - offloadSafeMarginInFrames);
    android::audio_utils::unique_lock ul(mStreamMutex);
    if (aaudio_result_t ret = drainStream_l(wakeUpNanosBootTime, drainType);
        ret != AAUDIO_OK) {
        ALOGE("%s() failed to drain, error=%d", __func__, ret);
        return ret;
    }
    mDraining = true;
    mDrainType = drainType;
    if (isDataCallbackSet()) {
        const int64_t drainNanos = std::max(
                (int64_t)0, wakeUpNanosBootTime - android::elapsedRealtimeNano());
        if (mUseDataAvailableCallback) {
            mDrainingNanos = drainNanos;
            mCallbackCV.notify_all();
            return AAUDIO_OK;
        }
        mCallbackCV.wait_for(ul, std::chrono::nanoseconds(drainNanos),
                             [this]() REQUIRES(mStreamMutex) {
            return !mDraining;
        });
        mDraining = false;
    }
    return AAUDIO_OK;
}

aaudio_result_t AudioStreamInternalPlay::drainStream_l(int64_t wakeUpNanos,
                                                       DrainType drainType) {
    aaudio_result_t result = mServiceInterface.drainStream(
            mServiceStreamHandleInfo, wakeUpNanos, drainType, &mWakeUpHandle);
    if (result == AAUDIO_OK) {
        return result;
    }
    ALOGE("%s() failed, error=%d", __func__, result);
    processCommands();
    result = isDisconnected() ? AAUDIO_ERROR_DISCONNECTED : result;
    maybeCallErrorCallback(result);
    return result;
}

aaudio_result_t AudioStreamInternalPlay::activateStream_l() {
    aaudio_result_t result = mServiceInterface.activateStream(
            mServiceStreamHandleInfo, mWakeUpHandle);
    if (result == AAUDIO_OK) {
        mWakeUpHandle = TimerQueue::INVALID_HANDLE;
        return result;
    }
    ALOGE("%s() failed, error=%d", __func__, result);
    processCommands();
    result = isDisconnected() ? AAUDIO_ERROR_DISCONNECTED : result;
    maybeCallErrorCallback(result);
    return result;
}

aaudio_result_t AudioStreamInternalPlay::setPlaybackParameters_l(
        const AAudioPlaybackParameters* parameters) {
    if (getPerformanceMode() != AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED) {
        // Setting playback parameters is not supported for offload stream.
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }
    if (isAAudioPlaybackParametersEqual(*parameters, mPlaybackParameters)) {
        return AAUDIO_OK;
    }
    android::AudioPlaybackRate rate = android::AUDIO_PLAYBACK_RATE_DEFAULT;
    if (aaudio_result_t result =
                AAudioConvert_aaudioToAndroidPlaybackParameters(*parameters, &rate);
            result != AAUDIO_OK) {
        ALOGE("%s failed to convert to android playback parameters", __func__);
        return result;
    }
    if (!android::isAudioPlaybackRateValid(rate)) {
        ALOGE("%s failed, the playback parameters are not valid", __func__);
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }

    if (rate.mFallbackMode == AUDIO_TIMESTRETCH_FALLBACK_DEFAULT) {
        // Unspecified by client, system determines behavior, set to `FAIL`.
        rate.mFallbackMode = AUDIO_TIMESTRETCH_FALLBACK_FAIL;
    }

    const aaudio_result_t result = mServiceInterface.setPlaybackParameters(
            mServiceStreamHandleInfo, rate);
    if (result == AAUDIO_OK) {
        if (mPlaybackParameters.speed != parameters->speed) {
            // The playback speed has changed, need to wake up the callback thread to avoid
            // the HAL consume faster and causing underrun.
            wakeupCallbackThread_l();
        }
        mPlaybackParameters = *parameters;
        // The playback speed is guaranteed to be greater than 0 by `isAudioPlaybackRateValid`.
        mClockModel.setPlaybackSpeed(mPlaybackParameters.speed);
    } else {
        ALOGE("%s failed, error=%d", __func__, result);
    }
    return result;
}

aaudio_result_t AudioStreamInternalPlay::getPlaybackParameters_l(
        AAudioPlaybackParameters* parameters) {
    if (getPerformanceMode() != AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED) {
        // Setting playback parameters is not supported for offload stream.
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    android::AudioPlaybackRate rate;
    aaudio_result_t result = mServiceInterface.getPlaybackParameters(
            mServiceStreamHandleInfo, &rate);
    if (result != AAUDIO_OK) {
        ALOGE("%s failed to query from service", __func__);
        return result;
    }
    AAudioPlaybackParameters tempParam;
    if (result = AAudioConvert_androidToAAudioPlaybackParameters(rate, &tempParam);
        result != AAUDIO_OK) {
        ALOGE("%s failed to convert to aaudio playback parameters", __func__);
        return result;
    }
    mPlaybackParameters = tempParam;
    mClockModel.setPlaybackSpeed(mPlaybackParameters.speed);
    *parameters = tempParam;
    return AAUDIO_OK;
}

void AudioStreamInternalPlay::updateReadCounter(int64_t currentNanoTime) {
    // Update data queue based on the timing model.
    int64_t estimatedReadCounter = mClockModel.convertTimeToPosition(currentNanoTime);
    // ALOGD("%s - estimatedReadCounter = %jd", __func__, estimatedReadCounter);
    mAudioEndpoint->setDataReadCounter(estimatedReadCounter);
}

// Render audio in the application callback and then write the data to the stream.
void *AudioStreamInternalPlay::callbackLoop() {
    ALOGD("%s() entering >>>>>>>>>>>>>>>", __func__);
    aaudio_result_t result = AAUDIO_OK;
    int32_t callbackResult = 0;
    if (!isDataCallbackSet()) return nullptr;
    int64_t timeoutNanos = calculateReasonableTimeout(mCallbackFrames);

    // result might be a frame count
    while (mCallbackEnabled.load() && isActive() && (result >= 0)) {
        processCommands();
        if (getPerformanceMode() == AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED) {
            android::audio_utils::unique_lock ul(mStreamMutex);
            if (mOffloadEosPending) {
                // Use BootTime for wakeup time as the device may have be suspended.
                const int64_t wakeUpNanosBootTime = mClockModel.convertPositionToBootTime(
                        mAudioEndpoint->getDataWriteCounter() - getDeviceFramesPerBurst());
                if (result = drainStream_l(wakeUpNanosBootTime, DrainType::DRAIN_ALL_DATA);
                    result != AAUDIO_OK) {
                    ALOGE("%s() failed to drain, error=%d", __func__, result);
                    break;
                }
                const int64_t streamEndNanos = std::max(
                        int64_t(0), wakeUpNanosBootTime - android::elapsedRealtimeNano());
                mStreamEndCV.wait_for(ul, std::chrono::nanoseconds(streamEndNanos),
                                      [this]() REQUIRES(mStreamMutex) {
                    return !mOffloadEosPending;
                });
                if (mOffloadEosPending || android::elapsedRealtimeNano() >= wakeUpNanosBootTime) {
                    maybeCallPresentationEndCallback_l();
                    mOffloadEosPending = false;
                }
            }
        }
        int64_t timeoutNanosForDataAvailableCB = 0;
        int32_t callbackFrames = 0;
        if (mUseDataAvailableCallback) {
            android::audio_utils::unique_lock ul(mStreamMutex);
            // For data available callback, it doesn't transfer any data. Instead,
            // it signals a notification to client to call write for data transfer.
            {
                std::lock_guard _endpointLock(mEndpointMutex);
                callbackFrames = mAudioEndpoint->getEmptyFramesAvailable();
            }
            if (callbackFrames <= 0) {
                // No need to fire data callback. The DSP may just start or slowly read.
                // Wait for a burst to check if there is data available.
                mCallbackCV.wait_for(ul, std::chrono::nanoseconds(mNanosPerBurst));
                continue;
            }
            timeoutNanosForDataAvailableCB =
                    callbackFrames * AAUDIO_NANOS_PER_SECOND / getSampleRate();
            mNeedCallbackWakeup = false;
        } else {
            callbackFrames = mCallbackFrames;
        }
        // Call application using the AAudio callback interface.
        callbackResult = maybeCallDataCallback(mCallbackBuffer.get(), callbackFrames);

        if (callbackResult < 0) {
            if (!shouldStopStream()) {
                ALOGD("%s(): callback request to stop but should not as it may be pending for"
                      "stream end", __func__);
                continue;
            }
            ALOGD("%s(): callback request to stop", __func__);
            result = systemStopInternal();
            break;
        } else if (callbackResult == 0 &&
                getPerformanceMode() == AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED &&
                !mUseDataAvailableCallback) {
            // This is offload playback and the client uses a partial data callback. Returning
            // 0 indicates the client may not be able to feed any data now. In that case, drain
            // most of the data before firing another data callback. If there are enough data,
            // it is better to drain with a wakeup callback so that the device can go into deep
            // suspend for power saving. Otherwise, it is simpler to just suspend the data callback
            // thread and timestamp report at the service side. There's not an easy way to
            // determine when the device can go into deep suspend. Use double the safe margin(2s)
            // as a boundary check to decide if a wakeup callback is required or not.
            const int32_t fullFramesAvailable = mAudioEndpoint->getFullFramesAvailable();
            DrainType drainType = fullFramesAvailable > mOffloadSafeMarginInFrames * 2
                    ? DrainType::DRAIN_ALL_ALLOW_SOFT_WAKEUP
                    : DrainType::DRAIN_ALL_WITHOUT_WAKEUP_CALLBACK;
            if (result = drainStream(drainType); result != AAUDIO_OK) {
                ALOGE("%s failed to drain data(drainType=%d), stopping the data callback thread",
                      __func__, drainType);
                break;
            }
            if (result = mServiceInterface.updateTimestamp(mServiceStreamHandleInfo);
                result != AAUDIO_OK) {
                ALOGE("%s, failed to update timestamp, error=%d", __func__, result);
                break;
            }
        }

        if (mUseDataAvailableCallback) {
            // Data available callback mode doesn't transfer data from the callback. Wait until the
            // client write enough data for draining.
            {
                android::audio_utils::unique_lock ul(mStreamMutex);
                mCallbackCV.wait_for(
                        ul, std::chrono::nanoseconds(timeoutNanosForDataAvailableCB),
                        [this]() REQUIRES(mStreamMutex) {
                    return mNeedCallbackWakeup || mDraining;
                });

                if (mDrainingNanos > 0) {
                    mCallbackCV.wait_for(ul, std::chrono::nanoseconds(mDrainingNanos),
                                         [this]() REQUIRES(mStreamMutex) {
                        return mNeedCallbackWakeup || !mDraining;
                    });
                    ALOGW_IF(mDraining,
                             "After waiting for drain, still draining, stream is %s active",
                             isActive() ? "" : "not");
                }
            }
        } else {
            // Write audio data to stream. This is a BLOCKING WRITE!
            // Write data regardless of the callbackResult because we assume the data
            // is valid even when the callback returns AAUDIO_CALLBACK_RESULT_STOP.
            // Imagine a callback that is playing a large sound in menory.
            // When it gets to the end of the sound it can partially fill the last buffer
            // with the end of the sound, then zero pad the buffer, then return STOP.
            // If the callback has no valid data then it should zero-fill the entire buffer.
            result = write(mCallbackBuffer.get(), callbackResult, timeoutNanos);
            if (result != callbackResult) {
                break;
            }
        }
    }

    ALOGD("%s() exiting, result = %d, isActive() = %d <<<<<<<<<<<<<<",
          __func__, result, (int) isActive());
    return nullptr;
}

//------------------------------------------------------------------------------
// Implementation of PlayerBase
status_t AudioStreamInternalPlay::doSetVolume() {
    float combinedVolume = mStreamVolume * getDuckAndMuteVolume();
    ALOGD("%s() mStreamVolume * duckAndMuteVolume = %f * %f = %f",
          __func__, mStreamVolume, getDuckAndMuteVolume(), combinedVolume);
    mFlowGraph.setTargetVolume(combinedVolume);
    return android::NO_ERROR;
}

//------------------------------------------------------------------------------
// Implementation of AAudioClientCallback
void AudioStreamInternalPlay::onWakeUp_l(android::audio_utils::TimerQueue::handle_t handle) {
    if (handle != mWakeUpHandle) {
        ALOGW("%s the wake up handle does not match %jd %jd", __func__, handle, mWakeUpHandle);
    }
    mWakeUpHandle = TimerQueue::INVALID_HANDLE;
    if (mPendingStop) {
        // When onWakeUp is called, it indicates drain completion. `mPendingStop` indicates the
        // client has called stop before. In that case, update state and positions to stopped state.
        // Note that we don't need to update stream state here as it should be updated from another
        // service event.
        if (mUseDataAvailableCallback) {
            maybeCallPresentationEndCallback_l();
        }
        if (mAudioEndpoint != nullptr) {
            const int64_t writeCounter = mAudioEndpoint->getDataWriteCounter();
            const int64_t nowNanos = AudioClock::getNanoseconds();
            // Read counter should be the same as write counter when all data is drained.
            mAudioEndpoint->setDataReadCounter(writeCounter);
            // There will not be any more mmap position update in this case. Force a position
            // update with write counter and time to reflect the truth that all data is played.
            mClockModel.setPositionAndTime(writeCounter, nowNanos);
            mClockModel.stop(nowNanos);
        }
        mPendingStop = false;
    }
    processCommands();
    if (isClockModelInControl()) {
        // If the stream is active, ensure the read counter is refreshed
        // for data available callback.
        mAudioEndpoint->setDataReadCounter(
                mClockModel.convertTimeToPosition(AudioClock::getNanoseconds()));
    }
    wakeupCallbackThread_l();
}
