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
#include <utils/Log.h>

#define ATRACE_TAG ATRACE_TAG_AUDIO

#include <media/MediaMetricsItem.h>
#include <utils/Trace.h>

#include "client/AudioStreamInternalPlay.h"
#include "utility/AudioClock.h"

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

AudioStreamInternalPlay::AudioStreamInternalPlay(AAudioServiceInterface  &serviceInterface,
                                                       bool inService)
        : AudioStreamInternal(serviceInterface, inService) {

}

constexpr int kRampMSec = 10; // time to apply a change in volume

aaudio_result_t AudioStreamInternalPlay::open(const AudioStreamBuilder &builder) {
    aaudio_result_t result = AudioStreamInternal::open(builder);
    const bool useVolumeRamps = (getSharingMode() == AAUDIO_SHARING_MODE_EXCLUSIVE);
    if (result == AAUDIO_OK) {
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
    return result;
}

// This must be called under mStreamLock.
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
    return mServiceInterface.pauseStream(mServiceStreamHandleInfo);
}

aaudio_result_t AudioStreamInternalPlay::requestFlush_l() {
    if (getServiceHandle() == AAUDIO_HANDLE_INVALID) {
        ALOGW("%s() mServiceStreamHandle invalid", __func__);
        return AAUDIO_ERROR_INVALID_STATE;
    }

    setState(AAUDIO_STREAM_STATE_FLUSHING);
    return mServiceInterface.flushStream(mServiceStreamHandleInfo);
}

void AudioStreamInternalPlay::prepareBuffersForStart() {
    // Reset volume ramps to avoid a starting noise.
    // This was called here instead of AudioStreamInternal so that
    // it will be easier to backport.
    mFlowGraph.reset();
    // Prevent stale data from being played.
    mAudioEndpoint->eraseDataMemory();
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
    return processData((void *)buffer, numFrames, timeoutNanoseconds);
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
        // Update data queue based on the timing model.
        int64_t estimatedReadCounter = mClockModel.convertTimeToPosition(currentNanoTime);
        // ALOGD("AudioStreamInternal::processDataNow() - estimatedReadCounter = %d", (int)estimatedReadCounter);
        mAudioEndpoint->setDataReadCounter(estimatedReadCounter);
    }

    if (mNeedCatchUp.isRequested()) {
        // Catch an MMAP pointer that is already advancing.
        // This will avoid initial underruns caused by a slow cold start.
        // We add a one burst margin in case the DSP advances before we can write the data.
        // This can help prevent the beginning of the stream from being skipped.
        advanceClientToMatchServerPosition(getFramesPerBurst());
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


aaudio_result_t AudioStreamInternalPlay::writeNowWithConversion(const void *buffer,
                                                            int32_t numFrames) {
    WrappingBuffer wrappingBuffer;
    uint8_t *byteBuffer = (uint8_t *) buffer;
    int32_t framesLeftInByteBuffer = numFrames;

    mAudioEndpoint->getEmptyFramesAvailable(&wrappingBuffer);

    // Write data in one or two parts.
    int partIndex = 0;
    int framesWrittenToAudioEndpoint = 0;
    while (framesLeftInByteBuffer > 0 && partIndex < WrappingBuffer::SIZE) {
        int32_t framesAvailableInWrappingBuffer = wrappingBuffer.numFrames[partIndex];
        uint8_t *currentWrappingBuffer = (uint8_t *) wrappingBuffer.data[partIndex];

        if (framesAvailableInWrappingBuffer > 0) {
            // Pull data from the flowgraph in case there is residual data.
            const int32_t framesActuallyWrittenToWrappingBuffer = mFlowGraph.pull(
                (void*) currentWrappingBuffer,
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

            //ALOGD("%s() framesLeftInByteBuffer %d, framesAvailableInWrappingBuffer %d"
            //      "framesToWriteFromByteBuffer %d, numBytesToWriteFromByteBuffer %d"
            //      , __func__, framesLeftInByteBuffer, framesAvailableInWrappingBuffer,
            //      framesToWriteFromByteBuffer, numBytesToWriteFromByteBuffer);

            const int32_t framesActuallyWrittenToWrappingBuffer = mFlowGraph.process(
                    (void *)byteBuffer,
                    framesToWriteFromByteBuffer,
                    (void *)currentWrappingBuffer,
                    framesAvailableInWrappingBuffer);

            byteBuffer += numBytesToWriteFromByteBuffer;
            framesLeftInByteBuffer -= framesToWriteFromByteBuffer;
            const int32_t numBytesActuallyWrittenToWrappingBuffer =
                    framesActuallyWrittenToWrappingBuffer * getBytesPerDeviceFrame();
            currentWrappingBuffer += numBytesActuallyWrittenToWrappingBuffer;
            framesAvailableInWrappingBuffer -= framesActuallyWrittenToWrappingBuffer;
            framesWrittenToAudioEndpoint += framesActuallyWrittenToWrappingBuffer;

            //ALOGD("%s() numBytesActuallyWrittenToWrappingBuffer %d, framesLeftInByteBuffer %d"
            //      "framesActuallyWrittenToWrappingBuffer %d, numBytesToWriteFromByteBuffer %d"
            //      "framesWrittenToAudioEndpoint %d"
            //      , __func__, numBytesActuallyWrittenToWrappingBuffer, framesLeftInByteBuffer,
            //      framesActuallyWrittenToWrappingBuffer, numBytesToWriteFromByteBuffer,
            //      framesWrittenToAudioEndpoint);
        }
        partIndex++;
    }
    //ALOGD("%s() framesWrittenToAudioEndpoint %d, numFrames %d"
    //              "framesLeftInByteBuffer %d"
    //              , __func__, framesWrittenToAudioEndpoint, numFrames,
    //              framesLeftInByteBuffer);

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

// Render audio in the application callback and then write the data to the stream.
void *AudioStreamInternalPlay::callbackLoop() {
    ALOGD("%s() entering >>>>>>>>>>>>>>>", __func__);
    aaudio_result_t result = AAUDIO_OK;
    aaudio_data_callback_result_t callbackResult = AAUDIO_CALLBACK_RESULT_CONTINUE;
    if (!isDataCallbackSet()) return nullptr;
    int64_t timeoutNanos = calculateReasonableTimeout(mCallbackFrames);

    // result might be a frame count
    while (mCallbackEnabled.load() && isActive() && (result >= 0)) {
        // Call application using the AAudio callback interface.
        callbackResult = maybeCallDataCallback(mCallbackBuffer.get(), mCallbackFrames);

        if (callbackResult == AAUDIO_CALLBACK_RESULT_CONTINUE) {
            // Write audio data to stream. This is a BLOCKING WRITE!
            result = write(mCallbackBuffer.get(), mCallbackFrames, timeoutNanos);
            if ((result != mCallbackFrames)) {
                if (result >= 0) {
                    // Only wrote some of the frames requested. The stream can be disconnected
                    // or timed out.
                    processCommands();
                    result = isDisconnected() ? AAUDIO_ERROR_DISCONNECTED : AAUDIO_ERROR_TIMEOUT;
                }
                maybeCallErrorCallback(result);
                break;
            }
        } else if (callbackResult == AAUDIO_CALLBACK_RESULT_STOP) {
            ALOGD("%s(): callback returned AAUDIO_CALLBACK_RESULT_STOP", __func__);
            result = systemStopInternal();
            break;
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
