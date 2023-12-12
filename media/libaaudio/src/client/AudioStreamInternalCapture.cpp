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

#include <algorithm>
#include <audio_utils/format.h>
#include <aaudio/AAudio.h>
#include <media/MediaMetricsItem.h>

#include "client/AudioStreamInternalCapture.h"
#include "utility/AudioClock.h"

#undef ATRACE_TAG
#define ATRACE_TAG ATRACE_TAG_AUDIO
#include <utils/Trace.h>

// We do this after the #includes because if a header uses ALOG.
// it would fail on the reference to mInService.
#undef LOG_TAG
// This file is used in both client and server processes.
// This is needed to make sense of the logs more easily.
#define LOG_TAG (mInService ? "AudioStreamInternalCapture_Service" \
                          : "AudioStreamInternalCapture_Client")

using android::WrappingBuffer;

using namespace aaudio;

AudioStreamInternalCapture::AudioStreamInternalCapture(AAudioServiceInterface  &serviceInterface,
                                                 bool inService)
    : AudioStreamInternal(serviceInterface, inService) {

}

aaudio_result_t AudioStreamInternalCapture::open(const AudioStreamBuilder &builder) {
    aaudio_result_t result = AudioStreamInternal::open(builder);
    if (result == AAUDIO_OK) {
        result = mFlowGraph.configure(getDeviceFormat(),
                             getDeviceSamplesPerFrame(),
                             getDeviceSampleRate(),
                             getFormat(),
                             getSamplesPerFrame(),
                             getSampleRate(),
                             getRequireMonoBlend(),
                             false /* useVolumeRamps */,
                             getAudioBalance(),
                             aaudio::resampler::MultiChannelResampler::Quality::Medium);

        if (result != AAUDIO_OK) {
            safeReleaseClose();
        }
    }
    return result;
}

void AudioStreamInternalCapture::advanceClientToMatchServerPosition(int32_t serverMargin) {
    int64_t readCounter = mAudioEndpoint->getDataReadCounter();
    int64_t writeCounter = mAudioEndpoint->getDataWriteCounter() + serverMargin;

    // Bump offset so caller does not see the retrograde motion in getFramesRead().
    int64_t offset = readCounter - writeCounter;
    mFramesOffsetFromService += offset;
    ALOGD("advanceClientToMatchServerPosition() readN = %lld, writeN = %lld, offset = %lld",
          (long long)readCounter, (long long)writeCounter, (long long)mFramesOffsetFromService);

    // Force readCounter to match writeCounter.
    // This is because we cannot change the write counter in the hardware.
    mAudioEndpoint->setDataReadCounter(writeCounter);
}

// Write the data, block if needed and timeoutMillis > 0
aaudio_result_t AudioStreamInternalCapture::read(void *buffer, int32_t numFrames,
                                               int64_t timeoutNanoseconds)
{
    return processData(buffer, numFrames, timeoutNanoseconds);
}

// Read as much data as we can without blocking.
aaudio_result_t AudioStreamInternalCapture::processDataNow(void *buffer, int32_t numFrames,
                                                  int64_t currentNanoTime, int64_t *wakeTimePtr) {
    aaudio_result_t result = processCommands();
    if (result != AAUDIO_OK) {
        return result;
    }

    const char *traceName = "aaRdNow";
    ATRACE_BEGIN(traceName);

    if (mClockModel.isStarting()) {
        // Still haven't got any timestamps from server.
        // Keep waiting until we get some valid timestamps then start writing to the
        // current buffer position.
        ALOGD("processDataNow() wait for valid timestamps");
        // Sleep very briefly and hope we get a timestamp soon.
        *wakeTimePtr = currentNanoTime + (2000 * AAUDIO_NANOS_PER_MICROSECOND);
        ATRACE_END();
        return 0;
    }
    // If we have gotten this far then we have at least one timestamp from server.

    if (mAudioEndpoint->isFreeRunning()) {
        //ALOGD("AudioStreamInternalCapture::processDataNow() - update remote counter");
        // Update data queue based on the timing model.
        // Jitter in the DSP can cause late writes to the FIFO.
        // This might be caused by resampling.
        // We want to read the FIFO after the latest possible time
        // that the DSP could have written the data.
        int64_t estimatedRemoteCounter = mClockModel.convertLatestTimeToPosition(currentNanoTime);
        // TODO refactor, maybe use setRemoteCounter()
        mAudioEndpoint->setDataWriteCounter(estimatedRemoteCounter);
    }

    // This code assumes that we have already received valid timestamps.
    if (mNeedCatchUp.isRequested()) {
        // Catch an MMAP pointer that is already advancing.
        // This will avoid initial underruns caused by a slow cold start.
        advanceClientToMatchServerPosition(0 /*serverMargin*/);
        mNeedCatchUp.acknowledge();
    }

    // If the capture buffer is full beyond capacity then consider it an overrun.
    // For shared streams, the xRunCount is passed up from the service.
    if (mAudioEndpoint->isFreeRunning()
        && mAudioEndpoint->getFullFramesAvailable() > mAudioEndpoint->getBufferCapacityInFrames()) {
        mXRunCount++;
        if (ATRACE_ENABLED()) {
            ATRACE_INT("aaOverRuns", mXRunCount);
        }
    }

    // Read some data from the buffer.
    //ALOGD("AudioStreamInternalCapture::processDataNow() - readNowWithConversion(%d)", numFrames);
    int32_t framesProcessed = readNowWithConversion(buffer, numFrames);
    //ALOGD("AudioStreamInternalCapture::processDataNow() - tried to read %d frames, read %d",
    //    numFrames, framesProcessed);
    if (ATRACE_ENABLED()) {
        ATRACE_INT("aaRead", framesProcessed);
    }

    // Calculate an ideal time to wake up.
    if (wakeTimePtr != nullptr && framesProcessed >= 0) {
        // By default wake up a few milliseconds from now.  // TODO review
        int64_t wakeTime = currentNanoTime + (1 * AAUDIO_NANOS_PER_MILLISECOND);
        aaudio_stream_state_t state = getState();
        //ALOGD("AudioStreamInternalCapture::processDataNow() - wakeTime based on %s",
        //      AAudio_convertStreamStateToText(state));
        switch (state) {
            case AAUDIO_STREAM_STATE_OPEN:
            case AAUDIO_STREAM_STATE_STARTING:
                break;
            case AAUDIO_STREAM_STATE_STARTED:
            {
                // When do we expect the next write burst to occur?

                // Calculate frame position based off of the readCounter because
                // the writeCounter might have just advanced in the background,
                // causing us to sleep until a later burst.
                const int64_t nextPosition = mAudioEndpoint->getDataReadCounter() +
                        getDeviceFramesPerBurst();
                wakeTime = mClockModel.convertPositionToLatestTime(nextPosition);
            }
                break;
            default:
                break;
        }
        *wakeTimePtr = wakeTime;

    }

    ATRACE_END();
    return framesProcessed;
}

aaudio_result_t AudioStreamInternalCapture::readNowWithConversion(void *buffer,
                                                                int32_t numFrames) {
    WrappingBuffer wrappingBuffer;
    uint8_t *byteBuffer = (uint8_t *) buffer;
    int32_t framesLeftInByteBuffer = numFrames;

    if (framesLeftInByteBuffer > 0) {
        // Pull data from the flowgraph in case there is residual data.
        const int32_t framesActuallyWrittenToByteBuffer = mFlowGraph.pull(
                (void *)byteBuffer,
                framesLeftInByteBuffer);

        const int32_t numBytesActuallyWrittenToByteBuffer =
                framesActuallyWrittenToByteBuffer * getBytesPerFrame();
        byteBuffer += numBytesActuallyWrittenToByteBuffer;
        framesLeftInByteBuffer -= framesActuallyWrittenToByteBuffer;
    }

    mAudioEndpoint->getFullFramesAvailable(&wrappingBuffer);

    // Write data in one or two parts.
    int partIndex = 0;
    int framesReadFromAudioEndpoint = 0;
    while (framesLeftInByteBuffer > 0 && partIndex < WrappingBuffer::SIZE) {
        const int32_t totalFramesInWrappingBuffer = wrappingBuffer.numFrames[partIndex];
        int32_t framesAvailableInWrappingBuffer = totalFramesInWrappingBuffer;
        uint8_t *currentWrappingBuffer = (uint8_t *) wrappingBuffer.data[partIndex];

        if (framesAvailableInWrappingBuffer <= 0) break;

        // Put data from the wrapping buffer into the flowgraph 8 frames at a time.
        // Continuously pull as much data as possible from the flowgraph into the byte buffer.
        // The return value of mFlowGraph.process is the number of frames actually pulled.
        while (framesAvailableInWrappingBuffer > 0 && framesLeftInByteBuffer > 0) {
            const int32_t framesToReadFromWrappingBuffer = std::min(flowgraph::kDefaultBufferSize,
                    framesAvailableInWrappingBuffer);

            const int32_t numBytesToReadFromWrappingBuffer = getBytesPerDeviceFrame() *
                    framesToReadFromWrappingBuffer;

            // If framesActuallyWrittenToByteBuffer < framesLeftInByteBuffer, it is guaranteed
            // that all the data is pulled. If there is no more space in the byteBuffer, the
            // remaining data will be pulled in the following readNowWithConversion().
            const int32_t framesActuallyWrittenToByteBuffer = mFlowGraph.process(
                    (void *)currentWrappingBuffer,
                    framesToReadFromWrappingBuffer,
                    (void *)byteBuffer,
                    framesLeftInByteBuffer);

            const int32_t numBytesActuallyWrittenToByteBuffer =
                    framesActuallyWrittenToByteBuffer * getBytesPerFrame();
            byteBuffer += numBytesActuallyWrittenToByteBuffer;
            framesLeftInByteBuffer -= framesActuallyWrittenToByteBuffer;
            currentWrappingBuffer += numBytesToReadFromWrappingBuffer;
            framesAvailableInWrappingBuffer -= framesToReadFromWrappingBuffer;

            //ALOGD("%s() numBytesActuallyWrittenToByteBuffer %d, framesLeftInByteBuffer %d"
            //      "framesAvailableInWrappingBuffer %d, framesReadFromAudioEndpoint %d"
            //      , __func__, numBytesActuallyWrittenToByteBuffer, framesLeftInByteBuffer,
            //      framesAvailableInWrappingBuffer, framesReadFromAudioEndpoint);
        }
        framesReadFromAudioEndpoint += totalFramesInWrappingBuffer -
                framesAvailableInWrappingBuffer;
        partIndex++;
    }

    // The audio endpoint should reference the number of frames written to the wrapping buffer.
    mAudioEndpoint->advanceReadIndex(framesReadFromAudioEndpoint);

    // The internal code should use the number of frames read from the app.
    return numFrames - framesLeftInByteBuffer;
}

int64_t AudioStreamInternalCapture::getFramesWritten() {
    if (mAudioEndpoint) {
        const int64_t framesWrittenHardware = isClockModelInControl()
                ? mClockModel.convertTimeToPosition(AudioClock::getNanoseconds())
                : mAudioEndpoint->getDataWriteCounter();
        // Add service offset and prevent retrograde motion.
        mLastFramesWritten = std::max(mLastFramesWritten,
                                      framesWrittenHardware + mFramesOffsetFromService);
    }
    return mLastFramesWritten;
}

int64_t AudioStreamInternalCapture::getFramesRead() {
    if (mAudioEndpoint) {
        mLastFramesRead = mAudioEndpoint->getDataReadCounter() + mFramesOffsetFromService;
    }
    return mLastFramesRead;
}

// Read data from the stream and pass it to the callback for processing.
void *AudioStreamInternalCapture::callbackLoop() {
    aaudio_result_t result = AAUDIO_OK;
    aaudio_data_callback_result_t callbackResult = AAUDIO_CALLBACK_RESULT_CONTINUE;
    if (!isDataCallbackSet()) return nullptr;

    // result might be a frame count
    while (mCallbackEnabled.load() && isActive() && (result >= 0)) {

        // Read audio data from stream.
        int64_t timeoutNanos = calculateReasonableTimeout(mCallbackFrames);

        // This is a BLOCKING READ!
        result = read(mCallbackBuffer.get(), mCallbackFrames, timeoutNanos);
        if ((result != mCallbackFrames)) {
            ALOGE("callbackLoop: read() returned %d", result);
            if (result >= 0) {
                // Only read some of the frames requested. The stream can be disconnected
                // or timed out.
                processCommands();
                result = isDisconnected() ? AAUDIO_ERROR_DISCONNECTED : AAUDIO_ERROR_TIMEOUT;
            }
            maybeCallErrorCallback(result);
            break;
        }

        // Call application using the AAudio callback interface.
        callbackResult = maybeCallDataCallback(mCallbackBuffer.get(), mCallbackFrames);

        if (callbackResult == AAUDIO_CALLBACK_RESULT_STOP) {
            ALOGD("%s(): callback returned AAUDIO_CALLBACK_RESULT_STOP", __func__);
            result = systemStopInternal();
            break;
        }
    }

    ALOGD("callbackLoop() exiting, result = %d, isActive() = %d",
          result, (int) isActive());
    return nullptr;
}
