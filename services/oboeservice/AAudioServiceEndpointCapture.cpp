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

#define LOG_TAG "AAudioService"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <assert.h>
#include <map>
#include <mutex>
#include <utils/Singleton.h>

#include "AAudioEndpointManager.h"
#include "AAudioServiceEndpoint.h"

#include "core/AudioStreamBuilder.h"
#include "AAudioServiceEndpoint.h"
#include "AAudioServiceStreamShared.h"
#include "AAudioServiceEndpointCapture.h"

using namespace android;  // TODO just import names needed
using namespace aaudio;   // TODO just import names needed

AAudioServiceEndpointCapture::AAudioServiceEndpointCapture(AAudioService &audioService)
        : mStreamInternalCapture(audioService, true) {
}

AAudioServiceEndpointCapture::~AAudioServiceEndpointCapture() {
    delete mDistributionBuffer;
}

aaudio_result_t AAudioServiceEndpointCapture::open(const AAudioStreamConfiguration& configuration) {
    aaudio_result_t result = AAudioServiceEndpoint::open(configuration);
    if (result == AAUDIO_OK) {
        delete mDistributionBuffer;
        int distributionBufferSizeBytes = getStreamInternal()->getFramesPerBurst()
                                          * getStreamInternal()->getBytesPerFrame();
        mDistributionBuffer = new uint8_t[distributionBufferSizeBytes];
    }
    return result;
}

// Read data from the shared MMAP stream and then distribute it to the client streams.
void *AAudioServiceEndpointCapture::callbackLoop() {
    ALOGD("AAudioServiceEndpointCapture(): callbackLoop() entering");
    int32_t underflowCount = 0;
    aaudio_result_t result = AAUDIO_OK;
    int64_t timeoutNanos = getStreamInternal()->calculateReasonableTimeout();

    // result might be a frame count
    while (mCallbackEnabled.load() && getStreamInternal()->isActive() && (result >= 0)) {
        // Read audio data from stream using a blocking read.
        result = getStreamInternal()->read(mDistributionBuffer, getFramesPerBurst(), timeoutNanos);
        if (result == AAUDIO_ERROR_DISCONNECTED) {
            disconnectRegisteredStreams();
            break;
        } else if (result != getFramesPerBurst()) {
            ALOGW("AAudioServiceEndpointCapture(): callbackLoop() read %d / %d",
                  result, getFramesPerBurst());
            break;
        }

        // Distribute data to each active stream.
        { // use lock guard
            std::lock_guard <std::mutex> lock(mLockStreams);
            for (sp<AAudioServiceStreamShared> sharedStream : mRegisteredStreams) {
                if (sharedStream->isRunning()) {
                    FifoBuffer *fifo = sharedStream->getDataFifoBuffer();
                    if (fifo->getFifoControllerBase()->getEmptyFramesAvailable() <
                        getFramesPerBurst()) {
                        underflowCount++;
                    } else {
                        fifo->write(mDistributionBuffer, getFramesPerBurst());
                    }
                    sharedStream->markTransferTime(AudioClock::getNanoseconds());
                }
            }
        }
    }

    ALOGD("AAudioServiceEndpointCapture(): callbackLoop() exiting, %d underflows", underflowCount);
    return NULL; // TODO review
}
