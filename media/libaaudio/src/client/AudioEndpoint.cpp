/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "AAudio"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <cassert>
#include <aaudio/AAudioDefinitions.h>

#include "AudioEndpointParcelable.h"
#include "AudioEndpoint.h"
#include "AAudioServiceMessage.h"

using namespace android;
using namespace aaudio;

AudioEndpoint::AudioEndpoint()
    : mOutputFreeRunning(false)
    , mDataReadCounter(0)
    , mDataWriteCounter(0)
{
}

AudioEndpoint::~AudioEndpoint()
{
}

static void AudioEndpoint_validateQueueDescriptor(const char *type,
                                                  const RingBufferDescriptor *descriptor) {
    assert(descriptor->capacityInFrames > 0);
    assert(descriptor->bytesPerFrame > 1);
    assert(descriptor->dataAddress != nullptr);
    ALOGD("AudioEndpoint_validateQueueDescriptor %s, dataAddress at %p ====================",
          type,
          descriptor->dataAddress);
    ALOGD("AudioEndpoint_validateQueueDescriptor  readCounter at %p, writeCounter at %p",
          descriptor->readCounterAddress,
          descriptor->writeCounterAddress);

    // Try to READ from the data area.
    uint8_t value = descriptor->dataAddress[0];
    ALOGD("AudioEndpoint_validateQueueDescriptor() dataAddress[0] = %d, then try to write",
        (int) value);
    // Try to WRITE to the data area.
    descriptor->dataAddress[0] = value;
    ALOGD("AudioEndpoint_validateQueueDescriptor() wrote successfully");

    if (descriptor->readCounterAddress) {
        fifo_counter_t counter = *descriptor->readCounterAddress;
        ALOGD("AudioEndpoint_validateQueueDescriptor() *readCounterAddress = %d, now write",
              (int) counter);
        *descriptor->readCounterAddress = counter;
        ALOGD("AudioEndpoint_validateQueueDescriptor() wrote readCounterAddress successfully");
    }
    if (descriptor->writeCounterAddress) {
        fifo_counter_t counter = *descriptor->writeCounterAddress;
        ALOGD("AudioEndpoint_validateQueueDescriptor() *writeCounterAddress = %d, now write",
              (int) counter);
        *descriptor->writeCounterAddress = counter;
        ALOGD("AudioEndpoint_validateQueueDescriptor() wrote writeCounterAddress successfully");
    }
}

void AudioEndpoint_validateDescriptor(const EndpointDescriptor *pEndpointDescriptor) {
    AudioEndpoint_validateQueueDescriptor("msg", &pEndpointDescriptor->upMessageQueueDescriptor);
    AudioEndpoint_validateQueueDescriptor("data", &pEndpointDescriptor->downDataQueueDescriptor);
}

aaudio_result_t AudioEndpoint::configure(const EndpointDescriptor *pEndpointDescriptor)
{
    aaudio_result_t result = AAUDIO_OK;
    AudioEndpoint_validateDescriptor(pEndpointDescriptor); // FIXME remove after debugging

    const RingBufferDescriptor *descriptor = &pEndpointDescriptor->upMessageQueueDescriptor;
    assert(descriptor->bytesPerFrame == sizeof(AAudioServiceMessage));
    assert(descriptor->readCounterAddress != nullptr);
    assert(descriptor->writeCounterAddress != nullptr);
    mUpCommandQueue = new FifoBuffer(
            descriptor->bytesPerFrame,
            descriptor->capacityInFrames,
            descriptor->readCounterAddress,
            descriptor->writeCounterAddress,
            descriptor->dataAddress
    );
    /* TODO mDownCommandQueue
    if (descriptor->capacityInFrames > 0) {
        descriptor = &pEndpointDescriptor->downMessageQueueDescriptor;
        mDownCommandQueue = new FifoBuffer(
                descriptor->capacityInFrames,
                descriptor->bytesPerFrame,
                descriptor->readCounterAddress,
                descriptor->writeCounterAddress,
                descriptor->dataAddress
        );
    }
     */
    descriptor = &pEndpointDescriptor->downDataQueueDescriptor;
    assert(descriptor->capacityInFrames > 0);
    assert(descriptor->bytesPerFrame > 1);
    assert(descriptor->bytesPerFrame < 4 * 16); // FIXME just for initial debugging
    assert(descriptor->framesPerBurst > 0);
    assert(descriptor->framesPerBurst < 8 * 1024); // FIXME just for initial debugging
    assert(descriptor->dataAddress != nullptr);
    ALOGD("AudioEndpoint::configure() data framesPerBurst = %d", descriptor->framesPerBurst);
    ALOGD("AudioEndpoint::configure() data readCounterAddress = %p", descriptor->readCounterAddress);
    mOutputFreeRunning = descriptor->readCounterAddress == nullptr;
    ALOGD("AudioEndpoint::configure() mOutputFreeRunning = %d", mOutputFreeRunning ? 1 : 0);
    int64_t *readCounterAddress = (descriptor->readCounterAddress == nullptr)
                                  ? &mDataReadCounter
                                  : descriptor->readCounterAddress;
    int64_t *writeCounterAddress = (descriptor->writeCounterAddress == nullptr)
                                  ? &mDataWriteCounter
                                  : descriptor->writeCounterAddress;
    mDownDataQueue = new FifoBuffer(
            descriptor->bytesPerFrame,
            descriptor->capacityInFrames,
            readCounterAddress,
            writeCounterAddress,
            descriptor->dataAddress
    );
    uint32_t threshold = descriptor->capacityInFrames / 2;
    mDownDataQueue->setThreshold(threshold);
    return result;
}

aaudio_result_t AudioEndpoint::readUpCommand(AAudioServiceMessage *commandPtr)
{
    return mUpCommandQueue->read(commandPtr, 1);
}

aaudio_result_t AudioEndpoint::writeDataNow(const void *buffer, int32_t numFrames)
{
    return mDownDataQueue->write(buffer, numFrames);
}

void AudioEndpoint::setDownDataReadCounter(fifo_counter_t framesRead)
{
    mDownDataQueue->setReadCounter(framesRead);
}

fifo_counter_t AudioEndpoint::getDownDataReadCounter()
{
    return mDownDataQueue->getReadCounter();
}

void AudioEndpoint::setDownDataWriteCounter(fifo_counter_t framesRead)
{
    mDownDataQueue->setWriteCounter(framesRead);
}

fifo_counter_t AudioEndpoint::getDownDataWriteCounter()
{
    return mDownDataQueue->getWriteCounter();
}

int32_t AudioEndpoint::setBufferSizeInFrames(int32_t requestedFrames,
                                            int32_t *actualFrames)
{
    if (requestedFrames < ENDPOINT_DATA_QUEUE_SIZE_MIN) {
        requestedFrames = ENDPOINT_DATA_QUEUE_SIZE_MIN;
    }
    mDownDataQueue->setThreshold(requestedFrames);
    *actualFrames = mDownDataQueue->getThreshold();
    return AAUDIO_OK;
}

int32_t AudioEndpoint::getBufferSizeInFrames() const
{
    return mDownDataQueue->getThreshold();
}

int32_t AudioEndpoint::getBufferCapacityInFrames() const
{
    return (int32_t)mDownDataQueue->getBufferCapacityInFrames();
}

int32_t AudioEndpoint::getFullFramesAvailable()
{
    return mDownDataQueue->getFifoControllerBase()->getFullFramesAvailable();
}
