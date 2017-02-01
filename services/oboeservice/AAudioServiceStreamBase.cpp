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

#define LOG_TAG "AAudioService"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include "IAAudioService.h"
#include "AAudioServiceDefinitions.h"
#include "AAudioServiceStreamBase.h"
#include "AudioEndpointParcelable.h"

using namespace android;
using namespace aaudio;

/**
 * Construct the AudioCommandQueues and the AudioDataQueue
 * and fill in the endpoint parcelable.
 */

AAudioServiceStreamBase::AAudioServiceStreamBase()
        : mUpMessageQueue(nullptr)
{
    // TODO could fail so move out of constructor
    mUpMessageQueue = new SharedRingBuffer();
    mUpMessageQueue->allocate(sizeof(AAudioServiceMessage), QUEUE_UP_CAPACITY_COMMANDS);
}

AAudioServiceStreamBase::~AAudioServiceStreamBase() {
    Mutex::Autolock _l(mLockUpMessageQueue);
    delete mUpMessageQueue;
}

void AAudioServiceStreamBase::sendServiceEvent(aaudio_service_event_t event,
                              int32_t data1,
                              int64_t data2) {

    Mutex::Autolock _l(mLockUpMessageQueue);
    AAudioServiceMessage command;
    command.what = AAudioServiceMessage::code::EVENT;
    command.event.event = event;
    command.event.data1 = data1;
    command.event.data2 = data2;
    mUpMessageQueue->getFifoBuffer()->write(&command, 1);
}


