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

#define LOG_TAG "OboeService"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include "IOboeAudioService.h"
#include "OboeService.h"
#include "OboeServiceStreamBase.h"
#include "AudioEndpointParcelable.h"

using namespace android;
using namespace oboe;

/**
 * Construct the AudioCommandQueues and the AudioDataQueue
 * and fill in the endpoint parcelable.
 */

OboeServiceStreamBase::OboeServiceStreamBase()
        : mUpMessageQueue(nullptr)
{
    // TODO could fail so move out of constructor
    mUpMessageQueue = new SharedRingBuffer();
    mUpMessageQueue->allocate(sizeof(OboeServiceMessage), QUEUE_UP_CAPACITY_COMMANDS);
}

OboeServiceStreamBase::~OboeServiceStreamBase() {
    Mutex::Autolock _l(mLockUpMessageQueue);
    delete mUpMessageQueue;
}

void OboeServiceStreamBase::sendServiceEvent(oboe_service_event_t event,
                              int32_t data1,
                              int64_t data2) {

    Mutex::Autolock _l(mLockUpMessageQueue);
    OboeServiceMessage command;
    command.what = OboeServiceMessage::code::EVENT;
    command.event.event = event;
    command.event.data1 = data1;
    command.event.data2 = data2;
    mUpMessageQueue->getFifoBuffer()->write(&command, 1);
}


