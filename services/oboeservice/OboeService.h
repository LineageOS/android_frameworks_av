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

#ifndef OBOE_OBOE_SERVICE_H
#define OBOE_OBOE_SERVICE_H

#include <stdint.h>

#include <oboe/OboeAudio.h>

#include "binding/RingBufferParcelable.h"

namespace oboe {

// TODO move this an "include" folder for the service.

struct OboeMessageTimestamp {
    oboe_position_frames_t position;
    int64_t                deviceOffset; // add to client position to get device position
    oboe_nanoseconds_t     timestamp;
};

typedef enum oboe_service_event_e : uint32_t {
    OBOE_SERVICE_EVENT_STARTED,
    OBOE_SERVICE_EVENT_PAUSED,
    OBOE_SERVICE_EVENT_FLUSHED,
    OBOE_SERVICE_EVENT_CLOSED,
    OBOE_SERVICE_EVENT_DISCONNECTED
} oboe_service_event_t;

struct OboeMessageEvent {
    oboe_service_event_t event;
    int32_t data1;
    int64_t data2;
};

typedef struct OboeServiceMessage_s {
    enum class code : uint32_t {
        NOTHING,
        TIMESTAMP,
        EVENT,
    };

    code what;
    union {
        OboeMessageTimestamp timestamp;
        OboeMessageEvent event;
    };
} OboeServiceMessage;


} /* namespace oboe */

#endif //OBOE_OBOE_SERVICE_H
