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

#ifndef OBOE_TIMESTAMP_SCHEDULER_H
#define OBOE_TIMESTAMP_SCHEDULER_H

//#include <stdlib.h> // random()

#include "IOboeAudioService.h"
#include "OboeService.h"
#include "AudioStream.h"
#include "fifo/FifoBuffer.h"
#include "SharedRingBuffer.h"
#include "AudioEndpointParcelable.h"

namespace oboe {

/**
 * Schedule wakeup time for monitoring the position
 * of an MMAP/NOIRQ buffer.
 *
 * Note that this object is not thread safe. Only call it from a single thread.
 */
class TimestampScheduler
{
public:
    TimestampScheduler() {};
    virtual ~TimestampScheduler() = default;

    /**
     * Start the schedule at the given time.
     */
    void start(oboe_nanoseconds_t startTime);

    /**
     * Calculate the next time that the read position should be
     * measured.
     */
    oboe_nanoseconds_t nextAbsoluteTime();

    void setBurstPeriod(oboe_nanoseconds_t burstPeriod) {
        mBurstPeriod = burstPeriod;
    }

    void setBurstPeriod(oboe_size_frames_t framesPerBurst,
                        oboe_sample_rate_t sampleRate) {
        mBurstPeriod = OBOE_NANOS_PER_SECOND * framesPerBurst / sampleRate;
    }

    oboe_nanoseconds_t getBurstPeriod() {
        return mBurstPeriod;
    }

private:
    // Start with an arbitrary default so we do not divide by zero.
    oboe_nanoseconds_t mBurstPeriod = OBOE_NANOS_PER_MILLISECOND;
    oboe_nanoseconds_t mStartTime;
    oboe_nanoseconds_t mLastTime;
};

} /* namespace oboe */

#endif /* OBOE_TIMESTAMP_SCHEDULER_H */
