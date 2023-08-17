/*
 * Copyright (C) 2023 The Android Open Source Project
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

#pragma once

namespace android {

class IAfRecordTrack;

/* The ResamplerBufferProvider is used to retrieve recorded input data from the
 * RecordThread.  It maintains local state on the relative position of the read
 * position of the RecordTrack compared with the RecordThread.
 */
class ResamplerBufferProvider : public AudioBufferProvider
{
public:
    explicit ResamplerBufferProvider(IAfRecordTrack* recordTrack) :
        mRecordTrack(recordTrack) {}

    // called to set the ResamplerBufferProvider to head of the RecordThread data buffer,
    // skipping any previous data read from the hal.
    void reset();

    /* Synchronizes RecordTrack position with the RecordThread.
     * Calculates available frames and handle overruns if the RecordThread
     * has advanced faster than the ResamplerBufferProvider has retrieved data.
     * TODO: why not do this for every getNextBuffer?
     *
     * Parameters
     * framesAvailable:  pointer to optional output size_t to store record track
     *                   frames available.
     *      hasOverrun:  pointer to optional boolean, returns true if track has overrun.
     */

    void sync(size_t* framesAvailable = nullptr, bool* hasOverrun = nullptr);

    // AudioBufferProvider interface
    status_t getNextBuffer(AudioBufferProvider::Buffer* buffer) final;
    void releaseBuffer(AudioBufferProvider::Buffer* buffer) final;

    int32_t getFront() const { return mRsmpInFront; }
    void setFront(int32_t front) { mRsmpInFront = front; }

private:
    IAfRecordTrack* const mRecordTrack;
    size_t mRsmpInUnrel = 0;   // unreleased frames remaining from
                               // most recent getNextBuffer
                               // for debug only
    int32_t mRsmpInFront = 0;  // next available frame
                               // rolling counter that is never cleared
};

} // namespace android