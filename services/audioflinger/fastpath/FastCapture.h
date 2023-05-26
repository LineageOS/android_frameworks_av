/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "FastThread.h"
#include "StateQueue.h"
#include "FastCaptureState.h"
#include "FastCaptureDumpState.h"

namespace android {

using FastCaptureStateQueue = StateQueue<FastCaptureState>;

class FastCapture : public FastThread {

public:
            FastCapture();

            FastCaptureStateQueue*  sq();

private:
            FastCaptureStateQueue   mSQ;

    // callouts
    const FastThreadState *poll() override;
    void setNBLogWriter(NBLog::Writer *logWriter) override;
    void onIdle() override;
    void onExit() override;
    bool isSubClassCommand(FastThreadState::Command command) override;
    void onStateChange() override;
    void onWork() override;

    static const FastCaptureState sInitial;

    FastCaptureState    mPreIdle;   // copy of state before we went into idle
    // FIXME by renaming, could pull up many of these to FastThread
    NBAIO_Source*       mInputSource = nullptr;
    int                 mInputSourceGen = 0;
    NBAIO_Sink*         mPipeSink = nullptr;
    int                 mPipeSinkGen = 0;
    void*               mReadBuffer = nullptr;
    ssize_t             mReadBufferState = -1;  // number of initialized frames in readBuffer,
                                                // or -1 to clear
    NBAIO_Format        mFormat = Format_Invalid;
    unsigned            mSampleRate = 0;
    FastCaptureDumpState mDummyFastCaptureDumpState;
    uint32_t            mTotalNativeFramesRead = 0; // copied to dumpState->mFramesRead

};  // class FastCapture

}   // namespace android
