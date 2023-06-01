/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <atomic>
#include <audio_utils/Balance.h>
#include "FastThread.h"
#include "StateQueue.h"
#include "FastMixerState.h"
#include "FastMixerDumpState.h"
#include <afutils/NBAIO_Tee.h>

namespace android {

class AudioMixer;

using FastMixerStateQueue = StateQueue<FastMixerState>;

class FastMixer : public FastThread {

public:
    /** FastMixer constructor takes as param the parent MixerThread's io handle (id)
        for purposes of identification. */
    explicit FastMixer(audio_io_handle_t threadIoHandle);

            FastMixerStateQueue* sq();

    virtual void setMasterMono(bool mono) { mMasterMono.store(mono); /* memory_order_seq_cst */ }
    virtual void setMasterBalance(float balance) { mMasterBalance.store(balance); }
    virtual float getMasterBalance() const { return mMasterBalance.load(); }
    virtual void setBoottimeOffset(int64_t boottimeOffset) {
        mBoottimeOffset.store(boottimeOffset); /* memory_order_seq_cst */
    }
private:
            FastMixerStateQueue mSQ;

    // callouts
    const FastThreadState *poll() override;
    void setNBLogWriter(NBLog::Writer *logWriter) override;
    void onIdle() override;
    void onExit() override;
    bool isSubClassCommand(FastThreadState::Command command) override;
    void onStateChange() override;
    void onWork() override;

    enum Reason {
        REASON_REMOVE,
        REASON_ADD,
        REASON_MODIFY,
    };
    // called when a fast track of index has been removed, added, or modified
    void updateMixerTrack(int index, Reason reason);

    // FIXME these former local variables need comments
    static const FastMixerState sInitial;

    FastMixerState  mPreIdle;   // copy of state before we went into idle
    int             mGenerations[FastMixerState::kMaxFastTracks]{};
                                // last observed mFastTracks[i].mGeneration
    NBAIO_Sink*     mOutputSink = nullptr;
    int             mOutputSinkGen = 0;
    AudioMixer*     mMixer = nullptr;

    // mSinkBuffer audio format is stored in format.mFormat.
    void*           mSinkBuffer = nullptr; // used for mixer output format translation
                                        // if sink format is different than mixer output.
    size_t          mSinkBufferSize = 0;
    uint32_t        mSinkChannelCount = FCC_2;
    audio_channel_mask_t mSinkChannelMask;        // set in ctor
    void*           mMixerBuffer = nullptr;       // mixer output buffer.
    size_t          mMixerBufferSize = 0;
    static constexpr audio_format_t mMixerBufferFormat = AUDIO_FORMAT_PCM_FLOAT;

    // audio channel count, excludes haptic channels.  Set in onStateChange().
    uint32_t        mAudioChannelCount = 0;

    enum {UNDEFINED, MIXED, ZEROED} mMixerBufferState = UNDEFINED;
    NBAIO_Format    mFormat{Format_Invalid};
    unsigned        mSampleRate = 0;
    int             mFastTracksGen = 0;
    FastMixerDumpState mDummyFastMixerDumpState;
    int64_t         mTotalNativeFramesWritten = 0;  // copied to dumpState->mFramesWritten

    // next 2 fields are valid only when timestampStatus == NO_ERROR
    ExtendedTimestamp mTimestamp;
    int64_t         mNativeFramesWrittenButNotPresented = 0;

    audio_utils::Balance mBalance;

    // accessed without lock between multiple threads.
    std::atomic_bool mMasterMono{};
    std::atomic<float> mMasterBalance{};
    std::atomic_int_fast64_t mBoottimeOffset{};

    // parent thread id for debugging purposes
    [[maybe_unused]] const audio_io_handle_t mThreadIoHandle;
#ifdef TEE_SINK
    NBAIO_Tee       mTee;
#endif
};  // class FastMixer

}   // namespace android
