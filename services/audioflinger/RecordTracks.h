/*
**
** Copyright 2012, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#ifndef INCLUDING_FROM_AUDIOFLINGER_H
    #error This header file should only be included from AudioFlinger.h
#endif

// Checks and monitors OP_RECORD_AUDIO
class OpRecordAudioMonitor : public RefBase {
public:
    ~OpRecordAudioMonitor() override;
    bool hasOpRecordAudio() const;

    static sp<OpRecordAudioMonitor> createIfNeeded
        (uid_t uid, const audio_attributes_t& attr, const String16& opPackageName);

private:
    OpRecordAudioMonitor(uid_t uid, const String16& opPackageName);
    void onFirstRef() override;

    AppOpsManager mAppOpsManager;

    class RecordAudioOpCallback : public BnAppOpsCallback {
    public:
        explicit RecordAudioOpCallback(const wp<OpRecordAudioMonitor>& monitor);
        void opChanged(int32_t op, const String16& packageName) override;

    private:
        const wp<OpRecordAudioMonitor> mMonitor;
    };

    sp<RecordAudioOpCallback> mOpCallback;
    // called by RecordAudioOpCallback when OP_RECORD_AUDIO is updated in AppOp callback
    // and in onFirstRef()
    void checkRecordAudio();

    std::atomic_bool mHasOpRecordAudio;
    const uid_t mUid;
    const String16 mPackage;
};

// record track
class RecordTrack : public TrackBase {
public:
                        RecordTrack(RecordThread *thread,
                                const sp<Client>& client,
                                const audio_attributes_t& attr,
                                uint32_t sampleRate,
                                audio_format_t format,
                                audio_channel_mask_t channelMask,
                                size_t frameCount,
                                void *buffer,
                                size_t bufferSize,
                                audio_session_t sessionId,
                                pid_t creatorPid,
                                uid_t uid,
                                audio_input_flags_t flags,
                                track_type type,
                                const String16& opPackageName,
                                audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE);
    virtual             ~RecordTrack();
    virtual status_t    initCheck() const;

    virtual status_t    start(AudioSystem::sync_event_t event, audio_session_t triggerSession);
    virtual void        stop();

            void        destroy();

    virtual void        invalidate();
            // clear the buffer overflow flag
            void        clearOverflow() { mOverflow = false; }
            // set the buffer overflow flag and return previous value
            bool        setOverflow() { bool tmp = mOverflow; mOverflow = true;
                                                return tmp; }

            void        appendDumpHeader(String8& result);
            void        appendDump(String8& result, bool active);

            void        handleSyncStartEvent(const sp<SyncEvent>& event);
            void        clearSyncStartEvent();

            void        updateTrackFrameInfo(int64_t trackFramesReleased,
                                             int64_t sourceFramesRead,
                                             uint32_t halSampleRate,
                                             const ExtendedTimestamp &timestamp);

    virtual bool        isFastTrack() const { return (mFlags & AUDIO_INPUT_FLAG_FAST) != 0; }
            bool        isDirect() const override
                                { return (mFlags & AUDIO_INPUT_FLAG_DIRECT) != 0; }

            void        setSilenced(bool silenced) { if (!isPatchTrack()) mSilenced = silenced; }
            bool        isSilenced() const;

            status_t    getActiveMicrophones(std::vector<media::MicrophoneInfo>* activeMicrophones);

            status_t    setPreferredMicrophoneDirection(audio_microphone_direction_t direction);
            status_t    setPreferredMicrophoneFieldDimension(float zoom);

    static  bool        checkServerLatencySupported(
                                audio_format_t format, audio_input_flags_t flags) {
                            return audio_is_linear_pcm(format)
                                    && (flags & AUDIO_INPUT_FLAG_HW_AV_SYNC) == 0;
                        }

private:
    friend class AudioFlinger;  // for mState

    DISALLOW_COPY_AND_ASSIGN(RecordTrack);

    // AudioBufferProvider interface
    virtual status_t getNextBuffer(AudioBufferProvider::Buffer* buffer);
    // releaseBuffer() not overridden

    bool                mOverflow;  // overflow on most recent attempt to fill client buffer

            AudioBufferProvider::Buffer mSink;  // references client's buffer sink in shared memory

            // sync event triggering actual audio capture. Frames read before this event will
            // be dropped and therefore not read by the application.
            sp<SyncEvent>                       mSyncStartEvent;

            // number of captured frames to drop after the start sync event has been received.
            // when < 0, maximum frames to drop before starting capture even if sync event is
            // not received
            ssize_t                             mFramesToDrop;

            // used by resampler to find source frames
            ResamplerBufferProvider            *mResamplerBufferProvider;

            // used by the record thread to convert frames to proper destination format
            RecordBufferConverter              *mRecordBufferConverter;
            audio_input_flags_t                mFlags;

            bool                               mSilenced;

            // used to enforce OP_RECORD_AUDIO
            uid_t                              mUid;
            String16                           mOpPackageName;
            sp<OpRecordAudioMonitor>           mOpRecordAudioMonitor;
};

// playback track, used by PatchPanel
class PatchRecord : public RecordTrack, public PatchTrackBase {
public:

    PatchRecord(RecordThread *recordThread,
                uint32_t sampleRate,
                audio_channel_mask_t channelMask,
                audio_format_t format,
                size_t frameCount,
                void *buffer,
                size_t bufferSize,
                audio_input_flags_t flags,
                const Timeout& timeout = {});
    virtual             ~PatchRecord();

    virtual Source* getSource() { return nullptr; }

    // AudioBufferProvider interface
    virtual status_t getNextBuffer(AudioBufferProvider::Buffer* buffer);
    virtual void releaseBuffer(AudioBufferProvider::Buffer* buffer);

    // PatchProxyBufferProvider interface
    virtual status_t    obtainBuffer(Proxy::Buffer *buffer,
                                     const struct timespec *timeOut = NULL);
    virtual void        releaseBuffer(Proxy::Buffer *buffer);

    size_t writeFrames(const void* src, size_t frameCount, size_t frameSize) {
        return writeFrames(this, src, frameCount, frameSize);
    }

protected:
    /** Write the source data into the buffer provider. @return written frame count. */
    static size_t writeFrames(AudioBufferProvider* dest, const void* src,
            size_t frameCount, size_t frameSize);

};  // end of PatchRecord

class PassthruPatchRecord : public PatchRecord, public Source {
public:
    PassthruPatchRecord(RecordThread *recordThread,
                        uint32_t sampleRate,
                        audio_channel_mask_t channelMask,
                        audio_format_t format,
                        size_t frameCount,
                        audio_input_flags_t flags);

    Source* getSource() override { return static_cast<Source*>(this); }

    // Source interface
    status_t read(void *buffer, size_t bytes, size_t *read) override;
    status_t getCapturePosition(int64_t *frames, int64_t *time) override;
    status_t standby() override;

    // AudioBufferProvider interface
    // This interface is used by RecordThread to pass the data obtained
    // from HAL or other source to the client. PassthruPatchRecord receives
    // the data in 'obtainBuffer' so these calls are stubbed out.
    status_t getNextBuffer(AudioBufferProvider::Buffer* buffer) override;
    void releaseBuffer(AudioBufferProvider::Buffer* buffer) override;

    // PatchProxyBufferProvider interface
    // This interface is used from DirectOutputThread to acquire data from HAL.
    bool producesBufferOnDemand() const override { return true; }
    status_t obtainBuffer(Proxy::Buffer *buffer, const struct timespec *timeOut = nullptr) override;
    void releaseBuffer(Proxy::Buffer *buffer) override;

private:
    // This is to use with PatchRecord::writeFrames
    struct PatchRecordAudioBufferProvider : public AudioBufferProvider {
        explicit PatchRecordAudioBufferProvider(PassthruPatchRecord& passthru) :
                mPassthru(passthru) {}
        status_t getNextBuffer(AudioBufferProvider::Buffer* buffer) override {
            return mPassthru.PatchRecord::getNextBuffer(buffer);
        }
        void releaseBuffer(AudioBufferProvider::Buffer* buffer) override {
            return mPassthru.PatchRecord::releaseBuffer(buffer);
        }
    private:
        PassthruPatchRecord& mPassthru;
    };

    sp<StreamInHalInterface> obtainStream(sp<ThreadBase>* thread);

    PatchRecordAudioBufferProvider mPatchRecordAudioBufferProvider;
    std::unique_ptr<void, decltype(free)*> mSinkBuffer;  // frame size aligned continuous buffer
    std::unique_ptr<void, decltype(free)*> mStubBuffer;  // buffer used for AudioBufferProvider
    size_t mUnconsumedFrames = 0;
    std::mutex mReadLock;
    std::condition_variable mReadCV;
    size_t mReadBytes = 0; // GUARDED_BY(mReadLock)
    status_t mReadError = NO_ERROR; // GUARDED_BY(mReadLock)
    int64_t mLastReadFrames = 0;  // accessed on RecordThread only
};
