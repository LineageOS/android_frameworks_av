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

#pragma once

#include "TrackBase.h"

#include <android/content/AttributionSourceState.h>
#include <audio_utils/mutex.h>
#include <datapath/AudioStreamIn.h> // struct Source

namespace android {

// record track
class RecordTrack : public TrackBase, public virtual IAfRecordTrack {
public:
    RecordTrack(IAfRecordThread* thread,
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
                                const AttributionSourceState& attributionSource,
                                audio_input_flags_t flags,
                                track_type type,
                                audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE,
                                int32_t startFrames = -1);
    ~RecordTrack() override;
    status_t initCheck() const final;

    status_t start(AudioSystem::sync_event_t event, audio_session_t triggerSession) final;
    void stop() final;
    void destroy() final;
    void invalidate() final;

            // clear the buffer overflow flag
    void clearOverflow() final { mOverflow = false; }
            // set the buffer overflow flag and return previous value
    bool setOverflow() final { bool tmp = mOverflow; mOverflow = true;
                                                return tmp; }

    void appendDumpHeader(String8& result) const final;
    void appendDump(String8& result, bool active) const final;

    void handleSyncStartEvent(const sp<audioflinger::SyncEvent>& event) final;
    void clearSyncStartEvent() final;

    void updateTrackFrameInfo(int64_t trackFramesReleased,
                                             int64_t sourceFramesRead,
                                             uint32_t halSampleRate,
                                             const ExtendedTimestamp &timestamp) final;

    bool isFastTrack() const final { return (mFlags & AUDIO_INPUT_FLAG_FAST) != 0; }
    bool isDirect() const final
                                { return (mFlags & AUDIO_INPUT_FLAG_DIRECT) != 0; }

    void setSilenced(bool silenced) final { if (!isPatchTrack()) mSilenced = silenced; }
    bool isSilenced() const final { return mSilenced; }

    status_t getActiveMicrophones(
            std::vector<media::MicrophoneInfoFw>* activeMicrophones) const final;

    status_t setPreferredMicrophoneDirection(audio_microphone_direction_t direction) final;
    status_t setPreferredMicrophoneFieldDimension(float zoom) final;
    status_t shareAudioHistory(const std::string& sharedAudioPackageName,
            int64_t sharedAudioStartMs) final;
    int32_t startFrames() const final { return mStartFrames; }

    using SinkMetadatas = std::vector<record_track_metadata_v7_t>;
    using MetadataInserter = std::back_insert_iterator<SinkMetadatas>;
    void copyMetadataTo(MetadataInserter& backInserter) const final;

    AudioBufferProvider::Buffer& sinkBuffer() final { return mSink; }
    audioflinger::SynchronizedRecordState& synchronizedRecordState() final {
        return mSynchronizedRecordState;
    }
    RecordBufferConverter* recordBufferConverter() const final { return mRecordBufferConverter; }
    ResamplerBufferProvider* resamplerBufferProvider() const final {
        return mResamplerBufferProvider;
    }

private:
    DISALLOW_COPY_AND_ASSIGN(RecordTrack);

protected:
    // AudioBufferProvider interface
    status_t getNextBuffer(AudioBufferProvider::Buffer* buffer) override;
    // releaseBuffer() not overridden

private:

    bool                mOverflow;  // overflow on most recent attempt to fill client buffer

            AudioBufferProvider::Buffer mSink;  // references client's buffer sink in shared memory

            // sync event triggering actual audio capture. Frames read before this event will
            // be dropped and therefore not read by the application.
            sp<audioflinger::SyncEvent>        mSyncStartEvent;

            audioflinger::SynchronizedRecordState
                    mSynchronizedRecordState{mSampleRate}; // sampleRate defined in base

            // used by resampler to find source frames
            ResamplerBufferProvider* mResamplerBufferProvider;

            // used by the record thread to convert frames to proper destination format
            RecordBufferConverter              *mRecordBufferConverter;
            audio_input_flags_t                mFlags;

            bool                               mSilenced;

            std::string                        mSharedAudioPackageName = {};
            int32_t                            mStartFrames = -1;
};

// playback track, used by PatchPanel
class PatchRecord : public RecordTrack, public PatchTrackBase, public IAfPatchRecord {
public:
    PatchRecord(IAfRecordThread* recordThread,
                uint32_t sampleRate,
                audio_channel_mask_t channelMask,
                audio_format_t format,
                size_t frameCount,
                void *buffer,
                size_t bufferSize,
                audio_input_flags_t flags,
                const Timeout& timeout = {},
                audio_source_t source = AUDIO_SOURCE_DEFAULT);
    ~PatchRecord() override;

    Source* getSource() override { return nullptr; }

    // AudioBufferProvider interface
    status_t getNextBuffer(AudioBufferProvider::Buffer* buffer) override;
    void releaseBuffer(AudioBufferProvider::Buffer* buffer) override;

    // PatchProxyBufferProvider interface
    status_t obtainBuffer(Proxy::Buffer* buffer,
                                     const struct timespec* timeOut = nullptr) override;
    void releaseBuffer(Proxy::Buffer* buffer) override;

    size_t writeFrames(const void* src, size_t frameCount, size_t frameSize) final {
        return writeFrames(this, src, frameCount, frameSize);
    }

protected:
    /** Write the source data into the buffer provider. @return written frame count. */
    static size_t writeFrames(AudioBufferProvider* dest, const void* src,
            size_t frameCount, size_t frameSize);

};  // end of PatchRecord

class PassthruPatchRecord : public PatchRecord, public Source {
public:
    PassthruPatchRecord(IAfRecordThread* recordThread,
                        uint32_t sampleRate,
                        audio_channel_mask_t channelMask,
                        audio_format_t format,
                        size_t frameCount,
                        audio_input_flags_t flags,
                        audio_source_t source = AUDIO_SOURCE_DEFAULT);

    Source* getSource() final { return static_cast<Source*>(this); }

    // Source interface
    status_t read(void* buffer, size_t bytes, size_t* read) final;
    status_t getCapturePosition(int64_t* frames, int64_t* time) final;
    status_t standby() final;

    // AudioBufferProvider interface
    // This interface is used by RecordThread to pass the data obtained
    // from HAL or other source to the client. PassthruPatchRecord receives
    // the data in 'obtainBuffer' so these calls are stubbed out.
    status_t getNextBuffer(AudioBufferProvider::Buffer* buffer) final;
    void releaseBuffer(AudioBufferProvider::Buffer* buffer) final;

    // PatchProxyBufferProvider interface
    // This interface is used from DirectOutputThread to acquire data from HAL.
    bool producesBufferOnDemand() const final { return true; }
    status_t obtainBuffer(Proxy::Buffer* buffer, const struct timespec* timeOut = nullptr) final;
    void releaseBuffer(Proxy::Buffer* buffer) final;

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

    sp<StreamInHalInterface> obtainStream(sp<IAfThreadBase>* thread);
    audio_utils::mutex& readMutex() const { return mReadMutex; }

    PatchRecordAudioBufferProvider mPatchRecordAudioBufferProvider;
    std::unique_ptr<void, decltype(free)*> mSinkBuffer;  // frame size aligned continuous buffer
    std::unique_ptr<void, decltype(free)*> mStubBuffer;  // buffer used for AudioBufferProvider
    size_t mUnconsumedFrames = 0;
    mutable audio_utils::mutex mReadMutex;
    audio_utils::condition_variable mReadCV;
    size_t mReadBytes = 0; // GUARDED_BY(readMutex())
    status_t mReadError = NO_ERROR; // GUARDED_BY(readMutex())
    int64_t mLastReadFrames = 0;  // accessed on RecordThread only
};

} // namespace android
