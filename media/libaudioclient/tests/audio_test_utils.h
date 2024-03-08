/*
 * Copyright (C) 2021 The Android Open Source Project
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

#ifndef AUDIO_TEST_UTILS_H_
#define AUDIO_TEST_UTILS_H_

#include <sys/stat.h>
#include <unistd.h>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>

#include <binder/MemoryDealer.h>
#include <media/AidlConversion.h>
#include <media/AudioRecord.h>
#include <media/AudioTrack.h>

using namespace android;

struct MixPort {
    std::string name;
    std::string role;
    std::string flags;
};

struct Route {
    std::string name;
    std::string sources;
    std::string sink;
};

status_t listAudioPorts(std::vector<audio_port_v7>& portsVec);
status_t listAudioPatches(std::vector<struct audio_patch>& patchesVec);
status_t getPortByAttributes(audio_port_role_t role, audio_port_type_t type,
                             audio_devices_t deviceType, const std::string& address,
                             audio_port_v7& port);
status_t getPatchForOutputMix(audio_io_handle_t audioIo, audio_patch& patch);
status_t getPatchForInputMix(audio_io_handle_t audioIo, audio_patch& patch);
bool patchContainsOutputDevice(audio_port_handle_t deviceId, audio_patch patch);
bool patchContainsInputDevice(audio_port_handle_t deviceId, audio_patch patch);
bool checkPatchPlayback(audio_io_handle_t audioIo, audio_port_handle_t deviceId);
bool checkPatchCapture(audio_io_handle_t audioIo, audio_port_handle_t deviceId);
std::string dumpPort(const audio_port_v7& port);
std::string dumpPortConfig(const audio_port_config& port);
std::string dumpPatch(const audio_patch& patch);

class OnAudioDeviceUpdateNotifier : public AudioSystem::AudioDeviceCallback {
  public:
    audio_io_handle_t mAudioIo = AUDIO_IO_HANDLE_NONE;
    audio_port_handle_t mDeviceId = AUDIO_PORT_HANDLE_NONE;
    std::mutex mMutex;
    std::condition_variable mCondition;

    void onAudioDeviceUpdate(audio_io_handle_t audioIo, audio_port_handle_t deviceId);
    status_t waitForAudioDeviceCb(audio_port_handle_t expDeviceId = AUDIO_PORT_HANDLE_NONE);
};

// Simple AudioPlayback class.
class AudioPlayback : public AudioTrack::IAudioTrackCallback {
    friend sp<AudioPlayback>;
    AudioPlayback(uint32_t sampleRate, audio_format_t format, audio_channel_mask_t channelMask,
                  audio_output_flags_t flags = AUDIO_OUTPUT_FLAG_NONE,
                  audio_session_t sessionId = AUDIO_SESSION_NONE,
                  AudioTrack::transfer_type transferType = AudioTrack::TRANSFER_SHARED,
                  audio_attributes_t* attributes = nullptr, audio_offload_info_t* info = nullptr);

  public:
    status_t loadResource(const char* name);
    status_t create();
    sp<AudioTrack> getAudioTrackHandle();
    status_t start();
    status_t waitForConsumption(bool testSeek = false);
    status_t fillBuffer();
    status_t onProcess(bool testSeek = false);
    virtual void onBufferEnd() override;
    void stop();

    bool mStopPlaying;
    std::mutex mMutex;
    std::condition_variable mCondition;

    enum State {
        PLAY_NO_INIT,
        PLAY_READY,
        PLAY_STARTED,
        PLAY_STOPPED,
    };

  private:
    ~AudioPlayback();
    const uint32_t mSampleRate;
    const audio_format_t mFormat;
    const audio_channel_mask_t mChannelMask;
    const audio_output_flags_t mFlags;
    const audio_session_t mSessionId;
    const AudioTrack::transfer_type mTransferType;
    const audio_attributes_t* mAttributes;
    const audio_offload_info_t* mOffloadInfo;

    size_t mBytesUsedSoFar;
    State mState;
    size_t mMemCapacity;
    sp<MemoryDealer> mMemoryDealer;
    sp<IMemory> mMemory;

    sp<AudioTrack> mTrack;
};

// hold pcm data sent by AudioRecord
class RawBuffer {
  public:
    RawBuffer(int64_t ptsPipeline = -1, int64_t ptsManual = -1, int32_t capacity = 0);

    std::unique_ptr<uint8_t[]> mData;
    int64_t mPtsPipeline;
    int64_t mPtsManual;
    int32_t mCapacity;
};

// Simple AudioCapture
class AudioCapture : public AudioRecord::IAudioRecordCallback {
  public:
    AudioCapture(audio_source_t inputSource, uint32_t sampleRate, audio_format_t format,
                 audio_channel_mask_t channelMask,
                 audio_input_flags_t flags = AUDIO_INPUT_FLAG_NONE,
                 audio_session_t sessionId = AUDIO_SESSION_ALLOCATE,
                 AudioRecord::transfer_type transferType = AudioRecord::TRANSFER_CALLBACK,
                 const audio_attributes_t* attributes = nullptr);
    ~AudioCapture();
    size_t onMoreData(const AudioRecord::Buffer& buffer) override;
    void onOverrun() override;
    void onMarker(uint32_t markerPosition) override;
    void onNewPos(uint32_t newPos) override;
    void onNewIAudioRecord() override;
    status_t create();
    status_t setRecordDuration(float durationInSec);
    status_t enableRecordDump();
    std::string getRecordDumpFileName() const { return mFileName; }
    sp<AudioRecord> getAudioRecordHandle();
    status_t start(AudioSystem::sync_event_t event = AudioSystem::SYNC_EVENT_NONE,
                   audio_session_t triggerSession = AUDIO_SESSION_NONE);
    status_t obtainBufferCb(RawBuffer& buffer);
    status_t obtainBuffer(RawBuffer& buffer);
    status_t audioProcess();
    status_t stop();

    uint32_t mFrameCount;
    uint32_t mNotificationFrames;
    int64_t mNumFramesToRecord;
    int64_t mNumFramesReceived;
    int64_t mNumFramesLost;
    uint32_t mMarkerPosition;
    uint32_t mMarkerPeriod;
    uint32_t mReceivedCbMarkerAtPosition;
    uint32_t mReceivedCbMarkerCount;
    bool mBufferOverrun;

    enum State {
        REC_NO_INIT,
        REC_READY,
        REC_STARTED,
        REC_STOPPED,
    };

  private:
    const audio_source_t mInputSource;
    const uint32_t mSampleRate;
    const audio_format_t mFormat;
    const audio_channel_mask_t mChannelMask;
    const audio_input_flags_t mFlags;
    const audio_session_t mSessionId;
    const AudioRecord::transfer_type mTransferType;
    const audio_attributes_t* mAttributes;

    size_t mMaxBytesPerCallback = 2048;
    sp<AudioRecord> mRecord;
    State mState;
    bool mStopRecording;
    std::string mFileName;
    int mOutFileFd = -1;

    std::mutex mMutex;
    std::condition_variable mCondition;
    std::deque<RawBuffer> mBuffersReceived;
};

#endif  // AUDIO_TEST_UTILS_H_
