/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <media/stagefright/foundation/AString.h>
#include "fuzzer/FuzzedDataProvider.h"

#include <AudioFlinger.h>
#include <MediaPlayerService.h>
#include <ResourceManagerService.h>
#include <fakeservicemanager/FakeServiceManager.h>
#include <StagefrightRecorder.h>
#include <camera/Camera.h>
#include <camera/android/hardware/ICamera.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <media/stagefright/PersistentSurface.h>
#include <mediametricsservice/MediaMetricsService.h>
#include <thread>

using namespace std;
using namespace android;
using namespace android::hardware;

constexpr video_source kSupportedVideoSources[] = {VIDEO_SOURCE_DEFAULT, VIDEO_SOURCE_CAMERA,
                                                   VIDEO_SOURCE_SURFACE};

constexpr audio_source_t kSupportedAudioSources[] = {
    AUDIO_SOURCE_DEFAULT,           AUDIO_SOURCE_MIC,
    AUDIO_SOURCE_VOICE_UPLINK,      AUDIO_SOURCE_VOICE_DOWNLINK,
    AUDIO_SOURCE_VOICE_CALL,        AUDIO_SOURCE_CAMCORDER,
    AUDIO_SOURCE_VOICE_RECOGNITION, AUDIO_SOURCE_VOICE_COMMUNICATION,
    AUDIO_SOURCE_REMOTE_SUBMIX,     AUDIO_SOURCE_UNPROCESSED,
    AUDIO_SOURCE_VOICE_PERFORMANCE, AUDIO_SOURCE_ECHO_REFERENCE,
    AUDIO_SOURCE_FM_TUNER,          AUDIO_SOURCE_HOTWORD};

constexpr audio_microphone_direction_t kSupportedMicrophoneDirections[] = {
    MIC_DIRECTION_UNSPECIFIED, MIC_DIRECTION_FRONT, MIC_DIRECTION_BACK, MIC_DIRECTION_EXTERNAL};

struct RecordingConfig {
    output_format outputFormat;
    audio_encoder audioEncoder;
    video_encoder videoEncoder;
};

const struct RecordingConfig kRecordingConfigList[] = {
    {OUTPUT_FORMAT_AMR_NB, AUDIO_ENCODER_AMR_NB, VIDEO_ENCODER_DEFAULT},
    {OUTPUT_FORMAT_AMR_WB, AUDIO_ENCODER_AMR_WB, VIDEO_ENCODER_DEFAULT},
    {OUTPUT_FORMAT_AAC_ADTS, AUDIO_ENCODER_AAC, VIDEO_ENCODER_DEFAULT},
    {OUTPUT_FORMAT_AAC_ADTS, AUDIO_ENCODER_HE_AAC, VIDEO_ENCODER_DEFAULT},
    {OUTPUT_FORMAT_AAC_ADTS, AUDIO_ENCODER_AAC_ELD, VIDEO_ENCODER_DEFAULT},
    {OUTPUT_FORMAT_OGG, AUDIO_ENCODER_OPUS, VIDEO_ENCODER_DEFAULT},
    {OUTPUT_FORMAT_RTP_AVP, AUDIO_ENCODER_DEFAULT, VIDEO_ENCODER_DEFAULT},
    {OUTPUT_FORMAT_MPEG2TS, AUDIO_ENCODER_AAC, VIDEO_ENCODER_H264},
    {OUTPUT_FORMAT_WEBM, AUDIO_ENCODER_VORBIS, VIDEO_ENCODER_VP8},
    {OUTPUT_FORMAT_THREE_GPP, AUDIO_ENCODER_DEFAULT, VIDEO_ENCODER_MPEG_4_SP},
    {OUTPUT_FORMAT_MPEG_4, AUDIO_ENCODER_AAC, VIDEO_ENCODER_H264},
    {OUTPUT_FORMAT_MPEG_4, AUDIO_ENCODER_DEFAULT, VIDEO_ENCODER_MPEG_4_SP},
    {OUTPUT_FORMAT_MPEG_4, AUDIO_ENCODER_DEFAULT, VIDEO_ENCODER_HEVC}};

const string kParametersList[] = {"max-duration",
                                  "max-filesize",
                                  "interleave-duration-us",
                                  "param-movie-time-scale",
                                  "param-geotag-longitude",
                                  "param-geotag-latitude",
                                  "param-track-time-status",
                                  "audio-param-sampling-rate",
                                  "audio-param-encoding-bitrate",
                                  "audio-param-number-of-channels",
                                  "audio-param-time-scale",
                                  "video-param-rotation-angle-degrees",
                                  "video-param-encoding-bitrate",
                                  "video-param-bitrate-mode",
                                  "video-param-i-frames-interval",
                                  "video-param-encoder-profile",
                                  "video-param-encoder-level",
                                  "video-param-camera-id",
                                  "video-param-time-scale",
                                  "param-use-64bit-offset",
                                  "time-lapse-enable",
                                  "time-lapse-fps",
                                  "rtp-param-local-ip",
                                  "rtp-param-local-port",
                                  "rtp-param-remote-port",
                                  "rtp-param-self-id",
                                  "rtp-param-opponent-id",
                                  "rtp-param-payload-type",
                                  "rtp-param-ext-cvo-extmap",
                                  "rtp-param-ext-cvo-degrees",
                                  "video-param-request-i-frame",
                                  "rtp-param-set-socket-dscp",
                                  "rtp-param-set-socket-network"};

constexpr int32_t kMaxSleepTimeInMs = 100;
constexpr int32_t kMinSleepTimeInMs = 0;
constexpr int32_t kMinVideoSize = 2;
constexpr int32_t kMaxVideoSize = 8192;
constexpr int32_t kNumRecordMin = 1;
constexpr int32_t kNumRecordMax = 10;

class TestAudioDeviceCallback : public AudioSystem::AudioDeviceCallback {
   public:
    virtual ~TestAudioDeviceCallback() = default;

    void onAudioDeviceUpdate(audio_io_handle_t /*audioIo*/,
                             audio_port_handle_t /*deviceId*/) override{};
};

class TestCamera : public ICamera {
   public:
    virtual ~TestCamera() = default;

    binder::Status disconnect() override { return binder::Status::ok(); };
    status_t connect(const sp<ICameraClient> & /*client*/) override { return 0; };
    status_t lock() override { return 0; };
    status_t unlock() override { return 0; };
    status_t setPreviewTarget(const sp<IGraphicBufferProducer> & /*bufferProducer*/) override {
        return 0;
    };
    void setPreviewCallbackFlag(int /*flag*/) override{};
    status_t setPreviewCallbackTarget(
        const sp<IGraphicBufferProducer> & /*callbackProducer*/) override {
        return 0;
    };
    status_t startPreview() override { return 0; };
    void stopPreview() override{};
    bool previewEnabled() override { return true; };
    status_t startRecording() override { return 0; };
    void stopRecording() override{};
    bool recordingEnabled() override { return true; };
    void releaseRecordingFrame(const sp<IMemory> & /*mem*/) override{};
    void releaseRecordingFrameHandle(native_handle_t * /*handle*/) override{};
    void releaseRecordingFrameHandleBatch(const vector<native_handle_t *> & /*handles*/) override{};
    status_t autoFocus() override { return 0; };
    status_t cancelAutoFocus() override { return 0; };
    status_t takePicture(int /*msgType*/) override { return 0; };
    status_t setParameters(const String8 & /*params*/) override { return 0; };
    String8 getParameters() const override { return String8(); };
    status_t sendCommand(int32_t /*cmd*/, int32_t /*arg1*/, int32_t /*arg2*/) override {
        return 0;
    };
    status_t setVideoBufferMode(int32_t /*videoBufferMode*/) override { return 0; };
    status_t setVideoTarget(const sp<IGraphicBufferProducer> & /*bufferProducer*/) override {
        return 0;
    };
    status_t setAudioRestriction(int32_t /*mode*/) override { return 0; };
    int32_t getGlobalAudioRestriction() override { return 0; };
    IBinder *onAsBinder() override { return reinterpret_cast<IBinder *>(this); };
};

class TestMediaRecorderClient : public IMediaRecorderClient {
   public:
    virtual ~TestMediaRecorderClient() = default;

    void notify(int /*msg*/, int /*ext1*/, int /*ext2*/) override{};
    IBinder *onAsBinder() override { return reinterpret_cast<IBinder *>(this); };
};

class MediaRecorderClientFuzzer {
   public:
    MediaRecorderClientFuzzer(const uint8_t *data, size_t size);
    ~MediaRecorderClientFuzzer() { close(mMediaRecorderOutputFd); }
    void process();

   private:
    void setConfig();
    void getConfig();
    void dumpInfo();

    FuzzedDataProvider mFdp;
    unique_ptr<MediaRecorderBase> mStfRecorder = nullptr;
    SurfaceComposerClient mComposerClient;
    sp<SurfaceControl> mSurfaceControl = nullptr;
    sp<Surface> mSurface = nullptr;
    const int32_t mMediaRecorderOutputFd;
};

void MediaRecorderClientFuzzer::getConfig() {
    int32_t max;
    mStfRecorder->getMaxAmplitude(&max);

    int32_t deviceId = mFdp.ConsumeIntegral<int32_t>();
    mStfRecorder->setInputDevice(deviceId);
    mStfRecorder->getRoutedDeviceId(&deviceId);

    vector<android::media::MicrophoneInfoFw> activeMicrophones{};
    mStfRecorder->getActiveMicrophones(&activeMicrophones);

    int32_t portId;
    mStfRecorder->getPortId(&portId);

    uint64_t bytes;
    mStfRecorder->getRtpDataUsage(&bytes);

    Parcel parcel;
    mStfRecorder->getMetrics(&parcel);

    sp<IGraphicBufferProducer> buffer = mStfRecorder->querySurfaceMediaSource();
}

void MediaRecorderClientFuzzer::dumpInfo() {
    int32_t dumpFd = memfd_create("DumpFile", MFD_ALLOW_SEALING);
    Vector<String16> args;
    args.push_back(String16(mFdp.ConsumeRandomLengthString().c_str()));
    mStfRecorder->dump(dumpFd, args);
    close(dumpFd);
}

void MediaRecorderClientFuzzer::setConfig() {
    mStfRecorder->setOutputFile(mMediaRecorderOutputFd);
    mStfRecorder->setAudioSource(mFdp.PickValueInArray(kSupportedAudioSources));
    mStfRecorder->setVideoSource(mFdp.PickValueInArray(kSupportedVideoSources));
    mStfRecorder->setPreferredMicrophoneDirection(
        mFdp.PickValueInArray(kSupportedMicrophoneDirections));
    mStfRecorder->setPrivacySensitive(mFdp.ConsumeBool());
    bool isPrivacySensitive;
    mStfRecorder->isPrivacySensitive(&isPrivacySensitive);
    mStfRecorder->setVideoSize(mFdp.ConsumeIntegralInRange<int32_t>(kMinVideoSize, kMaxVideoSize),
                               mFdp.ConsumeIntegralInRange<int32_t>(kMinVideoSize, kMaxVideoSize));
    mStfRecorder->setVideoFrameRate(mFdp.ConsumeIntegral<int32_t>());
    mStfRecorder->enableAudioDeviceCallback(mFdp.ConsumeBool());
    mStfRecorder->setPreferredMicrophoneFieldDimension(mFdp.ConsumeFloatingPoint<float>());
    mStfRecorder->setClientName(String16(mFdp.ConsumeRandomLengthString().c_str()));

    int32_t Idx = mFdp.ConsumeIntegralInRange<int32_t>(0, size(kRecordingConfigList) - 1);
    mStfRecorder->setOutputFormat(kRecordingConfigList[Idx].outputFormat);
    mStfRecorder->setAudioEncoder(kRecordingConfigList[Idx].audioEncoder);
    mStfRecorder->setVideoEncoder(kRecordingConfigList[Idx].videoEncoder);

    int32_t nextOutputFd = memfd_create("NextOutputFile", MFD_ALLOW_SEALING);
    mStfRecorder->setNextOutputFile(nextOutputFd);
    close(nextOutputFd);

    for (Idx = 0; Idx < size(kParametersList); ++Idx) {
        if (mFdp.ConsumeBool()) {
            int32_t value = mFdp.ConsumeIntegral<int32_t>();
            mStfRecorder->setParameters(
                String8((kParametersList[Idx] + "=" + to_string(value)).c_str()));
        }
    }
}

MediaRecorderClientFuzzer::MediaRecorderClientFuzzer(const uint8_t *data, size_t size)
    : mFdp(data, size), mMediaRecorderOutputFd(memfd_create("OutputFile", MFD_ALLOW_SEALING)) {
    AttributionSourceState attributionSource;
    attributionSource.packageName = mFdp.ConsumeRandomLengthString().c_str();
    attributionSource.token = sp<BBinder>::make();
    mStfRecorder = make_unique<StagefrightRecorder>(attributionSource);

    mSurfaceControl = mComposerClient.createSurface(
        String8(mFdp.ConsumeRandomLengthString().c_str()), mFdp.ConsumeIntegral<uint32_t>(),
        mFdp.ConsumeIntegral<uint32_t>(), mFdp.ConsumeIntegral<int32_t>(),
        mFdp.ConsumeIntegral<int32_t>());
    if (mSurfaceControl) {
        mSurface = mSurfaceControl->getSurface();
        mStfRecorder->setPreviewSurface(mSurface->getIGraphicBufferProducer());
    }

    sp<TestMediaRecorderClient> listener = sp<TestMediaRecorderClient>::make();
    mStfRecorder->setListener(listener);

    sp<TestCamera> testCamera = sp<TestCamera>::make();
    sp<Camera> camera = Camera::create(testCamera);
    mStfRecorder->setCamera(camera->remote(), camera->getRecordingProxy());

    sp<PersistentSurface> persistentSurface = sp<PersistentSurface>::make();
    mStfRecorder->setInputSurface(persistentSurface);

    sp<TestAudioDeviceCallback> callback = sp<TestAudioDeviceCallback>::make();
    mStfRecorder->setAudioDeviceCallback(callback);
}

void MediaRecorderClientFuzzer::process() {
    setConfig();

    mStfRecorder->init();
    mStfRecorder->prepare();
    size_t numRecord = mFdp.ConsumeIntegralInRange<size_t>(kNumRecordMin, kNumRecordMax);
    for (size_t Idx = 0; Idx < numRecord; ++Idx) {
        mStfRecorder->start();
        this_thread::sleep_for(chrono::milliseconds(
            mFdp.ConsumeIntegralInRange<int32_t>(kMinSleepTimeInMs, kMaxSleepTimeInMs)));
        mStfRecorder->pause();
        this_thread::sleep_for(chrono::milliseconds(
            mFdp.ConsumeIntegralInRange<int32_t>(kMinSleepTimeInMs, kMaxSleepTimeInMs)));
        mStfRecorder->resume();
        this_thread::sleep_for(chrono::milliseconds(
            mFdp.ConsumeIntegralInRange<int32_t>(kMinSleepTimeInMs, kMaxSleepTimeInMs)));
        mStfRecorder->stop();
    }
    dumpInfo();
    getConfig();

    mStfRecorder->close();
    mStfRecorder->reset();
}

extern "C" int LLVMFuzzerInitialize(int /* *argc */, char /* ***argv */) {
    /**
     * Initializing a FakeServiceManager and adding the instances
     * of all the required services
     */
    sp<IServiceManager> fakeServiceManager = new FakeServiceManager();
    setDefaultServiceManager(fakeServiceManager);
    MediaPlayerService::instantiate();
    AudioFlinger::instantiate();
    ResourceManagerService::instantiate();
    fakeServiceManager->addService(String16(MediaMetricsService::kServiceName),
                                    new MediaMetricsService());
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    MediaRecorderClientFuzzer mrcFuzzer(data, size);
    mrcFuzzer.process();
    return 0;
}
