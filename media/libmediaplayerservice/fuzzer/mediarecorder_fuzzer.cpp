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

#include <AudioFlinger.h>
#include <MediaPlayerService.h>
#include <ResourceManagerService.h>
#include <StagefrightRecorder.h>
#include <camera/Camera.h>
#include <camera/android/hardware/ICamera.h>
#include <fakeservicemanager/FakeServiceManager.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <media/stagefright/PersistentSurface.h>
#include <media/stagefright/foundation/AString.h>
#include <mediametricsservice/MediaMetricsService.h>
#include <thread>
#include "CameraService.h"
#include "fuzzer/FuzzedDataProvider.h"

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
    AUDIO_SOURCE_FM_TUNER,          AUDIO_SOURCE_HOTWORD,
    AUDIO_SOURCE_ULTRASOUND};

constexpr output_format kOutputFormat[] = {
        OUTPUT_FORMAT_DEFAULT,        OUTPUT_FORMAT_THREE_GPP,
        OUTPUT_FORMAT_MPEG_4,         OUTPUT_FORMAT_AUDIO_ONLY_START,
        OUTPUT_FORMAT_RAW_AMR,        OUTPUT_FORMAT_AMR_NB,
        OUTPUT_FORMAT_AMR_WB,         OUTPUT_FORMAT_AAC_ADTS,
        OUTPUT_FORMAT_AUDIO_ONLY_END, OUTPUT_FORMAT_RTP_AVP,
        OUTPUT_FORMAT_MPEG2TS,        OUTPUT_FORMAT_WEBM,
        OUTPUT_FORMAT_HEIF,           OUTPUT_FORMAT_OGG,
        OUTPUT_FORMAT_LIST_END};

constexpr video_encoder kVideoEncoder[] = {
        VIDEO_ENCODER_DEFAULT,      VIDEO_ENCODER_H263, VIDEO_ENCODER_H264,
        VIDEO_ENCODER_MPEG_4_SP,    VIDEO_ENCODER_VP8,  VIDEO_ENCODER_HEVC,
        VIDEO_ENCODER_DOLBY_VISION, VIDEO_ENCODER_AV1,  VIDEO_ENCODER_LIST_END};

constexpr audio_microphone_direction_t kSupportedMicrophoneDirections[] = {
    MIC_DIRECTION_UNSPECIFIED, MIC_DIRECTION_FRONT, MIC_DIRECTION_BACK, MIC_DIRECTION_EXTERNAL};

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
                                  "rtp-param-set-socket-network",
                                  "rtp-param-set-socket-ecn",
                                  "rtp-param-remote-ip",
                                  "rtp-param-set-socket-network",
                                  "log-session-id"};

constexpr int32_t kMinVideoSize = 2;
constexpr int32_t kMaxVideoSize = 8192;
const char kOutputFile[] = "OutputFile";
const char kNextOutputFile[] = "NextOutputFile";

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

    int32_t deviceId;
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

template <typename FuncWrapper>
void callMediaAPI(FuncWrapper funcWrapper, FuzzedDataProvider* fdp) {
    if (fdp->ConsumeBool()) {
        funcWrapper();
    }
}

void MediaRecorderClientFuzzer::setConfig() {
    callMediaAPI(
            [this]() {
                mSurfaceControl = mComposerClient.createSurface(
                        String8(mFdp.ConsumeRandomLengthString().c_str()) /* name */,
                        mFdp.ConsumeIntegral<uint32_t>() /* width */,
                        mFdp.ConsumeIntegral<uint32_t>() /* height */,
                        mFdp.ConsumeIntegral<int32_t>() /* pixel-format */,
                        mFdp.ConsumeIntegral<int32_t>() /* flags */);
                if (mSurfaceControl) {
                    mSurface = mSurfaceControl->getSurface();
                    mStfRecorder->setPreviewSurface(mSurface->getIGraphicBufferProducer());
                }
            },
            &mFdp);

    callMediaAPI([this]() { mStfRecorder->setInputDevice(mFdp.ConsumeIntegral<int32_t>()); },
                 &mFdp);

    callMediaAPI(
            [this]() {
                sp<TestMediaRecorderClient> listener = sp<TestMediaRecorderClient>::make();
                mStfRecorder->setListener(listener);
            },
            &mFdp);

    callMediaAPI(
            [this]() {
                sp<TestCamera> testCamera = sp<TestCamera>::make();
                sp<Camera> camera = Camera::create(testCamera);
                mStfRecorder->setCamera(camera->remote(), camera->getRecordingProxy());
            },
            &mFdp);

    callMediaAPI(
            [this]() {
                sp<PersistentSurface> persistentSurface = sp<PersistentSurface>::make();
                mStfRecorder->setInputSurface(persistentSurface);
            },
            &mFdp);

    callMediaAPI(
            [this]() {
                sp<TestAudioDeviceCallback> callback = sp<TestAudioDeviceCallback>::make();
                mStfRecorder->setAudioDeviceCallback(callback);
                mStfRecorder->setOutputFile(mMediaRecorderOutputFd);
            },
            &mFdp);

    callMediaAPI(
            [this]() {
                mStfRecorder->setAudioSource(mFdp.PickValueInArray(kSupportedAudioSources));
            },
            &mFdp);

    callMediaAPI(
            [this]() {
                mStfRecorder->setVideoSource(mFdp.PickValueInArray(kSupportedVideoSources));
            },
            &mFdp);

    callMediaAPI(
            [this]() {
                mStfRecorder->setPreferredMicrophoneDirection(
                        mFdp.PickValueInArray(kSupportedMicrophoneDirections));
            },
            &mFdp);

    callMediaAPI([this]() { mStfRecorder->setPrivacySensitive(mFdp.ConsumeBool()); }, &mFdp);

    callMediaAPI(
            [this]() {
                bool isPrivacySensitive;
                mStfRecorder->isPrivacySensitive(&isPrivacySensitive);
            },
            &mFdp);

    callMediaAPI(
            [this]() {
                mStfRecorder->setVideoSize(mFdp.ConsumeIntegralInRange<int32_t>(
                                                   kMinVideoSize, kMaxVideoSize) /* width */,
                                           mFdp.ConsumeIntegralInRange<int32_t>(
                                                   kMinVideoSize, kMaxVideoSize) /* height */);
            },
            &mFdp);

    callMediaAPI([this]() { mStfRecorder->setVideoFrameRate(mFdp.ConsumeIntegral<int32_t>()); },
                 &mFdp);

    callMediaAPI([this]() { mStfRecorder->enableAudioDeviceCallback(mFdp.ConsumeBool()); }, &mFdp);

    callMediaAPI(
            [this]() {
                mStfRecorder->setPreferredMicrophoneFieldDimension(
                        mFdp.ConsumeFloatingPoint<float>());
            },
            &mFdp);

    callMediaAPI(
            [this]() {
                mStfRecorder->setClientName(String16(mFdp.ConsumeRandomLengthString().c_str()));
            },
            &mFdp);

    callMediaAPI(
            [this]() {
                output_format OutputFormat = mFdp.PickValueInArray(kOutputFormat);
                audio_encoder AudioEncoderFormat =
                        (audio_encoder)mFdp.ConsumeIntegralInRange<int32_t>(AUDIO_ENCODER_DEFAULT,
                                                                            AUDIO_ENCODER_LIST_END);
                video_encoder VideoEncoderFormat = mFdp.PickValueInArray(kVideoEncoder);
                if (OutputFormat == OUTPUT_FORMAT_AMR_NB) {
                    AudioEncoderFormat =
                            mFdp.ConsumeBool() ? AUDIO_ENCODER_DEFAULT : AUDIO_ENCODER_AMR_NB;
                } else if (OutputFormat == OUTPUT_FORMAT_AMR_WB) {
                    AudioEncoderFormat = AUDIO_ENCODER_AMR_WB;
                } else if (OutputFormat == OUTPUT_FORMAT_AAC_ADIF ||
                           OutputFormat == OUTPUT_FORMAT_AAC_ADTS ||
                           OutputFormat == OUTPUT_FORMAT_MPEG2TS) {
                    AudioEncoderFormat = (audio_encoder)mFdp.ConsumeIntegralInRange<int32_t>(
                            AUDIO_ENCODER_AAC, AUDIO_ENCODER_AAC_ELD);
                    if (OutputFormat == OUTPUT_FORMAT_MPEG2TS) {
                        VideoEncoderFormat = VIDEO_ENCODER_H264;
                    }
                }
                mStfRecorder->setOutputFormat(OutputFormat);
                mStfRecorder->setAudioEncoder(AudioEncoderFormat);
                mStfRecorder->setVideoEncoder(VideoEncoderFormat);
            },
            &mFdp);

    callMediaAPI(
            [this]() {
                int32_t nextOutputFd = memfd_create(kNextOutputFile, MFD_ALLOW_SEALING);
                mStfRecorder->setNextOutputFile(nextOutputFd);
                close(nextOutputFd);
            },
            &mFdp);

    callMediaAPI(
            [this]() {
                for (int32_t idx = 0; idx < size(kParametersList); ++idx) {
                    if (mFdp.ConsumeBool()) {
                        int32_t value = mFdp.ConsumeIntegral<int32_t>();
                        mStfRecorder->setParameters(
                                String8((kParametersList[idx] + "=" + to_string(value)).c_str()));
                    }
                }
            },
            &mFdp);
}

MediaRecorderClientFuzzer::MediaRecorderClientFuzzer(const uint8_t* data, size_t size)
    : mFdp(data, size), mMediaRecorderOutputFd(memfd_create(kOutputFile, MFD_ALLOW_SEALING)) {
    AttributionSourceState attributionSource;
    attributionSource.packageName = mFdp.ConsumeRandomLengthString().c_str();
    attributionSource.token = sp<BBinder>::make();
    mStfRecorder = make_unique<StagefrightRecorder>(attributionSource);
}

void MediaRecorderClientFuzzer::process() {
    mStfRecorder->init();
    mStfRecorder->prepare();
    while (mFdp.remaining_bytes()) {
        auto invokeMediaPLayerApi = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() { setConfig(); },
                [&]() { mStfRecorder->start(); },
                [&]() { mStfRecorder->pause(); },
                [&]() { mStfRecorder->resume(); },
                [&]() { mStfRecorder->stop(); },
                [&]() { getConfig(); },
                [&]() { mStfRecorder->close(); },
                [&]() { mStfRecorder->reset(); },
        });
        invokeMediaPLayerApi();
    }
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
    CameraService::instantiate();
    fakeServiceManager->addService(String16(MediaMetricsService::kServiceName),
                                    new MediaMetricsService());
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    MediaRecorderClientFuzzer mrcFuzzer(data, size);
    mrcFuzzer.process();
    return 0;
}
