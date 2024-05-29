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

#include <MediaExtractorService.h>
#include <MediaPlayerService.h>
#include <android/gui/BnSurfaceComposerClient.h>
#include <camera/Camera.h>
#include <datasource/FileSource.h>
#include <fuzzbinder/random_binder.h>
#include <gmock/gmock.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <media/IMediaCodecList.h>
#include <media/IMediaHTTPService.h>
#include <media/IMediaPlayer.h>
#include <media/IMediaRecorder.h>
#include <media/IRemoteDisplay.h>
#include <media/IRemoteDisplayClient.h>
#include <media/MediaHTTPConnection.h>
#include <media/MediaHTTPService.h>
#include <media/stagefright/RemoteDataSource.h>
#include <media/stagefright/foundation/base64.h>
#include <thread>
#include "android-base/stringprintf.h"
#include "fuzzer/FuzzedDataProvider.h"
using namespace std;
using namespace android;

constexpr int32_t kUuidSize = 16;
constexpr int32_t kMinSize = 0;
constexpr int32_t kMaxSize = 100;
constexpr int32_t kFourCCVal = android::FOURCC('m', 't', 'r', 'X');
constexpr int32_t kFlagVal =
        ISurfaceComposerClient::eCursorWindow | ISurfaceComposerClient::eOpaque;

const char dumpFile[] = "OutputDumpFile";

enum DataSourceType { HTTP, FD, STREAM, FILETYPE, SOCKET, kMaxValue = SOCKET };

constexpr audio_flags_mask_t kAudioFlagsMasks[] = {AUDIO_FLAG_NONE,
                                                   AUDIO_FLAG_AUDIBILITY_ENFORCED,
                                                   AUDIO_FLAG_SECURE,
                                                   AUDIO_FLAG_SCO,
                                                   AUDIO_FLAG_BEACON,
                                                   AUDIO_FLAG_HW_AV_SYNC,
                                                   AUDIO_FLAG_HW_HOTWORD,
                                                   AUDIO_FLAG_BYPASS_INTERRUPTION_POLICY,
                                                   AUDIO_FLAG_BYPASS_MUTE,
                                                   AUDIO_FLAG_LOW_LATENCY,
                                                   AUDIO_FLAG_DEEP_BUFFER,
                                                   AUDIO_FLAG_NO_MEDIA_PROJECTION,
                                                   AUDIO_FLAG_MUTE_HAPTIC,
                                                   AUDIO_FLAG_NO_SYSTEM_CAPTURE,
                                                   AUDIO_FLAG_CAPTURE_PRIVATE,
                                                   AUDIO_FLAG_CONTENT_SPATIALIZED,
                                                   AUDIO_FLAG_NEVER_SPATIALIZE,
                                                   AUDIO_FLAG_CALL_REDIRECTION};

constexpr audio_content_type_t kAudioContentTypes[] = {
        AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_CONTENT_TYPE_SPEECH,       AUDIO_CONTENT_TYPE_MUSIC,
        AUDIO_CONTENT_TYPE_MOVIE,   AUDIO_CONTENT_TYPE_SONIFICATION, AUDIO_CONTENT_TYPE_ULTRASOUND};

constexpr audio_source_t kAudioSources[] = {AUDIO_SOURCE_INVALID,
                                            AUDIO_SOURCE_DEFAULT,
                                            AUDIO_SOURCE_MIC,
                                            AUDIO_SOURCE_VOICE_UPLINK,
                                            AUDIO_SOURCE_VOICE_DOWNLINK,
                                            AUDIO_SOURCE_VOICE_CALL,
                                            AUDIO_SOURCE_CAMCORDER,
                                            AUDIO_SOURCE_VOICE_RECOGNITION,
                                            AUDIO_SOURCE_VOICE_COMMUNICATION,
                                            AUDIO_SOURCE_REMOTE_SUBMIX,
                                            AUDIO_SOURCE_UNPROCESSED,
                                            AUDIO_SOURCE_VOICE_PERFORMANCE,
                                            AUDIO_SOURCE_ECHO_REFERENCE,
                                            AUDIO_SOURCE_FM_TUNER,
                                            AUDIO_SOURCE_HOTWORD,
                                            AUDIO_SOURCE_ULTRASOUND};

constexpr audio_usage_t kAudioUsages[] = {AUDIO_USAGE_UNKNOWN,
                                          AUDIO_USAGE_MEDIA,
                                          AUDIO_USAGE_VOICE_COMMUNICATION,
                                          AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                          AUDIO_USAGE_ALARM,
                                          AUDIO_USAGE_NOTIFICATION,
                                          AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                          AUDIO_USAGE_NOTIFICATION_COMMUNICATION_REQUEST,
                                          AUDIO_USAGE_NOTIFICATION_COMMUNICATION_INSTANT,
                                          AUDIO_USAGE_NOTIFICATION_COMMUNICATION_DELAYED,
                                          AUDIO_USAGE_NOTIFICATION_EVENT,
                                          AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                          AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                          AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                          AUDIO_USAGE_GAME,
                                          AUDIO_USAGE_VIRTUAL_SOURCE,
                                          AUDIO_USAGE_ASSISTANT,
                                          AUDIO_USAGE_CALL_ASSISTANT,
                                          AUDIO_USAGE_EMERGENCY,
                                          AUDIO_USAGE_SAFETY,
                                          AUDIO_USAGE_VEHICLE_STATUS,
                                          AUDIO_USAGE_ANNOUNCEMENT};

constexpr PixelFormat kPixelFormat[] = {
        PIXEL_FORMAT_UNKNOWN,       PIXEL_FORMAT_NONE,        PIXEL_FORMAT_CUSTOM,
        PIXEL_FORMAT_TRANSLUCENT,   PIXEL_FORMAT_TRANSPARENT, PIXEL_FORMAT_OPAQUE,
        PIXEL_FORMAT_RGBA_8888,     PIXEL_FORMAT_RGBX_8888,   PIXEL_FORMAT_RGB_888,
        PIXEL_FORMAT_RGB_565,       PIXEL_FORMAT_BGRA_8888,   PIXEL_FORMAT_RGBA_5551,
        PIXEL_FORMAT_RGBA_4444,     PIXEL_FORMAT_RGBA_FP16,   PIXEL_FORMAT_RGBA_1010102,
        PIXEL_FORMAT_R_8,           PIXEL_FORMAT_R_16_UINT,   PIXEL_FORMAT_RG_1616_UINT,
        PIXEL_FORMAT_RGBA_10101010,
};

constexpr media_parameter_keys kMediaParamKeys[] = {
    KEY_PARAMETER_CACHE_STAT_COLLECT_FREQ_MS, KEY_PARAMETER_AUDIO_CHANNEL_COUNT,
    KEY_PARAMETER_PLAYBACK_RATE_PERMILLE, KEY_PARAMETER_AUDIO_ATTRIBUTES,
    KEY_PARAMETER_RTP_ATTRIBUTES};

constexpr media_event_type kMediaEventTypes[] = {MEDIA_NOP,
                                                 MEDIA_PREPARED,
                                                 MEDIA_PLAYBACK_COMPLETE,
                                                 MEDIA_BUFFERING_UPDATE,
                                                 MEDIA_SEEK_COMPLETE,
                                                 MEDIA_SET_VIDEO_SIZE,
                                                 MEDIA_STARTED,
                                                 MEDIA_PAUSED,
                                                 MEDIA_STOPPED,
                                                 MEDIA_SKIPPED,
                                                 MEDIA_NOTIFY_TIME,
                                                 MEDIA_TIMED_TEXT,
                                                 MEDIA_ERROR,
                                                 MEDIA_INFO,
                                                 MEDIA_SUBTITLE_DATA,
                                                 MEDIA_META_DATA,
                                                 MEDIA_DRM_INFO,
                                                 MEDIA_TIME_DISCONTINUITY,
                                                 MEDIA_IMS_RX_NOTICE,
                                                 MEDIA_AUDIO_ROUTING_CHANGED};

constexpr media_info_type kMediaInfoTypes[] = {
    MEDIA_INFO_UNKNOWN,           MEDIA_INFO_STARTED_AS_NEXT,
    MEDIA_INFO_RENDERING_START,   MEDIA_INFO_VIDEO_TRACK_LAGGING,
    MEDIA_INFO_BUFFERING_START,   MEDIA_INFO_BUFFERING_END,
    MEDIA_INFO_NETWORK_BANDWIDTH, MEDIA_INFO_BAD_INTERLEAVING,
    MEDIA_INFO_NOT_SEEKABLE,      MEDIA_INFO_METADATA_UPDATE,
    MEDIA_INFO_PLAY_AUDIO_ERROR,  MEDIA_INFO_PLAY_VIDEO_ERROR,
    MEDIA_INFO_TIMED_TEXT_ERROR};

const char *kUrlPrefix[] = {"data:", "http://", "https://", "rtsp://", "content://", "test://"};

struct TestStreamSource : public IStreamSource {
    void setListener(const sp<IStreamListener> & /*listener*/) override{};
    void setBuffers(const Vector<sp<IMemory>> & /*buffers*/) override{};
    void onBufferAvailable(size_t /*index*/) override{};
    IBinder *onAsBinder() { return nullptr; };
};

struct TestMediaHTTPConnection : public MediaHTTPConnection {
  public:
    TestMediaHTTPConnection() {}
    virtual ~TestMediaHTTPConnection() {}

    virtual bool connect(const char* /*uri*/, const KeyedVector<String8, String8>* /*headers*/) {
        return true;
    }

    virtual void disconnect() { return; }

    virtual ssize_t readAt(off64_t /*offset*/, void* /*data*/, size_t size) { return size; }

    virtual off64_t getSize() { return 0; }
    virtual status_t getMIMEType(String8* /*mimeType*/) { return NO_ERROR; }
    virtual status_t getUri(String8* /*uri*/) { return NO_ERROR; }

  private:
    DISALLOW_EVIL_CONSTRUCTORS(TestMediaHTTPConnection);
};

struct TestMediaHTTPService : public BnInterface<IMediaHTTPService> {
  public:
    TestMediaHTTPService() {}
    ~TestMediaHTTPService(){};

    virtual sp<MediaHTTPConnection> makeHTTPConnection() {
        mMediaHTTPConnection = sp<TestMediaHTTPConnection>::make();
        return mMediaHTTPConnection;
    }

  private:
    sp<TestMediaHTTPConnection> mMediaHTTPConnection = nullptr;
    DISALLOW_EVIL_CONSTRUCTORS(TestMediaHTTPService);
};

class FakeBnSurfaceComposerClient : public gui::BnSurfaceComposerClient {
  public:
    MOCK_METHOD(binder::Status, createSurface,
                (const std::string& name, int32_t flags, const sp<IBinder>& parent,
                 const gui::LayerMetadata& metadata, gui::CreateSurfaceResult* outResult),
                (override));

    MOCK_METHOD(binder::Status, clearLayerFrameStats, (const sp<IBinder>& handle), (override));

    MOCK_METHOD(binder::Status, getLayerFrameStats,
                (const sp<IBinder>& handle, gui::FrameStats* outStats), (override));

    MOCK_METHOD(binder::Status, mirrorSurface,
                (const sp<IBinder>& mirrorFromHandle, gui::CreateSurfaceResult* outResult),
                (override));

    MOCK_METHOD(binder::Status, mirrorDisplay,
                (int64_t displayId, gui::CreateSurfaceResult* outResult), (override));

    MOCK_METHOD(binder::Status, getSchedulingPolicy, (gui::SchedulingPolicy*), (override));
};

class MediaPlayerServiceFuzzer {
   public:
    MediaPlayerServiceFuzzer(const uint8_t *data, size_t size)
        : mFdp(data, size), mDataSourceFd(memfd_create("InputFile", MFD_ALLOW_SEALING)){};
    ~MediaPlayerServiceFuzzer() { close(mDataSourceFd); };
    void process(const uint8_t *data, size_t size);

   private:
     FuzzedDataProvider mFdp;
     const int32_t mDataSourceFd;
     sp<IMediaPlayer> mMediaPlayer = nullptr;
     sp<IMediaPlayerClient> mMediaPlayerClient = nullptr;
     void invokeMediaPlayer();
     sp<SurfaceControl> makeSurfaceControl();
     bool setDataSource(const uint8_t* data, size_t size);
};

sp<SurfaceControl> MediaPlayerServiceFuzzer::makeSurfaceControl() {
     sp<IBinder> handle = getRandomBinder(&mFdp);
     const sp<FakeBnSurfaceComposerClient> testClient(new FakeBnSurfaceComposerClient());
     sp<SurfaceComposerClient> client = new SurfaceComposerClient(testClient);
     uint32_t width = mFdp.ConsumeIntegral<uint32_t>();
     uint32_t height = mFdp.ConsumeIntegral<uint32_t>();
     uint32_t transformHint = mFdp.ConsumeIntegral<uint32_t>();
     uint32_t flags = mFdp.ConsumeBool() ? kFlagVal : mFdp.ConsumeIntegral<uint32_t>();
     int32_t format = mFdp.ConsumeBool() ? mFdp.ConsumeIntegral<uint32_t>()
                                         : mFdp.PickValueInArray(kPixelFormat);
     int32_t layerId = mFdp.ConsumeIntegral<int32_t>();
     std::string layerName = android::base::StringPrintf("#%d", layerId);
     return new SurfaceControl(client, handle, layerId, layerName, width, height, format,
                               transformHint, flags);
}

bool MediaPlayerServiceFuzzer::setDataSource(const uint8_t* data, size_t size) {
     status_t status = UNKNOWN_ERROR;
     switch (mFdp.ConsumeEnum<DataSourceType>()) {
        case HTTP: {
            KeyedVector<String8, String8> headers;
            headers.add(String8(mFdp.ConsumeRandomLengthString().c_str()),
                        String8(mFdp.ConsumeRandomLengthString().c_str()));

            uint32_t dataBlobSize = mFdp.ConsumeIntegralInRange<uint16_t>(kMinSize, size);
            vector<uint8_t> uriSuffix = mFdp.ConsumeBytes<uint8_t>(dataBlobSize);

            string uri(mFdp.PickValueInArray(kUrlPrefix));
            uri += ";base64,";
            AString out;
            encodeBase64(uriSuffix.data(), uriSuffix.size(), &out);
            uri += out.c_str();
            sp<TestMediaHTTPService> testService = sp<TestMediaHTTPService>::make();
            status =
                    mMediaPlayer->setDataSource(testService /*httpService*/, uri.c_str(), &headers);
            break;
        }
        case FD: {
            write(mDataSourceFd, data, size);
            status = mMediaPlayer->setDataSource(mDataSourceFd, 0, size);
            break;
        }
        case STREAM: {
            sp<IStreamSource> streamSource = sp<TestStreamSource>::make();
            status = mMediaPlayer->setDataSource(streamSource);
            break;
        }
        case FILETYPE: {
            write(mDataSourceFd, data, size);

            sp<DataSource> dataSource = new FileSource(dup(mDataSourceFd), 0, size);
            sp<IDataSource> iDataSource = RemoteDataSource::wrap(dataSource);
            if (!iDataSource) {
                return false;
            }
            status = mMediaPlayer->setDataSource(iDataSource);
            break;
        }
        case SOCKET: {
            String8 rtpParams = String8(mFdp.ConsumeRandomLengthString().c_str());
            struct sockaddr_in endpoint;
            endpoint.sin_family = mFdp.ConsumeIntegral<unsigned short>();
            endpoint.sin_port = mFdp.ConsumeIntegral<uint16_t>();
            mMediaPlayer->setRetransmitEndpoint(&endpoint);
            status = mMediaPlayer->setDataSource(rtpParams);
            break;
        }
     }
     if (status != OK) {
        return false;
     }
     return true;
}

void MediaPlayerServiceFuzzer::invokeMediaPlayer() {
     Parcel request, reply;
     while (mFdp.remaining_bytes()) {
        auto invokeMediaPlayerApi = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() {
                    sp<SurfaceControl> surfaceControl = makeSurfaceControl();
                    if (surfaceControl) {
                        sp<Surface> surface = surfaceControl->getSurface();
                        mMediaPlayer->setVideoSurfaceTexture(surface->getIGraphicBufferProducer());
                    }
                },
                [&]() {
                    BufferingSettings buffering;
                    buffering.mInitialMarkMs = mFdp.ConsumeIntegral<int32_t>();
                    buffering.mResumePlaybackMarkMs = mFdp.ConsumeIntegral<int32_t>();
                    mMediaPlayer->setBufferingSettings(buffering);
                },
                [&]() {
                    BufferingSettings buffering;
                    mMediaPlayer->getBufferingSettings(&buffering);
                },
                [&]() {
                    mMediaPlayer->prepareAsync();
                    this_thread::sleep_for(chrono::milliseconds(100));  // Time to post message
                },
                [&]() {
                    mMediaPlayer->start();
                    this_thread::sleep_for(chrono::milliseconds(100));  // Time to post message
                },
                [&]() {
                    mMediaPlayer->pause();
                    this_thread::sleep_for(chrono::milliseconds(100));  // Time to post message
                },
                [&]() { mMediaPlayer->stop(); },
                [&]() {
                    bool state;
                    mMediaPlayer->isPlaying(&state);
                },
                [&]() {
                    AudioPlaybackRate rate;
                    rate.mSpeed = mFdp.ConsumeFloatingPoint<float>();
                    rate.mPitch = mFdp.ConsumeFloatingPoint<float>();
                    rate.mStretchMode = mFdp.ConsumeBool() ? AUDIO_TIMESTRETCH_STRETCH_DEFAULT
                                                           : AUDIO_TIMESTRETCH_STRETCH_VOICE;
                    rate.mFallbackMode =
                            (audio_timestretch_fallback_mode_t)mFdp.ConsumeIntegralInRange<int32_t>(
                                    AUDIO_TIMESTRETCH_FALLBACK_CUT_REPEAT,
                                    AUDIO_TIMESTRETCH_FALLBACK_FAIL);
                    mMediaPlayer->setPlaybackSettings(rate);
                    mMediaPlayer->getPlaybackSettings(&rate);
                },
                [&]() {
                    AVSyncSettings* avSyncSettings = new AVSyncSettings();
                    float videoFpsHint = mFdp.ConsumeFloatingPoint<float>();
                    mMediaPlayer->setSyncSettings(*avSyncSettings, videoFpsHint);
                    delete avSyncSettings;
                },
                [&]() {
                    AVSyncSettings* avSyncSettings = new AVSyncSettings();
                    float videoFpsHint = 0;
                    mMediaPlayer->getSyncSettings(avSyncSettings, &videoFpsHint);
                    delete avSyncSettings;
                },
                [&]() { mMediaPlayer->seekTo(mFdp.ConsumeIntegral<int32_t>()); },
                [&]() {
                    int32_t msec;
                    mMediaPlayer->getCurrentPosition(&msec);
                    mMediaPlayer->getDuration(&msec);
                },
                [&]() { mMediaPlayer->reset(); },
                [&]() { mMediaPlayer->notifyAt(mFdp.ConsumeIntegral<uint64_t>()); },
                [&]() {
                    mMediaPlayer->setAudioStreamType(
                            (audio_stream_type_t)mFdp.ConsumeIntegralInRange<int32_t>(
                                    AUDIO_STREAM_VOICE_CALL, AUDIO_STREAM_CALL_ASSISTANT));
                },
                [&]() { mMediaPlayer->setLooping(mFdp.ConsumeIntegral<int32_t>()); },
                [&]() {
                    mMediaPlayer->setVolume(mFdp.ConsumeFloatingPoint<float>() /* left */,
                                            mFdp.ConsumeFloatingPoint<float>() /* right */);
                },
                [&]() {
                    request.writeInt32(mFdp.ConsumeIntegral<int32_t>());
                    request.setDataPosition(0);
                    mMediaPlayer->invoke(request, &reply);
                },
                [&]() {
                    Parcel filter;
                    filter.writeInt32(mFdp.ConsumeIntegral<int32_t>());
                    filter.setDataPosition(0);
                    mMediaPlayer->setMetadataFilter(filter);
                },
                [&]() {
                    mMediaPlayer->getMetadata(mFdp.ConsumeBool() /* updateOnly */,
                                              mFdp.ConsumeBool() /* applyFilter */, &reply);
                },
                [&]() { mMediaPlayer->setAuxEffectSendLevel(mFdp.ConsumeFloatingPoint<float>()); },
                [&]() { mMediaPlayer->attachAuxEffect(mFdp.ConsumeIntegral<int32_t>()); },
                [&]() {
                    int32_t key = mFdp.PickValueInArray(kMediaParamKeys);
                    request.writeInt32((audio_usage_t)mFdp.ConsumeIntegralInRange<int32_t>(
                            AUDIO_USAGE_UNKNOWN, AUDIO_USAGE_ANNOUNCEMENT) /* usage */);
                    request.writeInt32((audio_content_type_t)mFdp.ConsumeIntegralInRange<int32_t>(
                            AUDIO_CONTENT_TYPE_UNKNOWN,
                            AUDIO_CONTENT_TYPE_ULTRASOUND) /* content_type */);
                    request.writeInt32((audio_source_t)mFdp.ConsumeIntegralInRange<int32_t>(
                            AUDIO_SOURCE_INVALID, AUDIO_SOURCE_ULTRASOUND) /* source */);
                    request.writeInt32((audio_flags_mask_t)mFdp.ConsumeIntegralInRange<int32_t>(
                            AUDIO_FLAG_NONE, AUDIO_FLAG_CALL_REDIRECTION) /* flags */);
                    request.writeInt32(mFdp.ConsumeBool() /* hasFlattenedTag */);
                    request.writeString16(
                            String16((mFdp.ConsumeRandomLengthString()).c_str()) /* tags */);
                    request.setDataPosition(0);
                    mMediaPlayer->setParameter(key, request);
                    key = mFdp.PickValueInArray(kMediaParamKeys);
                    mMediaPlayer->getParameter(key, &reply);
                },
                [&]() {
                    int32_t key =
                            mFdp.ConsumeBool() ? kFourCCVal : mFdp.ConsumeIntegral<uint32_t>();
                    mMediaPlayer->getParameter(key, &reply);
                },
                [&]() {
                    struct sockaddr_in endpoint;
                    mMediaPlayer->getRetransmitEndpoint(&endpoint);
                },
                [&]() {
                    AttributionSourceState attributionSource;
                    attributionSource.packageName = mFdp.ConsumeRandomLengthString().c_str();
                    attributionSource.token = sp<BBinder>::make();
                    const sp<IMediaPlayerService> mpService(
                            IMediaDeathNotifier::getMediaPlayerService());
                    audio_session_t audioSessionId =
                            (audio_session_t)mFdp.ConsumeIntegralInRange<int32_t>(
                                    AUDIO_SESSION_DEVICE, AUDIO_SESSION_OUTPUT_MIX);
                    sp<IMediaPlayer> mNextMediaPlayer = mpService->create(
                            mMediaPlayerClient, audioSessionId, attributionSource);
                    mMediaPlayer->setNextPlayer(mNextMediaPlayer);
                },
                [&]() {
                    const sp<media::VolumeShaper::Configuration> configuration =
                            sp<media::VolumeShaper::Configuration>::make();
                    const sp<media::VolumeShaper::Operation> operation =
                            sp<media::VolumeShaper::Operation>::make();
                    mMediaPlayer->applyVolumeShaper(configuration, operation);
                },
                [&]() { mMediaPlayer->getVolumeShaperState(mFdp.ConsumeIntegral<int32_t>()); },
                [&]() {
                    uint8_t uuid[kUuidSize];
                    for (int32_t index = 0; index < kUuidSize; ++index) {
                        uuid[index] = mFdp.ConsumeIntegral<uint8_t>();
                    }
                    Vector<uint8_t> drmSessionId;
                    int32_t length = mFdp.ConsumeIntegralInRange<uint32_t>(kMinSize, kMaxSize);
                    while (length--) {
                        drmSessionId.push_back(mFdp.ConsumeIntegral<uint8_t>());
                    }
                    mMediaPlayer->prepareDrm(uuid, drmSessionId);
                },
                [&]() { mMediaPlayer->releaseDrm(); },
                [&]() {
                    audio_port_handle_t deviceId = mFdp.ConsumeIntegral<int32_t>();
                    mMediaPlayer->setOutputDevice(deviceId);
                },
                [&]() {
                    audio_port_handle_t deviceId;
                    mMediaPlayer->getRoutedDeviceId(&deviceId);
                },
                [&]() { mMediaPlayer->enableAudioDeviceCallback(mFdp.ConsumeBool()); },
                [&]() {
                    sp<MediaPlayer> mediaPlayer = (MediaPlayer*)mMediaPlayer.get();
                    Parcel obj;
                    obj.writeInt32(mFdp.ConsumeIntegral<int32_t>());
                    obj.setDataPosition(0);
                    mediaPlayer->notify(mFdp.PickValueInArray(kMediaEventTypes) /* msg */,
                                        mFdp.PickValueInArray(kMediaInfoTypes) /* ext1 */,
                                        mFdp.ConsumeIntegral<int32_t>() /* ext2 */, &obj);
                },
                [&]() {
                    sp<MediaPlayer> mediaPlayer = (MediaPlayer*)mMediaPlayer.get();
                    int32_t mediaPlayerDumpFd = memfd_create(dumpFile, MFD_ALLOW_SEALING);
                    Vector<String16> args;
                    args.push_back(String16(mFdp.ConsumeRandomLengthString().c_str()));
                    mediaPlayer->dump(mediaPlayerDumpFd, args);
                    close(mediaPlayerDumpFd);
                },
                [&]() { mMediaPlayer->disconnect(); },
        });
        invokeMediaPlayerApi();
     }
}

void MediaPlayerServiceFuzzer::process(const uint8_t* data, size_t size) {
     const sp<IMediaPlayerService> mpService(IMediaDeathNotifier::getMediaPlayerService());
     if (!mpService) {
        return;
     }

     sp<IMediaCodecList> mediaCodecList = mpService->getCodecList();

     sp<IRemoteDisplayClient> remoteDisplayClient;
     sp<IRemoteDisplay> remoteDisplay = mpService->listenForRemoteDisplay(
             String16(mFdp.ConsumeRandomLengthString().c_str()) /*opPackageName*/,
             remoteDisplayClient, String8(mFdp.ConsumeRandomLengthString().c_str()) /*iface*/);

     mpService->addBatteryData(mFdp.ConsumeIntegral<uint32_t>());
     Parcel reply;
     mpService->pullBatteryData(&reply);

     sp<MediaPlayerService> mediaPlayerService = (MediaPlayerService*)mpService.get();
     AttributionSourceState attributionSource;
     attributionSource.packageName = mFdp.ConsumeRandomLengthString().c_str();
     attributionSource.token = sp<BBinder>::make();
     mMediaPlayer =
             mediaPlayerService->create(mMediaPlayerClient,
                                        (audio_session_t)mFdp.ConsumeIntegralInRange<int32_t>(
                                                AUDIO_SESSION_DEVICE, AUDIO_SESSION_OUTPUT_MIX),
                                        attributionSource);

     int32_t mediaPlayerServiceDumpFd = memfd_create(dumpFile, MFD_ALLOW_SEALING);
     Vector<String16> args;
     args.push_back(String16(mFdp.ConsumeRandomLengthString().c_str()));
     mediaPlayerService->dump(mediaPlayerServiceDumpFd, args);
     close(mediaPlayerServiceDumpFd);

     if (!mMediaPlayer) {
        return;
     }
     if (setDataSource(data, size)) {
        invokeMediaPlayer();
     }
}

extern "C" int LLVMFuzzerInitialize(int* /* argc */, char*** /* argv */) {
     MediaPlayerService::instantiate();
     MediaExtractorService::instantiate();
     return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    MediaPlayerServiceFuzzer mpsFuzzer(data, size);
    ProcessState::self()->startThreadPool();
    mpsFuzzer.process(data, size);
    return 0;
};
