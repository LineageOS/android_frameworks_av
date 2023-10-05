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

#include <MediaPlayerService.h>
#include <camera/Camera.h>
#include <datasource/FileSource.h>
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
#include "fuzzer/FuzzedDataProvider.h"

constexpr int32_t kUuidSize = 16;
constexpr int32_t kMaxSleepTimeInMs = 100;
constexpr int32_t kMinSleepTimeInMs = 0;
constexpr int32_t kPlayCountMin = 1;
constexpr int32_t kPlayCountMax = 10;
constexpr int32_t kMaxDimension = 8192;
constexpr int32_t kMinDimension = 0;

using namespace std;
using namespace android;

constexpr audio_session_t kSupportedAudioSessions[] = {
    AUDIO_SESSION_DEVICE, AUDIO_SESSION_OUTPUT_STAGE, AUDIO_SESSION_OUTPUT_MIX};

constexpr audio_timestretch_stretch_mode_t kAudioStretchModes[] = {
    AUDIO_TIMESTRETCH_STRETCH_DEFAULT, AUDIO_TIMESTRETCH_STRETCH_VOICE};

constexpr audio_timestretch_fallback_mode_t kAudioFallbackModes[] = {
    AUDIO_TIMESTRETCH_FALLBACK_CUT_REPEAT, AUDIO_TIMESTRETCH_FALLBACK_DEFAULT,
    AUDIO_TIMESTRETCH_FALLBACK_MUTE, AUDIO_TIMESTRETCH_FALLBACK_FAIL};

constexpr media_parameter_keys kMediaParamKeys[] = {
    KEY_PARAMETER_CACHE_STAT_COLLECT_FREQ_MS, KEY_PARAMETER_AUDIO_CHANNEL_COUNT,
    KEY_PARAMETER_PLAYBACK_RATE_PERMILLE, KEY_PARAMETER_AUDIO_ATTRIBUTES,
    KEY_PARAMETER_RTP_ATTRIBUTES};

constexpr audio_stream_type_t kAudioStreamTypes[] = {
    AUDIO_STREAM_DEFAULT,      AUDIO_STREAM_VOICE_CALL,    AUDIO_STREAM_SYSTEM,
    AUDIO_STREAM_RING,         AUDIO_STREAM_MUSIC,         AUDIO_STREAM_ALARM,
    AUDIO_STREAM_NOTIFICATION, AUDIO_STREAM_BLUETOOTH_SCO, AUDIO_STREAM_ENFORCED_AUDIBLE,
    AUDIO_STREAM_DTMF,         AUDIO_STREAM_TTS,           AUDIO_STREAM_ASSISTANT};

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

class BinderDeathNotifier : public IBinder::DeathRecipient {
   public:
    void binderDied(const wp<IBinder> &) { abort(); }
};

class MediaPlayerServiceFuzzer {
   public:
    MediaPlayerServiceFuzzer(const uint8_t *data, size_t size)
        : mFdp(data, size), mDataSourceFd(memfd_create("InputFile", MFD_ALLOW_SEALING)){};
    ~MediaPlayerServiceFuzzer() { close(mDataSourceFd); };
    void process(const uint8_t *data, size_t size);

   private:
    bool setDataSource(const uint8_t *data, size_t size);
    void invokeMediaPlayer();
    FuzzedDataProvider mFdp;
    sp<IMediaPlayer> mMediaPlayer = nullptr;
    sp<IMediaPlayerClient> mMediaPlayerClient = nullptr;
    const int32_t mDataSourceFd;
};

bool MediaPlayerServiceFuzzer::setDataSource(const uint8_t *data, size_t size) {
    status_t status = -1;
    enum DataSourceType {http, fd, stream, file, socket, kMaxValue = socket};
    switch (mFdp.ConsumeEnum<DataSourceType>()) {
        case http: {
            KeyedVector<String8, String8> headers;
            headers.add(String8(mFdp.ConsumeRandomLengthString().c_str()),
                        String8(mFdp.ConsumeRandomLengthString().c_str()));

            uint32_t dataBlobSize = mFdp.ConsumeIntegralInRange<uint16_t>(0, size);
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
        case fd: {
            write(mDataSourceFd, data, size);

            status = mMediaPlayer->setDataSource(mDataSourceFd, 0, size);
            break;
        }
        case stream: {
            sp<IStreamSource> streamSource = sp<TestStreamSource>::make();
            status = mMediaPlayer->setDataSource(streamSource);
            break;
        }
        case file: {
            write(mDataSourceFd, data, size);

            sp<DataSource> dataSource = new FileSource(dup(mDataSourceFd), 0, size);
            sp<IDataSource> iDataSource = RemoteDataSource::wrap(dataSource);
            if (!iDataSource) {
                return false;
            }
            status = mMediaPlayer->setDataSource(iDataSource);
            break;
        }
        case socket: {
            String8 rtpParams = String8(mFdp.ConsumeRandomLengthString().c_str());
            struct sockaddr_in endpoint;
            endpoint.sin_family = mFdp.ConsumeIntegral<unsigned short>();
            endpoint.sin_port = mFdp.ConsumeIntegral<uint16_t>();
            mMediaPlayer->setRetransmitEndpoint(&endpoint);
            status = mMediaPlayer->setDataSource(rtpParams);
            break;
        }
    }

    if (status != 0) {
        return false;
    }
    return true;
}

void MediaPlayerServiceFuzzer::invokeMediaPlayer() {
    sp<SurfaceComposerClient> composerClient = new SurfaceComposerClient;
    String8 name = String8(mFdp.ConsumeRandomLengthString().c_str());
    uint32_t width = mFdp.ConsumeIntegralInRange<uint32_t>(kMinDimension, kMaxDimension);
    uint32_t height = mFdp.ConsumeIntegralInRange<uint32_t>(kMinDimension, kMaxDimension);
    uint32_t pixelFormat = mFdp.ConsumeIntegral<int32_t>();
    uint32_t flags = mFdp.ConsumeIntegral<int32_t>();
    sp<SurfaceControl> surfaceControl =
        composerClient->createSurface(name, width, height, pixelFormat, flags);
    if (surfaceControl) {
        sp<Surface> surface = surfaceControl->getSurface();
        mMediaPlayer->setVideoSurfaceTexture(surface->getIGraphicBufferProducer());
    }

    BufferingSettings buffering;
    buffering.mInitialMarkMs = mFdp.ConsumeIntegral<int32_t>();
    buffering.mResumePlaybackMarkMs = mFdp.ConsumeIntegral<int32_t>();
    mMediaPlayer->setBufferingSettings(buffering);
    mMediaPlayer->getBufferingSettings(&buffering);

    mMediaPlayer->prepareAsync();
    size_t playCount = mFdp.ConsumeIntegralInRange<size_t>(kPlayCountMin, kPlayCountMax);
    for (size_t Idx = 0; Idx < playCount; ++Idx) {
        mMediaPlayer->start();
        this_thread::sleep_for(chrono::milliseconds(
            mFdp.ConsumeIntegralInRange<int32_t>(kMinSleepTimeInMs, kMaxSleepTimeInMs)));
        mMediaPlayer->pause();
        this_thread::sleep_for(chrono::milliseconds(
            mFdp.ConsumeIntegralInRange<int32_t>(kMinSleepTimeInMs, kMaxSleepTimeInMs)));
        mMediaPlayer->stop();
    }
    bool state;
    mMediaPlayer->isPlaying(&state);

    AudioPlaybackRate rate;
    rate.mSpeed = mFdp.ConsumeFloatingPoint<float>();
    rate.mPitch = mFdp.ConsumeFloatingPoint<float>();
    rate.mStretchMode = mFdp.PickValueInArray(kAudioStretchModes);
    rate.mFallbackMode = mFdp.PickValueInArray(kAudioFallbackModes);
    mMediaPlayer->setPlaybackSettings(rate);
    mMediaPlayer->getPlaybackSettings(&rate);

    AVSyncSettings *avSyncSettings = new AVSyncSettings();
    float videoFpsHint = mFdp.ConsumeFloatingPoint<float>();
    mMediaPlayer->setSyncSettings(*avSyncSettings, videoFpsHint);
    mMediaPlayer->getSyncSettings(avSyncSettings, &videoFpsHint);
    delete avSyncSettings;

    mMediaPlayer->seekTo(mFdp.ConsumeIntegral<int32_t>());

    int32_t msec;
    mMediaPlayer->getCurrentPosition(&msec);
    mMediaPlayer->getDuration(&msec);
    mMediaPlayer->reset();

    mMediaPlayer->notifyAt(mFdp.ConsumeIntegral<int64_t>());

    mMediaPlayer->setAudioStreamType(mFdp.PickValueInArray(kAudioStreamTypes));
    mMediaPlayer->setLooping(mFdp.ConsumeIntegral<int32_t>());
    float left = mFdp.ConsumeFloatingPoint<float>();
    float right = mFdp.ConsumeFloatingPoint<float>();
    mMediaPlayer->setVolume(left, right);

    Parcel request, reply;
    request.writeInt32(mFdp.ConsumeIntegral<int32_t>());
    request.setDataPosition(0);
    mMediaPlayer->invoke(request, &reply);

    Parcel filter;
    filter.writeInt32(mFdp.ConsumeIntegral<int32_t>());
    filter.setDataPosition(0);
    mMediaPlayer->setMetadataFilter(filter);

    bool updateOnly = mFdp.ConsumeBool();
    bool applyFilter = mFdp.ConsumeBool();
    mMediaPlayer->getMetadata(updateOnly, applyFilter, &reply);
    mMediaPlayer->setAuxEffectSendLevel(mFdp.ConsumeFloatingPoint<float>());
    mMediaPlayer->attachAuxEffect(mFdp.ConsumeIntegral<int32_t>());

    int32_t key = mFdp.PickValueInArray(kMediaParamKeys);
    request.writeInt32(mFdp.ConsumeIntegral<int32_t>());
    request.setDataPosition(0);
    mMediaPlayer->setParameter(key, request);
    key = mFdp.PickValueInArray(kMediaParamKeys);
    mMediaPlayer->getParameter(key, &reply);

    struct sockaddr_in endpoint;
    mMediaPlayer->getRetransmitEndpoint(&endpoint);

    AttributionSourceState attributionSource;
    attributionSource.packageName = mFdp.ConsumeRandomLengthString().c_str();
    attributionSource.token = sp<BBinder>::make();
    const sp<IMediaPlayerService> mpService(IMediaDeathNotifier::getMediaPlayerService());
    sp<IMediaPlayer> mNextMediaPlayer = mpService->create(
        mMediaPlayerClient, mFdp.PickValueInArray(kSupportedAudioSessions), attributionSource);
    mMediaPlayer->setNextPlayer(mNextMediaPlayer);

    const sp<media::VolumeShaper::Configuration> configuration =
        sp<media::VolumeShaper::Configuration>::make();
    const sp<media::VolumeShaper::Operation> operation = sp<media::VolumeShaper::Operation>::make();
    mMediaPlayer->applyVolumeShaper(configuration, operation);

    mMediaPlayer->getVolumeShaperState(mFdp.ConsumeIntegral<int32_t>());
    uint8_t uuid[kUuidSize];
    for (int32_t index = 0; index < kUuidSize; ++index) {
        uuid[index] = mFdp.ConsumeIntegral<uint8_t>();
    }
    Vector<uint8_t> drmSessionId;
    drmSessionId.push_back(mFdp.ConsumeIntegral<uint8_t>());
    mMediaPlayer->prepareDrm(uuid, drmSessionId);
    mMediaPlayer->releaseDrm();

    audio_port_handle_t deviceId = mFdp.ConsumeIntegral<int32_t>();
    mMediaPlayer->setOutputDevice(deviceId);
    mMediaPlayer->getRoutedDeviceId(&deviceId);

    mMediaPlayer->enableAudioDeviceCallback(mFdp.ConsumeBool());

    sp<MediaPlayer> mediaPlayer = (MediaPlayer *)mMediaPlayer.get();

    int32_t msg = mFdp.PickValueInArray(kMediaEventTypes);
    int32_t ext1 = mFdp.PickValueInArray(kMediaInfoTypes);
    int32_t ext2 = mFdp.ConsumeIntegral<int32_t>();
    Parcel obj;
    obj.writeInt32(mFdp.ConsumeIntegral<int32_t>());
    obj.setDataPosition(0);
    mediaPlayer->notify(msg, ext1, ext2, &obj);

    int32_t mediaPlayerDumpFd = memfd_create("OutputDumpFile", MFD_ALLOW_SEALING);
    Vector<String16> args;
    args.push_back(String16(mFdp.ConsumeRandomLengthString().c_str()));
    mediaPlayer->dump(mediaPlayerDumpFd, args);
    close(mediaPlayerDumpFd);

    mMediaPlayer->disconnect();
}

void MediaPlayerServiceFuzzer::process(const uint8_t *data, size_t size) {
    MediaPlayerService::instantiate();

    const sp<IMediaPlayerService> mpService(IMediaDeathNotifier::getMediaPlayerService());
    if (!mpService) {
        return;
    }

    sp<IMediaCodecList> mediaCodecList = mpService->getCodecList();

    sp<IRemoteDisplayClient> remoteDisplayClient;
    sp<IRemoteDisplay> remoteDisplay = mpService->listenForRemoteDisplay(
        String16(mFdp.ConsumeRandomLengthString().c_str()) /*opPackageName*/, remoteDisplayClient,
        String8(mFdp.ConsumeRandomLengthString().c_str()) /*iface*/);

    mpService->addBatteryData(mFdp.ConsumeIntegral<uint32_t>());
    Parcel reply;
    mpService->pullBatteryData(&reply);

    sp<MediaPlayerService> mediaPlayerService = (MediaPlayerService *)mpService.get();
    AttributionSourceState attributionSource;
    attributionSource.packageName = mFdp.ConsumeRandomLengthString().c_str();
    attributionSource.token = sp<BBinder>::make();
    mMediaPlayer = mediaPlayerService->create(
        mMediaPlayerClient, mFdp.PickValueInArray(kSupportedAudioSessions), attributionSource);

    int32_t mediaPlayerServiceDumpFd = memfd_create("OutputDumpFile", MFD_ALLOW_SEALING);
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    MediaPlayerServiceFuzzer mpsFuzzer(data, size);
    ProcessState::self()->startThreadPool();
    mpsFuzzer.process(data, size);
    return 0;
};
