/******************************************************************************
 *
 * Copyright (C) 2020 The Android Open Source Project
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
 *****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */
#include <fuzzer/FuzzedDataProvider.h>
#include <stdio.h>

#include <AAudioService.h>
#include <aaudio/AAudio.h>
#include "aaudio/BnAAudioClient.h"
#include <android/content/AttributionSourceState.h>

#define UNUSED_PARAM __attribute__((unused))

using namespace android;
using namespace aaudio;

aaudio_format_t kAAudioFormats[] = {
    AAUDIO_FORMAT_UNSPECIFIED,
    AAUDIO_FORMAT_PCM_I16,
    AAUDIO_FORMAT_PCM_FLOAT,
};

aaudio_usage_t kAAudioUsages[] = {
    AAUDIO_USAGE_MEDIA,
    AAUDIO_USAGE_VOICE_COMMUNICATION,
    AAUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
    AAUDIO_USAGE_ALARM,
    AAUDIO_USAGE_NOTIFICATION,
    AAUDIO_USAGE_NOTIFICATION_RINGTONE,
    AAUDIO_USAGE_NOTIFICATION_EVENT,
    AAUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
    AAUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
    AAUDIO_USAGE_ASSISTANCE_SONIFICATION,
    AAUDIO_USAGE_GAME,
    AAUDIO_USAGE_ASSISTANT,
    AAUDIO_SYSTEM_USAGE_EMERGENCY,
    AAUDIO_SYSTEM_USAGE_SAFETY,
    AAUDIO_SYSTEM_USAGE_VEHICLE_STATUS,
    AAUDIO_SYSTEM_USAGE_ANNOUNCEMENT,
};

aaudio_content_type_t kAAudioContentTypes[] = {
    AAUDIO_CONTENT_TYPE_SPEECH,
    AAUDIO_CONTENT_TYPE_MUSIC,
    AAUDIO_CONTENT_TYPE_MOVIE,
    AAUDIO_CONTENT_TYPE_SONIFICATION,
};

aaudio_input_preset_t kAAudioInputPresets[] = {
    AAUDIO_INPUT_PRESET_GENERIC,           AAUDIO_INPUT_PRESET_CAMCORDER,
    AAUDIO_INPUT_PRESET_VOICE_RECOGNITION, AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION,
    AAUDIO_INPUT_PRESET_UNPROCESSED,       AAUDIO_INPUT_PRESET_VOICE_PERFORMANCE,
};

const size_t kNumAAudioFormats = std::size(kAAudioFormats);
const size_t kNumAAudioUsages = std::size(kAAudioUsages);
const size_t kNumAAudioContentTypes = std::size(kAAudioContentTypes);
const size_t kNumAAudioInputPresets = std::size(kAAudioInputPresets);

class FuzzAAudioClient : public virtual RefBase, public AAudioServiceInterface {
   public:
    FuzzAAudioClient(sp<AAudioService> service);

    virtual ~FuzzAAudioClient();

    AAudioServiceInterface *getAAudioService();

    void dropAAudioService();

    void registerClient(const sp<IAAudioClient> &client UNUSED_PARAM) override {}

    aaudio_handle_t openStream(const AAudioStreamRequest &request,
                               AAudioStreamConfiguration &configurationOutput) override;

    aaudio_result_t closeStream(aaudio_handle_t streamHandle) override;

    aaudio_result_t getStreamDescription(aaudio_handle_t streamHandle,
                                         AudioEndpointParcelable &parcelable) override;

    aaudio_result_t startStream(aaudio_handle_t streamHandle) override;

    aaudio_result_t pauseStream(aaudio_handle_t streamHandle) override;

    aaudio_result_t stopStream(aaudio_handle_t streamHandle) override;

    aaudio_result_t flushStream(aaudio_handle_t streamHandle) override;

    aaudio_result_t registerAudioThread(aaudio_handle_t streamHandle, pid_t clientThreadId,
                                        int64_t periodNanoseconds) override;

    aaudio_result_t unregisterAudioThread(aaudio_handle_t streamHandle,
                                          pid_t clientThreadId) override;

    aaudio_result_t startClient(aaudio_handle_t streamHandle UNUSED_PARAM,
                                const AudioClient &client UNUSED_PARAM,
                                const audio_attributes_t *attr UNUSED_PARAM,
                                audio_port_handle_t *clientHandle UNUSED_PARAM) override {
        return AAUDIO_ERROR_UNAVAILABLE;
    }

    aaudio_result_t stopClient(aaudio_handle_t streamHandle UNUSED_PARAM,
                               audio_port_handle_t clientHandle UNUSED_PARAM) override {
        return AAUDIO_ERROR_UNAVAILABLE;
    }

    void onStreamChange(aaudio_handle_t handle, int32_t opcode, int32_t value) {}

    int getDeathCount() { return mDeathCount; }

    void incDeathCount() { ++mDeathCount; }

    class AAudioClient : public IBinder::DeathRecipient, public BnAAudioClient {
       public:
        AAudioClient(wp<FuzzAAudioClient> fuzzAAudioClient) : mBinderClient(fuzzAAudioClient) {}

        virtual void binderDied(const wp<IBinder> &who UNUSED_PARAM) {
            sp<FuzzAAudioClient> client = mBinderClient.promote();
            if (client.get()) {
                client->dropAAudioService();
                client->incDeathCount();
            }
        }

        android::binder::Status onStreamChange(int32_t handle, int32_t opcode, int32_t value) {
            static_assert(std::is_same_v<aaudio_handle_t, int32_t>);
            android::sp<FuzzAAudioClient> client = mBinderClient.promote();
            if (client.get() != nullptr) {
                client->onStreamChange(handle, opcode, value);
            }
            return android::binder::Status::ok();
        }

       private:
        wp<FuzzAAudioClient> mBinderClient;
    };

   private:
    sp<AAudioService> mAAudioService;
    sp<AAudioClient> mAAudioClient;
    AAudioServiceInterface *mAAudioServiceInterface;
    int mDeathCount;
};

FuzzAAudioClient::FuzzAAudioClient(sp<AAudioService> service) : AAudioServiceInterface() {
    mAAudioService = service;
    mAAudioServiceInterface = &service->asAAudioServiceInterface();
    mAAudioClient = new AAudioClient(this);
    mDeathCount = 0;
    if (mAAudioClient.get() && mAAudioService.get()) {
        mAAudioService->linkToDeath(mAAudioClient);
        mAAudioService->registerClient(mAAudioClient);
    }
}

FuzzAAudioClient::~FuzzAAudioClient() { dropAAudioService(); }

AAudioServiceInterface *FuzzAAudioClient::getAAudioService() {
    if (!mAAudioServiceInterface && mAAudioService.get()) {
        mAAudioServiceInterface = &mAAudioService->asAAudioServiceInterface();
    }
    return mAAudioServiceInterface;
}

void FuzzAAudioClient::dropAAudioService() {
    mAAudioService.clear();
}

aaudio_handle_t FuzzAAudioClient::openStream(const AAudioStreamRequest &request,
                                             AAudioStreamConfiguration &configurationOutput) {
    aaudio_handle_t stream;
    for (int i = 0; i < 2; ++i) {
        AAudioServiceInterface *service = getAAudioService();
        if (!service) {
            return AAUDIO_ERROR_NO_SERVICE;
        }

        stream = service->openStream(request, configurationOutput);

        if (stream == AAUDIO_ERROR_NO_SERVICE) {
            dropAAudioService();
        } else {
            break;
        }
    }
    return stream;
}

aaudio_result_t FuzzAAudioClient::closeStream(aaudio_handle_t streamHandle) {
    AAudioServiceInterface *service = getAAudioService();
    if (!service) {
        return AAUDIO_ERROR_NO_SERVICE;
    }
    return service->closeStream(streamHandle);
}

aaudio_result_t FuzzAAudioClient::getStreamDescription(aaudio_handle_t streamHandle,
                                                       AudioEndpointParcelable &parcelable) {
    AAudioServiceInterface *service = getAAudioService();
    if (!service) {
        return AAUDIO_ERROR_NO_SERVICE;
    }
    return service->getStreamDescription(streamHandle, parcelable);
}

aaudio_result_t FuzzAAudioClient::startStream(aaudio_handle_t streamHandle) {
    AAudioServiceInterface *service = getAAudioService();
    if (!service) {
        return AAUDIO_ERROR_NO_SERVICE;
    }
    return service->startStream(streamHandle);
}

aaudio_result_t FuzzAAudioClient::pauseStream(aaudio_handle_t streamHandle) {
    AAudioServiceInterface *service = getAAudioService();
    if (!service) {
        return AAUDIO_ERROR_NO_SERVICE;
    }
    return service->pauseStream(streamHandle);
}

aaudio_result_t FuzzAAudioClient::stopStream(aaudio_handle_t streamHandle) {
    AAudioServiceInterface *service = getAAudioService();
    if (!service) {
        return AAUDIO_ERROR_NO_SERVICE;
    }
    return service->stopStream(streamHandle);
}

aaudio_result_t FuzzAAudioClient::flushStream(aaudio_handle_t streamHandle) {
    AAudioServiceInterface *service = getAAudioService();
    if (!service) {
        return AAUDIO_ERROR_NO_SERVICE;
    }
    return service->flushStream(streamHandle);
}

aaudio_result_t FuzzAAudioClient::registerAudioThread(aaudio_handle_t streamHandle,
                                                      pid_t clientThreadId,
                                                      int64_t periodNanoseconds) {
    AAudioServiceInterface *service = getAAudioService();
    if (!service) {
        return AAUDIO_ERROR_NO_SERVICE;
    }
    return service->registerAudioThread(streamHandle, clientThreadId, periodNanoseconds);
}

aaudio_result_t FuzzAAudioClient::unregisterAudioThread(aaudio_handle_t streamHandle,
                                                        pid_t clientThreadId) {
    AAudioServiceInterface *service = getAAudioService();
    if (!service) {
        return AAUDIO_ERROR_NO_SERVICE;
    }
    return service->unregisterAudioThread(streamHandle, clientThreadId);
}

class OboeserviceFuzzer {
   public:
    OboeserviceFuzzer();
    ~OboeserviceFuzzer() = default;
    void process(const uint8_t *data, size_t size);

   private:
    sp<FuzzAAudioClient> mClient;
};

OboeserviceFuzzer::OboeserviceFuzzer() {
    sp<AAudioService> service = new AAudioService();
    mClient = new FuzzAAudioClient(service);
}

void OboeserviceFuzzer::process(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
    AAudioStreamRequest request;
    AAudioStreamConfiguration configurationOutput;

    // Initialize stream request
    request.getConfiguration().setFormat((audio_format_t)(
        fdp.ConsumeBool()
            ? fdp.ConsumeIntegral<int32_t>()
            : kAAudioFormats[fdp.ConsumeIntegralInRange<int32_t>(0, kNumAAudioFormats - 1)]));

    // TODO b/182392769: use attribution source util
    android::content::AttributionSourceState attributionSource;
    attributionSource.uid = getuid();
    attributionSource.pid = getpid();
    attributionSource.token = sp<BBinder>::make();
    request.setAttributionSource(attributionSource);
    request.setInService(fdp.ConsumeBool());

    request.getConfiguration().setDeviceId(fdp.ConsumeIntegral<int32_t>());
    request.getConfiguration().setSampleRate(fdp.ConsumeIntegral<int32_t>());
    request.getConfiguration().setSamplesPerFrame(fdp.ConsumeIntegral<int32_t>());
    request.getConfiguration().setDirection(
        fdp.ConsumeBool() ? fdp.ConsumeIntegral<int32_t>()
                          : (fdp.ConsumeBool() ? AAUDIO_DIRECTION_OUTPUT : AAUDIO_DIRECTION_INPUT));
    request.getConfiguration().setSharingMode(
        fdp.ConsumeBool()
            ? fdp.ConsumeIntegral<int32_t>()
            : (fdp.ConsumeBool() ? AAUDIO_SHARING_MODE_EXCLUSIVE : AAUDIO_SHARING_MODE_SHARED));

    request.getConfiguration().setUsage(
        fdp.ConsumeBool()
            ? fdp.ConsumeIntegral<int32_t>()
            : kAAudioUsages[fdp.ConsumeIntegralInRange<int32_t>(0, kNumAAudioUsages - 1)]);
    request.getConfiguration().setContentType(
        fdp.ConsumeBool() ? fdp.ConsumeIntegral<int32_t>()
                          : kAAudioContentTypes[fdp.ConsumeIntegralInRange<int32_t>(
                                0, kNumAAudioContentTypes - 1)]);
    request.getConfiguration().setInputPreset(
        fdp.ConsumeBool() ? fdp.ConsumeIntegral<int32_t>()
                          : kAAudioInputPresets[fdp.ConsumeIntegralInRange<int32_t>(
                                0, kNumAAudioInputPresets - 1)]);
    request.getConfiguration().setPrivacySensitive(fdp.ConsumeBool());

    request.getConfiguration().setBufferCapacity(fdp.ConsumeIntegral<int32_t>());

    aaudio_handle_t stream = mClient->openStream(request, configurationOutput);
    if (stream < 0) {
        // invalid request, stream not opened.
        return;
    }
    while (fdp.remaining_bytes()) {
        AudioEndpointParcelable audioEndpointParcelable;
        int action = fdp.ConsumeIntegralInRange<int32_t>(0, 4);
        switch (action) {
            case 0:
                mClient->getStreamDescription(stream, audioEndpointParcelable);
                break;
            case 1:
                mClient->startStream(stream);
                break;
            case 2:
                mClient->pauseStream(stream);
                break;
            case 3:
                mClient->stopStream(stream);
                break;
            case 4:
                mClient->flushStream(stream);
                break;
        }
    }
    mClient->closeStream(stream);
    assert(mClient->getDeathCount() == 0);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    OboeserviceFuzzer oboeserviceFuzzer;
    oboeserviceFuzzer.process(data, size);
    return 0;
}
