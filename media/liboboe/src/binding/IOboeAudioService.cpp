/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <oboe/OboeDefinitions.h>

#include "binding/AudioEndpointParcelable.h"
#include "binding/OboeStreamRequest.h"
#include "binding/OboeStreamConfiguration.h"
#include "binding/IOboeAudioService.h"
#include "utility/OboeUtilities.h"

namespace android {

/**
 * This is used by the Oboe Client to talk to the Oboe Service.
 *
 * The order of parameters in the Parcels must match with code in OboeAudioService.cpp.
 */
class BpOboeAudioService : public BpInterface<IOboeAudioService>
{
public:
    explicit BpOboeAudioService(const sp<IBinder>& impl)
        : BpInterface<IOboeAudioService>(impl)
    {
    }

    virtual oboe_handle_t openStream(oboe::OboeStreamRequest &request,
                                     oboe::OboeStreamConfiguration &configuration) override {
        Parcel data, reply;
        // send command
        data.writeInterfaceToken(IOboeAudioService::getInterfaceDescriptor());
        request.writeToParcel(&data);
        status_t err = remote()->transact(OPEN_STREAM, data, &reply);
        if (err != NO_ERROR) {
            return OboeConvert_androidToOboeResult(err);
        }
        // parse reply
        oboe_handle_t stream;
        reply.readInt32(&stream);
        configuration.readFromParcel(&reply);
        return stream;
    }

    virtual oboe_result_t closeStream(oboe_handle_t streamHandle) override {
        Parcel data, reply;
        // send command
        data.writeInterfaceToken(IOboeAudioService::getInterfaceDescriptor());
        data.writeInt32(streamHandle);
        status_t err = remote()->transact(CLOSE_STREAM, data, &reply);
        if (err != NO_ERROR) {
            return OboeConvert_androidToOboeResult(err);
        }
        // parse reply
        oboe_result_t res;
        reply.readInt32(&res);
        return res;
    }

    virtual oboe_result_t getStreamDescription(oboe_handle_t streamHandle,
                                               oboe::AudioEndpointParcelable &parcelable)   {
        Parcel data, reply;
        // send command
        data.writeInterfaceToken(IOboeAudioService::getInterfaceDescriptor());
        data.writeInt32(streamHandle);
        status_t err = remote()->transact(GET_STREAM_DESCRIPTION, data, &reply);
        if (err != NO_ERROR) {
            return OboeConvert_androidToOboeResult(err);
        }
        // parse reply
        parcelable.readFromParcel(&reply);
        parcelable.dump();
        oboe_result_t result = parcelable.validate();
        if (result != OBOE_OK) {
            return result;
        }
        reply.readInt32(&result);
        return result;
    }

    // TODO should we wait for a reply?
    virtual oboe_result_t startStream(oboe_handle_t streamHandle) override {
        Parcel data, reply;
        // send command
        data.writeInterfaceToken(IOboeAudioService::getInterfaceDescriptor());
        data.writeInt32(streamHandle);
        status_t err = remote()->transact(START_STREAM, data, &reply);
        if (err != NO_ERROR) {
            return OboeConvert_androidToOboeResult(err);
        }
        // parse reply
        oboe_result_t res;
        reply.readInt32(&res);
        return res;
    }

    virtual oboe_result_t pauseStream(oboe_handle_t streamHandle) override {
        Parcel data, reply;
        // send command
        data.writeInterfaceToken(IOboeAudioService::getInterfaceDescriptor());
        data.writeInt32(streamHandle);
        status_t err = remote()->transact(PAUSE_STREAM, data, &reply);
        if (err != NO_ERROR) {
            return OboeConvert_androidToOboeResult(err);
        }
        // parse reply
        oboe_result_t res;
        reply.readInt32(&res);
        return res;
    }

    virtual oboe_result_t flushStream(oboe_handle_t streamHandle) override {
        Parcel data, reply;
        // send command
        data.writeInterfaceToken(IOboeAudioService::getInterfaceDescriptor());
        data.writeInt32(streamHandle);
        status_t err = remote()->transact(FLUSH_STREAM, data, &reply);
        if (err != NO_ERROR) {
            return OboeConvert_androidToOboeResult(err);
        }
        // parse reply
        oboe_result_t res;
        reply.readInt32(&res);
        return res;
    }

    virtual oboe_result_t registerAudioThread(oboe_handle_t streamHandle, pid_t clientThreadId,
                                              oboe_nanoseconds_t periodNanoseconds)
    override {
        Parcel data, reply;
        // send command
        data.writeInterfaceToken(IOboeAudioService::getInterfaceDescriptor());
        data.writeInt32(streamHandle);
        data.writeInt32((int32_t) clientThreadId);
        data.writeInt64(periodNanoseconds);
        status_t err = remote()->transact(REGISTER_AUDIO_THREAD, data, &reply);
        if (err != NO_ERROR) {
            return OboeConvert_androidToOboeResult(err);
        }
        // parse reply
        oboe_result_t res;
        reply.readInt32(&res);
        return res;
    }

    virtual oboe_result_t unregisterAudioThread(oboe_handle_t streamHandle, pid_t clientThreadId)
    override {
        Parcel data, reply;
        // send command
        data.writeInterfaceToken(IOboeAudioService::getInterfaceDescriptor());
        data.writeInt32(streamHandle);
        data.writeInt32((int32_t) clientThreadId);
        status_t err = remote()->transact(UNREGISTER_AUDIO_THREAD, data, &reply);
        if (err != NO_ERROR) {
            return OboeConvert_androidToOboeResult(err);
        }
        // parse reply
        oboe_result_t res;
        reply.readInt32(&res);
        return res;
    }

};

// Implement an interface to the service.
// This is here so that you don't have to link with liboboe static library.
IMPLEMENT_META_INTERFACE(OboeAudioService, "IOboeAudioService");

// The order of parameters in the Parcels must match with code in BpOboeAudioService

status_t BnOboeAudioService::onTransact(uint32_t code, const Parcel& data,
                                        Parcel* reply, uint32_t flags) {
    OboeStream stream;
    oboe::OboeStreamRequest request;
    oboe::OboeStreamConfiguration configuration;
    pid_t pid;
    oboe_nanoseconds_t nanoseconds;
    oboe_result_t result;
    ALOGV("BnOboeAudioService::onTransact(%i) %i", code, flags);
    data.checkInterface(this);

    switch(code) {
        case OPEN_STREAM: {
            request.readFromParcel(&data);
            stream = openStream(request, configuration);
            ALOGD("BnOboeAudioService::onTransact OPEN_STREAM server handle = 0x%08X", stream);
            reply->writeInt32(stream);
            configuration.writeToParcel(reply);
            return NO_ERROR;
        } break;

        case CLOSE_STREAM: {
            data.readInt32(&stream);
            ALOGD("BnOboeAudioService::onTransact CLOSE_STREAM 0x%08X", stream);
            result = closeStream(stream);
            reply->writeInt32(result);
            return NO_ERROR;
        } break;

        case GET_STREAM_DESCRIPTION: {
            data.readInt32(&stream);
            ALOGD("BnOboeAudioService::onTransact GET_STREAM_DESCRIPTION 0x%08X", stream);
            oboe::AudioEndpointParcelable parcelable;
            result = getStreamDescription(stream, parcelable);
            if (result != OBOE_OK) {
                return OboeConvert_oboeToAndroidStatus(result);
            }
            parcelable.dump();
            result = parcelable.validate();
            if (result != OBOE_OK) {
                return OboeConvert_oboeToAndroidStatus(result);
            }
            parcelable.writeToParcel(reply);
            reply->writeInt32(result);
            return NO_ERROR;
        } break;

        case START_STREAM: {
            data.readInt32(&stream);
            result = startStream(stream);
            ALOGD("BnOboeAudioService::onTransact START_STREAM 0x%08X, result = %d",
                    stream, result);
            reply->writeInt32(result);
            return NO_ERROR;
        } break;

        case PAUSE_STREAM: {
            data.readInt32(&stream);
            result = pauseStream(stream);
            ALOGD("BnOboeAudioService::onTransact PAUSE_STREAM 0x%08X, result = %d",
                    stream, result);
            reply->writeInt32(result);
            return NO_ERROR;
        } break;

        case FLUSH_STREAM: {
            data.readInt32(&stream);
            result = flushStream(stream);
            ALOGD("BnOboeAudioService::onTransact FLUSH_STREAM 0x%08X, result = %d",
                    stream, result);
            reply->writeInt32(result);
            return NO_ERROR;
        } break;

        case REGISTER_AUDIO_THREAD: {
            data.readInt32(&stream);
            data.readInt32(&pid);
            data.readInt64(&nanoseconds);
            result = registerAudioThread(stream, pid, nanoseconds);
            ALOGD("BnOboeAudioService::onTransact REGISTER_AUDIO_THREAD 0x%08X, result = %d",
                    stream, result);
            reply->writeInt32(result);
            return NO_ERROR;
        } break;

        case UNREGISTER_AUDIO_THREAD: {
            data.readInt32(&stream);
            data.readInt32(&pid);
            result = unregisterAudioThread(stream, pid);
            ALOGD("BnOboeAudioService::onTransact UNREGISTER_AUDIO_THREAD 0x%08X, result = %d",
                    stream, result);
            reply->writeInt32(result);
            return NO_ERROR;
        } break;

        default:
            // ALOGW("BnOboeAudioService::onTransact not handled %u", code);
            return BBinder::onTransact(code, data, reply, flags);
    }
}

} /* namespace android */
