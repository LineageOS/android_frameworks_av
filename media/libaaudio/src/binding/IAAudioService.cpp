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

#include <aaudio/AAudioDefinitions.h>

#include "binding/AudioEndpointParcelable.h"
#include "binding/AAudioStreamRequest.h"
#include "binding/AAudioServiceDefinitions.h"
#include "binding/AAudioStreamConfiguration.h"
#include "binding/IAAudioService.h"
#include "utility/AAudioUtilities.h"

namespace android {

using aaudio::aaudio_handle_t;

/**
 * This is used by the AAudio Client to talk to the AAudio Service.
 *
 * The order of parameters in the Parcels must match with code in AAudioService.cpp.
 */
class BpAAudioService : public BpInterface<IAAudioService>
{
public:
    explicit BpAAudioService(const sp<IBinder>& impl)
        : BpInterface<IAAudioService>(impl)
    {
    }

    virtual aaudio_handle_t openStream(aaudio::AAudioStreamRequest &request,
                                     aaudio::AAudioStreamConfiguration &configuration) override {
        Parcel data, reply;
        // send command
        data.writeInterfaceToken(IAAudioService::getInterfaceDescriptor());
        request.writeToParcel(&data);
        status_t err = remote()->transact(OPEN_STREAM, data, &reply);
        if (err != NO_ERROR) {
            return AAudioConvert_androidToAAudioResult(err);
        }
        // parse reply
        aaudio_handle_t stream;
        reply.readInt32(&stream);
        configuration.readFromParcel(&reply);
        return stream;
    }

    virtual aaudio_result_t closeStream(aaudio_handle_t streamHandle) override {
        Parcel data, reply;
        // send command
        data.writeInterfaceToken(IAAudioService::getInterfaceDescriptor());
        data.writeInt32(streamHandle);
        status_t err = remote()->transact(CLOSE_STREAM, data, &reply);
        if (err != NO_ERROR) {
            return AAudioConvert_androidToAAudioResult(err);
        }
        // parse reply
        aaudio_result_t res;
        reply.readInt32(&res);
        return res;
    }

    virtual aaudio_result_t getStreamDescription(aaudio_handle_t streamHandle,
                                               aaudio::AudioEndpointParcelable &parcelable)   {
        Parcel data, reply;
        // send command
        data.writeInterfaceToken(IAAudioService::getInterfaceDescriptor());
        data.writeInt32(streamHandle);
        status_t err = remote()->transact(GET_STREAM_DESCRIPTION, data, &reply);
        if (err != NO_ERROR) {
            return AAudioConvert_androidToAAudioResult(err);
        }
        // parse reply
        parcelable.readFromParcel(&reply);
        parcelable.dump();
        aaudio_result_t result = parcelable.validate();
        if (result != AAUDIO_OK) {
            return result;
        }
        reply.readInt32(&result);
        return result;
    }

    // TODO should we wait for a reply?
    virtual aaudio_result_t startStream(aaudio_handle_t streamHandle) override {
        Parcel data, reply;
        // send command
        data.writeInterfaceToken(IAAudioService::getInterfaceDescriptor());
        data.writeInt32(streamHandle);
        status_t err = remote()->transact(START_STREAM, data, &reply);
        if (err != NO_ERROR) {
            return AAudioConvert_androidToAAudioResult(err);
        }
        // parse reply
        aaudio_result_t res;
        reply.readInt32(&res);
        return res;
    }

    virtual aaudio_result_t pauseStream(aaudio_handle_t streamHandle) override {
        Parcel data, reply;
        // send command
        data.writeInterfaceToken(IAAudioService::getInterfaceDescriptor());
        data.writeInt32(streamHandle);
        status_t err = remote()->transact(PAUSE_STREAM, data, &reply);
        if (err != NO_ERROR) {
            return AAudioConvert_androidToAAudioResult(err);
        }
        // parse reply
        aaudio_result_t res;
        reply.readInt32(&res);
        return res;
    }

    virtual aaudio_result_t flushStream(aaudio_handle_t streamHandle) override {
        Parcel data, reply;
        // send command
        data.writeInterfaceToken(IAAudioService::getInterfaceDescriptor());
        data.writeInt32(streamHandle);
        status_t err = remote()->transact(FLUSH_STREAM, data, &reply);
        if (err != NO_ERROR) {
            return AAudioConvert_androidToAAudioResult(err);
        }
        // parse reply
        aaudio_result_t res;
        reply.readInt32(&res);
        return res;
    }

    virtual aaudio_result_t registerAudioThread(aaudio_handle_t streamHandle, pid_t clientThreadId,
                                              int64_t periodNanoseconds)
    override {
        Parcel data, reply;
        // send command
        data.writeInterfaceToken(IAAudioService::getInterfaceDescriptor());
        data.writeInt32(streamHandle);
        data.writeInt32((int32_t) clientThreadId);
        data.writeInt64(periodNanoseconds);
        status_t err = remote()->transact(REGISTER_AUDIO_THREAD, data, &reply);
        if (err != NO_ERROR) {
            return AAudioConvert_androidToAAudioResult(err);
        }
        // parse reply
        aaudio_result_t res;
        reply.readInt32(&res);
        return res;
    }

    virtual aaudio_result_t unregisterAudioThread(aaudio_handle_t streamHandle, pid_t clientThreadId)
    override {
        Parcel data, reply;
        // send command
        data.writeInterfaceToken(IAAudioService::getInterfaceDescriptor());
        data.writeInt32(streamHandle);
        data.writeInt32((int32_t) clientThreadId);
        status_t err = remote()->transact(UNREGISTER_AUDIO_THREAD, data, &reply);
        if (err != NO_ERROR) {
            return AAudioConvert_androidToAAudioResult(err);
        }
        // parse reply
        aaudio_result_t res;
        reply.readInt32(&res);
        return res;
    }

};

// Implement an interface to the service.
// This is here so that you don't have to link with liboboe static library.
IMPLEMENT_META_INTERFACE(AAudioService, "IAAudioService");

// The order of parameters in the Parcels must match with code in BpAAudioService

status_t BnAAudioService::onTransact(uint32_t code, const Parcel& data,
                                        Parcel* reply, uint32_t flags) {
    aaudio_handle_t stream;
    aaudio::AAudioStreamRequest request;
    aaudio::AAudioStreamConfiguration configuration;
    pid_t pid;
    int64_t nanoseconds;
    aaudio_result_t result;
    ALOGV("BnAAudioService::onTransact(%i) %i", code, flags);
    data.checkInterface(this);

    switch(code) {
        case OPEN_STREAM: {
            request.readFromParcel(&data);
            stream = openStream(request, configuration);
            ALOGD("BnAAudioService::onTransact OPEN_STREAM server handle = 0x%08X", stream);
            reply->writeInt32(stream);
            configuration.writeToParcel(reply);
            return NO_ERROR;
        } break;

        case CLOSE_STREAM: {
            data.readInt32(&stream);
            ALOGD("BnAAudioService::onTransact CLOSE_STREAM 0x%08X", stream);
            result = closeStream(stream);
            reply->writeInt32(result);
            return NO_ERROR;
        } break;

        case GET_STREAM_DESCRIPTION: {
            data.readInt32(&stream);
            ALOGD("BnAAudioService::onTransact GET_STREAM_DESCRIPTION 0x%08X", stream);
            aaudio::AudioEndpointParcelable parcelable;
            result = getStreamDescription(stream, parcelable);
            if (result != AAUDIO_OK) {
                return AAudioConvert_aaudioToAndroidStatus(result);
            }
            parcelable.dump();
            result = parcelable.validate();
            if (result != AAUDIO_OK) {
                return AAudioConvert_aaudioToAndroidStatus(result);
            }
            parcelable.writeToParcel(reply);
            reply->writeInt32(result);
            return NO_ERROR;
        } break;

        case START_STREAM: {
            data.readInt32(&stream);
            result = startStream(stream);
            ALOGD("BnAAudioService::onTransact START_STREAM 0x%08X, result = %d",
                    stream, result);
            reply->writeInt32(result);
            return NO_ERROR;
        } break;

        case PAUSE_STREAM: {
            data.readInt32(&stream);
            result = pauseStream(stream);
            ALOGD("BnAAudioService::onTransact PAUSE_STREAM 0x%08X, result = %d",
                    stream, result);
            reply->writeInt32(result);
            return NO_ERROR;
        } break;

        case FLUSH_STREAM: {
            data.readInt32(&stream);
            result = flushStream(stream);
            ALOGD("BnAAudioService::onTransact FLUSH_STREAM 0x%08X, result = %d",
                    stream, result);
            reply->writeInt32(result);
            return NO_ERROR;
        } break;

        case REGISTER_AUDIO_THREAD: {
            data.readInt32(&stream);
            data.readInt32(&pid);
            data.readInt64(&nanoseconds);
            result = registerAudioThread(stream, pid, nanoseconds);
            ALOGD("BnAAudioService::onTransact REGISTER_AUDIO_THREAD 0x%08X, result = %d",
                    stream, result);
            reply->writeInt32(result);
            return NO_ERROR;
        } break;

        case UNREGISTER_AUDIO_THREAD: {
            data.readInt32(&stream);
            data.readInt32(&pid);
            result = unregisterAudioThread(stream, pid);
            ALOGD("BnAAudioService::onTransact UNREGISTER_AUDIO_THREAD 0x%08X, result = %d",
                    stream, result);
            reply->writeInt32(result);
            return NO_ERROR;
        } break;

        default:
            // ALOGW("BnAAudioService::onTransact not handled %u", code);
            return BBinder::onTransact(code, data, reply, flags);
    }
}

} /* namespace android */
