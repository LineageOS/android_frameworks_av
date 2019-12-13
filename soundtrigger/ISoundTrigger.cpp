/*
**
** Copyright 2014, The Android Open Source Project
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

#define LOG_TAG "ISoundTrigger"
#include <utils/Log.h>
#include <utils/Errors.h>
#include <binder/IMemory.h>
#include <soundtrigger/ISoundTrigger.h>
#include <soundtrigger/ISoundTriggerHwService.h>
#include <soundtrigger/ISoundTriggerClient.h>
#include <system/sound_trigger.h>

namespace android {

enum {
    DETACH = IBinder::FIRST_CALL_TRANSACTION,
    LOAD_SOUND_MODEL,
    UNLOAD_SOUND_MODEL,
    START_RECOGNITION,
    STOP_RECOGNITION,
    GET_MODEL_STATE,
    SET_PARAMETER,
    GET_PARAMETER,
    QUERY_PARAMETER,
};

class BpSoundTrigger: public BpInterface<ISoundTrigger>
{
public:
    explicit BpSoundTrigger(const sp<IBinder>& impl)
        : BpInterface<ISoundTrigger>(impl)
    {
    }

    void detach()
    {
        ALOGV("detach");
        Parcel data, reply;
        data.writeInterfaceToken(ISoundTrigger::getInterfaceDescriptor());
        remote()->transact(DETACH, data, &reply);
    }

    status_t loadSoundModel(const sp<IMemory>&  modelMemory,
                                    sound_model_handle_t *handle)
    {
        if (modelMemory == 0 || handle == NULL) {
            return BAD_VALUE;
        }
        Parcel data, reply;
        data.writeInterfaceToken(ISoundTrigger::getInterfaceDescriptor());
        data.writeStrongBinder(IInterface::asBinder(modelMemory));
        status_t status = remote()->transact(LOAD_SOUND_MODEL, data, &reply);
        if (status != NO_ERROR) {
            return status;
        }
        status = (status_t)reply.readInt32();
        if (status == NO_ERROR) {
            reply.read(handle, sizeof(sound_model_handle_t));
        }
        return status;
    }

    virtual status_t unloadSoundModel(sound_model_handle_t handle)
    {
        Parcel data, reply;
        data.writeInterfaceToken(ISoundTrigger::getInterfaceDescriptor());
        data.write(&handle, sizeof(sound_model_handle_t));
        status_t status = remote()->transact(UNLOAD_SOUND_MODEL, data, &reply);
        if (status == NO_ERROR) {
            status = (status_t)reply.readInt32();
        }
        return status;
    }

    virtual status_t startRecognition(sound_model_handle_t handle,
                                      const sp<IMemory>& dataMemory)
    {
        Parcel data, reply;
        data.writeInterfaceToken(ISoundTrigger::getInterfaceDescriptor());
        data.write(&handle, sizeof(sound_model_handle_t));
        if (dataMemory == 0) {
            data.writeInt32(0);
        } else {
            data.writeInt32(dataMemory->size());
        }
        data.writeStrongBinder(IInterface::asBinder(dataMemory));
        status_t status = remote()->transact(START_RECOGNITION, data, &reply);
        if (status == NO_ERROR) {
            status = (status_t)reply.readInt32();
        }
        return status;
    }

    virtual status_t stopRecognition(sound_model_handle_t handle)
    {
        Parcel data, reply;
        data.writeInterfaceToken(ISoundTrigger::getInterfaceDescriptor());
        data.write(&handle, sizeof(sound_model_handle_t));
        status_t status = remote()->transact(STOP_RECOGNITION, data, &reply);
        if (status == NO_ERROR) {
            status = (status_t)reply.readInt32();
        }
        return status;
    }

    virtual status_t getModelState(sound_model_handle_t handle)
    {
        Parcel data, reply;
        data.writeInterfaceToken(ISoundTrigger::getInterfaceDescriptor());
        data.write(&handle, sizeof(sound_model_handle_t));
        status_t status = remote()->transact(GET_MODEL_STATE, data, &reply);
        if (status == NO_ERROR) {
            status = (status_t)reply.readInt32();
        }
        return status;
    }

    virtual status_t setParameter(sound_model_handle_t handle,
                                     sound_trigger_model_parameter_t param,
                                     int32_t value)
    {
        Parcel data, reply;
        data.writeInterfaceToken(ISoundTrigger::getInterfaceDescriptor());
        data.write(&handle, sizeof(sound_model_handle_t));
        data.write(&param, sizeof(sound_trigger_model_parameter_t));
        data.writeInt32(value);
        status_t status = remote()->transact(SET_PARAMETER, data, &reply);
        if (status == NO_ERROR) {
            status = (status_t)reply.readInt32();
        }
        return status;
    }

    virtual status_t getParameter(sound_model_handle_t handle,
                                     sound_trigger_model_parameter_t param,
                                     int32_t* value)
    {
        Parcel data, reply;
        data.writeInterfaceToken(ISoundTrigger::getInterfaceDescriptor());
        data.write(&handle, sizeof(sound_model_handle_t));
        data.write(&param, sizeof(sound_trigger_model_parameter_t));
        status_t status = remote()->transact(GET_PARAMETER, data, &reply);
        if (status == NO_ERROR) {
            status = (status_t)reply.readInt32();
            *value = reply.readInt32();
        }
        return status;
    }

    virtual status_t queryParameter(sound_model_handle_t handle,
            sound_trigger_model_parameter_t param,
            sound_trigger_model_parameter_range_t* param_range)
    {
        Parcel data, reply;
        data.writeInterfaceToken(ISoundTrigger::getInterfaceDescriptor());
        data.write(&handle, sizeof(sound_model_handle_t));
        data.write(&param, sizeof(sound_trigger_model_parameter_t));
        status_t status = remote()->transact(QUERY_PARAMETER, data, &reply);
        if (status == NO_ERROR) {
            status = (status_t)reply.readInt32();
            param_range->start = reply.readInt32();
            param_range->end = reply.readInt32();
        }
        return status;
    }

};

IMPLEMENT_META_INTERFACE(SoundTrigger, "android.hardware.ISoundTrigger");

// ----------------------------------------------------------------------

status_t BnSoundTrigger::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    switch(code) {
        case DETACH: {
            ALOGV("DETACH");
            CHECK_INTERFACE(ISoundTrigger, data, reply);
            detach();
            return NO_ERROR;
        } break;
        case LOAD_SOUND_MODEL: {
            CHECK_INTERFACE(ISoundTrigger, data, reply);
            sp<IMemory> modelMemory = interface_cast<IMemory>(
                data.readStrongBinder());
            sound_model_handle_t handle;
            status_t status = loadSoundModel(modelMemory, &handle);
            reply->writeInt32(status);
            if (status == NO_ERROR) {
                reply->write(&handle, sizeof(sound_model_handle_t));
            }
            return NO_ERROR;
        }
        case UNLOAD_SOUND_MODEL: {
            CHECK_INTERFACE(ISoundTrigger, data, reply);
            sound_model_handle_t handle;
            data.read(&handle, sizeof(sound_model_handle_t));
            status_t status = unloadSoundModel(handle);
            reply->writeInt32(status);
            return NO_ERROR;
        }
        case START_RECOGNITION: {
            CHECK_INTERFACE(ISoundTrigger, data, reply);
            sound_model_handle_t handle;
            data.read(&handle, sizeof(sound_model_handle_t));
            sp<IMemory> dataMemory;
            if (data.readInt32() != 0) {
                dataMemory = interface_cast<IMemory>(data.readStrongBinder());
            }
            status_t status = startRecognition(handle, dataMemory);
            reply->writeInt32(status);
            return NO_ERROR;
        }
        case STOP_RECOGNITION: {
            CHECK_INTERFACE(ISoundTrigger, data, reply);
            sound_model_handle_t handle;
            data.read(&handle, sizeof(sound_model_handle_t));
            status_t status = stopRecognition(handle);
            reply->writeInt32(status);
            return NO_ERROR;
        }
        case GET_MODEL_STATE: {
            CHECK_INTERFACE(ISoundTrigger, data, reply);
            sound_model_handle_t handle;
            status_t status = UNKNOWN_ERROR;
            status_t ret = data.read(&handle, sizeof(sound_model_handle_t));
            if (ret == NO_ERROR) {
                status = getModelState(handle);
            }
            reply->writeInt32(status);
            return ret;
        }
        case SET_PARAMETER: {
            CHECK_INTERFACE(ISoundTrigger, data, reply);
            sound_model_handle_t handle;
            sound_trigger_model_parameter_t param;
            int32_t value;
            status_t status = UNKNOWN_ERROR;
            status_t ret;
            ret = data.read(&handle, sizeof(sound_model_handle_t));
            if (ret != NO_ERROR) {
                return ret;
            }
            ret = data.read(&param, sizeof(sound_trigger_model_parameter_t));
            if (ret != NO_ERROR) {
                return ret;
            }
            ret = data.read(&value, sizeof(int32_t));
            if (ret != NO_ERROR) {
                return ret;
            }
            status = setParameter(handle, param, value);
            reply->writeInt32(status);
            return NO_ERROR;
        }
        case GET_PARAMETER: {
            CHECK_INTERFACE(ISoundTrigger, data, reply);
            sound_model_handle_t handle;
            sound_trigger_model_parameter_t param;
            int32_t value;
            status_t status = UNKNOWN_ERROR;
            status_t ret;
            ret = data.read(&handle, sizeof(sound_model_handle_t));
            if (ret != NO_ERROR) {
                return ret;
            }
            ret = data.read(&param, sizeof(sound_trigger_model_parameter_t));
            if (ret != NO_ERROR) {
                return ret;
            }
            status = getParameter(handle, param, &value);
            reply->writeInt32(status);
            reply->writeInt32(value);
            return NO_ERROR;
        }
        case QUERY_PARAMETER: {
            CHECK_INTERFACE(ISoundTrigger, data, reply);
            sound_model_handle_t handle;
            sound_trigger_model_parameter_t param;
            status_t ret;
            status_t status = UNKNOWN_ERROR;
            sound_trigger_model_parameter_range_t retValue;
            ret = data.read(&handle, sizeof(sound_model_handle_t));
            if (ret != NO_ERROR) {
                return ret;
            }
            ret = data.read(&param, sizeof(sound_trigger_model_parameter_t));
            if (ret != NO_ERROR) {
                return ret;
            }
            status = queryParameter(handle, param, &retValue);
            reply->writeInt32(status);
            reply->writeInt32(retValue.start);
            reply->writeInt32(retValue.end);
            return NO_ERROR;
        }
        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
}

// ----------------------------------------------------------------------------

}; // namespace android
