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

#define LOG_TAG "RadioHalHidl"
//#define LOG_NDEBUG 0

#include <utils/Log.h>
#include <utils/misc.h>
#include <system/radio_metadata.h>
#include <android/hardware/broadcastradio/1.0/IBroadcastRadioFactory.h>

#include "RadioHalHidl.h"
#include "HidlUtils.h"

namespace android {

using android::hardware::broadcastradio::V1_0::IBroadcastRadioFactory;
using android::hardware::broadcastradio::V1_0::Class;
using android::hardware::broadcastradio::V1_0::Direction;
using android::hardware::broadcastradio::V1_0::Properties;


/* static */
sp<RadioInterface> RadioInterface::connectModule(radio_class_t classId)
{
    return new RadioHalHidl(classId);
}

int RadioHalHidl::getProperties(radio_hal_properties_t *properties)
{
    ALOGV("%s IN", __FUNCTION__);
    sp<IBroadcastRadio> module = getService();
    if (module == 0) {
        return -ENODEV;
    }
    Properties halProperties;
    Result halResult;
    Return<void> hidlReturn =
            module->getProperties([&](Result result, const Properties& properties) {
                    halResult = result;
                    if (result == Result::OK) {
                        halProperties = properties;
                    }
                });

    if (hidlReturn.getStatus().transactionError() == DEAD_OBJECT) {
        clearService();
        return -EPIPE;
    }
    if (halResult == Result::OK) {
        HidlUtils::convertPropertiesFromHal(properties, &halProperties);
    }
    return HidlUtils::convertHalResult(halResult);
}

int RadioHalHidl::openTuner(const radio_hal_band_config_t *config,
                            bool audio,
                            sp<TunerCallbackInterface> callback,
                            sp<TunerInterface>& tuner)
{
    sp<IBroadcastRadio> module = getService();
    if (module == 0) {
        return -ENODEV;
    }
    sp<Tuner> tunerImpl = new Tuner(callback, this);

    BandConfig halConfig;
    Result halResult;
    sp<ITuner> halTuner;

    HidlUtils::convertBandConfigToHal(&halConfig, config);
    Return<void> hidlReturn =
            module->openTuner(halConfig, audio, tunerImpl,
                              [&](Result result, const sp<ITuner>& tuner) {
                    halResult = result;
                    if (result == Result::OK) {
                        halTuner = tuner;
                    }
                });

    if (hidlReturn.getStatus().transactionError() == DEAD_OBJECT) {
        clearService();
        return -EPIPE;
    }
    if (halResult == Result::OK) {
        tunerImpl->setHalTuner(halTuner);
        tuner = tunerImpl;
    }

    return HidlUtils::convertHalResult(halResult);
}

int RadioHalHidl::closeTuner(sp<TunerInterface>& tuner)
{
    sp<Tuner> tunerImpl = static_cast<Tuner *>(tuner.get());
    sp<ITuner> clearTuner;
    tunerImpl->setHalTuner(clearTuner);
    return 0;
}

RadioHalHidl::RadioHalHidl(radio_class_t classId)
    : mClassId(classId)
{
}

RadioHalHidl::~RadioHalHidl()
{
}

sp<IBroadcastRadio> RadioHalHidl::getService()
{
    if (mHalModule == 0) {
        sp<IBroadcastRadioFactory> factory = IBroadcastRadioFactory::getService("broadcastradio");
        if (factory != 0) {
            factory->connectModule(static_cast<Class>(mClassId),
                               [&](Result retval, const ::android::sp<IBroadcastRadio>& result) {
                if (retval == Result::OK) {
                    mHalModule = result;
                }
            });
        }
    }
    ALOGV("%s OUT module %p", __FUNCTION__, mHalModule.get());
    return mHalModule;
}

void RadioHalHidl::clearService()
{
    ALOGV("%s IN module %p", __FUNCTION__, mHalModule.get());
    mHalModule.clear();
}


int RadioHalHidl::Tuner::setConfiguration(const radio_hal_band_config_t *config)
{
    ALOGV("%s IN mHalTuner %p", __FUNCTION__, mHalTuner.get());

    if (mHalTuner == 0) {
        return -ENODEV;
    }
    BandConfig halConfig;
    HidlUtils::convertBandConfigToHal(&halConfig, config);

    Return<Result> hidlResult = mHalTuner->setConfiguration(halConfig);
    checkHidlStatus(hidlResult.getStatus());
    return HidlUtils::convertHalResult(hidlResult);
}

int RadioHalHidl::Tuner::getConfiguration(radio_hal_band_config_t *config)
{
    ALOGV("%s IN mHalTuner %p", __FUNCTION__, mHalTuner.get());
    if (mHalTuner == 0) {
        return -ENODEV;
    }
    BandConfig halConfig;
    Result halResult;
    Return<void> hidlReturn =
            mHalTuner->getConfiguration([&](Result result, const BandConfig& config) {
                    halResult = result;
                    if (result == Result::OK) {
                        halConfig = config;
                    }
                });
    status_t status = checkHidlStatus(hidlReturn.getStatus());
    if (status == NO_ERROR && halResult == Result::OK) {
        HidlUtils::convertBandConfigFromHal(config, &halConfig);
    }
    return HidlUtils::convertHalResult(halResult);
}

int RadioHalHidl::Tuner::scan(radio_direction_t direction, bool skip_sub_channel)
{
    ALOGV("%s IN mHalTuner %p", __FUNCTION__, mHalTuner.get());
    if (mHalTuner == 0) {
        return -ENODEV;
    }
    Return<Result> hidlResult =
            mHalTuner->scan(static_cast<Direction>(direction), skip_sub_channel);
    checkHidlStatus(hidlResult.getStatus());
    return HidlUtils::convertHalResult(hidlResult);
}

int RadioHalHidl::Tuner::step(radio_direction_t direction, bool skip_sub_channel)
{
    ALOGV("%s IN mHalTuner %p", __FUNCTION__, mHalTuner.get());
    if (mHalTuner == 0) {
        return -ENODEV;
    }
    Return<Result> hidlResult =
            mHalTuner->step(static_cast<Direction>(direction), skip_sub_channel);
    checkHidlStatus(hidlResult.getStatus());
    return HidlUtils::convertHalResult(hidlResult);
}

int RadioHalHidl::Tuner::tune(unsigned int channel, unsigned int sub_channel)
{
    ALOGV("%s IN mHalTuner %p", __FUNCTION__, mHalTuner.get());
    if (mHalTuner == 0) {
        return -ENODEV;
    }
    Return<Result> hidlResult =
            mHalTuner->tune(channel, sub_channel);
    checkHidlStatus(hidlResult.getStatus());
    return HidlUtils::convertHalResult(hidlResult);
}

int RadioHalHidl::Tuner::cancel()
{
    ALOGV("%s IN mHalTuner %p", __FUNCTION__, mHalTuner.get());
    if (mHalTuner == 0) {
        return -ENODEV;
    }
    Return<Result> hidlResult = mHalTuner->cancel();
    checkHidlStatus(hidlResult.getStatus());
    return HidlUtils::convertHalResult(hidlResult);
}

int RadioHalHidl::Tuner::getProgramInformation(radio_program_info_t *info)
{
    ALOGV("%s IN mHalTuner %p", __FUNCTION__, mHalTuner.get());
    if (mHalTuner == 0) {
        return -ENODEV;
    }
    ProgramInfo halInfo;
    Result halResult;
    bool withMetaData = (info->metadata != NULL);
    Return<void> hidlReturn = mHalTuner->getProgramInformation(
                    withMetaData, [&](Result result, const ProgramInfo& info) {
                        halResult = result;
                        if (result == Result::OK) {
                            halInfo = info;
                        }
    });
    status_t status = checkHidlStatus(hidlReturn.getStatus());
    if (status == NO_ERROR && halResult == Result::OK) {
        HidlUtils::convertProgramInfoFromHal(info, &halInfo, withMetaData);
    }
    return HidlUtils::convertHalResult(halResult);
}

Return<void> RadioHalHidl::Tuner::hardwareFailure()
{
    ALOGV("%s IN", __FUNCTION__);
    handleHwFailure();
    return Return<void>();
}

Return<void> RadioHalHidl::Tuner::configChange(Result result, const BandConfig& config)
{
    ALOGV("%s IN", __FUNCTION__);
    radio_hal_event_t event;
    memset(&event, 0, sizeof(radio_hal_event_t));
    event.type = RADIO_EVENT_CONFIG;
    event.status = HidlUtils::convertHalResult(result);
    HidlUtils::convertBandConfigFromHal(&event.config, &config);
    onCallback(&event);
    return Return<void>();
}

Return<void> RadioHalHidl::Tuner::tuneComplete(Result result, const ProgramInfo& info)
{
    ALOGV("%s IN", __FUNCTION__);
    radio_hal_event_t event;
    memset(&event, 0, sizeof(radio_hal_event_t));
    event.type = RADIO_EVENT_TUNED;
    event.status = HidlUtils::convertHalResult(result);
    HidlUtils::convertProgramInfoFromHal(&event.info, &info, true);
    onCallback(&event);
    if (event.info.metadata != NULL) {
        radio_metadata_deallocate(event.info.metadata);
    }
    return Return<void>();
}

Return<void> RadioHalHidl::Tuner::afSwitch(const ProgramInfo& info)
{
    ALOGV("%s IN", __FUNCTION__);
    radio_hal_event_t event;
    memset(&event, 0, sizeof(radio_hal_event_t));
    event.type = RADIO_EVENT_AF_SWITCH;
    HidlUtils::convertProgramInfoFromHal(&event.info, &info, true);
    onCallback(&event);
    if (event.info.metadata != NULL) {
        radio_metadata_deallocate(event.info.metadata);
    }
    return Return<void>();
}

Return<void> RadioHalHidl::Tuner::antennaStateChange(bool connected)
{
    ALOGV("%s IN", __FUNCTION__);
    radio_hal_event_t event;
    memset(&event, 0, sizeof(radio_hal_event_t));
    event.type = RADIO_EVENT_ANTENNA;
    event.on = connected;
    onCallback(&event);
    return Return<void>();
}
Return<void> RadioHalHidl::Tuner::trafficAnnouncement(bool active)
{
    ALOGV("%s IN", __FUNCTION__);
    radio_hal_event_t event;
    memset(&event, 0, sizeof(radio_hal_event_t));
    event.type = RADIO_EVENT_TA;
    event.on = active;
    onCallback(&event);
    return Return<void>();
}
Return<void> RadioHalHidl::Tuner::emergencyAnnouncement(bool active)
{
    ALOGV("%s IN", __FUNCTION__);
    radio_hal_event_t event;
    memset(&event, 0, sizeof(radio_hal_event_t));
    event.type = RADIO_EVENT_EA;
    event.on = active;
    onCallback(&event);
    return Return<void>();
}
Return<void> RadioHalHidl::Tuner::newMetadata(uint32_t channel, uint32_t subChannel,
                                          const ::android::hardware::hidl_vec<MetaData>& metadata)
{
    ALOGV("%s IN", __FUNCTION__);
    radio_hal_event_t event;
    memset(&event, 0, sizeof(radio_hal_event_t));
    event.type = RADIO_EVENT_METADATA;
    HidlUtils::convertMetaDataFromHal(&event.metadata, metadata, channel, subChannel);
    onCallback(&event);
    if (event.metadata != NULL) {
        radio_metadata_deallocate(event.info.metadata);
    }
    return Return<void>();
}


RadioHalHidl::Tuner::Tuner(sp<TunerCallbackInterface> callback, sp<RadioHalHidl> module)
    : TunerInterface(), mHalTuner(NULL), mCallback(callback), mParentModule(module)
{
}


RadioHalHidl::Tuner::~Tuner()
{
}

void RadioHalHidl::Tuner::handleHwFailure()
{
    ALOGV("%s IN", __FUNCTION__);
    sp<RadioHalHidl> parentModule = mParentModule.promote();
    if (parentModule != 0) {
        parentModule->clearService();
    }
    radio_hal_event_t event;
    memset(&event, 0, sizeof(radio_hal_event_t));
    event.type = RADIO_EVENT_HW_FAILURE;
    onCallback(&event);
    mHalTuner.clear();
}

status_t RadioHalHidl::Tuner::checkHidlStatus(Status hidlStatus)
{
    status_t status = hidlStatus.transactionError();
    if (status == DEAD_OBJECT) {
        handleHwFailure();
    }
    return status;
}

void RadioHalHidl::Tuner::onCallback(radio_hal_event_t *halEvent)
{
    if (mCallback != 0) {
        mCallback->onEvent(halEvent);
    }
}

} // namespace android
