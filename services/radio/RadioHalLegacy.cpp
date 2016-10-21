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

#define LOG_TAG "RadioHalLegacy"
//#define LOG_NDEBUG 0

#include <utils/Log.h>
#include <utils/misc.h>
#include "RadioHalLegacy.h"

namespace android {

const char *RadioHalLegacy::sClassModuleNames[] = {
    RADIO_HARDWARE_MODULE_ID_FM, /* corresponds to RADIO_CLASS_AM_FM */
    RADIO_HARDWARE_MODULE_ID_SAT,  /* corresponds to RADIO_CLASS_SAT */
    RADIO_HARDWARE_MODULE_ID_DT,   /* corresponds to RADIO_CLASS_DT */
};

/* static */
sp<RadioInterface> RadioInterface::connectModule(radio_class_t classId)
{
    return new RadioHalLegacy(classId);
}

RadioHalLegacy::RadioHalLegacy(radio_class_t classId)
    : RadioInterface(), mClassId(classId), mHwDevice(NULL)
{
}

void RadioHalLegacy::onFirstRef()
{
    const hw_module_t *mod;
    int rc;
    ALOGI("%s mClassId %d", __FUNCTION__, mClassId);

    mHwDevice = NULL;

    if ((mClassId < 0) ||
            (mClassId >= NELEM(sClassModuleNames))) {
        ALOGE("invalid class ID %d", mClassId);
        return;
    }

    ALOGI("%s RADIO_HARDWARE_MODULE_ID %s %s",
          __FUNCTION__, RADIO_HARDWARE_MODULE_ID, sClassModuleNames[mClassId]);

    rc = hw_get_module_by_class(RADIO_HARDWARE_MODULE_ID, sClassModuleNames[mClassId], &mod);
    if (rc != 0) {
        ALOGE("couldn't load radio module %s.%s (%s)",
              RADIO_HARDWARE_MODULE_ID, sClassModuleNames[mClassId], strerror(-rc));
        return;
    }
    rc = radio_hw_device_open(mod, &mHwDevice);
    if (rc != 0) {
        ALOGE("couldn't open radio hw device in %s.%s (%s)",
              RADIO_HARDWARE_MODULE_ID, "primary", strerror(-rc));
        mHwDevice = NULL;
        return;
    }
    if (mHwDevice->common.version != RADIO_DEVICE_API_VERSION_CURRENT) {
        ALOGE("wrong radio hw device version %04x", mHwDevice->common.version);
        radio_hw_device_close(mHwDevice);
        mHwDevice = NULL;
    }
}

RadioHalLegacy::~RadioHalLegacy()
{
    if (mHwDevice != NULL) {
        radio_hw_device_close(mHwDevice);
    }
}

int RadioHalLegacy::getProperties(radio_hal_properties_t *properties)
{
    if (mHwDevice == NULL) {
        return -ENODEV;
    }

    int rc = mHwDevice->get_properties(mHwDevice, properties);
    if (rc != 0) {
        ALOGE("could not read implementation properties");
    }

    return rc;
}

int RadioHalLegacy::openTuner(const radio_hal_band_config_t *config,
                bool audio,
                sp<TunerCallbackInterface> callback,
                sp<TunerInterface>& tuner)
{
    if (mHwDevice == NULL) {
        return -ENODEV;
    }
    sp<Tuner> tunerImpl = new Tuner(callback);

    const struct radio_tuner *halTuner;
    int rc = mHwDevice->open_tuner(mHwDevice, config, audio,
                                   RadioHalLegacy::Tuner::callback, tunerImpl.get(),
                                   &halTuner);
    if (rc == 0) {
        tunerImpl->setHalTuner(halTuner);
        tuner = tunerImpl;
    }
    return rc;
}

int RadioHalLegacy::closeTuner(sp<TunerInterface>& tuner)
{
    if (mHwDevice == NULL) {
        return -ENODEV;
    }
    if (tuner == 0) {
        return -EINVAL;
    }
    sp<Tuner> tunerImpl = (Tuner *)tuner.get();
    return mHwDevice->close_tuner(mHwDevice, tunerImpl->getHalTuner());
}

int RadioHalLegacy::Tuner::setConfiguration(const radio_hal_band_config_t *config)
{
    if (mHalTuner == NULL) {
        return -ENODEV;
    }
    return mHalTuner->set_configuration(mHalTuner, config);
}

int RadioHalLegacy::Tuner::getConfiguration(radio_hal_band_config_t *config)
{
    if (mHalTuner == NULL) {
        return -ENODEV;
    }
    return mHalTuner->get_configuration(mHalTuner, config);
}

int RadioHalLegacy::Tuner::scan(radio_direction_t direction, bool skip_sub_channel)
{
    if (mHalTuner == NULL) {
        return -ENODEV;
    }
    return mHalTuner->scan(mHalTuner, direction, skip_sub_channel);
}

int RadioHalLegacy::Tuner::step(radio_direction_t direction, bool skip_sub_channel)
{
    if (mHalTuner == NULL) {
        return -ENODEV;
    }
    return mHalTuner->step(mHalTuner, direction, skip_sub_channel);
}

int RadioHalLegacy::Tuner::tune(unsigned int channel, unsigned int sub_channel)
{
    if (mHalTuner == NULL) {
        return -ENODEV;
    }
    return mHalTuner->tune(mHalTuner, channel, sub_channel);
}

int RadioHalLegacy::Tuner::cancel()
{
    if (mHalTuner == NULL) {
        return -ENODEV;
    }
    return mHalTuner->cancel(mHalTuner);
}

int RadioHalLegacy::Tuner::getProgramInformation(radio_program_info_t *info)
{
    if (mHalTuner == NULL) {
        return -ENODEV;
    }
    return mHalTuner->get_program_information(mHalTuner, info);
}

void RadioHalLegacy::Tuner::onCallback(radio_hal_event_t *halEvent)
{
    if (mCallback != 0) {
        mCallback->onEvent(halEvent);
    }
}

//static
void RadioHalLegacy::Tuner::callback(radio_hal_event_t *halEvent, void *cookie)
{
    wp<RadioHalLegacy::Tuner> weak = wp<RadioHalLegacy::Tuner>((RadioHalLegacy::Tuner *)cookie);
    sp<RadioHalLegacy::Tuner> tuner = weak.promote();
    if (tuner != 0) {
        tuner->onCallback(halEvent);
    }
}

RadioHalLegacy::Tuner::Tuner(sp<TunerCallbackInterface> callback)
    : TunerInterface(), mHalTuner(NULL), mCallback(callback)
{
}


RadioHalLegacy::Tuner::~Tuner()
{
}


} // namespace android
