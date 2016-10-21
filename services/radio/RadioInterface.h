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

#ifndef ANDROID_HARDWARE_RADIO_INTERFACE_H
#define ANDROID_HARDWARE_RADIO_INTERFACE_H

#include <utils/RefBase.h>
#include <system/radio.h>
#include "TunerInterface.h"
#include "TunerCallbackInterface.h"

namespace android {

class RadioInterface : public virtual RefBase
{
public:
        /* get a sound trigger HAL instance */
        static sp<RadioInterface> connectModule(radio_class_t classId);

        /*
         * Retrieve implementation properties.
         *
         * arguments:
         * - properties: where to return the module properties
         *
         * returns:
         *  0 if no error
         *  -EINVAL if invalid arguments are passed
         */
        virtual int getProperties(radio_hal_properties_t *properties) = 0;

        /*
         * Open a tuner interface for the requested configuration.
         * If no other tuner is opened, this will activate the radio module.
         *
         * arguments:
         * - config: the band configuration to apply
         * - audio: this tuner will be used for live radio listening and should be connected to
         * the radio audio source.
         * - callback: the event callback
         * - cookie: the cookie to pass when calling the callback
         * - tuner: where to return the tuner interface
         *
         * returns:
         *  0 if HW was powered up and configuration could be applied
         *  -EINVAL if configuration requested is invalid
         *  -ENOSYS if called out of sequence
         *
         * Callback function with event RADIO_EVENT_CONFIG MUST be called once the
         * configuration is applied or a failure occurs or after a time out.
         */
        virtual int openTuner(const radio_hal_band_config_t *config,
                        bool audio,
                        sp<TunerCallbackInterface> callback,
                        sp<TunerInterface>& tuner) = 0;

        /*
         * Close a tuner interface.
         * If the last tuner is closed, the radio module is deactivated.
         *
         * arguments:
         * - tuner: the tuner interface to close
         *
         * returns:
         *  0 if powered down successfully.
         *  -EINVAL if an invalid argument is passed
         *  -ENOSYS if called out of sequence
         */
        virtual int closeTuner(sp<TunerInterface>& tuner) = 0;

protected:
        RadioInterface() {}
        virtual     ~RadioInterface() {}
};

} // namespace android

#endif // ANDROID_HARDWARE_RADIO_INTERFACE_H
