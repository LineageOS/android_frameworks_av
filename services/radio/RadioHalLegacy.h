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

#ifndef ANDROID_HARDWARE_RADIO_HAL_LEGACY_H
#define ANDROID_HARDWARE_RADIO_HAL_LEGACY_H

#include <utils/RefBase.h>
#include <hardware/radio.h>
#include "RadioInterface.h"
#include "TunerInterface.h"
#include "TunerCallbackInterface.h"

namespace android {

class RadioHalLegacy : public RadioInterface
{
public:
        RadioHalLegacy(radio_class_t classId);

        // RadioInterface
        virtual int getProperties(radio_hal_properties_t *properties);
        virtual int openTuner(const radio_hal_band_config_t *config,
                        bool audio,
                        sp<TunerCallbackInterface> callback,
                        sp<TunerInterface>& tuner);
        virtual int closeTuner(sp<TunerInterface>& tuner);

        // RefBase
        virtual void onFirstRef();

        class Tuner  : public TunerInterface
        {
        public:
                        Tuner(sp<TunerCallbackInterface> callback);

            virtual int setConfiguration(const radio_hal_band_config_t *config);
            virtual int getConfiguration(radio_hal_band_config_t *config);
            virtual int scan(radio_direction_t direction, bool skip_sub_channel);
            virtual int step(radio_direction_t direction, bool skip_sub_channel);
            virtual int tune(unsigned int channel, unsigned int sub_channel);
            virtual int cancel();
            virtual int getProgramInformation(radio_program_info_t *info);

            static void callback(radio_hal_event_t *halEvent, void *cookie);
                   void onCallback(radio_hal_event_t *halEvent);

            void setHalTuner(const struct radio_tuner *halTuner) { mHalTuner = halTuner; }
            const struct radio_tuner *getHalTuner() { return mHalTuner; }

        private:
            virtual      ~Tuner();

            const struct radio_tuner    *mHalTuner;
            sp<TunerCallbackInterface>  mCallback;
        };

protected:
        virtual     ~RadioHalLegacy();

private:
        static const char * sClassModuleNames[];

        radio_class_t mClassId;
        struct radio_hw_device  *mHwDevice;
};

} // namespace android

#endif // ANDROID_HARDWARE_RADIO_HAL_LEGACY_H
