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

#ifndef ANDROID_HARDWARE_RADIO_HAL_HIDL_H
#define ANDROID_HARDWARE_RADIO_HAL_HIDL_H

#include <utils/RefBase.h>
#include <utils/threads.h>
#include "RadioInterface.h"
#include "TunerInterface.h"
#include "TunerCallbackInterface.h"
#include <android/hardware/broadcastradio/1.0/types.h>
#include <android/hardware/broadcastradio/1.0/IBroadcastRadio.h>
#include <android/hardware/broadcastradio/1.0/ITuner.h>
#include <android/hardware/broadcastradio/1.0/ITunerCallback.h>

namespace android {

using android::hardware::Return;
using android::hardware::broadcastradio::V1_0::Result;
using android::hardware::broadcastradio::V1_0::IBroadcastRadio;
using android::hardware::broadcastradio::V1_0::ITuner;
using android::hardware::broadcastradio::V1_0::ITunerCallback;

using android::hardware::broadcastradio::V1_0::BandConfig;
using android::hardware::broadcastradio::V1_0::ProgramInfo;
using android::hardware::broadcastradio::V1_0::MetaData;

class RadioHalHidl : public RadioInterface
{
public:
                    RadioHalHidl(radio_class_t classId);

                    // RadioInterface
        virtual int getProperties(radio_hal_properties_t *properties);
        virtual int openTuner(const radio_hal_band_config_t *config,
                              bool audio,
                              sp<TunerCallbackInterface> callback,
                              sp<TunerInterface>& tuner);
        virtual int closeTuner(sp<TunerInterface>& tuner);

        class Tuner  : public TunerInterface, public virtual ITunerCallback
        {
        public:
                        Tuner(sp<TunerCallbackInterface> callback, sp<RadioHalHidl> module);

                        // TunerInterface
            virtual int setConfiguration(const radio_hal_band_config_t *config);
            virtual int getConfiguration(radio_hal_band_config_t *config);
            virtual int scan(radio_direction_t direction, bool skip_sub_channel);
            virtual int step(radio_direction_t direction, bool skip_sub_channel);
            virtual int tune(unsigned int channel, unsigned int sub_channel);
            virtual int cancel();
            virtual int getProgramInformation(radio_program_info_t *info);

                        // ITunerCallback
            virtual Return<void> hardwareFailure();
            virtual Return<void> configChange(Result result, const BandConfig& config);
            virtual Return<void> tuneComplete(Result result, const ProgramInfo& info);
            virtual Return<void> afSwitch(const ProgramInfo& info);
            virtual Return<void> antennaStateChange(bool connected);
            virtual Return<void> trafficAnnouncement(bool active);
            virtual Return<void> emergencyAnnouncement(bool active);
            virtual Return<void> newMetadata(uint32_t channel, uint32_t subChannel,
                                         const ::android::hardware::hidl_vec<MetaData>& metadata);

            void setHalTuner(sp<ITuner>& halTuner);
            sp<ITuner> getHalTuner() { return mHalTuner; }

        private:
            virtual          ~Tuner();

                    void     onCallback(radio_hal_event_t *halEvent) const;
                    void     handleHwFailure();
                    void     sendHwFailureEvent() const;

            sp<ITuner> mHalTuner;
            const sp<TunerCallbackInterface> mCallback;
            wp<RadioHalHidl> mParentModule;
        };

        sp<IBroadcastRadio> getService();
        void clearService();

private:
        virtual         ~RadioHalHidl();

                radio_class_t mClassId;
                sp<IBroadcastRadio> mHalModule;
};

} // namespace android

#endif // ANDROID_HARDWARE_RADIO_HAL_HIDL_H
