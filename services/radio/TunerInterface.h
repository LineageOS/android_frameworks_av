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

#ifndef ANDROID_HARDWARE_TUNER_INTERFACE_H
#define ANDROID_HARDWARE_TUNER_INTERFACE_H

#include <utils/RefBase.h>
#include <system/radio.h>

namespace android {

class TunerInterface : public virtual RefBase
{
public:
        /*
         * Apply current radio band configuration (band, range, channel spacing ...).
         *
         * arguments:
         * - config: the band configuration to apply
         *
         * returns:
         *  0 if configuration could be applied
         *  -EINVAL if configuration requested is invalid
         *
         * Automatically cancels pending scan, step or tune.
         *
         * Callback function with event RADIO_EVENT_CONFIG MUST be called once the
         * configuration is applied or a failure occurs or after a time out.
         */
    virtual int setConfiguration(const radio_hal_band_config_t *config) = 0;

        /*
         * Retrieve current radio band configuration.
         *
         * arguments:
         * - config: where to return the band configuration
         *
         * returns:
         *  0 if valid configuration is returned
         *  -EINVAL if invalid arguments are passed
         */
    virtual int getConfiguration(radio_hal_band_config_t *config) = 0;

        /*
         * Start scanning up to next valid station.
         * Must be called when a valid configuration has been applied.
         *
         * arguments:
         * - direction: RADIO_DIRECTION_UP or RADIO_DIRECTION_DOWN
         * - skip_sub_channel: valid for HD radio or digital radios only: ignore sub channels
         *  (e.g SPS for HD radio).
         *
         * returns:
         *  0 if scan successfully started
         *  -ENOSYS if called out of sequence
         *  -ENODEV if another error occurs
         *
         * Automatically cancels pending scan, step or tune.
         *
         *  Callback function with event RADIO_EVENT_TUNED MUST be called once
         *  locked on a station or after a time out or full frequency scan if
         *  no station found. The event status should indicate if a valid station
         *  is tuned or not.
         */
    virtual int scan(radio_direction_t direction, bool skip_sub_channel) = 0;

        /*
         * Move one channel spacing up or down.
         * Must be called when a valid configuration has been applied.
         *
         * arguments:
         * - direction: RADIO_DIRECTION_UP or RADIO_DIRECTION_DOWN
         * - skip_sub_channel: valid for HD radio or digital radios only: ignore sub channels
         *  (e.g SPS for HD radio).
         *
         * returns:
         *  0 if step successfully started
         *  -ENOSYS if called out of sequence
         *  -ENODEV if another error occurs
         *
         * Automatically cancels pending scan, step or tune.
         *
         * Callback function with event RADIO_EVENT_TUNED MUST be called once
         * step completed or after a time out. The event status should indicate
         * if a valid station is tuned or not.
         */
    virtual int step(radio_direction_t direction, bool skip_sub_channel) = 0;

        /*
         * Tune to specified frequency.
         * Must be called when a valid configuration has been applied.
         *
         * arguments:
         * - channel: channel to tune to. A frequency in kHz for AM/FM/HD Radio bands.
         * - sub_channel: valid for HD radio or digital radios only: (e.g SPS number for HD radio).
         *
         * returns:
         *  0 if tune successfully started
         *  -ENOSYS if called out of sequence
         *  -EINVAL if invalid arguments are passed
         *  -ENODEV if another error occurs
         *
         * Automatically cancels pending scan, step or tune.
         *
         * Callback function with event RADIO_EVENT_TUNED MUST be called once
         * tuned or after a time out. The event status should indicate
         * if a valid station is tuned or not.
         */
    virtual int tune(unsigned int channel, unsigned int sub_channel) = 0;

        /*
         * Cancel a scan, step or tune operation.
         * Must be called while a scan, step or tune operation is pending
         * (callback not yet sent).
         *
         * returns:
         *  0 if successful
         *  -ENOSYS if called out of sequence
         *  -ENODEV if another error occurs
         *
         * The callback is not sent.
         */
    virtual int cancel() = 0;

        /*
         * Retrieve current station information.
         *
         * arguments:
         * - info: where to return the program info.
         * If info->metadata is NULL. no meta data should be returned.
         * If meta data must be returned, they should be added to or cloned to
         * info->metadata, not passed from a newly created meta data buffer.
         *
         * returns:
         *  0 if tuned and information available
         *  -EINVAL if invalid arguments are passed
         *  -ENODEV if another error occurs
         */
    virtual int getProgramInformation(radio_program_info_t *info) = 0;

protected:
                TunerInterface() {}
    virtual     ~TunerInterface() {}

};

} // namespace android

#endif // ANDROID_HARDWARE_TUNER_INTERFACE_H
