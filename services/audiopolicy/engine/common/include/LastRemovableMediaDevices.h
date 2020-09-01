/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef ANDROID_LAST_REMOVABLE_MEDIA_DEVICES_H
#define ANDROID_LAST_REMOVABLE_MEDIA_DEVICES_H

#include <vector>
#include <HwModule.h>
#include <system/audio_policy.h>

namespace android {

typedef enum {
    GROUP_NONE = -1,
    GROUP_WIRED,
    GROUP_BT_A2DP,
    NUM_GROUP
} device_out_group_t;

class LastRemovableMediaDevices
{
public:
    void setRemovableMediaDevices(sp<DeviceDescriptor> desc, audio_policy_dev_state_t state);
    std::vector<audio_devices_t> getLastRemovableMediaDevices(
            device_out_group_t group = GROUP_NONE) const;

private:
    struct DeviceGroupDescriptor {
        sp<DeviceDescriptor> desc;
        device_out_group_t group;
    };
    std::vector<DeviceGroupDescriptor> mMediaDevices;

    device_out_group_t getDeviceOutGroup(audio_devices_t device) const;
};

} // namespace android

#endif // ANDROID_LAST_REMOVABLE_MEDIA_DEVICES_H
