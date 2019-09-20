/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <unordered_set>

#include <gtest/gtest.h>

#define LOG_TAG "SysAudio_Test"
#include <log/log.h>
#include <media/PatchBuilder.h>
#include <system/audio.h>

using namespace android;

TEST(SystemAudioTest, PatchInvalid) {
    audio_patch patch{};
    ASSERT_FALSE(audio_patch_is_valid(&patch));
    patch.num_sources = AUDIO_PATCH_PORTS_MAX + 1;
    patch.num_sinks = 1;
    ASSERT_FALSE(audio_patch_is_valid(&patch));
    patch.num_sources = 1;
    patch.num_sinks = AUDIO_PATCH_PORTS_MAX + 1;
    ASSERT_FALSE(audio_patch_is_valid(&patch));
    patch.num_sources = 0;
    patch.num_sinks = 1;
    ASSERT_FALSE(audio_patch_is_valid(&patch));
}

TEST(SystemAudioTest, PatchValid) {
    const audio_port_config src = {
        .id = 1, .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE };
    // It's OK not to have sinks.
    ASSERT_TRUE(audio_patch_is_valid((PatchBuilder{}).addSource(src).patch()));
    const audio_port_config sink = {
        .id = 2, .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE };
    ASSERT_TRUE(audio_patch_is_valid((PatchBuilder{}).addSource(src).addSink(sink).patch()));
    ASSERT_TRUE(audio_patch_is_valid(
                    (PatchBuilder{}).addSource(src).addSource(src).addSink(sink).patch()));
    ASSERT_TRUE(audio_patch_is_valid(
                    (PatchBuilder{}).addSource(src).addSink(sink).addSink(sink).patch()));
    ASSERT_TRUE(audio_patch_is_valid(
                    (PatchBuilder{}).addSource(src).addSource(src).
                    addSink(sink).addSink(sink).patch()));
}

TEST(SystemAudioTest, PatchHwAvSync) {
    audio_port_config device_src_cfg = {
        .id = 1, .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE };
    ASSERT_FALSE(audio_port_config_has_hw_av_sync(&device_src_cfg));
    device_src_cfg.config_mask |= AUDIO_PORT_CONFIG_FLAGS;
    ASSERT_FALSE(audio_port_config_has_hw_av_sync(&device_src_cfg));
    device_src_cfg.flags.input = AUDIO_INPUT_FLAG_HW_AV_SYNC;
    ASSERT_TRUE(audio_port_config_has_hw_av_sync(&device_src_cfg));

    audio_port_config device_sink_cfg = {
        .id = 1, .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE };
    ASSERT_FALSE(audio_port_config_has_hw_av_sync(&device_sink_cfg));
    device_sink_cfg.config_mask |= AUDIO_PORT_CONFIG_FLAGS;
    ASSERT_FALSE(audio_port_config_has_hw_av_sync(&device_sink_cfg));
    device_sink_cfg.flags.output = AUDIO_OUTPUT_FLAG_HW_AV_SYNC;
    ASSERT_TRUE(audio_port_config_has_hw_av_sync(&device_sink_cfg));

    audio_port_config mix_sink_cfg = {
        .id = 1, .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_MIX };
    ASSERT_FALSE(audio_port_config_has_hw_av_sync(&mix_sink_cfg));
    mix_sink_cfg.config_mask |= AUDIO_PORT_CONFIG_FLAGS;
    ASSERT_FALSE(audio_port_config_has_hw_av_sync(&mix_sink_cfg));
    mix_sink_cfg.flags.input = AUDIO_INPUT_FLAG_HW_AV_SYNC;
    ASSERT_TRUE(audio_port_config_has_hw_av_sync(&mix_sink_cfg));

    audio_port_config mix_src_cfg = {
        .id = 1, .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_MIX };
    ASSERT_FALSE(audio_port_config_has_hw_av_sync(&mix_src_cfg));
    mix_src_cfg.config_mask |= AUDIO_PORT_CONFIG_FLAGS;
    ASSERT_FALSE(audio_port_config_has_hw_av_sync(&mix_src_cfg));
    mix_src_cfg.flags.output = AUDIO_OUTPUT_FLAG_HW_AV_SYNC;
    ASSERT_TRUE(audio_port_config_has_hw_av_sync(&mix_src_cfg));
}

TEST(SystemAudioTest, PatchEqual) {
    const audio_patch patch1{}, patch2{};
    // Invalid patches are not equal.
    ASSERT_FALSE(audio_patches_are_equal(&patch1, &patch2));
    const audio_port_config src = {
        .id = 1, .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE };
    const audio_port_config sink = {
        .id = 2, .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE };
    ASSERT_FALSE(audio_patches_are_equal(
                    (PatchBuilder{}).addSource(src).patch(),
                    (PatchBuilder{}).addSource(src).addSink(sink).patch()));
    ASSERT_TRUE(audio_patches_are_equal(
                    (PatchBuilder{}).addSource(src).addSink(sink).patch(),
                    (PatchBuilder{}).addSource(src).addSink(sink).patch()));
    ASSERT_FALSE(audio_patches_are_equal(
                    (PatchBuilder{}).addSource(src).addSink(sink).patch(),
                    (PatchBuilder{}).addSource(src).addSource(src).addSink(sink).patch()));
    audio_port_config sink_hw_av_sync = sink;
    sink_hw_av_sync.config_mask |= AUDIO_PORT_CONFIG_FLAGS;
    sink_hw_av_sync.flags.output = AUDIO_OUTPUT_FLAG_HW_AV_SYNC;
    ASSERT_FALSE(audio_patches_are_equal(
                    (PatchBuilder{}).addSource(src).addSink(sink).patch(),
                    (PatchBuilder{}).addSource(src).addSink(sink_hw_av_sync).patch()));
    ASSERT_TRUE(audio_patches_are_equal(
                    (PatchBuilder{}).addSource(src).addSink(sink_hw_av_sync).patch(),
                    (PatchBuilder{}).addSource(src).addSink(sink_hw_av_sync).patch()));
}

void runAudioDeviceTypeHelperFunction(const std::unordered_set<audio_devices_t>& allDevices,
                                      const audio_devices_t targetDevices[],
                                      unsigned int targetDeviceCount,
                                      const std::string& deviceTag,
                                      bool (*device_type_helper_function)(audio_devices_t))
{
    std::unordered_set<audio_devices_t> devices(targetDevices, targetDevices + targetDeviceCount);
    for (auto device : allDevices) {
        if (devices.find(device) == devices.end()) {
            ASSERT_FALSE(device_type_helper_function(device))
                    << std::hex << device << " should not be " << deviceTag << " device";
        } else {
            ASSERT_TRUE(device_type_helper_function(device))
                    << std::hex << device << " should be " << deviceTag << " device";
        }
    }
}

TEST(SystemAudioTest, AudioDeviceTypeHelperFunction) {
    std::unordered_set<audio_devices_t> allDeviceTypes;
    allDeviceTypes.insert(std::begin(AUDIO_DEVICE_OUT_ALL_ARRAY),
            std::end(AUDIO_DEVICE_OUT_ALL_ARRAY));
    allDeviceTypes.insert(std::begin(AUDIO_DEVICE_IN_ALL_ARRAY),
            std::end(AUDIO_DEVICE_IN_ALL_ARRAY));

    runAudioDeviceTypeHelperFunction(allDeviceTypes, AUDIO_DEVICE_OUT_ALL_ARRAY,
            std::size(AUDIO_DEVICE_OUT_ALL_ARRAY), "output", audio_is_output_device);
    runAudioDeviceTypeHelperFunction(allDeviceTypes, AUDIO_DEVICE_IN_ALL_ARRAY,
            std::size(AUDIO_DEVICE_IN_ALL_ARRAY), "input", audio_is_input_device);
    runAudioDeviceTypeHelperFunction(allDeviceTypes, AUDIO_DEVICE_OUT_ALL_A2DP_ARRAY,
            std::size(AUDIO_DEVICE_OUT_ALL_A2DP_ARRAY), "a2dp out", audio_is_a2dp_out_device);
    const audio_devices_t bluetoothInA2dpDevices[] = { AUDIO_DEVICE_IN_BLUETOOTH_A2DP };
    runAudioDeviceTypeHelperFunction(allDeviceTypes, bluetoothInA2dpDevices,
            std::size(bluetoothInA2dpDevices), "a2dp in", audio_is_a2dp_in_device);
    runAudioDeviceTypeHelperFunction(allDeviceTypes, AUDIO_DEVICE_OUT_ALL_SCO_ARRAY,
            std::size(AUDIO_DEVICE_OUT_ALL_SCO_ARRAY), "bluetooth out sco",
            audio_is_bluetooth_out_sco_device);
    runAudioDeviceTypeHelperFunction(allDeviceTypes, AUDIO_DEVICE_IN_ALL_SCO_ARRAY,
            std::size(AUDIO_DEVICE_IN_ALL_SCO_ARRAY), "bluetooth in sco",
            audio_is_bluetooth_in_sco_device);
    const unsigned int scoDeviceCount = AUDIO_DEVICE_OUT_SCO_CNT + AUDIO_DEVICE_IN_SCO_CNT;
    audio_devices_t scoDevices[scoDeviceCount];
    std::copy(std::begin(AUDIO_DEVICE_OUT_ALL_SCO_ARRAY), std::end(AUDIO_DEVICE_OUT_ALL_SCO_ARRAY),
              std::begin(scoDevices));
    std::copy(std::begin(AUDIO_DEVICE_IN_ALL_SCO_ARRAY), std::end(AUDIO_DEVICE_IN_ALL_SCO_ARRAY),
              std::begin(scoDevices) + AUDIO_DEVICE_OUT_SCO_CNT);
    runAudioDeviceTypeHelperFunction(allDeviceTypes, scoDevices,
            std::size(scoDevices), "bluetooth sco", audio_is_bluetooth_sco_device);
    const audio_devices_t hearingAidOutDevices[] = { AUDIO_DEVICE_OUT_HEARING_AID };
    runAudioDeviceTypeHelperFunction(allDeviceTypes, hearingAidOutDevices,
            std::size(hearingAidOutDevices), "hearing aid out", audio_is_hearing_aid_out_device);
    runAudioDeviceTypeHelperFunction(allDeviceTypes, AUDIO_DEVICE_OUT_ALL_USB_ARRAY,
            std::size(AUDIO_DEVICE_OUT_ALL_USB_ARRAY), "usb out", audio_is_usb_out_device);
    runAudioDeviceTypeHelperFunction(allDeviceTypes, AUDIO_DEVICE_IN_ALL_USB_ARRAY,
            std::size(AUDIO_DEVICE_IN_ALL_USB_ARRAY), "usb in", audio_is_usb_in_device);
    const audio_devices_t remoteSubmixDevices[] = {
            AUDIO_DEVICE_IN_REMOTE_SUBMIX, AUDIO_DEVICE_OUT_REMOTE_SUBMIX };
    runAudioDeviceTypeHelperFunction(allDeviceTypes, remoteSubmixDevices,
            std::size(remoteSubmixDevices), "remote submix", audio_is_remote_submix_device);
    runAudioDeviceTypeHelperFunction(allDeviceTypes, AUDIO_DEVICE_OUT_ALL_DIGITAL_ARRAY,
            std::size(AUDIO_DEVICE_OUT_ALL_DIGITAL_ARRAY), "digital out",
            audio_is_digital_out_device);
    runAudioDeviceTypeHelperFunction(allDeviceTypes, AUDIO_DEVICE_IN_ALL_DIGITAL_ARRAY,
            std::size(AUDIO_DEVICE_IN_ALL_DIGITAL_ARRAY), "digital in",
            audio_is_digital_in_device);
    const unsigned int digitalDeviceCount
            = AUDIO_DEVICE_OUT_DIGITAL_CNT + AUDIO_DEVICE_IN_DIGITAL_CNT;
    audio_devices_t digitalDevices[digitalDeviceCount];
    std::copy(std::begin(AUDIO_DEVICE_OUT_ALL_DIGITAL_ARRAY),
              std::end(AUDIO_DEVICE_OUT_ALL_DIGITAL_ARRAY),
              std::begin(digitalDevices));
    std::copy(std::begin(AUDIO_DEVICE_IN_ALL_DIGITAL_ARRAY),
              std::end(AUDIO_DEVICE_IN_ALL_DIGITAL_ARRAY),
              std::begin(digitalDevices) + AUDIO_DEVICE_OUT_DIGITAL_CNT);
    runAudioDeviceTypeHelperFunction(allDeviceTypes, digitalDevices,
              std::size(digitalDevices), "digital", audio_device_is_digital);
}
