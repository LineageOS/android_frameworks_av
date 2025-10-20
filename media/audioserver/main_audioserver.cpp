/*
 * Copyright (C) 2015 The Android Open Source Project
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

#define LOG_TAG "audioserver_main"
//#define LOG_NDEBUG 0

#include <algorithm>

#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <cutils/properties.h>

#include <android/media/audio/common/AudioMMapPolicy.h>
#include <android/media/audio/common/AudioMMapPolicyInfo.h>
#include <android/media/audio/common/AudioMMapPolicyType.h>
#include <android/media/IAudioFlingerService.h>
#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>
#include <hidl/HidlTransportSupport.h>
#include <mediautils/LimitProcessMemory.h>
#include <utils/Log.h>

// from include_dirs
#include "AudioFlinger.h"
#include "AudioPolicyService.h"
#include "AAudioService.h"
#include "utility/AAudioUtilities.h"

using namespace android;

using android::media::audio::common::AudioMMapPolicy;
using android::media::audio::common::AudioMMapPolicyInfo;
using android::media::audio::common::AudioMMapPolicyType;

int main(int argc __unused, char **argv __unused)
{
    SLOGI("%s: starting", __func__);
    const auto startTime = std::chrono::steady_clock::now();
    // TODO: update with refined parameters
    limitProcessMemory(
        "audio.maxmem", /* "ro.audio.maxmem", property that defines limit */
        (size_t)512 * (1 << 20), /* SIZE_MAX, upper limit in bytes */
        20 /* upper limit as percentage of physical RAM */);

    signal(SIGPIPE, SIG_IGN);

    android::hardware::configureRpcThreadpool(4, false /*callerWillJoin*/);

    // Ensure threads for possible callbacks.  Note that get_audio_flinger() does
    // this automatically when called from AudioPolicy, but we do this anyways here.
    ProcessState::self()->startThreadPool();

    // Instantiating AudioFlinger (making it public, e.g. through ::initialize())
    // and then instantiating AudioPolicy (and making it public)
    // leads to situations where AudioFlinger is accessed remotely before
    // AudioPolicy is initialized.  Not only might this
    // cause inaccurate results, but if AudioPolicy has slow audio HAL
    // initialization, it can cause a TimeCheck abort to occur on an AudioFlinger
    // call which tries to access AudioPolicy.
    //
    // We create AudioFlinger and AudioPolicy locally then make it public to ServiceManager.
    // This requires both AudioFlinger and AudioPolicy to be in-proc.
    //
    const auto af = sp<AudioFlinger>::make();
    const auto afAdapter = sp<AudioFlingerServerAdapter>::make(af);
    SLOGI("%s: AudioFlinger created", __func__);
    SLOGW_IF(AudioSystem::setLocalAudioFlinger(af) != OK,
            "%s: AudioSystem already has an AudioFlinger instance!", __func__);
    const auto aps = sp<AudioPolicyService>::make();
    af->initAudioPolicyLocal(aps);
    SLOGI("%s: AudioPolicy created", __func__);
    SLOGW_IF(AudioSystem::setLocalAudioPolicyService(aps) != OK,
             "%s: AudioSystem already has an AudioPolicyService instance!", __func__);

    // Start initialization of internally managed audio objects such as Device Effects.
    aps->onAudioSystemReady();

    SLOGI("%s: AudioSystem ready", __func__);

    // Add AudioFlinger and AudioPolicy to ServiceManager.
    sp<IServiceManager> sm = defaultServiceManager();
    sm->addService(String16(IAudioFlinger::DEFAULT_SERVICE_NAME), afAdapter,
            false /* allowIsolated */, IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT);
    sm->addService(String16(AudioPolicyService::getServiceName()), aps,
            false /* allowIsolated */, IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT);

    // AAudioService should only be used in OC-MR1 and later.
    // And only enable the AAudioService if the system MMAP policy explicitly allows it.
    // This prevents a client from misusing AAudioService when it is not supported.
    // If we cannot get audio flinger here, there must be some serious problems. In that case,
    // attempting to call audio flinger on a null pointer could make the process crash
    // and attract attentions.
    std::vector<AudioMMapPolicyInfo> policyInfos;
    status_t status = AudioSystem::getMmapPolicyInfos(
            AudioMMapPolicyType::DEFAULT, &policyInfos);
    // Initialize aaudio service when querying mmap policy succeeds and
    // any of the policy supports MMAP.
    if (status == NO_ERROR &&
        std::any_of(policyInfos.begin(), policyInfos.end(), [](const auto& info) {
                return info.mmapPolicy == AudioMMapPolicy::AUTO ||
                       info.mmapPolicy == AudioMMapPolicy::ALWAYS;
        })) {
        AAudioService::instantiate();
    } else {
        SLOGI("%s: Do not init aaudio service, status %d, policy info size %zu",
              __func__, status, policyInfos.size());
    }
    const auto endTime = std::chrono::steady_clock::now();
    af->startupFinished();
    using FloatMillis = std::chrono::duration<float, std::milli>;
    const float timeTaken = std::chrono::duration_cast<FloatMillis>(
            endTime - startTime).count();
    SLOGI("%s: initialization done in %.3f ms, joining thread pool", __func__, timeTaken);
    IPCThreadState::self()->joinThreadPool();
}
