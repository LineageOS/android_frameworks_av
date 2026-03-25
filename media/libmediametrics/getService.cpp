/*
 * Copyright (C) 2026 The Android Open Source Project
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

#define LOG_TAG "mediametrics::getService"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <mutex>

#include <binder/Parcel.h>
#include <cutils/multiuser.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/threads.h>

#include <android/media/BnMediaMetricsService.h> // for direct Binder access
#include <android/media/IMediaMetricsService.h>
#include <binder/IServiceManager.h>
#include <media/MediaMetricsItem.h>
#include <media/MediaMetricsInternal.h>
#include <private/android_filesystem_config.h>

#include <android/media/metrics/StructuredItem.h>

// Max per-property string size before truncation in toString().
// Do not make too large, as this is used for dumpsys purposes.
//static constexpr size_t kMaxPropertyStringSize = 4096;

namespace android::mediametrics {

#define DEBUG_SERVICEACCESS     1
#define DEBUG_API               0
#define DEBUG_ALLOCATIONS       0

// monitor health of our connection to the metrics service
class MediaMetricsDeathNotifier : public IBinder::DeathRecipient {
        virtual void binderDied(const wp<IBinder> &) final {
            ALOGW("Reacquire service connection on next request");
            BaseItem::dropInstance();
        }
};

static std::mutex sServiceMutex;
static sp<MediaMetricsDeathNotifier> sNotifier GUARDED_BY(sServiceMutex);
static sp<IMediaMetricsService> sMediaMetricsService GUARDED_BY(sServiceMutex);

sp<IMediaMetricsService> getService()
{
    static constexpr const char *servicename = "media.metrics";
    static const bool enabled = BaseItem::isEnabled(); // singleton initialized

    if (enabled == false) {
        ALOGD_IF(DEBUG_SERVICEACCESS, "%s: disabled", __func__);
        return nullptr;
    }
    std::lock_guard _l(sServiceMutex);
    if (sMediaMetricsService == nullptr) {
        const char *badness = "";
        sp<IServiceManager> sm = defaultServiceManager();
        if (sm != nullptr) {
            // checkService() is non-blocking, opening us for some busy-waiting
            // if the caller keeps retrying.
            sp<IBinder> binder = sm->checkService(String16(servicename));
            if (binder != nullptr) {
                sMediaMetricsService = interface_cast<IMediaMetricsService>(binder);
                sNotifier = new MediaMetricsDeathNotifier();
                binder->linkToDeath(sNotifier);
            } else {
                badness = "did not find service";
            }
        } else {
            badness = "No Service Manager access";
        }
        if (sMediaMetricsService == nullptr) {
            ALOGW_IF(DEBUG_SERVICEACCESS, "%s: unable to bind to service %s: %s",
                    __func__, servicename, badness);
        }
    }
    return sMediaMetricsService;
}

// static
void BaseItem::dropInstance() {
    std::lock_guard  _l(sServiceMutex);
    sMediaMetricsService = nullptr;
}

} // namespace android::mediametrics
