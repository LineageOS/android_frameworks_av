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

#define LOG_TAG "mediametrics::Item::submit"

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


/* Item::selfrecord()
 *
 * this allows the particular MediaMetricsItem to log itself.
 * The routine converts to the AIDL-ready format and sends to the service.
 */

bool mediametrics::Item::selfrecord() {
    bool success = true;
    ALOGD_IF(DEBUG_API, "%s: delivering %s", __func__, this->toString().c_str());

    // Do we have the service available?
    sp<IMediaMetricsService> svc = getService();
    if (svc == nullptr) return false;

    // get it ready to go
    std::shared_ptr<StructuredItem> pstruct = writeItemToStructured(*this);
    if (pstruct == nullptr) return false;

    ::android::status_t status = NO_ERROR;
#ifdef  METRICS_IN_MODULE
    ::ndk::ScopedAStatus AStatus;
    AStatus = svc->submitStructuredItem(*pstruct);
    status = AStatus.getStatus();
#else
    status = svc->submitStructuredItem(*pstruct).transactionError();
#endif

    if (status != NO_ERROR) {
        ALOGW("%s: failed to record: (%d) %s", __func__,
              status,  this->toString().c_str());
        success = false;
    }
    return success;
}

// used solely by audio analytics, which saves up a bunch of records (as Buffers) and then
// later decides which ones to submit. This allows that subsystem to continue to use
// the space-efficient bytebuffer construct, but we then convert at submit() time so
// it has an appropriate representation to go across the service call.
//
// The bytebuffer representation in the audio analytics was formerly efficient because
// there was no necessary extra processing when those records are submitted; we have
// to do the conversion because the interface's level of abstraction had to change for
// the move to stable aidl.
//
// static
status_t BaseItem::submitBuffer(const char *buffer, size_t size) {
    ALOGD_IF(DEBUG_API, "%s: delivering %zu bytes", __func__, size);

    // Validate parameters
    if (buffer == nullptr) return BAD_VALUE;
    if (size > std::numeric_limits<int32_t>::max()) return BAD_VALUE;

    // Do we have the service available?
    sp<IMediaMetricsService> svc = getService();
    if (svc == nullptr) return NO_INIT;

    ::android::status_t status = NO_ERROR;
    mediametrics::Item *item = mediametrics::Item::create();
    status = item->readFromByteString(buffer, size);
    if (status == NO_ERROR) {
        if (!item->selfrecord()) {
            status = FAILED_TRANSACTION;
        }
    }
    delete item;

    if (status == NO_ERROR) return NO_ERROR;

    ALOGW("%s: failed(%d) to record: %zu bytes", __func__, status, size);
    return status;
}

} // namespace android::mediametrics
