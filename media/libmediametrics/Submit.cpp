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
#include <private/android_filesystem_config.h>

// Max per-property string size before truncation in toString().
// Do not make too large, as this is used for dumpsys purposes.
//static constexpr size_t kMaxPropertyStringSize = 4096;

namespace android::mediametrics {

#define DEBUG_SERVICEACCESS     1
#define DEBUG_API               0
#define DEBUG_ALLOCATIONS       0


// monitor health of our connection to the metrics service
class MediaMetricsDeathNotifier : public IBinder::DeathRecipient {
        virtual void binderDied(const wp<IBinder> &) {
            ALOGW("Reacquire service connection on next request");
            BaseItem::dropInstance();
        }
};

static std::mutex sServiceMutex;
static sp<MediaMetricsDeathNotifier> sNotifier GUARDED_BY(sServiceMutex);
static sp<media::IMediaMetricsService> sMediaMetricsService GUARDED_BY(sServiceMutex);

static
sp<media::IMediaMetricsService> getService() {
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
                sMediaMetricsService = interface_cast<media::IMediaMetricsService>(binder);
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

// static
status_t BaseItem::submitBuffer(const char *buffer, size_t size) {
    ALOGD_IF(DEBUG_API, "%s: delivering %zu bytes", __func__, size);

    // Validate size
    if (size > std::numeric_limits<int32_t>::max()) return BAD_VALUE;

    // Do we have the service available?
    sp<media::IMediaMetricsService> svc = getService();
    if (svc == nullptr) return NO_INIT;

    ::android::status_t status = NO_ERROR;
    if constexpr (/* DISABLES CODE */ (false)) {
        // THIS PATH IS FOR REFERENCE ONLY.
        // It is compiled so that any changes to IMediaMetricsService::submitBuffer()
        // will lead here.  If this code is changed, the else branch must
        // be changed as well.
        //
        // Use the AIDL calling interface - this is a bit slower as a byte vector must be
        // constructed. As the call is one-way, the only a transaction error occurs.
        status = svc->submitBuffer({buffer, buffer + size}).transactionError();
    } else {
        // Use the Binder calling interface - this direct implementation avoids
        // malloc/copy/free for the vector and reduces the overhead for logging.
        // We based this off of the AIDL generated file:
        // out/soong/.intermediates/frameworks/av/media/libmediametrics/
        //  mediametricsservice-aidl-unstable-cpp-source/gen/android/media/IMediaMetricsService.cpp
        //
        // TODO: Create an AIDL C++ back end optimized form of vector writing.
        ::android::Parcel _aidl_data;
        ::android::Parcel _aidl_reply; // we don't care about this as it is one-way.

        status = _aidl_data.writeInterfaceToken(svc->getInterfaceDescriptor());
        if (status != ::android::OK) goto _aidl_error;

        status = _aidl_data.writeInt32(static_cast<int32_t>(size));
        if (status != ::android::OK) goto _aidl_error;

        status = _aidl_data.write(buffer, static_cast<int32_t>(size));
        if (status != ::android::OK) goto _aidl_error;

        status = ::android::IInterface::asBinder(svc)->transact(
                ::android::media::BnMediaMetricsService::TRANSACTION_submitBuffer,
                _aidl_data, &_aidl_reply, ::android::IBinder::FLAG_ONEWAY);

        // AIDL permits setting a default implementation for additional functionality.
        // See go/aog/713984. This is not used here.
        // if (status == ::android::UNKNOWN_TRANSACTION
        //         && ::android::media::IMediaMetricsService::getDefaultImpl()) {
        //     status = ::android::media::IMediaMetricsService::getDefaultImpl()
        //             ->submitBuffer(immutableByteVectorFromBuffer(buffer, size))
        //             .transactionError();
        // }
    }

    if (status == NO_ERROR) return NO_ERROR;

    _aidl_error:
    ALOGW("%s: failed(%d) to record: %zu bytes", __func__, status, size);
    return status;
}

} // namespace android::mediametrics
