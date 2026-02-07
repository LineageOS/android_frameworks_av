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

#define LOG_TAG "mediametrics::Item"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <mutex>

#include <android-base/properties.h>
#include <binder/Parcel.h>
#include <cutils/multiuser.h>
#include <cutils/properties.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/SortedVector.h>
#include <utils/threads.h>

#include <android/binder_auto_utils.h>
#include <android/binder_ibinder.h>
#include <android/binder_manager.h>
#include <android/binder_parcel.h>
#include <android/binder_parcel_utils.h>
#include <aidl/android/media/BnMediaMetricsService.h>
#include <aidl/android/media/IMediaMetricsService.h>
typedef ::aidl::android::media::IMediaMetricsService metricsservice_t;

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

AIBinder_DeathRecipient *sRecipient = nullptr;

static void onBinderDied(void *cookie) {
        // do the cleanup
    if (cookie == nullptr) {
        AIBinder_DeathRecipient_delete(sRecipient);
        sRecipient = nullptr;
                // clear sediaMetricsService
                // should we mutex in here too
        ALOGD("mediametrics service disappeared");
    }
}

static std::mutex sServiceMutex;
static std::shared_ptr<metricsservice_t> sMediaMetricsService GUARDED_BY(sServiceMutex);

static
std::shared_ptr<metricsservice_t> getService() {
    static const char *servicename = "media.metrics";
    static const bool enabled = BaseItem::isEnabled(); // singleton initialized

    if (enabled == false) {
        ALOGD_IF(DEBUG_SERVICEACCESS, "%s: disabled", __func__);
        return nullptr;
    }
    std::lock_guard _l(sServiceMutex);
    // think of remainingBindAttempts as telling us whether service == nullptr because
    // (1) we haven't tried to initialize it yet
    // (2) we've tried to initialize it, but failed.
    if (sMediaMetricsService == nullptr) {
        const char *badness = "";

        // checkService works as a replacement for getService()
        // checkService() is non-blocking, opening us for some busy-waiting
        // if the caller keeps retrying.
        ::ndk::SpAIBinder binder(AServiceManager_checkService(servicename));

        if (binder == nullptr)  {
            badness = "did not find service";
        } else {
            sMediaMetricsService = metricsservice_t::fromBinder(binder);
            sRecipient = AIBinder_DeathRecipient_new(onBinderDied);
            binder_status_t status = AIBinder_linkToDeath(binder.get(), sRecipient, nullptr);
            if (status != NO_ERROR) {
                ALOGD("Unable to establish linkToDeath");
            AIBinder_DeathRecipient_delete(sRecipient);
            sRecipient = nullptr;
            }
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
    std::shared_ptr<metricsservice_t> svc = getService();
    if (svc == nullptr)  return NO_INIT;

    ::android::status_t status = NO_ERROR;
    ::ndk::ScopedAStatus AStatus;
    // for now, the reference copy *is* the copy we use. No optimized version
    // for module use yet
    if constexpr ((true)) {
        // THIS PATH IS FOR REFERENCE ONLY.
        // It is compiled so that any changes to IMediaMetricsService::submitBuffer()
        // will lead here.  If this code is changed, the else branch must
        // be changed as well.
        //
        // Use the AIDL calling interface - this is a bit slower as a byte vector must be
        // constructed. As the call is one-way, the only a transaction error occurs.
        //
        //status = svc->submitBuffer({buffer, buffer + size}).transactionError();
        AStatus = svc->submitBuffer({buffer, buffer + size});
                // returns ::ndk::ScopedAStatus
        status = AStatus.getStatus();
#if 0
    } else {
        // NB: this has not been updated for the module
        // so we use the above, correct-but-unoptimized reference version.
        //
        // Use the Binder calling interface - this direct implementation avoids
        // malloc/copy/free for the vector and reduces the overhead for logging.
        // We based this off of the AIDL generated file:
        // out/soong/.intermediates/frameworks/av/media/libmediametrics/
        //  mediametricsservice-aidl-unstable-cpp-source/gen/android/media/IMediaMetricsService.cpp
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
                aidl::android::media::BnMediaMetricsService::TRANSACTION_submitBuffer,
                _aidl_data, &_aidl_reply, ::android::IBinder::FLAG_ONEWAY);

        // AIDL permits setting a default implementation for additional functionality.
        // See go/aog/713984. This is not used here.
        // if (status == ::android::UNKNOWN_TRANSACTION
        //         && ::android::media::IMediaMetricsService::getDefaultImpl()) {
        //     status = ::android::media::IMediaMetricsService::getDefaultImpl()
        //             ->submitBuffer(immutableByteVectorFromBuffer(buffer, size))
        //             .transactionError();
        // }
#endif
    }

    if (status == NO_ERROR) return NO_ERROR;

    // _aidl_error:
    ALOGW("%s: failed(%d) to record: %zu bytes", __func__, status, size);
    return status;
}

} // namespace android::mediametrics
