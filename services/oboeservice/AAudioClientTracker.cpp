/*
 * Copyright (C) 2017 The Android Open Source Project
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


#define LOG_TAG "AAudioClientTracker"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

// go/keep-sorted start
#include <assert.h>
#include <audio_utils/threads.h>
#include <binder/IPCThreadState.h>
#include <chrono>
#include <com_android_media_audioserver.h>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <utils/Singleton.h>
// go/keep-sorted end

#include "utility/AAudioUtilities.h"
#include "AAudioEndpointManager.h"
#include "AAudioServiceEndpoint.h"
#include "AAudioClientTracker.h"

using namespace android;
using namespace aaudio;

ANDROID_SINGLETON_STATIC_INSTANCE(AAudioClientTracker);

AAudioClientTracker::AAudioClientTracker()
        : Singleton<AAudioClientTracker>() {
}

std::string AAudioClientTracker::dump() const NO_THREAD_SAFETY_ANALYSIS {
    std::stringstream result;
    const bool isLocked = AAudio_tryUntilTrue(
            [this]()->bool { return mLock.try_lock(); } /* f */,
            50 /* times */,
            20 /* sleepMs */);
    if (!isLocked) {
        result << "AAudioClientTracker may be deadlocked\n";
    }

    result << "AAudioClientTracker:\n";
    for (const auto&  it : mNotificationClients) {
        result << it.second->dump();
    }

    if (isLocked) {
        mLock.unlock();
    }
    return result.str();
}

// Create a tracker for the client.
aaudio_result_t AAudioClientTracker::registerClient(pid_t pid,
                                         const sp<IAAudioClient>& client) {
    ALOGV("registerClient(), calling pid = %d, getpid() = %d\n", pid, getpid());

    if (client.get() == nullptr) {
        ALOGE("AAudioClientTracker::%s() client is NULL!", __func__);
        android_errorWriteLog(0x534e4554, "116230453");
        return AAUDIO_ERROR_NULL;
    }

    const std::lock_guard<std::mutex> lock(mLock);
    sp<NotificationClient> notificationClient;
    status_t status;
    sp<IBinder> binder = IInterface::asBinder(client);
    if (mNotificationClients.count(pid) == 0) {
        notificationClient = new NotificationClient(pid, binder);
        mNotificationClients[pid] = notificationClient;

        status = binder->linkToDeath(notificationClient);
        ALOGW_IF(status != NO_ERROR, "registerClient() linkToDeath = %d\n", status);
        if (com::android::media::audioserver::mmap_freezer_awareness()) {
            status = binder->addFrozenStateChangeCallback(notificationClient);
            ALOGW_IF(status != NO_ERROR, "registerClient() addFrozenStateChangeCallback = %d\n",
                     status);
        }
        return AAudioConvert_androidToAAudioResult(status);
    } else {
        ALOGW("registerClient(%d) already registered!", pid);
        notificationClient = mNotificationClients[pid];
        if (notificationClient-> isBinderNull()) {
            ALOGW("registerClient() need to linkToDeath as notificationClient binder is null");
            status = binder->linkToDeath(notificationClient);
            if (status != NO_ERROR) {
                ALOGE("registerClient() linkToDeath status = %d\n", status);
            } else {
                if (com::android::media::audioserver::mmap_freezer_awareness()) {
                    status = binder->addFrozenStateChangeCallback(notificationClient);
                    if (status != NO_ERROR) {
                        ALOGE("registerClient() addFrozenStateChangeCallback status = %d\n",
                              status);
                    }
                }
                notificationClient->setBinder(binder);
            }
        }
        return AAUDIO_OK; // TODO should this be considered an error
    }
}

void AAudioClientTracker::unregisterClient(pid_t pid) {
    ALOGV("unregisterClient(), calling pid = %d, getpid() = %d\n", pid, getpid());
    const std::lock_guard<std::mutex> lock(mLock);
    mNotificationClients.erase(pid);
}

int32_t AAudioClientTracker::getStreamCount(pid_t pid) {
    const std::lock_guard<std::mutex> lock(mLock);
    auto it = mNotificationClients.find(pid);
    if (it != mNotificationClients.end()) {
        return it->second->getStreamCount();
    } else {
        return 0; // no existing client
    }
}

aaudio_result_t
AAudioClientTracker::registerClientStream(
        pid_t pid, const sp<AAudioServiceStreamBase>& serviceStream) {
    const auto handle = serviceStream->getHandle();
    ALOGV("registerClientStream(%d, 0x%08X)\n", pid, handle);
    const std::lock_guard<std::mutex> lock(mLock);
    return getNotificationClient_l(pid)->registerClientStream(serviceStream);
}

// Find the tracker for this process and remove it.
aaudio_result_t
AAudioClientTracker::unregisterClientStream(pid_t pid,
                                            const sp<AAudioServiceStreamBase>& serviceStream) {
    const auto handle = serviceStream->getHandle();
    ALOGV("unregisterClientStream(%d, 0x%08X)\n", pid, handle);
    const std::lock_guard<std::mutex> lock(mLock);
    auto it = mNotificationClients.find(pid);
    if (it != mNotificationClients.end()) {
        ALOGV("unregisterClientStream(%d, 0x%08X) found NotificationClient\n", pid, handle);
        it->second->unregisterClientStream(serviceStream);
    } else {
        ALOGE("unregisterClientStream(%d, 0x%08X) missing NotificationClient\n", pid, handle);
    }
    return AAUDIO_OK;
}

void AAudioClientTracker::setExclusiveEnabled(pid_t pid, bool enabled) {
    ALOGD("%s(%d, %d)\n", __func__, pid, enabled);
    const std::lock_guard<std::mutex> lock(mLock);
    getNotificationClient_l(pid)->setExclusiveEnabled(enabled);
}

bool AAudioClientTracker::isExclusiveEnabled(pid_t pid) {
    const std::lock_guard<std::mutex> lock(mLock);
    return getNotificationClient_l(pid)->isExclusiveEnabled();
}

std::pair<bool, int64_t> AAudioClientTracker::getFrozenStatus(pid_t pid) const {
    std::lock_guard<std::mutex> l(mLock);

    const auto it = mNotificationClients.find(pid);
    if (it != mNotificationClients.end()) {
        return it->second->getFrozenStatus();
    }
    return {false, 0};
}

sp<AAudioClientTracker::NotificationClient>
        AAudioClientTracker::getNotificationClient_l(pid_t pid) {
    sp<NotificationClient> notificationClient = mNotificationClients[pid];
    if (notificationClient == nullptr) {
        // This will get called the first time the audio server uses this PID.
        ALOGV("%s(%d,) unrecognized PID\n", __func__, pid);
        notificationClient = new AAudioClientTracker::NotificationClient(pid, nullptr);
        mNotificationClients[pid] = notificationClient;
    }
    return notificationClient;
}

// =======================================
// AAudioClientTracker::NotificationClient
// =======================================

AAudioClientTracker::NotificationClient::NotificationClient(pid_t pid, const sp<IBinder>& binder)
        : mProcessId(pid), mBinder(binder) {
    ALOGV("%s: created NotificationClient for pid %d", __func__, mProcessId);
}

AAudioClientTracker::NotificationClient::~NotificationClient() {
    ALOGV("%s: destroyed NotificationClient for pid %d", __func__, mProcessId);
}

int32_t AAudioClientTracker::NotificationClient::getStreamCount() {
    const std::lock_guard<std::mutex> lock(mLock);
    return mStreams.size();
}

aaudio_result_t AAudioClientTracker::NotificationClient::registerClientStream(
        const sp<AAudioServiceStreamBase>& serviceStream) {
    const std::lock_guard<std::mutex> lock(mLock);
    mStreams.insert(serviceStream);
    return AAUDIO_OK;
}

aaudio_result_t AAudioClientTracker::NotificationClient::unregisterClientStream(
        const sp<AAudioServiceStreamBase>& serviceStream) {
    const std::lock_guard<std::mutex> lock(mLock);
    mStreams.erase(serviceStream);
    return AAUDIO_OK;
}

// Close any open streams for the client.
void AAudioClientTracker::NotificationClient::binderDied(const wp<IBinder>& who __unused) {
    closeStream(false /* fromFreeze */);
}

void AAudioClientTracker::NotificationClient::closeStream(bool fromFreeze) {
    audio_utils::set_priority_for_binder_callback(__func__);

    AAudioService *aaudioService = AAudioClientTracker::getInstance().getAAudioService();
    if (aaudioService != nullptr) {
        // Copy the current list of streams to another vector because closing them below
        // will cause unregisterClientStream() calls back to this object.
        std::set<sp<AAudioServiceStreamBase>>  streamsToClose;

        {
            const std::lock_guard<std::mutex> lock(mLock);
            for (const auto& serviceStream : mStreams) {
                streamsToClose.insert(serviceStream);
            }
        }

        for (const auto& serviceStream : streamsToClose) {
            const aaudio_handle_t handle = serviceStream->getHandle();
            if (fromFreeze) {
                ALOGW("%s close frozen AAudio stream 0x%08X for pid %d",
                        __func__, handle, mProcessId);
                // if the process is frozen but not dead, we need to disconnect client.
                serviceStream->stop();
                serviceStream->disconnect();
            } else {
                ALOGW("%s close abandoned AAudio stream 0x%08X for pid %d",
                        __func__, handle, mProcessId);
            }
            AAudioHandleInfo handleInfo(DEFAULT_AAUDIO_SERVICE_ID, handle);
            aaudioService->asAAudioServiceInterface().closeStream(handleInfo, true /*force*/);
        }
        // mStreams should be empty now if binder died.
        // If frozen, the openStream rolls back streams created after freeze.
    }

    if (!fromFreeze) {
        // only unregister client on binder died.
        // we need this open for frozen notifications and to ensure closure
        // on binder death.
        const sp<NotificationClient> keep(this);
        AAudioClientTracker::getInstance().unregisterClient(mProcessId);
    }
}

void AAudioClientTracker::NotificationClient::onStateChanged(
        const wp<IBinder>& who, State state) {
    const char* fstring;
    if (state == IBinder::FrozenStateChangeCallback::State::FROZEN) {
        mFrozen = true;
        mFreezeTime = systemTime(SYSTEM_TIME_MONOTONIC);
        fstring = "frozen";
        // We must delay the invalidation until after the freeze transition
        // to prevent creating excessive client activity during transition.
        static constexpr auto kFreezeDelay = std::chrono::milliseconds(100);
        AAudioThread::getAsyncCommandThread().add(
                "NotificationClient::onStateChanged",
                [who, wpThis = wp<AAudioClientTracker::NotificationClient>::fromExisting(this)] {
                    if (auto me = wpThis.promote()) me->closeStream(true /* fromFreeze */);
                }, kFreezeDelay);
    } else if (state == IBinder::FrozenStateChangeCallback::State::UNFROZEN) {
        mFrozen = false;
        fstring = "unfrozen";
    } else {
        ALOGW("%s: unknown state: %d", __func__, state);
        return;
    }
    ALOGD("%s: pid:%d state:%s", __func__, mProcessId, fstring);
}


std::string AAudioClientTracker::NotificationClient::dump() const NO_THREAD_SAFETY_ANALYSIS {
    std::stringstream result;
    const bool isLocked = AAudio_tryUntilTrue(
            [this]()->bool { return mLock.try_lock(); } /* f */,
            50 /* times */,
            20 /* sleepMs */);
    if (!isLocked) {
        result << "AAudioClientTracker::NotificationClient may be deadlocked\n";
    }

    result << "  (" << (mFrozen ? "frozen" : "unfrozen")
           << ") client: pid = " << mProcessId << " has " << mStreams.size() << " streams\n";
    for (const auto& serviceStream : mStreams) {
        result << "     stream: 0x" << std::setfill('0') << std::setw(8) << std::hex
               << serviceStream->getHandle()
               << std::dec << std::setfill(' ') << "\n";
    }

    if (isLocked) {
        mLock.unlock();
    }
    return result.str();
}
