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


#define LOG_TAG "AAudioService"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <assert.h>
#include <binder/IPCThreadState.h>
#include <map>
#include <mutex>
#include <utils/Singleton.h>

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

// Create a tracker for the client.
aaudio_result_t AAudioClientTracker::registerClient(pid_t pid,
                                         const sp<IAAudioClient>& client) {
    ALOGD("AAudioClientTracker::registerClient(), calling pid = %d, getpid() = %d\n",
          pid, getpid());

    std::lock_guard<std::mutex> lock(mLock);
    if (mNotificationClients.count(pid) == 0) {
        sp<NotificationClient> notificationClient = new NotificationClient(pid);
        mNotificationClients[pid] = notificationClient;

        sp<IBinder> binder = IInterface::asBinder(client);
        status_t status = binder->linkToDeath(notificationClient);
        ALOGW_IF(status != NO_ERROR,
                 "AAudioClientTracker::registerClient() linkToDeath = %d\n", status);
        return AAudioConvert_androidToAAudioResult(status);
    } else {
        ALOGW("AAudioClientTracker::registerClient(%d) already registered!", pid);
        return AAUDIO_OK; // TODO should this be considered an error
    }
}

void AAudioClientTracker::unregisterClient(pid_t pid) {
    ALOGD("AAudioClientTracker::unregisterClient(), calling pid = %d, getpid() = %d\n",
          pid, getpid());
    std::lock_guard<std::mutex> lock(mLock);
    mNotificationClients.erase(pid);
}

aaudio_result_t
AAudioClientTracker::registerClientStream(pid_t pid, sp<AAudioServiceStreamBase> serviceStream) {
    aaudio_result_t result = AAUDIO_OK;
    ALOGV("AAudioClientTracker::registerClientStream(%d, %p)\n", pid, serviceStream.get());
    std::lock_guard<std::mutex> lock(mLock);
    sp<NotificationClient> notificationClient = mNotificationClients[pid];
    if (notificationClient == 0) {
        // This will get called the first time the audio server registers an internal stream.
        ALOGV("AAudioClientTracker::registerClientStream(%d,) unrecognized pid\n", pid);
        notificationClient = new NotificationClient(pid);
        mNotificationClients[pid] = notificationClient;
    }
    notificationClient->registerClientStream(serviceStream);
    return result;
}

// Find the tracker for this process and remove it.
aaudio_result_t
AAudioClientTracker::unregisterClientStream(pid_t pid,
                                            sp<AAudioServiceStreamBase> serviceStream) {
    ALOGV("AAudioClientTracker::unregisterClientStream(%d, %p)\n", pid, serviceStream.get());
    std::lock_guard<std::mutex> lock(mLock);
    std::map<pid_t, android::sp<NotificationClient>>::iterator it;
    it = mNotificationClients.find(pid);
    if (it != mNotificationClients.end()) {
        it->second->unregisterClientStream(serviceStream);
    }
    return AAUDIO_OK;
}

AAudioClientTracker::NotificationClient::NotificationClient(pid_t pid)
        : mProcessId(pid) {
    //ALOGD("AAudioClientTracker::NotificationClient(%d) created %p\n", pid, this);
}

AAudioClientTracker::NotificationClient::~NotificationClient() {
    //ALOGD("AAudioClientTracker::~NotificationClient() destroyed %p\n", this);
}

aaudio_result_t AAudioClientTracker::NotificationClient::registerClientStream(
        sp<AAudioServiceStreamBase> serviceStream) {
    std::lock_guard<std::mutex> lock(mLock);
    mStreams.insert(serviceStream);
    return AAUDIO_OK;
}

aaudio_result_t AAudioClientTracker::NotificationClient::unregisterClientStream(
        sp<AAudioServiceStreamBase> serviceStream) {
    std::lock_guard<std::mutex> lock(mLock);
    mStreams.erase(serviceStream);
    return AAUDIO_OK;
}

// Close any open streams for the client.
void AAudioClientTracker::NotificationClient::binderDied(const wp<IBinder>& who __unused) {
    AAudioService *aaudioService = AAudioClientTracker::getInstance().getAAudioService();
    if (aaudioService != nullptr) {
        // Copy the current list of streams to another vector because closing them below
        // will cause unregisterClientStream() calls back to this object.
        std::set<android::sp<AAudioServiceStreamBase>>  streamsToClose;

        {
            std::lock_guard<std::mutex> lock(mLock);
            ALOGV("AAudioClientTracker::binderDied() pid = %d, # streams = %d\n",
                  mProcessId, (int) mStreams.size());
            for (auto serviceStream : mStreams) {
                streamsToClose.insert(serviceStream);
            }
        }

        for (auto serviceStream : streamsToClose) {
            aaudio_handle_t handle = serviceStream->getHandle();
            ALOGW("AAudioClientTracker::binderDied() close abandoned stream 0x%08X\n", handle);
            aaudioService->closeStream(handle);
        }
        // mStreams should be empty now
    }
    sp<NotificationClient> keep(this);
    AAudioClientTracker::getInstance().unregisterClient(mProcessId);
}
