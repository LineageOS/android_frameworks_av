/**
 *
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "ResourceObserverService"
#include <utils/Log.h>

#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <binder/IServiceManager.h>
#include <utils/String16.h>
#include <aidl/android/media/MediaResourceParcel.h>

#include "ResourceObserverService.h"

namespace android {

using ::aidl::android::media::MediaResourceParcel;
using ::aidl::android::media::MediaObservableEvent;

// MediaObservableEvent will be used as uint64_t flags.
static_assert(sizeof(MediaObservableEvent) == sizeof(uint64_t));

static std::vector<MediaObservableEvent> sEvents = {
        MediaObservableEvent::kBusy,
        MediaObservableEvent::kIdle,
};

static MediaObservableType getObservableType(const MediaResourceParcel& res) {
    if (res.subType == MediaResourceSubType::kHwVideoCodec ||
        res.subType == MediaResourceSubType::kSwVideoCodec) {
        if (res.type == MediaResourceType::kNonSecureCodec) {
            return MediaObservableType::kVideoNonSecureCodec;
        }
        if (res.type == MediaResourceType::kSecureCodec) {
            return MediaObservableType::kVideoSecureCodec;
        }
    }
    return MediaObservableType::kInvalid;
}

//static
std::mutex ResourceObserverService::sDeathRecipientLock;
//static
std::map<uintptr_t, std::shared_ptr<ResourceObserverService::DeathRecipient> >
ResourceObserverService::sDeathRecipientMap;

struct ResourceObserverService::DeathRecipient {
    DeathRecipient(ResourceObserverService* _service,
            const std::shared_ptr<IResourceObserver>& _observer)
        : service(_service), observer(_observer) {}
    ~DeathRecipient() {}

    void binderDied() {
        if (service != nullptr) {
            service->unregisterObserver(observer);
        }
    }

    ResourceObserverService* service;
    std::shared_ptr<IResourceObserver> observer;
};

// static
void ResourceObserverService::BinderDiedCallback(void* cookie) {
    uintptr_t id = reinterpret_cast<uintptr_t>(cookie);

    ALOGW("Observer %lld is dead", (long long)id);

    std::shared_ptr<DeathRecipient> recipient;

    {
        std::scoped_lock lock{sDeathRecipientLock};

        auto it = sDeathRecipientMap.find(id);
        if (it != sDeathRecipientMap.end()) {
            recipient = it->second;
        }
    }

    if (recipient != nullptr) {
        recipient->binderDied();
    }
}

//static
std::shared_ptr<ResourceObserverService> ResourceObserverService::instantiate() {
    std::shared_ptr<ResourceObserverService> observerService =
            ::ndk::SharedRefBase::make<ResourceObserverService>();
    binder_status_t status = AServiceManager_addServiceWithFlags(
      observerService->asBinder().get(),ResourceObserverService::getServiceName(),
      AServiceManager_AddServiceFlag::ADD_SERVICE_ALLOW_ISOLATED);

    if (status != STATUS_OK) {
        return nullptr;
    }
    return observerService;
}

ResourceObserverService::ResourceObserverService()
    : mDeathRecipient(AIBinder_DeathRecipient_new(BinderDiedCallback)) {}

binder_status_t ResourceObserverService::dump(
        int fd, const char** /*args*/, uint32_t /*numArgs*/) {
    String8 result;

    if (checkCallingPermission(String16("android.permission.DUMP")) == false) {
        result.format("Permission Denial: "
                "can't dump ResourceManagerService from pid=%d, uid=%d\n",
                AIBinder_getCallingPid(),
                AIBinder_getCallingUid());
        write(fd, result.c_str(), result.size());
        return PERMISSION_DENIED;
    }

    result.appendFormat("ResourceObserverService: %p\n", this);
    result.appendFormat("  Registered Observers: %zu\n", mObserverInfoMap.size());

    {
        std::scoped_lock lock{mObserverLock};

        for (auto &observer : mObserverInfoMap) {
            result.appendFormat("    Observer %p:\n", observer.second.binder.get());
            for (auto &observable : observer.second.filters) {
                String8 enabledEventsStr;
                for (auto &event : sEvents) {
                    if (((uint64_t)observable.eventFilter & (uint64_t)event) != 0) {
                        if (!enabledEventsStr.empty()) {
                            enabledEventsStr.append("|");
                        }
                        enabledEventsStr.append(toString(event).c_str());
                    }
                }
                result.appendFormat("      %s: %s\n",
                        toString(observable.type).c_str(), enabledEventsStr.c_str());
            }
        }
    }

    write(fd, result.c_str(), result.size());
    return OK;
}

Status ResourceObserverService::registerObserver(
        const std::shared_ptr<IResourceObserver>& in_observer,
        const std::vector<MediaObservableFilter>& in_filters) {
    if ((getpid() != AIBinder_getCallingPid()) &&
            checkCallingPermission(
            String16("android.permission.REGISTER_MEDIA_RESOURCE_OBSERVER")) == false) {
        ALOGE("Permission Denial: "
                "can't registerObserver from pid=%d, uid=%d\n",
                AIBinder_getCallingPid(),
                AIBinder_getCallingUid());
        return Status::fromServiceSpecificError(PERMISSION_DENIED);
    }

    if (in_observer == nullptr) {
        return Status::fromServiceSpecificError(BAD_VALUE);
    }

    ::ndk::SpAIBinder binder = in_observer->asBinder();

    {
        std::scoped_lock lock{mObserverLock};

        if (mObserverInfoMap.find((uintptr_t)binder.get()) != mObserverInfoMap.end()) {
            return Status::fromServiceSpecificError(ALREADY_EXISTS);
        }

        if (in_filters.empty()) {
            return Status::fromServiceSpecificError(BAD_VALUE);
        }

        // Add observer info.
        mObserverInfoMap.emplace((uintptr_t)binder.get(),
                ObserverInfo{binder, in_observer, in_filters});

        // Add observer to observable->subscribers map.
        for (auto &filter : in_filters) {
            for (auto &event : sEvents) {
                if (!((uint64_t)filter.eventFilter & (uint64_t)event)) {
                    continue;
                }
                MediaObservableFilter key{filter.type, event};
                mObservableToSubscribersMap[key].emplace((uintptr_t)binder.get(), in_observer);
            }
        }
    }

    // Add death binder and link.
    uintptr_t cookie = (uintptr_t)binder.get();
    {
        std::scoped_lock lock{sDeathRecipientLock};
        sDeathRecipientMap.emplace(
                cookie, std::make_shared<DeathRecipient>(this, in_observer));
    }

    AIBinder_linkToDeath(binder.get(), mDeathRecipient.get(),
                         reinterpret_cast<void*>(cookie));

    return Status::ok();
}

Status ResourceObserverService::unregisterObserver(
        const std::shared_ptr<IResourceObserver>& in_observer) {
    if ((getpid() != AIBinder_getCallingPid()) &&
            checkCallingPermission(
            String16("android.permission.REGISTER_MEDIA_RESOURCE_OBSERVER")) == false) {
        ALOGE("Permission Denial: "
                "can't unregisterObserver from pid=%d, uid=%d\n",
                AIBinder_getCallingPid(),
                AIBinder_getCallingUid());
        return Status::fromServiceSpecificError(PERMISSION_DENIED);
    }

    if (in_observer == nullptr) {
        return Status::fromServiceSpecificError(BAD_VALUE);
    }

    ::ndk::SpAIBinder binder = in_observer->asBinder();

    {
        std::scoped_lock lock{mObserverLock};

        auto it = mObserverInfoMap.find((uintptr_t)binder.get());
        if (it == mObserverInfoMap.end()) {
            return Status::fromServiceSpecificError(NAME_NOT_FOUND);
        }

        // Remove observer from observable->subscribers map.
        for (auto &filter : it->second.filters) {
            for (auto &event : sEvents) {
                if (!((uint64_t)filter.eventFilter & (uint64_t)event)) {
                    continue;
                }
                MediaObservableFilter key{filter.type, event};
                mObservableToSubscribersMap[key].erase((uintptr_t)binder.get());

                //Remove the entry if there's no more subscribers.
                if (mObservableToSubscribersMap[key].empty()) {
                    mObservableToSubscribersMap.erase(key);
                }
            }
        }

        // Remove observer info.
        mObserverInfoMap.erase(it);
    }

    // Unlink and remove death binder.
    uintptr_t cookie = (uintptr_t)binder.get();
    AIBinder_unlinkToDeath(binder.get(), mDeathRecipient.get(),
            reinterpret_cast<void*>(cookie));

    {
        std::scoped_lock lock{sDeathRecipientLock};
        sDeathRecipientMap.erase(cookie);
    }

    return Status::ok();
}

void ResourceObserverService::notifyObservers(
        MediaObservableEvent event, int uid, int pid, const ResourceList &resources) {
    struct CalleeInfo {
        std::shared_ptr<IResourceObserver> observer;
        std::vector<MediaObservableParcel> monitors;
    };
    // Build a consolidated list of observers to call with their respective observables.
    std::map<uintptr_t, CalleeInfo> calleeList;

    {
        std::scoped_lock lock{mObserverLock};

        for (const MediaResourceParcel& res : resources.getResources()) {
            // Skip if this resource doesn't map to any observable type.
            MediaObservableType observableType = getObservableType(res);
            if (observableType == MediaObservableType::kInvalid) {
                continue;
            }
            MediaObservableFilter key{observableType, event};
            // Skip if no one subscribed to this observable.
            auto observableIt = mObservableToSubscribersMap.find(key);
            if (observableIt == mObservableToSubscribersMap.end()) {
                continue;
            }
            // Loop through all subsribers.
            for (auto &subscriber : observableIt->second) {
                auto calleeIt = calleeList.find(subscriber.first);
                if (calleeIt == calleeList.end()) {
                    calleeList.emplace(subscriber.first, CalleeInfo{
                        subscriber.second, {{observableType, res.value}}});
                } else {
                    calleeIt->second.monitors.push_back({observableType, res.value});
                }
            }
        }
    }

    // Finally call the observers about the status change.
    for (auto &calleeInfo : calleeList) {
        calleeInfo.second.observer->onStatusChanged(
                event, uid, pid, calleeInfo.second.monitors);
    }
}

void ResourceObserverService::onResourceAdded(
        int uid, int pid, const ResourceList &resources) {
    notifyObservers(MediaObservableEvent::kBusy, uid, pid, resources);
}

void ResourceObserverService::onResourceRemoved(
        int uid, int pid, const ResourceList &resources) {
    notifyObservers(MediaObservableEvent::kIdle, uid, pid, resources);
}

} // namespace android
