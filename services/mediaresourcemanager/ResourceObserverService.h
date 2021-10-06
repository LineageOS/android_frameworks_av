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

#ifndef ANDROID_MEDIA_RESOURCE_OBSERVER_SERVICE_H
#define ANDROID_MEDIA_RESOURCE_OBSERVER_SERVICE_H

#include <map>

#include <aidl/android/media/BnResourceObserverService.h>
#include "ResourceManagerService.h"

namespace android {

using Status = ::ndk::ScopedAStatus;
using ::aidl::android::media::BnResourceObserverService;
using ::aidl::android::media::IResourceObserver;
using ::aidl::android::media::MediaObservableFilter;
using ::aidl::android::media::MediaObservableParcel;
using ::aidl::android::media::MediaObservableType;
using ::aidl::android::media::MediaObservableEvent;

class ResourceObserverService : public BnResourceObserverService {
public:

    static char const *getServiceName() { return "media.resource_observer"; }
    static std::shared_ptr<ResourceObserverService> instantiate();

    virtual inline binder_status_t dump(
            int /*fd*/, const char** /*args*/, uint32_t /*numArgs*/);

    ResourceObserverService();
    virtual ~ResourceObserverService() {}

    // IResourceObserverService interface
    Status registerObserver(const std::shared_ptr<IResourceObserver>& in_observer,
            const std::vector<MediaObservableFilter>& in_filters) override;

    Status unregisterObserver(const std::shared_ptr<IResourceObserver>& in_observer) override;
    // ~IResourceObserverService interface

    // Called by ResourceManagerService when resources are added.
    void onResourceAdded(int uid, int pid, const ResourceList &resources);

    // Called by ResourceManagerService when resources are removed.
    void onResourceRemoved(int uid, int pid, const ResourceList &resources);

private:
    struct ObserverInfo {
        ::ndk::SpAIBinder binder;
        std::shared_ptr<IResourceObserver> observer;
        std::vector<MediaObservableFilter> filters;
    };
    struct DeathRecipient;

    // Below maps are all keyed on the observer's binder ptr value.
    using ObserverInfoMap = std::map<uintptr_t, ObserverInfo>;
    using SubscriberMap = std::map<uintptr_t, std::shared_ptr<IResourceObserver>>;

    std::mutex mObserverLock;
    // Binder->ObserverInfo
    ObserverInfoMap mObserverInfoMap GUARDED_BY(mObserverLock);
    // Observable(<type,event>)->Subscribers
    std::map<MediaObservableFilter, SubscriberMap> mObservableToSubscribersMap
            GUARDED_BY(mObserverLock);

    ::ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;

    // Binder death handling.
    static std::mutex sDeathRecipientLock;
    static std::map<uintptr_t, std::shared_ptr<DeathRecipient>> sDeathRecipientMap
            GUARDED_BY(sDeathRecipientLock);
    static void BinderDiedCallback(void* cookie);

    void notifyObservers(MediaObservableEvent event,
            int uid, int pid, const ResourceList &resources);
};

// ----------------------------------------------------------------------------
} // namespace android

#endif // ANDROID_MEDIA_RESOURCE_OBSERVER_SERVICE_H
