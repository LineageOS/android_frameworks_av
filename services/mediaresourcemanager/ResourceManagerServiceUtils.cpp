/*
**
** Copyright 2023, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

//#define LOG_NDEBUG 0
#define LOG_TAG "ResourceManagerServiceUtils"
#include <utils/Log.h>

#include <binder/IServiceManager.h>

#include "IMediaResourceMonitor.h"
#include "ResourceManagerService.h"
#include "ResourceManagerServiceUtils.h"

namespace android {

bool ResourceList::add(const MediaResourceParcel& res, bool* isNewEntry) {
    // See if it's an existing entry, if so, merge it.
    for (MediaResourceParcel& item : mResourceList) {
        if (item.type == res.type && item.subType == res.subType && item.id == res.id) {
            // We already have an item. Merge them and return
            mergeResources(item, res);
            return true;
        }
    }

    // Since we have't found this resource yet, it is a new entry.
    // We can't init a new entry with negative value, although it's allowed
    // to merge in negative values after the initial add.
    if (res.value <= 0) {
        ALOGW("Ignoring request to add new resource entry with value <= 0");
        return false;
    }
    if (isNewEntry) {
        *isNewEntry = true;
    }
    mResourceList.push_back(res);
    return true;
}

void ResourceList::addOrUpdate(const MediaResourceParcel& res) {
    // See if it's an existing entry, just update the value.
    for (MediaResourceParcel& item : mResourceList) {
        if (item.type == res.type && item.subType == res.subType && item.id == res.id) {
            item.value = res.value;
            return;
        }
    }

    // Add the new entry.
    mResourceList.push_back(res);
}

bool ResourceList::remove(const MediaResourceParcel& res, long* removedEntryValue) {
    // Make sure we have an entry for this resource.
    for (std::vector<MediaResourceParcel>::iterator it = mResourceList.begin();
         it != mResourceList.end(); it++) {
        if (it->type == res.type && it->subType == res.subType && it->id == res.id) {
            if (it->value > res.value) {
                // Subtract the resource value by given value.
                it->value -= res.value;
            } else {
                // This entry will be removed.
                if (removedEntryValue) {
                    *removedEntryValue = it->value;
                }
                mResourceList.erase(it);
            }
            return true;
        }
    }

    // No such entry.
    return false;
}

std::string ResourceList::toString() const {
    std::string str;
    for (const ::aidl::android::media::MediaResourceParcel& res : mResourceList) {
        str.append(android::toString(res).c_str());
        str.append("\n");
    }

    return std::move(str);
}

bool ResourceList::operator==(const ResourceList& rhs) const {
    // Make sure the size is the same.
    if (mResourceList.size() != rhs.mResourceList.size()) {
        return false;
    }

    // Create a set from this object and check for the items from the rhs.
    std::set<::aidl::android::media::MediaResourceParcel> lhs(
            mResourceList.begin(), mResourceList.end());
    for (const ::aidl::android::media::MediaResourceParcel& res : rhs.mResourceList) {
        if (lhs.find(res) == lhs.end()) {
            return false;
        }
    }
    return true;
}

// Bunch of utility functions that looks for a specific Resource.
// Check whether a given resource (of type and subtype) is found in given resource parcel.
bool hasResourceType(MediaResource::Type type, MediaResource::SubType subType,
                     const MediaResourceParcel& resource) {
    if (type != resource.type) {
      return false;
    }
    switch (type) {
    // Codec subtypes (e.g. video vs. audio and hw vs. sw) are each considered separate resources,
    // so compare the subtypes as well.
    case MediaResource::Type::kSecureCodec:
    case MediaResource::Type::kNonSecureCodec:
        if (resource.subType == subType) {
            return true;
        }
        break;
    // Non-codec resources are not segregated by the subtype (e.g. video vs. audio).
    default:
        return true;
    }
    return false;
}

// Check whether a given resource (of type and subtype) is found in given resource list.
bool hasResourceType(MediaResource::Type type, MediaResource::SubType subType,
                     const ResourceList& resources) {
    for (const MediaResourceParcel& res : resources.getResources()) {
        if (hasResourceType(type, subType, res)) {
            return true;
        }
    }
    return false;
}

// Check whether a given resource (of type and subtype) is found in given resource info list.
bool hasResourceType(MediaResource::Type type, MediaResource::SubType subType,
                     const ResourceInfos& infos) {
    for (const auto& [id, info] : infos) {
        if (hasResourceType(type, subType, info.resources)) {
            return true;
        }
    }
    return false;
}

ResourceInfos& getResourceInfosForEdit(int pid, PidResourceInfosMap& map) {
    PidResourceInfosMap::iterator found = map.find(pid);
    if (found == map.end()) {
        // new pid
        ResourceInfos infosForPid;
        auto [it, inserted] = map.emplace(pid, infosForPid);
        found = it;
    }

    return found->second;
}

// Return modifiable ResourceInfo for a given client (look up by client id)
// from the map of ResourceInfos.
// If the item is not in the map, create one and add it to the map.
ResourceInfo& getResourceInfoForEdit(const ClientInfoParcel& clientInfo,
                                     const std::shared_ptr<IResourceManagerClient>& client,
                                     ResourceInfos& infos) {
    ResourceInfos::iterator found = infos.find(clientInfo.id);
    if (found == infos.end()) {
        ResourceInfo info{.pid = clientInfo.pid,
                          .uid = static_cast<uid_t>(clientInfo.uid),
                          .clientId = clientInfo.id,
                          .name = clientInfo.name.empty()? "<unknown client>" : clientInfo.name,
                          .client = client,
                          .deathNotifier = nullptr,
                          .pendingRemoval = false,
                          .importance = static_cast<uint32_t>(std::max(0, clientInfo.importance))};
        auto [it, inserted] = infos.emplace(clientInfo.id, info);
        found = it;
    }

    return found->second;
}

// Merge resources from r2 into r1.
void mergeResources(MediaResourceParcel& r1, const MediaResourceParcel& r2) {
    // The resource entry on record is maintained to be in [0,INT64_MAX].
    // Clamp if merging in the new resource value causes it to go out of bound.
    // Note that the new resource value could be negative, eg.DrmSession, the
    // value goes lower when the session is used more often. During reclaim
    // the session with the highest value (lowest usage) would be closed.
    if (r2.value < INT64_MAX - r1.value) {
        r1.value += r2.value;
        if (r1.value < 0) {
            r1.value = 0;
        }
    } else {
        r1.value = INT64_MAX;
    }
}

///////////////////////////////////////////////////////////////////////
////////////// Death Notifier implementation   ////////////////////////
///////////////////////////////////////////////////////////////////////

DeathNotifier::DeathNotifier(const std::shared_ptr<IResourceManagerClient>& client,
                             const std::weak_ptr<ResourceManagerService>& service,
                             const ClientInfoParcel& clientInfo)
    : mClient(client), mService(service), mClientInfo(clientInfo),
      mCookie(nullptr),
      mDeathRecipient(::ndk::ScopedAIBinder_DeathRecipient(
                      AIBinder_DeathRecipient_new(BinderDiedCallback))) {
    // Setting callback notification when DeathRecipient gets deleted.
    AIBinder_DeathRecipient_setOnUnlinked(mDeathRecipient.get(), BinderUnlinkedCallback);
}

//static
void DeathNotifier::BinderUnlinkedCallback(void* cookie) {
    BinderDiedContext* context = reinterpret_cast<BinderDiedContext*>(cookie);
    // Since we don't need the context anymore, we are deleting it now.
    delete context;
}

//static
void DeathNotifier::BinderDiedCallback(void* cookie) {
    BinderDiedContext* context = reinterpret_cast<BinderDiedContext*>(cookie);

    // Validate the context and check if the DeathNotifier object is still in scope.
    if (context != nullptr) {
        std::shared_ptr<DeathNotifier> thiz = context->mDeathNotifier.lock();
        if (thiz != nullptr) {
            thiz->binderDied();
        } else {
            ALOGI("DeathNotifier is out of scope already");
        }
    }
}

void DeathNotifier::binderDied() {
    // Don't check for pid validity since we know it's already dead.
    std::shared_ptr<ResourceManagerService> service = mService.lock();
    if (service == nullptr) {
        ALOGW("ResourceManagerService is dead as well.");
        return;
    }

    service->overridePid(mClientInfo.pid, -1);
    // thiz is freed in the call below, so it must be last call referring thiz
    service->removeResource(mClientInfo, false /*checkValid*/);
}

void OverrideProcessInfoDeathNotifier::binderDied() {
    // Don't check for pid validity since we know it's already dead.
    std::shared_ptr<ResourceManagerService> service = mService.lock();
    if (service == nullptr) {
        ALOGW("ResourceManagerService is dead as well.");
        return;
    }

    service->removeProcessInfoOverride(mClientInfo.pid);
}

std::shared_ptr<DeathNotifier> DeathNotifier::Create(
    const std::shared_ptr<IResourceManagerClient>& client,
    const std::weak_ptr<ResourceManagerService>& service,
    const ClientInfoParcel& clientInfo,
    bool overrideProcessInfo) {
    std::shared_ptr<DeathNotifier> deathNotifier = nullptr;
    if (overrideProcessInfo) {
        deathNotifier = std::make_shared<OverrideProcessInfoDeathNotifier>(
            client, service, clientInfo);
    } else {
        deathNotifier = std::make_shared<DeathNotifier>(client, service, clientInfo);
    }

    if (deathNotifier) {
        deathNotifier->link();
    }

    return deathNotifier;
}

void notifyResourceGranted(int pid, const std::vector<MediaResourceParcel>& resources) {
    static const char* const kServiceName = "media_resource_monitor";
    sp<IBinder> binder = defaultServiceManager()->checkService(String16(kServiceName));
    if (binder != NULL) {
        sp<IMediaResourceMonitor> service = interface_cast<IMediaResourceMonitor>(binder);
        for (size_t i = 0; i < resources.size(); ++i) {
            switch (resources[i].subType) {
                case MediaResource::SubType::kHwAudioCodec:
                case MediaResource::SubType::kSwAudioCodec:
                    service->notifyResourceGranted(pid, IMediaResourceMonitor::TYPE_AUDIO_CODEC);
                    break;
                case MediaResource::SubType::kHwVideoCodec:
                case MediaResource::SubType::kSwVideoCodec:
                    service->notifyResourceGranted(pid, IMediaResourceMonitor::TYPE_VIDEO_CODEC);
                    break;
                case MediaResource::SubType::kHwImageCodec:
                case MediaResource::SubType::kSwImageCodec:
                    service->notifyResourceGranted(pid, IMediaResourceMonitor::TYPE_IMAGE_CODEC);
                    break;
                case MediaResource::SubType::kUnspecifiedSubType:
                    break;
            }
        }
    }
}

} // namespace android
