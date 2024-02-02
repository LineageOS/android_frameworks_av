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

#ifndef ANDROID_MEDIA_RESOURCEMANAGERSERVICEUTILS_H_
#define ANDROID_MEDIA_RESOURCEMANAGERSERVICEUTILS_H_

#include <map>
#include <set>
#include <memory>
#include <vector>

#include <aidl/android/media/BnResourceManagerService.h>
#include <media/MediaResource.h>
#include <utils/String8.h>

namespace android {

class ResourceManagerService;

/*
 * Death Notifier to track IResourceManagerClient's death.
 */
class DeathNotifier : public std::enable_shared_from_this<DeathNotifier> {

    // BinderDiedContext defines the cookie that is passed as DeathRecipient.
    // Since this can maintain more context than a raw pointer, we can
    // validate the scope of DeathNotifier, before deferencing it upon the binder death.
    struct BinderDiedContext {
        std::weak_ptr<DeathNotifier> mDeathNotifier;
    };
public:
    static std::shared_ptr<DeathNotifier> Create(
        const std::shared_ptr<::aidl::android::media::IResourceManagerClient>& client,
        const std::weak_ptr<ResourceManagerService>& service,
        const ::aidl::android::media::ClientInfoParcel& clientInfo,
        bool overrideProcessInfo = false);

    DeathNotifier(const std::shared_ptr<::aidl::android::media::IResourceManagerClient>& client,
                  const std::weak_ptr<ResourceManagerService>& service,
                  const ::aidl::android::media::ClientInfoParcel& clientInfo);

    virtual ~DeathNotifier() {
        unlink();
    }

    // Implement death recipient
    static void BinderDiedCallback(void* cookie);
    static void BinderUnlinkedCallback(void* cookie);
    virtual void binderDied();

private:
    void link() {
        // Create the context that is passed as cookie to the binder death notification.
        // The context gets deleted at BinderUnlinkedCallback.
        mCookie = new BinderDiedContext{.mDeathNotifier = weak_from_this()};
        // Register for the callbacks by linking to death notification.
        AIBinder_linkToDeath(mClient->asBinder().get(), mDeathRecipient.get(), mCookie);
    }

    void unlink() {
        if (mClient != nullptr) {
            // Unlink from the death notification.
            AIBinder_unlinkToDeath(mClient->asBinder().get(), mDeathRecipient.get(), mCookie);
            mClient = nullptr;
        }
    }

protected:
    std::shared_ptr<::aidl::android::media::IResourceManagerClient> mClient;
    std::weak_ptr<ResourceManagerService> mService;
    const ::aidl::android::media::ClientInfoParcel mClientInfo;
    BinderDiedContext* mCookie;
    ::ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;
};

class OverrideProcessInfoDeathNotifier : public DeathNotifier {
public:
    OverrideProcessInfoDeathNotifier(
        const std::shared_ptr<::aidl::android::media::IResourceManagerClient>& client,
        const std::weak_ptr<ResourceManagerService>& service,
        const ::aidl::android::media::ClientInfoParcel& clientInfo)
            : DeathNotifier(client, service, clientInfo) {}

    virtual ~OverrideProcessInfoDeathNotifier() {}

    virtual void binderDied();
};

// Encapsulate Resource List as vector of resources instead of map.
// Since the number of resource is very limited, maintaining it as
// std::vector helps with both performance and memory requiremnts.
struct ResourceList {
    // Add or Update an entry into ResourceList.
    // If a new entry is added, isNewEntry will be set to true upon return
    // returns true on successful update, false otherwise.
    bool add(const ::aidl::android::media::MediaResourceParcel& res, bool* isNewEntry = nullptr);

    // reduce the resource usage by subtracting the resource value.
    // If the resource value is 0 after reducing the resource usage,
    // that entry will be removed and removedEntryValue is set to the
    // value before it was removed upon return otherwise it will be set to -1.
    // returns true on successful removal of the resource, false otherwise.
    bool remove(const ::aidl::android::media::MediaResourceParcel& res,
                long* removedEntryValue = nullptr);

    // Returns true if there aren't any resource entries.
    bool empty() const {
        return mResourceList.empty();
    }

    // Returns resource list as a non-modifiable vectors
    const std::vector<::aidl::android::media::MediaResourceParcel>& getResources() const {
        return mResourceList;
    }

    // Converts resource list into string format
    std::string toString() const;

    // BEGIN: Test only function
    // Check if two resource lists are the same.
    bool operator==(const ResourceList& rhs) const;

    // Add or Update an entry into ResourceList.
    void addOrUpdate(const ::aidl::android::media::MediaResourceParcel& res);
    // END: Test only function

private:
    std::vector<::aidl::android::media::MediaResourceParcel> mResourceList;
};

// Encapsulation for Resource Info, that contains
// - pid of the app
// - uid of the app
// - client id
// - name of the client (specifically for the codec)
// - the client associted with it
// - death notifier for the (above) client
// - list of resources associated with it
// - A flag that marks whether this resource is pending to be removed.
struct ResourceInfo {
    pid_t pid;
    uid_t uid;
    int64_t clientId;
    std::string name;
    std::shared_ptr<::aidl::android::media::IResourceManagerClient> client;
    std::shared_ptr<DeathNotifier> deathNotifier = nullptr;
    ResourceList resources;
    bool pendingRemoval{false};
    uint32_t importance = 0;
};

/*
 * Resource Reclaim request info that encapsulates
 *  - the calling/requesting process pid.
 *  - id of the client that made reclaim request.
 *  - the calling/requesting client's importance.
 *  - the list of resources requesting (to be reclaimed from others)
 */
struct ReclaimRequestInfo {
    int mCallingPid = -1;
    int64_t mClientId = 0;
    uint32_t mCallingClientImportance = 0;
    const std::vector<::aidl::android::media::MediaResourceParcel>& mResources;
};

/*
 * Resource request info that encapsulates
 *  - the calling/requesting process pid.
 *  - the calling/requesting client's id.
 *  - the resource requesting (to be reclaimed from others)
 */
struct ResourceRequestInfo {
    // pid of the calling/requesting process.
    int mCallingPid = -1;
    // id of the calling/requesting client.
    int64_t mClientId = 0;
    // resources requested.
    const ::aidl::android::media::MediaResourceParcel* mResource;
};

/*
 * Structure that defines the Client - a possible target to relcaim from.
 * This encapsulates pid, uid of the process and the client id
 * based on the reclaim policy.
 */
struct ClientInfo {
    // pid of the process.
    pid_t mPid = -1;
    // uid of the process.
    uid_t mUid = -1;
    // Client Id.
    int64_t mClientId = -1;
    ClientInfo(pid_t pid = -1, uid_t uid = -1, const int64_t& clientId = -1)
        : mPid(pid), mUid(uid), mClientId(clientId) {}
};

// Map of Resource information index through the client id.
typedef std::map<int64_t, ResourceInfo> ResourceInfos;

// Map of Resource information indexed through the process id.
typedef std::map<int, ResourceInfos> PidResourceInfosMap;

// templated function to stringify the given vector of items.
template <typename T>
String8 getString(const std::vector<T>& items) {
    String8 itemsStr;
    for (size_t i = 0; i < items.size(); ++i) {
        itemsStr.appendFormat("%s ", toString(items[i]).c_str());
    }
    return itemsStr;
}

// Bunch of utility functions that looks for a specific Resource.

//Check whether a given resource (of type and subtype) is found in given resource parcel.
bool hasResourceType(MediaResource::Type type, MediaResource::SubType subType,
                     const ::aidl::android::media::MediaResourceParcel& resource);

//Check whether a given resource (of type and subtype) is found in given resource list.
bool hasResourceType(MediaResource::Type type, MediaResource::SubType subType,
                     const ResourceList& resources);

//Check whether a given resource (of type and subtype) is found in given resource info list.
bool hasResourceType(MediaResource::Type type, MediaResource::SubType subType,
                     const ResourceInfos& infos);

// Return modifiable list of ResourceInfo for a given process (look up by pid)
// from the map of ResourceInfos.
ResourceInfos& getResourceInfosForEdit(int pid, PidResourceInfosMap& map);

// Return modifiable ResourceInfo for a given process (look up by pid)
// from the map of ResourceInfos.
// If the item is not in the map, create one and add it to the map.
ResourceInfo& getResourceInfoForEdit(
        const aidl::android::media::ClientInfoParcel& clientInfo,
        const std::shared_ptr<aidl::android::media::IResourceManagerClient>& client,
        ResourceInfos& infos);

// Merge resources from r2 into r1.
void mergeResources(::aidl::android::media::MediaResourceParcel& r1,
                    const ::aidl::android::media::MediaResourceParcel& r2);

// To notify the media_resource_monitor about the resource being granted.
void notifyResourceGranted(
        int pid,
        const std::vector<::aidl::android::media::MediaResourceParcel>& resources);

} // namespace android

#endif //ANDROID_MEDIA_RESOURCEMANAGERSERVICEUTILS_H_
