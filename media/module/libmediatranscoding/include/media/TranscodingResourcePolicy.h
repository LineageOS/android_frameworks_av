/*
 * Copyright (C) 2020 The Android Open Source Project
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

#ifndef ANDROID_MEDIA_TRANSCODING_RESOURCE_POLICY_H
#define ANDROID_MEDIA_TRANSCODING_RESOURCE_POLICY_H

#include <android/binder_auto_utils.h>
#include <media/ResourcePolicyInterface.h>
#include <utils/Condition.h>

#include <mutex>
#include <set>
namespace aidl {
namespace android {
namespace media {
class IResourceObserverService;
}
}  // namespace android
}  // namespace aidl

namespace android {

using ::aidl::android::media::IResourceObserverService;

class TranscodingResourcePolicy : public ResourcePolicyInterface {
public:
    explicit TranscodingResourcePolicy();
    ~TranscodingResourcePolicy();

    void setCallback(const std::shared_ptr<ResourcePolicyCallbackInterface>& cb) override;
    void setPidResourceLost(pid_t pid) override;

private:
    struct ResourceObserver;
    mutable std::mutex mRegisteredLock;
    bool mRegistered GUARDED_BY(mRegisteredLock);
    std::shared_ptr<IResourceObserverService> mService GUARDED_BY(mRegisteredLock);
    std::shared_ptr<ResourceObserver> mObserver;
    mutable std::mutex mCookieKeysLock;
    std::set<uintptr_t> mCookieKeys;

    mutable std::mutex mCallbackLock;
    std::weak_ptr<ResourcePolicyCallbackInterface> mResourcePolicyCallback
            GUARDED_BY(mCallbackLock);
    pid_t mResourceLostPid GUARDED_BY(mCallbackLock);

    ::ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;

    static void BinderDiedCallback(void* cookie);

    void registerSelf();
    // must delete the associated TranscodingResourcePolicyCookie any time this is called
    void unregisterSelf();
    void onResourceAvailable(pid_t pid);
};  // class TranscodingUidPolicy

}  // namespace android
#endif  // ANDROID_MEDIA_TRANSCODING_RESOURCE_POLICY_H
