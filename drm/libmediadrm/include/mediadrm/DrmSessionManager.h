/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef DRM_SESSION_MANAGER_H_

#define DRM_SESSION_MANAGER_H_

#include <binder/IBinder.h>
#include <media/IResourceManagerService.h>
#include <media/stagefright/foundation/ABase.h>
#include <utils/RefBase.h>
#include <utils/KeyedVector.h>
#include <utils/threads.h>
#include <utils/Vector.h>

#include <map>
#include <utility>
#include <vector>

namespace android {

class DrmSessionManagerTest;
class IResourceManagerClient;

bool isEqualSessionId(const Vector<uint8_t> &sessionId1, const Vector<uint8_t> &sessionId2);

struct SessionInfo {
    pid_t pid;
    uid_t uid;
    int64_t clientId;
};

typedef std::map<std::vector<uint8_t>, SessionInfo> SessionInfoMap;

struct DrmSessionManager : public IBinder::DeathRecipient {
    static sp<DrmSessionManager> Instance();

    DrmSessionManager();
    explicit DrmSessionManager(const sp<IResourceManagerService> &service);

    void addSession(int pid, const sp<IResourceManagerClient>& drm, const Vector<uint8_t>& sessionId);
    void useSession(const Vector<uint8_t>& sessionId);
    void removeSession(const Vector<uint8_t>& sessionId);
    bool reclaimSession(int callingPid);

    // sanity check APIs
    size_t getSessionCount() const;
    bool containsSession(const Vector<uint8_t>& sessionId) const;

    // implements DeathRecipient
    virtual void binderDied(const wp<IBinder>& /*who*/);

protected:
    virtual ~DrmSessionManager();

private:
    void init();

    sp<IResourceManagerService> mService;
    mutable Mutex mLock;
    SessionInfoMap mSessionMap;
    bool mInitialized;

    DISALLOW_EVIL_CONSTRUCTORS(DrmSessionManager);
};

}  // namespace android

#endif  // DRM_SESSION_MANAGER_H_
