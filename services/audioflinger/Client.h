/*
 * Copyright (C) 2023 The Android Open Source Project
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

#pragma once

#include <afutils/AllocatorFactory.h>
#include <android-base/macros.h>  // DISALLOW_COPY_AND_ASSIGN
#include <utils/Mutex.h>
#include <utils/RefBase.h>        // avoid transitive dependency

// TODO(b/291318727) Move to nested namespace
namespace android {

class IAfPlaybackThread;

class IAfClientCallback : public virtual RefBase {
public:
    virtual Mutex& clientMutex() const = 0;
    virtual void removeClient_l(pid_t pid) = 0;
    virtual void removeNotificationClient(pid_t pid) = 0;
    virtual status_t moveAuxEffectToIo(
            int effectId,
            const sp<IAfPlaybackThread>& dstThread,
            sp<IAfPlaybackThread>* srcThread) = 0;  // used by indirectly by clients.
};

class Client : public RefBase {
public:
    Client(const sp<IAfClientCallback>& audioFlinger, pid_t pid);

    // TODO(b/289139675) make Client container.
    // Client destructor must be called with AudioFlinger::mClientLock held
    ~Client() override;
    AllocatorFactory::ClientAllocator& allocator();
    pid_t pid() const { return mPid; }
    const auto& afClientCallback() const { return mAfClientCallback; }

private:
    DISALLOW_COPY_AND_ASSIGN(Client);

    const sp<IAfClientCallback> mAfClientCallback;
    const pid_t mPid;
    AllocatorFactory::ClientAllocator mClientAllocator;
};

} // namespace android
