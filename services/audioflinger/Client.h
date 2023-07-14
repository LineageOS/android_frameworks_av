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

// TODO(b/291318727) Move to nested namespace
namespace android {

class AudioFlinger;

class Client : public RefBase {
public:
    Client(const sp<AudioFlinger>& audioFlinger, pid_t pid);

    // TODO(b/289139675) make Client container.
    // Client destructor must be called with AudioFlinger::mClientLock held
    ~Client() override;
    AllocatorFactory::ClientAllocator& allocator();
    pid_t pid() const { return mPid; }
    sp<AudioFlinger> audioFlinger() const { return mAudioFlinger; }

private:
    DISALLOW_COPY_AND_ASSIGN(Client);

    const sp<AudioFlinger> mAudioFlinger;
    const pid_t mPid;
    AllocatorFactory::ClientAllocator mClientAllocator;
};

} // namespace android
