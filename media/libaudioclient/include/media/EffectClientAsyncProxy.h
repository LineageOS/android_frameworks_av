/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <android/media/BnEffectClient.h>
#include <audio_utils/CommandThread.h>

namespace android::media {

class EffectClientAsyncProxy : public IEffectClient {
public:

    /**
     * Call this factory method to interpose a worker thread when a binder
     * callback interface is invoked in-proc.
     */
    static sp<IEffectClient> makeIfNeeded(const sp<IEffectClient>& effectClient) {
        if (isLocalBinder(effectClient)) {
            return sp<EffectClientAsyncProxy>::make(effectClient);
        }
        return effectClient;
    }

    explicit EffectClientAsyncProxy(const sp<IEffectClient>& effectClient)
        : mEffectClient(effectClient) {}

    ::android::IBinder* onAsBinder() override {
        return nullptr;
    }

    ::android::binder::Status controlStatusChanged(bool controlGranted) override {
        getThread().add(__func__, [=, effectClient = mEffectClient]() {
            effectClient->controlStatusChanged(controlGranted);
        });
        return ::android::binder::Status::fromStatusT(::android::NO_ERROR);
    }

    ::android::binder::Status enableStatusChanged(bool enabled) override {
        getThread().add(__func__, [=, effectClient = mEffectClient]() {
            effectClient->enableStatusChanged(enabled);
        });
        return ::android::binder::Status::fromStatusT(::android::NO_ERROR);
    }

    ::android::binder::Status commandExecuted(
            int32_t cmdCode, const ::std::vector<uint8_t>& cmdData,
            const ::std::vector<uint8_t>& replyData) override {
        getThread().add(__func__, [=, effectClient = mEffectClient]() {
            effectClient->commandExecuted(cmdCode, cmdData, replyData);
        });
        return ::android::binder::Status::fromStatusT(::android::NO_ERROR);
    }

    ::android::binder::Status framesProcessed(int32_t frames) override {
        getThread().add(__func__, [=, effectClient = mEffectClient]() {
            effectClient->framesProcessed(frames);
        });
        return ::android::binder::Status::fromStatusT(::android::NO_ERROR);
    }

    /**
     * Returns true if the binder interface is local (in-proc).
     *
     * Move to a binder helper class?
     */
    static bool isLocalBinder(const sp<IInterface>& interface) {
        const auto b = IInterface::asBinder(interface);
        return b && b->localBinder();
    }

private:
    const sp<IEffectClient> mEffectClient;

    /**
     * Returns the per-interface-descriptor CommandThread for in-proc binder transactions.
     *
     * Note: Remote RPC transactions to a given binder (kernel) node enter that node's
     * async_todo list, which serializes all async operations to that binder node.
     * Each transaction on the async_todo list must complete before the next one
     * starts, even though there may be available threads in the process threadpool.
     *
     * For local transactions, we order all async requests entering
     * the CommandThread.  We do not maintain a threadpool, though a future implementation
     * could use a shared ThreadPool.
     *
     * By using a static here, all in-proc binder interfaces made async with
     * EffectClientAsyncProxy will get the same CommandThread.
     *
     * @return CommandThread to use.
     */
    static audio_utils::CommandThread& getThread() {
        [[clang::no_destroy]] static audio_utils::CommandThread commandThread;
        return commandThread;
    }
};  // class EffectClientAsyncProxy

}  // namespace android::media
