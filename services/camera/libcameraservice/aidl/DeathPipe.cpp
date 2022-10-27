/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "DeathPipe"

#include "DeathPipe.h"

namespace android::frameworks::cameraservice::utils {

DeathPipe::DeathPipe(IBinder* parent, const ::ndk::SpAIBinder& binder):
      mParent(parent), mAIBinder(binder) {
    mDeathRecipient = ::ndk::ScopedAIBinder_DeathRecipient(
            AIBinder_DeathRecipient_new(DeathPipe::onDeathCallback));
    // Set an unlinked callback that allows Obituaries to be deallocated
    AIBinder_DeathRecipient_setOnUnlinked(mDeathRecipient.get(),
                                          DeathPipe::onUnlinkedCallback);
}

status_t DeathPipe::linkToDeath(const sp<IBinder::DeathRecipient>& recipient,
                                void* cookie, uint32_t flags) {
    LOG_ALWAYS_FATAL_IF(recipient == nullptr, "%s: recipient must be non-nullptr", __FUNCTION__);
    std::lock_guard<std::mutex> _l(mLock);

    // Create and immortalize an obituary before linking it to death.
    // The created Obituary can now only be garbage collected if it is unlinked from death
    std::shared_ptr<Obituary> obituary = std::make_shared<Obituary>(recipient, cookie,
                                                                    flags, /* who= */ mParent);
    obituary->immortalize();

    // Ensure that "cookie" is a pointer to an immortal obituary.
    // AIBinder_linkToDeath calls DeathPipe::onUnlinkedCallback if linking to death fails, marking
    // it for garbage collection
    binder_status_t ret = AIBinder_linkToDeath(mAIBinder.get(),
                                               mDeathRecipient.get(),
                                               /* cookie= */ obituary.get());
    if (ret != STATUS_OK) {
        return DEAD_OBJECT;
    }
    mObituaries.emplace_back(obituary);
    return NO_ERROR;
}

status_t DeathPipe::unlinkToDeath(const wp<IBinder::DeathRecipient>& recipient,
                                  void* cookie, uint32_t flags,
                                  wp<IBinder::DeathRecipient>* outRecipient) {
    std::lock_guard<std::mutex> _l(mLock);
    // Temporary Obituary for checking equality
    std::shared_ptr<Obituary> inObituary = std::make_shared<Obituary>(recipient, cookie,
                                                                      flags, mParent);
    for (auto it = mObituaries.begin(); it != mObituaries.end(); it++) {
        if ((*inObituary) == (**it)) {
            if (outRecipient != nullptr) {
                *outRecipient = (*it)->recipient;
            }
            // Unlink the found Obituary from death. AIBinder_unlinkToDeath calls
            // DeathPipe::onUnlinkedCallback with the given cookie when unlinking is done
            binder_status_t ret = AIBinder_unlinkToDeath(mAIBinder.get(),
                                                         mDeathRecipient.get(),
                                                         /* cookie= */ (*it).get());
            mObituaries.erase(it);
            return ret == STATUS_OK ? NO_ERROR : DEAD_OBJECT;
        }
    }
    return NAME_NOT_FOUND;
}

DeathPipe::~DeathPipe() = default;


void DeathPipe::onDeathCallback(void* cookie) {
    // Cookie will always be a pointer to a valid immortal Obituary
    Obituary* obituary = static_cast<Obituary*>(cookie);
    obituary->onDeath();
    // Don't call Obituary::clear() because VNDK Binder will call DeathPipe::onUnlinkedCallback()
    // when it is ready
}

void DeathPipe::onUnlinkedCallback(void* cookie) {
    // Cookie will always be a pointer to a valid immortal Obituary.
    Obituary* obituary = static_cast<Obituary*>(cookie);
    // Mark obituary to be garbage collected if needed. onDeathCallback won't be called with
    // this particular cookie after this.
    obituary->clear();
}

} // namespace android::frameworks::cameraservice::utils