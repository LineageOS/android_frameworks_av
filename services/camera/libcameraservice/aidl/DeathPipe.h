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

#ifndef FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_DEATHPIPE_H_
#define FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_DEATHPIPE_H_

#include <android/binder_auto_utils.h>
#include <android/binder_ibinder.h>
#include <binder/Parcel.h>
#include <list>

namespace android::frameworks::cameraservice::utils {

/**
 * This is a helper class to pipe death notifications from  VNDK {@code AIBinder} to
 * S/NDK {@code IBinder}.
 *
 * To use this class, create a DeathPipe member object as a field of NDK interface
 * implementation, and forward functions {@code BBinder::linkToDeath} and
 * {@code BBinder::unlinkToDeath} to corresponding DeathPipe functions.
 */
class DeathPipe {
  public:
    /**
     * @param parent the NDK Binder object. Assumed to live longer than the DeathPipe
     *               object
     * @param binder the VNDK Binder object which DeathPipe with subscribe to.
     */
    explicit DeathPipe(IBinder* parent, const ::ndk::SpAIBinder& binder);
    ~DeathPipe();

    status_t linkToDeath(const sp<IBinder::DeathRecipient>& recipient, void* cookie,
                         uint32_t flags);
    status_t unlinkToDeath(const wp<IBinder::DeathRecipient>& recipient,
                           void* cookie, uint32_t flags, wp<IBinder::DeathRecipient>* outRecipient);

    // Static functions that will be called by VNDK binder upon death or unlinking
    static void onDeathCallback(void* cookie);
    static void onUnlinkedCallback(void* cookie);

  private:
    /**
     * {@code Obituary} is a tiny container that contains some metadata to pass VNDK binder's
     * death notification to the NDK binder. A pointer to the Obituary is used as the
     * {@code cookie} in VNDK binder's death notification.
     *
     * Theoretically, the VNDK binder might send out death notification after the DeathPipe
     * object is destroyed, so care must be taken to ensure that Obituaries aren't accidentally
     * destroyed before VNDK binder stops using its cookies.
     *
     */
    struct Obituary: public std::enable_shared_from_this<Obituary> {
        wp<IBinder::DeathRecipient> recipient; // NDK death recipient
        void *cookie; // cookie sent by the NDK recipient
        uint32_t flags; // flags sent by the NDK recipient
        wp<IBinder> who; // NDK binder whose death 'recipient' subscribed to

        // Self ptr to ensure we don't destroy this obituary while it can still be notified by the
        // VNDK Binder. When populated with Obituary::immortalize, this Obituary won't be
        // garbage collected until Obituary::clear is called.
        std::shared_ptr<Obituary> mSelfPtr;

        Obituary(const wp<IBinder::DeathRecipient>& recipient, void* cookie,
                 uint32_t flags, IBinder* who) :
              recipient(recipient), cookie(cookie), flags(flags),
              who(who), mSelfPtr(nullptr) {}

        // Function to be called when the VNDK Binder dies. Pipes the notification to the relevant
        // NDK recipient if it still exists
        void onDeath() const {
                sp<IBinder::DeathRecipient> r = recipient.promote();
                if (r == nullptr) { return; }
                r->binderDied(who);
        };

        // Should be called before calling AIBinder_linkToDeath. Once this function returns this
        // Obituary won't be garbage collected until Obituary::clear is called.
        void immortalize() {
            mSelfPtr = shared_from_this();
        }

        // Should be called when this Obituary can be garbage collected.
        // Typically, after the Obituary is no longer linked to a VNDK DeathRecipient
        void clear() {
            mSelfPtr = nullptr;
        }

        bool operator==(const Obituary& rhs) const {
            return recipient == rhs.recipient &&
                   cookie == rhs.cookie &&
                   flags == rhs.flags &&
                   who == rhs.who;
        }
    };

    // Parent to which the cameraservice wants to subscribe to for death notification
    IBinder* mParent;

    // VNDK Binder object to which the death notification will be bound to. If it dies,
    // cameraservice will be notified as if mParent died.
    ::ndk::SpAIBinder mAIBinder;

    // Owning VNDK's deathRecipient ensures that all linked death notifications are cleaned up
    // when this class destructs.
    ::ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;

    // Lock to protect access to fields below.
    std::mutex mLock;
    // List of all obituaries created by DeathPipe, used to unlink death subscription
    std::list<std::shared_ptr<Obituary>> mObituaries;

};

} // namespace android::frameworks::cameraservice::utils

#endif  // FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_DEATHPIPE_H_
