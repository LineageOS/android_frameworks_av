/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef _ACAMERA_MANAGER_H
#define _ACAMERA_MANAGER_H

#include <CameraMetadata.h>
#include <aidl/android/frameworks/cameraservice/common/Status.h>
#include <aidl/android/frameworks/cameraservice/common/VendorTag.h>
#include <aidl/android/frameworks/cameraservice/common/VendorTagSection.h>
#include <aidl/android/frameworks/cameraservice/service/BnCameraServiceListener.h>
#include <aidl/android/frameworks/cameraservice/service/CameraDeviceStatus.h>
#include <aidl/android/frameworks/cameraservice/service/CameraStatusAndId.h>
#include <aidl/android/frameworks/cameraservice/service/ICameraService.h>
#include <android-base/parseint.h>
#include <camera/NdkCameraManager.h>
#include <map>
#include <media/stagefright/foundation/AHandler.h>
#include <media/stagefright/foundation/ALooper.h>
#include <media/stagefright/foundation/AMessage.h>
#include <set>
#include <utility>
#include <utils/Mutex.h>
#include <utils/StrongPointer.h>

namespace android {
namespace acam {

using ::aidl::android::frameworks::cameraservice::common::Status;
using ::aidl::android::frameworks::cameraservice::common::VendorTag;
using ::aidl::android::frameworks::cameraservice::common::VendorTagSection;
using ::aidl::android::frameworks::cameraservice::service::BnCameraServiceListener;
using ::aidl::android::frameworks::cameraservice::service::CameraDeviceStatus;
using ::aidl::android::frameworks::cameraservice::service::CameraStatusAndId;
using ::aidl::android::frameworks::cameraservice::service::ICameraService;

/**
 * Per-process singleton instance of CameraManger. Shared by all ACameraManager
 * instances. Created when first ACameraManager is created and destroyed when
 * all ACameraManager instances are deleted.
 *
 * TODO: maybe CameraManagerGlobal is better suited in libcameraclient?
 */
class CameraManagerGlobal final: public std::enable_shared_from_this<CameraManagerGlobal> {
  public:
    static std::shared_ptr<CameraManagerGlobal> getInstance();
    static void binderDeathCallback(void* cookie);

    CameraManagerGlobal() {};
    ~CameraManagerGlobal();

    std::shared_ptr<ICameraService> getCameraService();

    void registerAvailabilityCallback(const ACameraManager_AvailabilityCallbacks *callback);
    void unregisterAvailabilityCallback(const ACameraManager_AvailabilityCallbacks *callback);

    void registerExtendedAvailabilityCallback(
            const ACameraManager_ExtendedAvailabilityCallbacks* callback);
    void unregisterExtendedAvailabilityCallback(
            const ACameraManager_ExtendedAvailabilityCallbacks* callback);

    /**
     * Return camera IDs that support camera2
     */
    void getCameraIdList(std::vector<std::string> *cameraIds);

  private:
    std::shared_ptr<ICameraService> mCameraService;
    const int          kCameraServicePollDelay = 500000; // 0.5s
    Mutex              mLock;
    ::ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;

    class CameraServiceListener final : public BnCameraServiceListener {
      public:
        explicit CameraServiceListener(std::weak_ptr<CameraManagerGlobal> cm) :
              mCameraManager(std::move(cm)) {}
        ndk::ScopedAStatus onPhysicalCameraStatusChanged(
                CameraDeviceStatus in_status, const std::string& in_cameraId,
                const std::string& in_physicalCameraId) override;
        ndk::ScopedAStatus onStatusChanged(CameraDeviceStatus in_status,
                                           const std::string& in_cameraId) override;

      private:
        const std::weak_ptr<CameraManagerGlobal> mCameraManager;
    };
    std::shared_ptr<CameraServiceListener> mCameraServiceListener;

    // Wrapper of ACameraManager_AvailabilityCallbacks so we can store it in std::set
    struct Callback {
        explicit Callback(const ACameraManager_AvailabilityCallbacks *callback) :
            mAvailable(callback->onCameraAvailable),
            mUnavailable(callback->onCameraUnavailable),
            mAccessPriorityChanged(nullptr),
            mPhysicalCamAvailable(nullptr),
            mPhysicalCamUnavailable(nullptr),
            mContext(callback->context) {}

        explicit Callback(const ACameraManager_ExtendedAvailabilityCallbacks *callback) :
            mAvailable(callback->availabilityCallbacks.onCameraAvailable),
            mUnavailable(callback->availabilityCallbacks.onCameraUnavailable),
            mAccessPriorityChanged(callback->onCameraAccessPrioritiesChanged),
            mPhysicalCamAvailable(callback->onPhysicalCameraAvailable),
            mPhysicalCamUnavailable(callback->onPhysicalCameraUnavailable),
            mContext(callback->availabilityCallbacks.context) {}

        bool operator == (const Callback& other) const {
            return (mAvailable == other.mAvailable &&
                    mUnavailable == other.mUnavailable &&
                    mAccessPriorityChanged == other.mAccessPriorityChanged &&
                    mPhysicalCamAvailable == other.mPhysicalCamAvailable &&
                    mPhysicalCamUnavailable == other.mPhysicalCamUnavailable &&
                    mContext == other.mContext);
        }
        bool operator != (const Callback& other) const {
            return !(*this == other);
        }
        bool operator < (const Callback& other) const {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wordered-compare-function-pointers"
            if (*this == other) return false;
            if (mContext != other.mContext) return mContext < other.mContext;
            if (mAvailable != other.mAvailable) return mAvailable < other.mAvailable;
            if (mAccessPriorityChanged != other.mAccessPriorityChanged)
                    return mAccessPriorityChanged < other.mAccessPriorityChanged;
            if (mPhysicalCamAvailable != other.mPhysicalCamAvailable)
                    return mPhysicalCamAvailable < other.mPhysicalCamAvailable;
            if (mPhysicalCamUnavailable != other.mPhysicalCamUnavailable)
                    return mPhysicalCamUnavailable < other.mPhysicalCamUnavailable;
            return mUnavailable < other.mUnavailable;
#pragma GCC diagnostic pop
        }
        bool operator > (const Callback& other) const {
            return (*this != other && !(*this < other));
        }
        ACameraManager_AvailabilityCallback mAvailable;
        ACameraManager_AvailabilityCallback mUnavailable;
        ACameraManager_AccessPrioritiesChangedCallback mAccessPriorityChanged;
        ACameraManager_PhysicalCameraAvailabilityCallback mPhysicalCamAvailable;
        ACameraManager_PhysicalCameraAvailabilityCallback mPhysicalCamUnavailable;
        void*                               mContext;
    };

    android::Condition mCallbacksCond;
    size_t mPendingCallbackCnt = 0;
    void onCallbackCalled();
    void drainPendingCallbacksLocked();

    std::set<Callback> mCallbacks;

    // definition of handler and message
    enum {
        kWhatSendSingleCallback,
        kWhatSendSinglePhysicalCameraCallback,
    };
    static const char* kCameraIdKey;
    static const char* kPhysicalCameraIdKey;
    static const char* kCallbackFpKey;
    static const char* kContextKey;
    static const nsecs_t kCallbackDrainTimeout;
    class CallbackHandler : public AHandler {
      public:
        CallbackHandler(std::weak_ptr<CameraManagerGlobal> parent) : mParent(std::move(parent)) {}
        void onMessageReceived(const sp<AMessage> &msg) override;
      private:
        std::weak_ptr<CameraManagerGlobal> mParent;
        void notifyParent();
        void onMessageReceivedInternal(const sp<AMessage> &msg);
    };
    sp<CallbackHandler> mHandler;
    sp<ALooper>         mCbLooper; // Looper thread where callbacks actually happen on

    void onStatusChanged(const CameraDeviceStatus &status, const std::string &cameraId);
    void onStatusChangedLocked(const CameraDeviceStatus &status, const std::string &cameraId);
    void onStatusChanged(const CameraDeviceStatus &status, const std::string &cameraId,
                         const std::string &physicalCameraId);
    void onStatusChangedLocked(const CameraDeviceStatus &status, const std::string &cameraId,
                               const std::string &physicalCameraId);
    bool setupVendorTags();

    // Utils for status
    static bool validStatus(CameraDeviceStatus status);
    static bool isStatusAvailable(CameraDeviceStatus status);

    // The sort logic must match the logic in
    // libcameraservice/common/CameraProviderManager.cpp::getAPI1CompatibleCameraDeviceIds
    struct CameraIdComparator {
        bool operator()(const std::string& a, const std::string& b) const {
            uint32_t aUint = 0, bUint = 0;
            bool aIsUint = base::ParseUint(a.c_str(), &aUint);
            bool bIsUint = base::ParseUint(b.c_str(), &bUint);

            // Uint device IDs first
            if (aIsUint && bIsUint) {
                return aUint < bUint;
            } else if (aIsUint) {
                return true;
            } else if (bIsUint) {
                return false;
            }
            // Simple string compare if both id are not uint
            return a < b;
        }
    };

    struct CameraStatus {
      private:
        CameraDeviceStatus status = CameraDeviceStatus::STATUS_NOT_PRESENT;
        mutable std::mutex mLock;
        std::set<std::string> unavailablePhysicalIds;
      public:
        CameraStatus(CameraDeviceStatus st): status(st) { };
        CameraStatus() = default;

        bool addUnavailablePhysicalId(const std::string& physicalCameraId);
        bool removeUnavailablePhysicalId(const std::string& physicalCameraId);
        CameraDeviceStatus getStatus();
        void updateStatus(CameraDeviceStatus newStatus);
        std::set<std::string> getUnavailablePhysicalIds();
    };

    template <class T>
    void registerAvailCallback(const T *callback);

    // Map camera_id -> status
    std::map<std::string, CameraStatus, CameraIdComparator> mDeviceStatusMap;

    // For the singleton instance
    static Mutex sLock;
    // Static instance is stored in a weak pointer, so will only exist if there is at least one
    // active consumer of CameraManagerGlobal
    static std::weak_ptr<CameraManagerGlobal> sInstance;
};

} // namespace acam;
} // namespace android;

/**
 * ACameraManager opaque struct definition
 * Leave outside of android namespace because it's NDK struct
 */
struct ACameraManager {
    ACameraManager() :
            mGlobalManager(android::acam::CameraManagerGlobal::getInstance()) {}
    ~ACameraManager();
    camera_status_t getCameraIdList(ACameraIdList** cameraIdList);
    static void     deleteCameraIdList(ACameraIdList* cameraIdList);

    camera_status_t getCameraCharacteristics(
            const char* cameraId, android::sp<ACameraMetadata>* characteristics);

    camera_status_t openCamera(const char* cameraId,
                               ACameraDevice_StateCallbacks* callback,
                               /*out*/ACameraDevice** device);
    camera_status_t getTagFromName(const char *cameraId, const char *name, uint32_t *tag);
    void registerAvailabilityCallback(const ACameraManager_AvailabilityCallbacks* callback);
    void unregisterAvailabilityCallback(const ACameraManager_AvailabilityCallbacks* callback);
    void registerExtendedAvailabilityCallback(
            const ACameraManager_ExtendedAvailabilityCallbacks* callback);
    void unregisterExtendedAvailabilityCallback(
            const ACameraManager_ExtendedAvailabilityCallbacks* callback);

  private:
    enum {
        kCameraIdListNotInit = -1
    };
    android::Mutex         mLock;
    std::shared_ptr<android::acam::CameraManagerGlobal> mGlobalManager;
};

#endif //_ACAMERA_MANAGER_H
