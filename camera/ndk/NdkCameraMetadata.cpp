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

//#define LOG_NDEBUG 0
#define LOG_TAG "NdkCameraMetadata"
#define ATRACE_TAG ATRACE_TAG_CAMERA

#include <utils/Log.h>
#include <utils/Trace.h>

#include <camera/NdkCameraMetadata.h>
#include "impl/ACameraMetadata.h"

using namespace android;

#ifndef __ANDROID_VNDK__
namespace {

constexpr const char* android_hardware_camera2_CameraMetadata_jniClassName =
    "android/hardware/camera2/CameraMetadata";
constexpr const char* android_hardware_camera2_CameraCharacteristics_jniClassName =
    "android/hardware/camera2/CameraCharacteristics";
constexpr const char* android_hardware_camera2_CaptureResult_jniClassName =
    "android/hardware/camera2/CaptureResult";

jclass android_hardware_camera2_CameraCharacteristics_clazz = nullptr;
jclass android_hardware_camera2_CaptureResult_clazz = nullptr;
jmethodID android_hardware_camera2_CameraMetadata_getNativeMetadataPtr = nullptr;

// Called at most once to initializes global variables used by JNI.
bool InitJni(JNIEnv* env) {
    // From C++11 onward, static initializers are guaranteed to be executed at most once,
    // even if called from multiple threads.
    static bool ok = [env]() -> bool {
        const jclass cameraMetadataClazz = env->FindClass(
            android_hardware_camera2_CameraMetadata_jniClassName);
        if (cameraMetadataClazz == nullptr) {
            return false;
        }
        const jmethodID cameraMetadata_getNativeMetadataPtr =
            env->GetMethodID(cameraMetadataClazz, "getNativeMetadataPtr", "()J");
        if (cameraMetadata_getNativeMetadataPtr == nullptr) {
            return false;
        }

        const jclass cameraCharacteristics_clazz = env->FindClass(
            android_hardware_camera2_CameraCharacteristics_jniClassName);
        if (cameraCharacteristics_clazz == nullptr) {
            return false;
        }

        const jclass captureResult_clazz = env->FindClass(
            android_hardware_camera2_CaptureResult_jniClassName);
        if (captureResult_clazz == nullptr) {
            return false;
        }

        android_hardware_camera2_CameraMetadata_getNativeMetadataPtr =
            cameraMetadata_getNativeMetadataPtr;
        android_hardware_camera2_CameraCharacteristics_clazz =
            static_cast<jclass>(env->NewGlobalRef(cameraCharacteristics_clazz));
        android_hardware_camera2_CaptureResult_clazz =
            static_cast<jclass>(env->NewGlobalRef(captureResult_clazz));

        return true;
    }();
    return ok;
}

// Given cameraMetadata, an instance of android.hardware.camera2.CameraMetadata, invokes
// cameraMetadata.getNativeMetadataPtr() and returns it as a std::shared_ptr<CameraMetadata>*.
std::shared_ptr<CameraMetadata>* CameraMetadata_getNativeMetadataPtr(JNIEnv* env,
        jobject cameraMetadata) {
    if (cameraMetadata == nullptr) {
        ALOGE("%s: Invalid Java CameraMetadata object.", __FUNCTION__);
        return nullptr;
    }
    jlong ret = env->CallLongMethod(cameraMetadata,
                                    android_hardware_camera2_CameraMetadata_getNativeMetadataPtr);
    return reinterpret_cast<std::shared_ptr<CameraMetadata>* >(ret);
}

}  // namespace
#endif  /* __ANDROID_VNDK__ */

EXPORT
camera_status_t ACameraMetadata_getConstEntry(
        const ACameraMetadata* acm, uint32_t tag, ACameraMetadata_const_entry* entry) {
    ATRACE_CALL();
    if (acm == nullptr || entry == nullptr) {
        ALOGE("%s: invalid argument! metadata %p, tag 0x%x, entry %p",
               __FUNCTION__, acm, tag, entry);
        return ACAMERA_ERROR_INVALID_PARAMETER;
    }
    return acm->getConstEntry(tag, entry);
}

EXPORT
camera_status_t ACameraMetadata_getAllTags(
        const ACameraMetadata* acm, /*out*/int32_t* numTags, /*out*/const uint32_t** tags) {
    ATRACE_CALL();
    if (acm == nullptr || numTags == nullptr || tags == nullptr) {
        ALOGE("%s: invalid argument! metadata %p, numTags %p, tags %p",
               __FUNCTION__, acm, numTags, tags);
        return ACAMERA_ERROR_INVALID_PARAMETER;
    }
    return acm->getTags(numTags, tags);
}

EXPORT
ACameraMetadata* ACameraMetadata_copy(const ACameraMetadata* src) {
    ATRACE_CALL();
    if (src == nullptr) {
        ALOGE("%s: src is null!", __FUNCTION__);
        return nullptr;
    }
    ACameraMetadata* copy = new ACameraMetadata(*src);
    copy->incStrong(/*id=*/(void*) ACameraMetadata_copy);
    return copy;
}

EXPORT
void ACameraMetadata_free(ACameraMetadata* metadata) {
    ATRACE_CALL();
    if (metadata != nullptr) {
        metadata->decStrong((void*) ACameraMetadata_free);
    }
}

EXPORT
bool ACameraMetadata_isLogicalMultiCamera(const ACameraMetadata* staticMetadata,
        /*out*/size_t* numPhysicalCameras, /*out*/const char*const** physicalCameraIds) {
    ATRACE_CALL();
    if (numPhysicalCameras == nullptr || physicalCameraIds == nullptr) {
        ALOGE("%s: Invalid input: numPhysicalCameras %p, physicalCameraIds %p",
                 __FUNCTION__, numPhysicalCameras, physicalCameraIds);
        return false;
    }
    if (staticMetadata == nullptr) {
        ALOGE("%s: Invalid input: staticMetadata is null.", __FUNCTION__);
        return false;
    }

    return staticMetadata->isLogicalMultiCamera(numPhysicalCameras, physicalCameraIds);
}

#ifndef __ANDROID_VNDK__
EXPORT
ACameraMetadata* ACameraMetadata_fromCameraMetadata(JNIEnv* env, jobject cameraMetadata) {
    ATRACE_CALL();

    const bool ok = InitJni(env);
    LOG_ALWAYS_FATAL_IF(!ok, "Failed to find CameraMetadata Java classes.");

    if (cameraMetadata == nullptr) {
        return nullptr;
    }

    ACameraMetadata::ACAMERA_METADATA_TYPE type;
    if (env->IsInstanceOf(cameraMetadata,
        android_hardware_camera2_CameraCharacteristics_clazz)) {
        type = ACameraMetadata::ACM_CHARACTERISTICS;
    } else if (env->IsInstanceOf(cameraMetadata,
        android_hardware_camera2_CaptureResult_clazz)) {
        type = ACameraMetadata::ACM_RESULT;
    } else {
        return nullptr;
    }

    auto sharedData = CameraMetadata_getNativeMetadataPtr(env, cameraMetadata);
    ACameraMetadata* output = new ACameraMetadata(*sharedData, type);
    output->incStrong(/*id=*/(void*) ACameraMetadata_fromCameraMetadata);
    return output;
}
#endif  /* __ANDROID_VNDK__ */
