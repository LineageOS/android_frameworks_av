LOCAL_PATH:= $(call my-dir)

#
# libmediadrm
#

include $(CLEAR_VARS)

LOCAL_AIDL_INCLUDES := \
    frameworks/av/drm/libmediadrm/aidl

LOCAL_SRC_FILES := \
    aidl/android/media/ICas.aidl \
    aidl/android/media/ICasListener.aidl \
    aidl/android/media/IDescrambler.aidl \
    aidl/android/media/IMediaCasService.aidl \

LOCAL_SRC_FILES += \
    CasImpl.cpp \
    DescramblerImpl.cpp \
    DrmPluginPath.cpp \
    DrmSessionManager.cpp \
    ICrypto.cpp \
    IDrm.cpp \
    IDrmClient.cpp \
    IMediaDrmService.cpp \
    MediaCasDefs.cpp \
    SharedLibrary.cpp
ifneq ($(DISABLE_TREBLE_DRM), true)
LOCAL_SRC_FILES += \
    DrmHal.cpp \
    CryptoHal.cpp
else
LOCAL_SRC_FILES += \
    Drm.cpp \
    Crypto.cpp
endif

LOCAL_SHARED_LIBRARIES := \
    libbinder \
    libcutils \
    libdl \
    liblog \
    libmediautils \
    libstagefright_foundation \
    libutils
ifneq ($(DISABLE_TREBLE_DRM), true)
LOCAL_SHARED_LIBRARIES += \
    android.hidl.base@1.0 \
    android.hardware.drm@1.0 \
    libhidlbase \
    libhidlmemory \
    libhidltransport
endif

LOCAL_CFLAGS += -Werror -Wno-error=deprecated-declarations -Wall

LOCAL_MODULE:= libmediadrm

include $(BUILD_SHARED_LIBRARY)

include $(call all-makefiles-under,$(LOCAL_PATH))
