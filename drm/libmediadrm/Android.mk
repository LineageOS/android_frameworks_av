LOCAL_PATH:= $(call my-dir)

#
# libmediadrm
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    DrmSessionManager.cpp \
    ICrypto.cpp \
    IDrm.cpp \
    IDrmClient.cpp \
    IMediaDrmService.cpp \
    SharedLibrary.cpp
ifeq ($(ENABLE_TREBLE_DRM), true)
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
ifeq ($(ENABLE_TREBLE_DRM), true)
LOCAL_SHARED_LIBRARIES += \
    android.hidl.base@1.0 \
    android.hardware.drm@1.0 \
    libhidlbase \
    libhidlmemory
endif

LOCAL_CFLAGS += -Werror -Wno-error=deprecated-declarations -Wall

LOCAL_MODULE:= libmediadrm

include $(BUILD_SHARED_LIBRARY)

include $(call all-makefiles-under,$(LOCAL_PATH))
