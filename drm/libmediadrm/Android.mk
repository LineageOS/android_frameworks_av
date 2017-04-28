LOCAL_PATH:= $(call my-dir)

#
# libmediadrm
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    Crypto.cpp \
    Drm.cpp \
    DrmSessionManager.cpp \
    ICrypto.cpp \
    IDrm.cpp \
    IDrmClient.cpp \
    IMediaDrmService.cpp \
    SharedLibrary.cpp

LOCAL_SHARED_LIBRARIES := \
    libbinder \
    libcutils \
    libdl \
    liblog \
    libmediautils \
    libstagefright_foundation \
    libutils

LOCAL_CFLAGS += -Werror -Wno-error=deprecated-declarations -Wall

LOCAL_MODULE:= libmediadrm

include $(BUILD_SHARED_LIBRARY)

include $(call all-makefiles-under,$(LOCAL_PATH))
