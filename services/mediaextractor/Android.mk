LOCAL_PATH := $(call my-dir)

# service library
include $(CLEAR_VARS)
LOCAL_CFLAGS := -Wall -Werror
LOCAL_SRC_FILES := \
    MediaExtractorService.cpp

LOCAL_SHARED_LIBRARIES := libmedia libstagefright libbinder libutils
LOCAL_MODULE:= libmediaextractorservice
include $(BUILD_SHARED_LIBRARY)


# service executable
include $(CLEAR_VARS)
# seccomp filters are defined for the following architectures:
LOCAL_REQUIRED_MODULES_arm := crash_dump.policy mediaextractor.policy
LOCAL_REQUIRED_MODULES_arm64 := crash_dump.policy mediaextractor.policy
LOCAL_REQUIRED_MODULES_x86 := crash_dump.policy mediaextractor.policy
LOCAL_REQUIRED_MODULES_x86_64 := crash_dump.policy mediaextractor.policy

LOCAL_SRC_FILES := main_extractorservice.cpp
ifneq (true, $(filter true, $(MALLOC_SVELTE)))
# Scudo increases memory footprint, so only use on non-svelte configs.
LOCAL_SHARED_LIBRARIES := libc_scudo
endif
LOCAL_SHARED_LIBRARIES += libmedia libmediaextractorservice libbinder libutils \
    liblog libavservices_minijail
LOCAL_MODULE:= mediaextractor
LOCAL_INIT_RC := mediaextractor.rc
LOCAL_C_INCLUDES := frameworks/av/media/libmedia
LOCAL_CFLAGS := -Wall -Werror
include $(BUILD_EXECUTABLE)

# service seccomp filter
ifeq ($(TARGET_ARCH), $(filter $(TARGET_ARCH), arm arm64 x86 x86_64))
include $(CLEAR_VARS)
LOCAL_MODULE := mediaextractor.policy
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)/etc/seccomp_policy
LOCAL_SRC_FILES := seccomp_policy/mediaextractor-$(TARGET_ARCH).policy
include $(BUILD_PREBUILT)
endif
