LOCAL_PATH := $(call my-dir)

# service library
include $(CLEAR_VARS)
LOCAL_SRC_FILES := MediaExtractorService.cpp
LOCAL_SHARED_LIBRARIES := libmedia libstagefright libbinder libutils liblog
LOCAL_MODULE:= libmediaextractorservice
include $(BUILD_SHARED_LIBRARY)


# service executable
include $(CLEAR_VARS)
# seccomp filters are defined for the following architectures:
LOCAL_REQUIRED_MODULES_arm := mediaextractor-seccomp.policy
LOCAL_REQUIRED_MODULES_arm64 := mediaextractor-seccomp.policy
LOCAL_REQUIRED_MODULES_x86 := mediaextractor-seccomp.policy
# TODO add seccomp filter for x86_64.
LOCAL_SRC_FILES := main_extractorservice.cpp minijail/minijail.cpp
LOCAL_SHARED_LIBRARIES := libmedia libmediaextractorservice libbinder libutils liblog libicuuc libminijail
LOCAL_STATIC_LIBRARIES := libicuandroid_utils
LOCAL_MODULE:= mediaextractor
LOCAL_INIT_RC := mediaextractor.rc
LOCAL_C_INCLUDES := frameworks/av/media/libmedia
include $(BUILD_EXECUTABLE)

include $(call all-makefiles-under, $(LOCAL_PATH))
