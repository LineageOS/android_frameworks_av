LOCAL_PATH := $(call my-dir)

# Small library for media.extractor and media.codec sandboxing.
include $(CLEAR_VARS)
LOCAL_MODULE := libavservices_minijail
LOCAL_SRC_FILES := minijail.cpp
LOCAL_SHARED_LIBRARIES := libbase libminijail
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
include $(BUILD_SHARED_LIBRARY)
