LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := tests
LOCAL_C_INCLUDES := \
    $(call include-path-for, audio-utils) \
    frameworks/av/media/liboboe/include

LOCAL_SRC_FILES:= frameworks/av/media/liboboe/src/write_sine.cpp
LOCAL_SHARED_LIBRARIES := libaudioutils libmedia libtinyalsa \
        libbinder libcutils libutils
LOCAL_STATIC_LIBRARIES := libsndfile
LOCAL_MODULE := write_sine_ndk
LOCAL_SHARED_LIBRARIES += liboboe_prebuilt
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := tests
LOCAL_C_INCLUDES := \
    $(call include-path-for, audio-utils) \
    frameworks/av/media/liboboe/include

LOCAL_SRC_FILES:= frameworks/av/media/liboboe/src/write_sine_threaded.cpp
LOCAL_SHARED_LIBRARIES := libaudioutils libmedia libtinyalsa \
        libbinder libcutils libutils
LOCAL_STATIC_LIBRARIES := libsndfile
LOCAL_MODULE := write_sine_threaded_ndk
LOCAL_SHARED_LIBRARIES += liboboe_prebuilt
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := liboboe_prebuilt
LOCAL_SRC_FILES := liboboe.so
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include
include $(PREBUILT_SHARED_LIBRARY)
