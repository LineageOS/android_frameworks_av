LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_C_INCLUDES := \
    $(call include-path-for, audio-utils) \
    frameworks/av/media/liboboe/include \
    frameworks/av/media/liboboe/src/core \
    frameworks/av/media/liboboe/src/utility
LOCAL_SRC_FILES:= test_oboe_api.cpp
LOCAL_SHARED_LIBRARIES := libaudioutils libmedia \
                          libbinder libcutils libutils \
                          libaudioclient liblog
LOCAL_STATIC_LIBRARIES := liboboe
LOCAL_MODULE := test_oboe_api
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_C_INCLUDES := \
    $(call include-path-for, audio-utils) \
    frameworks/av/media/liboboe/include \
    frameworks/av/media/liboboe/src/core \
    frameworks/av/media/liboboe/src/utility
LOCAL_SRC_FILES:= test_handle_tracker.cpp
LOCAL_SHARED_LIBRARIES := libbinder libcutils libutils liblog
LOCAL_STATIC_LIBRARIES := liboboe
LOCAL_MODULE := test_handle_tracker
include $(BUILD_NATIVE_TEST)
