LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_C_INCLUDES := \
    $(call include-path-for, audio-utils) \
    frameworks/av/media/libaaudio/include \
    frameworks/av/media/libaaudio/src/core \
    frameworks/av/media/libaaudio/src/utility
LOCAL_SRC_FILES:= test_handle_tracker.cpp
LOCAL_SHARED_LIBRARIES := libaudioclient libaudioutils libbinder \
                          libcutils liblog libmedia libutils
LOCAL_STATIC_LIBRARIES := libaaudio
LOCAL_MODULE := test_handle_tracker
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_C_INCLUDES := \
    $(call include-path-for, audio-utils) \
    frameworks/av/media/libaaudio/include \
    frameworks/av/media/libaaudio/src \
    frameworks/av/media/libaaudio/src/core \
    frameworks/av/media/libaaudio/src/fifo \
    frameworks/av/media/libaaudio/src/utility
LOCAL_SRC_FILES:= test_marshalling.cpp
LOCAL_SHARED_LIBRARIES := libaudioclient libaudioutils libbinder \
                          libcutils liblog libmedia libutils
LOCAL_STATIC_LIBRARIES := libaaudio
LOCAL_MODULE := test_marshalling
include $(BUILD_NATIVE_TEST)
