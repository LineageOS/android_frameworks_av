LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := examples
LOCAL_C_INCLUDES := \
    $(call include-path-for, audio-utils) \
    frameworks/av/media/libaaudio/include \
    frameworks/av/media/libaaudio/examples/utils

# TODO reorganize folders to avoid using ../
LOCAL_SRC_FILES:= ../src/input_monitor.cpp

LOCAL_SHARED_LIBRARIES := libaudioutils libmedia \
                          libbinder libcutils libutils \
                          libaudioclient liblog libtinyalsa
LOCAL_STATIC_LIBRARIES := libaaudio

LOCAL_MODULE := input_monitor
include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := tests
LOCAL_C_INCLUDES := \
    $(call include-path-for, audio-utils) \
    frameworks/av/media/libaaudio/include \
    frameworks/av/media/libaaudio/examples/utils

LOCAL_SRC_FILES:= ../src/input_monitor_callback.cpp

LOCAL_SHARED_LIBRARIES := libaudioutils libmedia \
                          libbinder libcutils libutils \
                          libaudioclient liblog
LOCAL_STATIC_LIBRARIES := libaaudio

LOCAL_MODULE := input_monitor_callback
include $(BUILD_EXECUTABLE)
