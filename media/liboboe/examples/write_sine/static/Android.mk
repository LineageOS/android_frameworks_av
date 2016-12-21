LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := examples
LOCAL_C_INCLUDES := \
    $(call include-path-for, audio-utils) \
    frameworks/av/media/liboboe/include

# TODO reorganize folders to avoid using ../
LOCAL_SRC_FILES:= ../src/write_sine.cpp

LOCAL_SHARED_LIBRARIES := libaudioutils libmedia \
                          libbinder libcutils libutils \
                          libaudioclient liblog libtinyalsa
LOCAL_STATIC_LIBRARIES := liboboe

LOCAL_MODULE := write_sine
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := tests
LOCAL_C_INCLUDES := \
    $(call include-path-for, audio-utils) \
    frameworks/av/media/liboboe/include

LOCAL_SRC_FILES:= ../src/write_sine_threaded.cpp

LOCAL_SHARED_LIBRARIES := libaudioutils libmedia \
                          libbinder libcutils libutils \
                          libaudioclient liblog libtinyalsa
LOCAL_STATIC_LIBRARIES := liboboe

LOCAL_MODULE := write_sine_threaded
include $(BUILD_EXECUTABLE)
