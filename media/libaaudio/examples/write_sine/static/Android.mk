LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := examples
LOCAL_C_INCLUDES := \
    $(call include-path-for, audio-utils) \
    frameworks/av/media/libaaudio/src \
    frameworks/av/media/libaaudio/include

# NDK recommends using this kind of relative path instead of an absolute path.
LOCAL_SRC_FILES:= ../src/write_sine.cpp

LOCAL_SHARED_LIBRARIES := libaudioutils libmedia \
                          libbinder libcutils libutils \
                          libaudioclient liblog libtinyalsa
LOCAL_STATIC_LIBRARIES := libaaudio

LOCAL_MODULE := write_sine
include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := tests
LOCAL_C_INCLUDES := \
    $(call include-path-for, audio-utils) \
    frameworks/av/media/libaaudio/include

LOCAL_SRC_FILES:= ../src/write_sine_callback.cpp

LOCAL_SHARED_LIBRARIES := libaudioutils libmedia \
                          libbinder libcutils libutils \
                          libaudioclient liblog
LOCAL_STATIC_LIBRARIES := libaaudio

LOCAL_MODULE := write_sine_callback
include $(BUILD_EXECUTABLE)
