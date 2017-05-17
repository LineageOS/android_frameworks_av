LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := tests
LOCAL_C_INCLUDES := \
    $(call include-path-for, audio-utils) \
    frameworks/av/media/libaaudio/include

# NDK recommends using this kind of relative path instead of an absolute path.
LOCAL_SRC_FILES:= ../src/loopback.cpp
LOCAL_SHARED_LIBRARIES := libaaudio
LOCAL_MODULE := aaudio_loopback
include $(BUILD_EXECUTABLE)
