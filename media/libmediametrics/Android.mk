LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES += \
    IMediaAnalyticsService.cpp \
    MediaAnalyticsItem.cpp \

LOCAL_SHARED_LIBRARIES := \
        liblog libcutils libutils libbinder \
        libstagefright_foundation \
        libbase \

LOCAL_MODULE:= libmediametrics

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk

LOCAL_C_INCLUDES := \
    $(TOP)/system/libhidl/base/include \
    $(TOP)/frameworks/native/include/media/openmax \
    $(TOP)/frameworks/av/include/media/ \
    $(TOP)/frameworks/av/media/libmedia/aidl \
    $(TOP)/frameworks/av/include \
    $(TOP)/frameworks/native/include \
    $(call include-path-for, audio-utils)

LOCAL_EXPORT_C_INCLUDE_DIRS := \
    frameworks/av/include/media \

LOCAL_CFLAGS += -Werror -Wno-error=deprecated-declarations -Wall
LOCAL_SANITIZE := unsigned-integer-overflow signed-integer-overflow cfi
LOCAL_SANITIZE_DIAG := cfi

include $(BUILD_SHARED_LIBRARY)
