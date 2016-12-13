# Build the unit tests.
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk

LOCAL_MODULE := mtp_ffs_handle_test

LOCAL_MODULE_TAGS := tests

LOCAL_SRC_FILES := \
	MtpFfsHandle_test.cpp \

LOCAL_SHARED_LIBRARIES := \
	libbase \
	libcutils \
	libmedia \
	libmtp \
	libutils \
	liblog

LOCAL_C_INCLUDES := \
	frameworks/av/media/mtp \

LOCAL_CFLAGS += -Werror -Wall

include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk

LOCAL_MODULE := async_io_test

LOCAL_MODULE_TAGS := tests

LOCAL_SRC_FILES := \
	AsyncIO_test.cpp \

LOCAL_SHARED_LIBRARIES := \
	libbase \
	libcutils \
	libmedia \
	libmtp \
	libutils \
	liblog

LOCAL_C_INCLUDES := \
	frameworks/av/media/mtp \

LOCAL_CFLAGS += -Werror -Wall

include $(BUILD_NATIVE_TEST)
