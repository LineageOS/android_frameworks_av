# include $(call all-subdir-makefiles)

# Just include static/ for now.
LOCAL_PATH := $(call my-dir)
#include $(LOCAL_PATH)/jni/Android.mk
include $(LOCAL_PATH)/static/Android.mk
