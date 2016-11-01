# Media Statistics service
#
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	main_mediaanalytics.cpp

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	liblog \
	libmedia \
	libmediaanalyticsservice \
	libutils \
	libbinder \
	libicuuc

LOCAL_STATIC_LIBRARIES := \
        libicuandroid_utils \
        libregistermsext

LOCAL_C_INCLUDES := \
    frameworks/av/media/libmediaanalyticsservice

LOCAL_MODULE:= mediaanalytics

LOCAL_INIT_RC := mediaanalytics.rc

LOCAL_CFLAGS := -Werror -Wall

include $(BUILD_EXECUTABLE)
