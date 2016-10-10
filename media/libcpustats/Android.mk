LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=     \
        CentralTendencyStatistics.cpp \
        ThreadCpuUsage.cpp

LOCAL_MODULE := libcpustats

LOCAL_CFLAGS := -Werror -Wall

include $(BUILD_STATIC_LIBRARY)
