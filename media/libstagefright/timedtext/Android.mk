LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:=                 \
        TextDescriptions.cpp      \

LOCAL_CFLAGS += -Wno-multichar -Werror -Wall
LOCAL_SANITIZE := signed-integer-overflow

LOCAL_C_INCLUDES:= \
        $(TOP)/frameworks/av/include/media/stagefright/timedtext \
        $(TOP)/frameworks/av/media/libstagefright

LOCAL_SHARED_LIBRARIES := libmedia

LOCAL_MODULE:= libstagefright_timedtext

include $(BUILD_STATIC_LIBRARY)
