LOCAL_PATH := $(call my-dir)

##################################################################
# Component build
##################################################################

include $(CLEAR_VARS)

LOCAL_EXPORT_C_INCLUDE_DIRS :=  $(LOCAL_PATH)/include

LOCAL_C_INCLUDES := \
    $(LOCAL_EXPORT_C_INCLUDE_DIRS) \
    external/libxml2/include \
    external/icu/icu4c/source/common

LOCAL_SRC_FILES := \
    src/EngineConfig.cpp

LOCAL_CFLAGS += -Wall -Werror -Wextra

LOCAL_SHARED_LIBRARIES := \
    libmedia_helper \
    libandroidicu \
    libxml2 \
    libutils \
    liblog

LOCAL_STATIC_LIBRARIES := \
    libaudiopolicycomponents

LOCAL_MULTILIB := $(AUDIOSERVER_MULTILIB)

LOCAL_MODULE := libaudiopolicyengineconfig
LOCAL_MODULE_TAGS := optional

LOCAL_HEADER_LIBRARIES := \
    libaudio_system_headers \
    libaudiopolicycommon

include $(BUILD_SHARED_LIBRARY)

