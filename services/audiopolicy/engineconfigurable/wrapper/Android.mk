LOCAL_PATH:= $(call my-dir)

##################################################################
# WRAPPER LIBRARY
##################################################################

include $(CLEAR_VARS)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/include \
    frameworks/av/services/audiopolicy/engineconfigurable/include \
    frameworks/av/services/audiopolicy/engineconfigurable/interface \
    external/libxml2/include \
    external/icu/icu4c/source/common

LOCAL_SRC_FILES:= \
    ParameterManagerWrapper.cpp

LOCAL_SHARED_LIBRARIES := \
    libparameter \
    libmedia_helper \
    libxml2

LOCAL_HEADER_LIBRARIES := \
    libaudiopolicycommon

LOCAL_STATIC_LIBRARIES := \
    libaudiopolicycomponents

LOCAL_MULTILIB := $(AUDIOSERVER_MULTILIB)

LOCAL_MODULE:= libaudiopolicypfwwrapper
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include

LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -Wall -Werror -Wextra

include $(BUILD_STATIC_LIBRARY)

