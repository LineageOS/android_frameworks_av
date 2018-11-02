LOCAL_PATH:= $(call my-dir)

TOOLS := frameworks/av/services/audiopolicy/engineconfigurable/tools
PROVISION_CRITERION_TYPES := $(TOOLS)/provision_criterion_types_from_android_headers.mk

##################################################################
# WRAPPER LIBRARY
##################################################################

include $(CLEAR_VARS)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/include \
    frameworks/av/services/audiopolicy/engineconfigurable/include \
    frameworks/av/services/audiopolicy/engineconfigurable/interface \
    frameworks/av/services/audiopolicy/common/include \
    frameworks/av/services/audiopolicy/utilities/convert \
    external/libxml2/include \
    external/icu/icu4c/source/common

LOCAL_SRC_FILES:= \
    ParameterManagerWrapper.cpp \
    ParameterManagerWrapperConfig.cpp

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

##################################################################
# CONFIGURATION FILE
##################################################################

ifeq ($(BUILD_AUDIO_POLICY_EXAMPLE_CONFIGURATION), 1)

include $(CLEAR_VARS)
LOCAL_MODULE := policy_wrapper_configuration.xml
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_VENDOR_MODULE := true
LOCAL_SRC_FILES := config/$(LOCAL_MODULE)
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := policy_criteria.xml
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_VENDOR_MODULE := true
LOCAL_SRC_FILES := config/$(LOCAL_MODULE)
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := policy_criterion_types.xml
LOCAL_MODULE_CLASS := ETC
LOCAL_VENDOR_MODULE := true
LOCAL_ADDITIONAL_DEPENDENCIES := \
    $(TARGET_OUT_VENDOR_ETC)/audio_policy_configuration.xml

AUDIO_POLICY_CONFIGURATION_FILE := $(TARGET_OUT_VENDOR_ETC)/audio_policy_configuration.xml
ANDROID_AUDIO_BASE_HEADER_FILE := system/media/audio/include/system/audio-base.h
CRITERION_TYPES_FILE := $(LOCAL_PATH)/config/policy_criterion_types.xml.in

include $(PROVISION_CRITERION_TYPES)

endif #ifeq ($(BUILD_AUDIO_POLICY_EXAMPLE_CONFIGURATION), 1)
