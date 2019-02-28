ifeq ($(USE_CONFIGURABLE_AUDIO_POLICY), 1)

LOCAL_PATH := $(call my-dir)

# Component build
#######################################################################

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
    src/Engine.cpp \
    src/EngineInstance.cpp \
    src/Stream.cpp \
    src/InputSource.cpp \

audio_policy_engine_includes_common := \
    frameworks/av/services/audiopolicy/engineconfigurable/include \
    frameworks/av/services/audiopolicy/engineconfigurable/interface

LOCAL_CFLAGS += \
    -Wall \
    -Werror \
    -Wextra \

LOCAL_EXPORT_C_INCLUDE_DIRS := \
    $(audio_policy_engine_includes_common)

LOCAL_C_INCLUDES := \
    $(audio_policy_engine_includes_common) \
    $(TARGET_OUT_HEADERS)/hw \
    $(call include-path-for, frameworks-av) \
    $(call include-path-for, audio-utils)

LOCAL_HEADER_LIBRARIES := \
    libaudiopolicycommon \
    libaudiopolicyengine_interface_headers

LOCAL_MULTILIB := $(AUDIOSERVER_MULTILIB)

LOCAL_MODULE := libaudiopolicyengineconfigurable
LOCAL_MODULE_TAGS := optional

LOCAL_STATIC_LIBRARIES := \
    libaudiopolicypfwwrapper \
    libaudiopolicycomponents \
    libaudiopolicyengine_common \
    libaudiopolicyengine_config \

LOCAL_SHARED_LIBRARIES := \
    liblog \
    libutils \
    liblog \
    libcutils \
    libaudioutils \
    libparameter \
    libmedia_helper \
    libaudiopolicy \
    libxml2

include $(BUILD_SHARED_LIBRARY)

#######################################################################
# Recursive call sub-folder Android.mk
#
include $(call all-makefiles-under,$(LOCAL_PATH))

endif
