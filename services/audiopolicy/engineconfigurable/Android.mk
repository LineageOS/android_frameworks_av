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
    ../engine/common/src/VolumeCurve.cpp \
    ../engine/common/src/VolumeGroup.cpp \
    ../engine/common/src/ProductStrategy.cpp \
    ../engine/common/src/EngineBase.cpp

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
    libaudiopolicyengine_common_headers \
    libaudiopolicyengine_interface_headers

LOCAL_MULTILIB := $(AUDIOSERVER_MULTILIB)

LOCAL_MODULE := libaudiopolicyengineconfigurable
LOCAL_MODULE_TAGS := optional

LOCAL_STATIC_LIBRARIES := \
    libaudiopolicypfwwrapper \
    libaudiopolicycomponents

LOCAL_SHARED_LIBRARIES := \
    libaudiopolicyengineconfig \
    liblog \
    libutils \
    liblog \
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
