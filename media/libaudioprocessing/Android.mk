LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

#QTI Resampler
ifeq ($(call is-vendor-board-platform,QCOM), true)
ifeq ($(strip $(AUDIO_FEATURE_ENABLED_EXTN_RESAMPLER)), true)
LOCAL_SRC_FILES_$(TARGET_2ND_ARCH) += AudioResamplerQTI.cpp.arm
LOCAL_C_INCLUDES_$(TARGET_2ND_ARCH) += $(TARGET_OUT_HEADERS)/mm-audio/audio-src
LOCAL_SHARED_LIBRARIES_$(TARGET_2ND_ARCH) += libqct_resampler
LOCAL_CFLAGS_$(TARGET_2ND_ARCH) += -DQTI_RESAMPLER
endif
endif
#QTI Resampler

LOCAL_SRC_FILES := \
    AudioMixer.cpp.arm \
    AudioResampler.cpp.arm \
    AudioResamplerCubic.cpp.arm \
    AudioResamplerSinc.cpp.arm \
    AudioResamplerDyn.cpp.arm \
    BufferProviders.cpp \
    RecordBufferConverter.cpp \

LOCAL_C_INCLUDES := \
    $(TOP) \
    $(call include-path-for, audio-utils) \
    $(LOCAL_PATH)/include \

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include

LOCAL_SHARED_LIBRARIES := \
    libaudiohal \
    libaudioutils \
    libcutils \
    liblog \
    libnbaio \
    libsonic \
    libutils \

LOCAL_MODULE := libaudioprocessing

LOCAL_CFLAGS := -Werror -Wall

# uncomment to disable NEON on architectures that actually do support NEON, for benchmarking
#LOCAL_CFLAGS += -DUSE_NEON=false

include $(BUILD_SHARED_LIBRARY)

include $(call all-makefiles-under,$(LOCAL_PATH))
