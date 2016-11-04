LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES += \
    AudioEffect.cpp \
    AudioPolicy.cpp \
    AudioRecord.cpp \
    AudioSystem.cpp \
    AudioTrack.cpp \
    AudioTrackShared.cpp \
    IAudioFlinger.cpp \
    IAudioFlingerClient.cpp \
    IAudioPolicyService.cpp \
    IAudioPolicyServiceClient.cpp \
    IAudioRecord.cpp \
    IAudioTrack.cpp \
    IEffect.cpp \
    IEffectClient.cpp \
    ToneGenerator.cpp \

LOCAL_SHARED_LIBRARIES := \
	liblog libcutils libutils libbinder \
        libdl libaudioutils \

LOCAL_EXPORT_SHARED_LIBRARY_HEADERS := libbinder

# for memory heap analysis
LOCAL_STATIC_LIBRARIES := libc_malloc_debug_backtrace libc_logging

LOCAL_MODULE:= libaudioclient

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk

LOCAL_C_INCLUDES := \
    $(TOP)/frameworks/native/include/media/openmax \
    $(TOP)/frameworks/av/include/media/ \
    $(TOP)/frameworks/av/media/libstagefright \
    $(TOP)/frameworks/av/media/libmedia/aidl \
    $(call include-path-for, audio-utils)

LOCAL_EXPORT_C_INCLUDE_DIRS := \
    frameworks/av/include/media \
    frameworks/av/media/libmedia/aidl

LOCAL_CFLAGS += -Werror -Wno-error=deprecated-declarations -Wall
LOCAL_SANITIZE := unsigned-integer-overflow signed-integer-overflow

include $(BUILD_SHARED_LIBRARY)

