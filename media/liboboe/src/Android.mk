LOCAL_PATH:= $(call my-dir)

# ======================= STATIC LIBRARY ==========================
# This is being built because it make Oboe testing very easy with a complete executable.
# TODO Remove this target later, when not needed.
include $(CLEAR_VARS)

LOCAL_MODULE := liboboe
LOCAL_MODULE_TAGS := optional

LOCAL_C_INCLUDES := \
    $(call include-path-for, audio-utils) \
    frameworks/native/include \
    system/core/base/include \
    frameworks/native/media/liboboe/include/include \
    frameworks/av/media/liboboe/include \
    $(LOCAL_PATH)/core \
    $(LOCAL_PATH)/utility \
    $(LOCAL_PATH)/legacy

LOCAL_SRC_FILES += core/AudioStream.cpp
LOCAL_SRC_FILES += core/AudioStreamBuilder.cpp
LOCAL_SRC_FILES += core/OboeAudio.cpp
LOCAL_SRC_FILES += legacy/AudioStreamRecord.cpp
LOCAL_SRC_FILES += legacy/AudioStreamTrack.cpp
LOCAL_SRC_FILES += utility/HandleTracker.cpp
LOCAL_SRC_FILES += utility/OboeUtilities.cpp

LOCAL_CFLAGS += -Wno-unused-parameter
LOCAL_CFLAGS += -Wall -Werror
# By default, all symbols are hidden.
LOCAL_CFLAGS += -fvisibility=hidden
# OBOE_API is used to explicitly export a function or a variable as a visible symbol.
LOCAL_CFLAGS += -DOBOE_API='__attribute__((visibility("default")))'

include $(BUILD_STATIC_LIBRARY)

# ======================= SHARED LIBRARY ==========================
include $(CLEAR_VARS)

LOCAL_MODULE := liboboe
LOCAL_MODULE_TAGS := optional

LOCAL_C_INCLUDES := \
    $(call include-path-for, audio-utils) \
    frameworks/native/include \
    system/core/base/include \
    frameworks/native/media/liboboe/include/include \
    frameworks/av/media/liboboe/include \
    $(LOCAL_PATH)/core \
    $(LOCAL_PATH)/utility \
    $(LOCAL_PATH)/legacy

LOCAL_SRC_FILES += core/AudioStream.cpp
LOCAL_SRC_FILES += core/AudioStreamBuilder.cpp
LOCAL_SRC_FILES += core/OboeAudio.cpp
LOCAL_SRC_FILES += legacy/AudioStreamRecord.cpp
LOCAL_SRC_FILES += legacy/AudioStreamTrack.cpp
LOCAL_SRC_FILES += utility/HandleTracker.cpp
LOCAL_SRC_FILES += utility/OboeUtilities.cpp

LOCAL_CFLAGS += -Wno-unused-parameter
LOCAL_CFLAGS += -Wall -Werror
# By default, all symbols are hidden.
LOCAL_CFLAGS += -fvisibility=hidden
# OBOE_API is used to explicitly export a function or a variable as a visible symbol.
LOCAL_CFLAGS += -DOBOE_API='__attribute__((visibility("default")))'

LOCAL_SHARED_LIBRARIES := libaudioclient liblog libutils
include $(BUILD_SHARED_LIBRARY)
