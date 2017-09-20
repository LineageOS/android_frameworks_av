LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:=                          \
        stagefright/ExtendedMediaDefs.cpp  \
        stagefright/AVUtils.cpp            \
        stagefright/AVFactory.cpp          \

LOCAL_C_INCLUDES:= \
        $(TOP)/frameworks/av/include/media \
        $(TOP)/frameworks/av/media/libstagefright \
        $(TOP)/frameworks/av/media/libstagefright/mpeg2ts \
        $(TOP)/frameworks/av/media/libavextensions \
        $(TOP)/frameworks/native/include/media/hardware \
        $(TOP)/frameworks/native/include/media/openmax \
        $(TOP)/external/flac/include \
        $(TOP)/system/core/base/include

LOCAL_SHARED_LIBRARIES += \
        libcrypto \
        libhidlbase \
        liblog \
        libui \
        libgui \
        libcutils \
        libutils \
        libmediadrm \
        libnativewindow \
        libstagefright \
        android.hardware.media.omx@1.0 \

LOCAL_CFLAGS += -Wno-multichar -Werror

LOCAL_MODULE:= libavextensions

LOCAL_MODULE_TAGS := optional

include $(BUILD_STATIC_LIBRARY)

########################################################

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=                                      \
        mediaplayerservice/AVMediaServiceFactory.cpp   \
        mediaplayerservice/AVMediaServiceUtils.cpp     \
        mediaplayerservice/AVNuFactory.cpp             \
        mediaplayerservice/AVNuUtils.cpp               \

LOCAL_C_INCLUDES:= \
        $(TOP)/frameworks/av/include/media/ \
        $(TOP)/frameworks/av/media/libstagefright/rtsp \
        $(TOP)/frameworks/av/media/libmediaplayerservice \
        $(TOP)/frameworks/av/media/libstagefright/include \
        $(TOP)/frameworks/av/media/libavextensions \
        $(TOP)/frameworks/native/include/media/hardware \
        $(TOP)/frameworks/native/include/media/openmax \
        $(TOP)/external/flac/include \
        $(TOP)/system/core/base/include

LOCAL_SHARED_LIBRARIES += \
        libhidlbase \
        liblog \
        libui \
        libgui \
        libcutils \
        libutils \
        libmediadrm \
        libnativewindow \
        libstagefright \
        android.hardware.media.omx@1.0 \

LOCAL_CFLAGS += -Wno-multichar -Werror

LOCAL_MODULE:= libavmediaserviceextensions

LOCAL_MODULE_TAGS := optional

include $(BUILD_STATIC_LIBRARY)
