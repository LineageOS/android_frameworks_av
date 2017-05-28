LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:=                       \
        GenericSource.cpp               \
        HTTPLiveSource.cpp              \
        NuPlayer.cpp                    \
        NuPlayerCCDecoder.cpp           \
        NuPlayerDecoder.cpp             \
        NuPlayerDecoderBase.cpp         \
        NuPlayerDecoderPassThrough.cpp  \
        NuPlayerDriver.cpp              \
        NuPlayerDrm.cpp                 \
        NuPlayerRenderer.cpp            \
        NuPlayerStreamListener.cpp      \
        RTSPSource.cpp                  \
        StreamingSource.cpp             \

LOCAL_C_INCLUDES := \
	frameworks/av/media/libstagefright                     \
	frameworks/av/media/libstagefright/httplive            \
	frameworks/av/media/libstagefright/include             \
	frameworks/av/media/libstagefright/mpeg2ts             \
	frameworks/av/media/libstagefright/rtsp                \
	frameworks/av/media/libstagefright/timedtext           \
	frameworks/av/media/libmediaplayerservice              \
	frameworks/native/include/media/openmax

LOCAL_CFLAGS += -Werror -Wall

# enable experiments only in userdebug and eng builds
ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DENABLE_STAGEFRIGHT_EXPERIMENTS
endif

LOCAL_SHARED_LIBRARIES :=       \
    libbinder                   \
    libui                       \
    libgui                      \
    libmedia                    \
    libmediadrm                 \

LOCAL_MODULE:= libstagefright_nuplayer

LOCAL_MODULE_TAGS := eng

LOCAL_SANITIZE := cfi
LOCAL_SANITIZE_DIAG := cfi

include $(BUILD_STATIC_LIBRARY)
