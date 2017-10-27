LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=       \
        stagefright.cpp \
        jpeg.cpp        \
        SineSource.cpp

LOCAL_HEADER_LIBRARIES := \
        media_plugin_headers \

LOCAL_SHARED_LIBRARIES := \
        libstagefright libmedia libmediaextractor libutils libbinder \
        libstagefright_foundation libjpeg libui libgui libcutils liblog \
        libhidlbase \
        android.hardware.media.omx@1.0 \

LOCAL_C_INCLUDES:= \
        external/jpeg \

LOCAL_CFLAGS += -Wno-multichar -Werror -Wall

LOCAL_MODULE_TAGS := optional

LOCAL_MODULE:= stagefright

include $(BUILD_EXECUTABLE)

################################################################################

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=         \
        SineSource.cpp    \
        record.cpp

LOCAL_HEADER_LIBRARIES := \
        media_plugin_headers \

LOCAL_SHARED_LIBRARIES := \
        libstagefright libmedia libmediaextractor liblog libutils libbinder \
        libstagefright_foundation

LOCAL_CFLAGS += -Wno-multichar -Werror -Wall

LOCAL_MODULE_TAGS := optional

LOCAL_MODULE:= record

include $(BUILD_EXECUTABLE)

################################################################################

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=         \
        SineSource.cpp    \
        recordvideo.cpp

LOCAL_HEADER_LIBRARIES := \
        media_plugin_headers \

LOCAL_SHARED_LIBRARIES := \
        libstagefright libmedia libmediaextractor liblog libutils libbinder \
        libstagefright_foundation

LOCAL_CFLAGS += -Wno-multichar -Werror -Wall

LOCAL_MODULE_TAGS := optional

LOCAL_MODULE:= recordvideo

include $(BUILD_EXECUTABLE)


################################################################################

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=         \
        SineSource.cpp    \
        audioloop.cpp

LOCAL_HEADER_LIBRARIES := \
        media_plugin_headers \

LOCAL_SHARED_LIBRARIES := \
        libstagefright libmedia libmediaextractor liblog libutils libbinder \
        libstagefright_foundation

LOCAL_CFLAGS += -Wno-multichar -Werror -Wall

LOCAL_MODULE_TAGS := optional

LOCAL_MODULE:= audioloop

include $(BUILD_EXECUTABLE)

################################################################################

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=         \
        stream.cpp    \

LOCAL_HEADER_LIBRARIES := \
        media_plugin_headers \

LOCAL_SHARED_LIBRARIES := \
        libstagefright liblog libutils libbinder libui libgui \
        libstagefright_foundation libmedia libcutils

LOCAL_CFLAGS += -Wno-multichar -Werror -Wall

LOCAL_MODULE_TAGS := optional

LOCAL_MODULE:= stream

include $(BUILD_EXECUTABLE)

################################################################################

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=               \
        codec.cpp               \
        SimplePlayer.cpp        \

LOCAL_HEADER_LIBRARIES := \
        media_plugin_headers \

LOCAL_SHARED_LIBRARIES := \
        libstagefright liblog libutils libbinder libstagefright_foundation \
        libmedia libaudioclient libui libgui libcutils

LOCAL_CFLAGS += -Wno-multichar -Werror -Wall

LOCAL_MODULE_TAGS := optional

LOCAL_MODULE:= codec

include $(BUILD_EXECUTABLE)

################################################################################

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
        filters/argbtorgba.rs \
        filters/nightvision.rs \
        filters/saturation.rs \
        mediafilter.cpp \

LOCAL_HEADER_LIBRARIES := \
        media_plugin_headers \

LOCAL_SHARED_LIBRARIES := \
        libstagefright \
        liblog \
        libutils \
        libbinder \
        libstagefright_foundation \
        libmedia \
        libui \
        libgui \
        libcutils \
        libRScpp \

intermediates := $(call intermediates-dir-for,STATIC_LIBRARIES,libRS,TARGET,)
LOCAL_C_INCLUDES += $(intermediates)
LOCAL_C_INCLUDES += frameworks/av/media/libstagefright/filters

LOCAL_STATIC_LIBRARIES:= \
        libstagefright_mediafilter

LOCAL_CFLAGS += -Wno-multichar -Werror -Wall

LOCAL_MODULE_TAGS := optional

LOCAL_MODULE:= mediafilter

LOCAL_SANITIZE := cfi
LOCAL_SANITIZE_DIAG := cfi

include $(BUILD_EXECUTABLE)

################################################################################

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=               \
        muxer.cpp            \

LOCAL_HEADER_LIBRARIES := \
        media_plugin_headers \

LOCAL_SHARED_LIBRARIES := \
        libstagefright liblog libutils libbinder libstagefright_foundation \
        libcutils libc

LOCAL_CFLAGS += -Wno-multichar -Werror -Wall

LOCAL_MODULE_TAGS := optional

LOCAL_MODULE:= muxer

include $(BUILD_EXECUTABLE)
