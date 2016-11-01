LOCAL_PATH:= $(call my-dir)

#
# libmediaanalyticsservice
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=               \
    MediaAnalyticsService.cpp      \

LOCAL_SHARED_LIBRARIES :=       \
    libbinder                   \
    libcutils                   \
    liblog                      \
    libdl                       \
    libgui                      \
    libmedia                    \
    libmediautils               \
    libstagefright_foundation   \
    libutils

LOCAL_EXPORT_SHARED_LIBRARY_HEADERS := libmedia

LOCAL_C_INCLUDES :=                                                 \
    $(TOP)/frameworks/av/media/libstagefright/include               \
    $(TOP)/frameworks/av/media/libstagefright/rtsp                  \
    $(TOP)/frameworks/av/media/libstagefright/wifi-display          \
    $(TOP)/frameworks/av/media/libstagefright/webm                  \
    $(TOP)/frameworks/av/include/media                              \
    $(TOP)/frameworks/av/include/camera                             \
    $(TOP)/frameworks/native/include/media/openmax                  \
    $(TOP)/frameworks/native/include/media/hardware                 \
    $(TOP)/external/tremolo/Tremolo                                 \
    libcore/include                                                 \

LOCAL_CFLAGS += -Werror -Wno-error=deprecated-declarations -Wall
LOCAL_CLANG := true

LOCAL_MODULE:= libmediaanalyticsservice

include $(BUILD_SHARED_LIBRARY)

include $(call all-makefiles-under,$(LOCAL_PATH))
