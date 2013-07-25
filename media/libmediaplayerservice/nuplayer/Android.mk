# This file was modified by Dolby Laboratories, Inc. The portions of the
# code that are surrounded by "DOLBY..." are copyrighted and
# licensed separately, as follows:
#
# (C)  2016 Dolby Laboratories, Inc.
# All rights reserved.
#
# This program is protected under international and U.S. Copyright laws as
# an unpublished work. This program is confidential and proprietary to the
# copyright owners. Reproduction or disclosure, in whole or in part, or the
# production of derivative works therefrom without the express permission of
# the copyright owners is prohibited.
#
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
        NuPlayerRenderer.cpp            \
        NuPlayerStreamListener.cpp      \
        RTSPSource.cpp                  \
        StreamingSource.cpp             \

LOCAL_C_INCLUDES := \
	$(TOP)/frameworks/av/media/libstagefright                     \
	$(TOP)/frameworks/av/media/libstagefright/httplive            \
	$(TOP)/frameworks/av/media/libstagefright/include             \
	$(TOP)/frameworks/av/media/libstagefright/mpeg2ts             \
	$(TOP)/frameworks/av/media/libstagefright/rtsp                \
	$(TOP)/frameworks/av/media/libstagefright/timedtext           \
	$(TOP)/frameworks/av/media/libmediaplayerservice              \
	$(TOP)/frameworks/native/include/media/openmax                \
	$(TOP)/frameworks/av/include/media                            \
	$(TOP)/frameworks/av/media/libavextensions

LOCAL_CFLAGS += -Werror -Wall

# enable experiments only in userdebug and eng builds
ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DENABLE_STAGEFRIGHT_EXPERIMENTS
endif
# DOLBY_START
ifeq ($(strip $(DOLBY_ENABLE)),true)
    LOCAL_CFLAGS += $(dolby_cflags)
endif
# DOLBY_END

LOCAL_CLANG := true

LOCAL_MODULE:= libstagefright_nuplayer

LOCAL_MODULE_TAGS := eng

include $(BUILD_STATIC_LIBRARY)

