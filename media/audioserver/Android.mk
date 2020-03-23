LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	main_audioserver.cpp \

LOCAL_SHARED_LIBRARIES := \
	libaaudioservice \
	libaudioflinger \
	libaudiopolicyservice \
	libaudioprocessing \
	libbinder \
	libcutils \
	liblog \
	libhidlbase \
	libmedia \
	libmedialogservice \
	libmediautils \
	libnbaio \
	libnblog \
	libutils \
	libvibrator

LOCAL_HEADER_LIBRARIES := \
	libaudiohal_headers \
	libmediametrics_headers \

# TODO oboeservice is the old folder name for aaudioservice. It will be changed.
LOCAL_C_INCLUDES := \
	frameworks/av/services/audioflinger \
	frameworks/av/services/audiopolicy \
	frameworks/av/services/audiopolicy/common/managerdefinitions/include \
	frameworks/av/services/audiopolicy/common/include \
	frameworks/av/services/audiopolicy/engine/interface \
	frameworks/av/services/audiopolicy/service \
	frameworks/av/services/medialog \
	frameworks/av/services/oboeservice \
	frameworks/av/media/libaaudio/include \
	frameworks/av/media/libaaudio/src \
	frameworks/av/media/libaaudio/src/binding \
	frameworks/av/media/libmedia/include \
	external/sonic \

LOCAL_MODULE := audioserver

LOCAL_INIT_RC := audioserver.rc

LOCAL_CFLAGS := -Werror -Wall

include $(BUILD_EXECUTABLE)
