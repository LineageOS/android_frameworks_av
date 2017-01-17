LOCAL_PATH:= $(call my-dir)

# Oboe Service
include $(CLEAR_VARS)

LOCAL_MODULE := oboeservice
LOCAL_MODULE_TAGS := optional

LIBOBOE_DIR := ../../media/liboboe
LIBOBOE_SRC_DIR := $(LIBOBOE_DIR)/src

LOCAL_C_INCLUDES := \
    $(call include-path-for, audio-utils) \
    frameworks/native/include \
    system/core/base/include \
    $(TOP)/frameworks/native/media/liboboe/include/include \
    $(TOP)/frameworks/av/media/liboboe/include \
    frameworks/native/include \
    $(TOP)/external/tinyalsa/include \
    $(TOP)/frameworks/av/media/liboboe/src \
    $(TOP)/frameworks/av/media/liboboe/src/binding \
    $(TOP)/frameworks/av/media/liboboe/src/client \
    $(TOP)/frameworks/av/media/liboboe/src/core \
    $(TOP)/frameworks/av/media/liboboe/src/fifo \
    $(TOP)/frameworks/av/media/liboboe/src/utility

# TODO These could be in a liboboe_common library
LOCAL_SRC_FILES += \
    $(LIBOBOE_SRC_DIR)/utility/HandleTracker.cpp \
    $(LIBOBOE_SRC_DIR)/utility/OboeUtilities.cpp \
    $(LIBOBOE_SRC_DIR)/fifo/FifoBuffer.cpp \
    $(LIBOBOE_SRC_DIR)/fifo/FifoControllerBase.cpp \
    $(LIBOBOE_SRC_DIR)/binding/SharedMemoryParcelable.cpp \
    $(LIBOBOE_SRC_DIR)/binding/SharedRegionParcelable.cpp \
    $(LIBOBOE_SRC_DIR)/binding/RingBufferParcelable.cpp \
    $(LIBOBOE_SRC_DIR)/binding/AudioEndpointParcelable.cpp \
    $(LIBOBOE_SRC_DIR)/binding/OboeStreamRequest.cpp \
    $(LIBOBOE_SRC_DIR)/binding/OboeStreamConfiguration.cpp \
    $(LIBOBOE_SRC_DIR)/binding/IOboeAudioService.cpp \
    SharedRingBuffer.cpp \
    FakeAudioHal.cpp \
    OboeAudioService.cpp \
    OboeServiceStreamBase.cpp \
    OboeServiceStreamFakeHal.cpp \
    TimestampScheduler.cpp \
    OboeServiceMain.cpp \
    OboeThread.cpp

LOCAL_CFLAGS += -Wno-unused-parameter
LOCAL_CFLAGS += -Wall -Werror

LOCAL_SHARED_LIBRARIES :=  libbinder libcutils libutils liblog libtinyalsa

include $(BUILD_EXECUTABLE)
