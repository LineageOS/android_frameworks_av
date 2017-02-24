LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := android.hardware.media.omx@1.0-impl
LOCAL_SRC_FILES := \
    WGraphicBufferSource.cpp \
    WOmx.cpp \
    WOmxBufferProducer.cpp \
    WOmxBufferSource.cpp \
    WOmxNode.cpp \
    WOmxObserver.cpp \
    WOmxProducerListener.cpp \
    Omx.cpp \

LOCAL_SHARED_LIBRARIES := \
    libmedia \
    libstagefright_foundation \
    libstagefright_omx \
    libui \
    libgui \
    libhidlbase \
    libhidltransport \
    libhwbinder \
    libhidlmemory \
    libutils \
    libcutils \
    libbinder \
    liblog \
    libbase \
    android.hardware.media.omx@1.0 \
    android.hardware.graphics.common@1.0 \
    android.hardware.media@1.0 \
    android.hidl.base@1.0 \

LOCAL_C_INCLUDES += \
        $(TOP)/frameworks/av/include \
        $(TOP)/frameworks/av/media/libstagefright \
        $(TOP)/frameworks/native/include \
        $(TOP)/frameworks/native/include/media/openmax \
        $(TOP)/frameworks/native/include/media/hardware \

include $(BUILD_SHARED_LIBRARY)
