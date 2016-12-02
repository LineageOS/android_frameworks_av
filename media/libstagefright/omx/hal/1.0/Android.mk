LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := android.hardware.media.omx@1.0-impl
LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_SRC_FILES := \
    WGraphicBufferSource.cpp \
    WOmx.cpp \
    WOmxBufferSource.cpp \
    WOmxNode.cpp \
    WOmxObserver.cpp \
    Omx.cpp \
    OmxNode.cpp \

LOCAL_SHARED_LIBRARIES := \
    libmedia \
    libstagefright_foundation \
    libstagefright_omx \
    libui \
    libhidlbase \
    libhidltransport \
    libhwbinder \
    libutils \
    libcutils \
    libbinder \
    android.hardware.media.omx@1.0 \
    android.hardware.graphics.common@1.0 \
    android.hardware.media@1.0 \
    android.hidl.base@1.0 \

LOCAL_C_INCLUDES += \
        $(TOP) \
        $(TOP)/frameworks/av/include/media \
        $(TOP)/frameworks/av/media/libstagefright/include \
        $(TOP)/frameworks/native/include/media/hardware \
        $(TOP)/frameworks/native/include/media/openmax

include $(BUILD_SHARED_LIBRARY)
