LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := android.hardware.media.omx@1.0-impl
LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_SRC_FILES := \
    GraphicBufferSource.cpp \
    Omx.cpp \
    OmxBufferSource.cpp \
    OmxNode.cpp \
    OmxObserver.cpp \

LOCAL_SHARED_LIBRARIES := \
    libhidlbase \
    libhidltransport \
    libhwbinder \
    libutils \
    android.hardware.media.omx@1.0 \
    android.hardware.graphics.common@1.0 \
    android.hardware.media@1.0 \

include $(BUILD_SHARED_LIBRARY)
