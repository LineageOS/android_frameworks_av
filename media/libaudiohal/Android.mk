LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SHARED_LIBRARIES := \
    libcutils   \
    libeffects  \
    libhardware \
    liblog      \
    libutils

ifeq ($(ENABLE_TREBLE), true)

LOCAL_CFLAGS += -DENABLE_TREBLE

LOCAL_SRC_FILES := \
    ConversionHelperHidl.cpp   \
    DeviceHalHidl.cpp          \
    DevicesFactoryHalHidl.cpp  \
    EffectBufferHalHidl.cpp    \
    EffectHalHidl.cpp          \
    EffectsFactoryHalHidl.cpp  \
    StreamHalHidl.cpp

LOCAL_SHARED_LIBRARIES += \
    libbase          \
    libfmq           \
    libhwbinder      \
    libhidlbase      \
    libhidlmemory    \
    libhidltransport \
    android.hardware.audio@2.0             \
    android.hardware.audio.common@2.0      \
    android.hardware.audio.common@2.0-util \
    android.hardware.audio.effect@2.0      \
    android.hidl.memory@1.0                \
    libmedia_helper

else  # if !ENABLE_TREBLE

LOCAL_SRC_FILES := \
    DeviceHalLocal.cpp          \
    DevicesFactoryHalLocal.cpp  \
    EffectBufferHalLocal.cpp    \
    EffectHalLocal.cpp          \
    EffectsFactoryHalLocal.cpp  \
    StreamHalLocal.cpp
endif  # ENABLE_TREBLE

LOCAL_MODULE := libaudiohal

LOCAL_CFLAGS := -Wall -Werror

include $(BUILD_SHARED_LIBRARY)
