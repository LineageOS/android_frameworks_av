LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
    DeviceHalLocal.cpp          \
    DevicesFactoryHalLocal.cpp  \
    EffectHalLocal.cpp          \
    EffectsFactoryHalLocal.cpp  \
    StreamHalLocal.cpp

LOCAL_MODULE := libaudiohal

LOCAL_SHARED_LIBRARIES := \
    libcutils \
    libhardware \
    liblog \
    libeffects \
    libutils

LOCAL_CFLAGS := -Werror -Wall

include $(BUILD_SHARED_LIBRARY)
