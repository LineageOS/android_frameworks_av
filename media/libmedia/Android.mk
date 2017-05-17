LOCAL_PATH := $(call my-dir)

#######################################
# xml/media_profiles_V1_0.dtd

include $(CLEAR_VARS)

LOCAL_MODULE := media_profiles_V1_0.dtd
LOCAL_SRC_FILES := xml/$(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)

include $(BUILD_PREBUILT)

