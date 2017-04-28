LOCAL_PATH:= $(call my-dir)

ifneq ($(TARGET_BUILD_PDK), true)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=       \
        HTTPHelper.cpp          \

LOCAL_C_INCLUDES:= \
	$(TOP)/frameworks/av/media/libstagefright \
	$(TOP)/frameworks/native/include/media/openmax \
	$(TOP)/frameworks/base/core/jni \

LOCAL_SHARED_LIBRARIES := \
    liblog libutils libbinder \
    libandroid_runtime \
    libmedia

LOCAL_MODULE:= libstagefright_http_support

LOCAL_CFLAGS += -Wno-multichar

LOCAL_CFLAGS += -Werror -Wall
LOCAL_SANITIZE := signed-integer-overflow

include $(BUILD_SHARED_LIBRARY)

endif
