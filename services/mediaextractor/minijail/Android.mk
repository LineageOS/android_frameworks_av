LOCAL_PATH := $(call my-dir)

# TODO add filter for x86_64
ifeq ($(TARGET_ARCH), $(filter $(TARGET_ARCH), arm arm64 x86))
include $(CLEAR_VARS)
LOCAL_MODULE := mediaextractor-seccomp.policy
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)/etc/seccomp_policy
LOCAL_SRC_FILES := $(LOCAL_PATH)/seccomp_policy/mediaextractor-seccomp-$(TARGET_ARCH).policy

# allow device specific additions to the syscall whitelist
ifneq (,$(wildcard $(BOARD_SECCOMP_POLICY)/mediaextractor-seccomp.policy))
    LOCAL_SRC_FILES += $(BOARD_SECCOMP_POLICY)/mediaextractor-seccomp.policy
endif

include $(BUILD_SYSTEM)/base_rules.mk

$(LOCAL_BUILT_MODULE): $(LOCAL_SRC_FILES)
	@mkdir -p $(dir $@)
	$(hide) cat > $@ $^

endif
