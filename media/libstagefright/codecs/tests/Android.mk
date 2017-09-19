# Copyright (C) 2017 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	C2SoftAvcDec_test.cpp \

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := c2_google_component_test

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libmedia \
	libstagefright_codec2 \
	libstagefright_soft_c2avcdec \
	liblog \

LOCAL_C_INCLUDES := \
	frameworks/av/media/libstagefright/codec2/include \
	frameworks/av/media/libstagefright/codec2/vndk/include \
	frameworks/av/media/libstagefright/codecs/avcdec \

LOCAL_CFLAGS += -Werror -Wall -std=c++14
LOCAL_CLANG := true

include $(BUILD_NATIVE_TEST)
