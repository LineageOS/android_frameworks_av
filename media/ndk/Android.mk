#
# Copyright (C) 2014 The Android Open Source Project
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
#

LOCAL_PATH:= $(call my-dir)

ifneq ($(TARGET_BUILD_PDK), true)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=                                       \
                  NdkMediaCodec.cpp                     \
                  NdkMediaCrypto.cpp                    \
                  NdkMediaExtractor.cpp                 \
                  NdkMediaFormat.cpp                    \
                  NdkMediaMuxer.cpp                     \
                  NdkMediaDrm.cpp                       \
                  NdkImage.cpp                          \
                  NdkImageReader.cpp                    \

LOCAL_MODULE:= libmediandk

LOCAL_C_INCLUDES := \
    bionic/libc/private \
    external/piex \
    frameworks/base/core/jni \
    frameworks/base/media/jni \
    frameworks/av/include/ndk \
    frameworks/native/include \
    frameworks/native/include/media/openmax \
    system/media/camera/include \
    $(call include-path-for, libhardware)/hardware \

LOCAL_CFLAGS += -fvisibility=hidden -D EXPORT='__attribute__ ((visibility ("default")))'

LOCAL_CFLAGS += -Werror -Wall

LOCAL_STATIC_LIBRARIES := \
    libgrallocusage \

LOCAL_SHARED_LIBRARIES := \
    libbinder \
    libmedia \
    libmedia_jni \
    libmediadrm \
    libskia \
    libstagefright \
    libstagefright_foundation \
    liblog \
    libutils \
    libcutils \
    libandroid \
    libandroid_runtime \
    libbinder \
    libgui \
    libui \
    libandroid \

include $(BUILD_SHARED_LIBRARY)

endif
