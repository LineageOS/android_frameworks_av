#
# Copyright 2017 The Android Open Source Project
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

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_PACKAGE_NAME := MediaUpdate
LOCAL_MODULE_OWNER := google
LOCAL_PRIVILEGED_MODULE := true

# TODO: create a separate key for this package.
LOCAL_CERTIFICATE := platform

# TODO: Use System SDK once public APIs are approved
# LOCAL_SDK_VERSION := system_current

LOCAL_SRC_FILES := $(call all-java-files-under, src)
LOCAL_PROGUARD_FLAG_FILES := proguard.cfg

LOCAL_MULTILIB := first

# Embed native libraries in package, rather than installing to /system/lib*.
LOCAL_MODULE_TAGS := samples

# To embed native libraries in package, uncomment the lines below.
LOCAL_JNI_SHARED_LIBRARIES := \
    libaacextractor \
    libamrextractor \
    libflacextractor \
    libmidiextractor \
    libmkvextractor \
    libmp3extractor \
    libmp4extractor \
    libmpeg2extractor \
    liboggextractor \
    libwavextractor \

include $(BUILD_PACKAGE)
