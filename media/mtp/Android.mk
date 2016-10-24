#
# Copyright (C) 2010 The Android Open Source Project
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

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=                                       \
                  AsyncIO.cpp                           \
                  MtpDataPacket.cpp                     \
                  MtpDebug.cpp                          \
                  MtpDevHandle.cpp                      \
                  MtpDevice.cpp                         \
                  MtpDeviceInfo.cpp                     \
                  MtpEventPacket.cpp                    \
                  MtpFfsHandle.cpp                      \
                  MtpObjectInfo.cpp                     \
                  MtpPacket.cpp                         \
                  MtpProperty.cpp                       \
                  MtpRequestPacket.cpp                  \
                  MtpResponsePacket.cpp                 \
                  MtpServer.cpp                         \
                  MtpStorage.cpp                        \
                  MtpStorageInfo.cpp                    \
                  MtpStringBuffer.cpp                   \
                  MtpUtils.cpp                          \

LOCAL_MODULE:= libmtp

LOCAL_CFLAGS := -DMTP_DEVICE -DMTP_HOST -Wall -Wextra -Werror

LOCAL_SHARED_LIBRARIES := libbase libutils libcutils liblog libusbhost libbinder

include $(BUILD_SHARED_LIBRARY)

include $(call all-makefiles-under,$(LOCAL_PATH))
