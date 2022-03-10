/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef AIDL_CLEARKEY_PROPERTIES_H
#define AIDL_CLEARKEY_PROPERTIES_H
#include <string>

namespace clearkeydrm {
static const std::string kAidlVendorValue("Google");
static const std::string kAidlVersionValue("aidl-1");
static const std::string kAidlPluginDescriptionValue("ClearKey CDM");
static const std::string kAidlAlgorithmsValue("");
static const std::string kAidlListenerTestSupportValue("true");

static const std::string kAidlDrmErrorTestValue("");
static const std::string kAidlResourceContentionValue("resourceContention");
static const std::string kAidlLostStateValue("lostState");
static const std::string kAidlFrameTooLargeValue("frameTooLarge");
static const std::string kAidlInvalidStateValue("invalidState");
}  // namespace clearkeydrm

#endif