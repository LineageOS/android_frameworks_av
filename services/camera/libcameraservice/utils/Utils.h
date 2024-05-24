/*
 * Copyright (C) 2024 The Android Open Source Project
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

#ifndef ANDROID_SERVERS_CAMERA_UTILS_H
#define ANDROID_SERVERS_CAMERA_UTILS_H

namespace android {

/**
 * As of Android V, ro.board.api_level returns the year and month of release (ex. 202404)
 * instead of release SDK version. This function maps year/month format back to release
 * SDK version.
 *
 * Returns defaultVersion if the property is not found.
 */
int getVNDKVersionFromProp(int defaultVersion);

} // namespace android

#endif //ANDROID_SERVERS_CAMERA_UTILS_H
