/*
 * Copyright (C) 2014 The CyanogenMod Project
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

#define CAMERA_PARAMETERS_EXTRA_C \
const char CameraParameters::KEY_SUPPORTED_ISO_MODES[] = "iso-values"; \
const char CameraParameters::KEY_ISO[] = "iso"; \
const char CameraParameters::KEY_CITYID[] = "contextualtag-cityid"; \
const char CameraParameters::KEY_WEATHER[] = "weather"; \
const char CameraParameters::METERING_SPOT[] = "spot"; \
const char CameraParameters::METERING_CENTER[] = "center"; \
const char CameraParameters::METERING_MATRIX[] = "matrix"; \
const char CameraParameters::ISO_AUTO[] = "auto"; \
const char CameraParameters::ISO_50[] = "ISO50"; \
const char CameraParameters::ISO_100[] = "ISO100"; \
const char CameraParameters::ISO_200[] = "ISO200"; \
const char CameraParameters::ISO_400[] = "ISO400"; \
int CameraParameters::getInt64(const char *key) const {    return -1; } ;


#define CAMERA_PARAMETERS_EXTRA_H \
    static const char KEY_SUPPORTED_ISO_MODES[]; \
    static const char KEY_ISO[]; \
    static const char KEY_CITYID[]; \
    static const char KEY_WEATHER[]; \
    static const char METERING_CENTER[]; \
    static const char METERING_SPOT[]; \
    static const char METERING_MATRIX[]; \
    static const char ISO_AUTO[]; \
    static const char ISO_50[]; \
    static const char ISO_100[]; \
    static const char ISO_200[]; \
    static const char ISO_400[]; \
    int getInt64(const char *key) const;
    
