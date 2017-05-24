/* Copyright (c) 2017, The Linux Foundation. All rights reserved.
 * Not a Contribution.
 */
/*
 * Copyright (C) 2012 The Android Open Source Project
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

#ifndef ANDROID_SERVERS_CAMERA_CAMERA2_QTIFRAMEPROCESSOR_H
#define ANDROID_SERVERS_CAMERA_CAMERA2_QTIFRAMEPROCESSOR_H

#include <camera/CameraMetadata.h>
#include <utils/RefBase.h>

namespace android {

class Camera2Client;

namespace camera2 {

class QTIFrameProcessor: public virtual RefBase {
    public:
    bool processSingleFrameExtn(const CameraMetadata &metadata,
            sp<Camera2Client> client);
};

}; //namespace camera2
}; //namespace android

#endif
