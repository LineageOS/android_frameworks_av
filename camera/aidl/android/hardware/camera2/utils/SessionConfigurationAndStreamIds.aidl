/*
 * Copyright (C) 2025 The Android Open Source Project
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

package android.hardware.camera2.utils;

import android.hardware.camera2.params.SessionConfiguration;

/**
 * Stream ids and session configuration as the input to ICameraDevice.configureStreams call.
 * @hide
 */
parcelable SessionConfigurationAndStreamIds {
    /**
     * The  output stream ids that are deleted.
     */
    int[] deletedStreamIds;

    /**
     * The input stream id that is deleted.
     */
    int deletedInputStreamId = -1;

    /**
     * The session configuration object that contains the new stream ids to be created
     * and session parameters.
     */

    SessionConfiguration sessionConfigurationDelta;

    long createSessionTime = 0;
}