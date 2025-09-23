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

/**
 * Output and input stream ids as a result of a ICameraDevice.configureStreams call.
 * @hide
 */
parcelable OutputAndInputStreamIds {
  /**
   * The output stream ids.
   *
   * <p>The output stream ids are the stream ids of the output streams that are
   * configured successfully.
   */
  int[] outputStreamIds;
  /**

   * The input stream id.
   *
   * <p>The input stream id is the stream id of the input stream that is
   * configured successfully.
   */

  int inputStreamId;

  /**
   * The offline stream ids.
   *
   * <p>The offline stream ids are the stream ids of the offline streams that are
   * configured successfully.
   */
  int[] offlineStreamIds;
}