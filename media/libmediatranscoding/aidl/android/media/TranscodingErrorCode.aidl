/**
 * Copyright (c) 2019, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.media;

/**
 * Type enums of video transcoding errors.
 *
 * {@hide}
 */
@Backing(type = "int")
enum TranscodingErrorCode {
    // Errors exposed to client side.
    kNoError = 0,
    kDroppedByService = 1,
    kServiceUnavailable = 2,

    // Other private errors.
    kPrivateErrorFirst     = 1000,
    kUnknown               = kPrivateErrorFirst + 0,
    kMalformed             = kPrivateErrorFirst + 1,
    kUnsupported           = kPrivateErrorFirst + 2,
    kInvalidParameter      = kPrivateErrorFirst + 3,
    kInvalidOperation      = kPrivateErrorFirst + 4,
    kErrorIO               = kPrivateErrorFirst + 5,
    kInsufficientResources = kPrivateErrorFirst + 6,
    kWatchdogTimeout       = kPrivateErrorFirst + 7,
    kUidGoneCancelled      = kPrivateErrorFirst + 8,
}