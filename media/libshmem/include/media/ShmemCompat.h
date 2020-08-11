/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

// This module contains utilities for interfacing between legacy code that is using IMemory and new
// code that is using android.os.SharedFileRegion.

#include "android/media/SharedFileRegion.h"
#include "binder/IMemory.h"
#include "utils/StrongPointer.h"

namespace android {
namespace media {

/**
 * Converts a SharedFileRegion parcelable to an IMemory instance.
 * @param shmem The SharedFileRegion instance.
 * @param result The resulting IMemory instance, or null of the SharedFileRegion is null (has a
 *               negative FD).
 * @return true if the conversion is successful (should always succeed under normal circumstances,
 *         failure usually means corrupt data).
 */
bool convertSharedFileRegionToIMemory(const SharedFileRegion& shmem,
                                      sp<IMemory>* result);

/**
 * Converts an IMemory instance to SharedFileRegion.
 * @param mem The IMemory instance. May be null.
 * @param result The resulting SharedFileRegion instance.
 * @return true if the conversion is successful (should always succeed under normal circumstances,
 *         failure usually means corrupt data).
 */
bool convertIMemoryToSharedFileRegion(const sp<IMemory>& mem,
                                      SharedFileRegion* result);

}  // namespace media
}  // namespace android
