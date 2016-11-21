/*
 * Copyright 2016 The Android Open Source Project
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

#ifndef OBOE_LEGACY_H
#define OBOE_LEGACY_H

#include <stdint.h>
#include <oboe/OboeAudio.h>

/**
 * Common code for legacy classes.
 */

/* AudioTrack uses a 32-bit frame counter that can wrap around in about a day. */
typedef uint32_t oboe_wrapping_frames_t;

#endif /* OBOE_LEGACY_H */
