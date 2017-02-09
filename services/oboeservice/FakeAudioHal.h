/*
 * Copyright (C) 2016 The Android Open Source Project
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

/**
 * Simple fake HAL that supports ALSA MMAP/NOIRQ mode.
 */

#ifndef FAKE_AUDIO_HAL_H
#define FAKE_AUDIO_HAL_H

//namespace aaudio {

using sample_t = int16_t;
struct mmap_buffer_info {
    int       fd;
    int32_t   burst_size_in_frames;
    int32_t   buffer_capacity_in_frames;
    int32_t   buffer_capacity_in_bytes;
    int32_t   sample_rate;
    int32_t   channel_count;
    sample_t *hw_buffer;
};

typedef void *fake_hal_stream_ptr;

//extern "C"
//{

int fake_hal_open(int card_id, int device_id,
                  int frameCapacity,
                  fake_hal_stream_ptr *stream_pp);

int fake_hal_get_mmap_info(fake_hal_stream_ptr stream, mmap_buffer_info *info);

int fake_hal_start(fake_hal_stream_ptr stream);

int fake_hal_pause(fake_hal_stream_ptr stream);

int fake_hal_get_frame_counter(fake_hal_stream_ptr stream, int *frame_counter);

int fake_hal_close(fake_hal_stream_ptr stream);

//} /* "C" */

//} /* namespace aaudio */

#endif // FAKE_AUDIO_HAL_H
