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

#include <iostream>
#include <math.h>
#include <limits>
#include <string.h>
#include <unistd.h>

#define __force
#define __bitwise
#define __user
#include <sound/asound.h>

#include "tinyalsa/asoundlib.h"

#include "FakeAudioHal.h"

//using namespace oboe;

using sample_t = int16_t;
using std::cout;
using std::endl;

#undef SNDRV_PCM_IOCTL_SYNC_PTR
#define SNDRV_PCM_IOCTL_SYNC_PTR 0xc0884123
#define PCM_ERROR_MAX 128

const int SAMPLE_RATE = 48000;       // Hz
const int CHANNEL_COUNT = 2;

struct pcm {
    int fd;
    unsigned int flags;
    int running:1;
    int prepared:1;
    int underruns;
    unsigned int buffer_size;
    unsigned int boundary;
    char error[PCM_ERROR_MAX];
    struct pcm_config config;
    struct snd_pcm_mmap_status *mmap_status;
    struct snd_pcm_mmap_control *mmap_control;
    struct snd_pcm_sync_ptr *sync_ptr;
    void *mmap_buffer;
    unsigned int noirq_frames_per_msec;
    int wait_for_avail_min;
};

static int pcm_sync_ptr(struct pcm *pcm, int flags) {
    if (pcm->sync_ptr) {
        pcm->sync_ptr->flags = flags;
        if (ioctl(pcm->fd, SNDRV_PCM_IOCTL_SYNC_PTR, pcm->sync_ptr) < 0)
            return -1;
    }
    return 0;
}

int pcm_get_hw_ptr(struct pcm* pcm, unsigned int* hw_ptr) {
    if (!hw_ptr || !pcm) return -EINVAL;

    int result = pcm_sync_ptr(pcm, SNDRV_PCM_SYNC_PTR_HWSYNC);
    if (!result) {
        *hw_ptr = pcm->sync_ptr->s.status.hw_ptr;
    }

    return result;
}

typedef struct stream_tracker {
    struct pcm * pcm;
    int          framesPerBurst;
    sample_t   * hwBuffer;
    int32_t      capacityInFrames;
    int32_t      capacityInBytes;
} stream_tracker_t;

#define FRAMES_PER_BURST_QUALCOMM 192
#define FRAMES_PER_BURST_NVIDIA   128

int fake_hal_open(int card_id, int device_id, fake_hal_stream_ptr *streamPP) {
    int framesPerBurst = FRAMES_PER_BURST_QUALCOMM; // TODO update as needed
    int periodCount = 32;
    unsigned int offset1;
    unsigned int frames1;
    void *area = nullptr;
    int mmapAvail = 0;

    // Configuration for an ALSA stream.
    pcm_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.channels = CHANNEL_COUNT;
    cfg.format = PCM_FORMAT_S16_LE;
    cfg.rate = SAMPLE_RATE;
    cfg.period_count = periodCount;
    cfg.period_size = framesPerBurst;
    cfg.start_threshold = 0; // for NOIRQ, should just start, was     framesPerBurst;
    cfg.stop_threshold = INT32_MAX;
    cfg.silence_size = 0;
    cfg.silence_threshold = 0;
    cfg.avail_min = framesPerBurst;

    stream_tracker_t *streamTracker = (stream_tracker_t *) malloc(sizeof(stream_tracker_t));
    if (streamTracker == nullptr) {
        return -1;
    }
    memset(streamTracker, 0, sizeof(stream_tracker_t));

    streamTracker->pcm = pcm_open(card_id, device_id, PCM_OUT | PCM_MMAP | PCM_NOIRQ, &cfg);
    if (streamTracker->pcm == nullptr) {
        cout << "Could not open device." << endl;
        free(streamTracker);
        return -1;
    }

    streamTracker->framesPerBurst = cfg.period_size; // Get from ALSA
    streamTracker->capacityInFrames = pcm_get_buffer_size(streamTracker->pcm);
    streamTracker->capacityInBytes = pcm_frames_to_bytes(streamTracker->pcm, streamTracker->capacityInFrames);
    std::cout << "fake_hal_open() streamTracker->framesPerBurst = " << streamTracker->framesPerBurst << std::endl;
    std::cout << "fake_hal_open() streamTracker->capacityInFrames = " << streamTracker->capacityInFrames << std::endl;

    if (pcm_is_ready(streamTracker->pcm) < 0) {
        cout << "Device is not ready." << endl;
        goto error;
    }

    if (pcm_prepare(streamTracker->pcm) < 0) {
        cout << "Device could not be prepared." << endl;
        cout << "For Marlin, please enter:" << endl;
        cout << "   adb shell" << endl;
        cout << "   tinymix \"QUAT_MI2S_RX Audio Mixer MultiMedia8\" 1" << endl;
        goto error;
    }
    mmapAvail = pcm_mmap_avail(streamTracker->pcm);
    if (mmapAvail <= 0) {
        cout << "fake_hal_open() mmap_avail is <=0" << endl;
        goto error;
    }
    cout << "fake_hal_open() mmap_avail = " << mmapAvail << endl;

    // Where is the memory mapped area?
    if (pcm_mmap_begin(streamTracker->pcm, &area, &offset1, &frames1) < 0)  {
        cout << "fake_hal_open() pcm_mmap_begin failed" << endl;
        goto error;
    }

    // Clear the buffer.
    memset((sample_t*) area, 0, streamTracker->capacityInBytes);
    streamTracker->hwBuffer = (sample_t*) area;
    streamTracker->hwBuffer[0] = 32000; // impulse

    // Prime the buffer so it can start.
    if (pcm_mmap_commit(streamTracker->pcm, 0, framesPerBurst) < 0) {
        cout << "fake_hal_open() pcm_mmap_commit failed" << endl;
        goto error;
    }

    *streamPP = streamTracker;
    return 1;

error:
    fake_hal_close(streamTracker);
    return -1;
}

int fake_hal_get_mmap_info(fake_hal_stream_ptr stream, mmap_buffer_info *info) {
    stream_tracker_t *streamTracker = (stream_tracker_t *) stream;
    info->fd = streamTracker->pcm->fd; // TODO use tinyalsa function
    info->hw_buffer = streamTracker->hwBuffer;
    info->burst_size_in_frames = streamTracker->framesPerBurst;
    info->buffer_capacity_in_frames = streamTracker->capacityInFrames;
    info->buffer_capacity_in_bytes = streamTracker->capacityInBytes;
    info->sample_rate = SAMPLE_RATE;
    info->channel_count = CHANNEL_COUNT;
    return 0;
}

int fake_hal_start(fake_hal_stream_ptr stream) {
    stream_tracker_t *streamTracker = (stream_tracker_t *) stream;
    if (pcm_start(streamTracker->pcm) < 0) {
        cout << "fake_hal_start failed" << endl;
        return -1;
    }
    return 0;
}

int fake_hal_pause(fake_hal_stream_ptr stream) {
    stream_tracker_t *streamTracker = (stream_tracker_t *) stream;
    if (pcm_stop(streamTracker->pcm) < 0) {
        cout << "fake_hal_stop failed" << endl;
        return -1;
    }
    return 0;
}

int fake_hal_get_frame_counter(fake_hal_stream_ptr stream, int *frame_counter) {
    stream_tracker_t *streamTracker = (stream_tracker_t *) stream;
    if (pcm_get_hw_ptr(streamTracker->pcm, (unsigned int *)frame_counter) < 0) {
        cout << "fake_hal_get_frame_counter failed" << endl;
        return -1;
    }
    return 0;
}

int fake_hal_close(fake_hal_stream_ptr stream) {
    stream_tracker_t *streamTracker = (stream_tracker_t *) stream;
    pcm_close(streamTracker->pcm);
    free(streamTracker);
    return 0;
}

