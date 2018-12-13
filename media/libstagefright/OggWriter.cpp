/*
 * Copyright (C) 2018 The Android Open Source Project
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

#define LOG_TAG "OggWriter"

#include <fcntl.h>
#include <inttypes.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <media/MediaSource.h>
#include <media/mediarecorder.h>
#include <media/stagefright/MediaBuffer.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/OggWriter.h>
#include <media/stagefright/foundation/ADebug.h>
#include "OpusHeader.h"

extern "C" {
#include <ogg/ogg.h>
}

// store the int32 value in little-endian order.
static inline void writeint(char *buf, int base, int32_t val) {
    buf[base + 3] = ((val) >> 24) & 0xff;
    buf[base + 2] = ((val) >> 16) & 0xff;
    buf[base + 1] = ((val) >> 8) & 0xff;
    buf[base] = (val)&0xff;
}

// linkage between our header OggStreamState and the underlying ogg_stream_state
// so that consumers of our interface do not require the ogg headers themselves.
struct OggStreamState : public ogg_stream_state {};

namespace android {

OggWriter::OggWriter(int fd)
      : mFd(dup(fd)),
        mInitCheck(mFd < 0 ? NO_INIT : OK) {
    // empty
}

OggWriter::~OggWriter() {
    if (mStarted) {
        reset();
    }

    if (mFd != -1) {
        close(mFd);
        mFd = -1;
    }

    free(mOs);
}

status_t OggWriter::initCheck() const {
    return mInitCheck;
}

status_t OggWriter::addSource(const sp<MediaSource>& source) {
    if (mInitCheck != OK) {
        return mInitCheck;
    }

    if (mSource != NULL) {
        return UNKNOWN_ERROR;
    }

    // Support is limited to single track of Opus audio.
    const char* mime;
    source->getFormat()->findCString(kKeyMIMEType, &mime);
    const char* opus = MEDIA_MIMETYPE_AUDIO_OPUS;
    if (strncasecmp(mime, opus, strlen(opus))) {
        ALOGE("Track (%s) other than %s is not supported", mime, opus);
        return ERROR_UNSUPPORTED;
    }

    mOs = (OggStreamState*) malloc(sizeof(ogg_stream_state));
    if (ogg_stream_init((ogg_stream_state*)mOs, rand()) == -1) {
        ALOGE("ogg stream init failed");
        return UNKNOWN_ERROR;
    }

    // Write Ogg headers.
    int32_t nChannels = 0;
    if (!source->getFormat()->findInt32(kKeyChannelCount, &nChannels)) {
        ALOGE("Missing format keys for audio track");
        source->getFormat()->dumpToLog();
        return BAD_VALUE;
    }
    source->getFormat()->dumpToLog();

    int32_t sampleRate = 0;
    if (!source->getFormat()->findInt32(kKeySampleRate, &sampleRate)) {
        ALOGE("Missing format key for sample rate");
        source->getFormat()->dumpToLog();
        return UNKNOWN_ERROR;
    }

    mSampleRate = sampleRate;

    OpusHeader header;
    header.channels = nChannels;
    header.num_streams = nChannels;
    header.num_coupled = 0;
    header.channel_mapping = ((nChannels > 8) ? 255 : (nChannels > 2));
    header.gain_db = 0;
    header.skip_samples = 0;

    // headers are 21-bytes + something driven by channel count
    // expect numbers in the low 30's here. WriteOpusHeader() will tell us
    // if things are bad.
    unsigned char header_data[100];
    ogg_packet op;
    ogg_page og;

    const int packet_size = WriteOpusHeader(header, mSampleRate, (uint8_t*)header_data,
                                            sizeof(header_data));

    if (packet_size < 0) {
        ALOGE("opus header writing failed");
        return UNKNOWN_ERROR;
    }
    op.packet = header_data;
    op.bytes = packet_size;
    op.b_o_s = 1;
    op.e_o_s = 0;
    op.granulepos = 0;
    op.packetno = 0;
    ogg_stream_packetin((ogg_stream_state*)mOs, &op);

    int ret;
    while ((ret = ogg_stream_flush((ogg_stream_state*)mOs, &og))) {
        if (!ret) break;
        write(mFd, og.header, og.header_len);
        write(mFd, og.body, og.body_len);
    }


    const char* vendor_string = "libopus";
    const int vendor_length = strlen(vendor_string);
    int user_comment_list_length = 0;

    const int comments_length = 8 + 4 + vendor_length + 4 + user_comment_list_length;
    char* comments = (char*)malloc(comments_length);
    if (comments == NULL) {
        ALOGE("failed to allocate ogg comment buffer");
        return UNKNOWN_ERROR;
    }
    memcpy(comments, "OpusTags", 8);
    writeint(comments, 8, vendor_length);
    memcpy(comments + 12, vendor_string, vendor_length);
    writeint(comments, 12 + vendor_length, user_comment_list_length);

    op.packet = (unsigned char*)comments;
    op.bytes = comments_length;
    op.b_o_s = 0;
    op.e_o_s = 0;
    op.granulepos = 0;
    op.packetno = 1;
    ogg_stream_packetin((ogg_stream_state*)mOs, &op);

    while ((ret = ogg_stream_flush((ogg_stream_state*)mOs, &og))) {
        if (!ret) break;
        write(mFd, og.header, og.header_len);
        write(mFd, og.body, og.body_len);
    }

    mSource = source;
    free(comments);
    return OK;
}

status_t OggWriter::start(MetaData* /* params */) {
    if (mInitCheck != OK) {
        return mInitCheck;
    }

    if (mSource == NULL) {
        return UNKNOWN_ERROR;
    }

    if (mStarted && mPaused) {
        mPaused = false;
        mResumed = true;
        return OK;
    } else if (mStarted) {
        // Already started, does nothing
        return OK;
    }

    status_t err = mSource->start();

    if (err != OK) {
        return err;
    }

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    mReachedEOS = false;
    mDone = false;

    pthread_create(&mThread, &attr, ThreadWrapper, this);
    pthread_attr_destroy(&attr);

    mStarted = true;

    return OK;
}

status_t OggWriter::pause() {
    if (!mStarted) {
        return OK;
    }
    mPaused = true;
    return OK;
}

status_t OggWriter::reset() {
    if (!mStarted) {
        return OK;
    }

    mDone = true;

    void* dummy;
    pthread_join(mThread, &dummy);

    status_t err = static_cast<status_t>(reinterpret_cast<uintptr_t>(dummy));
    {
        status_t status = mSource->stop();
        if (err == OK && (status != OK && status != ERROR_END_OF_STREAM)) {
            err = status;
        }
    }

    mStarted = false;
    return err;
}

bool OggWriter::exceedsFileSizeLimit() {
    if (mMaxFileSizeLimitBytes == 0) {
        return false;
    }
    return mEstimatedSizeBytes > mMaxFileSizeLimitBytes;
}

bool OggWriter::exceedsFileDurationLimit() {
    if (mMaxFileDurationLimitUs == 0) {
        return false;
    }
    return mEstimatedDurationUs > mMaxFileDurationLimitUs;
}

// static
void* OggWriter::ThreadWrapper(void* me) {
    return (void*)(uintptr_t) static_cast<OggWriter*>(me)->threadFunc();
}

status_t OggWriter::threadFunc() {
    mEstimatedDurationUs = 0;
    mEstimatedSizeBytes = 0;
    bool stoppedPrematurely = true;
    int64_t previousPausedDurationUs = 0;
    int64_t maxTimestampUs = 0;
    status_t err = OK;

    prctl(PR_SET_NAME, (unsigned long)"OggWriter", 0, 0, 0);

    while (!mDone) {
        MediaBufferBase* buffer = nullptr;
        err = mSource->read(&buffer);

        if (err != OK) {
            ALOGW("failed to read next buffer");
            break;
        }

        if (mPaused) {
            buffer->release();
            buffer = nullptr;
            continue;
        }
        mEstimatedSizeBytes += buffer->range_length();
        if (exceedsFileSizeLimit()) {
            buffer->release();
            buffer = nullptr;
            notify(MEDIA_RECORDER_EVENT_INFO, MEDIA_RECORDER_INFO_MAX_FILESIZE_REACHED, 0);
            ALOGW("estimated size(%" PRId64 ") exceeds limit (%" PRId64 ")",
                  mEstimatedSizeBytes, mMaxFileSizeLimitBytes);
            break;
        }
        int64_t timestampUs;
        CHECK(buffer->meta_data().findInt64(kKeyTime, &timestampUs));
        if (timestampUs > mEstimatedDurationUs) {
            mEstimatedDurationUs = timestampUs;
        }
        if (mResumed) {
            previousPausedDurationUs += (timestampUs - maxTimestampUs - 20000);
            mResumed = false;
        }

        timestampUs -= previousPausedDurationUs;

        ALOGV("time stamp: %" PRId64 ", previous paused duration: %" PRId64, timestampUs,
              previousPausedDurationUs);
        if (timestampUs > maxTimestampUs) {
            maxTimestampUs = timestampUs;
        }

        if (exceedsFileDurationLimit()) {
            buffer->release();
            buffer = nullptr;
            notify(MEDIA_RECORDER_EVENT_INFO, MEDIA_RECORDER_INFO_MAX_DURATION_REACHED, 0);
            ALOGW("estimated duration(%" PRId64 " us) exceeds limit(%" PRId64 " us)",
                  mEstimatedDurationUs, mMaxFileDurationLimitUs);
            break;
        }

        ogg_packet op;
        ogg_page og;
        op.packet = (uint8_t*)buffer->data() + buffer->range_offset();
        op.bytes = (long)buffer->range_length();
        op.b_o_s = 0;
        op.e_o_s = mReachedEOS ? 1 : 0;
        // granulepos is the total number of PCM audio samples @ 48 kHz, up to and
        // including the current packet.
        ogg_int64_t granulepos = (48000 * mEstimatedDurationUs) / 1000000;
        op.granulepos = granulepos;

        // Headers are at packets 0 and 1.
        op.packetno = 2 + (ogg_int32_t)mCurrentPacketId++;
        ogg_stream_packetin((ogg_stream_state*)mOs, &op);
        size_t n = 0;

        while (ogg_stream_flush((ogg_stream_state*)mOs, &og) > 0) {
            write(mFd, og.header, og.header_len);
            write(mFd, og.body, og.body_len);
            n = n + og.header_len + og.body_len;
        }

        if (n < buffer->range_length()) {
            buffer->release();
            buffer = nullptr;
            err = ERROR_IO;
            break;
        }

        if (err != OK) {
            break;
        }

        stoppedPrematurely = false;

        buffer->release();
        buffer = nullptr;
    }

    // end of stream is an ok thing
    if (err == ERROR_END_OF_STREAM) {
        err = OK;
    }

    if (err == OK && stoppedPrematurely) {
        err = ERROR_MALFORMED;
    }

    close(mFd);
    mFd = -1;
    mReachedEOS = true;

    return err;
}

bool OggWriter::reachedEOS() {
    return mReachedEOS;
}

}  // namespace android
