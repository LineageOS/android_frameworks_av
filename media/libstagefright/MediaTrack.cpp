/*
 * Copyright (C) 2009 The Android Open Source Project
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

#include <mutex>

#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/Utils.h>

#include <media/MediaTrack.h>
#include <media/MediaExtractorPluginApi.h>
#include <media/NdkMediaErrorPriv.h>
#include <media/NdkMediaFormatPriv.h>

namespace android {

MediaTrack::MediaTrack() {}

MediaTrack::~MediaTrack() {}

////////////////////////////////////////////////////////////////////////////////

void MediaTrack::ReadOptions::setNonBlocking() {
    mNonBlocking = true;
}

void MediaTrack::ReadOptions::clearNonBlocking() {
    mNonBlocking = false;
}

bool MediaTrack::ReadOptions::getNonBlocking() const {
    return mNonBlocking;
}

void MediaTrack::ReadOptions::setSeekTo(int64_t time_us, SeekMode mode) {
    mOptions |= kSeekTo_Option;
    mSeekTimeUs = time_us;
    mSeekMode = mode;
}

bool MediaTrack::ReadOptions::getSeekTo(
        int64_t *time_us, SeekMode *mode) const {
    *time_us = mSeekTimeUs;
    *mode = mSeekMode;
    return (mOptions & kSeekTo_Option) != 0;
}

/* -------------- unwrapper v1 --------------- */

MediaTrackCUnwrapper::MediaTrackCUnwrapper(CMediaTrack *cmediatrack) {
    wrapper = cmediatrack;
}

MediaTrackCUnwrapper::~MediaTrackCUnwrapper() {
    wrapper->free(wrapper->data);
    free(wrapper);
}

status_t MediaTrackCUnwrapper::start() {
    return wrapper->start(wrapper->data);
}

status_t MediaTrackCUnwrapper::stop() {
    return wrapper->stop(wrapper->data);
}

status_t MediaTrackCUnwrapper::getFormat(MetaDataBase& format) {
    return wrapper->getFormat(wrapper->data, format);
}

status_t MediaTrackCUnwrapper::read(MediaBufferBase **buffer, const ReadOptions *options) {

    uint32_t opts = 0;

    if (options && options->getNonBlocking()) {
        opts |= CMediaTrackReadOptions::NONBLOCKING;
    }

    int64_t seekPosition = 0;
    MediaTrack::ReadOptions::SeekMode seekMode;
    if (options && options->getSeekTo(&seekPosition, &seekMode)) {
        opts |= SEEK;
        opts |= (uint32_t) seekMode;
    }


    return wrapper->read(wrapper->data, buffer, opts, seekPosition);
}

bool MediaTrackCUnwrapper::supportNonblockingRead() {
    return wrapper->supportsNonBlockingRead(wrapper->data);
}

/* -------------- unwrapper v2 --------------- */

MediaTrackCUnwrapperV2::MediaTrackCUnwrapperV2(CMediaTrackV2 *cmediatrack2) {
    wrapper = cmediatrack2;
}

MediaTrackCUnwrapperV2::~MediaTrackCUnwrapperV2() {
}

status_t MediaTrackCUnwrapperV2::start() {
    return reverse_translate_error(wrapper->start(wrapper->data));
}

status_t MediaTrackCUnwrapperV2::stop() {
    return reverse_translate_error(wrapper->stop(wrapper->data));
}

status_t MediaTrackCUnwrapperV2::getFormat(MetaDataBase& format) {
    sp<AMessage> msg = new AMessage();
    AMediaFormat *tmpFormat =  AMediaFormat_fromMsg(&msg);
    media_status_t ret = wrapper->getFormat(wrapper->data, tmpFormat);
    sp<MetaData> newMeta = new MetaData();
    convertMessageToMetaData(msg, newMeta);
    delete tmpFormat;
    format = *newMeta;
    return reverse_translate_error(ret);
}

status_t MediaTrackCUnwrapperV2::read(MediaBufferBase **buffer, const ReadOptions *options) {

    uint32_t opts = 0;

    if (options && options->getNonBlocking()) {
        opts |= CMediaTrackReadOptions::NONBLOCKING;
    }

    int64_t seekPosition = 0;
    MediaTrack::ReadOptions::SeekMode seekMode;
    if (options && options->getSeekTo(&seekPosition, &seekMode)) {
        opts |= SEEK;
        opts |= (uint32_t) seekMode;
    }

    return reverse_translate_error(wrapper->read(wrapper->data, buffer, opts, seekPosition));
}

bool MediaTrackCUnwrapperV2::supportNonblockingRead() {
    return wrapper->supportsNonBlockingRead(wrapper->data);
}

}  // namespace android
