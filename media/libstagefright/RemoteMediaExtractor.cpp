/*
 * Copyright 2017, The Android Open Source Project
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

#include <media/stagefright/InterfaceUtils.h>
#include <media/MediaSource.h>
#include <media/stagefright/RemoteMediaExtractor.h>

namespace android {

RemoteMediaExtractor::RemoteMediaExtractor(const sp<MediaExtractor> &extractor)
    :mExtractor(extractor) {}

RemoteMediaExtractor::~RemoteMediaExtractor() {}

size_t RemoteMediaExtractor::countTracks() {
    return mExtractor->countTracks();
}

sp<IMediaSource> RemoteMediaExtractor::getTrack(size_t index) {
    sp<MediaSource> source = mExtractor->getTrack(index);
    return (source.get() == nullptr) ? nullptr : CreateIMediaSourceFromMediaSource(source);
}

sp<MetaData> RemoteMediaExtractor::getTrackMetaData(size_t index, uint32_t flags) {
    return mExtractor->getTrackMetaData(index, flags);
}

sp<MetaData> RemoteMediaExtractor::getMetaData() {
    return mExtractor->getMetaData();
}

status_t RemoteMediaExtractor::getMetrics(Parcel *reply) {
    return mExtractor->getMetrics(reply);
}

uint32_t RemoteMediaExtractor::flags() const {
    return mExtractor->flags();
}

char* RemoteMediaExtractor::getDrmTrackInfo(size_t trackID, int * len) {
    return mExtractor->getDrmTrackInfo(trackID, len);
}

void RemoteMediaExtractor::setUID(uid_t uid) {
    return mExtractor->setUID(uid);
}

status_t RemoteMediaExtractor::setMediaCas(const HInterfaceToken &casToken) {
    return mExtractor->setMediaCas(casToken);
}

const char * RemoteMediaExtractor::name() {
    return mExtractor->name();
}

void RemoteMediaExtractor::release() {
    return mExtractor->release();
}

////////////////////////////////////////////////////////////////////////////////

// static
sp<IMediaExtractor> RemoteMediaExtractor::wrap(const sp<MediaExtractor> &extractor) {
    if (extractor.get() == nullptr) {
        return nullptr;
    }
    return new RemoteMediaExtractor(extractor);
}

}  // namespace android
