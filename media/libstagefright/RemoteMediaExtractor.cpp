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

//#define LOG_NDEBUG 0
#define LOG_TAG "RemoteMediaExtractor"
#include <utils/Log.h>

#include <binder/IPCThreadState.h>
#include <media/stagefright/InterfaceUtils.h>
#include <media/MediaMetricsItem.h>
#include <media/stagefright/MediaSource.h>
#include <media/stagefright/RemoteMediaExtractor.h>

// still doing some on/off toggling here.
#define MEDIA_LOG       1

namespace android {

// key for media statistics
static const char *kKeyExtractor = "extractor";

// attrs for media statistics
// NB: these are matched with public Java API constants defined
// in frameworks/base/media/java/android/media/MediaExtractor.java
// These must be kept synchronized with the constants there.
static const char *kExtractorFormat = "android.media.mediaextractor.fmt";
static const char *kExtractorMime = "android.media.mediaextractor.mime";
static const char *kExtractorTracks = "android.media.mediaextractor.ntrk";
static const char *kExtractorEntryPoint = "android.media.mediaextractor.entry";

static const char *kEntryPointSdk = "sdk";
static const char *kEntryPointWithJvm = "ndk-with-jvm";
static const char *kEntryPointNoJvm = "ndk-no-jvm";
static const char *kEntryPointOther = "other";

RemoteMediaExtractor::RemoteMediaExtractor(
        MediaExtractor *extractor,
        const sp<DataSource> &source,
        const sp<RefBase> &plugin)
    :mExtractor(extractor),
     mSource(source),
     mExtractorPlugin(plugin) {

    mMetricsItem = nullptr;
    if (MEDIA_LOG) {
        mMetricsItem = mediametrics::Item::create(kKeyExtractor);

        // we're in the extractor service, we want to attribute to the app
        // that invoked us.
        int uid = IPCThreadState::self()->getCallingUid();
        mMetricsItem->setUid(uid);

        // track the container format (mpeg, aac, wvm, etc)
        size_t ntracks = extractor->countTracks();
        mMetricsItem->setCString(kExtractorFormat, extractor->name());
        // tracks (size_t)
        mMetricsItem->setInt32(kExtractorTracks, ntracks);
        // metadata
        MetaDataBase pMetaData;
        if (extractor->getMetaData(pMetaData) == OK) {
            String8 xx = pMetaData.toString();
            // 'titl' -- but this verges into PII
            // 'mime'
            const char *mime = nullptr;
            if (pMetaData.findCString(kKeyMIMEType, &mime)) {
                mMetricsItem->setCString(kExtractorMime,  mime);
            }
            // what else is interesting and not already available?
        }
        // By default, we set the entry point to be "other". Clients of this
        // class will override this value by calling setEntryPoint.
        mMetricsItem->setCString(kExtractorEntryPoint, kEntryPointOther);
    }
}

RemoteMediaExtractor::~RemoteMediaExtractor() {
    delete mExtractor;
    mSource->close();
    mSource.clear();
    mExtractorPlugin = nullptr;
    // log the current record, provided it has some information worth recording
    if (MEDIA_LOG) {
        if (mMetricsItem != nullptr) {
            if (mMetricsItem->count() > 0) {
                mMetricsItem->selfrecord();
            }
        }
    }
    if (mMetricsItem != nullptr) {
        delete mMetricsItem;
        mMetricsItem = nullptr;
    }
}

size_t RemoteMediaExtractor::countTracks() {
    return mExtractor->countTracks();
}

sp<IMediaSource> RemoteMediaExtractor::getTrack(size_t index) {
    MediaTrack *source = mExtractor->getTrack(index);
    return (source == nullptr)
            ? nullptr : CreateIMediaSourceFromMediaSourceBase(this, source, mExtractorPlugin);
}

sp<MetaData> RemoteMediaExtractor::getTrackMetaData(size_t index, uint32_t flags) {
    sp<MetaData> meta = new MetaData();
    if (mExtractor->getTrackMetaData(*meta.get(), index, flags) == OK) {
        return meta;
    }
    return nullptr;
}

sp<MetaData> RemoteMediaExtractor::getMetaData() {
    sp<MetaData> meta = new MetaData();
    if (mExtractor->getMetaData(*meta.get()) == OK) {
        return meta;
    }
    return nullptr;
}

status_t RemoteMediaExtractor::getMetrics(Parcel *reply) {
    if (mMetricsItem == nullptr || reply == nullptr) {
        return UNKNOWN_ERROR;
    }

    mMetricsItem->writeToParcel(reply);
    return OK;
}

uint32_t RemoteMediaExtractor::flags() const {
    return mExtractor->flags();
}

status_t RemoteMediaExtractor::setMediaCas(const HInterfaceToken &casToken) {
    return mExtractor->setMediaCas((uint8_t*)casToken.data(), casToken.size());
}

String8 RemoteMediaExtractor::name() {
    return String8(mExtractor->name());
}

status_t RemoteMediaExtractor::setEntryPoint(EntryPoint entryPoint) {
    const char* entryPointString;
    switch (entryPoint) {
      case EntryPoint::SDK:
            entryPointString = kEntryPointSdk;
            break;
        case EntryPoint::NDK_WITH_JVM:
            entryPointString = kEntryPointWithJvm;
            break;
        case EntryPoint::NDK_NO_JVM:
            entryPointString = kEntryPointNoJvm;
            break;
        case EntryPoint::OTHER:
            entryPointString = kEntryPointOther;
            break;
        default:
            return BAD_VALUE;
    }
    mMetricsItem->setCString(kExtractorEntryPoint, entryPointString);
    return OK;
}

////////////////////////////////////////////////////////////////////////////////

// static
sp<IMediaExtractor> RemoteMediaExtractor::wrap(
        MediaExtractor *extractor,
        const sp<DataSource> &source,
        const sp<RefBase> &plugin) {
    if (extractor == nullptr) {
        return nullptr;
    }
    return new RemoteMediaExtractor(extractor, source, plugin);
}

}  // namespace android
