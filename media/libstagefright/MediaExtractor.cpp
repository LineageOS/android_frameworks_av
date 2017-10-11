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

//#define LOG_NDEBUG 0
#define LOG_TAG "MediaExtractor"
#include <utils/Log.h>
#include <inttypes.h>
#include <pwd.h>

#include <binder/IServiceManager.h>
#include <binder/MemoryDealer.h>

#include <media/MediaAnalyticsItem.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/DataSource.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaExtractor.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/RemoteMediaExtractor.h>
#include <media/IMediaExtractor.h>
#include <media/IMediaExtractorService.h>
#include <media/IMediaSource.h>
#include <cutils/properties.h>
#include <utils/String8.h>
#include <private/android_filesystem_config.h>

// still doing some on/off toggling here.
#define MEDIA_LOG       1

#include <sys/types.h>
#include <dirent.h>
#include <dlfcn.h>

namespace android {

// key for media statistics
static const char *kKeyExtractor = "extractor";
// attrs for media statistics
static const char *kExtractorMime = "android.media.mediaextractor.mime";
static const char *kExtractorTracks = "android.media.mediaextractor.ntrk";
static const char *kExtractorFormat = "android.media.mediaextractor.fmt";

MediaExtractor::MediaExtractor() {
    if (!LOG_NDEBUG) {
        uid_t uid = getuid();
        struct passwd *pw = getpwuid(uid);
        ALOGV("extractor created in uid: %d (%s)", getuid(), pw->pw_name);
    }

    mAnalyticsItem = NULL;
    if (MEDIA_LOG) {
        mAnalyticsItem = new MediaAnalyticsItem(kKeyExtractor);
        (void) mAnalyticsItem->generateSessionID();
    }
}

MediaExtractor::~MediaExtractor() {

    // log the current record, provided it has some information worth recording
    if (MEDIA_LOG) {
        if (mAnalyticsItem != NULL) {
            if (mAnalyticsItem->count() > 0) {
                mAnalyticsItem->setFinalized(true);
                mAnalyticsItem->selfrecord();
            }
        }
    }
    if (mAnalyticsItem != NULL) {
        delete mAnalyticsItem;
        mAnalyticsItem = NULL;
    }
}

sp<IMediaExtractor> MediaExtractor::asIMediaExtractor() {
    return RemoteMediaExtractor::wrap(sp<MediaExtractor>(this));
}

sp<MetaData> MediaExtractor::getMetaData() {
    return new MetaData;
}

status_t MediaExtractor::getMetrics(Parcel *reply) {

    if (mAnalyticsItem == NULL || reply == NULL) {
        return UNKNOWN_ERROR;
    }

    populateMetrics();
    mAnalyticsItem->writeToParcel(reply);

    return OK;
}

void MediaExtractor::populateMetrics() {
    ALOGV("MediaExtractor::populateMetrics");
    // normally overridden in subclasses
}

uint32_t MediaExtractor::flags() const {
    return CAN_SEEK_BACKWARD | CAN_SEEK_FORWARD | CAN_PAUSE | CAN_SEEK;
}

// static
sp<IMediaExtractor> MediaExtractor::Create(
        const sp<DataSource> &source, const char *mime) {
    ALOGV("MediaExtractor::Create %s", mime);

    if (!property_get_bool("media.stagefright.extractremote", true)) {
        // local extractor
        ALOGW("creating media extractor in calling process");
        sp<MediaExtractor> extractor = CreateFromService(source, mime);
        return (extractor.get() == nullptr) ? nullptr : extractor->asIMediaExtractor();
    } else {
        // remote extractor
        ALOGV("get service manager");
        sp<IBinder> binder = defaultServiceManager()->getService(String16("media.extractor"));

        if (binder != 0) {
            sp<IMediaExtractorService> mediaExService(interface_cast<IMediaExtractorService>(binder));
            sp<IMediaExtractor> ex = mediaExService->makeExtractor(source->asIDataSource(), mime);
            return ex;
        } else {
            ALOGE("extractor service not running");
            return NULL;
        }
    }
    return NULL;
}

sp<MediaExtractor> MediaExtractor::CreateFromService(
        const sp<DataSource> &source, const char *mime) {

    ALOGV("MediaExtractor::CreateFromService %s", mime);
    RegisterDefaultSniffers();

    // initialize source decryption if needed
    source->DrmInitialization(nullptr /* mime */);

    sp<AMessage> meta;

    CreatorFunc creator = NULL;
    String8 tmp;
    float confidence;
    creator = sniff(source, &tmp, &confidence, &meta);
    if (!creator) {
        ALOGV("FAILED to autodetect media content.");
        return NULL;
    }

    mime = tmp.string();
    ALOGV("Autodetected media content as '%s' with confidence %.2f",
         mime, confidence);

    MediaExtractor *ret = creator(source, meta);

    if (ret != NULL) {
        // track the container format (mpeg, aac, wvm, etc)
        if (MEDIA_LOG) {
            if (ret->mAnalyticsItem != NULL) {
                size_t ntracks = ret->countTracks();
                ret->mAnalyticsItem->setCString(kExtractorFormat,  ret->name());
                // tracks (size_t)
                ret->mAnalyticsItem->setInt32(kExtractorTracks,  ntracks);
                // metadata
                sp<MetaData> pMetaData = ret->getMetaData();
                if (pMetaData != NULL) {
                    String8 xx = pMetaData->toString();
                    // 'titl' -- but this verges into PII
                    // 'mime'
                    const char *mime = NULL;
                    if (pMetaData->findCString(kKeyMIMEType, &mime)) {
                        ret->mAnalyticsItem->setCString(kExtractorMime,  mime);
                    }
                    // what else is interesting and not already available?
                }
            }
        }
    }

    return ret;
}

Mutex MediaExtractor::gSnifferMutex;
List<MediaExtractor::ExtractorDef> MediaExtractor::gSniffers;
bool MediaExtractor::gSniffersRegistered = false;

// static
MediaExtractor::CreatorFunc MediaExtractor::sniff(
        const sp<DataSource> &source, String8 *mimeType, float *confidence, sp<AMessage> *meta) {
    *mimeType = "";
    *confidence = 0.0f;
    meta->clear();

    {
        Mutex::Autolock autoLock(gSnifferMutex);
        if (!gSniffersRegistered) {
            return NULL;
        }
    }

    CreatorFunc curCreator = NULL;
    CreatorFunc bestCreator = NULL;
    for (List<ExtractorDef>::iterator it = gSniffers.begin();
         it != gSniffers.end(); ++it) {
        String8 newMimeType;
        float newConfidence;
        sp<AMessage> newMeta;
        if ((curCreator = (*it).sniff(source, &newMimeType, &newConfidence, &newMeta))) {
            if (newConfidence > *confidence) {
                *mimeType = newMimeType;
                *confidence = newConfidence;
                *meta = newMeta;
                bestCreator = curCreator;
            }
        }
    }

    return bestCreator;
}

// static
void MediaExtractor::RegisterSniffer_l(const ExtractorDef &def) {
    // sanity check check struct version, uuid, name
    if (def.def_version == 0 || def.def_version > EXTRACTORDEF_VERSION) {
        ALOGE("don't understand extractor format %u, ignoring.", def.def_version);
        return;
    }
    if (memcmp(&def.extractor_uuid, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) == 0) {
        ALOGE("invalid UUID, ignoring");
        return;
    }
    if (def.extractor_name == NULL || strlen(def.extractor_name) == 0) {
        ALOGE("extractors should have a name, ignoring");
        return;
    }

    for (List<ExtractorDef>::iterator it = gSniffers.begin();
            it != gSniffers.end(); ++it) {
        if (memcmp(&((*it).extractor_uuid), &def.extractor_uuid, 16) == 0) {
            // there's already an extractor with the same uuid
            if ((*it).extractor_version < def.extractor_version) {
                // this one is newer, replace the old one
                ALOGW("replacing extractor '%s' version %u with version %u",
                        def.extractor_name,
                        (*it).extractor_version,
                        def.extractor_version);
                gSniffers.erase(it);
                break;
            } else {
                ALOGW("ignoring extractor '%s' version %u in favor of version %u",
                        def.extractor_name,
                        def.extractor_version,
                        (*it).extractor_version);
                return;
            }
        }
    }
    ALOGV("registering extractor for %s", def.extractor_name);
    gSniffers.push_back(def);
}

// static
void MediaExtractor::RegisterDefaultSniffers() {
    Mutex::Autolock autoLock(gSnifferMutex);
    if (gSniffersRegistered) {
        return;
    }

    auto registerExtractors = [](const char *libDirPath) -> void {
        DIR *libDir = opendir(libDirPath);
        if (libDir) {
            struct dirent* libEntry;
            while ((libEntry = readdir(libDir))) {
                String8 libPath = String8(libDirPath) + libEntry->d_name;
                void *libHandle = dlopen(libPath.string(), RTLD_NOW | RTLD_LOCAL);
                if (libHandle) {
                    GetExtractorDef getsniffer = (GetExtractorDef) dlsym(libHandle, "GETEXTRACTORDEF");
                    if (getsniffer) {
                        ALOGV("registering sniffer for %s", libPath.string());
                        RegisterSniffer_l(getsniffer());
                    } else {
                        ALOGW("%s does not contain sniffer", libPath.string());
                        dlclose(libHandle);
                    }
                } else {
                    ALOGW("couldn't dlopen(%s)", libPath.string());
                }
            }

            closedir(libDir);
        } else {
            ALOGE("couldn't opendir(%s)", libDirPath);
        }
    };

    registerExtractors("/system/lib"
#ifdef __LP64__
            "64"
#endif
            "/extractors/");

    registerExtractors("/vendor/lib"
#ifdef __LP64__
            "64"
#endif
            "/extractors/");

    gSniffersRegistered = true;
}


}  // namespace android
