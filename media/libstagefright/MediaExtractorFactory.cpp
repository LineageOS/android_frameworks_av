/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <binder/IServiceManager.h>
#include <media/DataSource.h>
#include <media/MediaAnalyticsItem.h>
#include <media/MediaExtractor.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/FileSource.h>
#include <media/stagefright/InterfaceUtils.h>
#include <media/stagefright/MediaExtractorFactory.h>
#include <media/stagefright/MetaData.h>
#include <media/IMediaExtractor.h>
#include <media/IMediaExtractorService.h>
#include <cutils/properties.h>
#include <utils/String8.h>

#include <dirent.h>
#include <dlfcn.h>

namespace android {

// attrs for media statistics
static const char *kExtractorMime = "android.media.mediaextractor.mime";
static const char *kExtractorTracks = "android.media.mediaextractor.ntrk";
static const char *kExtractorFormat = "android.media.mediaextractor.fmt";

// static
sp<IMediaExtractor> MediaExtractorFactory::Create(
        const sp<DataSource> &source, const char *mime) {
    ALOGV("MediaExtractorFactory::%s %s", __func__, mime);

    if (!property_get_bool("media.stagefright.extractremote", true)) {
        // local extractor
        ALOGW("creating media extractor in calling process");
        sp<MediaExtractor> extractor = CreateFromService(source, mime);
        return CreateIMediaExtractorFromMediaExtractor(extractor);
    } else {
        // remote extractor
        ALOGV("get service manager");
        sp<IBinder> binder = defaultServiceManager()->getService(String16("media.extractor"));

        if (binder != 0) {
            sp<IMediaExtractorService> mediaExService(interface_cast<IMediaExtractorService>(binder));
            sp<IMediaExtractor> ex = mediaExService->makeExtractor(
                    CreateIDataSourceFromDataSource(source), mime);
            return ex;
        } else {
            ALOGE("extractor service not running");
            return NULL;
        }
    }
    return NULL;
}

// static
sp<IMediaExtractor> MediaExtractorFactory::CreateFromFd(
        int fd, int64_t offset, int64_t length, const char *mime, sp<DataSource> *out) {
    ALOGV("MediaExtractorFactory::%s %s", __func__, mime);

    if (property_get_bool("media.stagefright.extractremote", true)) {
        // remote extractor
        ALOGV("get service manager");
        sp<IBinder> binder = defaultServiceManager()->getService(String16("media.extractor"));

        if (binder != 0) {
            sp<IMediaExtractorService> mediaExService(
                    interface_cast<IMediaExtractorService>(binder));
            if (!FileSource::requiresDrm(fd, offset, length, nullptr /* mime */)) {
                ALOGD("FileSource remote");
                sp<IDataSource> remoteSource =
                    mediaExService->makeIDataSource(fd, offset, length);
                ALOGV("IDataSource(FileSource): %p %d %lld %lld",
                        remoteSource.get(), fd, (long long)offset, (long long)length);
                if (remoteSource.get() != nullptr) {
                    // replace the caller's local source with remote source.
                    *out = CreateDataSourceFromIDataSource(remoteSource);
                    return mediaExService->makeExtractor(remoteSource, mime);
                } else {
                    ALOGW("extractor service cannot make file source."
                            " falling back to local file source.");
                }
            }
            // Falls back.
        } else {
            ALOGE("extractor service not running");
            return nullptr;
        }
    }
    *out = new FileSource(fd, offset, length);
    return Create(*out, mime);
}

sp<MediaExtractor> MediaExtractorFactory::CreateFromService(
        const sp<DataSource> &source, const char *mime) {

    ALOGV("MediaExtractorFactory::%s %s", __func__, mime);
    RegisterDefaultSniffers();

    // initialize source decryption if needed
    source->DrmInitialization(nullptr /* mime */);

    sp<AMessage> meta;

    MediaExtractor::CreatorFunc creator = NULL;
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

Mutex MediaExtractorFactory::gSnifferMutex;
List<MediaExtractor::ExtractorDef> MediaExtractorFactory::gSniffers;
bool MediaExtractorFactory::gSniffersRegistered = false;

// static
MediaExtractor::CreatorFunc MediaExtractorFactory::sniff(
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

    MediaExtractor::CreatorFunc curCreator = NULL;
    MediaExtractor::CreatorFunc bestCreator = NULL;
    for (List<MediaExtractor::ExtractorDef>::iterator it = gSniffers.begin();
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
void MediaExtractorFactory::RegisterSniffer_l(const MediaExtractor::ExtractorDef &def) {
    // sanity check check struct version, uuid, name
    if (def.def_version == 0 || def.def_version > MediaExtractor::EXTRACTORDEF_VERSION) {
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

    for (List<MediaExtractor::ExtractorDef>::iterator it = gSniffers.begin();
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
void MediaExtractorFactory::RegisterDefaultSniffers() {
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
                    MediaExtractor::GetExtractorDef getsniffer =
                            (MediaExtractor::GetExtractorDef) dlsym(libHandle, "GETEXTRACTORDEF");
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
