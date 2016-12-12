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

#include "include/AMRExtractor.h"
#include "include/MP3Extractor.h"
#include "include/MPEG4Extractor.h"
#include "include/WAVExtractor.h"
#include "include/OggExtractor.h"
#include "include/MPEG2PSExtractor.h"
#include "include/MPEG2TSExtractor.h"
#include "include/DRMExtractor.h"
#include "include/FLACExtractor.h"
#include "include/AACExtractor.h"
#include "include/MidiExtractor.h"

#include "matroska/MatroskaExtractor.h"

#include <binder/IServiceManager.h>
#include <binder/MemoryDealer.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/DataSource.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaExtractor.h>
#include <media/stagefright/MetaData.h>
#include <media/IMediaExtractorService.h>
#include <cutils/properties.h>
#include <utils/String8.h>
#include <private/android_filesystem_config.h>


namespace android {

MediaExtractor::MediaExtractor():
    mIsDrm(false) {
    if (!LOG_NDEBUG) {
        uid_t uid = getuid();
        struct passwd *pw = getpwuid(uid);
        ALOGI("extractor created in uid: %d (%s)", getuid(), pw->pw_name);
    }

}


sp<MetaData> MediaExtractor::getMetaData() {
    return new MetaData;
}

uint32_t MediaExtractor::flags() const {
    return CAN_SEEK_BACKWARD | CAN_SEEK_FORWARD | CAN_PAUSE | CAN_SEEK;
}



class RemoteDataSource : public BnDataSource {
public:
    enum {
        kBufferSize = 64 * 1024,
    };

    static sp<IDataSource> wrap(const sp<DataSource> &source);
    virtual ~RemoteDataSource();

    virtual sp<IMemory> getIMemory();
    virtual ssize_t readAt(off64_t offset, size_t size);
    virtual status_t getSize(off64_t* size);
    virtual void close();
    virtual uint32_t getFlags();
    virtual String8 toString();
    virtual sp<DecryptHandle> DrmInitialization(const char *mime);

private:
    sp<IMemory> mMemory;
    sp<DataSource> mSource;
    String8 mName;
    explicit RemoteDataSource(const sp<DataSource> &source);
    DISALLOW_EVIL_CONSTRUCTORS(RemoteDataSource);
};


sp<IDataSource> RemoteDataSource::wrap(const sp<DataSource> &source) {
    return new RemoteDataSource(source);
}
RemoteDataSource::RemoteDataSource(const sp<DataSource> &source) {
    mSource = source;
    sp<MemoryDealer> memoryDealer = new MemoryDealer(kBufferSize, "RemoteDataSource");
    mMemory = memoryDealer->allocate(kBufferSize);
    if (mMemory == NULL) {
        ALOGE("Failed to allocate memory!");
    }
    mName = String8::format("RemoteDataSource(%s)", mSource->toString().string());
}
RemoteDataSource::~RemoteDataSource() {
    close();
}
sp<IMemory> RemoteDataSource::getIMemory() {
    return mMemory;
}
ssize_t RemoteDataSource::readAt(off64_t offset, size_t size) {
    ALOGV("readAt(%" PRId64 ", %zu)", offset, size);
    return mSource->readAt(offset, mMemory->pointer(), size);
}
status_t RemoteDataSource::getSize(off64_t* size) {
    return mSource->getSize(size);
}
void RemoteDataSource::close() {
    mSource = NULL;
}
uint32_t RemoteDataSource::getFlags() {
    return mSource->flags();
}

String8 RemoteDataSource::toString() {
    return mName;
}

sp<DecryptHandle> RemoteDataSource::DrmInitialization(const char *mime) {
    return mSource->DrmInitialization(mime);
}

// static
sp<IMediaExtractor> MediaExtractor::Create(
        const sp<DataSource> &source, const char *mime) {
    ALOGV("MediaExtractor::Create %s", mime);

    if (!property_get_bool("media.stagefright.extractremote", true)) {
        // local extractor
        ALOGW("creating media extractor in calling process");
        return CreateFromService(source, mime);
    } else {
        String8 mime8;
        float confidence;
        sp<AMessage> meta;

        // Check if it's es-based DRM, since DRMExtractor needs to be created in the media server
        // process, not the extractor process.
        if (SniffDRM(source, &mime8, &confidence, &meta)) {
            const char *drmMime = mime8.string();
            ALOGV("Detected media content as '%s' with confidence %.2f", drmMime, confidence);
            if (!strncmp(drmMime, "drm+es_based+", 13)) {
                // DRMExtractor sets container metadata kKeyIsDRM to 1
                return new DRMExtractor(source, drmMime + 14);
            } else {
                mime = drmMime + 20; // get real mimetype after "drm+container_based+" prefix
            }
        }

        // remote extractor
        ALOGV("get service manager");
        sp<IBinder> binder = defaultServiceManager()->getService(String16("media.extractor"));

        if (binder != 0) {
            sp<IMediaExtractorService> mediaExService(interface_cast<IMediaExtractorService>(binder));
            sp<IMediaExtractor> ex = mediaExService->makeExtractor(RemoteDataSource::wrap(source), mime);
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

    sp<AMessage> meta;

    String8 tmp;
    if (mime == NULL) {
        float confidence;
        if (!sniff(source, &tmp, &confidence, &meta)) {
            ALOGV("FAILED to autodetect media content.");

            return NULL;
        }

        mime = tmp.string();
        ALOGV("Autodetected media content as '%s' with confidence %.2f",
             mime, confidence);
    }

    MediaExtractor *ret = NULL;
    if (!strcasecmp(mime, MEDIA_MIMETYPE_CONTAINER_MPEG4)
            || !strcasecmp(mime, "audio/mp4")) {
        ret = new MPEG4Extractor(source);
    } else if (!strcasecmp(mime, MEDIA_MIMETYPE_AUDIO_MPEG)) {
        ret = new MP3Extractor(source, meta);
    } else if (!strcasecmp(mime, MEDIA_MIMETYPE_AUDIO_AMR_NB)
            || !strcasecmp(mime, MEDIA_MIMETYPE_AUDIO_AMR_WB)) {
        ret = new AMRExtractor(source);
    } else if (!strcasecmp(mime, MEDIA_MIMETYPE_AUDIO_FLAC)) {
        ret = new FLACExtractor(source);
    } else if (!strcasecmp(mime, MEDIA_MIMETYPE_CONTAINER_WAV)) {
        ret = new WAVExtractor(source);
    } else if (!strcasecmp(mime, MEDIA_MIMETYPE_CONTAINER_OGG)) {
        ret = new OggExtractor(source);
    } else if (!strcasecmp(mime, MEDIA_MIMETYPE_CONTAINER_MATROSKA)) {
        ret = new MatroskaExtractor(source);
    } else if (!strcasecmp(mime, MEDIA_MIMETYPE_CONTAINER_MPEG2TS)) {
        ret = new MPEG2TSExtractor(source);
    } else if (!strcasecmp(mime, MEDIA_MIMETYPE_AUDIO_AAC_ADTS)) {
        ret = new AACExtractor(source, meta);
    } else if (!strcasecmp(mime, MEDIA_MIMETYPE_CONTAINER_MPEG2PS)) {
        ret = new MPEG2PSExtractor(source);
    } else if (!strcasecmp(mime, MEDIA_MIMETYPE_AUDIO_MIDI)) {
        ret = new MidiExtractor(source);
    }

    return ret;
}

Mutex MediaExtractor::gSnifferMutex;
List<MediaExtractor::SnifferFunc> MediaExtractor::gSniffers;
bool MediaExtractor::gSniffersRegistered = false;

// static
bool MediaExtractor::sniff(
        const sp<DataSource> &source, String8 *mimeType, float *confidence, sp<AMessage> *meta) {
    *mimeType = "";
    *confidence = 0.0f;
    meta->clear();

    {
        Mutex::Autolock autoLock(gSnifferMutex);
        if (!gSniffersRegistered) {
            return false;
        }
    }

    for (List<SnifferFunc>::iterator it = gSniffers.begin();
         it != gSniffers.end(); ++it) {
        String8 newMimeType;
        float newConfidence;
        sp<AMessage> newMeta;
        if ((*it)(source, &newMimeType, &newConfidence, &newMeta)) {
            if (newConfidence > *confidence) {
                *mimeType = newMimeType;
                *confidence = newConfidence;
                *meta = newMeta;
            }
        }
    }

    return *confidence > 0.0;
}

// static
void MediaExtractor::RegisterSniffer_l(SnifferFunc func) {
    for (List<SnifferFunc>::iterator it = gSniffers.begin();
         it != gSniffers.end(); ++it) {
        if (*it == func) {
            return;
        }
    }

    gSniffers.push_back(func);
}

// static
void MediaExtractor::RegisterDefaultSniffers() {
    Mutex::Autolock autoLock(gSnifferMutex);
    if (gSniffersRegistered) {
        return;
    }

    RegisterSniffer_l(SniffMPEG4);
    RegisterSniffer_l(SniffMatroska);
    RegisterSniffer_l(SniffOgg);
    RegisterSniffer_l(SniffWAV);
    RegisterSniffer_l(SniffFLAC);
    RegisterSniffer_l(SniffAMR);
    RegisterSniffer_l(SniffMPEG2TS);
    RegisterSniffer_l(SniffMP3);
    RegisterSniffer_l(SniffAAC);
    RegisterSniffer_l(SniffMPEG2PS);
    RegisterSniffer_l(SniffMidi);

    if (property_get_bool("drm.service.enabled", false)) {
        RegisterSniffer_l(SniffDRM);
    }
    gSniffersRegistered = true;
}


}  // namespace android
