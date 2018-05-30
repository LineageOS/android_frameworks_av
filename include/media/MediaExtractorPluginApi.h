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

#ifndef MEDIA_EXTRACTOR_PLUGIN_API_H_
#define MEDIA_EXTRACTOR_PLUGIN_API_H_

#include <utils/Errors.h> // for status_t

namespace android {

struct MediaTrack;
class MetaDataBase;
class DataSourceBase;

extern "C" {

struct CMediaExtractor {
    void *data;

    void (*free)(void *data);
    size_t (*countTracks)(void *data);
    MediaTrack* (*getTrack)(void *data, size_t index);
    status_t (*getTrackMetaData)(
            void *data,
            MetaDataBase& meta,
            size_t index, uint32_t flags);

    status_t (*getMetaData)(void *data, MetaDataBase& meta);
    uint32_t (*flags)(void *data);
    status_t (*setMediaCas)(void *data, const uint8_t* casToken, size_t size);
    const char * (*name)(void *data);
};

typedef CMediaExtractor* (*CreatorFunc)(DataSourceBase *source, void *meta);
typedef void (*FreeMetaFunc)(void *meta);

// The sniffer can optionally fill in an opaque object, "meta", that helps
// the corresponding extractor initialize its state without duplicating
// effort already exerted by the sniffer. If "freeMeta" is given, it will be
// called against the opaque object when it is no longer used.
typedef CreatorFunc (*SnifferFunc)(
        DataSourceBase *source, float *confidence,
        void **meta, FreeMetaFunc *freeMeta);

typedef struct {
    const uint8_t b[16];
} media_uuid_t;

typedef struct {
    // version number of this structure
    const uint32_t def_version;

    // A unique identifier for this extractor.
    // See below for a convenience macro to create this from a string.
    media_uuid_t extractor_uuid;

    // Version number of this extractor. When two extractors with the same
    // uuid are encountered, the one with the largest version number will
    // be used.
    const uint32_t extractor_version;

    // a human readable name
    const char *extractor_name;

    // the sniffer function
    const SnifferFunc sniff;
} ExtractorDef;

const uint32_t EXTRACTORDEF_VERSION = 1;

// each plugin library exports one function of this type
typedef ExtractorDef (*GetExtractorDef)();

} // extern "C"

}  // namespace android

#endif  // MEDIA_EXTRACTOR_PLUGIN_API_H_
