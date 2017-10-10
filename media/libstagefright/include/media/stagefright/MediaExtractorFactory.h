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

#ifndef MEDIA_EXTRACTOR_FACTORY_H_

#define MEDIA_EXTRACTOR_FACTORY_H_

#include <stdio.h>

#include <media/IMediaExtractor.h>
#include <media/MediaExtractor.h>

namespace android {

class DataSource;

class MediaExtractorFactory {
public:
    static sp<IMediaExtractor> Create(
            const sp<DataSource> &source, const char *mime = NULL);
    static sp<MediaExtractor> CreateFromService(
            const sp<DataSource> &source, const char *mime = NULL);

private:
    static Mutex gSnifferMutex;
    static List<MediaExtractor::ExtractorDef> gSniffers;
    static bool gSniffersRegistered;

    static void RegisterSniffer_l(const MediaExtractor::ExtractorDef &def);

    static MediaExtractor::CreatorFunc sniff(const sp<DataSource> &source,
            String8 *mimeType, float *confidence, sp<AMessage> *meta);

    static void RegisterDefaultSniffers();
};

}  // namespace android

#endif  // MEDIA_EXTRACTOR_FACTORY_H_
