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
struct ExtractorPlugin;

class MediaExtractorFactory {
public:
    static sp<IMediaExtractor> Create(
            const sp<DataSource> &source, const char *mime = NULL);
    // Creates media extractor from the given file descriptor. To avoid binder calls for
    // reading file data, this tries to create remote file source in extractor service.
    // If that fails, this falls back to local file source. The data source used for extractor
    // will be alsp returned with |out|.
    static sp<IMediaExtractor> CreateFromFd(
            int fd, int64_t offset, int64_t length, const char *mime, sp<DataSource> *out);
    static sp<IMediaExtractor> CreateFromService(
            const sp<DataSource> &source, const char *mime = NULL);
    static void LoadPlugins(const ::std::string& apkPath);

private:
    static Mutex gPluginMutex;
    static std::shared_ptr<List<sp<ExtractorPlugin>>> gPlugins;
    static bool gPluginsRegistered;

    static void RegisterExtractors(
            const char *apkPath, List<sp<ExtractorPlugin>> &pluginList);
    static void RegisterExtractor(
            const sp<ExtractorPlugin> &plugin, List<sp<ExtractorPlugin>> &pluginList);

    static MediaExtractor::CreatorFunc sniff(const sp<DataSource> &source,
            String8 *mimeType, float *confidence, sp<AMessage> *meta,
            sp<ExtractorPlugin> &plugin);

    static void UpdateExtractors(const char *newUpdateApkPath);
};

}  // namespace android

#endif  // MEDIA_EXTRACTOR_FACTORY_H_
