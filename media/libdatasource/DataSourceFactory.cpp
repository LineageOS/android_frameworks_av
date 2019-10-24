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
#define LOG_TAG "DataSource"


#include <datasource/DataSourceFactory.h>
#include <datasource/DataURISource.h>
#include <datasource/HTTPBase.h>
#include <datasource/FileSource.h>
#include <datasource/MediaHTTP.h>
#include <datasource/NuCachedSource2.h>
#include <media/MediaHTTPConnection.h>
#include <media/MediaHTTPService.h>
#include <utils/String8.h>

namespace android {

// static
sp<DataSourceFactory> DataSourceFactory::sInstance;
// static
Mutex DataSourceFactory::sInstanceLock;

// static
sp<DataSourceFactory> DataSourceFactory::getInstance() {
    Mutex::Autolock l(sInstanceLock);
    if (!sInstance) {
        sInstance = new DataSourceFactory();
    }
    return sInstance;
}

sp<DataSource> DataSourceFactory::CreateFromURI(
        const sp<MediaHTTPService> &httpService,
        const char *uri,
        const KeyedVector<String8, String8> *headers,
        String8 *contentType,
        HTTPBase *httpSource) {
    if (contentType != NULL) {
        *contentType = "";
    }

    sp<DataSource> source;
    if (!strncasecmp("file://", uri, 7)) {
        source = CreateFileSource(uri + 7);
    } else if (!strncasecmp("http://", uri, 7) || !strncasecmp("https://", uri, 8)) {
        if (httpService == NULL) {
            ALOGE("Invalid http service!");
            return NULL;
        }

        sp<HTTPBase> mediaHTTP = httpSource;
        if (mediaHTTP == NULL) {
            mediaHTTP = static_cast<HTTPBase *>(CreateMediaHTTP(httpService).get());
        }

        String8 cacheConfig;
        bool disconnectAtHighwatermark = false;
        KeyedVector<String8, String8> nonCacheSpecificHeaders;
        if (headers != NULL) {
            nonCacheSpecificHeaders = *headers;
            NuCachedSource2::RemoveCacheSpecificHeaders(
                    &nonCacheSpecificHeaders,
                    &cacheConfig,
                    &disconnectAtHighwatermark);
        }

        if (mediaHTTP->connect(uri, &nonCacheSpecificHeaders) != OK) {
            ALOGE("Failed to connect http source!");
            return NULL;
        }

        if (contentType != NULL) {
            *contentType = mediaHTTP->getMIMEType();
        }

        source = NuCachedSource2::Create(
                mediaHTTP,
                cacheConfig.isEmpty() ? NULL : cacheConfig.string(),
                disconnectAtHighwatermark);
    } else if (!strncasecmp("data:", uri, 5)) {
        source = DataURISource::Create(uri);
    } else {
        // Assume it's a filename.
        source = CreateFileSource(uri);
    }

    if (source == NULL || source->initCheck() != OK) {
        return NULL;
    }

    return source;
}

sp<DataSource> DataSourceFactory::CreateFromFd(int fd, int64_t offset, int64_t length) {
    sp<FileSource> source = new FileSource(fd, offset, length);
    return source->initCheck() != OK ? nullptr : source;
}

sp<DataSource> DataSourceFactory::CreateMediaHTTP(const sp<MediaHTTPService> &httpService) {
    if (httpService == NULL) {
        return NULL;
    }

    sp<MediaHTTPConnection> conn = httpService->makeHTTPConnection();
    if (conn == NULL) {
        ALOGE("Failed to make http connection from http service!");
        return NULL;
    } else {
        return new MediaHTTP(conn);
    }
}

sp<DataSource> DataSourceFactory::CreateFileSource(const char *uri) {
    return new FileSource(uri);
}

}  // namespace android
