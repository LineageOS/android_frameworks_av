/*
 * Copyright (C) 2013 The Android Open Source Project
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

#define LOG_TAG "MediaExtractorService"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <utils/Vector.h>

#include <datasource/DataSourceFactory.h>
#include <media/DataSource.h>
#include <media/stagefright/InterfaceUtils.h>
#include <media/stagefright/MediaExtractorFactory.h>
#include <media/stagefright/RemoteDataSource.h>
#include "MediaExtractorService.h"

namespace android {

MediaExtractorService::MediaExtractorService() {
    MediaExtractorFactory::LoadExtractors();
}

MediaExtractorService::~MediaExtractorService() {
    ALOGE("should not be in ~MediaExtractorService");
}

::android::binder::Status MediaExtractorService::makeExtractor(
        const ::android::sp<::android::IDataSource>& remoteSource,
        const ::std::unique_ptr< ::std::string> &mime,
        ::android::sp<::android::IMediaExtractor>* _aidl_return) {
    ALOGV("@@@ MediaExtractorService::makeExtractor for %s", mime.get()->c_str());

    sp<DataSource> localSource = CreateDataSourceFromIDataSource(remoteSource);

    MediaBuffer::useSharedMemory();
    sp<IMediaExtractor> extractor = MediaExtractorFactory::CreateFromService(
            localSource,
            mime.get() ? mime.get()->c_str() : nullptr);

    ALOGV("extractor service created %p (%s)",
            extractor.get(),
            extractor == nullptr ? "" : extractor->name());

    if (extractor != nullptr) {
        registerMediaExtractor(extractor, localSource, mime.get() ? mime.get()->c_str() : nullptr);
    }
    *_aidl_return = extractor;
    return binder::Status::ok();
}

::android::binder::Status MediaExtractorService::makeIDataSource(
        base::unique_fd fd,
        int64_t offset,
        int64_t length,
        ::android::sp<::android::IDataSource>* _aidl_return) {
    sp<DataSource> source = DataSourceFactory::getInstance()->CreateFromFd(fd.release(), offset, length);
    *_aidl_return = CreateIDataSourceFromDataSource(source);
    return binder::Status::ok();
}

::android::binder::Status MediaExtractorService::getSupportedTypes(
        ::std::vector<::std::string>* _aidl_return) {
    *_aidl_return = MediaExtractorFactory::getSupportedTypes();
    return binder::Status::ok();
}

status_t MediaExtractorService::dump(int fd, const Vector<String16>& args) {
    return MediaExtractorFactory::dump(fd, args) || dumpExtractors(fd, args);
}

}   // namespace android
