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

#ifndef ANDROID_MEDIA_EXTRACTOR_SERVICE_H
#define ANDROID_MEDIA_EXTRACTOR_SERVICE_H

#include <binder/BinderService.h>
#include <android/BnMediaExtractorService.h>
#include <android/IMediaExtractor.h>

namespace android {

class MediaExtractorService : public BinderService<MediaExtractorService>, public BnMediaExtractorService
{
public:
    MediaExtractorService();
    virtual ~MediaExtractorService();

    static const char*  getServiceName() { return "media.extractor"; }

    virtual ::android::binder::Status makeExtractor(
            const ::android::sp<::android::IDataSource>& source,
            const ::std::unique_ptr< ::std::string> &mime,
            ::android::sp<::android::IMediaExtractor>* _aidl_return);

    virtual ::android::binder::Status makeIDataSource(
            base::unique_fd fd,
            int64_t offset,
            int64_t length,
            ::android::sp<::android::IDataSource>* _aidl_return);

    virtual ::android::binder::Status getSupportedTypes(::std::vector<::std::string>* _aidl_return);

    virtual status_t dump(int fd, const Vector<String16>& args);

private:
    Mutex               mLock;
};

}   // namespace android

#endif  // ANDROID_MEDIA_EXTRACTOR_SERVICE_H
