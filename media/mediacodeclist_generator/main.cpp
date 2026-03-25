/*
 * Copyright (C) 2026 The Android Open Source Project
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

#define LOG_TAG "MediaCodecListGenerator"
#include <android-base/logging.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/LazyServiceRegistrar.h>
#include <binder/ProcessState.h>
#include <android/media/BnMediaCodecListGenerator.h>
#include <media/stagefright/MediaCodecList.h>

namespace android {

class MediaCodecListGenerator : public media::BnMediaCodecListGenerator {
public:
    binder::Status generateCodecList(std::vector<uint8_t>* _aidl_return) override {
        LOG(INFO) << "Generating MediaCodecList...";
        // This process has its own memory space and UID.
        // It will dlopen all the necessary codec libraries here.
        sp<MediaCodecList> list = MediaCodecList::Build();
        if (list == nullptr) {
            LOG(ERROR) << "Failed to get MediaCodecList instance.";
            return binder::Status::fromExceptionCode(binder::Status::EX_NULL_POINTER);
        }

        Parcel parcel;
        list->writeToParcel(&parcel);

        _aidl_return->assign(parcel.data(), parcel.data() + parcel.dataSize());
        LOG(INFO) << "MediaCodecList generated and serialized ("
                  << _aidl_return->size() << " bytes).";

        return binder::Status::ok();
    }
};

}  // namespace android

int main() {
    using android::MediaCodecListGenerator;
    using android::IPCThreadState;
    using android::OK;
    using android::ProcessState;
    using android::sp;

    // Initialize base logging
    android::base::InitLogging(nullptr, android::base::LogdLogger(android::base::SYSTEM));

    LOG(INFO) << "MediaCodecListGenerator starting...";

    sp<ProcessState> self = ProcessState::self();
    self->setThreadPoolMaxThreadCount(1);
    self->startThreadPool();

    auto service = sp<MediaCodecListGenerator>::make();
    auto& registrar = android::binder::LazyServiceRegistrar::getInstance();
    if (registrar.registerService(service, "media.codeclist.generator") != OK) {
        LOG(ERROR) << "Failed to register media.codeclist.generator service.";
        return 1;
    }

    LOG(INFO) << "MediaCodecListGenerator ready.";
    IPCThreadState::self()->joinThreadPool();
    return 0;
}
