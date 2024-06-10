/*
 * Copyright 2020 The Android Open Source Project
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

#include "FuzzerMediaUtility.h"

namespace android {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // memfd_create() creates an anonymous file and returns a file
    // descriptor that refers to it. MFD_ALLOW_SEALING allows sealing
    // operations on this file.
    int32_t fd = memfd_create("WriterFuzzer", MFD_ALLOW_SEALING);
    if (fd == -1) {
        ALOGE("memfd_create() failed: %s", strerror(errno));
        return 0;
    }

    StandardWriters writerType = fdp.ConsumeEnum<StandardWriters>();
    sp<MetaData> writerMeta = sp<MetaData>::make();

    sp<MediaWriter> writer = createWriter(fd, writerType, writerMeta, &fdp);
    if (writer == nullptr) {
        close(fd);
        return 0;
    }

    if (writerType == StandardWriters::WEBM) {
        // This range is set to avoid CHECK failure in WEBMWriter::reset() -> EbmlVoid::EBmlVoid().
        writer->setMaxFileSize(fdp.ConsumeIntegralInRange<int64_t>(5 * 1024 * 1024, INT64_MAX));
    } else {
        writer->setMaxFileSize(fdp.ConsumeIntegral<int64_t>());
    }
    writer->setMaxFileDuration(fdp.ConsumeIntegral<int64_t>());
    writer->setCaptureRate(fdp.ConsumeFloatingPoint<float>());

    sp<MediaSource> source = createSource(writerType, &fdp);
    writer->addSource(source);
    writer->start(writerMeta.get());
    writer->pause();
    writer->stop();

    close(fd);

    return 0;
}
}  // namespace android
