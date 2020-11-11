/**
 * Copyright (C) 2020 The Android Open Source Project
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
#include <binder/IMemory.h>
#include <binder/MemoryDealer.h>
#include <private/android_filesystem_config.h>
#include "MediaLogService.h"
#include "fuzzer/FuzzedDataProvider.h"

constexpr const char* kWriterNames[2] = {"FastMixer", "FastCapture"};
constexpr size_t kMinSize = 0x100;
constexpr size_t kMaxSize = 0x10000;
constexpr size_t kLogMemorySize = 400 * 1024;
constexpr size_t kMaxNumLines = USHRT_MAX;

using namespace android;

class MediaLogFuzzer {
   public:
    void init();
    void process(const uint8_t* data, size_t size);

   private:
    sp<MemoryDealer> mMemoryDealer = nullptr;
    sp<MediaLogService> mService = nullptr;
};

void MediaLogFuzzer::init() {
    setuid(AID_MEDIA);
    mService = new MediaLogService();
    mMemoryDealer = new MemoryDealer(kLogMemorySize, "MediaLogFuzzer", MemoryHeapBase::READ_ONLY);
}

void MediaLogFuzzer::process(const uint8_t* data, size_t size) {
    FuzzedDataProvider fuzzedDataProvider(data, size);
    size_t writerNameIdx =
        fuzzedDataProvider.ConsumeIntegralInRange<size_t>(0, std::size(kWriterNames) - 1);
    bool shouldDumpBeforeUnregister = fuzzedDataProvider.ConsumeBool();
    size_t logSize = fuzzedDataProvider.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize);
    sp<IMemory> logBuffer = mMemoryDealer->allocate(NBLog::Timeline::sharedSize(logSize));
    Vector<String16> args;
    size_t numberOfLines = fuzzedDataProvider.ConsumeIntegralInRange<size_t>(0, kMaxNumLines);
    for (size_t lineIdx = 0; lineIdx < numberOfLines; ++lineIdx) {
        args.add(static_cast<String16>(fuzzedDataProvider.ConsumeRandomLengthString().c_str()));
    }
    const char* fileName = "logDumpFile";
    int fd = memfd_create(fileName, MFD_ALLOW_SEALING);
    fuzzedDataProvider.ConsumeData(logBuffer->unsecurePointer(), logBuffer->size());
    mService->registerWriter(logBuffer, logSize, kWriterNames[writerNameIdx]);
    if (shouldDumpBeforeUnregister) {
        mService->dump(fd, args);
        mService->unregisterWriter(logBuffer);
    } else {
        mService->unregisterWriter(logBuffer);
        mService->dump(fd, args);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    MediaLogFuzzer mediaLogFuzzer = MediaLogFuzzer();
    mediaLogFuzzer.init();
    mediaLogFuzzer.process(data, size);
    return 0;
}
