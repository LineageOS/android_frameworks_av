/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef SAMPLE_AES_PROCESSOR_H_

#define SAMPLE_AES_PROCESSOR_H_

#include <media/stagefright/foundation/AMessage.h>

#include <utils/RefBase.h>

namespace android {

// Base class of HlsSampleDecryptor which has dummy default implementation.
struct SampleDecryptor : RefBase {

    SampleDecryptor() { };

    virtual void signalNewSampleAesKey(const sp<AMessage> &) { };

    virtual size_t processNal(uint8_t *, size_t) { return -1; };
    virtual void processAAC(size_t, uint8_t *, size_t) { };
    virtual void processAC3(uint8_t *, size_t) { };

private:
    DISALLOW_EVIL_CONSTRUCTORS(SampleDecryptor);
};

}  // namespace android

#endif // SAMPLE_AES_PROCESSOR_H_
