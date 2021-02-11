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
// Authors: corbin.souffrant@leviathansecurity.com
//          dylan.katz@leviathansecurity.com

#include <fuzzer/FuzzedDataProvider.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/MediaClock.h>

namespace android {
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
    sp<MediaClock> mClock(new MediaClock);

    bool registered = false;
    while (fdp.remaining_bytes() > 0) {
        switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 5)) {
            case 0: {
                if (registered == false) {
                    mClock->init();
                    registered = true;
                }
                break;
                }
            case 1: {
                int64_t startingTimeMediaUs = fdp.ConsumeIntegral<int64_t>();
                mClock->setStartingTimeMedia(startingTimeMediaUs);
                break;
            }
            case 2: {
                mClock->clearAnchor();
                break;
            }
            case 3: {
                int64_t anchorTimeRealUs = fdp.ConsumeIntegral<int64_t>();
                int64_t anchorTimeMediaUs = fdp.ConsumeIntegral<int64_t>();
                int64_t maxTimeMediaUs = fdp.ConsumeIntegral<int64_t>();
                mClock->updateAnchor(anchorTimeMediaUs, anchorTimeRealUs,
                                     maxTimeMediaUs);
                break;
            }
            case 4: {
                int64_t maxTimeMediaUs = fdp.ConsumeIntegral<int64_t>();
                mClock->updateMaxTimeMedia(maxTimeMediaUs);
                break;
                }
            case 5: {
                wp<AMessage> msg(new AMessage);
                mClock->setNotificationMessage(msg.promote());
            }
        }
    }

    return 0;
}
}  // namespace android
