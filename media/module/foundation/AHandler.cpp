/*
 * Copyright (C) 2010 The Android Open Source Project
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
#define LOG_TAG "AHandler"
#include <utils/Log.h>

#include <media/stagefright/foundation/AHandler.h>
#include <media/stagefright/foundation/AMessage.h>

namespace android {

void AHandler::deliverMessage(const sp<AMessage> &msg) {
    setDeliveryStatus(true, msg->what(), ALooper::GetNowUs());
    onMessageReceived(msg);
    mMessageCounter++;
    setDeliveryStatus(false, 0, 0);

    if (mVerboseStats) {
        uint32_t what = msg->what();
        ssize_t idx = mMessages.indexOfKey(what);
        if (idx < 0) {
            mMessages.add(what, 1);
        } else {
            mMessages.editValueAt(idx)++;
        }
    }
}

void AHandler::setDeliveryStatus(bool delivering, uint32_t what, int64_t startUs) {
    AutoMutex autoLock(mLock);
    mDeliveringMessage = delivering;
    mCurrentMessageWhat = what;
    mCurrentMessageStartTimeUs = startUs;
}

void AHandler::getDeliveryStatus(bool& delivering, uint32_t& what, int64_t& durationUs) {
    AutoMutex autoLock(mLock);
    delivering = mDeliveringMessage;
    what = mCurrentMessageWhat;
    durationUs = mCurrentMessageStartTimeUs == 0 ?
            0 : ALooper::GetNowUs() - mCurrentMessageStartTimeUs;
}

}  // namespace android
