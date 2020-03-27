/*
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

#ifndef WRITER_LISTENER_H_
#define WRITER_LISTENER_H_

#include <mutex>

#include <media/IMediaRecorderClient.h>
#include <media/mediarecorder.h>

using namespace android;
using namespace std;

class WriterListener : public BnMediaRecorderClient {
  public:
    WriterListener() : mSignaledSize(false), mSignaledDuration(false) {}

    virtual void notify(int32_t msg, int32_t ext1, int32_t ext2) {
        ALOGV("msg : %d, ext1 : %d, ext2 : %d", msg, ext1, ext2);
        if (ext1 == MEDIA_RECORDER_INFO_MAX_FILESIZE_REACHED) {
            mSignaledSize = true;
        } else if (ext1 == MEDIA_RECORDER_INFO_MAX_DURATION_REACHED) {
            mSignaledDuration = true;
        }
    }

    volatile bool mSignaledSize;
    volatile bool mSignaledDuration;
};

#endif  // WRITER_LISTENER_H_
