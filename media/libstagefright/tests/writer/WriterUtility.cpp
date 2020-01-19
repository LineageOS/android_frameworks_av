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

//#define LOG_NDEBUG 0
#define LOG_TAG "WriterUtility"
#include <utils/Log.h>

#include <media/stagefright/MediaBuffer.h>

#include "WriterUtility.h"

int32_t sendBuffersToWriter(ifstream &inputStream, vector<BufferInfo> &bufferInfo,
                            int32_t &inputFrameId, sp<MediaAdapter> &currentTrack, int32_t offset,
                            int32_t range, bool isPaused) {
    while (1) {
        if (inputFrameId >= (int)bufferInfo.size() || inputFrameId >= (offset + range)) break;
        int32_t size = bufferInfo[inputFrameId].size;
        char *data = (char *)malloc(size);
        if (!data) {
            ALOGE("Insufficient memeory to read input");
            return -1;
        }

        inputStream.read(data, size);
        CHECK_EQ(inputStream.gcount(), size);

        sp<ABuffer> buffer = new ABuffer((void *)data, size);
        if (buffer.get() == nullptr) {
            ALOGE("sendBuffersToWriter() got a nullptr buffer.");
            return -1;
        }
        MediaBuffer *mediaBuffer = new MediaBuffer(buffer);

        // Released in MediaAdapter::signalBufferReturned().
        mediaBuffer->add_ref();
        mediaBuffer->set_range(buffer->offset(), buffer->size());

        MetaDataBase &sampleMetaData = mediaBuffer->meta_data();
        sampleMetaData.setInt64(kKeyTime, bufferInfo[inputFrameId].timeUs);
        // Just set the kKeyDecodingTime as the presentation time for now.
        sampleMetaData.setInt64(kKeyDecodingTime, bufferInfo[inputFrameId].timeUs);

        if (bufferInfo[inputFrameId].flags == 1) {
            sampleMetaData.setInt32(kKeyIsSyncFrame, true);
        }

        // This pushBuffer will wait until the mediaBuffer is consumed.
        int status = currentTrack->pushBuffer(mediaBuffer);
        free(data);
        inputFrameId++;

        if (OK != status) {
            if (!isPaused) return status;
            else {
                ALOGD("Writer is in paused state. Input buffers won't get consumed");
                return 0;
            }
        }
    }
    return 0;
}

int32_t writeHeaderBuffers(ifstream &inputStream, vector<BufferInfo> &bufferInfo,
                           int32_t &inputFrameId, sp<AMessage> &format, int32_t numCsds) {
    char csdName[kMaxCSDStrlen];
    for (int csdId = 0; csdId < numCsds; csdId++) {
        int32_t flags = bufferInfo[inputFrameId].flags;
        if (flags == CODEC_CONFIG_FLAG) {
            int32_t size = bufferInfo[inputFrameId].size;
            char *data = (char *)malloc(size);
            if (!data) {
                ALOGE("Insufficient memeory to read input");
                return -1;
            }
            inputStream.read(data, size);
            CHECK_EQ(inputStream.gcount(), size);

            sp<ABuffer> csdBuffer = ABuffer::CreateAsCopy((void *)data, size);
            if (csdBuffer.get() == nullptr || csdBuffer->base() == nullptr) {
                return -1;
            }
            snprintf(csdName, sizeof(csdName), "csd-%d", csdId);
            format->setBuffer(csdName, csdBuffer);
            inputFrameId++;
            free(data);
        }
    }
    return 0;
}
