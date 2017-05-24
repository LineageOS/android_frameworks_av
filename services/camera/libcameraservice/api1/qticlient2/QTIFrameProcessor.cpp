/* Copyright (c) 2017, The Linux Foundation. All rights reserved.
 * Not a Contribution.
 */
/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define LOG_TAG "Camera2-QTIFrameProcessor"
#define ATRACE_TAG ATRACE_TAG_CAMERA
#define LOG_NDEBUG 0

#include <utils/Log.h>
#include <utils/Trace.h>

#include "QTIFrameProcessor.h"
#include "api1/Camera2Client.h"

namespace android {
namespace camera2 {

bool QTIFrameProcessor::processSingleFrameExtn(const CameraMetadata &metadata,
        sp<Camera2Client> client) {

    bool result = true;
    status_t res = OK;
    uint8_t enableHistogram = 0;
    uint32_t tag = 0;
    sp<MemoryHeapBase> mHeap;

    camera_metadata_ro_entry_t entry;
    SharedParameters::Lock l(client->getParameters());

    sp<VendorTagDescriptor> vTags =
        VendorTagDescriptor::getGlobalVendorTagDescriptor();
    if ((nullptr == vTags.get()) || (0 >= vTags->getTagCount())) {
        sp<VendorTagDescriptorCache> cache =
                VendorTagDescriptorCache::getGlobalVendorTagCache();
        if (cache.get()) {
            cache->getVendorTagDescriptor(l.mParameters.qtiParams->vendorTagId, &vTags);
        }
    }

    // Find if histogram enabled.
    enableHistogram = l.mParameters.qtiParams->histogramMode;

    if (enableHistogram) {
        res = CameraMetadata::getTagFromName("org.codeaurora.qcamera3.histogram.stats",
                vTags.get(), &tag);
        if(res!=OK)
        {
            ALOGE("couldn't find org.codeaurora.qcamera3.histogram.stats %d",res);
        }
        else if(metadata.exists(tag)) {
            entry = metadata.find(tag);
            if (entry.count > 0) {
                ALOGV("histogram count : %zu %d", entry.count,__LINE__);
            }
            const int32_t hist_size = l.mParameters.qtiParams->histogramBucketSize;
            mHeap = new MemoryHeapBase(entry.count, 0, "histogram");
            const sp<MemoryBase> &histogramData = new MemoryBase(mHeap, 0, entry.count);
            void* temp = (void*)((uint8_t*)mHeap->getBase() + (0*hist_size));
            memcpy(temp, &entry.data.i32[0*hist_size], hist_size*4);
            Camera2Client::SharedCameraCallbacks::Lock lc(client->mSharedCameraCallbacks);
            if (lc.mRemoteCallback != NULL) {
                lc.mRemoteCallback->dataCallback(CAMERA_MSG_STATS_DATA,
                                                            histogramData,
                                                            NULL);
            }

        }
    }
    // Process auto Scene mode
    if(l.mParameters.qtiParams->autoHDREnabled) {
        sp<MemoryHeapBase> mFrameHeap =
                new MemoryHeapBase(sizeof(int)*3, 0, "FrameProcessor::MetaData");
        sp<MemoryBase> FrameBuffer = new MemoryBase(mFrameHeap, 0, sizeof(int)*3);

        status_t res = OK;
        uint32_t tag = 0;
        int HdrData[3];

        camera_metadata_ro_entry_t entry;
        res = CameraMetadata::getTagFromName("org.codeaurora.qcamera3.stats.is_hdr_scene",
                vTags.get(), &tag);
        if (metadata.exists(tag)) {
            entry = metadata.find(tag);
            if (entry.count > 0) {
                // A boolean value indicating if the scene is ideal for HDR capture
                // 0-False/1-True
                {
                    l.mParameters.qtiParams->isHdrScene = entry.data.u8[0];

                    HdrData[0] = CAMERA_META_DATA_HDR;
                    HdrData[1] = sizeof(int)*3;
                    HdrData[2] = l.mParameters.qtiParams->isHdrScene;
                    void* captureMemory = mFrameHeap->getBase();
                    memcpy(captureMemory, HdrData, sizeof(int)*3);

                    Camera2Client::SharedCameraCallbacks::Lock ll(client->mSharedCameraCallbacks);
                    if (ll.mRemoteCallback != NULL) {
                        ll.mRemoteCallback->dataCallback(CAMERA_MSG_META_DATA,
                                                        FrameBuffer,
                                                        (camera_frame_metadata *)&metadata);
                    }
                }
            }
        }
    }
    return result;
}


}; // namespace camera2
}; // namespace android
