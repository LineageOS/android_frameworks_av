/* Copyright (c) 2017, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#define LOG_TAG "QTICamera2Client"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0

#include <inttypes.h>
#include <utils/Log.h>
#include <utils/Trace.h>

#include <cutils/properties.h>

#include "api1/Camera2Client.h"
#include "api1/QTICamera2Client.h"

#include "api1/qticlient2/StreamingProcessor.h"
#include "api1/qticlient2/JpegProcessor.h"
#include "api1/qticlient2/CaptureSequencer.h"
#include "api1/qticlient2/CallbackProcessor.h"
#include "api1/qticlient2/ZslProcessor.h"


#define ALOG1(...) ALOGD_IF(gLogLevel >= 1, __VA_ARGS__);
#define ALOG2(...) ALOGD_IF(gLogLevel >= 2, __VA_ARGS__);

namespace android {
using namespace camera2;

QTICamera2Client::QTICamera2Client(sp<Camera2Client> client):
        mParentClient(client) {
}

QTICamera2Client::~QTICamera2Client() {
    ALOGV("%s: Exit", __FUNCTION__);
}

status_t QTICamera2Client::setParametersExtn(Parameters &params) {
    status_t res = OK;
    sp<Camera2Client> client = mParentClient.promote();

    // Check whether preview restart needed.
    // Stop the preview, if there is a need for restart.
    if (params.qtiParams->mNeedRestart) {
        if (params.state >= Parameters::PREVIEW) {
            stopPreviewExtn();
            {
                params.state = Parameters::STOPPED;
            }
        }
        client->mStreamingProcessor->deletePreviewStream();
        client->mStreamingProcessor->deleteRecordingStream();
        client->mJpegProcessor->deleteStream();
        client->mCallbackProcessor->deleteStream();
        client->mZslProcessor->deleteStream();
    }

    return res;
}

status_t QTICamera2Client::stopPreviewExtn() {
    status_t res = OK;
    sp<Camera2Client> client = mParentClient.promote();
    client->syncWithDevice();
    res = client->stopStream();
    if (res != OK) {
        ALOGE("%s: Can't stop streaming: %s (%d)",
                __FUNCTION__, strerror(-res), res);
    }

    res = client->mDevice->flush();
    if (res != OK) {
        ALOGE("%s: Unable to flush pending requests: %s (%d)",
                __FUNCTION__, strerror(-res), res);
    }

    res = client->mDevice->waitUntilDrained();
    if (res != OK) {
        ALOGE("%s: Waiting to stop streaming failed: %s (%d)",
                __FUNCTION__, strerror(-res), res);
    }
    return res;
}
} // namespace android