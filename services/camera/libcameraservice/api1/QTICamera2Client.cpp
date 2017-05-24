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
    int32_t prevVidHdr,currVidHdr;

    prevVidHdr = params.qtiParams->prevVideoHdr;
    currVidHdr = params.qtiParams->videoHdr;

    if(prevVidHdr != currVidHdr) {
        ALOGE(" video hdr mode changed %d %d",prevVidHdr,currVidHdr);
        restartVideoHdr(params);
    }

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

status_t QTICamera2Client::restartVideoHdr(Parameters &params)
{
    sp<Camera2Client> client = mParentClient.promote();

    stopPreviewExtn();

    client->mStreamingProcessor->deletePreviewStream();
    client->mStreamingProcessor->deleteRecordingStream();
    client->mJpegProcessor->deleteStream();
    client->mCallbackProcessor->deleteStream();
    client->mZslProcessor->deleteStream();
    client->mZslProcessor->clearZslQueue();

    params.slowJpegMode = false;
    client->updateRequests(params);

    if (params.state == Parameters::STOPPED) {
        client->startPreviewL(params,false);
    }
    return OK;
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

status_t QTICamera2Client::startHFRRecording(Parameters &params) {
    status_t res = OK;
    sp<Camera2Client> client = mParentClient.promote();
    bool needRestart = (params.qtiParams->hfrMode &&
            (params.state >= Parameters::PREVIEW));


    if (needRestart) {
        stopPreviewForRestart(params);
        // Store previous Fps range values,
        // will be useful to restart preview, when recording stops.
        params.qtiParams->nonHfrPreviewFpsRange[0] = params.previewFpsRange[0];
        params.qtiParams->nonHfrPreviewFpsRange[1] = params.previewFpsRange[1];

        params.previewFpsRange[0] = params.qtiParams->hfrPreviewFpsRange[0];
        params.previewFpsRange[1] = params.qtiParams->hfrPreviewFpsRange[1];
    }

    if (params.videoBufferMode != hardware::ICamera::VIDEO_BUFFER_MODE_BUFFER_QUEUE) {
        ALOGE("%s: Camera %d: Recording only supported buffer queue mode, but "
                "mode %d is requested!", __FUNCTION__, client->mCameraId, params.videoBufferMode);
        return INVALID_OPERATION;
    }

    if (!client->mStreamingProcessor->haveValidRecordingWindow()) {
        ALOGE("%s: No valid recording window", __FUNCTION__);
        return INVALID_OPERATION;
    }


    client->sCameraService->playSound(CameraService::SOUND_RECORDING_START);
    client->mStreamingProcessor->updateRecordingRequest(params);
    if (res != OK) {
        ALOGE("%s: Camera %d: Unable to update recording request: %s (%d)",
                __FUNCTION__, client->mCameraId, strerror(-res), res);
        return res;
    }

    // Disable callbacks if they're enabled; can't record and use callbacks,
    // and we can't fail record start without stagefright asserting.
    params.previewCallbackFlags = 0;

    res = client->mStreamingProcessor->updatePreviewStream(params);
    if (res != OK) {
        ALOGE("%s: Camera %d: Unable to update preview stream: "
                "%s (%d)", __FUNCTION__, client->mCameraId,
                strerror(-res), res);
        return res;
    }

    res = client->updateProcessorStream<
        StreamingProcessor,
        &StreamingProcessor::updateRecordingStream>(
                                                    client->mStreamingProcessor,
                                                    params);
    if (res != OK) {
        ALOGE("%s: Camera %d: Unable to update recording stream: "
                "%s (%d)", __FUNCTION__, client->mCameraId,
                strerror(-res), res);
        return res;
    }

    size_t requestListSize = params.qtiParams->hfrPreviewFpsRange[1]/30;
    Vector<Vector<int32_t>> outputStreams;
    for (size_t i = 0; i < requestListSize; i++) {
        Vector<int32_t> request;
        // For first request, add preview + video stream requests
        if (i == 0) {
            request.push(client->getPreviewStreamId());
            request.push(client->getRecordingStreamId());
        } else {
            // For any other request, only add recording stream.
            request.push(client->getRecordingStreamId());
        }
        outputStreams.push(request);
    }

    res = client->mStreamingProcessor->startHfrStream(outputStreams);

    if (res != OK) {
        ALOGE("%s: Camera %d: Unable to start recording stream: %s (%d)",
                __FUNCTION__, client->mCameraId, strerror(-res), res);
        return res;
    }

    if (params.state < Parameters::RECORD) {
        params.state = Parameters::RECORD;
    }

    return res;

}

void QTICamera2Client::stopHFRRecording(Parameters &params) {
    status_t res = OK;
    sp<Camera2Client> client = mParentClient.promote();
    client->sCameraService->playSound(CameraService::SOUND_RECORDING_STOP);

    // We need to reconfigure for the preview.to start in non-hfr mode.
    stopPreviewForRestart(params);

    params.previewFpsRange[0] = params.qtiParams->nonHfrPreviewFpsRange[0];
    params.previewFpsRange[1] = params.qtiParams->nonHfrPreviewFpsRange[1];

    //.Reset the constrained high speed to false.
    client->mDevice->configureStreams(false);

    res = client->startPreviewL(params, false);
    if (res != OK) {
        ALOGE("%s: Camera %d: Unable to re-start preview after recording : %s (%d)",
                __FUNCTION__, client->mCameraId, strerror(-res), res);
        return;
    }

}

void QTICamera2Client::stopPreviewForRestart(Parameters &params) {
    status_t res;
    sp<Camera2Client> client = mParentClient.promote();
    const nsecs_t kStopCaptureTimeout = 3000000000LL; // 3 seconds
    Parameters::State state = params.state;

    switch (state) {
        case Parameters::DISCONNECTED:
            // Nothing to do.
            break;
        case Parameters::STOPPED:
        case Parameters::VIDEO_SNAPSHOT:
        case Parameters::STILL_CAPTURE:
            client->mCaptureSequencer->waitUntilIdle(kStopCaptureTimeout);
            // no break
        case Parameters::RECORD:
        case Parameters::PREVIEW:
            client->syncWithDevice();
            res = client->stopStream();
            if (res != OK) {
                ALOGE("%s: Camera %d: Can't stop streaming: %s (%d)",
                        __FUNCTION__, client->mCameraId, strerror(-res), res);
            }

            // Flush all in-process captures and buffer in order to stop
            // preview faster.
            res = client->mDevice->flush();
            if (res != OK) {
                ALOGE("%s: Camera %d: Unable to flush pending requests: %s (%d)",
                        __FUNCTION__, client->mCameraId, strerror(-res), res);
            }

            res = client->mDevice->waitUntilDrained();
            if (res != OK) {
                ALOGE("%s: Camera %d: Waiting to stop streaming failed: %s (%d)",
                        __FUNCTION__, client->mCameraId, strerror(-res), res);
            }
            // Clean up recording stream
            res = client->mStreamingProcessor->deleteRecordingStream();
            if (res != OK) {
                ALOGE("%s: Camera %d: Unable to delete recording stream before "
                        "stop preview: %s (%d)",
                        __FUNCTION__, client->mCameraId, strerror(-res), res);
            }
            // no break
        case Parameters::WAITING_FOR_PREVIEW_WINDOW: {
            params.state = Parameters::STOPPED;
            client->commandStopFaceDetectionL(params);
            break;
        }
        default:
            ALOGE("%s: Camera %d: Unknown state %d", __FUNCTION__, client->mCameraId,
                    state);
    }

    {
        params.state = Parameters::STOPPED;
    }

    client->mStreamingProcessor->deletePreviewStream();
    client->mStreamingProcessor->deleteRecordingStream();
    client->mJpegProcessor->deleteStream();
    client->mCallbackProcessor->deleteStream();
    client->mZslProcessor->deleteStream();

}

status_t QTICamera2Client::sendCommand(Parameters &params,int32_t cmd, int32_t arg1, int32_t arg2) {
    status_t res = OK;
    switch (cmd) {
        case CAMERA_CMD_METADATA_ON:
            return OK;
        case CAMERA_CMD_METADATA_OFF:
            return OK;
        case CAMERA_CMD_HISTOGRAM_ON:
            params.qtiParams->histogramMode = 1;
            break;
        case CAMERA_CMD_HISTOGRAM_OFF:
            params.qtiParams->histogramMode = 0;
            break;
        case CAMERA_CMD_HISTOGRAM_SEND_DATA:
            return OK;
        default:
            ALOGE("%s: Unknown command %d (arguments %d, %d)",
                    __FUNCTION__, cmd, arg1, arg2);
            return BAD_VALUE;
    }
    return res;
}

} // namespace android

