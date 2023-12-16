/*
 * Copyright (C) 2023 The Android Open Source Project
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

// When receive disconnect event, ignore it and leave the shared stream at OPEN
// state. It should be possible to open another shared stream and start it.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <aaudio/AAudio.h>
#include <aaudio/AAudioTesting.h>

static constexpr unsigned int ONE_SECOND = 1e6;
static constexpr unsigned int WAIT_TIME_MS = 10 * ONE_SECOND;
#define MMAP_POLICY              AAUDIO_POLICY_ALWAYS

AAudioStream* openStream() {
    AAudioStreamBuilder *aaudioBuilder = nullptr;
    aaudio_result_t result = AAudio_createStreamBuilder(&aaudioBuilder);
    if (result != AAUDIO_OK) {
        printf("Failed to create stream builder, result=%d, %s\n",
               result, AAudio_convertResultToText(result));
        return nullptr;
    }
    AAudioStreamBuilder_setSharingMode(aaudioBuilder, AAUDIO_SHARING_MODE_SHARED);
    AAudioStreamBuilder_setPerformanceMode(aaudioBuilder, AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
    AAudioStream* aaudioStream;
    result = AAudioStreamBuilder_openStream(aaudioBuilder, &aaudioStream);
    if (result != AAUDIO_OK) {
        printf("ERROR could not open AAudio stream, %d %s\n",
               result, AAudio_convertResultToText(result));
    }
    AAudioStreamBuilder_delete(aaudioBuilder);
    return aaudioStream;
}

aaudio_result_t testNoCloseSharedStreamAfterRoutingChanged(bool stopFirstStream) {
    aaudio_result_t result = AAUDIO_OK;
    printf("Please connect external device that supports MMAP playback, will wait 10 seconds\n");
    usleep(WAIT_TIME_MS);

    // Open first shared stream
    printf("Open first shared stream\n");
    AAudioStream* firstStream = openStream();
    if (firstStream == nullptr) {
        return 1;
    }
    result = AAudioStream_requestStart(firstStream);
    if (result != AAUDIO_OK) {
        return result;
    }

    if (stopFirstStream) {
        printf("Stop first shared stream\n");
        result = AAudioStream_requestStop(firstStream);
        if (result != AAUDIO_OK) {
            return result;
        }
        printf("Wait to make sure the stream is stopped\n");
        usleep(ONE_SECOND * 3);
    }

    printf("Please disconnect and reconnect the external device, will wait 10 second\n");
    usleep(WAIT_TIME_MS);

    // Open second stream after the first shared stream was reconnected
    printf("Open second shared stream\n");
    AAudioStream* secondStream = openStream();
    if (secondStream == nullptr) {
        result = 1;
        goto exit;
    }

    // Starting second stream should be successful
    printf("Start second shared stream\n");
    result = AAudioStream_requestStart(secondStream);
    if (result != AAUDIO_OK) {
        printf("ERROR could not start second stream, %d %s\n",
               result, AAudio_convertResultToText(result));
    }

exit:
    // Close all streams
    AAudioStream_close(firstStream);
    AAudioStream_close(secondStream);
    return result;
}

int main(int argc, char **argv) {
    (void) argc; // unused
    (void) argv; // unused

    aaudio_policy_t originalPolicy = AAudio_getMMapPolicy();
    AAudio_setMMapPolicy(MMAP_POLICY);

    printf("Run first test. The first stream is started when routing changed.\n");
    aaudio_result_t result = testNoCloseSharedStreamAfterRoutingChanged(false /*stopFirstStream*/);

    if (result != AAUDIO_OK) {
        goto exit;
    }

    printf("First test passed\n");
    printf("----------------------------------------------------------------\n");
    printf("Run second test. The first stream is stopped when routing changed.\n");
    if (testNoCloseSharedStreamAfterRoutingChanged(true /*stopFirstStream*/) == AAUDIO_OK) {
        printf("Second test passed\n");
    }

exit:
    AAudio_setMMapPolicy(originalPolicy);

    return result != AAUDIO_OK ? EXIT_FAILURE : EXIT_SUCCESS;
}