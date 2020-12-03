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

#ifndef ANDROID_MEDIA_TRACK_TRANSCODER_CALLBACK_H
#define ANDROID_MEDIA_TRACK_TRANSCODER_CALLBACK_H

#include <media/NdkMediaError.h>

namespace android {

class MediaTrackTranscoder;

/** Callback interface for MediaTrackTranscoder. */
class MediaTrackTranscoderCallback {
public:
    /**
     * Called when the MediaTrackTranscoder's actual track format becomes available.
     * @param transcoder The MediaTrackTranscoder whose track format becomes available.
     */
    virtual void onTrackFormatAvailable(const MediaTrackTranscoder* transcoder);
    /**
     * Called when the MediaTrackTranscoder instance have finished transcoding all media samples
     * successfully.
     * @param transcoder The MediaTrackTranscoder that finished the transcoding.
     */
    virtual void onTrackFinished(const MediaTrackTranscoder* transcoder);

    /**
     * Called when the MediaTrackTranscoder instance was explicitly stopped before it was finished.
     * @param transcoder The MediaTrackTranscoder that was stopped.
     */
    virtual void onTrackStopped(const MediaTrackTranscoder* transcoder);

    /**
     * Called when the MediaTrackTranscoder instance encountered an error it could not recover from.
     * @param transcoder The MediaTrackTranscoder that encountered the error.
     * @param status The non-zero error code describing the encountered error.
     */
    virtual void onTrackError(const MediaTrackTranscoder* transcoder, media_status_t status);

protected:
    virtual ~MediaTrackTranscoderCallback() = default;
};

}  // namespace android
#endif  // ANDROID_MEDIA_TRACK_TRANSCODER_CALLBACK_H
