/*
 * Copyright (C) 2021 The Android Open Source Project
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

#ifndef MEDIA_MUXER_BASE_H_
#define MEDIA_MUXER_BASE_H_

#include <utils/RefBase.h>
#include "media/stagefright/foundation/ABase.h"

namespace android {

struct ABuffer;
struct AMessage;

// MediaMuxer is used to mux multiple tracks into a video. Currently, we only
// support a mp4 file as the output.
// The expected calling order of the functions is:
// Constructor -> addTrack+ -> start -> writeSampleData+ -> stop
// If muxing operation need to be cancelled, the app is responsible for
// deleting the output file after stop.
struct MediaMuxerBase : public RefBase {
public:
    // Please update media/java/android/media/MediaMuxer.java if the
    // OutputFormat is updated.
    enum OutputFormat {
        OUTPUT_FORMAT_MPEG_4      = 0,
        OUTPUT_FORMAT_WEBM        = 1,
        OUTPUT_FORMAT_THREE_GPP   = 2,
        OUTPUT_FORMAT_HEIF        = 3,
        OUTPUT_FORMAT_OGG         = 4,
        OUTPUT_FORMAT_LIST_END // must be last - used to validate format type
    };

    // Construct the muxer with the file descriptor. Note that the MediaMuxer
    // will close this file at stop().
    MediaMuxerBase() {};

    virtual ~MediaMuxerBase() {};

    /**
     * Add a track with its format information. This should be
     * called before start().
     * @param format the track's format.
     * @return the track's index or negative number if error.
     */
    virtual ssize_t addTrack(const sp<AMessage> &format) = 0;

    /**
     * Start muxing. Make sure all the tracks have been added before
     * calling this.
     */
    virtual status_t start() = 0;

    /**
     * Set the orientation hint.
     * @param degrees The rotation degrees. It has to be either 0,
     *                90, 180 or 270.
     * @return OK if no error.
     */
    virtual status_t setOrientationHint(int degrees) = 0;

    /**
     * Set the location.
     * @param latitude The latitude in degree x 1000. Its value must be in the range
     * [-900000, 900000].
     * @param longitude The longitude in degree x 1000. Its value must be in the range
     * [-1800000, 1800000].
     * @return OK if no error.
     */
    virtual status_t setLocation(int latitude, int longitude) = 0;

    /**
     * Stop muxing.
     * This method is a blocking call. Depending on how
     * much data is bufferred internally, the time needed for stopping
     * the muxer may be time consuming. UI thread is
     * not recommended for launching this call.
     * @return OK if no error.
     */
    virtual status_t stop() = 0;

    /**
     * Send a sample buffer for muxing.
     * The buffer can be reused once this method returns. Typically,
     * this function won't be blocked for very long, and thus there
     * is no need to use a separate thread calling this method to
     * push a buffer.
     * @param buffer the incoming sample buffer.
     * @param trackIndex the buffer's track index number.
     * @param timeUs the buffer's time stamp.
     * @param flags the only supported flag for now is
     *              MediaCodec::BUFFER_FLAG_SYNCFRAME.
     * @return OK if no error.
     */
    virtual status_t writeSampleData(const sp<ABuffer> &buffer, size_t trackIndex,
                             int64_t timeUs, uint32_t flags) = 0 ;

    /**
     * Gets the number of tracks added successfully.  Should be called in
     * INITIALIZED(after constructor) or STARTED(after start()) state.
     * @return the number of tracks or -1 in wrong state.
     */
    virtual ssize_t getTrackCount() = 0;

    /**
     * Gets the format of the track by their index.
     * @param idx : index of the track whose format is wanted.
     * @return smart pointer to AMessage containing the format details.
     */
    virtual sp<AMessage> getTrackFormat(size_t idx) = 0;

private:

    DISALLOW_EVIL_CONSTRUCTORS(MediaMuxerBase);
};

}  // namespace android

#endif  // MEDIA_MUXER_BASE_H_

