/*
 * Copyright 2018, The Android Open Source Project
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

#ifndef INPUT_SURFACE_WRAPPER_H_
#define INPUT_SURFACE_WRAPPER_H_

#include <codec2/hidl/client.h>
#include <system/graphics.h>

namespace android {

/**
 * Wrapper interface around InputSurface.
 */
class InputSurfaceWrapper {
public:
    InputSurfaceWrapper()
        : mDataSpace(HAL_DATASPACE_UNKNOWN) {
    }

    virtual ~InputSurfaceWrapper() = default;

    /**
     * Connect the surface with |comp|. A surface can
     * connect to at most one component at a time.
     *
     * \return OK               successfully connected to |comp|
     * \return ALREADY_EXISTS   already connected to another component.
     */
    virtual status_t connect(
            const std::shared_ptr<Codec2Client::Component> &comp) = 0;

    /**
     * Disconnect the surface from the component if any.
     */
    virtual void disconnect() = 0;

    /**
     * Start pushing buffers to the surface.
     */
    virtual status_t start() = 0;

    /**
     * Ref: GraphicBufferSource::signalEndOfInputStream.
     */
    virtual status_t signalEndOfInputStream() = 0;

    /// Input Surface configuration
    struct Config {
        // IN PARAMS (GBS)
        float mMinFps = 0.0; // minimum fps (repeat frame to achieve this)
        float mMaxFps = 0.0; // max fps (via frame drop)
        float mCaptureFps = 0.0; // capture fps
        float mCodedFps = 0.0;   // coded fps
        bool mSuspended = false; // suspended
        int64_t mTimeOffsetUs = 0; // time offset (input => codec)
        int64_t mSuspendAtUs = 0; // suspend/resume time
        int64_t mStartAtUs = 0; // start time
        bool mStopped = false; // stopped
        int64_t mStopAtUs = 0; // stop time

        // OUT PARAMS (GBS)
        int64_t mInputDelayUs = 0; // delay between encoder input and surface input

        // IN PARAMS (CODEC WRAPPER)
        float mFixedAdjustedFps = 0.0; // fixed fps via PTS manipulation
        float mMinAdjustedFps = 0.0; // minimum fps via PTS manipulation
        uint64_t mUsage = 0; // consumer usage
    };

    /**
     * Configures input surface.
     *
     * \param config configuration. This can be updated during this call to provide output
     *               parameters, but not to provide configured parameters (to avoid continually
     *               reconfiguring)
     */
    virtual status_t configure(Config &config) = 0;

    /**
     * Configures desired data space.
     *
     * \param dataSpace desired data space
     */
    inline void setDataSpace(android_dataspace dataSpace) {
        mDataSpace = dataSpace;
    }

    /**
     * Clean up C2Work related references if necessary. No-op by default.
     *
     * \param index index of input work.
     */
    virtual void onInputBufferDone(c2_cntr64_t /* index */) {}

    /**
     * Returns dataspace information from GraphicBufferSource.
     */
    virtual android_dataspace getDataspace() { return mDataSpace; }

protected:
    android_dataspace mDataSpace;
};

}  // namespace android

#endif  // INPUT_SURFACE_WRAPPER_H_
