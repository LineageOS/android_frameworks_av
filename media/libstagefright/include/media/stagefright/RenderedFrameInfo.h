/*
 * Copyright 2015 The Android Open Source Project
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

#ifndef RENDERED_FRAME_INFO_H
#define RENDERED_FRAME_INFO_H

namespace android {

class RenderedFrameInfo {
public:
    RenderedFrameInfo(int64_t mediaTimeUs, int64_t renderTimeNs)
        : mMediaTimeUs(mediaTimeUs), mRenderTimeNs(renderTimeNs) {}

    int64_t getMediaTimeUs() const  { return mMediaTimeUs; }
    nsecs_t getRenderTimeNs() const { return mRenderTimeNs;}

private:
    int64_t mMediaTimeUs;
    nsecs_t mRenderTimeNs;
};

} // android

#endif // RENDERED_FRAME_INFO_H