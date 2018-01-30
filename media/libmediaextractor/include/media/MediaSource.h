/*
 * Copyright (C) 2009 The Android Open Source Project
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

#ifndef MEDIA_SOURCE_H_

#define MEDIA_SOURCE_H_

#include <sys/types.h>

#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/MetaData.h>
#include <utils/RefBase.h>

#include "media/MediaSourceBase.h"

namespace android {

class MediaBuffer;

struct MediaSource : public MediaSourceBase, public virtual RefBase {
    MediaSource();

    virtual ~MediaSource();

private:
    MediaSource(const MediaSource &);
    MediaSource &operator=(const MediaSource &);
};

}  // namespace android

#endif  // MEDIA_SOURCE_H_
