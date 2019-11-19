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

#ifndef PLAYER_SERVICE_FILE_SOURCE_H_

#define PLAYER_SERVICE_FILE_SOURCE_H_

#include <stdio.h>

#include <datasource/FileSource.h>
#include <media/stagefright/MediaErrors.h>
#include <utils/threads.h>
#include <drm/DrmManagerClient.h>

namespace android {

// FileSource implementation which works on MediaPlayerService.
// Supports OMA(forword-lock) files.
class PlayerServiceFileSource : public FileSource {
public:
    PlayerServiceFileSource(const char *filename);
    // PlayerServiceFileSource takes ownership and will close the fd
    PlayerServiceFileSource(int fd, int64_t offset, int64_t length);

    virtual ssize_t readAt(off64_t offset, void *data, size_t size);

    static bool requiresDrm(int fd, int64_t offset, int64_t length, const char *mime);

protected:
    virtual ~PlayerServiceFileSource();

private:
    /*for DRM*/
    sp<DecryptHandle> mDecryptHandle;
    DrmManagerClient *mDrmManagerClient;
    int64_t mDrmBufOffset;
    ssize_t mDrmBufSize;
    unsigned char *mDrmBuf;

    sp<DecryptHandle> DrmInitialization(const char *mime);
    ssize_t readAtDRM_l(off64_t offset, void *data, size_t size);

    PlayerServiceFileSource(const PlayerServiceFileSource &);
    PlayerServiceFileSource &operator=(const PlayerServiceFileSource &);
};

}  // namespace android

#endif  // PLAYER_SERVICE_FILE_SOURCE_H_

