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
#include <android-base/properties.h>
#include <Codec2CommonUtils.h>
#include <Codec2Mapper.h>
#include <dav1d/dav1d.h>

#define DUMP_FILE_PATH "/data/local/tmp/dump"
#define INPUT_DATA_DUMP_EXT "av1"
#define INPUT_SIZE_DUMP_EXT "size"
#define OUTPUT_YUV_DUMP_EXT "yuv"

namespace android {
constexpr size_t kFileNameLength = 256;

class C2SoftDav1dDump {
  public:
    void initDumping();
    void destroyDumping();
    void dumpInput(uint8_t* ptr, int new_size);
    template <typename T>
    void dumpOutput(const T* srcY, const T* srcU, const T* srcV, size_t srcYStride,
                    size_t srcUStride, size_t srcVStride, int width, int height);
    void writeDav1dOutYuvFile(const Dav1dPicture& p);

  private:
    int mFramesToDump = 0;
    int mFirstFrameToDump = 0;
    int mOutputCount = 0;

    char mInDataFileName[kFileNameLength];
    char mInSizeFileName[kFileNameLength];
    char mDav1dOutYuvFileName[kFileNameLength];

    FILE* mInDataFile = nullptr;
    FILE* mInSizeFile = nullptr;
    FILE* mDav1dOutYuvFile = nullptr;
};
}  // namespace android
