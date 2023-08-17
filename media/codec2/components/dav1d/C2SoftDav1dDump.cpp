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
//#define LOG_NDEBUG 0
#define LOG_TAG "C2SoftDav1dDump"
#include "C2SoftDav1dDump.h"

namespace android {

// Flag to enable dumping the bitsteram and the decoded pictures to files.
static const bool ENABLE_DUMPING_FILES_DEFAULT = true;
static const char ENABLE_DUMPING_FILES_PROPERTY[] = "debug.dav1d.enabledumping";

// The number of frames to dump to a file
static const int NUM_FRAMES_TO_DUMP_DEFAULT = INT_MAX;
static const char NUM_FRAMES_TO_DUMP_PROPERTY[] = "debug.dav1d.numframestodump";

// start dumping from this frame
static const int STARTING_FRAME_TO_DUMP_DEFAULT = 0;
static const char STARTING_FRAME_TO_DUMP_PROPERTY[] = "debug.dav1d.startingframetodump";

void C2SoftDav1dDump::initDumping() {
    nsecs_t now = systemTime();
    snprintf(mInDataFileName, kFileNameLength, "%s_%" PRId64 "d.%s", DUMP_FILE_PATH, now,
             INPUT_DATA_DUMP_EXT);
    snprintf(mInSizeFileName, kFileNameLength, "%s_%" PRId64 "d.%s", DUMP_FILE_PATH, now,
             INPUT_SIZE_DUMP_EXT);
    snprintf(mDav1dOutYuvFileName, kFileNameLength, "%s_%" PRId64 "dx.%s", DUMP_FILE_PATH, now,
             OUTPUT_YUV_DUMP_EXT);

    mFramesToDump =
            android::base::GetIntProperty(NUM_FRAMES_TO_DUMP_PROPERTY, NUM_FRAMES_TO_DUMP_DEFAULT);
    mFirstFrameToDump = android::base::GetIntProperty(STARTING_FRAME_TO_DUMP_PROPERTY,
                                                      STARTING_FRAME_TO_DUMP_DEFAULT);
    bool enableDumping = android::base::GetBoolProperty(ENABLE_DUMPING_FILES_PROPERTY,
                                                        ENABLE_DUMPING_FILES_DEFAULT);
    ALOGD("enableDumping = %d, mFramesToDump = %d", enableDumping, mFramesToDump);

    if (enableDumping) {
        mInDataFile = fopen(mInDataFileName, "wb");
        if (mInDataFile == nullptr) {
            ALOGD("Could not open file %s", mInDataFileName);
        }

        mInSizeFile = fopen(mInSizeFileName, "wb");
        if (mInSizeFile == nullptr) {
            ALOGD("Could not open file %s", mInSizeFileName);
        }

        mDav1dOutYuvFile = fopen(mDav1dOutYuvFileName, "wb");
        if (mDav1dOutYuvFile == nullptr) {
            ALOGD("Could not open file %s", mDav1dOutYuvFileName);
        }
    }
}

void C2SoftDav1dDump::destroyDumping() {
    if (mInDataFile != nullptr) {
        fclose(mInDataFile);
        mInDataFile = nullptr;
    }

    if (mInSizeFile != nullptr) {
        fclose(mInSizeFile);
        mInSizeFile = nullptr;
    }

    if (mDav1dOutYuvFile != nullptr) {
        fclose(mDav1dOutYuvFile);
        mDav1dOutYuvFile = nullptr;
    }
}

void C2SoftDav1dDump::dumpInput(uint8_t* ptr, int size) {
    if (mInDataFile) {
        int ret = fwrite(ptr, 1, size, mInDataFile);

        if (ret != size) {
            ALOGE("Error in fwrite %s, requested %d, returned %d", mInDataFileName, size, ret);
        }
    }

    // Dump the size per inputBuffer if dumping is enabled.
    if (mInSizeFile) {
        int ret = fwrite(&size, 1, 4, mInSizeFile);

        if (ret != 4) {
            ALOGE("Error in fwrite %s, requested %d, returned %d", mInSizeFileName, 4, ret);
        }
    }
}

template <typename T>
void C2SoftDav1dDump::dumpOutput(const T* srcY, const T* srcU, const T* srcV, size_t srcYStride,
                                 size_t srcUStride, size_t srcVStride, int width, int height) {
    mOutputCount++;
    FILE* fp_out = mDav1dOutYuvFile;
    int typeSize = sizeof(T);
    if (fp_out && mOutputCount >= mFirstFrameToDump &&
        mOutputCount <= (mFirstFrameToDump + mFramesToDump - 1)) {
        for (int i = 0; i < height; i++) {
            int ret =
                    fwrite((uint8_t*)srcY + i * srcYStride * typeSize, 1, width * typeSize, fp_out);
            if (ret != width * typeSize) {
                ALOGE("Error in fwrite, requested %d, returned %d", width * typeSize, ret);
                break;
            }
        }

        for (int i = 0; i < height / 2; i++) {
            int ret = fwrite((uint8_t*)srcU + i * srcUStride * typeSize, 1, width * typeSize / 2,
                             fp_out);
            if (ret != width * typeSize / 2) {
                ALOGE("Error in fwrite, requested %d, returned %d", width * typeSize / 2, ret);
                break;
            }
        }

        for (int i = 0; i < height / 2; i++) {
            int ret = fwrite((uint8_t*)srcV + i * srcVStride * typeSize, 1, width * typeSize / 2,
                             fp_out);
            if (ret != width * typeSize / 2) {
                ALOGE("Error in fwrite, requested %d, returned %d", width * typeSize / 2, ret);
                break;
            }
        }
    }
}

void C2SoftDav1dDump::writeDav1dOutYuvFile(const Dav1dPicture& p) {
    if (mDav1dOutYuvFile != NULL) {
        uint8_t* ptr;
        const int hbd = p.p.bpc > 8;

        ptr = (uint8_t*)p.data[0];
        for (int y = 0; y < p.p.h; y++) {
            int iSize = p.p.w << hbd;
            int ret = fwrite(ptr, 1, iSize, mDav1dOutYuvFile);
            if (ret != iSize) {
                ALOGE("Error in fwrite %s, requested %d, returned %d", mDav1dOutYuvFileName, iSize,
                      ret);
                break;
            }

            ptr += p.stride[0];
        }

        if (p.p.layout != DAV1D_PIXEL_LAYOUT_I400) {
            // u/v
            const int ss_ver = p.p.layout == DAV1D_PIXEL_LAYOUT_I420;
            const int ss_hor = p.p.layout != DAV1D_PIXEL_LAYOUT_I444;
            const int cw = (p.p.w + ss_hor) >> ss_hor;
            const int ch = (p.p.h + ss_ver) >> ss_ver;
            for (int pl = 1; pl <= 2; pl++) {
                ptr = (uint8_t*)p.data[pl];
                for (int y = 0; y < ch; y++) {
                    int iSize = cw << hbd;
                    int ret = fwrite(ptr, 1, cw << hbd, mDav1dOutYuvFile);
                    if (ret != iSize) {
                        ALOGE("Error in fwrite %s, requested %d, returned %d", mDav1dOutYuvFileName,
                              iSize, ret);
                        break;
                    }
                    ptr += p.stride[1];
                }
            }
        }
    }
}

template void C2SoftDav1dDump::dumpOutput<uint8_t>(const uint8_t* srcY, const uint8_t* srcU,
                                                   const uint8_t* srcV, size_t srcYStride,
                                                   size_t srcUStride, size_t srcVStride, int width,
                                                   int height);
template void C2SoftDav1dDump::dumpOutput<uint16_t>(const uint16_t* srcY, const uint16_t* srcU,
                                                    const uint16_t* srcV, size_t srcYStride,
                                                    size_t srcUStride, size_t srcVStride, int width,
                                                    int height);
}  // namespace android