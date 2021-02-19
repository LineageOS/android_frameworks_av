/******************************************************************************
 *
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */

#ifndef __WRITER_FUZZER_BASE_H__
#define __WRITER_FUZZER_BASE_H__

#include <media/stagefright/MediaAdapter.h>
#include <media/stagefright/MediaWriter.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/Utils.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AMessage.h>
#include <algorithm>
#include <cstring>
#include <vector>

using namespace std;

constexpr uint32_t kMimeSize = 128;
constexpr uint8_t kMaxTrackCount = 3;
constexpr uint32_t kMaxCSDStrlen = 16;
constexpr uint32_t kCodecConfigFlag = 32;

namespace android {

struct ConfigFormat {
    char* mime;
    int32_t width;
    int32_t height;
    int32_t sampleRate;
    int32_t channelCount;
};

struct FrameData {
    size_t size;
    uint8_t flags;
    int64_t timeUs;
    const uint8_t* buf;
};

static string supportedMimeTypes[] = {"audio/3gpp",
                                      "audio/amr-wb",
                                      "audio/vorbis",
                                      "audio/opus",
                                      "audio/mp4a-latm",
                                      "audio/mpeg",
                                      "audio/mpeg-L1",
                                      "audio/mpeg-L2",
                                      "audio/midi",
                                      "audio/qcelp",
                                      "audio/g711-alaw",
                                      "audio/g711-mlaw",
                                      "audio/flac",
                                      "audio/aac-adts",
                                      "audio/gsm",
                                      "audio/ac3",
                                      "audio/eac3",
                                      "audio/eac3-joc",
                                      "audio/ac4",
                                      "audio/scrambled",
                                      "audio/alac",
                                      "audio/x-ms-wma",
                                      "audio/x-adpcm-ms",
                                      "audio/x-adpcm-dvi-ima",
                                      "video/avc",
                                      "video/hevc",
                                      "video/mp4v-es",
                                      "video/3gpp",
                                      "video/x-vnd.on2.vp8",
                                      "video/x-vnd.on2.vp9",
                                      "video/av01",
                                      "video/mpeg2",
                                      "video/dolby-vision",
                                      "video/scrambled",
                                      "video/divx",
                                      "video/divx3",
                                      "video/xvid",
                                      "video/x-motion-jpeg",
                                      "text/3gpp-tt",
                                      "application/x-subrip",
                                      "text/vtt",
                                      "text/cea-608",
                                      "text/cea-708",
                                      "application/x-id3v4"};

enum SampleFlag {
    DEFAULT_FLAG = 0,
    SYNC_FLAG = 1,
    ENCRYPTED_FLAG = 2,
};

static uint8_t flagTypes[] = {SampleFlag::DEFAULT_FLAG, SampleFlag::SYNC_FLAG,
                              SampleFlag::ENCRYPTED_FLAG};

class WriterFuzzerBase {
   public:
    WriterFuzzerBase() = default;
    virtual ~WriterFuzzerBase() {
        if (mFileMeta) {
            mFileMeta.clear();
            mFileMeta = nullptr;
        }
        if (mWriter) {
            mWriter.clear();
            mWriter = nullptr;
        }
        for (int32_t idx = 0; idx < kMaxTrackCount; ++idx) {
            if (mCurrentTrack[idx]) {
                mCurrentTrack[idx]->stop();
                mCurrentTrack[idx].clear();
                mCurrentTrack[idx] = nullptr;
            }
        }
        close(mFd);
    };

    /** Function to create the media writer component.
     * To be implemented by the derived class.
     */
    virtual bool createWriter() = 0;

    /** Parent class functions to be reused by derived class.
     * These are common for all media writer components.
     */
    bool createOutputFile();

    void addWriterSource(int32_t trackIndex);

    void start();

    void sendBuffersToWriter(sp<MediaAdapter>& currentTrack, int32_t trackIndex,
                             int32_t startFrameIndex, int32_t endFrameIndex);

    void sendBuffersInterleave(int32_t numTracks, uint8_t numBuffersInterleave);

    void initFileWriterAndProcessData(const uint8_t* data, size_t size);

   protected:
    class BufferSource {
       public:
        BufferSource(const uint8_t* data, size_t size) : mData(data), mSize(size), mReadIndex(0) {}
        ~BufferSource() {
            mData = nullptr;
            mSize = 0;
            mReadIndex = 0;
            for (int32_t idx = 0; idx < kMaxTrackCount; ++idx) {
                mFrameList[idx].clear();
            }
        }
        uint32_t getNumTracks();
        bool getTrackInfo(int32_t trackIndex);
        void getFrameInfo();
        ConfigFormat getConfigFormat(int32_t trackIndex);
        int32_t getNumCsds(int32_t trackIndex);
        vector<FrameData>& getFrameList(int32_t trackIndex);

       private:
        bool isMarker() { return (memcmp(&mData[mReadIndex], kMarker, kMarkerSize) == 0); }

        bool isCSDMarker(size_t position) {
            return (memcmp(&mData[position], kCsdMarkerSuffix, kMarkerSuffixSize) == 0);
        }

        bool searchForMarker(size_t startIndex);

        const uint8_t* mData = nullptr;
        size_t mSize = 0;
        size_t mReadIndex = 0;
        ConfigFormat mParams[kMaxTrackCount] = {};
        int32_t mNumCsds[kMaxTrackCount] = {0};
        vector<FrameData> mFrameList[kMaxTrackCount];

        static constexpr int kSupportedMimeTypes = size(supportedMimeTypes);
        static constexpr uint8_t kMarker[] = "_MARK";
        static constexpr uint8_t kCsdMarkerSuffix[] = "_H_";
        static constexpr uint8_t kFrameMarkerSuffix[] = "_F_";
        // All markers should be 5 bytes long ( sizeof '_MARK' which is 5)
        static constexpr size_t kMarkerSize = (sizeof(kMarker) - 1);
        // All marker types should be 3 bytes long ('_H_', '_F_')
        static constexpr size_t kMarkerSuffixSize = 3;
    };

    BufferSource* mBufferSource = nullptr;
    int32_t mFd = -1;
    uint32_t mNumTracks = 0;
    string mOutputFileName = "writer.out";
    sp<MediaWriter> mWriter = nullptr;
    sp<MetaData> mFileMeta = nullptr;
    sp<MediaAdapter> mCurrentTrack[kMaxTrackCount] = {};
};

}  // namespace android

#endif  // __WRITER_FUZZER_BASE_H__
