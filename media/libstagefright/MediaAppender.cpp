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

//#define LOG_NDEBUG 0
#define LOG_TAG "MediaAppender"

#include <media/stagefright/MediaAppender.h>
#include <media/stagefright/MediaCodec.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <utils/Log.h>
// TODO : check if this works for NDK apps without JVM
// #include <media/ndk/NdkJavaVMHelperPriv.h>

namespace android {

struct MediaAppender::sampleDataInfo {
    size_t size;
    int64_t time;
    size_t exTrackIndex;
    sp<MetaData> meta;
};

sp<MediaAppender> MediaAppender::create(int fd, AppendMode mode) {
    if (fd < 0) {
        ALOGE("invalid file descriptor");
        return nullptr;
    }
    if (!(mode >= APPEND_MODE_FIRST && mode <= APPEND_MODE_LAST)) {
        ALOGE("invalid mode %d", mode);
        return nullptr;
    }
    sp<MediaAppender> ma = new (std::nothrow) MediaAppender(fd, mode);
    if (ma->init() != OK) {
        return nullptr;
    }
    return ma;
}

// TODO: inject mediamuxer and mediaextractor objects.
// TODO: @format is not required as an input if we can sniff the file and find the format of
//       the existing content.
// TODO: Code it to the interface(MediaAppender), and have a separate MediaAppender NDK
MediaAppender::MediaAppender(int fd, AppendMode mode)
    : mFd(fd),
      mMode(mode),
      // TODO : check if this works for NDK apps without JVM
      // mExtractor(new NuMediaExtractor(NdkJavaVMHelper::getJNIEnv() != nullptr
      //           ? NuMediaExtractor::EntryPoint::NDK_WITH_JVM
      //           : NuMediaExtractor::EntryPoint::NDK_NO_JVM)),
      mExtractor(new (std::nothrow) NuMediaExtractor(NuMediaExtractor::EntryPoint::NDK_WITH_JVM)),
      mTrackCount(0),
      mState(UNINITIALIZED) {
          ALOGV("MediaAppender::MediaAppender mode:%d", mode);
      }

status_t MediaAppender::init() {
    std::scoped_lock lock(mMutex);
    ALOGV("MediaAppender::init");
    status_t status = mExtractor->setDataSource(mFd, 0, lseek(mFd, 0, SEEK_END));
    if (status != OK) {
        ALOGE("extractor_setDataSource failed, status :%d", status);
        return status;
    }

    sp<AMessage> fileFormat;
    status = mExtractor->getFileFormat(&fileFormat);
    if (status != OK) {
        ALOGE("extractor_getFileFormat failed, status :%d", status);
        return status;
    }

    AString fileMime;
    fileFormat->findString("mime", &fileMime);
    // only compare the end of the file MIME type to allow for vendor customized mime type
    if (fileMime.endsWith("mp4")){
        mFormat = MediaMuxer::OUTPUT_FORMAT_MPEG_4;
    } else {
        ALOGE("Unsupported file format, extractor name:%s, fileformat %s",
              mExtractor->getName(), fileMime.c_str());
        return ERROR_UNSUPPORTED;
    }

    mTrackCount = mExtractor->countTracks();
    ALOGV("mTrackCount:%zu", mTrackCount);
    if (mTrackCount == 0) {
        ALOGE("no tracks are present");
        return ERROR_MALFORMED;
    }
    size_t exTrackIndex = 0;
    ssize_t audioTrackIndex = -1, videoTrackIndex = -1;
    bool audioSyncSampleTimeSet = false;

    while (exTrackIndex < mTrackCount) {
        sp<AMessage> fmt;
        status = mExtractor->getTrackFormat(exTrackIndex, &fmt, 0);
        if (status != OK) {
            ALOGE("getTrackFormat failed for trackIndex:%zu, status:%d", exTrackIndex, status);
            return status;
        }
        AString mime;
        if (fmt->findString("mime", &mime)) {
            if (!strncasecmp(mime.c_str(), "video/", 6)) {
                ALOGV("VideoTrack");
                if (videoTrackIndex != -1) {
                    ALOGE("Not more than one video track is supported");
                    return ERROR_UNSUPPORTED;
                }
                videoTrackIndex = exTrackIndex;
            } else if (!strncasecmp(mime.c_str(), "audio/", 6)) {
                ALOGV("AudioTrack");
                if (audioTrackIndex != -1) {
                    ALOGE("Not more than one audio track is supported");
                }
                audioTrackIndex = exTrackIndex;
            } else {
                ALOGV("Neither Video nor Audio track");
            }
        }
        mFmtIndexMap.emplace(exTrackIndex, fmt);
        mSampleCountVect.emplace_back(0);
        mMaxTimestampVect.emplace_back(0);
        mLastSyncSampleTimeVect.emplace_back(0);
        status = mExtractor->selectTrack(exTrackIndex);
        if (status != OK) {
            ALOGE("selectTrack failed for trackIndex:%zu, status:%d", exTrackIndex, status);
            return status;
        }
        ++exTrackIndex;
    }

    ALOGV("AudioTrackIndex:%zu, VideoTrackIndex:%zu", audioTrackIndex, videoTrackIndex);

    do {
        sampleDataInfo tmpSDI;
        // TODO: read info into members of the struct sampleDataInfo directly
        size_t sampleSize;
        status = mExtractor->getSampleSize(&sampleSize);
        if (status != OK) {
            ALOGE("getSampleSize failed, status:%d", status);
            return status;
        }
        mSampleSizeVect.emplace_back(sampleSize);
        tmpSDI.size = sampleSize;
        int64_t sampleTime = 0;
        status = mExtractor->getSampleTime(&sampleTime);
        if (status != OK) {
            ALOGE("getSampleTime failed, status:%d", status);
            return status;
        }
        mSampleTimeVect.emplace_back(sampleTime);
        tmpSDI.time = sampleTime;
        status = mExtractor->getSampleTrackIndex(&exTrackIndex);
        if (status != OK) {
            ALOGE("getSampleTrackIndex failed, status:%d", status);
            return status;
        }
        mSampleIndexVect.emplace_back(exTrackIndex);
        tmpSDI.exTrackIndex = exTrackIndex;
        ++mSampleCountVect[exTrackIndex];
        mMaxTimestampVect[exTrackIndex] = std::max(mMaxTimestampVect[exTrackIndex], sampleTime);
        sp<MetaData> sampleMeta;
        status = mExtractor->getSampleMeta(&sampleMeta);
        if (status != OK) {
            ALOGE("getSampleMeta failed, status:%d", status);
            return status;
        }
        mSampleMetaVect.emplace_back(sampleMeta);
        int32_t val = 0;
        if (sampleMeta->findInt32(kKeyIsSyncFrame, &val) && val != 0) {
            mLastSyncSampleTimeVect[exTrackIndex] = sampleTime;
        }
        tmpSDI.meta = sampleMeta;
        mSDI.emplace_back(tmpSDI);
    } while (mExtractor->advance() == OK);

    mExtractor.clear();

    std::sort(mSDI.begin(), mSDI.end(), [](sampleDataInfo& a, sampleDataInfo& b) {
        int64_t aOffset, bOffset;
        a.meta->findInt64(kKeySampleFileOffset, &aOffset);
        b.meta->findInt64(kKeySampleFileOffset, &bOffset);
        return aOffset < bOffset;
    });
    for (int64_t syncSampleTime : mLastSyncSampleTimeVect) {
        ALOGV("before ignoring frames, mLastSyncSampleTimeVect:%lld", (long long)syncSampleTime);
    }
    ALOGV("mMode:%u", mMode);
    if (mMode == APPEND_MODE_IGNORE_LAST_VIDEO_GOP && videoTrackIndex != -1 ) {
        ALOGV("Video track is present");
        bool lastVideoIframe = false;
        size_t lastVideoIframeOffset = 0;
        int64_t lastVideoSampleTime = -1;
        for (auto rItr = mSDI.rbegin(); rItr != mSDI.rend(); ++rItr) {
            if (rItr->exTrackIndex != videoTrackIndex) {
                continue;
            }
            if (lastVideoSampleTime == -1) {
                lastVideoSampleTime = rItr->time;
            }
            int64_t offset = 0;
            if (!rItr->meta->findInt64(kKeySampleFileOffset, &offset) || offset == 0) {
                ALOGE("Missing offset");
                return ERROR_MALFORMED;
            }
            ALOGV("offset:%lld", (long long)offset);
            int32_t val = 0;
            if (rItr->meta->findInt32(kKeyIsSyncFrame, &val) && val != 0) {
                ALOGV("sampleTime:%lld", (long long)rItr->time);
                ALOGV("lastVideoSampleTime:%lld", (long long)lastVideoSampleTime);
                if (lastVideoIframe == false && (lastVideoSampleTime - rItr->time) >
                                1000000/* Track interleaving duration in MPEG4Writer*/) {
                    ALOGV("lastVideoIframe got chosen");
                    lastVideoIframe = true;
                    mLastSyncSampleTimeVect[videoTrackIndex] = rItr->time;
                    lastVideoIframeOffset = offset;
                    ALOGV("lastVideoIframeOffset:%lld", (long long)offset);
                    break;
                }
            }
        }
        if (lastVideoIframe == false) {
            ALOGV("Need to rewrite all samples");
            mLastSyncSampleTimeVect[videoTrackIndex] = 0;
            lastVideoIframeOffset = 0;
        }
        unsigned int framesIgnoredCount = 0;
        for (auto itr = mSDI.begin(); itr != mSDI.end();) {
            int64_t offset = 0;
            ALOGV("trackIndex:%zu, %" PRId64 "", itr->exTrackIndex, itr->time);
            if (itr->meta->findInt64(kKeySampleFileOffset, &offset) &&
                                        offset >= lastVideoIframeOffset) {
                ALOGV("offset:%lld", (long long)offset);
                if (!audioSyncSampleTimeSet && audioTrackIndex != -1 &&
                                            audioTrackIndex == itr->exTrackIndex) {
                    mLastSyncSampleTimeVect[audioTrackIndex] = itr->time;
                    audioSyncSampleTimeSet = true;
                }
                itr = mSDI.erase(itr);
                ++framesIgnoredCount;
            } else {
                ++itr;
            }
        }
        ALOGV("framesIgnoredCount:%u", framesIgnoredCount);
    }

    if (mMode == APPEND_MODE_IGNORE_LAST_VIDEO_GOP && videoTrackIndex == -1 &&
                            audioTrackIndex != -1) {
        ALOGV("Only AudioTrack is present");
        for (auto rItr = mSDI.rbegin(); rItr != mSDI.rend();  ++rItr) {
            int32_t val = 0;
            if (rItr->meta->findInt32(kKeyIsSyncFrame, &val) && val != 0) {
                    mLastSyncSampleTimeVect[audioTrackIndex] = rItr->time;
                    break;
            }
        }
        unsigned int framesIgnoredCount = 0;
        for (auto itr = mSDI.begin(); itr != mSDI.end();) {
            if (itr->time >= mLastSyncSampleTimeVect[audioTrackIndex]) {
                itr = mSDI.erase(itr);
                ++framesIgnoredCount;
            } else {
                ++itr;
            }
        }
        ALOGV("framesIgnoredCount :%u", framesIgnoredCount);
    }

    for (size_t i = 0; i < mLastSyncSampleTimeVect.size(); ++i) {
        ALOGV("mLastSyncSampleTimeVect[%zu]:%lld", i, (long long)mLastSyncSampleTimeVect[i]);
        mFmtIndexMap[i]->setInt64(
                "sample-time-before-append" /*AMEDIAFORMAT_KEY_SAMPLE_TIME_BEFORE_APPEND*/,
                mLastSyncSampleTimeVect[i]);
    }
    for (size_t i = 0; i < mMaxTimestampVect.size(); ++i) {
        ALOGV("mMaxTimestamp[%zu]:%lld", i, (long long)mMaxTimestampVect[i]);
    }
    for (size_t i = 0; i < mSampleCountVect.size(); ++i) {
        ALOGV("SampleCountVect[%zu]:%zu", i, mSampleCountVect[i]);
    }
    mState = INITIALIZED;
    return OK;
}

MediaAppender::~MediaAppender() {
    ALOGV("MediaAppender::~MediaAppender");
    mMuxer.clear();
    mExtractor.clear();
}

status_t MediaAppender::start() {
    std::scoped_lock lock(mMutex);
    ALOGV("MediaAppender::start");
    if (mState != INITIALIZED) {
        ALOGE("MediaAppender::start() is called in invalid state %d", mState);
        return INVALID_OPERATION;
    }
    mMuxer = new (std::nothrow) MediaMuxer(mFd, mFormat);
    for (const auto& n : mFmtIndexMap) {
        ssize_t muxIndex = mMuxer->addTrack(n.second);
        if (muxIndex < 0) {
            ALOGE("addTrack failed");
            return UNKNOWN_ERROR;
        }
        mTrackIndexMap.emplace(n.first, muxIndex);
    }
    ALOGV("trackIndexmap size:%zu", mTrackIndexMap.size());

    status_t status = mMuxer->start();
    if (status != OK) {
        ALOGE("muxer start failed:%d", status);
        return status;
    }

    ALOGV("Sorting samples based on their offsets");
    for (int i = 0; i < mSDI.size(); ++i) {
        ALOGV("i:%d", i + 1);
        /* TODO : Allocate a single allocation of the max size, and reuse it across ABuffers if
         * using new ABuffer(void *, size_t).
         */
        sp<ABuffer> data = new (std::nothrow) ABuffer(mSDI[i].size);
        if (data == nullptr) {
            ALOGE("memory allocation failed");
            return NO_MEMORY;
        }
        data->setRange(0, mSDI[i].size);
        int32_t val = 0;
        int sampleFlags = 0;
        if (mSDI[i].meta->findInt32(kKeyIsSyncFrame, &val) && val != 0) {
            sampleFlags |= MediaCodec::BUFFER_FLAG_SYNCFRAME;
        }

        int64_t val64;
        if (mSDI[i].meta->findInt64(kKeySampleFileOffset, &val64)) {
            ALOGV("SampleFileOffset Found :%zu:%lld:%lld", mSDI[i].exTrackIndex,
                  (long long)mSampleCountVect[mSDI[i].exTrackIndex], (long long)val64);
            sp<AMessage> bufMeta = data->meta();
            bufMeta->setInt64("sample-file-offset" /*AMEDIAFORMAT_KEY_SAMPLE_TIME_BEFORE_APPEND*/,
                              val64);
        }
        if (mSDI[i].meta->findInt64(kKeyLastSampleIndexInChunk, &val64)) {
            ALOGV("kKeyLastSampleIndexInChunk Found %lld:%lld",
                  (long long)mSampleCountVect[mSDI[i].exTrackIndex], (long long)val64);
            sp<AMessage> bufMeta = data->meta();
            bufMeta->setInt64(
                    "last-sample-index-in-chunk" /*AMEDIAFORMAT_KEY_LAST_SAMPLE_INDEX_IN_CHUNK*/,
                    val64);
        }
        status = mMuxer->writeSampleData(data, mTrackIndexMap[mSDI[i].exTrackIndex], mSDI[i].time,
                                         sampleFlags);
        if (status != OK) {
            ALOGE("muxer writeSampleData failed:%d", status);
            return status;
        }
    }
    mState = STARTED;
    return OK;
}

status_t MediaAppender::stop() {
    std::scoped_lock lock(mMutex);
    ALOGV("MediaAppender::stop");
    if (mState == STARTED) {
        status_t status = mMuxer->stop();
        if (status != OK) {
            mState = ERROR;
        } else {
            mState = STOPPED;
        }
        return status;
    } else {
        ALOGE("stop() is called in invalid state %d", mState);
        return INVALID_OPERATION;
    }
}

ssize_t MediaAppender::getTrackCount() {
    std::scoped_lock lock(mMutex);
    ALOGV("MediaAppender::getTrackCount");
    if (mState != INITIALIZED && mState != STARTED) {
        ALOGE("getTrackCount() is called in invalid state %d", mState);
        return -1;
    }
    return mTrackCount;
}

sp<AMessage> MediaAppender::getTrackFormat(size_t idx) {
    std::scoped_lock lock(mMutex);
    ALOGV("MediaAppender::getTrackFormat");
    if (mState != INITIALIZED && mState != STARTED) {
        ALOGE("getTrackFormat() is called in invalid state %d", mState);
        return nullptr;
    }
    if (idx < 0 || idx >= mTrackCount) {
        ALOGE("getTrackFormat() idx is out of range");
        return nullptr;
    }
    return mFmtIndexMap[idx];
}

status_t MediaAppender::writeSampleData(const sp<ABuffer>& buffer, size_t trackIndex,
                                        int64_t timeUs, uint32_t flags) {
    std::scoped_lock lock(mMutex);
    ALOGV("writeSampleData:trackIndex:%zu, time:%" PRId64 "", trackIndex, timeUs);
    return mMuxer->writeSampleData(buffer, trackIndex, timeUs, flags);
}

status_t MediaAppender::setOrientationHint([[maybe_unused]] int degrees) {
    ALOGE("setOrientationHint not supported. Has to be called prior to start on initial muxer");
    return ERROR_UNSUPPORTED;
};

status_t MediaAppender::setLocation([[maybe_unused]] int latit, [[maybe_unused]] int longit) {
    ALOGE("setLocation not supported. Has to be called prior to start on initial muxer");
    return ERROR_UNSUPPORTED;
}

ssize_t MediaAppender::addTrack([[maybe_unused]] const sp<AMessage> &format) {
    ALOGE("addTrack not supported");
    return ERROR_UNSUPPORTED;
}

}  // namespace android
