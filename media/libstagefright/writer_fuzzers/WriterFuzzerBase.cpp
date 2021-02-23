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
#include <utils/Log.h>

#include "WriterFuzzerBase.h"

using namespace android;

/**
 * Buffer source implementations to parse input file
 */

uint32_t WriterFuzzerBase::BufferSource::getNumTracks() {
    uint32_t numTracks = 0;
    if (mSize > sizeof(uint8_t)) {
        numTracks = min(mData[0], kMaxTrackCount);
        mReadIndex += sizeof(uint8_t);
    }
    return numTracks;
}

bool WriterFuzzerBase::BufferSource::searchForMarker(size_t startIndex) {
    while (true) {
        if (isMarker()) {
            return true;
        }
        --mReadIndex;
        if (mReadIndex < startIndex) {
            break;
        }
    }
    return false;
}

ConfigFormat WriterFuzzerBase::BufferSource::getConfigFormat(int32_t trackIndex) {
    return mParams[trackIndex];
}

int32_t WriterFuzzerBase::BufferSource::getNumCsds(int32_t trackIndex) {
    return mNumCsds[trackIndex];
}

vector<FrameData> &WriterFuzzerBase::BufferSource::getFrameList(int32_t trackIndex) {
    return mFrameList[trackIndex];
}

void WriterFuzzerBase::BufferSource::getFrameInfo() {
    size_t readIndexStart = mReadIndex;
    if (mSize - mReadIndex > kMarkerSize + kMarkerSuffixSize) {
        bool isFrameAvailable = true;
        size_t bytesRemaining = mSize;
        mReadIndex = mSize - kMarkerSize;
        while (isFrameAvailable) {
            isFrameAvailable = searchForMarker(readIndexStart);
            if (isFrameAvailable) {
                size_t location = mReadIndex + kMarkerSize;
                if (location + kMarkerSuffixSize >= bytesRemaining) {
                    break;
                }
                bool isCSD = isCSDMarker(location);
                location += kMarkerSuffixSize;
                uint8_t *framePtr = const_cast<uint8_t *>(&mData[location]);
                size_t frameSize = bytesRemaining - location, bufferSize = 0;
                uint8_t trackIndex = framePtr[0] % kMaxTrackCount;
                ++framePtr;
                uint8_t flags = 0;
                int64_t pts = 0;
                if (isCSD && frameSize > 1) {
                    flags |= kCodecConfigFlag;
                    pts = 0;
                    ++mNumCsds[trackIndex];
                    bufferSize = frameSize - 1;
                } else if (frameSize > sizeof(uint8_t) + sizeof(int64_t) + 1) {
                    flags = flagTypes[framePtr[0] % size(flagTypes)];
                    ++framePtr;
                    copy(framePtr, framePtr + sizeof(int64_t), reinterpret_cast<uint8_t *>(&pts));
                    framePtr += sizeof(int64_t);
                    bufferSize = frameSize - (sizeof(uint8_t) + sizeof(int64_t)) - 1;
                } else {
                    break;
                }
                mFrameList[trackIndex].insert(mFrameList[trackIndex].begin(),
                                              FrameData{bufferSize, flags, pts, framePtr});
                bytesRemaining -= (frameSize + kMarkerSize + kMarkerSuffixSize);
                --mReadIndex;
            }
        }
    }
    if (mFrameList[0].empty() && mFrameList[1].empty()) {
        /**
         * Scenario where input data does not contain the custom frame markers.
         * Hence feed the entire data as single frame.
         */
        mFrameList[0].emplace_back(FrameData{mSize - readIndexStart, 0, 0, mData + readIndexStart});
    }
}
bool WriterFuzzerBase::BufferSource::getTrackInfo(int32_t trackIndex) {
    if (mSize <= mReadIndex + sizeof(uint8_t)) {
        return false;
    }
    size_t mimeTypeIdx = mData[mReadIndex] % kSupportedMimeTypes;
    char *mime = (char *)supportedMimeTypes[mimeTypeIdx].c_str();
    mParams[trackIndex].mime = mime;
    mReadIndex += sizeof(uint8_t);

    if (mSize > mReadIndex + 2 * sizeof(int32_t)) {
        if (!strncmp(mime, "audio/", 6)) {
            copy(mData + mReadIndex, mData + mReadIndex + sizeof(int32_t),
                 reinterpret_cast<char *>(&mParams[trackIndex].channelCount));
            copy(mData + mReadIndex + sizeof(int32_t), mData + mReadIndex + 2 * sizeof(int32_t),
                 reinterpret_cast<char *>(&mParams[trackIndex].sampleRate));
        } else if (!strncmp(mime, "video/", 6)) {
            copy(mData + mReadIndex, mData + mReadIndex + sizeof(int32_t),
                 reinterpret_cast<char *>(&mParams[trackIndex].height));
            copy(mData + mReadIndex + sizeof(int32_t), mData + mReadIndex + 2 * sizeof(int32_t),
                 reinterpret_cast<char *>(&mParams[trackIndex].width));
        }
        mReadIndex += 2 * sizeof(int32_t);
    } else {
        if (strncmp(mime, "text/", 5) && strncmp(mime, "application/", 12)) {
            return false;
        }
    }
    return true;
}

void writeHeaderBuffers(vector<FrameData> &bufferInfo, sp<AMessage> &format, int32_t numCsds) {
    char csdName[kMaxCSDStrlen];
    for (int csdId = 0; csdId < numCsds; ++csdId) {
        int32_t flags = bufferInfo[csdId].flags;
        if (flags == kCodecConfigFlag) {
            sp<ABuffer> csdBuffer =
                ABuffer::CreateAsCopy((void *)bufferInfo[csdId].buf, bufferInfo[csdId].size);
            if (csdBuffer.get() == nullptr || csdBuffer->base() == nullptr) {
                return;
            }
            snprintf(csdName, sizeof(csdName), "csd-%d", csdId);
            format->setBuffer(csdName, csdBuffer);
        }
    }
}

bool WriterFuzzerBase::createOutputFile() {
    mFd = memfd_create(mOutputFileName.c_str(), MFD_ALLOW_SEALING);
    if (mFd == -1) {
        return false;
    }
    return true;
}

void WriterFuzzerBase::addWriterSource(int32_t trackIndex) {
    ConfigFormat params = mBufferSource->getConfigFormat(trackIndex);
    sp<AMessage> format = new AMessage;
    format->setString("mime", params.mime);
    if (!strncmp(params.mime, "audio/", 6)) {
        if (!strncmp(params.mime, "audio/3gpp", 10)) {
            params.channelCount = 1;
            params.sampleRate = 8000;
        } else if (!strncmp(params.mime, "audio/amr-wb", 12)) {
            params.channelCount = 1;
            params.sampleRate = 16000;
        } else {
            params.sampleRate = max(1, params.sampleRate);
        }
        format->setInt32("channel-count", params.channelCount);
        format->setInt32("sample-rate", params.sampleRate);
    } else if (!strncmp(params.mime, "video/", 6)) {
        format->setInt32("width", params.width);
        format->setInt32("height", params.height);
    }
    int32_t numCsds = mBufferSource->getNumCsds(trackIndex);
    if (numCsds) {
        vector<FrameData> mFrames = mBufferSource->getFrameList(trackIndex);
        writeHeaderBuffers(mFrames, format, numCsds);
    }
    sp<MetaData> trackMeta = new MetaData;
    convertMessageToMetaData(format, trackMeta);
    mCurrentTrack[trackIndex] = new MediaAdapter(trackMeta);
    mWriter->addSource(mCurrentTrack[trackIndex]);
}

void WriterFuzzerBase::start() {
    mFileMeta->setInt32(kKeyRealTimeRecording, false);
    mWriter->start(mFileMeta.get());
}

void WriterFuzzerBase::sendBuffersToWriter(sp<MediaAdapter> &currentTrack, int32_t trackIndex,
                                           int32_t startFrameIndex, int32_t endFrameIndex) {
    vector<FrameData> bufferInfo = mBufferSource->getFrameList(trackIndex);
    for (int idx = startFrameIndex; idx < endFrameIndex; ++idx) {
        sp<ABuffer> buffer = new ABuffer((void *)bufferInfo[idx].buf, bufferInfo[idx].size);
        MediaBuffer *mediaBuffer = new MediaBuffer(buffer);

        // Released in MediaAdapter::signalBufferReturned().
        mediaBuffer->add_ref();
        mediaBuffer->set_range(buffer->offset(), buffer->size());
        MetaDataBase &sampleMetaData = mediaBuffer->meta_data();
        sampleMetaData.setInt64(kKeyTime, bufferInfo[idx].timeUs);

        // Just set the kKeyDecodingTime as the presentation time for now.
        sampleMetaData.setInt64(kKeyDecodingTime, bufferInfo[idx].timeUs);
        if (bufferInfo[idx].flags == SampleFlag::SYNC_FLAG) {
            sampleMetaData.setInt32(kKeyIsSyncFrame, true);
        }

        // This pushBuffer will wait until the mediaBuffer is consumed.
        currentTrack->pushBuffer(mediaBuffer);
    }
}

void WriterFuzzerBase::sendBuffersInterleave(int32_t numTracks, uint8_t numBuffersInterleave) {
    int32_t currentFrameIndex[numTracks], remainingNumFrames[numTracks], numTrackFramesDone;
    for (int32_t idx = 0; idx < numTracks; ++idx) {
        currentFrameIndex[idx] = mBufferSource->getNumCsds(idx);
        remainingNumFrames[idx] = mBufferSource->getFrameList(idx).size() - currentFrameIndex[idx];
    }
    do {
        numTrackFramesDone = numTracks;
        for (int32_t idx = 0; idx < numTracks; ++idx) {
            if (remainingNumFrames[idx] > 0) {
                int32_t numFramesInterleave =
                    min(remainingNumFrames[idx], static_cast<int32_t>(numBuffersInterleave));
                sendBuffersToWriter(mCurrentTrack[idx], idx, currentFrameIndex[idx],
                                    currentFrameIndex[idx] + numFramesInterleave);
                currentFrameIndex[idx] += numFramesInterleave;
                remainingNumFrames[idx] -= numFramesInterleave;
                --numTrackFramesDone;
            }
        }
    } while (numTrackFramesDone < numTracks);
}

void WriterFuzzerBase::initFileWriterAndProcessData(const uint8_t *data, size_t size) {
    if (!createOutputFile()) {
        return;
    }
    if (!createWriter()) {
        return;
    }

    if (size < 1) {
        return;
    }
    uint8_t numBuffersInterleave = (data[0] == 0 ? 1 : data[0]);
    ++data;
    --size;

    mBufferSource = new BufferSource(data, size);
    if (!mBufferSource) {
        return;
    }
    mNumTracks = mBufferSource->getNumTracks();
    if (mNumTracks > 0) {
        for (int32_t idx = 0; idx < mNumTracks; ++idx) {
            if (!mBufferSource->getTrackInfo(idx)) {
                if (idx == 0) {
                    delete mBufferSource;
                    return;
                }
                mNumTracks = idx;
                break;
            }
        }
        mBufferSource->getFrameInfo();
        for (int32_t idx = 0; idx < mNumTracks; ++idx) {
            addWriterSource(idx);
        }
        start();
        sendBuffersInterleave(mNumTracks, numBuffersInterleave);
        for (int32_t idx = 0; idx < mNumTracks; ++idx) {
            if (mCurrentTrack[idx]) {
                mCurrentTrack[idx]->stop();
            }
        }
    }
    delete mBufferSource;
    mWriter->stop();
}
