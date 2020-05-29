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
#define LOG_TAG "ExtractorFuzzerBase"
#include <utils/Log.h>

#include "ExtractorFuzzerBase.h"

using namespace android;

bool ExtractorFuzzerBase::setDataSource(const uint8_t* data, size_t size) {
  if ((!data) || (size == 0)) {
    return false;
  }
  mBufferSource = new BufferSource(data, size);
  mDataSource = reinterpret_cast<DataSource*>(mBufferSource.get());
  if (!mDataSource) {
    return false;
  }
  return true;
}

void ExtractorFuzzerBase::getExtractorDef() {
  float confidence;
  void* meta = nullptr;
  FreeMetaFunc freeMeta = nullptr;

  ExtractorDef extractorDef = GETEXTRACTORDEF();
  if (extractorDef.def_version == EXTRACTORDEF_VERSION_NDK_V1) {
    extractorDef.u.v2.sniff(mDataSource->wrap(), &confidence, &meta, &freeMeta);
  } else if (extractorDef.def_version == EXTRACTORDEF_VERSION_NDK_V2) {
    extractorDef.u.v3.sniff(mDataSource->wrap(), &confidence, &meta, &freeMeta);
  }

  if (meta != nullptr && freeMeta != nullptr) {
    freeMeta(meta);
  }
}

void ExtractorFuzzerBase::extractTracks() {
  MediaBufferGroup* bufferGroup = new MediaBufferGroup();
  if (!bufferGroup) {
    return;
  }
  size_t trackCount = mExtractor->countTracks();
  for (size_t trackIndex = 0; trackIndex < trackCount; ++trackIndex) {
    MediaTrackHelper* track = mExtractor->getTrack(trackIndex);
    if (!track) {
      continue;
    }
    extractTrack(track, bufferGroup);
    delete track;
  }
  delete bufferGroup;
}

void ExtractorFuzzerBase::extractTrack(MediaTrackHelper* track, MediaBufferGroup* bufferGroup) {
  CMediaTrack* cTrack = wrap(track);
  if (!cTrack) {
    return;
  }

  media_status_t status = cTrack->start(track, bufferGroup->wrap());
  if (status != AMEDIA_OK) {
    free(cTrack);
    return;
  }

  do {
    MediaBufferHelper* buffer = nullptr;
    status = track->read(&buffer);
    if (buffer) {
      buffer->release();
    }
  } while (status == AMEDIA_OK);

  cTrack->stop(track);
  free(cTrack);
}

void ExtractorFuzzerBase::getTracksMetadata() {
  AMediaFormat* format = AMediaFormat_new();
  uint32_t flags = MediaExtractorPluginHelper::kIncludeExtensiveMetaData;

  size_t trackCount = mExtractor->countTracks();
  for (size_t trackIndex = 0; trackIndex < trackCount; ++trackIndex) {
    mExtractor->getTrackMetaData(format, trackIndex, flags);
  }

  AMediaFormat_delete(format);
}

void ExtractorFuzzerBase::getMetadata() {
  AMediaFormat* format = AMediaFormat_new();
  mExtractor->getMetaData(format);
  AMediaFormat_delete(format);
}

void ExtractorFuzzerBase::setDataSourceFlags(uint32_t flags) {
  mBufferSource->setFlags(flags);
}

void ExtractorFuzzerBase::seekAndExtractTracks() {
  MediaBufferGroup* bufferGroup = new MediaBufferGroup();
  if (!bufferGroup) {
    return;
  }
  size_t trackCount = mExtractor->countTracks();
  for (size_t trackIndex = 0; trackIndex < trackCount; ++trackIndex) {
    MediaTrackHelper* track = mExtractor->getTrack(trackIndex);
    if (!track) {
      continue;
    }

    AMediaFormat* trackMetaData = AMediaFormat_new();
    int64_t trackDuration = 0;
    uint32_t flags = MediaExtractorPluginHelper::kIncludeExtensiveMetaData;
    mExtractor->getTrackMetaData(trackMetaData, trackIndex, flags);
    AMediaFormat_getInt64(trackMetaData, AMEDIAFORMAT_KEY_DURATION, &trackDuration);

    seekAndExtractTrack(track, bufferGroup, trackDuration);
    AMediaFormat_delete(trackMetaData);
    delete track;
  }
  delete bufferGroup;
}

void ExtractorFuzzerBase::seekAndExtractTrack(MediaTrackHelper* track,
                                              MediaBufferGroup* bufferGroup,
                                              int64_t trackDuration) {
  CMediaTrack* cTrack = wrap(track);
  if (!cTrack) {
    return;
  }

  media_status_t status = cTrack->start(track, bufferGroup->wrap());
  if (status != AMEDIA_OK) {
    free(cTrack);
    return;
  }

  int32_t seekCount = 0;
  std::vector<int64_t> seekToTimeStamp;
  while (seekCount <= kFuzzerMaxSeekPointsCount) {
    /* This ensures kFuzzerMaxSeekPointsCount seek points are within the clipDuration and 1 seek
     * point is outside of the clipDuration.
     */
    int64_t timeStamp = (seekCount * trackDuration) / (kFuzzerMaxSeekPointsCount - 1);
    seekToTimeStamp.push_back(timeStamp);
    seekCount++;
  }

  std::vector<uint32_t> seekOptions;
  seekOptions.push_back(CMediaTrackReadOptions::SEEK | CMediaTrackReadOptions::SEEK_CLOSEST);
  seekOptions.push_back(CMediaTrackReadOptions::SEEK | CMediaTrackReadOptions::SEEK_CLOSEST_SYNC);
  seekOptions.push_back(CMediaTrackReadOptions::SEEK | CMediaTrackReadOptions::SEEK_PREVIOUS_SYNC);
  seekOptions.push_back(CMediaTrackReadOptions::SEEK | CMediaTrackReadOptions::SEEK_NEXT_SYNC);
  seekOptions.push_back(CMediaTrackReadOptions::SEEK | CMediaTrackReadOptions::SEEK_FRAME_INDEX);

  for (uint32_t seekOption : seekOptions) {
    for (int64_t seekPts : seekToTimeStamp) {
      MediaTrackHelper::ReadOptions* options =
          new MediaTrackHelper::ReadOptions(seekOption, seekPts);
      MediaBufferHelper* buffer = nullptr;
      track->read(&buffer, options);
      if (buffer) {
        buffer->release();
      }
      delete options;
    }
  }

  cTrack->stop(track);
  free(cTrack);
}

void ExtractorFuzzerBase::processData(const uint8_t* data, size_t size) {
  if (setDataSource(data, size)) {
    if (createExtractor()) {
      getExtractorDef();
      getMetadata();
      extractTracks();
      getTracksMetadata();
      seekAndExtractTracks();
    }
  }
}
