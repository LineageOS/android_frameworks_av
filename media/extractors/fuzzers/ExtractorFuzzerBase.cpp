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

bool ExtractorFuzzerBase::getExtractorDef() {
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

  return true;
}

bool ExtractorFuzzerBase::extractTracks() {
  MediaBufferGroup* bufferGroup = new MediaBufferGroup();
  if (!bufferGroup) {
    return false;
  }
  for (size_t trackIndex = 0; trackIndex < mExtractor->countTracks(); ++trackIndex) {
    MediaTrackHelper* track = mExtractor->getTrack(trackIndex);
    if (!track) {
      continue;
    }
    extractTrack(track, bufferGroup);
    delete track;
  }
  delete bufferGroup;
  return true;
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

bool ExtractorFuzzerBase::getTracksMetadata() {
  AMediaFormat* format = AMediaFormat_new();
  uint32_t flags = MediaExtractorPluginHelper::kIncludeExtensiveMetaData;

  for (size_t trackIndex = 0; trackIndex < mExtractor->countTracks(); ++trackIndex) {
    mExtractor->getTrackMetaData(format, trackIndex, flags);
  }

  AMediaFormat_delete(format);
  return true;
}

bool ExtractorFuzzerBase::getMetadata() {
  AMediaFormat* format = AMediaFormat_new();
  mExtractor->getMetaData(format);
  AMediaFormat_delete(format);
  return true;
}

void ExtractorFuzzerBase::setDataSourceFlags(uint32_t flags) {
  mBufferSource->setFlags(flags);
}
