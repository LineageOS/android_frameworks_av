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

#ifndef __EXTRACTOR_FUZZER_BASE_H__
#define __EXTRACTOR_FUZZER_BASE_H__

#include <media/DataSource.h>
#include <media/MediaExtractorPluginHelper.h>
#include <media/stagefright/MediaBufferGroup.h>

extern "C" {
android::ExtractorDef GETEXTRACTORDEF();
}

namespace android {

class ExtractorFuzzerBase {
 public:
  ExtractorFuzzerBase() = default;
  virtual ~ExtractorFuzzerBase() {
    if (mExtractor) {
      delete mExtractor;
      mExtractor = nullptr;
    }
    if (mBufferSource) {
      mBufferSource.clear();
      mBufferSource = nullptr;
    }
  }

  /** Function to create the media extractor component.
    * To be implemented by the derived class.
    */
  virtual bool createExtractor() = 0;

  /** Parent class functions to be reused by derived class.
    * These are common for all media extractor components.
    */
  bool setDataSource(const uint8_t* data, size_t size);

  bool getExtractorDef();

  bool extractTracks();

  bool getMetadata();

  bool getTracksMetadata();

  void setDataSourceFlags(uint32_t flags);

 protected:
  class BufferSource : public DataSource {
   public:
    BufferSource(const uint8_t* data, size_t length) : mData(data), mLength(length) {}
    virtual ~BufferSource() { mData = nullptr; }

    void setFlags(uint32_t flags) { mFlags = flags; }

    uint32_t flags() { return mFlags; }

    status_t initCheck() const { return mData != nullptr ? OK : NO_INIT; }

    ssize_t readAt(off64_t offset, void* data, size_t size) {
      if (!mData) {
        return NO_INIT;
      }

      Mutex::Autolock autoLock(mLock);
      if ((offset >= static_cast<off64_t>(mLength)) || (offset < 0)) {
        return 0;  // read beyond bounds.
      }
      size_t numAvailable = mLength - static_cast<size_t>(offset);
      if (size > numAvailable) {
        size = numAvailable;
      }
      return readAt_l(offset, data, size);
    }

    status_t getSize(off64_t* size) {
      if (!mData) {
        return NO_INIT;
      }

      Mutex::Autolock autoLock(mLock);
      *size = static_cast<off64_t>(mLength);
      return OK;
    }

   protected:
    ssize_t readAt_l(off64_t offset, void* data, size_t size) {
      void* result = memcpy(data, mData + offset, size);
      return result != nullptr ? size : 0;
    }

    const uint8_t* mData = nullptr;
    size_t mLength = 0;
    Mutex mLock;
    uint32_t mFlags = 0;

   private:
    DISALLOW_EVIL_CONSTRUCTORS(BufferSource);
  };

  sp<BufferSource> mBufferSource;
  DataSource* mDataSource = nullptr;
  MediaExtractorPluginHelper* mExtractor = nullptr;

  virtual void extractTrack(MediaTrackHelper* track, MediaBufferGroup* bufferGroup);
};

}  // namespace android

#endif  // __EXTRACTOR_FUZZER_BASE_H__
