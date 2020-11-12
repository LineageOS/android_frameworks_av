/*
 * Copyright (C) 2021 The Android Open Source Project
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

#ifndef ANDROID_LIBAUDIOPROCESSING_FUZZ_UTILS_H
#define ANDROID_LIBAUDIOPROCESSING_FUZZ_UTILS_H

#include <media/AudioBufferProvider.h>
#include <system/audio.h>

namespace android {

class Provider : public AudioBufferProvider {
  const void* mAddr;        // base address
  const size_t mNumFrames;  // total frames
  const size_t mFrameSize;  // size of each frame in bytes
  size_t mNextFrame;        // index of next frame to provide
  size_t mUnrel;            // number of frames not yet released
 public:
  Provider(const void* addr, size_t frames, size_t frameSize)
      : mAddr(addr),
        mNumFrames(frames),
        mFrameSize(frameSize),
        mNextFrame(0),
        mUnrel(0) {}
  status_t getNextBuffer(Buffer* buffer) override {
    if (buffer->frameCount > mNumFrames - mNextFrame) {
      buffer->frameCount = mNumFrames - mNextFrame;
    }
    mUnrel = buffer->frameCount;
    if (buffer->frameCount > 0) {
      buffer->raw = (char*)mAddr + mFrameSize * mNextFrame;
      return NO_ERROR;
    } else {
      buffer->raw = nullptr;
      return NOT_ENOUGH_DATA;
    }
  }
  void releaseBuffer(Buffer* buffer) override {
    if (buffer->frameCount > mUnrel) {
      mNextFrame += mUnrel;
      mUnrel = 0;
    } else {
      mNextFrame += buffer->frameCount;
      mUnrel -= buffer->frameCount;
    }
    buffer->frameCount = 0;
    buffer->raw = nullptr;
  }
  void reset() { mNextFrame = 0; }
};

} // namespace android

#endif // ANDROID_LIBAUDIOPROCESSING_FUZZ_UTILS_H
