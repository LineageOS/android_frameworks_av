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
#ifndef __C2FUZZER_H__
#define __C2FUZZER_H__

#include <C2AllocatorIon.h>
#include <C2Buffer.h>
#include <C2BufferPriv.h>
#include <C2Component.h>
#include <C2Config.h>
#include <C2PlatformSupport.h>

using namespace std::chrono_literals;

extern "C" ::C2ComponentFactory* CreateCodec2Factory();
extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory);

namespace android {

#define C2FUZZER_ALIGN(_sz, _align) (((_sz) + ((_align)-1)) & ~((_align)-1))

constexpr std::chrono::milliseconds kC2FuzzerTimeOut = 5000ms;
constexpr int32_t kNumberOfC2WorkItems = 8;
constexpr uint32_t kWidthOfVideo = 3840;
constexpr uint32_t kHeightOfVideo = 2160;
constexpr uint32_t kSamplingRateOfAudio = 48000;
constexpr uint32_t kChannelsOfAudio = 8;

typedef std::tuple<uint8_t*, size_t, uint32_t> FrameData;

class Codec2Fuzzer {
 public:
  Codec2Fuzzer() = default;
  ~Codec2Fuzzer() { deInitDecoder(); }
  bool initDecoder();
  void deInitDecoder();
  void decodeFrames(const uint8_t* data, size_t size);

  void handleWorkDone(std::weak_ptr<C2Component> comp,
                      std::list<std::unique_ptr<C2Work>>& workItems);

 private:
  class BufferSource {
   public:
    BufferSource(const uint8_t* data, size_t size) : mData(data), mSize(size) {
      mReadIndex = (size <= kMarkerSize) ? 0 : (size - kMarkerSize);
    }
    ~BufferSource() {
      mData = nullptr;
      mSize = 0;
      mReadIndex = 0;
      mFrameList.clear();
    }
    bool isEos() { return mFrameList.empty(); }
    void parse();
    FrameData getFrame();

   private:
    bool isMarker() {
      if ((kMarkerSize < mSize) && (mReadIndex < mSize - kMarkerSize)) {
        return (memcmp(&mData[mReadIndex], kMarker, kMarkerSize) == 0);
      } else {
        return false;
      }
    }

    bool isCSDMarker(size_t position) {
      if ((kMarkerSuffixSize < mSize) && (position < mSize - kMarkerSuffixSize)) {
        return (memcmp(&mData[position], kCsdMarkerSuffix, kMarkerSuffixSize) == 0);
      } else {
        return false;
      }
    }

    bool searchForMarker();

    const uint8_t* mData = nullptr;
    size_t mSize = 0;
    size_t mReadIndex = 0;
    std::vector<FrameData> mFrameList;
    static constexpr uint8_t kMarker[] = "_MARK";
    static constexpr uint8_t kCsdMarkerSuffix[] = "_H_";
    static constexpr uint8_t kFrameMarkerSuffix[] = "_F_";
    // All markers should be 5 bytes long ( sizeof '_MARK' which is 5)
    static constexpr size_t kMarkerSize = (sizeof(kMarker) - 1);
    // All marker types should be 3 bytes long ('_H_', '_F_')
    static constexpr size_t kMarkerSuffixSize = 3;
  };

  BufferSource* mBufferSource;
  bool mEos = false;
  C2BlockPool::local_id_t mBlockPoolId;

  std::shared_ptr<C2BlockPool> mLinearPool;
  std::shared_ptr<C2Allocator> mLinearAllocator;
  std::shared_ptr<C2Component::Listener> mListener;
  std::shared_ptr<C2Component> mComponent;
  std::shared_ptr<C2ComponentInterface> mInterface;
  std::mutex mQueueLock;
  std::condition_variable mQueueCondition;
  std::list<std::unique_ptr<C2Work>> mWorkQueue;
  std::mutex mDecodeCompleteMutex;
  std::condition_variable mConditionalVariable;
};

}  // namespace android

#endif  // __C2FUZZER_H__
