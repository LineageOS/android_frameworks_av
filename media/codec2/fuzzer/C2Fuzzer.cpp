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
#include <stdio.h>

#include <C2Fuzzer.h>

using namespace android;

class LinearBuffer : public C2Buffer {
 public:
  explicit LinearBuffer(const std::shared_ptr<C2LinearBlock>& block)
      : C2Buffer({block->share(block->offset(), block->size(), ::C2Fence())}) {}

  explicit LinearBuffer(const std::shared_ptr<C2LinearBlock>& block, size_t size)
      : C2Buffer({block->share(block->offset(), size, ::C2Fence())}) {}
};

/**
 * Handle Callback functions onWorkDone_nb(), onTripped_nb(), onError_nb() for C2 Components
 */
struct CodecListener : public C2Component::Listener {
 public:
  CodecListener(const std::function<void(std::weak_ptr<C2Component> comp,
                                         std::list<std::unique_ptr<C2Work>>& workItems)>
                    fn = nullptr)
      : callBack(fn) {}
  virtual void onWorkDone_nb(const std::weak_ptr<C2Component> comp,
                             std::list<std::unique_ptr<C2Work>> workItems) {
    if (callBack) {
      callBack(comp, workItems);
    }
  }

  virtual void onTripped_nb(const std::weak_ptr<C2Component> comp,
                            const std::vector<std::shared_ptr<C2SettingResult>> settingResults) {
    (void)comp;
    (void)settingResults;
  }

  virtual void onError_nb(const std::weak_ptr<C2Component> comp, uint32_t errorCode) {
    (void)comp;
    (void)errorCode;
  }

  std::function<void(std::weak_ptr<C2Component> comp,
                     std::list<std::unique_ptr<C2Work>>& workItems)> callBack;
};

/**
 * Buffer source implementations to identify a frame and its size
 */
bool Codec2Fuzzer::BufferSource::searchForMarker() {
  while (true) {
    if (isMarker()) {
      return true;
    }
    --mReadIndex;
    if (mReadIndex > mSize) {
      break;
    }
  }
  return false;
}

void Codec2Fuzzer::BufferSource::parse() {
  bool isFrameAvailable = true;
  size_t bytesRemaining = mSize;
  while (isFrameAvailable) {
    isFrameAvailable = searchForMarker();
    if (isFrameAvailable) {
      size_t location = mReadIndex + kMarkerSize;
      bool isCSD = isCSDMarker(location);
      location += kMarkerSuffixSize;
      uint8_t* framePtr = const_cast<uint8_t*>(&mData[location]);
      size_t frameSize = bytesRemaining - location;
      uint32_t flags = 0;
      if (mFrameList.empty()) {
        flags |= C2FrameData::FLAG_END_OF_STREAM;
      } else if (isCSD) {
        flags |= C2FrameData::FLAG_CODEC_CONFIG;
      }
      mFrameList.emplace_back(std::make_tuple(framePtr, frameSize, flags));
      bytesRemaining -= (frameSize + kMarkerSize + kMarkerSuffixSize);
      --mReadIndex;
    }
  }
  if (mFrameList.empty()) {
    /**
     * Scenario where input data does not contain the custom frame markers.
     * Hence feed the entire data as single frame.
     */
    mFrameList.emplace_back(
        std::make_tuple(const_cast<uint8_t*>(mData), 0, C2FrameData::FLAG_END_OF_STREAM));
    mFrameList.emplace_back(
        std::make_tuple(const_cast<uint8_t*>(mData), mSize, C2FrameData::FLAG_CODEC_CONFIG));
  }
}

FrameData Codec2Fuzzer::BufferSource::getFrame() {
  FrameData frame = mFrameList.back();
  mFrameList.pop_back();
  return frame;
}

void Codec2Fuzzer::handleWorkDone(std::weak_ptr<C2Component> comp,
                                  std::list<std::unique_ptr<C2Work>>& workItems) {
  (void)comp;
  for (std::unique_ptr<C2Work>& work : workItems) {
    if (!work->worklets.empty()) {
      if (work->worklets.front()->output.flags != C2FrameData::FLAG_INCOMPLETE) {
        mEos = (work->worklets.front()->output.flags & C2FrameData::FLAG_END_OF_STREAM) != 0;
        work->input.buffers.clear();
        work->worklets.clear();
        {
          std::unique_lock<std::mutex> lock(mQueueLock);
          mWorkQueue.push_back(std::move(work));
          mQueueCondition.notify_all();
        }
        if (mEos) {
          {
            std::lock_guard<std::mutex> waitForDecodeComplete(mDecodeCompleteMutex);
          }
          mConditionalVariable.notify_one();
        }
      }
    }
  }
}

bool Codec2Fuzzer::initDecoder() {
  std::vector<std::tuple<C2String, C2ComponentFactory::CreateCodec2FactoryFunc,
        C2ComponentFactory::DestroyCodec2FactoryFunc>> codec2FactoryFunc;

  codec2FactoryFunc.emplace_back(
      std::make_tuple(C2COMPONENTNAME, &CreateCodec2Factory, &DestroyCodec2Factory));

  std::shared_ptr<C2ComponentStore> componentStore = GetTestComponentStore(codec2FactoryFunc);
  if (!componentStore) {
    return false;
  }

  std::shared_ptr<C2AllocatorStore> allocatorStore = GetCodec2PlatformAllocatorStore();
  if (!allocatorStore) {
    return false;
  }

  c2_status_t status =
      allocatorStore->fetchAllocator(C2AllocatorStore::DEFAULT_LINEAR, &mLinearAllocator);
  if (status != C2_OK) {
    return false;
  }

  mLinearPool = std::make_shared<C2PooledBlockPool>(mLinearAllocator, ++mBlockPoolId);
  if (!mLinearPool) {
    return false;
  }

  for (int32_t i = 0; i < kNumberOfC2WorkItems; ++i) {
    mWorkQueue.emplace_back(new C2Work);
  }

  status = componentStore->createComponent(C2COMPONENTNAME, &mComponent);
  if (status != C2_OK) {
    return false;
  }

  status = componentStore->createInterface(C2COMPONENTNAME, &mInterface);
  if (status != C2_OK) {
    return false;
  }

  C2ComponentKindSetting kind;
  C2ComponentDomainSetting domain;
  status = mInterface->query_vb({&kind, &domain}, {}, C2_MAY_BLOCK, nullptr);
  if (status != C2_OK) {
    return false;
  }

  std::vector<C2Param*> configParams;
  if (domain.value == DOMAIN_VIDEO) {
    C2StreamPictureSizeInfo::input inputSize(0u, kWidthOfVideo, kHeightOfVideo);
    configParams.push_back(&inputSize);
  } else if (domain.value == DOMAIN_AUDIO) {
    C2StreamSampleRateInfo::output sampleRateInfo(0u, kSamplingRateOfAudio);
    C2StreamChannelCountInfo::output channelCountInfo(0u, kChannelsOfAudio);
    configParams.push_back(&sampleRateInfo);
    configParams.push_back(&channelCountInfo);
  }

  mListener.reset(new CodecListener(
      [this](std::weak_ptr<C2Component> comp, std::list<std::unique_ptr<C2Work>>& workItems) {
        handleWorkDone(comp, workItems);
      }));
  if (!mListener) {
    return false;
  }

  status = mComponent->setListener_vb(mListener, C2_DONT_BLOCK);
  if (status != C2_OK) {
    return false;
  }

  std::vector<std::unique_ptr<C2SettingResult>> failures;
  componentStore->config_sm(configParams, &failures);
  if (failures.size() != 0) {
    return false;
  }

  status = mComponent->start();
  if (status != C2_OK) {
    return false;
  }

  return true;
}

void Codec2Fuzzer::deInitDecoder() {
  mComponent->stop();
  mComponent->reset();
  mComponent->release();
  mComponent = nullptr;
}

void Codec2Fuzzer::decodeFrames(const uint8_t* data, size_t size) {
  mBufferSource = new BufferSource(data, size);
  if (!mBufferSource) {
    return;
  }
  mBufferSource->parse();
  c2_status_t status = C2_OK;
  size_t numFrames = 0;
  while (!mBufferSource->isEos()) {
    uint8_t* frame = nullptr;
    size_t frameSize = 0;
    FrameData frameData = mBufferSource->getFrame();
    frame = std::get<0>(frameData);
    frameSize = std::get<1>(frameData);

    std::unique_ptr<C2Work> work;
    {
      std::unique_lock<std::mutex> lock(mQueueLock);
      if (mWorkQueue.empty()) mQueueCondition.wait_for(lock, kC2FuzzerTimeOut);
      if (!mWorkQueue.empty()) {
        work.swap(mWorkQueue.front());
        mWorkQueue.pop_front();
      } else {
        return;
      }
    }

    work->input.flags = (C2FrameData::flags_t)std::get<2>(frameData);
    work->input.ordinal.timestamp = 0;
    work->input.ordinal.frameIndex = ++numFrames;
    work->input.buffers.clear();
    int32_t alignedSize = C2FUZZER_ALIGN(frameSize, PAGE_SIZE);

    std::shared_ptr<C2LinearBlock> block;
    status = mLinearPool->fetchLinearBlock(
        alignedSize, {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE}, &block);
    if (status != C2_OK || block == nullptr) {
      return;
    }

    C2WriteView view = block->map().get();
    if (view.error() != C2_OK) {
      return;
    }
    memcpy(view.base(), frame, frameSize);
    work->input.buffers.emplace_back(new LinearBuffer(block, frameSize));
    work->worklets.clear();
    work->worklets.emplace_back(new C2Worklet);

    std::list<std::unique_ptr<C2Work>> items;
    items.push_back(std::move(work));
    status = mComponent->queue_nb(&items);
    if (status != C2_OK) {
      return;
    }
  }
  std::unique_lock<std::mutex> waitForDecodeComplete(mDecodeCompleteMutex);
  mConditionalVariable.wait_for(waitForDecodeComplete, kC2FuzzerTimeOut, [this] { return mEos; });
  std::list<std::unique_ptr<C2Work>> c2flushedWorks;
  mComponent->flush_sm(C2Component::FLUSH_COMPONENT, &c2flushedWorks);
  delete mBufferSource;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) {
    return 0;
  }
  Codec2Fuzzer* codec = new Codec2Fuzzer();
  if (!codec) {
    return 0;
  }
  if (codec->initDecoder()) {
    codec->decodeFrames(data, size);
  }
  delete codec;
  return 0;
}
