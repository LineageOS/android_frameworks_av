/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef __BENCHMARK_C2_COMMON_H__
#define __BENCHMARK_C2_COMMON_H__

#include "codec2/hidl/client.h"

#include <C2Component.h>
#include <C2Config.h>

#include <hidl/HidlSupport.h>

#include <C2AllocatorIon.h>
#include <C2Buffer.h>
#include <C2BufferPriv.h>

#include "BenchmarkCommon.h"

#define MAX_RETRY 20
#define TIME_OUT 400ms
#define MAX_INPUT_BUFFERS 8

using android::C2AllocatorIon;

class LinearBuffer : public C2Buffer {
  public:
    explicit LinearBuffer(const std::shared_ptr<C2LinearBlock> &block)
        : C2Buffer({block->share(block->offset(), block->size(), ::C2Fence())}) {}

    explicit LinearBuffer(const std::shared_ptr<C2LinearBlock> &block, size_t size)
        : C2Buffer({block->share(block->offset(), size, ::C2Fence())}) {}
};

class GraphicBuffer : public C2Buffer {
  public:
    explicit GraphicBuffer(const std::shared_ptr<C2GraphicBlock> &block)
        : C2Buffer({block->share(C2Rect(block->width(), block->height()), ::C2Fence())}) {}
};

/**
 * Handle Callback functions onWorkDone(), onTripped(),
 * onError(), onDeath(), onFramesRendered() for C2 Components
 */
struct CodecListener : public android::Codec2Client::Listener {
  public:
    CodecListener(
            const std::function<void(std::list<std::unique_ptr<C2Work>> &workItems)> fn = nullptr)
        : callBack(fn) {}
    virtual void onWorkDone(const std::weak_ptr<android::Codec2Client::Component> &comp,
                            std::list<std::unique_ptr<C2Work>> &workItems) override {
        ALOGV("onWorkDone called");
        (void)comp;
        if (callBack) callBack(workItems);
    }

    virtual void onTripped(
            const std::weak_ptr<android::Codec2Client::Component> &comp,
            const std::vector<std::shared_ptr<C2SettingResult>> &settingResults) override {
        (void)comp;
        (void)settingResults;
    }

    virtual void onError(const std::weak_ptr<android::Codec2Client::Component> &comp,
                         uint32_t errorCode) override {
        (void)comp;
        ALOGV("onError called");
        if (errorCode != 0) ALOGE("Error : %u", errorCode);
    }

    virtual void onDeath(const std::weak_ptr<android::Codec2Client::Component> &comp) override {
        (void)comp;
    }

    virtual void onInputBufferDone(uint64_t frameIndex, size_t arrayIndex) override {
        (void)frameIndex;
        (void)arrayIndex;
    }

    virtual void onFrameRendered(uint64_t bufferQueueId, int32_t slotId,
                                 int64_t timestampNs) override {
        (void)bufferQueueId;
        (void)slotId;
        (void)timestampNs;
    }

    std::function<void(std::list<std::unique_ptr<C2Work>> &workItems)> callBack;
};

class BenchmarkC2Common {
  public:
    BenchmarkC2Common()
        : mEos(false),
          mStats(nullptr),
          mClient(nullptr),
          mBlockPoolId(0),
          mLinearPool(nullptr),
          mGraphicPool(nullptr),
          mLinearAllocator(nullptr),
          mGraphicAllocator(nullptr) {}

    int32_t setupCodec2();

    vector<string> getSupportedComponentList(bool isEncoder);

    void waitOnInputConsumption();

    // callback function to process onWorkDone received by Listener
    void handleWorkDone(std::list<std::unique_ptr<C2Work>> &workItems);

    bool mEos;
  protected:
    Stats *mStats;

    std::shared_ptr<android::Codec2Client> mClient;

    C2BlockPool::local_id_t mBlockPoolId;
    std::shared_ptr<C2BlockPool> mLinearPool;
    std::shared_ptr<C2BlockPool> mGraphicPool;
    std::shared_ptr<C2Allocator> mLinearAllocator;
    std::shared_ptr<C2Allocator> mGraphicAllocator;

    std::mutex mQueueLock;
    std::condition_variable mQueueCondition;
    std::list<std::unique_ptr<C2Work>> mWorkQueue;
};

#endif  // __BENCHMARK_C2_COMMON_H__
