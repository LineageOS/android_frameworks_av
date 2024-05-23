/*
 * Copyright 2024, The Android Open Source Project
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
#define LOG_TAG "C2NodeImpl"
#include <log/log.h>

#include <C2AllocatorGralloc.h>
#include <C2BlockInternal.h>
#include <C2Component.h>
#include <C2Config.h>
#include <C2Debug.h>
#include <C2PlatformSupport.h>

#include <android_media_codec.h>
#include <android/fdsan.h>
#include <media/stagefright/foundation/ColorUtils.h>
#include <ui/Fence.h>
#include <ui/GraphicBuffer.h>
#include <utils/Errors.h>
#include <utils/Thread.h>

#include "utils/Codec2Mapper.h"
#include "C2NodeImpl.h"
#include "Codec2Buffer.h"

namespace android {

using ::aidl::android::media::IAidlBufferSource;
using ::aidl::android::media::IAidlNode;

using ::android::media::BUFFERFLAG_EOS;

namespace {

class Buffer2D : public C2Buffer {
public:
    explicit Buffer2D(C2ConstGraphicBlock block) : C2Buffer({ block }) {}
};

}  // namespace

class C2NodeImpl::QueueThread : public Thread {
public:
    QueueThread() : Thread(false) {}
    ~QueueThread() override = default;
    void queue(
            const std::shared_ptr<Codec2Client::Component> &comp,
            int fenceFd,
            std::unique_ptr<C2Work> &&work,
            android::base::unique_fd &&fd0,
            android::base::unique_fd &&fd1) {
        Mutexed<Jobs>::Locked jobs(mJobs);
        auto it = jobs->queues.try_emplace(comp, comp).first;
        it->second.workList.emplace_back(
                std::move(work), fenceFd, std::move(fd0), std::move(fd1));
        jobs->cond.broadcast();
    }

    void setDataspace(android_dataspace dataspace) {
        Mutexed<Jobs>::Locked jobs(mJobs);
        ColorUtils::convertDataSpaceToV0(dataspace);
        jobs->configUpdate.emplace_back(new C2StreamDataSpaceInfo::input(0u, dataspace));
        int32_t standard;
        int32_t transfer;
        int32_t range;
        ColorUtils::getColorConfigFromDataSpace(dataspace, &range, &standard, &transfer);
        std::unique_ptr<C2StreamColorAspectsInfo::input> colorAspects =
            std::make_unique<C2StreamColorAspectsInfo::input>(0u);
        if (C2Mapper::map(standard, &colorAspects->primaries, &colorAspects->matrix)
                && C2Mapper::map(transfer, &colorAspects->transfer)
                && C2Mapper::map(range, &colorAspects->range)) {
            jobs->configUpdate.push_back(std::move(colorAspects));
        }
    }

    void setPriority(int priority) {
        androidSetThreadPriority(getTid(), priority);
    }

protected:
    bool threadLoop() override {
        constexpr nsecs_t kIntervalNs = nsecs_t(10) * 1000 * 1000;  // 10ms
        constexpr nsecs_t kWaitNs = kIntervalNs * 2;
        for (int i = 0; i < 2; ++i) {
            Mutexed<Jobs>::Locked jobs(mJobs);
            nsecs_t nowNs = systemTime();
            bool queued = false;
            for (auto it = jobs->queues.begin(); it != jobs->queues.end(); ) {
                Queue &queue = it->second;
                if (queue.workList.empty()
                        || (queue.lastQueuedTimestampNs != 0 &&
                            nowNs - queue.lastQueuedTimestampNs < kIntervalNs)) {
                    ++it;
                    continue;
                }
                std::shared_ptr<Codec2Client::Component> comp = queue.component.lock();
                if (!comp) {
                    it = jobs->queues.erase(it);
                    continue;
                }
                std::list<std::unique_ptr<C2Work>> items;
                std::vector<int> fenceFds;
                std::vector<android::base::unique_fd> uniqueFds;
                while (!queue.workList.empty()) {
                    items.push_back(std::move(queue.workList.front().work));
                    fenceFds.push_back(queue.workList.front().fenceFd);
                    uniqueFds.push_back(std::move(queue.workList.front().fd0));
                    uniqueFds.push_back(std::move(queue.workList.front().fd1));
                    queue.workList.pop_front();
                }
                for (const std::unique_ptr<C2Param> &param : jobs->configUpdate) {
                    items.front()->input.configUpdate.emplace_back(C2Param::Copy(*param));
                }

                jobs.unlock();
                for (int fenceFd : fenceFds) {
                    sp<Fence> fence(new Fence(fenceFd));
                    fence->waitForever(LOG_TAG);
                }
                queue.lastQueuedTimestampNs = nowNs;
                comp->queue(&items);
                for (android::base::unique_fd &ufd : uniqueFds) {
                    (void)ufd.release();
                }
                jobs.lock();

                it = jobs->queues.upper_bound(comp);
                queued = true;
            }
            if (queued) {
                jobs->configUpdate.clear();
                return true;
            }
            if (i == 0) {
                jobs.waitForConditionRelative(jobs->cond, kWaitNs);
            }
        }
        return true;
    }

private:
    struct WorkFence {
        WorkFence(std::unique_ptr<C2Work> &&w, int fd) : work(std::move(w)), fenceFd(fd) {}

        WorkFence(
                std::unique_ptr<C2Work> &&w,
                int fd,
                android::base::unique_fd &&uniqueFd0,
                android::base::unique_fd &&uniqueFd1)
            : work(std::move(w)),
              fenceFd(fd),
              fd0(std::move(uniqueFd0)),
              fd1(std::move(uniqueFd1)) {}

        std::unique_ptr<C2Work> work;
        int fenceFd;
        android::base::unique_fd fd0;
        android::base::unique_fd fd1;
    };
    struct Queue {
        Queue(const std::shared_ptr<Codec2Client::Component> &comp)
            : component(comp), lastQueuedTimestampNs(0) {}
        Queue(const Queue &) = delete;
        Queue &operator =(const Queue &) = delete;

        std::weak_ptr<Codec2Client::Component> component;
        std::list<WorkFence> workList;
        nsecs_t lastQueuedTimestampNs;
    };
    struct Jobs {
        std::map<std::weak_ptr<Codec2Client::Component>,
                 Queue,
                 std::owner_less<std::weak_ptr<Codec2Client::Component>>> queues;
        std::vector<std::unique_ptr<C2Param>> configUpdate;
        Condition cond;
    };
    Mutexed<Jobs> mJobs;
};

C2NodeImpl::C2NodeImpl(const std::shared_ptr<Codec2Client::Component> &comp, bool aidl)
    : mComp(comp), mFrameIndex(0), mWidth(0), mHeight(0), mUsage(0),
      mAdjustTimestampGapUs(0), mFirstInputFrame(true),
      mQueueThread(new QueueThread), mAidlHal(aidl) {
    android_fdsan_set_error_level(ANDROID_FDSAN_ERROR_LEVEL_WARN_ALWAYS);
    mQueueThread->run("C2NodeImpl", PRIORITY_AUDIO);

    android_dataspace ds = HAL_DATASPACE_UNKNOWN;
    mDataspace.lock().set(ds);
    uint32_t pf = PIXEL_FORMAT_UNKNOWN;
    mPixelFormat.lock().set(pf);
}

C2NodeImpl::~C2NodeImpl() {
}

status_t C2NodeImpl::freeNode() {
    mComp.reset();
    android_fdsan_set_error_level(ANDROID_FDSAN_ERROR_LEVEL_WARN_ONCE);
    return mQueueThread->requestExitAndWait();
}

void C2NodeImpl::onFirstInputFrame() {
    mFirstInputFrame = true;
}

void C2NodeImpl::getConsumerUsageBits(uint64_t *usage) {
    *usage = mUsage;
}

void C2NodeImpl::getInputBufferParams(IAidlNode::InputBufferParams *params) {
    params->bufferCountActual = 16;

    // WORKAROUND: having more slots improve performance while consuming
    // more memory. This is a temporary workaround to reduce memory for
    // larger-than-4K scenario.
    if (mWidth * mHeight > 4096 * 2340) {
        std::shared_ptr<Codec2Client::Component> comp = mComp.lock();
        C2PortActualDelayTuning::input inputDelay(0);
        C2ActualPipelineDelayTuning pipelineDelay(0);
        c2_status_t c2err = C2_NOT_FOUND;
        if (comp) {
            c2err = comp->query(
                    {&inputDelay, &pipelineDelay}, {}, C2_DONT_BLOCK, nullptr);
        }
        if (c2err == C2_OK || c2err == C2_BAD_INDEX) {
            params->bufferCountActual = 4;
            params->bufferCountActual += (inputDelay ? inputDelay.value : 0u);
            params->bufferCountActual += (pipelineDelay ? pipelineDelay.value : 0u);
        }
    }

    params->frameWidth = mWidth;
    params->frameHeight = mHeight;
}

void C2NodeImpl::setConsumerUsageBits(uint64_t usage) {
    mUsage = usage;
}

void C2NodeImpl::setAdjustTimestampGapUs(int32_t gapUs) {
    mAdjustTimestampGapUs = gapUs;
}

status_t C2NodeImpl::setInputSurface(const sp<IOMXBufferSource> &bufferSource) {
    c2_status_t err = GetCodec2PlatformAllocatorStore()->fetchAllocator(
            C2PlatformAllocatorStore::GRALLOC,
            &mAllocator);
    if (err != OK) {
        return UNKNOWN_ERROR;
    }
    CHECK(!mAidlHal);
    mBufferSource = bufferSource;
    return OK;
}

status_t C2NodeImpl::setAidlInputSurface(
        const std::shared_ptr<IAidlBufferSource> &aidlBufferSource) {
    c2_status_t err = GetCodec2PlatformAllocatorStore()->fetchAllocator(
            C2PlatformAllocatorStore::GRALLOC,
            &mAllocator);
    if (err != OK) {
        return UNKNOWN_ERROR;
    }
    CHECK(mAidlHal);
    mAidlBufferSource = aidlBufferSource;
    return OK;
}

status_t C2NodeImpl::submitBuffer(
        uint32_t buffer, const sp<GraphicBuffer> &graphicBuffer,
        uint32_t flags, int64_t timestamp, int fenceFd) {
    std::shared_ptr<Codec2Client::Component> comp = mComp.lock();
    if (!comp) {
        return NO_INIT;
    }

    uint32_t c2Flags = (flags & BUFFERFLAG_EOS)
            ? C2FrameData::FLAG_END_OF_STREAM : 0;
    std::shared_ptr<C2GraphicBlock> block;

    android::base::unique_fd fd0, fd1;
    C2Handle *handle = nullptr;
    if (graphicBuffer) {
        std::shared_ptr<C2GraphicAllocation> alloc;
        handle = WrapNativeCodec2GrallocHandle(
                graphicBuffer->handle,
                graphicBuffer->width,
                graphicBuffer->height,
                graphicBuffer->format,
                graphicBuffer->usage,
                graphicBuffer->stride);
        if (handle != nullptr) {
            // unique_fd takes ownership of the fds, we'll get warning if these
            // fds get closed by somebody else. Onwership will be released before
            // we return, so that the fds get closed as usually when this function
            // goes out of scope (when both items and block are gone).
            native_handle_t *nativeHandle = reinterpret_cast<native_handle_t*>(handle);
            fd0.reset(nativeHandle->numFds > 0 ? nativeHandle->data[0] : -1);
            fd1.reset(nativeHandle->numFds > 1 ? nativeHandle->data[1] : -1);
        }
        c2_status_t err = mAllocator->priorGraphicAllocation(handle, &alloc);
        if (err != OK) {
            (void)fd0.release();
            (void)fd1.release();
            native_handle_close(handle);
            native_handle_delete(handle);
            return UNKNOWN_ERROR;
        }
        block = _C2BlockFactory::CreateGraphicBlock(alloc);
    } else if (!(flags & BUFFERFLAG_EOS)) {
        return BAD_VALUE;
    }

    std::unique_ptr<C2Work> work(new C2Work);
    work->input.flags = (C2FrameData::flags_t)c2Flags;
    work->input.ordinal.timestamp = timestamp;

    // WORKAROUND: adjust timestamp based on gapUs
    {
        work->input.ordinal.customOrdinal = timestamp; // save input timestamp
        if (mFirstInputFrame) {
            // grab timestamps on first frame
            mPrevInputTimestamp = timestamp;
            mPrevCodecTimestamp = timestamp;
            mFirstInputFrame = false;
        } else if (mAdjustTimestampGapUs > 0) {
            work->input.ordinal.timestamp =
                mPrevCodecTimestamp
                        + c2_min((timestamp - mPrevInputTimestamp).peek(), mAdjustTimestampGapUs);
        } else if (mAdjustTimestampGapUs < 0) {
            work->input.ordinal.timestamp = mPrevCodecTimestamp - mAdjustTimestampGapUs;
        }
        mPrevInputTimestamp = work->input.ordinal.customOrdinal;
        mPrevCodecTimestamp = work->input.ordinal.timestamp;
        ALOGV("adjusting %lld to %lld (gap=%lld)",
              work->input.ordinal.customOrdinal.peekll(),
              work->input.ordinal.timestamp.peekll(),
              (long long)mAdjustTimestampGapUs);
    }

    work->input.ordinal.frameIndex = mFrameIndex++;
    work->input.buffers.clear();
    if (block) {
        std::shared_ptr<C2Buffer> c2Buffer(
                new Buffer2D(block->share(
                        C2Rect(block->width(), block->height()), ::C2Fence())));
        work->input.buffers.push_back(c2Buffer);
        std::shared_ptr<C2StreamHdrStaticInfo::input> staticInfo;
        std::shared_ptr<C2StreamHdrDynamicMetadataInfo::input> dynamicInfo;
        GetHdrMetadataFromGralloc4Handle(
                block->handle(),
                &staticInfo,
                &dynamicInfo);
        if (staticInfo && *staticInfo) {
            c2Buffer->setInfo(staticInfo);
        }
        if (dynamicInfo && *dynamicInfo) {
            c2Buffer->setInfo(dynamicInfo);
        }
    }
    work->worklets.clear();
    work->worklets.emplace_back(new C2Worklet);
    {
        Mutexed<BuffersTracker>::Locked buffers(mBuffersTracker);
        buffers->mIdsInUse.emplace(work->input.ordinal.frameIndex.peeku(), buffer);
    }
    mQueueThread->queue(comp, fenceFd, std::move(work), std::move(fd0), std::move(fd1));

    return OK;
}

status_t C2NodeImpl::onDataspaceChanged(uint32_t dataSpace, uint32_t pixelFormat) {
    ALOGD("dataspace changed to %#x pixel format: %#x", dataSpace, pixelFormat);
    android_dataspace d = (android_dataspace)dataSpace;
    mQueueThread->setDataspace(d);

    mDataspace.lock().set(d);
    mPixelFormat.lock().set(pixelFormat);
    return OK;
}

sp<IOMXBufferSource> C2NodeImpl::getSource() {
    CHECK(!mAidlHal);
    return mBufferSource;
}

std::shared_ptr<IAidlBufferSource> C2NodeImpl::getAidlSource() {
    CHECK(mAidlHal);
    return mAidlBufferSource;
}

void C2NodeImpl::setFrameSize(uint32_t width, uint32_t height) {
    mWidth = width;
    mHeight = height;
}

void C2NodeImpl::onInputBufferDone(c2_cntr64_t index) {
    if (android::media::codec::provider_->input_surface_throttle()) {
        Mutexed<BuffersTracker>::Locked buffers(mBuffersTracker);
        auto it = buffers->mIdsInUse.find(index.peeku());
        if (it == buffers->mIdsInUse.end()) {
            ALOGV("Untracked input index %llu (maybe already removed)", index.peekull());
            return;
        }
        int32_t bufferId = it->second;
        (void)buffers->mIdsInUse.erase(it);
        buffers->mAvailableIds.push_back(bufferId);
    } else {
        if (!hasBufferSource()) {
            return;
        }
        int32_t bufferId = 0;
        {
            Mutexed<BuffersTracker>::Locked buffers(mBuffersTracker);
            auto it = buffers->mIdsInUse.find(index.peeku());
            if (it == buffers->mIdsInUse.end()) {
                ALOGV("Untracked input index %llu (maybe already removed)", index.peekull());
                return;
            }
            bufferId = it->second;
            (void)buffers->mIdsInUse.erase(it);
        }
        notifyInputBufferEmptied(bufferId);
    }
}

void C2NodeImpl::onInputBufferEmptied() {
    if (!android::media::codec::provider_->input_surface_throttle()) {
        ALOGE("onInputBufferEmptied should not be called "
              "when input_surface_throttle is false");
        return;
    }
    if (!hasBufferSource()) {
        return;
    }
    int32_t bufferId = 0;
    {
        Mutexed<BuffersTracker>::Locked buffers(mBuffersTracker);
        if (buffers->mAvailableIds.empty()) {
            ALOGV("The codec is ready to take more input buffers "
                    "but no input buffers are ready yet.");
            return;
        }
        bufferId = buffers->mAvailableIds.front();
        buffers->mAvailableIds.pop_front();
    }
    notifyInputBufferEmptied(bufferId);
}

bool C2NodeImpl::hasBufferSource() {
    if (mAidlHal) {
        if (!mAidlBufferSource) {
            ALOGD("Buffer source not set");
            return false;
        }
    } else {
        if (!mBufferSource) {
            ALOGD("Buffer source not set");
            return false;
        }
    }
    return true;
}

void C2NodeImpl::notifyInputBufferEmptied(int32_t bufferId) {
    if (mAidlHal) {
        ::ndk::ScopedFileDescriptor nullFence;
        (void)mAidlBufferSource->onInputBufferEmptied(bufferId, nullFence);
    } else {
        (void)mBufferSource->onInputBufferEmptied(bufferId, -1);
    }
}

android_dataspace C2NodeImpl::getDataspace() {
    return *mDataspace.lock();
}

uint32_t C2NodeImpl::getPixelFormat() {
    return *mPixelFormat.lock();
}

void C2NodeImpl::setPriority(int priority) {
    mQueueThread->setPriority(priority);
}

}  // namespace android
