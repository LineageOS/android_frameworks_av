/*
 * Copyright (C) 2018 The Android Open Source Project
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
#define LOG_TAG "Codec2-InputSurfaceConnection"
#include <log/log.h>

#include <codec2/hidl/1.0/InputSurfaceConnection.h>

#include <memory>
#include <list>
#include <mutex>
#include <atomic>

#include <hidl/HidlSupport.h>
#include <media/stagefright/bqhelper/ComponentWrapper.h>
#include <system/graphics.h>
#include <ui/GraphicBuffer.h>
#include <utils/Errors.h>

#include <C2.h>
#include <C2AllocatorGralloc.h>
#include <C2BlockInternal.h>
#include <C2Buffer.h>
#include <C2Component.h>
#include <C2Config.h>
#include <C2Debug.h>
#include <C2PlatformSupport.h>
#include <C2Work.h>

namespace hardware {
namespace google {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {

constexpr int32_t kBufferCount = 16;

using namespace ::android;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;

namespace /* unnamed */ {

class Buffer2D : public C2Buffer {
public:
    explicit Buffer2D(C2ConstGraphicBlock block) : C2Buffer({ block }) {
    }
};

} // unnamed namespace

struct InputSurfaceConnection::Impl : public ComponentWrapper {
    Impl(const sp<GraphicBufferSource>& source,
         const std::shared_ptr<C2Component>& comp) :
            mSource(source), mComp(comp), mRemoteComp(),
            mFrameIndex(0) {
        std::shared_ptr<C2ComponentInterface> intf = comp->intf();
        mCompName = intf ? intf->getName() : "";
    }

    Impl(const sp<GraphicBufferSource>& source,
         const sp<IComponent>& comp) :
            mSource(source), mComp(), mRemoteComp(comp),
            mFrameIndex(0) {
        Return<void> transStatus = comp->getName(
                [this](const hidl_string& name) {
                    mCompName = name.c_str();
                });
        if (!transStatus.isOk()) {
            ALOGD("getName -- Cannot obtain remote component name.");
        }
    }

    virtual ~Impl() = default;

    bool init() {
        sp<GraphicBufferSource> source = mSource.promote();
        if (source == nullptr) {
            return false;
        }
        status_t err = source->initCheck();
        if (err != OK) {
            ALOGD("Impl::init -- GBS init failed: %d", err);
            return false;
        }

        // TODO: read settings properly from the interface
        C2VideoSizeStreamTuning::input inputSize;
        C2StreamUsageTuning::input usage;
        c2_status_t c2Status = compQuery({ &inputSize, &usage },
                                         {},
                                         C2_MAY_BLOCK,
                                         nullptr);
        if (c2Status != C2_OK) {
            ALOGD("Impl::init -- cannot query information from "
                    "the component interface: %s.", asString(c2Status));
            return false;
        }

        // TODO: proper color aspect & dataspace
        android_dataspace dataSpace = HAL_DATASPACE_BT709;

        // TODO: use the usage read from intf
        // uint32_t grallocUsage =
        //         C2AndroidMemoryUsage(C2MemoryUsage(usage.value)).
        //         asGrallocUsage();

        uint32_t grallocUsage =
                mCompName.compare(0, 11, "c2.android.") == 0 ?
                GRALLOC_USAGE_SW_READ_OFTEN :
                GRALLOC_USAGE_HW_VIDEO_ENCODER;

        err = source->configure(
                this, dataSpace, kBufferCount,
                inputSize.width, inputSize.height,
                grallocUsage);
        if (err != OK) {
            ALOGD("Impl::init -- GBS configure failed: %d", err);
            return false;
        }
        for (int32_t i = 0; i < kBufferCount; ++i) {
            if (!source->onInputBufferAdded(i).isOk()) {
                ALOGD("Impl::init: populating GBS slots failed");
                return false;
            }
        }
        if (!source->start().isOk()) {
            ALOGD("Impl::init -- GBS start failed");
            return false;
        }
        mAllocatorMutex.lock();
        c2_status_t c2err = GetCodec2PlatformAllocatorStore()->fetchAllocator(
                C2AllocatorStore::PLATFORM_START + 1,  // GRALLOC
                &mAllocator);
        mAllocatorMutex.unlock();
        if (c2err != OK) {
            ALOGD("Impl::init -- failed to fetch gralloc allocator: %d", c2err);
            return false;
        }
        return true;
    }

    // From ComponentWrapper
    virtual status_t submitBuffer(
            int32_t bufferId,
            const sp<GraphicBuffer>& buffer,
            int64_t timestamp,
            int fenceFd) override {
        ALOGV("Impl::submitBuffer -- bufferId = %d", bufferId);
        // TODO: Use fd to construct fence
        (void)fenceFd;

        std::shared_ptr<C2GraphicAllocation> alloc;
        C2Handle* handle = WrapNativeCodec2GrallocHandle(
                native_handle_clone(buffer->handle),
                buffer->width, buffer->height,
                buffer->format, buffer->usage, buffer->stride);
        mAllocatorMutex.lock();
        c2_status_t err = mAllocator->priorGraphicAllocation(handle, &alloc);
        mAllocatorMutex.unlock();
        if (err != OK) {
            return UNKNOWN_ERROR;
        }
        std::shared_ptr<C2GraphicBlock> block =
                _C2BlockFactory::CreateGraphicBlock(alloc);

        std::unique_ptr<C2Work> work(new C2Work);
        work->input.flags = (C2FrameData::flags_t)0;
        work->input.ordinal.timestamp = timestamp;
        work->input.ordinal.frameIndex = mFrameIndex.fetch_add(
                1, std::memory_order_relaxed);
        work->input.buffers.clear();
        std::shared_ptr<C2Buffer> c2Buffer(
                // TODO: fence
                new Buffer2D(block->share(
                        C2Rect(block->width(), block->height()), ::C2Fence())),
                [bufferId, src = mSource](C2Buffer* ptr) {
                    delete ptr;
                    sp<GraphicBufferSource> source = src.promote();
                    if (source != nullptr) {
                        // TODO: fence
                        (void)source->onInputBufferEmptied(bufferId, -1);
                    }
                });
        work->input.buffers.push_back(c2Buffer);
        work->worklets.clear();
        work->worklets.emplace_back(new C2Worklet);
        std::list<std::unique_ptr<C2Work>> items;
        items.push_back(std::move(work));

        err = compQueue(&items);
        return (err == C2_OK) ? OK : UNKNOWN_ERROR;
    }

    virtual status_t submitEos(int32_t /* bufferId */) override {
        ALOGV("Impl::submitEos");

        std::unique_ptr<C2Work> work(new C2Work);
        work->input.flags = (C2FrameData::flags_t)0;
        work->input.ordinal.frameIndex = mFrameIndex.fetch_add(
                1, std::memory_order_relaxed);
        work->input.buffers.clear();
        work->worklets.clear();
        work->worklets.emplace_back(new C2Worklet);
        std::list<std::unique_ptr<C2Work>> items;
        items.push_back(std::move(work));

        c2_status_t err = compQueue(&items);
        return (err == C2_OK) ? OK : UNKNOWN_ERROR;
    }

    void dispatchDataSpaceChanged(
            int32_t dataSpace, int32_t aspects, int32_t pixelFormat) override {
        // TODO
        (void)dataSpace;
        (void)aspects;
        (void)pixelFormat;
    }

private:
    c2_status_t compQuery(
            const std::vector<C2Param*> &stackParams,
            const std::vector<C2Param::Index> &heapParamIndices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const heapParams) {
        std::shared_ptr<C2Component> comp = mComp.lock();
        if (comp) {
            std::shared_ptr<C2ComponentInterface> intf = comp->intf();
            if (intf) {
                return intf->query_vb(stackParams,
                                      heapParamIndices,
                                      mayBlock,
                                      heapParams);
            } else {
                ALOGD("compQuery -- component does not have an interface.");
                return C2_BAD_STATE;
            }
        }
        if (!mRemoteComp) {
            ALOGD("compQuery -- component no longer exists.");
            return C2_BAD_STATE;
        }

        hidl_vec<ParamIndex> indices(
                stackParams.size() + heapParamIndices.size());
        size_t numIndices = 0;
        for (C2Param* const& stackParam : stackParams) {
            if (!stackParam) {
                ALOGD("compQuery -- null stack param encountered.");
                continue;
            }
            indices[numIndices++] = static_cast<ParamIndex>(stackParam->index());
        }
        size_t numStackIndices = numIndices;
        for (const C2Param::Index& index : heapParamIndices) {
            indices[numIndices++] =
                    static_cast<ParamIndex>(static_cast<uint32_t>(index));
        }
        indices.resize(numIndices);
        if (heapParams) {
            heapParams->reserve(heapParams->size() + numIndices);
        }
        c2_status_t status;
        Return<void> transStatus = mRemoteComp->query(
                indices,
                mayBlock == C2_MAY_BLOCK,
                [&status, &numStackIndices, &stackParams, heapParams](
                        Status s, const Params& p) {
                    status = static_cast<c2_status_t>(s);
                    if (status != C2_OK && status != C2_BAD_INDEX) {
                        ALOGD("compQuery -- call failed: %s.", asString(status));
                        return;
                    }
                    std::vector<C2Param*> paramPointers;
                    c2_status_t parseStatus = parseParamsBlob(&paramPointers, p);
                    if (parseStatus != C2_OK) {
                        ALOGD("compQuery -- error while parsing params: %s.",
                              asString(parseStatus));
                        status = parseStatus;
                        return;
                    }
                    size_t i = 0;
                    for (auto it = paramPointers.begin();
                            it != paramPointers.end(); ) {
                        C2Param* paramPointer = *it;
                        if (numStackIndices > 0) {
                            --numStackIndices;
                            if (!paramPointer) {
                                ALOGD("compQuery -- null stack param.");
                                ++it;
                                continue;
                            }
                            for (; i < stackParams.size() &&
                                    !stackParams[i]; ) {
                                ++i;
                            }
                            CHECK(i < stackParams.size());
                            if (stackParams[i]->index() !=
                                    paramPointer->index()) {
                                ALOGD("compQuery -- param skipped. index = %d",
                                      static_cast<int>(
                                      stackParams[i]->index()));
                                stackParams[i++]->invalidate();
                                continue;
                            }
                            if (!stackParams[i++]->updateFrom(*paramPointer)) {
                                ALOGD("compQuery -- param update failed: "
                                      "index = %d.",
                                      static_cast<int>(paramPointer->index()));
                            }
                        } else {
                            if (!paramPointer) {
                                ALOGD("compQuery -- null heap param.");
                                ++it;
                                continue;
                            }
                            if (!heapParams) {
                                ALOGD("compQuery -- too many stack params.");
                                break;
                            }
                            heapParams->emplace_back(C2Param::Copy(*paramPointer));
                        }
                        ++it;
                    }
                });
        if (!transStatus.isOk()) {
            ALOGD("compQuery -- transaction failed.");
            return C2_CORRUPTED;
        }
        return status;
    }

    c2_status_t compQueue(std::list<std::unique_ptr<C2Work>>* const items) {
        std::shared_ptr<C2Component> comp = mComp.lock();
        if (comp) {
            return comp->queue_nb(items);
        }

        WorkBundle workBundle;
        Status hidlStatus = objcpy(&workBundle, *items, nullptr);
        if (hidlStatus != Status::OK) {
            ALOGD("compQueue -- bad input.");
            return C2_CORRUPTED;
        }
        Return<Status> transStatus = mRemoteComp->queue(workBundle);
        if (!transStatus.isOk()) {
            ALOGD("compQueue -- transaction failed.");
            return C2_CORRUPTED;
        }
        c2_status_t status =
                static_cast<c2_status_t>(static_cast<Status>(transStatus));
        if (status != C2_OK) {
            ALOGV("compQueue -- call failed: %s.", asString(status));
        }
        return status;
    }

    wp<GraphicBufferSource> mSource;
    std::weak_ptr<C2Component> mComp;
    sp<IComponent> mRemoteComp;
    std::string mCompName;

    // Needed for ComponentWrapper implementation
    std::mutex mAllocatorMutex;
    std::shared_ptr<C2Allocator> mAllocator;
    std::atomic_uint64_t mFrameIndex;
};

InputSurfaceConnection::InputSurfaceConnection(
        const sp<GraphicBufferSource>& source,
        const std::shared_ptr<C2Component>& comp) :
    mSource(source),
    mImpl(new Impl(source, comp)) {
}

InputSurfaceConnection::InputSurfaceConnection(
        const sp<GraphicBufferSource>& source,
        const sp<IComponent>& comp) :
    mSource(source),
    mImpl(new Impl(source, comp)) {
}

InputSurfaceConnection::~InputSurfaceConnection() {
    if (mSource) {
        (void)mSource->stop();
        (void)mSource->release();
        mSource.clear();
    }
    mImpl.clear();
}

bool InputSurfaceConnection::init() {
    mMutex.lock();
    sp<Impl> impl = mImpl;
    mMutex.unlock();

    if (!impl) {
        return false;
    }
    return impl->init();
}

Return<Status> InputSurfaceConnection::disconnect() {
    ALOGV("disconnect");
    mMutex.lock();
    if (mSource) {
        (void)mSource->stop();
        (void)mSource->release();
        mSource.clear();
    }
    mImpl.clear();
    mMutex.unlock();
    ALOGV("disconnected");
    return Status::OK;
}

}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace google
}  // namespace hardware

