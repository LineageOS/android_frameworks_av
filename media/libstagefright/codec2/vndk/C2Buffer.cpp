/*
 * Copyright (C) 2016 The Android Open Source Project
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
#define LOG_TAG "C2Buffer"
#include <utils/Log.h>

#include <map>

#include <C2BufferPriv.h>
#include <C2BlockInternal.h>

namespace android {

namespace {

// This anonymous namespace contains the helper classes that allow our implementation to create
// block/buffer objects.
//
// Inherit from the parent, share with the friend.
class ReadViewBuddy : public C2ReadView {
    using C2ReadView::C2ReadView;
    friend class ::android::C2ConstLinearBlock;
};

class WriteViewBuddy : public C2WriteView {
    using C2WriteView::C2WriteView;
    friend class ::android::C2LinearBlock;
};

class ConstLinearBlockBuddy : public C2ConstLinearBlock {
    using C2ConstLinearBlock::C2ConstLinearBlock;
    friend class ::android::C2LinearBlock;
};

class LinearBlockBuddy : public C2LinearBlock {
    using C2LinearBlock::C2LinearBlock;
    friend class ::android::C2BasicLinearBlockPool;
};

class AcquirableReadViewBuddy : public C2Acquirable<C2ReadView> {
    using C2Acquirable::C2Acquirable;
    friend class ::android::C2ConstLinearBlock;
};

class AcquirableWriteViewBuddy : public C2Acquirable<C2WriteView> {
    using C2Acquirable::C2Acquirable;
    friend class ::android::C2LinearBlock;
};

class C2DefaultGraphicView : public C2GraphicView {
    using C2GraphicView::C2GraphicView;
    friend class ::android::C2ConstGraphicBlock;
    friend class ::android::C2GraphicBlock;
};

class C2AcquirableConstGraphicView : public C2Acquirable<const C2GraphicView> {
    using C2Acquirable::C2Acquirable;
    friend class ::android::C2ConstGraphicBlock;
};

class C2AcquirableGraphicView : public C2Acquirable<C2GraphicView> {
    using C2Acquirable::C2Acquirable;
    friend class ::android::C2GraphicBlock;
};

class C2DefaultConstGraphicBlock : public C2ConstGraphicBlock {
    using C2ConstGraphicBlock::C2ConstGraphicBlock;
    friend class ::android::C2GraphicBlock;
};

class C2DefaultGraphicBlock : public C2GraphicBlock {
    using C2GraphicBlock::C2GraphicBlock;
    friend class ::android::C2BasicGraphicBlockPool;
};

class C2DefaultBufferData : public C2BufferData {
    using C2BufferData::C2BufferData;
    friend class ::android::C2Buffer;
};

}  // namespace

/* ========================================== 1D BLOCK ========================================= */

struct C2_HIDE _C2BlockPoolData;

/**
 * This class is the base class for all 1D block and view implementations.
 *
 * This is basically just a placeholder for the underlying 1D allocation and the range of the
 * alloted portion to this block. There is also a placeholder for a blockpool data.
 */
class C2_HIDE _C2Block1DImpl : public _C2LinearRangeAspect {
public:
    _C2Block1DImpl(const std::shared_ptr<C2LinearAllocation> &alloc,
            const std::shared_ptr<_C2BlockPoolData> &poolData = nullptr,
            size_t offset = 0, size_t size = ~(size_t)0)
        : _C2LinearRangeAspect(alloc.get(), offset, size),
          mAllocation(alloc),
          mPoolData(poolData) { }

    _C2Block1DImpl(const _C2Block1DImpl &other, size_t offset = 0, size_t size = ~(size_t)0)
        : _C2LinearRangeAspect(&other, offset, size),
          mAllocation(other.mAllocation),
          mPoolData(other.mPoolData) { }

    /** returns const pool data  */
    std::shared_ptr<const _C2BlockPoolData> poolData() const {
        return mPoolData;
    }

    /** returns native handle */
    const C2Handle *handle() const {
        return mAllocation ? mAllocation->handle() : nullptr;
    }

    /** returns the allocator's ID */
    C2Allocator::id_t getAllocatorId() const {
        // BAD_ID can only happen if this Impl class is initialized for a view - never for a block.
        return mAllocation ? mAllocation->getAllocatorId() : C2Allocator::BAD_ID;
    }

    std::shared_ptr<C2LinearAllocation> getAllocation() const {
        return mAllocation;
    }

private:
    std::shared_ptr<C2LinearAllocation> mAllocation;
    std::shared_ptr<_C2BlockPoolData> mPoolData;
};

/**
 * This class contains the mapped data pointer, and the potential error.
 *
 * range is the mapped range of the underlying allocation (which is part of the allotted
 * range).
 */
class C2_HIDE _C2MappedBlock1DImpl : public _C2Block1DImpl {
public:
    _C2MappedBlock1DImpl(const _C2Block1DImpl &block, uint8_t *data,
                         size_t offset = 0, size_t size = ~(size_t)0)
        : _C2Block1DImpl(block, offset, size), mData(data), mError(C2_OK) { }

    _C2MappedBlock1DImpl(c2_status_t error)
        : _C2Block1DImpl(nullptr), mData(nullptr), mError(error) {
        // CHECK(error != C2_OK);
    }

    const uint8_t *data() const {
        return mData;
    }

    uint8_t *data() {
        return mData;
    }

    c2_status_t error() const {
        return mError;
    }

private:
    uint8_t *mData;
    c2_status_t mError;
};

/**
 * Block implementation.
 */
class C2Block1D::Impl : public _C2Block1DImpl {
    using _C2Block1DImpl::_C2Block1DImpl;
};

const C2Handle *C2Block1D::handle() const {
    return mImpl->handle();
};

C2Allocator::id_t C2Block1D::getAllocatorId() const {
    return mImpl->getAllocatorId();
};

C2Block1D::C2Block1D(std::shared_ptr<Impl> impl, const _C2LinearRangeAspect &range)
    // always clamp subrange to parent (impl) range for safety
    : _C2LinearRangeAspect(impl.get(), range.offset(), range.size()), mImpl(impl) {
}

/**
 * Read view implementation.
 *
 * range of Impl is the mapped range of the underlying allocation (which is part of the allotted
 * range). range of View is 0 to capacity() (not represented as an actual range). This maps to a
 * subrange of Impl range starting at mImpl->offset() + _mOffset.
 */
class C2ReadView::Impl : public _C2MappedBlock1DImpl {
    using _C2MappedBlock1DImpl::_C2MappedBlock1DImpl;
};

C2ReadView::C2ReadView(std::shared_ptr<Impl> impl, uint32_t offset, uint32_t size)
    : _C2LinearCapacityAspect(C2LinearCapacity(impl->size()).range(offset, size).size()),
      mImpl(impl),
      mOffset(C2LinearCapacity(impl->size()).range(offset, size).offset()) { }

C2ReadView::C2ReadView(c2_status_t error)
    : _C2LinearCapacityAspect(0u), mImpl(std::make_shared<Impl>(error)), mOffset(0u) {
    // CHECK(error != C2_OK);
}

const uint8_t *C2ReadView::data() const {
    return mImpl->error() ? nullptr : mImpl->data() + mOffset;
}

c2_status_t C2ReadView::error() const {
    return mImpl->error();
}

C2ReadView C2ReadView::subView(size_t offset, size_t size) const {
    C2LinearRange subRange(*this, offset, size);
    return C2ReadView(mImpl, mOffset + subRange.offset(), subRange.size());
}

/**
 * Write view implementation.
 */
class C2WriteView::Impl : public _C2MappedBlock1DImpl {
    using _C2MappedBlock1DImpl::_C2MappedBlock1DImpl;
};

C2WriteView::C2WriteView(std::shared_ptr<Impl> impl)
// UGLY: _C2LinearRangeAspect requires a bona-fide object for capacity to prevent spoofing, so
// this is what we have to do.
    : _C2EditableLinearRange(std::make_unique<C2LinearCapacity>(impl->size()).get()), mImpl(impl) { }

C2WriteView::C2WriteView(c2_status_t error)
    : _C2EditableLinearRange(nullptr), mImpl(std::make_shared<Impl>(error)) {}

uint8_t *C2WriteView::base() { return mImpl->data(); }

uint8_t *C2WriteView::data() { return mImpl->data() + offset(); }

c2_status_t C2WriteView::error() const { return mImpl->error(); }

/**
 * Const linear block implementation.
 */
C2ConstLinearBlock::C2ConstLinearBlock(std::shared_ptr<Impl> impl, const _C2LinearRangeAspect &range, C2Fence fence)
    : C2Block1D(impl, range), mFence(fence) { }

C2Acquirable<C2ReadView> C2ConstLinearBlock::map() const {
    void *base = nullptr;
    uint32_t len = size();
    c2_status_t error = mImpl->getAllocation()->map(
            offset(), len, { C2MemoryUsage::CPU_READ, 0 }, nullptr, &base);
    // TODO: wait on fence
    if (error == C2_OK) {
        std::shared_ptr<ReadViewBuddy::Impl> rvi = std::shared_ptr<ReadViewBuddy::Impl>(
                new ReadViewBuddy::Impl(*mImpl, (uint8_t *)base, offset(), len),
                [base, len](ReadViewBuddy::Impl *i) {
                    (void)i->getAllocation()->unmap(base, len, nullptr);
        });
        return AcquirableReadViewBuddy(error, C2Fence(), ReadViewBuddy(rvi, 0, len));
    } else {
        return AcquirableReadViewBuddy(error, C2Fence(), ReadViewBuddy(error));
    }
}

C2ConstLinearBlock C2ConstLinearBlock::subBlock(size_t offset_, size_t size_) const {
    C2LinearRange subRange(*mImpl, offset_, size_);
    return C2ConstLinearBlock(mImpl, subRange, mFence);
}

/**
 * Linear block implementation.
 */
C2LinearBlock::C2LinearBlock(std::shared_ptr<Impl> impl, const _C2LinearRangeAspect &range)
    : C2Block1D(impl, range) { }

C2Acquirable<C2WriteView> C2LinearBlock::map() {
    void *base = nullptr;
    uint32_t len = size();
    c2_status_t error = mImpl->getAllocation()->map(
            offset(), len, { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE }, nullptr, &base);
    // TODO: wait on fence
    if (error == C2_OK) {
        std::shared_ptr<WriteViewBuddy::Impl> rvi = std::shared_ptr<WriteViewBuddy::Impl>(
                new WriteViewBuddy::Impl(*mImpl, (uint8_t *)base, 0, len),
                [base, len](WriteViewBuddy::Impl *i) {
                    (void)i->getAllocation()->unmap(base, len, nullptr);
        });
        return AcquirableWriteViewBuddy(error, C2Fence(), WriteViewBuddy(rvi));
    } else {
        return AcquirableWriteViewBuddy(error, C2Fence(), WriteViewBuddy(error));
    }
}

C2ConstLinearBlock C2LinearBlock::share(size_t offset_, size_t size_, C2Fence fence) {
    return ConstLinearBlockBuddy(mImpl, C2LinearRange(*this, offset_, size_), fence);
}

std::shared_ptr<C2LinearBlock> _C2BlockFactory::CreateLinearBlock(
        const std::shared_ptr<C2LinearAllocation> &alloc,
        const std::shared_ptr<_C2BlockPoolData> &data, size_t offset, size_t size) {
    std::shared_ptr<C2Block1D::Impl> impl =
        std::make_shared<C2Block1D::Impl>(alloc, data, offset, size);
    return std::shared_ptr<C2LinearBlock>(new C2LinearBlock(impl, *impl));
}

C2BasicLinearBlockPool::C2BasicLinearBlockPool(
        const std::shared_ptr<C2Allocator> &allocator)
  : mAllocator(allocator) { }

c2_status_t C2BasicLinearBlockPool::fetchLinearBlock(
        uint32_t capacity,
        C2MemoryUsage usage,
        std::shared_ptr<C2LinearBlock> *block /* nonnull */) {
    block->reset();

    std::shared_ptr<C2LinearAllocation> alloc;
    c2_status_t err = mAllocator->newLinearAllocation(capacity, usage, &alloc);
    if (err != C2_OK) {
        return err;
    }

    *block = _C2BlockFactory::CreateLinearBlock(alloc);

    return C2_OK;
}

/* ========================================== 2D BLOCK ========================================= */

class C2Block2D::Impl {
public:
    const C2Handle *handle() const {
        return mAllocation->handle();
    }

    Impl(const std::shared_ptr<C2GraphicAllocation> &alloc)
        : mAllocation(alloc) {}

private:
    std::shared_ptr<C2GraphicAllocation> mAllocation;
};

C2Block2D::C2Block2D(const std::shared_ptr<C2GraphicAllocation> &alloc)
    : _C2PlanarSection(alloc.get()), mImpl(new Impl(alloc)) {}

const C2Handle *C2Block2D::handle() const {
    return mImpl->handle();
}

class C2GraphicView::Impl {
public:
    Impl(uint8_t *const *data, const C2PlanarLayout &layout)
        : mData(data), mLayout(layout), mError(C2_OK) {}
    explicit Impl(c2_status_t error) : mData(nullptr), mError(error) {}

    uint8_t *const *data() const { return mData; }
    const C2PlanarLayout &layout() const { return mLayout; }
    c2_status_t error() const { return mError; }

private:
    uint8_t *const *mData;
    C2PlanarLayout mLayout;
    c2_status_t mError;
};

C2GraphicView::C2GraphicView(
        const _C2PlanarCapacityAspect *parent,
        uint8_t *const *data,
        const C2PlanarLayout& layout)
    : _C2PlanarSection(parent), mImpl(new Impl(data, layout)) {}

C2GraphicView::C2GraphicView(c2_status_t error)
    : _C2PlanarSection(nullptr), mImpl(new Impl(error)) {}

const uint8_t *const *C2GraphicView::data() const {
    return mImpl->data();
}

uint8_t *const *C2GraphicView::data() {
    return mImpl->data();
}

const C2PlanarLayout C2GraphicView::layout() const {
    return mImpl->layout();
}

const C2GraphicView C2GraphicView::subView(const C2Rect &rect) const {
    C2GraphicView view(this, mImpl->data(), mImpl->layout());
    view.setCrop_be(rect);
    return view;
}

C2GraphicView C2GraphicView::subView(const C2Rect &rect) {
    C2GraphicView view(this, mImpl->data(), mImpl->layout());
    view.setCrop_be(rect);
    return view;
}

c2_status_t C2GraphicView::error() const {
    return mImpl->error();
}

class C2ConstGraphicBlock::Impl {
public:
    explicit Impl(const std::shared_ptr<C2GraphicAllocation> &alloc)
        : mAllocation(alloc), mData{ nullptr } {}

    ~Impl() {
        if (mData[0] != nullptr) {
            // TODO: fence
            mAllocation->unmap(nullptr);
        }
    }

    c2_status_t map(C2Rect rect) {
        if (mData[0] != nullptr) {
            // Already mapped.
            return C2_OK;
        }
        c2_status_t err = mAllocation->map(
                rect,
                { C2MemoryUsage::CPU_READ, 0 },
                nullptr,
                &mLayout,
                mData);
        if (err != C2_OK) {
            memset(mData, 0, sizeof(mData));
        }
        return err;
    }

    C2ConstGraphicBlock subBlock(const C2Rect &rect, C2Fence fence) const {
        C2ConstGraphicBlock block(mAllocation, fence);
        block.setCrop_be(rect);
        return block;
    }

    uint8_t *const *data() const {
        return mData[0] == nullptr ? nullptr : &mData[0];
    }

    const C2PlanarLayout &layout() const { return mLayout; }

private:
    std::shared_ptr<C2GraphicAllocation> mAllocation;
    C2PlanarLayout mLayout;
    uint8_t *mData[C2PlanarLayout::MAX_NUM_PLANES];
};

C2ConstGraphicBlock::C2ConstGraphicBlock(
        const std::shared_ptr<C2GraphicAllocation> &alloc, C2Fence fence)
    : C2Block2D(alloc), mImpl(new Impl(alloc)), mFence(fence) {}

C2Acquirable<const C2GraphicView> C2ConstGraphicBlock::map() const {
    c2_status_t err = mImpl->map(crop());
    if (err != C2_OK) {
        C2DefaultGraphicView view(err);
        return C2AcquirableConstGraphicView(err, mFence, view);
    }
    C2DefaultGraphicView view(this, mImpl->data(), mImpl->layout());
    return C2AcquirableConstGraphicView(err, mFence, view);
}

C2ConstGraphicBlock C2ConstGraphicBlock::subBlock(const C2Rect &rect) const {
    return mImpl->subBlock(rect, mFence);
}

class C2GraphicBlock::Impl {
public:
    explicit Impl(const std::shared_ptr<C2GraphicAllocation> &alloc)
        : mAllocation(alloc), mData{ nullptr } {}

    ~Impl() {
        if (mData[0] != nullptr) {
            // TODO: fence
            mAllocation->unmap(nullptr);
        }
    }

    c2_status_t map(C2Rect rect) {
        if (mData[0] != nullptr) {
            // Already mapped.
            return C2_OK;
        }
        uint8_t *data[C2PlanarLayout::MAX_NUM_PLANES];
        c2_status_t err = mAllocation->map(
                rect,
                { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE },
                nullptr,
                &mLayout,
                data);
        if (err == C2_OK) {
            memcpy(mData, data, sizeof(mData));
        } else {
            memset(mData, 0, sizeof(mData));
        }
        return err;
    }

    C2ConstGraphicBlock share(const C2Rect &crop, C2Fence fence) const {
        C2DefaultConstGraphicBlock block(mAllocation, fence);
        block.setCrop_be(crop);
        return block;
    }

    uint8_t *const *data() const {
        return mData[0] == nullptr ? nullptr : mData;
    }

    const C2PlanarLayout &layout() const { return mLayout; }

private:
    std::shared_ptr<C2GraphicAllocation> mAllocation;
    C2PlanarLayout mLayout;
    uint8_t *mData[C2PlanarLayout::MAX_NUM_PLANES];
};

C2GraphicBlock::C2GraphicBlock(const std::shared_ptr<C2GraphicAllocation> &alloc)
    : C2Block2D(alloc), mImpl(new Impl(alloc)) {}

C2Acquirable<C2GraphicView> C2GraphicBlock::map() {
    c2_status_t err = mImpl->map(crop());
    if (err != C2_OK) {
        C2DefaultGraphicView view(err);
        // TODO: fence
        return C2AcquirableGraphicView(err, C2Fence(), view);
    }
    C2DefaultGraphicView view(this, mImpl->data(), mImpl->layout());
    // TODO: fence
    return C2AcquirableGraphicView(err, C2Fence(), view);
}

C2ConstGraphicBlock C2GraphicBlock::share(const C2Rect &crop, C2Fence fence) {
    return mImpl->share(crop, fence);
}

C2BasicGraphicBlockPool::C2BasicGraphicBlockPool(
        const std::shared_ptr<C2Allocator> &allocator)
  : mAllocator(allocator) {}

c2_status_t C2BasicGraphicBlockPool::fetchGraphicBlock(
        uint32_t width,
        uint32_t height,
        uint32_t format,
        C2MemoryUsage usage,
        std::shared_ptr<C2GraphicBlock> *block /* nonnull */) {
    block->reset();

    std::shared_ptr<C2GraphicAllocation> alloc;
    c2_status_t err = mAllocator->newGraphicAllocation(width, height, format, usage, &alloc);
    if (err != C2_OK) {
        return err;
    }

    block->reset(new C2DefaultGraphicBlock(alloc));

    return C2_OK;
}

/* ========================================== BUFFER ========================================= */

class C2BufferData::Impl {
public:
    explicit Impl(const std::vector<C2ConstLinearBlock> &blocks)
        : mType(blocks.size() == 1 ? LINEAR : LINEAR_CHUNKS),
          mLinearBlocks(blocks) {
    }

    explicit Impl(const std::vector<C2ConstGraphicBlock> &blocks)
        : mType(blocks.size() == 1 ? GRAPHIC : GRAPHIC_CHUNKS),
          mGraphicBlocks(blocks) {
    }

    Type type() const { return mType; }
    const std::vector<C2ConstLinearBlock> &linearBlocks() const { return mLinearBlocks; }
    const std::vector<C2ConstGraphicBlock> &graphicBlocks() const { return mGraphicBlocks; }

private:
    Type mType;
    std::vector<C2ConstLinearBlock> mLinearBlocks;
    std::vector<C2ConstGraphicBlock> mGraphicBlocks;
};

C2BufferData::C2BufferData(const std::vector<C2ConstLinearBlock> &blocks) : mImpl(new Impl(blocks)) {}
C2BufferData::C2BufferData(const std::vector<C2ConstGraphicBlock> &blocks) : mImpl(new Impl(blocks)) {}

C2BufferData::Type C2BufferData::type() const { return mImpl->type(); }

const std::vector<C2ConstLinearBlock> C2BufferData::linearBlocks() const {
    return mImpl->linearBlocks();
}

const std::vector<C2ConstGraphicBlock> C2BufferData::graphicBlocks() const {
    return mImpl->graphicBlocks();
}

class C2Buffer::Impl {
public:
    Impl(C2Buffer *thiz, const std::vector<C2ConstLinearBlock> &blocks)
        : mThis(thiz), mData(blocks) {}
    Impl(C2Buffer *thiz, const std::vector<C2ConstGraphicBlock> &blocks)
        : mThis(thiz), mData(blocks) {}

    ~Impl() {
        for (const auto &pair : mNotify) {
            pair.first(mThis, pair.second);
        }
    }

    const C2BufferData &data() const { return mData; }

    c2_status_t registerOnDestroyNotify(OnDestroyNotify onDestroyNotify, void *arg) {
        auto it = std::find_if(
                mNotify.begin(), mNotify.end(),
                [onDestroyNotify, arg] (const auto &pair) {
                    return pair.first == onDestroyNotify && pair.second == arg;
                });
        if (it != mNotify.end()) {
            return C2_DUPLICATE;
        }
        mNotify.emplace_back(onDestroyNotify, arg);
        return C2_OK;
    }

    c2_status_t unregisterOnDestroyNotify(OnDestroyNotify onDestroyNotify, void *arg) {
        auto it = std::find_if(
                mNotify.begin(), mNotify.end(),
                [onDestroyNotify, arg] (const auto &pair) {
                    return pair.first == onDestroyNotify && pair.second == arg;
                });
        if (it == mNotify.end()) {
            return C2_NOT_FOUND;
        }
        mNotify.erase(it);
        return C2_OK;
    }

    std::vector<std::shared_ptr<const C2Info>> info() const {
        std::vector<std::shared_ptr<const C2Info>> result(mInfos.size());
        std::transform(
                mInfos.begin(), mInfos.end(), result.begin(),
                [] (const auto &elem) { return elem.second; });
        return result;
    }

    c2_status_t setInfo(const std::shared_ptr<C2Info> &info) {
        // To "update" you need to erase the existing one if any, and then insert.
        (void) mInfos.erase(info->type());
        (void) mInfos.insert({ info->type(), info });
        return C2_OK;
    }

    bool hasInfo(C2Param::Type index) const {
        return mInfos.count(index.type()) > 0;
    }

    std::shared_ptr<C2Info> removeInfo(C2Param::Type index) {
        auto it = mInfos.find(index.type());
        if (it == mInfos.end()) {
            return nullptr;
        }
        std::shared_ptr<C2Info> ret = it->second;
        (void) mInfos.erase(it);
        return ret;
    }

private:
    C2Buffer * const mThis;
    C2DefaultBufferData mData;
    std::map<C2Param::Type, std::shared_ptr<C2Info>> mInfos;
    std::list<std::pair<OnDestroyNotify, void *>> mNotify;
};

C2Buffer::C2Buffer(const std::vector<C2ConstLinearBlock> &blocks)
    : mImpl(new Impl(this, blocks)) {}

C2Buffer::C2Buffer(const std::vector<C2ConstGraphicBlock> &blocks)
    : mImpl(new Impl(this, blocks)) {}

const C2BufferData C2Buffer::data() const { return mImpl->data(); }

c2_status_t C2Buffer::registerOnDestroyNotify(OnDestroyNotify onDestroyNotify, void *arg) {
    return mImpl->registerOnDestroyNotify(onDestroyNotify, arg);
}

c2_status_t C2Buffer::unregisterOnDestroyNotify(OnDestroyNotify onDestroyNotify, void *arg) {
    return mImpl->unregisterOnDestroyNotify(onDestroyNotify, arg);
}

const std::vector<std::shared_ptr<const C2Info>> C2Buffer::info() const {
    return mImpl->info();
}

c2_status_t C2Buffer::setInfo(const std::shared_ptr<C2Info> &info) {
    return mImpl->setInfo(info);
}

bool C2Buffer::hasInfo(C2Param::Type index) const {
    return mImpl->hasInfo(index);
}

std::shared_ptr<C2Info> C2Buffer::removeInfo(C2Param::Type index) {
    return mImpl->removeInfo(index);
}

} // namespace android
