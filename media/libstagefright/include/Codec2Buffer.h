/*
 * Copyright 2017, The Android Open Source Project
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

#ifndef CODEC2_BUFFER_H_

#define CODEC2_BUFFER_H_

#include <C2Buffer.h>

#include <media/MediaCodecBuffer.h>

namespace android {

class Codec2Buffer : public MediaCodecBuffer {
public:
    using MediaCodecBuffer::MediaCodecBuffer;
    ~Codec2Buffer() override = default;

    /**
     * \return  C2Buffer object represents this buffer.
     */
    virtual std::shared_ptr<C2Buffer> asC2Buffer() = 0;

    /**
     * Test if we can copy the content of |buffer| into this object.
     *
     * \param   buffer  C2Buffer object to copy.
     * \return  true    if the content of buffer can be copied over to this buffer
     *          false   otherwise.
     */
    virtual bool canCopy(const std::shared_ptr<C2Buffer> &buffer) const {
        (void)buffer;
        return false;
    }

    /**
     * Copy the content of |buffer| into this object. This method assumes that
     * canCopy() check already passed.
     *
     * \param   buffer  C2Buffer object to copy.
     * \return  true    if successful
     *          false   otherwise.
     */
    virtual bool copy(const std::shared_ptr<C2Buffer> &buffer) {
        (void)buffer;
        return false;
    }

protected:
    /**
     * canCopy() implementation for linear buffers.
     */
    bool canCopyLinear(const std::shared_ptr<C2Buffer> &buffer) const;

    /**
     * copy() implementation for linear buffers.
     */
    bool copyLinear(const std::shared_ptr<C2Buffer> &buffer);
};

/**
 * MediaCodecBuffer implementation on top of local linear buffer. This cannot
 * cross process boundary so asC2Buffer() returns only nullptr.
 */
class LocalLinearBuffer : public Codec2Buffer {
public:
    using Codec2Buffer::Codec2Buffer;

    std::shared_ptr<C2Buffer> asC2Buffer() override { return nullptr; }
    bool canCopy(const std::shared_ptr<C2Buffer> &buffer) const override;
    bool copy(const std::shared_ptr<C2Buffer> &buffer) override;
};

/**
 * MediaCodecBuffer implementation to be used only as a dummy wrapper around a
 * C2Buffer object.
 */
class DummyContainerBuffer : public Codec2Buffer {
public:
    DummyContainerBuffer(
            const sp<AMessage> &format,
            const std::shared_ptr<C2Buffer> &buffer = nullptr);

    std::shared_ptr<C2Buffer> asC2Buffer() override;
    bool canCopy(const std::shared_ptr<C2Buffer> &buffer) const override;
    bool copy(const std::shared_ptr<C2Buffer> &buffer) override;

private:
    std::shared_ptr<C2Buffer> mBufferRef;
};

/**
 * MediaCodecBuffer implementation wraps around C2LinearBlock.
 */
class LinearBlockBuffer : public Codec2Buffer {
public:
    /**
     * Allocate a new LinearBufferBlock wrapping around C2LinearBlock object.
     */
    static sp<LinearBlockBuffer> Allocate(
            const sp<AMessage> &format, const std::shared_ptr<C2LinearBlock> &block);

    virtual ~LinearBlockBuffer() = default;

    std::shared_ptr<C2Buffer> asC2Buffer() override;
    bool canCopy(const std::shared_ptr<C2Buffer> &buffer) const override;
    bool copy(const std::shared_ptr<C2Buffer> &buffer) override;

private:
    LinearBlockBuffer(
            const sp<AMessage> &format,
            C2WriteView &&writeView,
            const std::shared_ptr<C2LinearBlock> &block);
    LinearBlockBuffer() = delete;

    C2WriteView mWriteView;
    std::shared_ptr<C2LinearBlock> mBlock;
};

/**
 * MediaCodecBuffer implementation wraps around C2ConstLinearBlock.
 */
class ConstLinearBlockBuffer : public Codec2Buffer {
public:
    /**
     * Allocate a new ConstLinearBlockBuffer wrapping around C2Buffer object.
     */
    static sp<ConstLinearBlockBuffer> Allocate(
            const sp<AMessage> &format, const std::shared_ptr<C2Buffer> &buffer);

    virtual ~ConstLinearBlockBuffer() = default;

    std::shared_ptr<C2Buffer> asC2Buffer() override;

private:
    ConstLinearBlockBuffer(
            const sp<AMessage> &format,
            C2ReadView &&readView,
            const std::shared_ptr<C2Buffer> &buffer);
    ConstLinearBlockBuffer() = delete;

    C2ReadView mReadView;
    std::shared_ptr<C2Buffer> mBufferRef;
};

}  // namespace android

#endif  // CODEC2_BUFFER_H_
