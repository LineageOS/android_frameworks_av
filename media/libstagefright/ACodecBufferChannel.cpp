/*
 * Copyright 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "ACodecBufferChannel"
#include <utils/Log.h>

#include <numeric>

#include <C2Buffer.h>

#include <Codec2BufferUtils.h>

#include <android/hardware/cas/native/1.0/IDescrambler.h>
#include <android/hardware/drm/1.0/types.h>
#include <binder/MemoryDealer.h>
#include <hidlmemory/FrameworkUtils.h>
#include <media/openmax/OMX_Core.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/AUtils.h>
#include <media/stagefright/ACodec.h>
#include <media/stagefright/MediaCodec.h>
#include <media/MediaCodecBuffer.h>
#include <system/window.h>

#include "include/ACodecBufferChannel.h"
#include "include/SecureBuffer.h"
#include "include/SharedMemoryBuffer.h"

namespace android {
using hardware::fromHeap;
using hardware::hidl_handle;
using hardware::hidl_string;
using hardware::hidl_vec;
using namespace hardware::cas::V1_0;
using namespace hardware::cas::native::V1_0;
using DrmBufferType = hardware::drm::V1_0::BufferType;
using BufferInfo = ACodecBufferChannel::BufferInfo;
using BufferInfoIterator = std::vector<const BufferInfo>::const_iterator;

ACodecBufferChannel::~ACodecBufferChannel() {
    if (mCrypto != nullptr && mDealer != nullptr && mHeapSeqNum >= 0) {
        mCrypto->unsetHeap(mHeapSeqNum);
    }
}

static BufferInfoIterator findClientBuffer(
        const std::shared_ptr<const std::vector<const BufferInfo>> &array,
        const sp<MediaCodecBuffer> &buffer) {
    return std::find_if(
            array->begin(), array->end(),
            [buffer](const BufferInfo &info) { return info.mClientBuffer == buffer; });
}

static BufferInfoIterator findBufferId(
        const std::shared_ptr<const std::vector<const BufferInfo>> &array,
        IOMX::buffer_id bufferId) {
    return std::find_if(
            array->begin(), array->end(),
            [bufferId](const BufferInfo &info) { return bufferId == info.mBufferId; });
}

ACodecBufferChannel::BufferInfo::BufferInfo(
        const sp<MediaCodecBuffer> &buffer,
        IOMX::buffer_id bufferId,
        const sp<IMemory> &sharedEncryptedBuffer)
    : mClientBuffer(
          (sharedEncryptedBuffer == nullptr)
          ? buffer
          : new SharedMemoryBuffer(buffer->format(), sharedEncryptedBuffer)),
      mCodecBuffer(buffer),
      mBufferId(bufferId),
      mSharedEncryptedBuffer(sharedEncryptedBuffer) {
}

ACodecBufferChannel::ACodecBufferChannel(
        const sp<AMessage> &inputBufferFilled, const sp<AMessage> &outputBufferDrained,
        const sp<AMessage> &pollForRenderedBuffers)
    : mInputBufferFilled(inputBufferFilled),
      mOutputBufferDrained(outputBufferDrained),
      mPollForRenderedBuffers(pollForRenderedBuffers),
      mHeapSeqNum(-1) {
}

status_t ACodecBufferChannel::queueInputBuffer(const sp<MediaCodecBuffer> &buffer) {
    std::shared_ptr<const std::vector<const BufferInfo>> array(
            std::atomic_load(&mInputBuffers));
    BufferInfoIterator it = findClientBuffer(array, buffer);
    if (it == array->end()) {
        return -ENOENT;
    }
    if (it->mClientBuffer != it->mCodecBuffer) {
        // Copy metadata from client to codec buffer.
        it->mCodecBuffer->meta()->clear();
        int64_t timeUs;
        CHECK(it->mClientBuffer->meta()->findInt64("timeUs", &timeUs));
        it->mCodecBuffer->meta()->setInt64("timeUs", timeUs);
        int32_t eos;
        if (it->mClientBuffer->meta()->findInt32("eos", &eos)) {
            it->mCodecBuffer->meta()->setInt32("eos", eos);
        }
        int32_t csd;
        if (it->mClientBuffer->meta()->findInt32("csd", &csd)) {
            it->mCodecBuffer->meta()->setInt32("csd", csd);
        }
        int32_t decodeOnly;
        if (it->mClientBuffer->meta()->findInt32("decode-only", &decodeOnly)) {
            it->mCodecBuffer->meta()->setInt32("decode-only", decodeOnly);
        }
    }
    ALOGV("queueInputBuffer #%d", it->mBufferId);
    sp<AMessage> msg = mInputBufferFilled->dup();
    msg->setObject("buffer", it->mCodecBuffer);
    msg->setInt32("buffer-id", it->mBufferId);
    msg->post();
    return OK;
}

status_t ACodecBufferChannel::queueSecureInputBuffer(
        const sp<MediaCodecBuffer> &buffer, bool secure, const uint8_t *key,
        const uint8_t *iv, CryptoPlugin::Mode mode, CryptoPlugin::Pattern pattern,
        const CryptoPlugin::SubSample *subSamples, size_t numSubSamples,
        AString *errorDetailMsg) {
    if (!hasCryptoOrDescrambler() || mDealer == nullptr) {
        return -ENOSYS;
    }
    std::shared_ptr<const std::vector<const BufferInfo>> array(
            std::atomic_load(&mInputBuffers));
    BufferInfoIterator it = findClientBuffer(array, buffer);
    if (it == array->end()) {
        return -ENOENT;
    }

    native_handle_t *secureHandle = NULL;
    if (secure) {
        sp<SecureBuffer> secureData =
                static_cast<SecureBuffer *>(it->mCodecBuffer.get());
        if (secureData->getDestinationType() != ICrypto::kDestinationTypeNativeHandle) {
            return BAD_VALUE;
        }
        secureHandle = static_cast<native_handle_t *>(secureData->getDestinationPointer());
    }
    ssize_t result = -1;
    ssize_t codecDataOffset = 0;
    if (numSubSamples == 1
            && subSamples[0].mNumBytesOfClearData == 0
            && subSamples[0].mNumBytesOfEncryptedData == 0) {
        // We don't need to go through crypto or descrambler if the input is empty.
        result = 0;
    } else if (mCrypto != NULL) {
        hardware::drm::V1_0::DestinationBuffer destination;
        if (secure) {
            destination.type = DrmBufferType::NATIVE_HANDLE;
            destination.secureMemory = hidl_handle(secureHandle);
        } else {
            destination.type = DrmBufferType::SHARED_MEMORY;
            IMemoryToSharedBuffer(
                    mDecryptDestination, mHeapSeqNum, &destination.nonsecureMemory);
        }

        hardware::drm::V1_0::SharedBuffer source;
        IMemoryToSharedBuffer(it->mSharedEncryptedBuffer, mHeapSeqNum, &source);

        result = mCrypto->decrypt(key, iv, mode, pattern,
                source, it->mClientBuffer->offset(),
                subSamples, numSubSamples, destination, errorDetailMsg);

        if (result < 0) {
            return result;
        }

        if (destination.type == DrmBufferType::SHARED_MEMORY) {
            memcpy(it->mCodecBuffer->base(), mDecryptDestination->unsecurePointer(), result);
        }
    } else {
        // Here we cast CryptoPlugin::SubSample to hardware::cas::native::V1_0::SubSample
        // directly, the structure definitions should match as checked in DescramblerImpl.cpp.
        hidl_vec<SubSample> hidlSubSamples;
        hidlSubSamples.setToExternal((SubSample *)subSamples, numSubSamples, false /*own*/);

        ssize_t offset;
        size_t size;
        it->mSharedEncryptedBuffer->getMemory(&offset, &size);
        hardware::cas::native::V1_0::SharedBuffer srcBuffer = {
                .heapBase = *mHidlMemory,
                .offset = (uint64_t) offset,
                .size = size
        };

        DestinationBuffer dstBuffer;
        if (secure) {
            dstBuffer.type = BufferType::NATIVE_HANDLE;
            dstBuffer.secureMemory = hidl_handle(secureHandle);
        } else {
            dstBuffer.type = BufferType::SHARED_MEMORY;
            dstBuffer.nonsecureMemory = srcBuffer;
        }

        Status status = Status::OK;
        hidl_string detailedError;
        ScramblingControl sctrl = ScramblingControl::UNSCRAMBLED;

        if (key != NULL) {
            sctrl = (ScramblingControl)key[0];
            // Adjust for the PES offset
            codecDataOffset = key[2] | (key[3] << 8);
        }

        auto returnVoid = mDescrambler->descramble(
                sctrl,
                hidlSubSamples,
                srcBuffer,
                0,
                dstBuffer,
                0,
                [&status, &result, &detailedError] (
                        Status _status, uint32_t _bytesWritten,
                        const hidl_string& _detailedError) {
                    status = _status;
                    result = (ssize_t)_bytesWritten;
                    detailedError = _detailedError;
                });

        if (!returnVoid.isOk() || status != Status::OK || result < 0) {
            ALOGE("descramble failed, trans=%s, status=%d, result=%zd",
                    returnVoid.description().c_str(), status, result);
            return UNKNOWN_ERROR;
        }

        if (result < codecDataOffset) {
            ALOGD("invalid codec data offset: %zd, result %zd", codecDataOffset, result);
            return BAD_VALUE;
        }

        ALOGV("descramble succeeded, %zd bytes", result);

        if (dstBuffer.type == BufferType::SHARED_MEMORY) {
            memcpy(it->mCodecBuffer->base(),
                    (uint8_t*)it->mSharedEncryptedBuffer->unsecurePointer(),
                    result);
        }
    }

    it->mCodecBuffer->setRange(codecDataOffset, result - codecDataOffset);

    // Copy metadata from client to codec buffer.
    it->mCodecBuffer->meta()->clear();
    int64_t timeUs;
    CHECK(it->mClientBuffer->meta()->findInt64("timeUs", &timeUs));
    it->mCodecBuffer->meta()->setInt64("timeUs", timeUs);
    int32_t eos;
    if (it->mClientBuffer->meta()->findInt32("eos", &eos)) {
        it->mCodecBuffer->meta()->setInt32("eos", eos);
    }
    int32_t csd;
    if (it->mClientBuffer->meta()->findInt32("csd", &csd)) {
        it->mCodecBuffer->meta()->setInt32("csd", csd);
    }
    int32_t decodeOnly;
    if (it->mClientBuffer->meta()->findInt32("decode-only", &decodeOnly)) {
        it->mCodecBuffer->meta()->setInt32("decode-only", decodeOnly);
    }

    ALOGV("queueSecureInputBuffer #%d", it->mBufferId);
    sp<AMessage> msg = mInputBufferFilled->dup();
    msg->setObject("buffer", it->mCodecBuffer);
    msg->setInt32("buffer-id", it->mBufferId);
    msg->post();
    return OK;
}

status_t ACodecBufferChannel::attachBuffer(
        const std::shared_ptr<C2Buffer> &c2Buffer,
        const sp<MediaCodecBuffer> &buffer) {
    switch (c2Buffer->data().type()) {
        case C2BufferData::LINEAR: {
            if (c2Buffer->data().linearBlocks().size() != 1u) {
                return -ENOSYS;
            }
            C2ConstLinearBlock block{c2Buffer->data().linearBlocks().front()};
            C2ReadView view{block.map().get()};
            size_t copyLength = std::min(size_t(view.capacity()), buffer->capacity());
            ALOGV_IF(view.capacity() > buffer->capacity(),
                    "view.capacity() = %zu, buffer->capacity() = %zu",
                    view.capacity(), buffer->capacity());
            memcpy(buffer->base(), view.data(), copyLength);
            buffer->setRange(0, copyLength);
            break;
        }
        case C2BufferData::GRAPHIC: {
            sp<ABuffer> imageData;
            if (!buffer->format()->findBuffer("image-data", &imageData)) {
                return -ENOSYS;
            }
            if (c2Buffer->data().graphicBlocks().size() != 1u) {
                return -ENOSYS;
            }
            C2ConstGraphicBlock block{c2Buffer->data().graphicBlocks().front()};
            const C2GraphicView view{block.map().get()};
            status_t err = ImageCopy(
                    buffer->base(), (const MediaImage2 *)(imageData->base()), view);
            if (err != OK) {
                return err;
            }
            break;
        }
        case C2BufferData::LINEAR_CHUNKS:  [[fallthrough]];
        case C2BufferData::GRAPHIC_CHUNKS: [[fallthrough]];
        default:
            return -ENOSYS;
    }

    return OK;
}

int32_t ACodecBufferChannel::getHeapSeqNum(const sp<HidlMemory> &memory) {
    CHECK(mCrypto);
    auto it = mHeapSeqNumMap.find(memory);
    int32_t heapSeqNum = -1;
    if (it == mHeapSeqNumMap.end()) {
        heapSeqNum = mCrypto->setHeap(memory);
        mHeapSeqNumMap.emplace(memory, heapSeqNum);
    } else {
        heapSeqNum = it->second;
    }
    return heapSeqNum;
}

status_t ACodecBufferChannel::attachEncryptedBuffer(
        const sp<hardware::HidlMemory> &memory,
        bool secure,
        const uint8_t *key,
        const uint8_t *iv,
        CryptoPlugin::Mode mode,
        CryptoPlugin::Pattern pattern,
        size_t offset,
        const CryptoPlugin::SubSample *subSamples,
        size_t numSubSamples,
        const sp<MediaCodecBuffer> &buffer,
        AString* errorDetailMsg) {
    std::shared_ptr<const std::vector<const BufferInfo>> array(
            std::atomic_load(&mInputBuffers));
    BufferInfoIterator it = findClientBuffer(array, buffer);
    if (it == array->end()) {
        return -ENOENT;
    }

    native_handle_t *secureHandle = NULL;
    if (secure) {
        sp<SecureBuffer> secureData =
                static_cast<SecureBuffer *>(it->mCodecBuffer.get());
        if (secureData->getDestinationType() != ICrypto::kDestinationTypeNativeHandle) {
            return BAD_VALUE;
        }
        secureHandle = static_cast<native_handle_t *>(secureData->getDestinationPointer());
    }
    size_t size = 0;
    for (size_t i = 0; i < numSubSamples; ++i) {
        size += subSamples[i].mNumBytesOfClearData + subSamples[i].mNumBytesOfEncryptedData;
    }
    ssize_t result = -1;
    ssize_t codecDataOffset = 0;
    if (mCrypto != NULL) {
        hardware::drm::V1_0::DestinationBuffer destination;
        if (secure) {
            destination.type = DrmBufferType::NATIVE_HANDLE;
            destination.secureMemory = hidl_handle(secureHandle);
        } else {
            destination.type = DrmBufferType::SHARED_MEMORY;
            IMemoryToSharedBuffer(
                    mDecryptDestination, mHeapSeqNum, &destination.nonsecureMemory);
        }

        int32_t heapSeqNum = getHeapSeqNum(memory);
        hardware::drm::V1_0::SharedBuffer source{(uint32_t)heapSeqNum, offset, size};

        result = mCrypto->decrypt(key, iv, mode, pattern,
                source, it->mClientBuffer->offset(),
                subSamples, numSubSamples, destination, errorDetailMsg);

        if (result < 0) {
            return result;
        }

        if (destination.type == DrmBufferType::SHARED_MEMORY) {
            memcpy(it->mCodecBuffer->base(), mDecryptDestination->unsecurePointer(), result);
        }
    } else {
        // Here we cast CryptoPlugin::SubSample to hardware::cas::native::V1_0::SubSample
        // directly, the structure definitions should match as checked in DescramblerImpl.cpp.
        hidl_vec<SubSample> hidlSubSamples;
        hidlSubSamples.setToExternal((SubSample *)subSamples, numSubSamples, false /*own*/);

        hardware::cas::native::V1_0::SharedBuffer srcBuffer = {
                .heapBase = *memory,
                .offset = (uint64_t) offset,
                .size = size
        };

        DestinationBuffer dstBuffer;
        if (secure) {
            dstBuffer.type = BufferType::NATIVE_HANDLE;
            dstBuffer.secureMemory = hidl_handle(secureHandle);
        } else {
            dstBuffer.type = BufferType::SHARED_MEMORY;
            dstBuffer.nonsecureMemory = srcBuffer;
        }

        Status status = Status::OK;
        hidl_string detailedError;
        ScramblingControl sctrl = ScramblingControl::UNSCRAMBLED;

        if (key != NULL) {
            sctrl = (ScramblingControl)key[0];
            // Adjust for the PES offset
            codecDataOffset = key[2] | (key[3] << 8);
        }

        auto returnVoid = mDescrambler->descramble(
                sctrl,
                hidlSubSamples,
                srcBuffer,
                0,
                dstBuffer,
                0,
                [&status, &result, &detailedError] (
                        Status _status, uint32_t _bytesWritten,
                        const hidl_string& _detailedError) {
                    status = _status;
                    result = (ssize_t)_bytesWritten;
                    detailedError = _detailedError;
                });
        if (errorDetailMsg) {
            errorDetailMsg->setTo(detailedError.c_str(), detailedError.size());
        }
        if (!returnVoid.isOk() || status != Status::OK || result < 0) {
            ALOGE("descramble failed, trans=%s, status=%d, result=%zd",
                    returnVoid.description().c_str(), status, result);
            return UNKNOWN_ERROR;
        }

        if (result < codecDataOffset) {
            ALOGD("invalid codec data offset: %zd, result %zd", codecDataOffset, result);
            return BAD_VALUE;
        }

        ALOGV("descramble succeeded, %zd bytes", result);

        if (dstBuffer.type == BufferType::SHARED_MEMORY) {
            memcpy(it->mCodecBuffer->base(),
                    (uint8_t*)it->mSharedEncryptedBuffer->unsecurePointer(),
                    result);
        }
    }

    it->mCodecBuffer->setRange(codecDataOffset, result - codecDataOffset);
    return OK;
}

status_t ACodecBufferChannel::renderOutputBuffer(
        const sp<MediaCodecBuffer> &buffer, int64_t timestampNs) {
    std::shared_ptr<const std::vector<const BufferInfo>> array(
            std::atomic_load(&mOutputBuffers));
    BufferInfoIterator it = findClientBuffer(array, buffer);
    if (it == array->end()) {
        return -ENOENT;
    }

    ALOGV("renderOutputBuffer #%d", it->mBufferId);
    sp<AMessage> msg = mOutputBufferDrained->dup();
    msg->setObject("buffer", buffer);
    msg->setInt32("buffer-id", it->mBufferId);
    msg->setInt32("render", true);
    msg->setInt64("timestampNs", timestampNs);
    msg->post();
    return OK;
}

void ACodecBufferChannel::pollForRenderedBuffers() {
    mPollForRenderedBuffers->post();
}

status_t ACodecBufferChannel::discardBuffer(const sp<MediaCodecBuffer> &buffer) {
    std::shared_ptr<const std::vector<const BufferInfo>> array(
            std::atomic_load(&mInputBuffers));
    bool input = true;
    BufferInfoIterator it = findClientBuffer(array, buffer);
    if (it == array->end()) {
        array = std::atomic_load(&mOutputBuffers);
        input = false;
        it = findClientBuffer(array, buffer);
        if (it == array->end()) {
            return -ENOENT;
        }
    }
    ALOGV("discardBuffer #%d", it->mBufferId);
    sp<AMessage> msg = input ? mInputBufferFilled->dup() : mOutputBufferDrained->dup();
    msg->setObject("buffer", it->mCodecBuffer);
    msg->setInt32("buffer-id", it->mBufferId);
    msg->setInt32("discarded", true);
    msg->post();
    return OK;
}

void ACodecBufferChannel::getInputBufferArray(Vector<sp<MediaCodecBuffer>> *array) {
    std::shared_ptr<const std::vector<const BufferInfo>> inputBuffers(
            std::atomic_load(&mInputBuffers));
    array->clear();
    for (const BufferInfo &elem : *inputBuffers) {
        array->push_back(elem.mClientBuffer);
    }
}

void ACodecBufferChannel::getOutputBufferArray(Vector<sp<MediaCodecBuffer>> *array) {
    std::shared_ptr<const std::vector<const BufferInfo>> outputBuffers(
            std::atomic_load(&mOutputBuffers));
    array->clear();
    for (const BufferInfo &elem : *outputBuffers) {
        array->push_back(elem.mClientBuffer);
    }
}

sp<MemoryDealer> ACodecBufferChannel::makeMemoryDealer(size_t heapSize) {
    sp<MemoryDealer> dealer;
    if (mDealer != nullptr && mCrypto != nullptr && mHeapSeqNum >= 0) {
        mCrypto->unsetHeap(mHeapSeqNum);
    }
    dealer = new MemoryDealer(heapSize, "ACodecBufferChannel");
    if (mCrypto != nullptr) {
        sp<HidlMemory> hHeap = fromHeap(dealer->getMemoryHeap());
        int32_t seqNum = mCrypto->setHeap(hHeap);
        if (seqNum >= 0) {
            mHeapSeqNum = seqNum;
            ALOGV("setHeap returned mHeapSeqNum=%d", mHeapSeqNum);
        } else {
            mHeapSeqNum = -1;
            ALOGE("setHeap failed, setting mHeapSeqNum=-1");
        }
    } else if (mDescrambler != nullptr) {
        sp<IMemoryHeap> heap = dealer->getMemoryHeap();
        mHidlMemory = fromHeap(heap);
        if (mHidlMemory != NULL) {
            ALOGV("created hidl_memory for descrambler");
        } else {
            ALOGE("failed to create hidl_memory for descrambler");
        }
    }
    return dealer;
}

void ACodecBufferChannel::setInputBufferArray(const std::vector<BufferAndId> &array) {
    if (hasCryptoOrDescrambler()) {
        size_t totalSize = std::accumulate(
                array.begin(), array.end(), 0u,
                [alignment = MemoryDealer::getAllocationAlignment()]
                (size_t sum, const BufferAndId& elem) {
                    return sum + align(elem.mBuffer->capacity(), alignment);
                });
        size_t maxSize = std::accumulate(
                array.begin(), array.end(), 0u,
                [alignment = MemoryDealer::getAllocationAlignment()]
                (size_t max, const BufferAndId& elem) {
                    return std::max(max, align(elem.mBuffer->capacity(), alignment));
                });
        size_t destinationBufferSize = maxSize;
        size_t heapSize = totalSize + destinationBufferSize;
        if (heapSize > 0) {
            mDealer = makeMemoryDealer(heapSize);
            mDecryptDestination = mDealer->allocate(destinationBufferSize);
        }
    }
    std::vector<const BufferInfo> inputBuffers;
    for (const BufferAndId &elem : array) {
        sp<IMemory> sharedEncryptedBuffer;
        if (hasCryptoOrDescrambler()) {
            sharedEncryptedBuffer = mDealer->allocate(elem.mBuffer->capacity());
        }
        inputBuffers.emplace_back(elem.mBuffer, elem.mBufferId, sharedEncryptedBuffer);
    }
    std::atomic_store(
            &mInputBuffers,
            std::make_shared<const std::vector<const BufferInfo>>(inputBuffers));
}

void ACodecBufferChannel::setOutputBufferArray(const std::vector<BufferAndId> &array) {
    std::vector<const BufferInfo> outputBuffers;
    for (const BufferAndId &elem : array) {
        outputBuffers.emplace_back(elem.mBuffer, elem.mBufferId, nullptr);
    }
    std::atomic_store(
            &mOutputBuffers,
            std::make_shared<const std::vector<const BufferInfo>>(outputBuffers));
}

void ACodecBufferChannel::fillThisBuffer(IOMX::buffer_id bufferId) {
    ALOGV("fillThisBuffer #%d", bufferId);
    std::shared_ptr<const std::vector<const BufferInfo>> array(
            std::atomic_load(&mInputBuffers));
    BufferInfoIterator it = findBufferId(array, bufferId);

    if (it == array->end()) {
        ALOGE("fillThisBuffer: unrecognized buffer #%d", bufferId);
        return;
    }
    if (it->mClientBuffer != it->mCodecBuffer) {
        it->mClientBuffer->setFormat(it->mCodecBuffer->format());
    }

    mCallback->onInputBufferAvailable(
            std::distance(array->begin(), it),
            it->mClientBuffer);
}

void ACodecBufferChannel::drainThisBuffer(
        IOMX::buffer_id bufferId,
        OMX_U32 omxFlags) {
    ALOGV("drainThisBuffer #%d", bufferId);
    std::shared_ptr<const std::vector<const BufferInfo>> array(
            std::atomic_load(&mOutputBuffers));
    BufferInfoIterator it = findBufferId(array, bufferId);

    if (it == array->end()) {
        ALOGE("drainThisBuffer: unrecognized buffer #%d", bufferId);
        return;
    }
    if (it->mClientBuffer != it->mCodecBuffer) {
        it->mClientBuffer->setFormat(it->mCodecBuffer->format());
    }

    uint32_t flags = 0;
    if (omxFlags & OMX_BUFFERFLAG_SYNCFRAME) {
        flags |= MediaCodec::BUFFER_FLAG_SYNCFRAME;
    }
    if (omxFlags & OMX_BUFFERFLAG_CODECCONFIG) {
        flags |= MediaCodec::BUFFER_FLAG_CODECCONFIG;
    }
    if (omxFlags & OMX_BUFFERFLAG_EOS) {
        flags |= MediaCodec::BUFFER_FLAG_EOS;
    }
    if (omxFlags & OMX_BUFFERFLAG_DECODEONLY) {
        flags |= MediaCodec::BUFFER_FLAG_DECODE_ONLY;
    }
    it->mClientBuffer->meta()->setInt32("flags", flags);

    mCallback->onOutputBufferAvailable(
            std::distance(array->begin(), it),
            it->mClientBuffer);
}

void ACodecBufferChannel::setCrypto(const sp<ICrypto> &crypto) {
    if (mCrypto != nullptr) {
        for (std::pair<wp<HidlMemory>, int32_t> entry : mHeapSeqNumMap) {
            mCrypto->unsetHeap(entry.second);
        }
        mHeapSeqNumMap.clear();
        if (mHeapSeqNum >= 0) {
            mCrypto->unsetHeap(mHeapSeqNum);
            mHeapSeqNum = -1;
        }
    }
    mCrypto = crypto;
}

void ACodecBufferChannel::setDescrambler(const sp<IDescrambler> &descrambler) {
    mDescrambler = descrambler;
}

}  // namespace android
