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

#include <android/media/IDescrambler.h>
#include <binder/MemoryDealer.h>
#include <media/openmax/OMX_Core.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/AUtils.h>
#include <media/stagefright/MediaCodec.h>
#include <media/MediaCodecBuffer.h>
#include <system/window.h>

#include "include/ACodecBufferChannel.h"
#include "include/SecureBuffer.h"
#include "include/SharedMemoryBuffer.h"

namespace android {
using binder::Status;
using MediaDescrambler::DescrambleInfo;
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
        const sp<AMessage> &inputBufferFilled, const sp<AMessage> &outputBufferDrained)
    : mInputBufferFilled(inputBufferFilled),
      mOutputBufferDrained(outputBufferDrained),
      mHeapSeqNum(-1) {
}

status_t ACodecBufferChannel::queueInputBuffer(const sp<MediaCodecBuffer> &buffer) {
    if (mDealer != nullptr) {
        return -ENOSYS;
    }
    std::shared_ptr<const std::vector<const BufferInfo>> array(
            std::atomic_load(&mInputBuffers));
    BufferInfoIterator it = findClientBuffer(array, buffer);
    if (it == array->end()) {
        return -ENOENT;
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

    ICrypto::DestinationBuffer destination;
    if (secure) {
        sp<SecureBuffer> secureData =
                static_cast<SecureBuffer *>(it->mCodecBuffer.get());
        destination.mType = secureData->getDestinationType();
        if (destination.mType != ICrypto::kDestinationTypeNativeHandle) {
            return BAD_VALUE;
        }
        destination.mHandle =
                static_cast<native_handle_t *>(secureData->getDestinationPointer());
    } else {
        destination.mType = ICrypto::kDestinationTypeSharedMemory;
        destination.mSharedMemory = mDecryptDestination;
    }

    ICrypto::SourceBuffer source;
    source.mSharedMemory = it->mSharedEncryptedBuffer;
    source.mHeapSeqNum = mHeapSeqNum;

    ssize_t result = -1;
    if (mCrypto != NULL) {
        result = mCrypto->decrypt(key, iv, mode, pattern,
                source, it->mClientBuffer->offset(),
                subSamples, numSubSamples, destination, errorDetailMsg);
    } else {
        DescrambleInfo descrambleInfo;
        descrambleInfo.dstType = destination.mType ==
                ICrypto::kDestinationTypeSharedMemory ?
                DescrambleInfo::kDestinationTypeVmPointer :
                DescrambleInfo::kDestinationTypeNativeHandle;
        descrambleInfo.scramblingControl = key != NULL ?
                (DescramblerPlugin::ScramblingControl)key[0] :
                DescramblerPlugin::kScrambling_Unscrambled;
        descrambleInfo.numSubSamples = numSubSamples;
        descrambleInfo.subSamples = (DescramblerPlugin::SubSample *)subSamples;
        descrambleInfo.srcMem = it->mSharedEncryptedBuffer;
        descrambleInfo.srcOffset = 0;
        descrambleInfo.dstPtr = NULL;
        descrambleInfo.dstOffset = 0;

        int32_t descrambleResult = -1;
        Status status = mDescrambler->descramble(descrambleInfo, &descrambleResult);

        if (status.isOk()) {
            result = descrambleResult;
        }

        if (result < 0) {
            ALOGE("descramble failed, exceptionCode=%d, err=%d, result=%zd",
                    status.exceptionCode(), status.transactionError(), result);
        } else {
            ALOGV("descramble succeeded, result=%zd", result);
        }

        if (result > 0 && destination.mType == ICrypto::kDestinationTypeSharedMemory) {
            memcpy(destination.mSharedMemory->pointer(),
                    (uint8_t*)it->mSharedEncryptedBuffer->pointer(), result);
        }
    }

    if (result < 0) {
        return result;
    }

    if (destination.mType == ICrypto::kDestinationTypeSharedMemory) {
        memcpy(it->mCodecBuffer->base(), destination.mSharedMemory->pointer(), result);
    }

    it->mCodecBuffer->setRange(0, result);

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

    ALOGV("queueSecureInputBuffer #%d", it->mBufferId);
    sp<AMessage> msg = mInputBufferFilled->dup();
    msg->setObject("buffer", it->mCodecBuffer);
    msg->setInt32("buffer-id", it->mBufferId);
    msg->post();
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
        int32_t seqNum = mCrypto->setHeap(dealer->getMemoryHeap());
        if (seqNum >= 0) {
            mHeapSeqNum = seqNum;
            ALOGD("setHeap returned mHeapSeqNum=%d", mHeapSeqNum);
        } else {
            mHeapSeqNum = -1;
            ALOGD("setHeap failed, setting mHeapSeqNum=-1");
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
    if (omxFlags & OMX_BUFFERFLAG_EXTRADATA) {
        flags |= MediaCodec::BUFFER_FLAG_EXTRADATA;
    }
    if (omxFlags & OMX_BUFFERFLAG_DATACORRUPT) {
        flags |= MediaCodec::BUFFER_FLAG_DATACORRUPT;
    }
    it->mClientBuffer->meta()->setInt32("flags", flags);

    mCallback->onOutputBufferAvailable(
            std::distance(array->begin(), it),
            it->mClientBuffer);
}

}  // namespace android
