/*
 * Copyright 2022 The Android Open Source Project
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
#define LOG_TAG "CryptoAsync"

#include <log/log.h>

#include "hidl/HidlSupport.h"
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ADebug.h>

#include <media/MediaCodecBuffer.h>
#include <media/stagefright/MediaCodec.h>
#include <media/stagefright/CryptoAsync.h>

namespace android {

CryptoAsync::CryptoAsyncInfo::CryptoAsyncInfo(const std::unique_ptr<CodecCryptoInfo> &info) {
    if (info == nullptr) {
        return;
    }
    size_t key_len = (info->mKey != nullptr)? 16 : 0;
    size_t iv_len = (info->mIv != nullptr)? 16 : 0;
    mNumSubSamples = info->mNumSubSamples;
    mMode = info->mMode;
    mPattern = info->mPattern;
    if (key_len > 0) {
        mKeyBuffer = ABuffer::CreateAsCopy((void*)info->mKey, key_len);
        mKey = (uint8_t*)(mKeyBuffer.get() != nullptr ? mKeyBuffer.get()->data() : nullptr);
    }
    if (iv_len > 0) {
        mIvBuffer = ABuffer::CreateAsCopy((void*)info->mIv, iv_len);
        mIv = (uint8_t*)(mIvBuffer.get() != nullptr ? mIvBuffer.get()->data() : nullptr);
    }
    mSubSamplesBuffer =
        new ABuffer(sizeof(CryptoPlugin::SubSample) * mNumSubSamples);
    if (mSubSamplesBuffer.get()) {
        CryptoPlugin::SubSample * samples =
           (CryptoPlugin::SubSample *)(mSubSamplesBuffer.get()->data());
        for (int s = 0 ; s < mNumSubSamples ; s++) {
            samples[s].mNumBytesOfClearData = info->mSubSamples[s].mNumBytesOfClearData;
            samples[s].mNumBytesOfEncryptedData = info->mSubSamples[s].mNumBytesOfEncryptedData;
        }
        mSubSamples = (CryptoPlugin::SubSample *)mSubSamplesBuffer.get()->data();
    }
}

CryptoAsync::~CryptoAsync() {
}

status_t CryptoAsync::decrypt(sp<AMessage> &msg) {
    int32_t decryptAction;
    CHECK(msg->findInt32("action", &decryptAction));
    if (mCallback == nullptr) {
       ALOGE("Crypto callback channel is not set");
       return -ENOSYS;
    }
    bool shouldPost = false;
    Mutexed<std::list<sp<AMessage>>>::Locked pendingBuffers(mPendingBuffers);
    if (mState != kCryptoAsyncActive) {
       ALOGE("Cannot decrypt in errored state");
       return -ENOSYS;
    }
    shouldPost = pendingBuffers->size() == 0 ? true : false;
    pendingBuffers->push_back(std::move(msg));
    if (shouldPost) {
       sp<AMessage> decryptMsg = new AMessage(kWhatDecrypt, this);
       decryptMsg->post();
    }
    return OK;
}

void CryptoAsync::stop(std::list<sp<AMessage>> * const buffers) {
    sp<AMessage>  stopMsg = new AMessage(kWhatStop, this);
    stopMsg->setPointer("remaining", static_cast<void*>(buffers));
    sp<AMessage> response;
    status_t err = stopMsg->postAndAwaitResponse(&response);
    if (err == OK && response != NULL) {
        CHECK(response->findInt32("err", &err));
    } else {
        ALOGE("Error handling stop in CryptoAsync");
        //TODO: handle the error here.
    }
}

status_t CryptoAsync::decryptAndQueue(sp<AMessage> & msg) {
    std::shared_ptr<BufferChannelBase> channel = mBufferChannel.lock();
    status_t err = OK;
    sp<RefBase> obj;
    size_t numSubSamples = 0;
    int32_t secure = 0;
    CryptoPlugin::Mode mode;
    CryptoPlugin::Pattern pattern;
    sp<ABuffer> keyBuffer;
    sp<ABuffer> ivBuffer;
    sp<ABuffer> subSamplesBuffer;
    AString errorDetailMsg;
    msg->findObject("buffer", &obj);
    msg->findInt32("secure", &secure);
    sp<MediaCodecBuffer> buffer = static_cast<MediaCodecBuffer *>(obj.get());
    if (buffer->meta()->findObject("cryptoInfos", &obj)) {
        err = channel->queueSecureInputBuffers(buffer, secure, &errorDetailMsg);
    } else {
        msg->findInt32("encryptBlocks", (int32_t*)&pattern.mEncryptBlocks);
        msg->findInt32("skipBlocks", (int32_t*)&pattern.mSkipBlocks);
        msg->findBuffer("key", &keyBuffer);
        msg->findBuffer("iv", &ivBuffer);
        msg->findBuffer("subSamples", &subSamplesBuffer);
        msg->findSize("numSubSamples", &numSubSamples);
        msg->findInt32("mode", (int32_t*)&mode);
        const uint8_t * key = keyBuffer.get() != nullptr ? keyBuffer.get()->data() : nullptr;
        const uint8_t * iv = ivBuffer.get() != nullptr ? ivBuffer.get()->data() : nullptr;
        const CryptoPlugin::SubSample * subSamples =
           (CryptoPlugin::SubSample *)(subSamplesBuffer.get()->data());
        err = channel->queueSecureInputBuffer(buffer, secure, key, iv, mode,
            pattern, subSamples, numSubSamples, &errorDetailMsg);
    }
    if (err != OK) {
        std::list<sp<AMessage>> errorList;
        msg->removeEntryByName("buffer");
        msg->setInt32("err", err);
        msg->setInt32("actionCode", ACTION_CODE_FATAL);
        msg->setString("errorDetail", errorDetailMsg);
        errorList.push_back(std::move(msg));
        mCallback->onDecryptError(errorList);
   }
   return err;
}

status_t CryptoAsync::attachEncryptedBufferAndQueue(sp<AMessage> & msg) {
    std::shared_ptr<BufferChannelBase> channel = mBufferChannel.lock();
    status_t err = OK;
    sp<RefBase> obj;
    sp<RefBase> mem_obj;
    sp<hardware::HidlMemory> memory;
    size_t numSubSamples = 0;
    int32_t secure = 0;
    size_t offset;
    size_t size;
    CryptoPlugin::Mode mode;
    CryptoPlugin::Pattern pattern;
    sp<ABuffer> keyBuffer;
    sp<ABuffer> ivBuffer;
    sp<ABuffer> subSamplesBuffer;
    msg->findInt32("encryptBlocks", (int32_t*)&pattern.mEncryptBlocks);
    msg->findInt32("skipBlocks", (int32_t*)&pattern.mSkipBlocks);
    msg->findBuffer("key", &keyBuffer);
    msg->findBuffer("iv", &ivBuffer);
    msg->findBuffer("subSamples", &subSamplesBuffer);
    msg->findInt32("secure", &secure);
    msg->findSize("numSubSamples", &numSubSamples);
    msg->findObject("buffer", &obj);
    msg->findInt32("mode", (int32_t*)&mode);
    CHECK(msg->findObject("memory", &mem_obj));
    CHECK(msg->findSize("offset", (size_t*)&offset));
    AString errorDetailMsg;
    // get key info
    const uint8_t * key = keyBuffer.get() != nullptr ? keyBuffer.get()->data() : nullptr;
    // get iv info
    const uint8_t * iv = ivBuffer.get() != nullptr ? ivBuffer.get()->data() : nullptr;

    const CryptoPlugin::SubSample * subSamples =
     (CryptoPlugin::SubSample *)(subSamplesBuffer.get()->data());

    // get MediaCodecBuffer
    sp<MediaCodecBuffer> buffer = static_cast<MediaCodecBuffer *>(obj.get());

    // get HidlMemory
    memory = static_cast<MediaCodec::WrapperObject<sp<hardware::HidlMemory>> *>
        (mem_obj.get())->value;

    // attach buffer
    err = channel->attachEncryptedBuffer(
        memory, secure, key, iv, mode, pattern,
        offset, subSamples, numSubSamples, buffer, &errorDetailMsg);

    // a generic error
    auto handleError = [this, &err, &msg]() {
        std::list<sp<AMessage>> errorList;
        msg->removeEntryByName("buffer");
        msg->setInt32("err", err);
        msg->setInt32("actionCode", ACTION_CODE_FATAL);
        errorList.push_back(std::move(msg));
        mCallback->onDecryptError(errorList);
    };
    if (err != OK) {
        handleError();
        return err;
     }
     offset = buffer->offset();
     size = buffer->size();

    if (offset + size > buffer->capacity()) {
        err = -ENOSYS;
        handleError();
        return err;
    }
    buffer->setRange(offset, size);
    err = channel->queueInputBuffer(buffer);
    if (err != OK) {
        handleError();
        return err;
    }
   return err;
}

void CryptoAsync::onMessageReceived(const sp<AMessage> & msg) {
    status_t err = OK;
    auto getCurrentAndNextTask =
        [this](sp<AMessage> * const  current, uint32_t & nextTask) -> status_t {
        sp<AMessage> obj;
        Mutexed<std::list<sp<AMessage>>>::Locked pendingBuffers(mPendingBuffers);
        if ((pendingBuffers->size() == 0) || (mState != kCryptoAsyncActive)) {
           return -ENOMSG;
        }
        *current = std::move(*(pendingBuffers->begin()));
        pendingBuffers->pop_front();
        //Try to see if we will be able to process next buffer
        while((nextTask == kWhatDoNothing) && pendingBuffers->size() > 0)
        {
            sp<AMessage> & nextBuffer = pendingBuffers->front();
            if (nextBuffer == nullptr) {
                pendingBuffers->pop_front();
                continue;
            }
            nextTask = kWhatDecrypt;
        }
        return OK;
    };
    switch(msg->what()) {
        case kWhatDecrypt:
        {
            sp<AMessage> thisMsg;
            uint32_t nextTask = kWhatDoNothing;
            if(OK != getCurrentAndNextTask(&thisMsg, nextTask)) {
                return;
            }
            if (thisMsg != nullptr) {
                int32_t action;
                err = OK;
                CHECK(thisMsg->findInt32("action", &action));
                switch(action) {
                    case kActionDecrypt:
                    {
                        err = decryptAndQueue(thisMsg);
                        break;
                    }

                    case kActionAttachEncryptedBuffer:
                    {
                        err = attachEncryptedBufferAndQueue(thisMsg);
                        break;
                    }

                    default:
                    {
                        ALOGE("Unrecognized action in decrypt");
                    }
                }
                if (err != OK) {
                    Mutexed<std::list<sp<AMessage>>>::Locked pendingBuffers(mPendingBuffers);
                    mState = kCryptoAsyncError;
                }
            }
            // we won't take  next buffers if buffer caused
            // an error. We want the caller to deal with the error first
            // Expected behahiour is that the caller acknowledge the error
            // with a call to stop() which clear the queues.
            // Then move forward with processing of next set of buffers.
            if (mState == kCryptoAsyncActive && nextTask != kWhatDoNothing) {
                sp<AMessage> nextMsg = new AMessage(nextTask,this);
                nextMsg->post();
            }
            break;
        }

        case kWhatStop:
        {
            typedef std::list<sp<AMessage>> ReturnListType;
            ReturnListType * returnList = nullptr;
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));
            sp<AMessage> response = new AMessage;
            msg->findPointer("remaining", (void**)(&returnList));
            Mutexed<std::list<sp<AMessage>>>::Locked pendingBuffers(mPendingBuffers);
            if (returnList) {
                returnList->clear();
                returnList->splice(returnList->end(), std::move(*pendingBuffers));
            }
            pendingBuffers->clear();
            mState = kCryptoAsyncActive;
            response->setInt32("err", OK);
            response->postReply(replyID);

            break;
        }

        default:
        {
            status_t err = OK;
            //TODO: do something with error here.
            (void)err;
            break;
        }
    }
}

}  // namespace android
