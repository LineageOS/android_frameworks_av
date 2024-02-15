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

#ifndef CRYPTO_ASYNC_H_
#define CRYPTO_ASYNC_H_

#include <media/stagefright/CodecBase.h>
#include <media/stagefright/foundation/Mutexed.h>
namespace android {

class CryptoAsync: public AHandler {
public:

    class CryptoAsyncCallback {
    public:

        virtual ~CryptoAsyncCallback() = default;

        /*
         * Callback with result for queuing the decrypted buffer to the
         * underlying codec. Cannot block this function
         */
        virtual void onDecryptComplete(const sp<AMessage>& result) = 0;

        /*
         * Callback with error information while decryption. Cannot block
         * this call. The return should contain the error information
         * and the buffer the caused the error.
         */
        virtual void onDecryptError(const std::list<sp<AMessage>>& errorMsg) = 0;
    };

    // Ideally we should be returning the output of the decryption in
    // onDecryptComple() calback and let the next module take over the
    // rest of the processing. In the current state, the next step will
    // be to queue the output the codec which is done using BufferChannel

    // In order to prevent thread hop to just do that, we have created
    // a dependency on BufferChannel here to queue the buffer to the codec
    // immediately after decryption.
    CryptoAsync(std::weak_ptr<BufferChannelBase> bufferChannel)
        :mState(kCryptoAsyncActive) {
        mBufferChannel = std::move(bufferChannel);
    }

    // Destructor
    virtual ~CryptoAsync();

    inline void setCallback(std::unique_ptr<CryptoAsyncCallback>&& callback) {
        mCallback = std::move(callback);
    }

    // Call this function to decrypt the buffer in the message.
    status_t decrypt(sp<AMessage>& msg);

    // This function stops further processing in the thread and returns
    // with any unprocessed buffers from the queue.
    // We can use this method in case of flush or clearing the queue
    // upon error. When the processing hits an error, the self processing
    // in this looper stops and in-fact., there is a need to clear (call stop())
    // for the queue to become operational again. Also acts like a rest.
    void stop(std::list<sp<AMessage>> * const buffers = nullptr);

    // Describes two actions for decrypt();
    // kActionDecrypt - decrypts the buffer and queues to codec
    // kActionAttachEncryptedBuffer - decrypts and attaches the buffer
    //                               and queues to the codec.
    // TODO: kActionAttachEncryptedBuffer is meant to work with
    // BLOCK_MODEL which is not yet implemented.
    enum : uint32_t {
        // decryption types
        kActionDecrypt                 = (1 <<  0),
        kActionAttachEncryptedBuffer   = (1 <<  1)
    };

    // This struct is meant to copy the mapped contents from the original info.
    struct CryptoAsyncInfo : public CodecCryptoInfo {
        public:
            explicit CryptoAsyncInfo(const std::unique_ptr<CodecCryptoInfo> &info);
            virtual ~CryptoAsyncInfo() = default;
        protected:
            // all backup buffers for the base object.
            sp<ABuffer> mKeyBuffer;
            sp<ABuffer> mIvBuffer;
            sp<ABuffer> mSubSamplesBuffer;
    };
protected:

    // Message types for the looper
    enum : uint32_t {
        // used with decrypt()
        // Exact decryption type as described by the above enum
        // decides what "action" to take. The "action" should be
        // part of this message
        kWhatDecrypt         = 1,
        // used with stop()
        kWhatStop            = 2,
        // place holder
        kWhatDoNothing       = 10
    };

    // Defines the staste of this thread.
    typedef enum : uint32_t {
        // kCryptoAsyncActive as long as we have not encountered
        // any errors during processing. Any errors will
        // put the state to error and the thread now refuses to
        // do further processing until the error state is cleared
        // with a call to stop()

        kCryptoAsyncActive  = (0 <<  0),
        // state of the looper when encountered with error during
        // processing
        kCryptoAsyncError   = (1 <<  8)
    } CryptoAsyncState;

    // Implements kActionDecrypt
    status_t decryptAndQueue(sp<AMessage>& msg);

    // Implements kActionAttachEncryptedBuffer
    status_t attachEncryptedBufferAndQueue(sp<AMessage>& msg);

    // Implements the Looper
    void onMessageReceived(const sp<AMessage>& msg) override;

    std::unique_ptr<CryptoAsyncCallback> mCallback;
private:

    CryptoAsyncState mState;

    // Queue holding any pending buffers
    Mutexed<std::list<sp<AMessage>>> mPendingBuffers;

    std::weak_ptr<BufferChannelBase> mBufferChannel;
};

}  // namespace android

#endif  // CRYPTO_ASYNC_H_
