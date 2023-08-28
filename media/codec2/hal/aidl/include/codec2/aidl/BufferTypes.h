/*
 * Copyright 2018 The Android Open Source Project
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

#ifndef CODEC2_AIDL_BUFFER_TYPES_H
#define CODEC2_AIDL_BUFFER_TYPES_H

#include <codec2/common/BufferTypes.h>

#include <aidl/android/hardware/media/bufferpool2/BufferStatusMessage.h>
#include <aidl/android/hardware/media/bufferpool2/IClientManager.h>
#include <aidl/android/hardware/media/bufferpool2/ResultStatus.h>
#include <aidl/android/hardware/media/c2/WorkBundle.h>

#include <bufferpool2/BufferPoolTypes.h>
#include <bufferpool2/ClientManager.h>


namespace aidl {
namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace utils {

namespace bufferpool2 = ::aidl::android::hardware::media::bufferpool2;

using namespace std::chrono_literals;

struct BufferPoolTypes {
    typedef bufferpool2::BufferPoolData BufferPoolData;
    typedef bufferpool2::ResultStatus ResultStatus;
    typedef bufferpool2::implementation::BufferPoolStatus BufferPoolStatus;
    typedef bufferpool2::BufferStatusMessage BufferStatusMessage;
};

// Default implementation of BufferPoolSender.
//
// To use DefaultBufferPoolSender, the IClientManager instance of the receiving
// process must be set before send() can operate. DefaultBufferPoolSender will
// hold a strong reference to the IClientManager instance and use it to call
// IClientManager::registerSender() to establish the bufferpool connection when
// send() is called.
struct DefaultBufferPoolSender : ::android::BufferPoolSender<BufferPoolTypes> {
    typedef bufferpool2::implementation::ClientManager ClientManager;
    typedef bufferpool2::IClientManager IClientManager;

    // Set the IClientManager instance of the receiving process and the refresh
    // interval for the connection. The default interval is 4.5 seconds, which
    // is slightly shorter than the amount of time the bufferpool will keep an
    // inactive connection for.
    DefaultBufferPoolSender(
            const std::shared_ptr<IClientManager>& receiverManager = nullptr,
            std::chrono::steady_clock::duration refreshInterval = 4500ms);

    // Set the IClientManager instance of the receiving process and the refresh
    // interval for the connection. The default interval is 4.5 seconds, which
    // is slightly shorter than the amount of time the bufferpool will keep an
    // inactive connection for.
    void setReceiver(
            const std::shared_ptr<IClientManager>& receiverManager,
            std::chrono::steady_clock::duration refreshInterval = 4500ms);

    // Implementation of BufferPoolSender::send(). send() will establish a
    // bufferpool connection if needed, then send the bufferpool data over to
    // the receiving process.
    BufferPoolStatus send(
            const std::shared_ptr<BufferPoolData>& bpData,
            BufferStatusMessage* bpMessage) override;

private:
    std::mutex mMutex;
    std::shared_ptr<ClientManager> mSenderManager;
    std::shared_ptr<IClientManager> mReceiverManager;
    std::chrono::steady_clock::duration mRefreshInterval;

    struct Connection {
        int64_t receiverConnectionId;
        std::chrono::steady_clock::time_point lastSent;
        Connection(int64_t receiverConnectionId,
                   std::chrono::steady_clock::time_point lastSent)
              : receiverConnectionId(receiverConnectionId),
                lastSent(lastSent) {
        }
    };

    // Map of connections.
    //
    // The key is the connection id. One sender-receiver pair may have multiple
    // connections.
    std::map<int64_t, Connection> mConnections;
};

// std::list<std::unique_ptr<C2Work>> -> WorkBundle
// Note: If bufferpool will be used, bpSender must not be null.
bool ToAidl(
        WorkBundle* d,
        const std::list<std::unique_ptr<C2Work>>& s,
        ::android::BufferPoolSender<BufferPoolTypes>* bpSender = nullptr);

// WorkBundle -> std::list<std::unique_ptr<C2Work>>
bool FromAidl(
        std::list<std::unique_ptr<C2Work>>* d,
        const WorkBundle& s);

/**
 * Converts a BufferPool status value to c2_status_t.
 * \param BufferPool status
 * \return Corresponding c2_status_t
 */
c2_status_t toC2Status(BufferPoolTypes::BufferPoolStatus rs);

}  // namespace utils
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android
}  // namespace aidl

#endif  // CODEC2_AIDL_BUFFER_TYPES_H
