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

#ifndef CODEC2_COMMON_BUFFER_POOL_SENDER_H
#define CODEC2_COMMON_BUFFER_POOL_SENDER_H

#include <memory>

namespace android {

// Template class to be used in
// objcpy(std::list<std::unique_ptr<C2Work>> -> WorkBundle).
template <typename BufferPoolTypes>
struct BufferPoolSender {
    // BufferPoolTypes should define the following types:
    typedef typename BufferPoolTypes::BufferPoolData        BufferPoolData;
    typedef typename BufferPoolTypes::ResultStatus          ResultStatus;
    typedef typename BufferPoolTypes::BufferPoolStatus      BufferPoolStatus;
    typedef typename BufferPoolTypes::BufferStatusMessage   BufferStatusMessage;

    /**
     * Send bpData and return BufferStatusMessage that can be supplied to
     * IClientManager::receive() in the receiving process.
     *
     * This function will be called from within the function
     * objcpy(std::list<std::unique_ptr<C2Work>> -> WorkBundle).
     *
     * \param[in] bpData BufferPoolData identifying the buffer to send.
     * \param[out] bpMessage BufferStatusMessage of the transaction. Information
     *    inside \p bpMessage should be passed to the receiving process by some
     *    other means so it can call receive() properly.
     * \return ResultStatus value that determines the success of the operation.
     *    (See the possible values of ResultStatus in
     *    hardware/interfaces/media/bufferpool/2.0/types.hal.)
     */
    virtual BufferPoolStatus send(
            const std::shared_ptr<BufferPoolData>& bpData,
            BufferStatusMessage* bpMessage) = 0;

    virtual ~BufferPoolSender() = default;
};

}  // namespace android

#endif  // CODEC2_COMMON_BUFFER_POOL_SENDER_H
