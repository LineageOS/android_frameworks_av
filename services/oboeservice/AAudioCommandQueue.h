/*
 * Copyright (C) 2021 The Android Open Source Project
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

#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>

#include <aaudio/AAudio.h>
#include <android-base/thread_annotations.h>

namespace aaudio {

using aaudio_command_opcode = int32_t;

class AAudioCommandParam {
public:
    AAudioCommandParam() = default;
    virtual ~AAudioCommandParam() = default;
};

class AAudioCommand {
public:
    explicit AAudioCommand(
            aaudio_command_opcode opCode, std::shared_ptr<AAudioCommandParam> param = nullptr,
            bool waitForReply = false, int64_t timeoutNanos = 0)
            : operationCode(opCode), parameter(std::move(param)), isWaitingForReply(waitForReply),
              timeoutNanoseconds(timeoutNanos) { }
    virtual ~AAudioCommand() = default;

    std::mutex lock;
    std::condition_variable conditionVariable;

    const aaudio_command_opcode operationCode;
    std::shared_ptr<AAudioCommandParam> parameter;
    bool isWaitingForReply GUARDED_BY(lock);
    const int64_t timeoutNanoseconds;
    aaudio_result_t result GUARDED_BY(lock) = AAUDIO_OK;
};

class AAudioCommandQueue {
public:
    AAudioCommandQueue() = default;
    ~AAudioCommandQueue() = default;

    /**
     * Send a command to the command queue. The return will be waiting for a specified timeout
     * period indicated by the command if it is required.
     *
     * @param command the command to send to the command queue.
     * @return the result of sending the command or the result of executing the command if command
     *         need to wait for a reply. If timeout happens, AAUDIO_ERROR_TIMEOUT will be returned.
     */
    aaudio_result_t sendCommand(const std::shared_ptr<AAudioCommand>& command);

    /**
     * Wait for next available command OR until the timeout is expired.
     *
     * @param timeoutNanos the maximum time to wait for next command (0 means return immediately in
     *                     any case), negative to wait forever.
     * @return the next available command if any or a nullptr when there is none.
     */
    std::shared_ptr<AAudioCommand> waitForCommand(int64_t timeoutNanos = -1);

    /**
     * Start waiting for commands. Commands can only be pushed into the command queue after it
     * starts waiting.
     */
    void startWaiting();

    /**
     * Force stop waiting for next command
     */
    void stopWaiting();

private:
    std::mutex mLock;
    std::condition_variable mWaitWorkCond;

    std::queue<std::shared_ptr<AAudioCommand>> mCommands GUARDED_BY(mLock);
    bool mRunning GUARDED_BY(mLock) = false;
};

} // namespace aaudio