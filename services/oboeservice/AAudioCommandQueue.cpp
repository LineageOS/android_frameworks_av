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

#define LOG_TAG "AAudioCommandQueue"
//#define LOG_NDEBUG 0

#include <chrono>

#include <utils/Log.h>

#include "AAudioCommandQueue.h"

namespace aaudio {

aaudio_result_t AAudioCommandQueue::sendCommand(const std::shared_ptr<AAudioCommand>& command) {
    {
        std::scoped_lock<std::mutex> _l(mLock);
        if (!mRunning) {
            ALOGE("Tried to send command while it was not running");
            return AAUDIO_ERROR_INVALID_STATE;
        }
        mCommands.push(command);
        mWaitWorkCond.notify_one();
    }

    std::unique_lock _cl(command->lock);
    android::base::ScopedLockAssertion lockAssertion(command->lock);
    ALOGV("Sending command %d, wait for reply(%d) with timeout %jd",
           command->operationCode, command->isWaitingForReply, command->timeoutNanoseconds);
    // `mWaitForReply` is first initialized when the command is constructed. It will be flipped
    // when the command is completed.
    auto timeoutExpire = std::chrono::steady_clock::now()
            + std::chrono::nanoseconds(command->timeoutNanoseconds);
    while (command->isWaitingForReply) {
        if (command->conditionVariable.wait_until(_cl, timeoutExpire)
                == std::cv_status::timeout) {
            ALOGD("Command %d time out", command->operationCode);
            command->result = AAUDIO_ERROR_TIMEOUT;
            command->isWaitingForReply = false;
        }
    }
    ALOGV("Command %d sent with result as %d", command->operationCode, command->result);
    return command->result;
}

std::shared_ptr<AAudioCommand> AAudioCommandQueue::waitForCommand(int64_t timeoutNanos) {
    std::shared_ptr<AAudioCommand> command;
    {
        std::unique_lock _l(mLock);
        android::base::ScopedLockAssertion lockAssertion(mLock);
        if (timeoutNanos >= 0) {
            mWaitWorkCond.wait_for(_l, std::chrono::nanoseconds(timeoutNanos), [this]() {
                android::base::ScopedLockAssertion lockAssertion(mLock);
                return !mRunning || !mCommands.empty();
            });
        } else {
            mWaitWorkCond.wait(_l, [this]() {
                android::base::ScopedLockAssertion lockAssertion(mLock);
                return !mRunning || !mCommands.empty();
            });
        }
        if (!mCommands.empty() && mRunning) {
            command = mCommands.front();
            mCommands.pop();
        }
    }
    return command;
}

void AAudioCommandQueue::startWaiting() {
    std::scoped_lock<std::mutex> _l(mLock);
    mRunning = true;
}

void AAudioCommandQueue::stopWaiting() {
    std::scoped_lock<std::mutex> _l(mLock);
    mRunning = false;
    // Clear all commands in the queue as the command thread is stopped.
    while (!mCommands.empty()) {
        auto command = mCommands.front();
        mCommands.pop();
        std::scoped_lock<std::mutex> _cl(command->lock);
        // If the command is waiting for result, returns AAUDIO_ERROR_INVALID_STATE
        // as there is no thread waiting for the command.
        if (command->isWaitingForReply) {
            command->result = AAUDIO_ERROR_INVALID_STATE;
            command->isWaitingForReply = false;
            command->conditionVariable.notify_one();
        }
    }
    mWaitWorkCond.notify_one();
}

} // namespace aaudio