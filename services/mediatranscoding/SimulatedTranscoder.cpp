/*
 * Copyright (C) 2020 The Android Open Source Project
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
#define LOG_TAG "SimulatedTranscoder"
#include "SimulatedTranscoder.h"

#include <utils/Log.h>

#include <thread>

namespace android {

//static
const char* SimulatedTranscoder::toString(Event::Type type) {
    switch (type) {
    case Event::Start:
        return "Start";
    case Event::Pause:
        return "Pause";
    case Event::Resume:
        return "Resume";
    case Event::Stop:
        return "Stop";
    case Event::Finished:
        return "Finished";
    case Event::Failed:
        return "Failed";
    case Event::Abandon:
        return "Abandon";
    default:
        break;
    }
    return "(unknown)";
}

SimulatedTranscoder::SimulatedTranscoder(const std::shared_ptr<TranscoderCallbackInterface>& cb)
      : mCallback(cb), mLooperReady(false) {
    ALOGV("SimulatedTranscoder CTOR: %p", this);
}

SimulatedTranscoder::~SimulatedTranscoder() {
    ALOGV("SimulatedTranscoder DTOR: %p", this);
}

void SimulatedTranscoder::start(
        ClientIdType clientId, SessionIdType sessionId, const TranscodingRequestParcel& request,
        uid_t /*callingUid*/,
        const std::shared_ptr<ITranscodingClientCallback>& /*clientCallback*/) {
    {
        auto lock = std::scoped_lock(mLock);
        int64_t processingTimeUs = kSessionDurationUs;
        if (request.testConfig.has_value() && request.testConfig->processingTotalTimeMs > 0) {
            processingTimeUs = request.testConfig->processingTotalTimeMs * 1000;
        }
        ALOGI("%s: session {%lld, %d}: processingTimeUs: %lld", __FUNCTION__, (long long)clientId,
              sessionId, (long long)processingTimeUs);
        SessionKeyType key = std::make_pair(clientId, sessionId);
        mRemainingTimeMap.emplace(key, processingTimeUs);
    }

    queueEvent(Event::Start, clientId, sessionId, [=] {
        auto callback = mCallback.lock();
        if (callback != nullptr) {
            callback->onStarted(clientId, sessionId);
        }
    });
}

void SimulatedTranscoder::pause(ClientIdType clientId, SessionIdType sessionId) {
    queueEvent(Event::Pause, clientId, sessionId, [=] {
        auto callback = mCallback.lock();
        if (callback != nullptr) {
            callback->onPaused(clientId, sessionId);
        }
    });
}

void SimulatedTranscoder::resume(
        ClientIdType clientId, SessionIdType sessionId, const TranscodingRequestParcel& /*request*/,
        uid_t /*callingUid*/,
        const std::shared_ptr<ITranscodingClientCallback>& /*clientCallback*/) {
    queueEvent(Event::Resume, clientId, sessionId, [=] {
        auto callback = mCallback.lock();
        if (callback != nullptr) {
            callback->onResumed(clientId, sessionId);
        }
    });
}

void SimulatedTranscoder::stop(ClientIdType clientId, SessionIdType sessionId, bool abandon) {
    queueEvent(Event::Stop, clientId, sessionId, nullptr);

    if (abandon) {
        queueEvent(Event::Abandon, 0, 0, nullptr);
    }
}

void SimulatedTranscoder::queueEvent(Event::Type type, ClientIdType clientId,
                                     SessionIdType sessionId, std::function<void()> runnable) {
    ALOGV("%s: session {%lld, %d}: %s", __FUNCTION__, (long long)clientId, sessionId,
          toString(type));

    auto lock = std::scoped_lock(mLock);

    if (!mLooperReady) {
        // A shared_ptr to ourselves is given to the thread's stack, so that SimulatedTranscoder
        // object doesn't go away until the thread exits. When a watchdog timeout happens, this
        // allows the session controller to release its reference to the TranscoderWrapper object
        // without blocking on the thread exits.
        std::thread([owner = shared_from_this()]() { owner->threadLoop(); }).detach();
        mLooperReady = true;
    }

    mQueue.push_back({type, clientId, sessionId, runnable});
    mCondition.notify_one();
}

void SimulatedTranscoder::threadLoop() {
    bool running = false;
    std::chrono::steady_clock::time_point lastRunningTime;
    Event lastRunningEvent;

    std::unique_lock<std::mutex> lock(mLock);
    // SimulatedTranscoder currently lives in the transcoding service, as long as
    // MediaTranscodingService itself.
    while (true) {
        // Wait for the next event.
        while (mQueue.empty()) {
            if (!running) {
                mCondition.wait(lock);
                continue;
            }
            // If running, wait for the remaining life of this session. Report finish if timed out.
            SessionKeyType key =
                    std::make_pair(lastRunningEvent.clientId, lastRunningEvent.sessionId);
            std::cv_status status = mCondition.wait_for(lock, mRemainingTimeMap[key]);
            if (status == std::cv_status::timeout) {
                running = false;

                auto callback = mCallback.lock();
                if (callback != nullptr) {
                    mRemainingTimeMap.erase(key);

                    lock.unlock();
                    callback->onFinish(lastRunningEvent.clientId, lastRunningEvent.sessionId);
                    lock.lock();
                }
            } else {
                // Advance last running time and remaining time. This is needed to guard
                // against bad events (which will be ignored) or spurious wakeups, in that
                // case we don't want to wait for the same time again.
                auto now = std::chrono::steady_clock::now();
                mRemainingTimeMap[key] -= std::chrono::duration_cast<std::chrono::microseconds>(
                        now - lastRunningTime);
                lastRunningTime = now;
            }
        }

        // Handle the events, adjust state and send updates to client accordingly.
        Event event = *mQueue.begin();
        mQueue.pop_front();

        ALOGD("%s: session {%lld, %d}: %s", __FUNCTION__, (long long)event.clientId,
              event.sessionId, toString(event.type));

        if (event.type == Event::Abandon) {
            break;
        }

        SessionKeyType key = std::make_pair(event.clientId, event.sessionId);
        if (!running && (event.type == Event::Start || event.type == Event::Resume)) {
            running = true;
            lastRunningTime = std::chrono::steady_clock::now();
            lastRunningEvent = event;
            ALOGV("%s: session {%lld, %d}: remaining time: %lld", __FUNCTION__,
                  (long long)event.clientId, event.sessionId,
                  (long long)mRemainingTimeMap[key].count());

        } else if (running && (event.type == Event::Pause || event.type == Event::Stop)) {
            running = false;
            if (event.type == Event::Stop) {
                mRemainingTimeMap.erase(key);
            } else {
                mRemainingTimeMap[key] -= std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now() - lastRunningTime);
            }
        } else {
            ALOGW("%s: discarding bad event: session {%lld, %d}: %s", __FUNCTION__,
                  (long long)event.clientId, event.sessionId, toString(event.type));
            continue;
        }

        if (event.runnable != nullptr) {
            lock.unlock();
            event.runnable();
            lock.lock();
        }
    }
}

}  // namespace android
