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
#define LOG_TAG "TranscodingSessionController"

#define VALIDATE_STATE 1

#include <inttypes.h>
#include <media/TranscodingSessionController.h>
#include <media/TranscodingUidPolicy.h>
#include <utils/Log.h>

#include <utility>

namespace android {

static_assert((SessionIdType)-1 < 0, "SessionIdType should be signed");

constexpr static uid_t OFFLINE_UID = -1;
constexpr static size_t kSessionHistoryMax = 100;

//static
String8 TranscodingSessionController::sessionToString(const SessionKeyType& sessionKey) {
    return String8::format("{client:%lld, session:%d}", (long long)sessionKey.first,
                           sessionKey.second);
}

//static
const char* TranscodingSessionController::sessionStateToString(const Session::State sessionState) {
    switch (sessionState) {
    case Session::State::NOT_STARTED:
        return "NOT_STARTED";
    case Session::State::RUNNING:
        return "RUNNING";
    case Session::State::PAUSED:
        return "PAUSED";
    case Session::State::FINISHED:
        return "FINISHED";
    case Session::State::CANCELED:
        return "CANCELED";
    case Session::State::ERROR:
        return "ERROR";
    default:
        break;
    }
    return "(unknown)";
}

TranscodingSessionController::TranscodingSessionController(
        const std::shared_ptr<TranscoderInterface>& transcoder,
        const std::shared_ptr<UidPolicyInterface>& uidPolicy,
        const std::shared_ptr<ResourcePolicyInterface>& resourcePolicy,
        const std::shared_ptr<ThermalPolicyInterface>& thermalPolicy)
      : mTranscoder(transcoder),
        mUidPolicy(uidPolicy),
        mResourcePolicy(resourcePolicy),
        mThermalPolicy(thermalPolicy),
        mCurrentSession(nullptr),
        mResourceLost(false) {
    // Only push empty offline queue initially. Realtime queues are added when requests come in.
    mUidSortedList.push_back(OFFLINE_UID);
    mOfflineUidIterator = mUidSortedList.begin();
    mSessionQueues.emplace(OFFLINE_UID, SessionQueueType());
    mUidPackageNames[OFFLINE_UID] = "(offline)";
    mThermalThrottling = thermalPolicy->getThrottlingStatus();
}

TranscodingSessionController::~TranscodingSessionController() {}

void TranscodingSessionController::dumpSession_l(const Session& session, String8& result,
                                                 bool closedSession) {
    const size_t SIZE = 256;
    char buffer[SIZE];
    const TranscodingRequestParcel& request = session.request;
    snprintf(buffer, SIZE, "      Session: %s, %s, %d%%\n", sessionToString(session.key).c_str(),
             sessionStateToString(session.getState()), session.lastProgress);
    result.append(buffer);
    snprintf(buffer, SIZE, "        pkg: %s\n", request.clientPackageName.c_str());
    result.append(buffer);
    snprintf(buffer, SIZE, "        src: %s\n", request.sourceFilePath.c_str());
    result.append(buffer);
    snprintf(buffer, SIZE, "        dst: %s\n", request.destinationFilePath.c_str());
    result.append(buffer);

    if (closedSession) {
        snprintf(buffer, SIZE,
                 "        waiting: %.1fs, running: %.1fs, paused: %.1fs, paused count: %d\n",
                 session.waitingTime.count() / 1000000.0f, session.runningTime.count() / 1000000.0f,
                 session.pausedTime.count() / 1000000.0f, session.pauseCount);
        result.append(buffer);
    }
}

void TranscodingSessionController::dumpAllSessions(int fd, const Vector<String16>& args __unused) {
    String8 result;

    const size_t SIZE = 256;
    char buffer[SIZE];
    std::scoped_lock lock{mLock};

    snprintf(buffer, SIZE, "\n========== Dumping live sessions queues =========\n");
    result.append(buffer);
    snprintf(buffer, SIZE, "  Total num of Sessions: %zu\n", mSessionMap.size());
    result.append(buffer);

    std::vector<int32_t> uids(mUidSortedList.begin(), mUidSortedList.end());

    for (int32_t i = 0; i < uids.size(); i++) {
        const uid_t uid = uids[i];

        if (mSessionQueues[uid].empty()) {
            continue;
        }
        snprintf(buffer, SIZE, "    uid: %d, pkg: %s\n", uid,
                 mUidPackageNames.count(uid) > 0 ? mUidPackageNames[uid].c_str() : "(unknown)");
        result.append(buffer);
        snprintf(buffer, SIZE, "      Num of sessions: %zu\n", mSessionQueues[uid].size());
        result.append(buffer);
        for (auto& sessionKey : mSessionQueues[uid]) {
            auto sessionIt = mSessionMap.find(sessionKey);
            if (sessionIt == mSessionMap.end()) {
                snprintf(buffer, SIZE, "Failed to look up Session %s  \n",
                         sessionToString(sessionKey).c_str());
                result.append(buffer);
                continue;
            }
            dumpSession_l(sessionIt->second, result);
        }
    }

    snprintf(buffer, SIZE, "\n========== Dumping past sessions =========\n");
    result.append(buffer);
    for (auto& session : mSessionHistory) {
        dumpSession_l(session, result, true /*closedSession*/);
    }

    write(fd, result.string(), result.size());
}

TranscodingSessionController::Session* TranscodingSessionController::getTopSession_l() {
    if (mSessionMap.empty()) {
        return nullptr;
    }
    uid_t topUid = *mUidSortedList.begin();
    SessionKeyType topSessionKey = *mSessionQueues[topUid].begin();
    return &mSessionMap[topSessionKey];
}

void TranscodingSessionController::Session::setState(Session::State newState) {
    if (state == newState) {
        return;
    }
    auto nowTime = std::chrono::system_clock::now();
    if (state != INVALID) {
        std::chrono::microseconds elapsedTime = (nowTime - stateEnterTime);
        switch (state) {
        case PAUSED:
            pausedTime = pausedTime + elapsedTime;
            break;
        case RUNNING:
            runningTime = runningTime + elapsedTime;
            break;
        case NOT_STARTED:
            waitingTime = waitingTime + elapsedTime;
            break;
        default:
            break;
        }
    }
    if (newState == PAUSED) {
        pauseCount++;
    }
    stateEnterTime = nowTime;
    state = newState;
}

void TranscodingSessionController::updateCurrentSession_l() {
    Session* topSession = getTopSession_l();
    Session* curSession = mCurrentSession;
    ALOGV("updateCurrentSession: topSession is %s, curSession is %s",
          topSession == nullptr ? "null" : sessionToString(topSession->key).c_str(),
          curSession == nullptr ? "null" : sessionToString(curSession->key).c_str());

    if (topSession == nullptr) {
        mCurrentSession = nullptr;
        return;
    }

    bool shouldBeRunning = !((mResourcePolicy != nullptr && mResourceLost) ||
                             (mThermalPolicy != nullptr && mThermalThrottling));
    // If we found a topSession that should be run, and it's not already running,
    // take some actions to ensure it's running.
    if (topSession != curSession ||
        (shouldBeRunning ^ (topSession->getState() == Session::RUNNING))) {
        // If current session is running, pause it first. Note this is true for either
        // cases: 1) If top session is changing, or 2) if top session is not changing but
        // the topSession's state is changing.
        if (curSession != nullptr && curSession->getState() == Session::RUNNING) {
            mTranscoder->pause(curSession->key.first, curSession->key.second);
            curSession->setState(Session::PAUSED);
        }
        // If we are not experiencing resource loss nor thermal throttling, we can start
        // or resume the topSession now.
        if (shouldBeRunning) {
            if (topSession->getState() == Session::NOT_STARTED) {
                mTranscoder->start(topSession->key.first, topSession->key.second,
                                   topSession->request, topSession->callback.lock());
            } else if (topSession->getState() == Session::PAUSED) {
                mTranscoder->resume(topSession->key.first, topSession->key.second,
                                    topSession->request, topSession->callback.lock());
            }
            topSession->setState(Session::RUNNING);
        }
    }
    mCurrentSession = topSession;
}

void TranscodingSessionController::removeSession_l(const SessionKeyType& sessionKey,
                                                   Session::State finalState) {
    ALOGV("%s: session %s", __FUNCTION__, sessionToString(sessionKey).c_str());

    if (mSessionMap.count(sessionKey) == 0) {
        ALOGE("session %s doesn't exist", sessionToString(sessionKey).c_str());
        return;
    }

    // Remove session from uid's queue.
    const uid_t uid = mSessionMap[sessionKey].uid;
    SessionQueueType& sessionQueue = mSessionQueues[uid];
    auto it = std::find(sessionQueue.begin(), sessionQueue.end(), sessionKey);
    if (it == sessionQueue.end()) {
        ALOGE("couldn't find session %s in queue for uid %d", sessionToString(sessionKey).c_str(),
              uid);
        return;
    }
    sessionQueue.erase(it);

    // If this is the last session in a real-time queue, remove this uid's queue.
    if (uid != OFFLINE_UID && sessionQueue.empty()) {
        mUidSortedList.remove(uid);
        mSessionQueues.erase(uid);
        mUidPolicy->unregisterMonitorUid(uid);

        std::unordered_set<uid_t> topUids = mUidPolicy->getTopUids();
        moveUidsToTop_l(topUids, false /*preserveTopUid*/);
    }

    // Clear current session.
    if (mCurrentSession == &mSessionMap[sessionKey]) {
        mCurrentSession = nullptr;
    }

    mSessionMap[sessionKey].setState(finalState);
    mSessionHistory.push_back(mSessionMap[sessionKey]);
    if (mSessionHistory.size() > kSessionHistoryMax) {
        mSessionHistory.erase(mSessionHistory.begin());
    }

    // Remove session from session map.
    mSessionMap.erase(sessionKey);
}

/**
 * Moves the set of uids to the front of mUidSortedList (which is used to pick
 * the next session to run).
 *
 * This is called when 1) we received a onTopUidsChanged() callback from UidPolicy,
 * or 2) we removed the session queue for a uid because it becomes empty.
 *
 * In case of 1), if there are multiple uids in the set, and the current front
 * uid in mUidSortedList is still in the set, we try to keep that uid at front
 * so that current session run is not interrupted. (This is not a concern for case 2)
 * because the queue for a uid was just removed entirely.)
 */
void TranscodingSessionController::moveUidsToTop_l(const std::unordered_set<uid_t>& uids,
                                                   bool preserveTopUid) {
    // If uid set is empty, nothing to do. Do not change the queue status.
    if (uids.empty()) {
        return;
    }

    // Save the current top uid.
    uid_t curTopUid = *mUidSortedList.begin();
    bool pushCurTopToFront = false;
    int32_t numUidsMoved = 0;

    // Go through the sorted uid list once, and move the ones in top set to front.
    for (auto it = mUidSortedList.begin(); it != mUidSortedList.end();) {
        uid_t uid = *it;

        if (uid != OFFLINE_UID && uids.count(uid) > 0) {
            it = mUidSortedList.erase(it);

            // If this is the top we're preserving, don't push it here, push
            // it after the for-loop.
            if (uid == curTopUid && preserveTopUid) {
                pushCurTopToFront = true;
            } else {
                mUidSortedList.push_front(uid);
            }

            // If we found all uids in the set, break out.
            if (++numUidsMoved == uids.size()) {
                break;
            }
        } else {
            ++it;
        }
    }

    if (pushCurTopToFront) {
        mUidSortedList.push_front(curTopUid);
    }
}

bool TranscodingSessionController::submit(
        ClientIdType clientId, SessionIdType sessionId, uid_t uid,
        const TranscodingRequestParcel& request,
        const std::weak_ptr<ITranscodingClientCallback>& callback) {
    SessionKeyType sessionKey = std::make_pair(clientId, sessionId);

    ALOGV("%s: session %s, uid %d, prioirty %d", __FUNCTION__, sessionToString(sessionKey).c_str(),
          uid, (int32_t)request.priority);

    std::scoped_lock lock{mLock};

    if (mSessionMap.count(sessionKey) > 0) {
        ALOGE("session %s already exists", sessionToString(sessionKey).c_str());
        return false;
    }

    // Add the uid package name to the store of package names we already know.
    if (mUidPackageNames.count(uid) == 0) {
        mUidPackageNames.emplace(uid, request.clientPackageName);
    }

    // TODO(chz): only support offline vs real-time for now. All kUnspecified sessions
    // go to offline queue.
    if (request.priority == TranscodingSessionPriority::kUnspecified) {
        uid = OFFLINE_UID;
    }

    // Add session to session map.
    mSessionMap[sessionKey].key = sessionKey;
    mSessionMap[sessionKey].uid = uid;
    mSessionMap[sessionKey].lastProgress = 0;
    mSessionMap[sessionKey].pauseCount = 0;
    mSessionMap[sessionKey].request = request;
    mSessionMap[sessionKey].callback = callback;
    mSessionMap[sessionKey].setState(Session::NOT_STARTED);

    // If it's an offline session, the queue was already added in constructor.
    // If it's a real-time sessions, check if a queue is already present for the uid,
    // and add a new queue if needed.
    if (uid != OFFLINE_UID) {
        if (mSessionQueues.count(uid) == 0) {
            mUidPolicy->registerMonitorUid(uid);
            if (mUidPolicy->isUidOnTop(uid)) {
                mUidSortedList.push_front(uid);
            } else {
                // Shouldn't be submitting real-time requests from non-top app,
                // put it in front of the offline queue.
                mUidSortedList.insert(mOfflineUidIterator, uid);
            }
        } else if (uid != *mUidSortedList.begin()) {
            if (mUidPolicy->isUidOnTop(uid)) {
                mUidSortedList.remove(uid);
                mUidSortedList.push_front(uid);
            }
        }
    }
    // Append this session to the uid's queue.
    mSessionQueues[uid].push_back(sessionKey);

    updateCurrentSession_l();

    validateState_l();
    return true;
}

bool TranscodingSessionController::cancel(ClientIdType clientId, SessionIdType sessionId) {
    SessionKeyType sessionKey = std::make_pair(clientId, sessionId);

    ALOGV("%s: session %s", __FUNCTION__, sessionToString(sessionKey).c_str());

    std::list<SessionKeyType> sessionsToRemove;

    std::scoped_lock lock{mLock};

    if (sessionId < 0) {
        for (auto it = mSessionMap.begin(); it != mSessionMap.end(); ++it) {
            if (it->first.first == clientId && it->second.uid != OFFLINE_UID) {
                sessionsToRemove.push_back(it->first);
            }
        }
    } else {
        if (mSessionMap.count(sessionKey) == 0) {
            ALOGE("session %s doesn't exist", sessionToString(sessionKey).c_str());
            return false;
        }
        sessionsToRemove.push_back(sessionKey);
    }

    for (auto it = sessionsToRemove.begin(); it != sessionsToRemove.end(); ++it) {
        // If the session has ever been started, stop it now.
        // Note that stop() is needed even if the session is currently paused. This instructs
        // the transcoder to discard any states for the session, otherwise the states may
        // never be discarded.
        if (mSessionMap[*it].getState() != Session::NOT_STARTED) {
            mTranscoder->stop(it->first, it->second);
        }

        // Remove the session.
        removeSession_l(*it, Session::CANCELED);
    }

    // Start next session.
    updateCurrentSession_l();

    validateState_l();
    return true;
}

bool TranscodingSessionController::getSession(ClientIdType clientId, SessionIdType sessionId,
                                              TranscodingRequestParcel* request) {
    SessionKeyType sessionKey = std::make_pair(clientId, sessionId);

    std::scoped_lock lock{mLock};

    if (mSessionMap.count(sessionKey) == 0) {
        ALOGE("session %s doesn't exist", sessionToString(sessionKey).c_str());
        return false;
    }

    *(TranscodingRequest*)request = mSessionMap[sessionKey].request;
    return true;
}

void TranscodingSessionController::notifyClient(ClientIdType clientId, SessionIdType sessionId,
                                                const char* reason,
                                                std::function<void(const SessionKeyType&)> func) {
    SessionKeyType sessionKey = std::make_pair(clientId, sessionId);

    std::scoped_lock lock{mLock};

    if (mSessionMap.count(sessionKey) == 0) {
        ALOGW("%s: ignoring %s for session %s that doesn't exist", __FUNCTION__, reason,
              sessionToString(sessionKey).c_str());
        return;
    }

    // Only ignore if session was never started. In particular, propagate the status
    // to client if the session is paused. Transcoder could have posted finish when
    // we're pausing it, and the finish arrived after we changed current session.
    if (mSessionMap[sessionKey].getState() == Session::NOT_STARTED) {
        ALOGW("%s: ignoring %s for session %s that was never started", __FUNCTION__, reason,
              sessionToString(sessionKey).c_str());
        return;
    }

    ALOGV("%s: session %s %s", __FUNCTION__, sessionToString(sessionKey).c_str(), reason);
    func(sessionKey);
}

void TranscodingSessionController::onStarted(ClientIdType clientId, SessionIdType sessionId) {
    notifyClient(clientId, sessionId, "started", [=](const SessionKeyType& sessionKey) {
        auto callback = mSessionMap[sessionKey].callback.lock();
        if (callback != nullptr) {
            callback->onTranscodingStarted(sessionId);
        }
    });
}

void TranscodingSessionController::onPaused(ClientIdType clientId, SessionIdType sessionId) {
    notifyClient(clientId, sessionId, "paused", [=](const SessionKeyType& sessionKey) {
        auto callback = mSessionMap[sessionKey].callback.lock();
        if (callback != nullptr) {
            callback->onTranscodingPaused(sessionId);
        }
    });
}

void TranscodingSessionController::onResumed(ClientIdType clientId, SessionIdType sessionId) {
    notifyClient(clientId, sessionId, "resumed", [=](const SessionKeyType& sessionKey) {
        auto callback = mSessionMap[sessionKey].callback.lock();
        if (callback != nullptr) {
            callback->onTranscodingResumed(sessionId);
        }
    });
}

void TranscodingSessionController::onFinish(ClientIdType clientId, SessionIdType sessionId) {
    notifyClient(clientId, sessionId, "finish", [=](const SessionKeyType& sessionKey) {
        {
            auto clientCallback = mSessionMap[sessionKey].callback.lock();
            if (clientCallback != nullptr) {
                clientCallback->onTranscodingFinished(
                        sessionId, TranscodingResultParcel({sessionId, -1 /*actualBitrateBps*/,
                                                            std::nullopt /*sessionStats*/}));
            }
        }

        // Remove the session.
        removeSession_l(sessionKey, Session::FINISHED);

        // Start next session.
        updateCurrentSession_l();

        validateState_l();
    });
}

void TranscodingSessionController::onError(ClientIdType clientId, SessionIdType sessionId,
                                           TranscodingErrorCode err) {
    notifyClient(clientId, sessionId, "error", [=](const SessionKeyType& sessionKey) {
        {
            auto clientCallback = mSessionMap[sessionKey].callback.lock();
            if (clientCallback != nullptr) {
                clientCallback->onTranscodingFailed(sessionId, err);
            }
        }

        // Remove the session.
        removeSession_l(sessionKey, Session::ERROR);

        // Start next session.
        updateCurrentSession_l();

        validateState_l();
    });
}

void TranscodingSessionController::onProgressUpdate(ClientIdType clientId, SessionIdType sessionId,
                                                    int32_t progress) {
    notifyClient(clientId, sessionId, "progress", [=](const SessionKeyType& sessionKey) {
        auto callback = mSessionMap[sessionKey].callback.lock();
        if (callback != nullptr) {
            callback->onProgressUpdate(sessionId, progress);
        }
        mSessionMap[sessionKey].lastProgress = progress;
    });
}

void TranscodingSessionController::onResourceLost(ClientIdType clientId, SessionIdType sessionId) {
    ALOGI("%s", __FUNCTION__);

    notifyClient(clientId, sessionId, "resource_lost", [=](const SessionKeyType& sessionKey) {
        if (mResourceLost) {
            return;
        }

        Session* resourceLostSession = &mSessionMap[sessionKey];
        if (resourceLostSession->getState() != Session::RUNNING) {
            ALOGW("session %s lost resource but is no longer running",
                  sessionToString(sessionKey).c_str());
            return;
        }
        // If we receive a resource loss event, the transcoder already paused the transcoding,
        // so we don't need to call onPaused() to pause it. However, we still need to notify
        // the client and update the session state here.
        resourceLostSession->setState(Session::PAUSED);
        // Notify the client as a paused event.
        auto clientCallback = resourceLostSession->callback.lock();
        if (clientCallback != nullptr) {
            clientCallback->onTranscodingPaused(sessionKey.second);
        }
        if (mResourcePolicy != nullptr) {
            mResourcePolicy->setPidResourceLost(resourceLostSession->request.clientPid);
        }
        mResourceLost = true;

        validateState_l();
    });
}

void TranscodingSessionController::onTopUidsChanged(const std::unordered_set<uid_t>& uids) {
    if (uids.empty()) {
        ALOGW("%s: ignoring empty uids", __FUNCTION__);
        return;
    }

    std::string uidStr;
    for (auto it = uids.begin(); it != uids.end(); it++) {
        if (!uidStr.empty()) {
            uidStr += ", ";
        }
        uidStr += std::to_string(*it);
    }

    ALOGD("%s: topUids: size %zu, uids: %s", __FUNCTION__, uids.size(), uidStr.c_str());

    std::scoped_lock lock{mLock};

    moveUidsToTop_l(uids, true /*preserveTopUid*/);

    updateCurrentSession_l();

    validateState_l();
}

void TranscodingSessionController::onResourceAvailable() {
    std::scoped_lock lock{mLock};

    if (!mResourceLost) {
        return;
    }

    ALOGI("%s", __FUNCTION__);

    mResourceLost = false;
    updateCurrentSession_l();

    validateState_l();
}

void TranscodingSessionController::onThrottlingStarted() {
    std::scoped_lock lock{mLock};

    if (mThermalThrottling) {
        return;
    }

    ALOGI("%s", __FUNCTION__);

    mThermalThrottling = true;
    updateCurrentSession_l();

    validateState_l();
}

void TranscodingSessionController::onThrottlingStopped() {
    std::scoped_lock lock{mLock};

    if (!mThermalThrottling) {
        return;
    }

    ALOGI("%s", __FUNCTION__);

    mThermalThrottling = false;
    updateCurrentSession_l();

    validateState_l();
}

void TranscodingSessionController::validateState_l() {
#ifdef VALIDATE_STATE
    LOG_ALWAYS_FATAL_IF(mSessionQueues.count(OFFLINE_UID) != 1,
                        "mSessionQueues offline queue number is not 1");
    LOG_ALWAYS_FATAL_IF(*mOfflineUidIterator != OFFLINE_UID,
                        "mOfflineUidIterator not pointing to offline uid");
    LOG_ALWAYS_FATAL_IF(mUidSortedList.size() != mSessionQueues.size(),
                        "mUidList and mSessionQueues size mismatch");

    int32_t totalSessions = 0;
    for (auto uid : mUidSortedList) {
        LOG_ALWAYS_FATAL_IF(mSessionQueues.count(uid) != 1,
                            "mSessionQueues count for uid %d is not 1", uid);
        for (auto& sessionKey : mSessionQueues[uid]) {
            LOG_ALWAYS_FATAL_IF(mSessionMap.count(sessionKey) != 1,
                                "mSessions count for session %s is not 1",
                                sessionToString(sessionKey).c_str());
        }

        totalSessions += mSessionQueues[uid].size();
    }
    LOG_ALWAYS_FATAL_IF(mSessionMap.size() != totalSessions,
                        "mSessions size doesn't match total sessions counted from uid queues");
#endif  // VALIDATE_STATE
}

}  // namespace android
