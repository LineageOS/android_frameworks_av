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

#include <android/permission_manager.h>
#include <inttypes.h>
#include <media/TranscodingSessionController.h>
#include <media/TranscodingUidPolicy.h>
#include <utils/AndroidThreads.h>
#include <utils/Log.h>

#include <thread>
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

///////////////////////////////////////////////////////////////////////////////
struct TranscodingSessionController::Watchdog {
    Watchdog(TranscodingSessionController* owner, int64_t timeoutUs);
    ~Watchdog();

    // Starts monitoring the session.
    void start(const SessionKeyType& key);
    // Stops monitoring the session.
    void stop();
    // Signals that the session is still alive. Must be sent at least every mTimeoutUs.
    // (Timeout will happen if no ping in mTimeoutUs since the last ping.)
    void keepAlive();

private:
    void threadLoop();
    void updateTimer_l();

    TranscodingSessionController* mOwner;
    const int64_t mTimeoutUs;
    mutable std::mutex mLock;
    std::condition_variable mCondition GUARDED_BY(mLock);
    // Whether watchdog is monitoring a session for timeout.
    bool mActive GUARDED_BY(mLock);
    // Whether watchdog is aborted and the monitoring thread should exit.
    bool mAbort GUARDED_BY(mLock);
    // When watchdog is active, the next timeout time point.
    std::chrono::steady_clock::time_point mNextTimeoutTime GUARDED_BY(mLock);
    // When watchdog is active, the session being watched.
    SessionKeyType mSessionToWatch GUARDED_BY(mLock);
    std::thread mThread;
};

TranscodingSessionController::Watchdog::Watchdog(TranscodingSessionController* owner,
                                                 int64_t timeoutUs)
      : mOwner(owner),
        mTimeoutUs(timeoutUs),
        mActive(false),
        mAbort(false),
        mThread(&Watchdog::threadLoop, this) {
    ALOGV("Watchdog CTOR: %p", this);
}

TranscodingSessionController::Watchdog::~Watchdog() {
    ALOGV("Watchdog DTOR: %p", this);

    {
        // Exit the looper thread.
        std::scoped_lock lock{mLock};

        mAbort = true;
        mCondition.notify_one();
    }

    mThread.join();
    ALOGV("Watchdog DTOR: %p, done.", this);
}

void TranscodingSessionController::Watchdog::start(const SessionKeyType& key) {
    std::scoped_lock lock{mLock};

    if (!mActive) {
        ALOGI("Watchdog start: %s", sessionToString(key).c_str());

        mActive = true;
        mSessionToWatch = key;
        updateTimer_l();
        mCondition.notify_one();
    }
}

void TranscodingSessionController::Watchdog::stop() {
    std::scoped_lock lock{mLock};

    if (mActive) {
        ALOGI("Watchdog stop: %s", sessionToString(mSessionToWatch).c_str());

        mActive = false;
        mCondition.notify_one();
    }
}

void TranscodingSessionController::Watchdog::keepAlive() {
    std::scoped_lock lock{mLock};

    if (mActive) {
        ALOGI("Watchdog keepAlive: %s", sessionToString(mSessionToWatch).c_str());

        updateTimer_l();
        mCondition.notify_one();
    }
}

// updateTimer_l() is only called with lock held.
void TranscodingSessionController::Watchdog::updateTimer_l() NO_THREAD_SAFETY_ANALYSIS {
    std::chrono::microseconds timeout(mTimeoutUs);
    mNextTimeoutTime = std::chrono::steady_clock::now() + timeout;
}

// Unfortunately std::unique_lock is incompatible with -Wthread-safety.
void TranscodingSessionController::Watchdog::threadLoop() NO_THREAD_SAFETY_ANALYSIS {
    androidSetThreadPriority(0 /*tid (0 = current) */, ANDROID_PRIORITY_BACKGROUND);
    std::unique_lock<std::mutex> lock{mLock};

    while (!mAbort) {
        if (!mActive) {
            mCondition.wait(lock);
            continue;
        }
        // Watchdog active, wait till next timeout time.
        if (mCondition.wait_until(lock, mNextTimeoutTime) == std::cv_status::timeout) {
            // If timeout happens, report timeout and deactivate watchdog.
            mActive = false;
            // Make a copy of session key, as once we unlock, it could be unprotected.
            SessionKeyType sessionKey = mSessionToWatch;

            ALOGE("Watchdog timeout: %s", sessionToString(sessionKey).c_str());

            lock.unlock();
            mOwner->onError(sessionKey.first, sessionKey.second,
                            TranscodingErrorCode::kWatchdogTimeout);
            lock.lock();
        }
    }
}
///////////////////////////////////////////////////////////////////////////////
struct TranscodingSessionController::Pacer {
    Pacer(const ControllerConfig& config)
          : mBurstThresholdMs(config.pacerBurstThresholdMs),
            mBurstCountQuota(config.pacerBurstCountQuota),
            mBurstTimeQuotaSec(config.pacerBurstTimeQuotaSeconds) {}

    ~Pacer() = default;

    bool onSessionStarted(uid_t uid, uid_t callingUid);
    void onSessionCompleted(uid_t uid, std::chrono::microseconds runningTime);
    void onSessionCancelled(uid_t uid);

private:
    // Threshold of time between finish/start below which a back-to-back start is counted.
    int32_t mBurstThresholdMs;
    // Maximum allowed back-to-back start count.
    int32_t mBurstCountQuota;
    // Maximum allowed back-to-back running time.
    int32_t mBurstTimeQuotaSec;

    struct UidHistoryEntry {
        bool sessionActive = false;
        int32_t burstCount = 0;
        std::chrono::steady_clock::duration burstDuration{0};
        std::chrono::steady_clock::time_point lastCompletedTime;
    };
    std::map<uid_t, UidHistoryEntry> mUidHistoryMap;
    std::unordered_set<uid_t> mMtpUids;
    std::unordered_set<uid_t> mNonMtpUids;

    bool isSubjectToQuota(uid_t uid, uid_t callingUid);
};

bool TranscodingSessionController::Pacer::isSubjectToQuota(uid_t uid, uid_t callingUid) {
    // Submitting with self uid is not limited (which can only happen if it's used as an
    // app-facing API). MediaProvider usage always submit on behalf of other uids.
    if (uid == callingUid) {
        return false;
    }

    if (mMtpUids.find(uid) != mMtpUids.end()) {
        return false;
    }

    if (mNonMtpUids.find(uid) != mNonMtpUids.end()) {
        return true;
    }

    // We don't have MTP permission info about this uid yet, check permission and save the result.
    int32_t result;
    if (__builtin_available(android __TRANSCODING_MIN_API__, *)) {
        if (APermissionManager_checkPermission("android.permission.ACCESS_MTP", -1 /*pid*/, uid,
                                               &result) == PERMISSION_MANAGER_STATUS_OK &&
            result == PERMISSION_MANAGER_PERMISSION_GRANTED) {
            mMtpUids.insert(uid);
            return false;
        }
    }

    mNonMtpUids.insert(uid);
    return true;
}

bool TranscodingSessionController::Pacer::onSessionStarted(uid_t uid, uid_t callingUid) {
    if (!isSubjectToQuota(uid, callingUid)) {
        ALOGI("Pacer::onSessionStarted: uid %d (caling uid: %d): not subject to quota", uid,
              callingUid);
        return true;
    }

    // If uid doesn't exist, only insert the entry and mark session active. Skip quota checking.
    if (mUidHistoryMap.find(uid) == mUidHistoryMap.end()) {
        mUidHistoryMap.emplace(uid, UidHistoryEntry{});
        mUidHistoryMap[uid].sessionActive = true;
        ALOGV("Pacer::onSessionStarted: uid %d: new", uid);
        return true;
    }

    // TODO: if Thermal throttling or resoure lost happened to occurr between this start
    // and the previous completion, we should deduct the paused time from the elapsed time.
    // (Individual session's pause time, on the other hand, doesn't need to be deducted
    // because it doesn't affect the gap between last completion and the start.
    auto timeSinceLastComplete =
            std::chrono::steady_clock::now() - mUidHistoryMap[uid].lastCompletedTime;
    if (mUidHistoryMap[uid].burstCount >= mBurstCountQuota &&
        mUidHistoryMap[uid].burstDuration >= std::chrono::seconds(mBurstTimeQuotaSec)) {
        ALOGW("Pacer::onSessionStarted: uid %d: over quota, burst count %d, time %lldms", uid,
              mUidHistoryMap[uid].burstCount,
              (long long)mUidHistoryMap[uid].burstDuration.count() / 1000000);
        return false;
    }

    // If not over quota, allow the session, and reset as long as this is not too close
    // to previous completion.
    if (timeSinceLastComplete > std::chrono::milliseconds(mBurstThresholdMs)) {
        ALOGV("Pacer::onSessionStarted: uid %d: reset quota", uid);
        mUidHistoryMap[uid].burstCount = 0;
        mUidHistoryMap[uid].burstDuration = std::chrono::milliseconds(0);
    } else {
        ALOGV("Pacer::onSessionStarted: uid %d: burst count %d, time %lldms", uid,
              mUidHistoryMap[uid].burstCount,
              (long long)mUidHistoryMap[uid].burstDuration.count() / 1000000);
    }

    mUidHistoryMap[uid].sessionActive = true;
    return true;
}

void TranscodingSessionController::Pacer::onSessionCompleted(
        uid_t uid, std::chrono::microseconds runningTime) {
    // Skip quota update if this uid missed the start. (Could happen if the uid is added via
    // addClientUid() after the session start.)
    if (mUidHistoryMap.find(uid) == mUidHistoryMap.end() || !mUidHistoryMap[uid].sessionActive) {
        ALOGV("Pacer::onSessionCompleted: uid %d: not started", uid);
        return;
    }
    ALOGV("Pacer::onSessionCompleted: uid %d: runningTime %lld", uid, runningTime.count() / 1000);
    mUidHistoryMap[uid].sessionActive = false;
    mUidHistoryMap[uid].burstCount++;
    mUidHistoryMap[uid].burstDuration += runningTime;
    mUidHistoryMap[uid].lastCompletedTime = std::chrono::steady_clock::now();
}

void TranscodingSessionController::Pacer::onSessionCancelled(uid_t uid) {
    if (mUidHistoryMap.find(uid) == mUidHistoryMap.end()) {
        ALOGV("Pacer::onSessionCancelled: uid %d: not present", uid);
        return;
    }
    // This is only called if a uid is removed from a session (due to it being killed
    // or the original submitting client was gone but session was kept for offline use).
    // Since the uid is going to miss the onSessionCompleted(), we can't track this
    // session, and have to check back at next onSessionStarted().
    mUidHistoryMap[uid].sessionActive = false;
}

///////////////////////////////////////////////////////////////////////////////

TranscodingSessionController::TranscodingSessionController(
        const TranscoderFactoryType& transcoderFactory,
        const std::shared_ptr<UidPolicyInterface>& uidPolicy,
        const std::shared_ptr<ResourcePolicyInterface>& resourcePolicy,
        const std::shared_ptr<ThermalPolicyInterface>& thermalPolicy,
        const ControllerConfig* config)
      : mTranscoderFactory(transcoderFactory),
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
    if (config != nullptr) {
        mConfig = *config;
    }
    mPacer.reset(new Pacer(mConfig));
    ALOGD("@@@ watchdog %lld, burst count %d, burst time %d, burst threshold %d",
          (long long)mConfig.watchdogTimeoutUs, mConfig.pacerBurstCountQuota,
          mConfig.pacerBurstTimeQuotaSeconds, mConfig.pacerBurstThresholdMs);
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

    write(fd, result.c_str(), result.size());
}

/*
 * Returns nullptr if there is no session, or we're paused globally (due to resource lost,
 * thermal throttling, etc.). Otherwise, return the session that should be run next.
 */
TranscodingSessionController::Session* TranscodingSessionController::getTopSession_l() {
    if (mSessionMap.empty()) {
        return nullptr;
    }

    // Return nullptr if we're paused globally due to resource lost or thermal throttling.
    if (((mResourcePolicy != nullptr && mResourceLost) ||
         (mThermalPolicy != nullptr && mThermalThrottling))) {
        return nullptr;
    }

    uid_t topUid = *mUidSortedList.begin();
    // If the current session is running, and it's in the topUid's queue, let it continue
    // to run even if it's not the earliest in that uid's queue.
    // For example, uid(B) is added to a session while it's pending in uid(A)'s queue, then
    // B is brought to front which caused the session to run, then user switches back to A.
    if (mCurrentSession != nullptr && mCurrentSession->getState() == Session::RUNNING &&
        mCurrentSession->allClientUids.count(topUid) > 0) {
        return mCurrentSession;
    }
    SessionKeyType topSessionKey = *mSessionQueues[topUid].begin();
    return &mSessionMap[topSessionKey];
}

void TranscodingSessionController::setSessionState_l(Session* session, Session::State state) {
    bool wasRunning = (session->getState() == Session::RUNNING);
    session->setState(state);
    bool isRunning = (session->getState() == Session::RUNNING);

    if (wasRunning == isRunning) {
        return;
    }

    // Currently we only have 1 running session, and we always put the previous
    // session in non-running state before we run the new session, so it's okay
    // to start/stop the watchdog here. If this assumption changes, we need to
    // track the number of running sessions and start/stop watchdog based on that.
    if (isRunning) {
        mWatchdog->start(session->key);
    } else {
        mWatchdog->stop();
    }
}

void TranscodingSessionController::Session::setState(Session::State newState) {
    if (state == newState) {
        return;
    }
    auto nowTime = std::chrono::steady_clock::now();
    if (state != INVALID) {
        std::chrono::microseconds elapsedTime =
                std::chrono::duration_cast<std::chrono::microseconds>(nowTime - stateEnterTime);
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
    Session* curSession = mCurrentSession;
    Session* topSession = nullptr;

    // Delayed init of transcoder and watchdog.
    if (mTranscoder == nullptr) {
        mTranscoder = mTranscoderFactory(shared_from_this());
        mWatchdog = std::make_shared<Watchdog>(this, mConfig.watchdogTimeoutUs);
    }

    // If we found a different top session, or the top session's running state is not
    // correct. Take some actions to ensure it's correct.
    while ((topSession = getTopSession_l()) != curSession ||
           (topSession != nullptr && !topSession->isRunning())) {
        ALOGV("updateCurrentSession_l: topSession is %s, curSession is %s",
              topSession == nullptr ? "null" : sessionToString(topSession->key).c_str(),
              curSession == nullptr ? "null" : sessionToString(curSession->key).c_str());

        // If current session is running, pause it first. Note this is needed for either
        // cases: 1) Top session is changing to another session, or 2) Top session is
        // changing to null (which means we should be globally paused).
        if (curSession != nullptr && curSession->getState() == Session::RUNNING) {
            mTranscoder->pause(curSession->key.first, curSession->key.second);
            setSessionState_l(curSession, Session::PAUSED);
        }

        if (topSession == nullptr) {
            // Nothing more to run (either no session or globally paused).
            break;
        }

        // Otherwise, ensure topSession is running.
        if (topSession->getState() == Session::NOT_STARTED) {
            // Check if at least one client has quota to start the session.
            bool keepForClient = false;
            for (uid_t uid : topSession->allClientUids) {
                if (mPacer->onSessionStarted(uid, topSession->callingUid)) {
                    keepForClient = true;
                    // DO NOT break here, because book-keeping still needs to happen
                    // for the other uids.
                }
            }
            if (!keepForClient) {
                // Unfortunately all uids requesting this session are out of quota.
                // Drop this session and try the next one.
                {
                    auto clientCallback = mSessionMap[topSession->key].callback.lock();
                    if (clientCallback != nullptr) {
                        clientCallback->onTranscodingFailed(
                                topSession->key.second, TranscodingErrorCode::kDroppedByService);
                    }
                }
                removeSession_l(topSession->key, Session::DROPPED_BY_PACER);
                continue;
            }
            mTranscoder->start(topSession->key.first, topSession->key.second, topSession->request,
                               topSession->callingUid, topSession->callback.lock());
            setSessionState_l(topSession, Session::RUNNING);
        } else if (topSession->getState() == Session::PAUSED) {
            mTranscoder->resume(topSession->key.first, topSession->key.second, topSession->request,
                                topSession->callingUid, topSession->callback.lock());
            setSessionState_l(topSession, Session::RUNNING);
        }
        break;
    }
    mCurrentSession = topSession;
}

void TranscodingSessionController::addUidToSession_l(uid_t clientUid,
                                                     const SessionKeyType& sessionKey) {
    // If it's an offline session, the queue was already added in constructor.
    // If it's a real-time sessions, check if a queue is already present for the uid,
    // and add a new queue if needed.
    if (clientUid != OFFLINE_UID) {
        if (mSessionQueues.count(clientUid) == 0) {
            mUidPolicy->registerMonitorUid(clientUid);
            if (mUidPolicy->isUidOnTop(clientUid)) {
                mUidSortedList.push_front(clientUid);
            } else {
                // Shouldn't be submitting real-time requests from non-top app,
                // put it in front of the offline queue.
                mUidSortedList.insert(mOfflineUidIterator, clientUid);
            }
        } else if (clientUid != *mUidSortedList.begin()) {
            if (mUidPolicy->isUidOnTop(clientUid)) {
                mUidSortedList.remove(clientUid);
                mUidSortedList.push_front(clientUid);
            }
        }
    }
    // Append this session to the uid's queue.
    mSessionQueues[clientUid].push_back(sessionKey);
}

void TranscodingSessionController::removeSession_l(
        const SessionKeyType& sessionKey, Session::State finalState,
        const std::shared_ptr<std::function<bool(uid_t uid)>>& keepUid) {
    ALOGV("%s: session %s", __FUNCTION__, sessionToString(sessionKey).c_str());

    if (mSessionMap.count(sessionKey) == 0) {
        ALOGE("session %s doesn't exist", sessionToString(sessionKey).c_str());
        return;
    }

    // Remove session from uid's queue.
    bool uidQueueRemoved = false;
    std::unordered_set<uid_t> remainingUids;
    for (uid_t uid : mSessionMap[sessionKey].allClientUids) {
        if (keepUid != nullptr) {
            if ((*keepUid)(uid)) {
                remainingUids.insert(uid);
                continue;
            }
            // If we have uids to keep, the session is not going to any final
            // state we can't use onSessionCompleted as the running time will
            // not be valid. Only notify pacer to stop tracking this session.
            mPacer->onSessionCancelled(uid);
        }
        SessionQueueType& sessionQueue = mSessionQueues[uid];
        auto it = std::find(sessionQueue.begin(), sessionQueue.end(), sessionKey);
        if (it == sessionQueue.end()) {
            ALOGW("couldn't find session %s in queue for uid %d",
                  sessionToString(sessionKey).c_str(), uid);
            continue;
        }
        sessionQueue.erase(it);

        // If this is the last session in a real-time queue, remove this uid's queue.
        if (uid != OFFLINE_UID && sessionQueue.empty()) {
            mUidSortedList.remove(uid);
            mSessionQueues.erase(uid);
            mUidPolicy->unregisterMonitorUid(uid);

            uidQueueRemoved = true;
        }
    }

    if (uidQueueRemoved) {
        std::unordered_set<uid_t> topUids = mUidPolicy->getTopUids();
        moveUidsToTop_l(topUids, false /*preserveTopUid*/);
    }

    if (keepUid != nullptr) {
        mSessionMap[sessionKey].allClientUids = remainingUids;
        return;
    }

    // Clear current session.
    if (mCurrentSession == &mSessionMap[sessionKey]) {
        mCurrentSession = nullptr;
    }

    setSessionState_l(&mSessionMap[sessionKey], finalState);

    // We can use onSessionCompleted() even for CANCELLED, because runningTime is
    // now updated by setSessionState_l().
    for (uid_t uid : mSessionMap[sessionKey].allClientUids) {
        mPacer->onSessionCompleted(uid, mSessionMap[sessionKey].runningTime);
    }

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
        ClientIdType clientId, SessionIdType sessionId, uid_t callingUid, uid_t clientUid,
        const TranscodingRequestParcel& request,
        const std::weak_ptr<ITranscodingClientCallback>& callback) {
    SessionKeyType sessionKey = std::make_pair(clientId, sessionId);

    ALOGV("%s: session %s, uid %d, prioirty %d", __FUNCTION__, sessionToString(sessionKey).c_str(),
          clientUid, (int32_t)request.priority);

    std::scoped_lock lock{mLock};

    if (mSessionMap.count(sessionKey) > 0) {
        ALOGE("session %s already exists", sessionToString(sessionKey).c_str());
        return false;
    }

    // Add the uid package name to the store of package names we already know.
    if (mUidPackageNames.count(clientUid) == 0) {
        mUidPackageNames.emplace(clientUid, request.clientPackageName);
    }

    // TODO(chz): only support offline vs real-time for now. All kUnspecified sessions
    // go to offline queue.
    if (request.priority == TranscodingSessionPriority::kUnspecified) {
        clientUid = OFFLINE_UID;
    }

    // Add session to session map.
    mSessionMap[sessionKey].key = sessionKey;
    mSessionMap[sessionKey].callingUid = callingUid;
    mSessionMap[sessionKey].allClientUids.insert(clientUid);
    mSessionMap[sessionKey].request = request;
    mSessionMap[sessionKey].callback = callback;
    setSessionState_l(&mSessionMap[sessionKey], Session::NOT_STARTED);

    addUidToSession_l(clientUid, sessionKey);

    updateCurrentSession_l();

    validateState_l();
    return true;
}

bool TranscodingSessionController::cancel(ClientIdType clientId, SessionIdType sessionId) {
    SessionKeyType sessionKey = std::make_pair(clientId, sessionId);

    ALOGV("%s: session %s", __FUNCTION__, sessionToString(sessionKey).c_str());

    std::list<SessionKeyType> sessionsToRemove, sessionsForOffline;

    std::scoped_lock lock{mLock};

    if (sessionId < 0) {
        for (auto it = mSessionMap.begin(); it != mSessionMap.end(); ++it) {
            if (it->first.first == clientId) {
                // If there is offline request, only keep the offline client;
                // otherwise remove the session.
                if (it->second.allClientUids.count(OFFLINE_UID) > 0) {
                    sessionsForOffline.push_back(it->first);
                } else {
                    sessionsToRemove.push_back(it->first);
                }
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

    auto keepUid = std::make_shared<std::function<bool(uid_t)>>(
            [](uid_t uid) { return uid == OFFLINE_UID; });
    for (auto it = sessionsForOffline.begin(); it != sessionsForOffline.end(); ++it) {
        removeSession_l(*it, Session::CANCELED, keepUid);
    }

    // Start next session.
    updateCurrentSession_l();

    validateState_l();
    return true;
}

bool TranscodingSessionController::addClientUid(ClientIdType clientId, SessionIdType sessionId,
                                                uid_t clientUid) {
    SessionKeyType sessionKey = std::make_pair(clientId, sessionId);

    std::scoped_lock lock{mLock};

    if (mSessionMap.count(sessionKey) == 0) {
        ALOGE("session %s doesn't exist", sessionToString(sessionKey).c_str());
        return false;
    }

    if (mSessionMap[sessionKey].allClientUids.count(clientUid) > 0) {
        ALOGE("session %s already has uid %d", sessionToString(sessionKey).c_str(), clientUid);
        return false;
    }

    mSessionMap[sessionKey].allClientUids.insert(clientUid);
    addUidToSession_l(clientUid, sessionKey);

    updateCurrentSession_l();

    validateState_l();
    return true;
}

bool TranscodingSessionController::getClientUids(ClientIdType clientId, SessionIdType sessionId,
                                                 std::vector<int32_t>* out_clientUids) {
    SessionKeyType sessionKey = std::make_pair(clientId, sessionId);

    std::scoped_lock lock{mLock};

    if (mSessionMap.count(sessionKey) == 0) {
        ALOGE("session %s doesn't exist", sessionToString(sessionKey).c_str());
        return false;
    }

    out_clientUids->clear();
    for (uid_t uid : mSessionMap[sessionKey].allClientUids) {
        if (uid != OFFLINE_UID) {
            out_clientUids->push_back(uid);
        }
    }
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
        if (err == TranscodingErrorCode::kWatchdogTimeout) {
            // Abandon the transcoder, as its handler thread might be stuck in some call to
            // MediaTranscoder altogether, and may not be able to handle any new tasks.
            mTranscoder->stop(clientId, sessionId, true /*abandon*/);
            // Clear the last ref count before we create new transcoder.
            mTranscoder = nullptr;
            mTranscoder = mTranscoderFactory(shared_from_this());
        }

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

void TranscodingSessionController::onHeartBeat(ClientIdType clientId, SessionIdType sessionId) {
    notifyClient(clientId, sessionId, "heart-beat",
                 [=](const SessionKeyType& /*sessionKey*/) { mWatchdog->keepAlive(); });
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
        setSessionState_l(resourceLostSession, Session::PAUSED);
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

void TranscodingSessionController::onUidGone(uid_t goneUid) {
    ALOGD("%s: gone uid %u", __FUNCTION__, goneUid);

    std::list<SessionKeyType> sessionsToRemove, sessionsForOtherUids;

    std::scoped_lock lock{mLock};

    for (auto it = mSessionMap.begin(); it != mSessionMap.end(); ++it) {
        if (it->second.allClientUids.count(goneUid) > 0) {
            // If goneUid is the only uid, remove the session; otherwise, only
            // remove the uid from the session.
            if (it->second.allClientUids.size() > 1) {
                sessionsForOtherUids.push_back(it->first);
            } else {
                sessionsToRemove.push_back(it->first);
            }
        }
    }

    for (auto it = sessionsToRemove.begin(); it != sessionsToRemove.end(); ++it) {
        // If the session has ever been started, stop it now.
        // Note that stop() is needed even if the session is currently paused. This instructs
        // the transcoder to discard any states for the session, otherwise the states may
        // never be discarded.
        if (mSessionMap[*it].getState() != Session::NOT_STARTED) {
            mTranscoder->stop(it->first, it->second);
        }

        {
            auto clientCallback = mSessionMap[*it].callback.lock();
            if (clientCallback != nullptr) {
                clientCallback->onTranscodingFailed(it->second,
                                                    TranscodingErrorCode::kUidGoneCancelled);
            }
        }

        // Remove the session.
        removeSession_l(*it, Session::CANCELED);
    }

    auto keepUid = std::make_shared<std::function<bool(uid_t)>>(
            [goneUid](uid_t uid) { return uid != goneUid; });
    for (auto it = sessionsForOtherUids.begin(); it != sessionsForOtherUids.end(); ++it) {
        removeSession_l(*it, Session::CANCELED, keepUid);
    }

    // Start next session.
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
                        "mUidSortedList and mSessionQueues size mismatch, %zu vs %zu",
                        mUidSortedList.size(), mSessionQueues.size());

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
    int32_t totalSessionsAlternative = 0;
    for (auto const& s : mSessionMap) {
        totalSessionsAlternative += s.second.allClientUids.size();
    }
    LOG_ALWAYS_FATAL_IF(totalSessions != totalSessionsAlternative,
                        "session count (including dup) from mSessionQueues doesn't match that from "
                        "mSessionMap, %d vs %d",
                        totalSessions, totalSessionsAlternative);
#endif  // VALIDATE_STATE
}

}  // namespace android
