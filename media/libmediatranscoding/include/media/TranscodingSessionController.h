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

#ifndef ANDROID_MEDIA_TRANSCODING_SESSION_CONTROLLER_H
#define ANDROID_MEDIA_TRANSCODING_SESSION_CONTROLLER_H

#include <aidl/android/media/TranscodingSessionPriority.h>
#include <media/ControllerClientInterface.h>
#include <media/ResourcePolicyInterface.h>
#include <media/ThermalPolicyInterface.h>
#include <media/TranscoderInterface.h>
#include <media/TranscodingRequest.h>
#include <media/UidPolicyInterface.h>
#include <utils/String8.h>
#include <utils/Vector.h>

#include <chrono>
#include <functional>
#include <list>
#include <map>
#include <mutex>

namespace android {
using ::aidl::android::media::TranscodingResultParcel;
using ::aidl::android::media::TranscodingSessionPriority;

class TranscodingSessionController
      : public UidPolicyCallbackInterface,
        public ControllerClientInterface,
        public TranscoderCallbackInterface,
        public ResourcePolicyCallbackInterface,
        public ThermalPolicyCallbackInterface,
        public std::enable_shared_from_this<TranscodingSessionController> {
public:
    virtual ~TranscodingSessionController();

    // ControllerClientInterface
    bool submit(ClientIdType clientId, SessionIdType sessionId, uid_t callingUid, uid_t clientUid,
                const TranscodingRequestParcel& request,
                const std::weak_ptr<ITranscodingClientCallback>& clientCallback) override;
    bool cancel(ClientIdType clientId, SessionIdType sessionId) override;
    bool getSession(ClientIdType clientId, SessionIdType sessionId,
                    TranscodingRequestParcel* request) override;
    bool addClientUid(ClientIdType clientId, SessionIdType sessionId, uid_t clientUid) override;
    bool getClientUids(ClientIdType clientId, SessionIdType sessionId,
                       std::vector<int32_t>* out_clientUids) override;
    // ~ControllerClientInterface

    // TranscoderCallbackInterface
    void onStarted(ClientIdType clientId, SessionIdType sessionId) override;
    void onPaused(ClientIdType clientId, SessionIdType sessionId) override;
    void onResumed(ClientIdType clientId, SessionIdType sessionId) override;
    void onFinish(ClientIdType clientId, SessionIdType sessionId) override;
    void onError(ClientIdType clientId, SessionIdType sessionId, TranscodingErrorCode err) override;
    void onProgressUpdate(ClientIdType clientId, SessionIdType sessionId,
                          int32_t progress) override;
    void onHeartBeat(ClientIdType clientId, SessionIdType sessionId) override;
    void onResourceLost(ClientIdType clientId, SessionIdType sessionId) override;
    // ~TranscoderCallbackInterface

    // UidPolicyCallbackInterface
    void onTopUidsChanged(const std::unordered_set<uid_t>& uids) override;
    void onUidGone(uid_t goneUid) override;
    // ~UidPolicyCallbackInterface

    // ResourcePolicyCallbackInterface
    void onResourceAvailable() override;
    // ~ResourcePolicyCallbackInterface

    // ThermalPolicyCallbackInterface
    void onThrottlingStarted() override;
    void onThrottlingStopped() override;
    // ~ResourcePolicyCallbackInterface

    /**
     * Dump all the session information to the fd.
     */
    void dumpAllSessions(int fd, const Vector<String16>& args);

private:
    friend class MediaTranscodingService;
    friend class TranscodingSessionControllerTest;

    using SessionKeyType = std::pair<ClientIdType, SessionIdType>;
    using SessionQueueType = std::list<SessionKeyType>;
    using TranscoderFactoryType = std::function<std::shared_ptr<TranscoderInterface>(
            const std::shared_ptr<TranscoderCallbackInterface>&)>;

    struct ControllerConfig {
        // Watchdog timeout.
        int64_t watchdogTimeoutUs = 3000000LL;
        // Threshold of time between finish/start below which a back-to-back start is counted.
        int32_t pacerBurstThresholdMs = 1000;
        // Maximum allowed back-to-back start count.
        int32_t pacerBurstCountQuota = 10;
        // Maximum allowed back-to-back running time.
        int32_t pacerBurstTimeQuotaSeconds = 120;  // 2-min
    };

    struct Session {
        enum State {
            INVALID = -1,
            NOT_STARTED = 0,
            RUNNING,
            PAUSED,
            // The following states would not appear in live sessions map, but could
            // appear in past sessions map for logging purpose.
            FINISHED,
            CANCELED,
            ERROR,
            DROPPED_BY_PACER,
        };
        SessionKeyType key;
        uid_t callingUid;
        std::unordered_set<uid_t> allClientUids;
        int32_t lastProgress = 0;
        int32_t pauseCount = 0;
        std::chrono::time_point<std::chrono::steady_clock> stateEnterTime;
        std::chrono::microseconds waitingTime{0};
        std::chrono::microseconds runningTime{0};
        std::chrono::microseconds pausedTime{0};

        TranscodingRequest request;
        std::weak_ptr<ITranscodingClientCallback> callback;

        // Must use setState to change state.
        void setState(Session::State state);
        State getState() const { return state; }
        bool isRunning() { return state == RUNNING; }

    private:
        State state = INVALID;
    };

    struct Watchdog;
    struct Pacer;

    ControllerConfig mConfig;

    // TODO(chz): call transcoder without global lock.
    // Use mLock for all entrypoints for now.
    mutable std::mutex mLock;

    std::map<SessionKeyType, Session> mSessionMap;

    // uid->SessionQueue map (uid == -1: offline queue)
    std::map<uid_t, SessionQueueType> mSessionQueues;

    // uids, with the head being the most-recently-top app, 2nd item is the
    // previous top app, etc.
    std::list<uid_t> mUidSortedList;
    std::list<uid_t>::iterator mOfflineUidIterator;
    std::map<uid_t, std::string> mUidPackageNames;

    TranscoderFactoryType mTranscoderFactory;
    std::shared_ptr<TranscoderInterface> mTranscoder;
    std::shared_ptr<UidPolicyInterface> mUidPolicy;
    std::shared_ptr<ResourcePolicyInterface> mResourcePolicy;
    std::shared_ptr<ThermalPolicyInterface> mThermalPolicy;

    Session* mCurrentSession;
    bool mResourceLost;
    bool mThermalThrottling;
    std::list<Session> mSessionHistory;
    std::shared_ptr<Watchdog> mWatchdog;
    std::shared_ptr<Pacer> mPacer;

    // Only allow MediaTranscodingService and unit tests to instantiate.
    TranscodingSessionController(const TranscoderFactoryType& transcoderFactory,
                                 const std::shared_ptr<UidPolicyInterface>& uidPolicy,
                                 const std::shared_ptr<ResourcePolicyInterface>& resourcePolicy,
                                 const std::shared_ptr<ThermalPolicyInterface>& thermalPolicy,
                                 const ControllerConfig* config = nullptr);

    void dumpSession_l(const Session& session, String8& result, bool closedSession = false);
    Session* getTopSession_l();
    void updateCurrentSession_l();
    void addUidToSession_l(uid_t uid, const SessionKeyType& sessionKey);
    void removeSession_l(const SessionKeyType& sessionKey, Session::State finalState,
                         const std::shared_ptr<std::function<bool(uid_t uid)>>& keepUid = nullptr);
    void moveUidsToTop_l(const std::unordered_set<uid_t>& uids, bool preserveTopUid);
    void setSessionState_l(Session* session, Session::State state);
    void notifyClient(ClientIdType clientId, SessionIdType sessionId, const char* reason,
                      std::function<void(const SessionKeyType&)> func);
    // Internal state verifier (debug only)
    void validateState_l();

    static String8 sessionToString(const SessionKeyType& sessionKey);
    static const char* sessionStateToString(const Session::State sessionState);
};

}  // namespace android
#endif  // ANDROID_MEDIA_TRANSCODING_SESSION_CONTROLLER_H
