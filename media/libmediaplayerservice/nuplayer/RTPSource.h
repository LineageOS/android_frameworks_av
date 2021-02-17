/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef RTP_SOURCE_H_

#define RTP_SOURCE_H_

#include <media/stagefright/foundation/ABase.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/MediaSource.h>
#include <media/stagefright/Utils.h>
#include <media/BufferingSettings.h>

#include <utils/KeyedVector.h>
#include <utils/Vector.h>
#include <utils/RefBase.h>

#include "AnotherPacketSource.h"
#include "APacketSource.h"
#include "ARTPConnection.h"
#include "ASessionDescription.h"
#include "NuPlayerSource.h"






namespace android {

struct ALooper;
struct AnotherPacketSource;

struct NuPlayer::RTPSource : public NuPlayer::Source {
    RTPSource(
            const sp<AMessage> &notify,
            const String8& rtpParams);

    virtual status_t getBufferingSettings(
            BufferingSettings* buffering /* nonnull */) override;
    virtual status_t setBufferingSettings(const BufferingSettings& buffering) override;

    virtual void prepareAsync();
    virtual void start();
    virtual void stop();
    virtual void pause();
    virtual void resume();

    virtual status_t feedMoreTSData();

    virtual status_t dequeueAccessUnit(bool audio, sp<ABuffer> *accessUnit);

    virtual status_t getDuration(int64_t *durationUs);
    virtual status_t seekTo(
            int64_t seekTimeUs,
            MediaPlayerSeekMode mode = MediaPlayerSeekMode::SEEK_PREVIOUS_SYNC) override;

    void onMessageReceived(const sp<AMessage> &msg);

protected:
    virtual ~RTPSource();

    virtual sp<MetaData> getFormatMeta(bool audio);

private:
    enum {
        kWhatAccessUnit = 'accU',
        kWhatAccessUnitComplete = 'accu',
        kWhatDisconnect = 'disc',
        kWhatEOS = 'eos!',
        kWhatPollBuffering = 'poll',
        kWhatSetBufferingSettings = 'sBuS',
    };

    enum State {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        PAUSED,
    };

    struct TrackInfo {

        /* SDP of track */
        bool mIsAudio;
        int32_t mPayloadType;
        String8 mMimeType;
        String8 mCodecName;
        int32_t mCodecProfile;
        int32_t mCodecLevel;
        int32_t mWidth;
        int32_t mHeight;
        String8 mLocalIp;
        String8 mRemoteIp;
        int32_t mLocalPort;
        int32_t mRemotePort;
        int32_t mTimeScale;
        int32_t mAS;

        /* Unique ID indicates itself */
        uint32_t mSelfID;

        /* a copy of TrackInfo in RTSPSource */
        sp<AnotherPacketSource> mSource;
        uint32_t mRTPTime;
        int64_t mNormalPlaytimeUs;
        bool mNPTMappingValid;

        /* a copy of TrackInfo in MyHandler.h */
        int mRTPSocket;
        int mRTCPSocket;
        uint32_t mFirstSeqNumInSegment;
        bool mNewSegment;
        int32_t mAllowedStaleAccessUnits;
        uint32_t mRTPAnchor;
        int64_t mNTPAnchorUs;
        bool mEOSReceived;
        uint32_t mNormalPlayTimeRTP;
        int64_t mNormalPlayTimeUs;
        sp<APacketSource> mPacketSource;
        List<sp<ABuffer>> mPackets;
    };

    const String8 mRTPParams;
    uint32_t mFlags;
    State mState;
    status_t mFinalResult;

    // below 3 parameters need to be checked whether it needed or not.
    Mutex mBufferingLock;
    bool mBuffering;
    bool mInPreparationPhase;
    Mutex mBufferingSettingsLock;
    BufferingSettings mBufferingSettings;

    sp<ALooper> mLooper;

    sp<ARTPConnection> mRTPConn;

    Vector<TrackInfo> mTracks;
    sp<AnotherPacketSource> mAudioTrack;
    sp<AnotherPacketSource> mVideoTrack;

    int64_t mEOSTimeoutAudio;
    int64_t mEOSTimeoutVideo;

    /* MyHandler.h */
    bool mFirstAccessUnit;
    bool mAllTracksHaveTime;
    int64_t mNTPAnchorUs;
    int64_t mMediaAnchorUs;
    int64_t mLastMediaTimeUs;
    int64_t mNumAccessUnitsReceived;
    bool mReceivedFirstRTCPPacket;
    bool mReceivedFirstRTPPacket;
    bool mPausing;
    int32_t mPauseGeneration;

    sp<AnotherPacketSource> getSource(bool audio);

    /* MyHandler.h */
    void onTimeUpdate(int32_t trackIndex, uint32_t rtpTime, uint64_t ntpTime);
    bool addMediaTimestamp(int32_t trackIndex, const TrackInfo *track,
            const sp<ABuffer> &accessUnit);
    bool dataReceivedOnAllChannels();
    void postQueueAccessUnit(size_t trackIndex, const sp<ABuffer> &accessUnit);
    void postQueueEOS(size_t trackIndex, status_t finalResult);
    sp<MetaData> getTrackFormat(size_t index, int32_t *timeScale);
    void onConnected();
    void onDisconnected(const sp<AMessage> &msg);

    void schedulePollBuffering();
    void onPollBuffering();

    bool haveSufficientDataOnAllTracks();

    void setEOSTimeout(bool audio, int64_t timeout);

    status_t setParameters(const String8 &params);
    status_t setParameter(const String8 &key, const String8 &value);
    static void TrimString(String8 *s);

    DISALLOW_EVIL_CONSTRUCTORS(RTPSource);
};

}  // namespace android

#endif  // RTP_SOURCE_H_
