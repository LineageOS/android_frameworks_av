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

#ifndef A_RTP_SOURCE_H_

#define A_RTP_SOURCE_H_

#include <stdint.h>

#include <media/stagefright/foundation/ABase.h>
#include <utils/List.h>
#include <utils/RefBase.h>
#include <utils/Thread.h>

#include <map>

namespace android {

struct ABuffer;
struct AMessage;
struct ARTPAssembler;
struct ASessionDescription;

struct ARTPSource : public RefBase {
    ARTPSource(
            uint32_t id,
            const sp<ASessionDescription> &sessionDesc, size_t index,
            const sp<AMessage> &notify);

    void processRTPPacket(const sp<ABuffer> &buffer);
    void timeUpdate(uint32_t rtpTime, uint64_t ntpTime);
    void byeReceived();

    List<sp<ABuffer> > *queue() { return &mQueue; }

    void addReceiverReport(const sp<ABuffer> &buffer);
    void addFIR(const sp<ABuffer> &buffer);
    void addTMMBR(const sp<ABuffer> &buffer, int32_t targetBitrate);
    int addNACK(const sp<ABuffer> &buffer);
    void setSeqNumToNACK(uint16_t seqNum, uint16_t mask, uint16_t nowJitterHeadSeqNum);
    uint32_t getSelfID();
    void setSelfID(const uint32_t selfID);
    void setJbTime(const uint32_t jbTimeMs);
    void setPeriodicFIR(bool enable);
    void notifyPktInfo(int32_t bitrate, int64_t time);
    // FIR needs to be sent by missing packet or broken video image.
    void onIssueFIRByAssembler();

    void noticeAbandonBuffer(int cnt=1);

    int32_t mFirstSeqNumber;
    uint32_t mFirstRtpTime;
    int64_t mFirstSysTime;
    int32_t mClockRate;

    uint32_t mJbTimeMs;
    int32_t mFirstSsrc;
    int32_t mHighestNackNumber;

private:

    uint32_t mID;
    uint32_t mHighestSeqNumber;
    uint32_t mPrevExpected;
    uint32_t mBaseSeqNumber;
    int32_t mNumBuffersReceived;
    int32_t mPrevNumBuffersReceived;
    uint32_t mPrevExpectedForRR;
    int32_t mPrevNumBuffersReceivedForRR;

    List<sp<ABuffer> > mQueue;
    sp<ARTPAssembler> mAssembler;

    typedef struct infoNACK {
        uint16_t seqNum;
        uint16_t mask;
        uint16_t nowJitterHeadSeqNum;
        bool    needToNACK;
    } infoNACK;

    Mutex mMapLock;
    std::map<uint16_t, infoNACK> mNACKMap;
    int getSeqNumToNACK(List<int>& list, int size);

    uint64_t mLastNTPTime;
    int64_t mLastNTPTimeUpdateUs;

    bool mIssueFIRRequests;
    bool mIssueFIRByAssembler;
    int64_t mLastFIRRequestUs;
    uint8_t mNextFIRSeqNo;

    sp<AMessage> mNotify;

    bool queuePacket(const sp<ABuffer> &buffer);

    DISALLOW_EVIL_CONSTRUCTORS(ARTPSource);
};

}  // namespace android

#endif  // A_RTP_SOURCE_H_
