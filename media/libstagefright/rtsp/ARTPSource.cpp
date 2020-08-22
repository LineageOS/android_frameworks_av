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

//#define LOG_NDEBUG 0
#define LOG_TAG "ARTPSource"
#include <utils/Log.h>

#include "ARTPSource.h"

#include "AAMRAssembler.h"
#include "AAVCAssembler.h"
#include "AHEVCAssembler.h"
#include "AH263Assembler.h"
#include "AMPEG2TSAssembler.h"
#include "AMPEG4AudioAssembler.h"
#include "AMPEG4ElementaryAssembler.h"
#include "ARawAudioAssembler.h"
#include "ASessionDescription.h"

#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>

namespace android {

static uint32_t kSourceID = 0xdeadbeef;

ARTPSource::ARTPSource(
        uint32_t id,
        const sp<ASessionDescription> &sessionDesc, size_t index,
        const sp<AMessage> &notify)
    : mFirstSeqNumber(0),
      mFirstRtpTime(0),
      mFirstSysTime(0),
      mClockRate(0),
      mJbTimeMs(300), // default jitter buffer time is 300ms.
      mFirstSsrc(0),
      mHighestNackNumber(0),
      mID(id),
      mHighestSeqNumber(0),
      mPrevExpected(0),
      mBaseSeqNumber(0),
      mNumBuffersReceived(0),
      mPrevNumBuffersReceived(0),
      mPrevExpectedForRR(0),
      mPrevNumBuffersReceivedForRR(0),
      mLastNTPTime(0),
      mLastNTPTimeUpdateUs(0),
      mIssueFIRRequests(false),
      mIssueFIRByAssembler(false),
      mLastFIRRequestUs(-1),
      mNextFIRSeqNo((rand() * 256.0) / RAND_MAX),
      mNotify(notify) {
    unsigned long PT;
    AString desc;
    AString params;
    sessionDesc->getFormatType(index, &PT, &desc, &params);

    if (!strncmp(desc.c_str(), "H264/", 5)) {
        mAssembler = new AAVCAssembler(notify);
        mIssueFIRRequests = true;
    } else if (!strncmp(desc.c_str(), "H265/", 5)) {
        mAssembler = new AHEVCAssembler(notify);
        mIssueFIRRequests = true;
    } else if (!strncmp(desc.c_str(), "MP4A-LATM/", 10)) {
        mAssembler = new AMPEG4AudioAssembler(notify, params);
    } else if (!strncmp(desc.c_str(), "H263-1998/", 10)
            || !strncmp(desc.c_str(), "H263-2000/", 10)) {
        mAssembler = new AH263Assembler(notify);
        mIssueFIRRequests = true;
    } else if (!strncmp(desc.c_str(), "AMR/", 4)) {
        mAssembler = new AAMRAssembler(notify, false /* isWide */, params);
    } else  if (!strncmp(desc.c_str(), "AMR-WB/", 7)) {
        mAssembler = new AAMRAssembler(notify, true /* isWide */, params);
    } else if (!strncmp(desc.c_str(), "MP4V-ES/", 8)
            || !strncasecmp(desc.c_str(), "mpeg4-generic/", 14)) {
        mAssembler = new AMPEG4ElementaryAssembler(notify, desc, params);
        mIssueFIRRequests = true;
    } else if (ARawAudioAssembler::Supports(desc.c_str())) {
        mAssembler = new ARawAudioAssembler(notify, desc.c_str(), params);
    } else if (!strncasecmp(desc.c_str(), "MP2T/", 5)) {
        mAssembler = new AMPEG2TSAssembler(notify, desc.c_str(), params);
    } else {
        TRESPASS();
    }

    if (mAssembler != NULL && !mAssembler->initCheck()) {
        mAssembler.clear();
    }
}

static uint32_t AbsDiff(uint32_t seq1, uint32_t seq2) {
    return seq1 > seq2 ? seq1 - seq2 : seq2 - seq1;
}

void ARTPSource::processRTPPacket(const sp<ABuffer> &buffer) {
    if (mAssembler != NULL && queuePacket(buffer)) {
        mAssembler->onPacketReceived(this);
    }
}

void ARTPSource::timeUpdate(uint32_t rtpTime, uint64_t ntpTime) {
    mLastNTPTime = ntpTime;
    mLastNTPTimeUpdateUs = ALooper::GetNowUs();

    sp<AMessage> notify = mNotify->dup();
    notify->setInt32("time-update", true);
    notify->setInt32("rtp-time", rtpTime);
    notify->setInt64("ntp-time", ntpTime);
    notify->post();
}

bool ARTPSource::queuePacket(const sp<ABuffer> &buffer) {
    uint32_t seqNum = (uint32_t)buffer->int32Data();

    int32_t ssrc = 0;
    buffer->meta()->findInt32("ssrc", &ssrc);

    if (mNumBuffersReceived++ == 0 && mFirstSysTime == 0) {
        uint32_t firstRtpTime;
        CHECK(buffer->meta()->findInt32("rtp-time", (int32_t *)&firstRtpTime));
        mFirstSysTime = ALooper::GetNowUs();
        mHighestSeqNumber = seqNum;
        mBaseSeqNumber = seqNum;
        mFirstRtpTime = firstRtpTime;
        mFirstSsrc = ssrc;
        ALOGD("first-rtp arrived: first-rtp-time=%d, sys-time=%lld, seq-num=%u, ssrc=%d",
                mFirstRtpTime, (long long)mFirstSysTime, mHighestSeqNumber, mFirstSsrc);
        mClockRate = 90000;
        mQueue.push_back(buffer);
        return true;
    }

    if (mFirstSsrc != ssrc) {
        ALOGW("Discarding a buffer due to unexpected ssrc");
        return false;
    }

    // Only the lower 16-bit of the sequence numbers are transmitted,
    // derive the high-order bits by choosing the candidate closest
    // to the highest sequence number (extended to 32 bits) received so far.

    uint32_t seq1 = seqNum | (mHighestSeqNumber & 0xffff0000);

    // non-overflowing version of:
    // uint32_t seq2 = seqNum | ((mHighestSeqNumber & 0xffff0000) + 0x10000);
    uint32_t seq2 = seqNum | (((mHighestSeqNumber >> 16) + 1) << 16);

    // non-underflowing version of:
    // uint32_t seq2 = seqNum | ((mHighestSeqNumber & 0xffff0000) - 0x10000);
    uint32_t seq3 = seqNum | ((((mHighestSeqNumber >> 16) | 0x10000) - 1) << 16);

    uint32_t diff1 = AbsDiff(seq1, mHighestSeqNumber);
    uint32_t diff2 = AbsDiff(seq2, mHighestSeqNumber);
    uint32_t diff3 = AbsDiff(seq3, mHighestSeqNumber);

    if (diff1 < diff2) {
        if (diff1 < diff3) {
            // diff1 < diff2 ^ diff1 < diff3
            seqNum = seq1;
        } else {
            // diff3 <= diff1 < diff2
            seqNum = seq3;
        }
    } else if (diff2 < diff3) {
        // diff2 <= diff1 ^ diff2 < diff3
        seqNum = seq2;
    } else {
        // diff3 <= diff2 <= diff1
        seqNum = seq3;
    }

    if (seqNum > mHighestSeqNumber) {
        mHighestSeqNumber = seqNum;
    }

    buffer->setInt32Data(seqNum);

    List<sp<ABuffer> >::iterator it = mQueue.begin();
    while (it != mQueue.end() && (uint32_t)(*it)->int32Data() < seqNum) {
        ++it;
    }

    if (it != mQueue.end() && (uint32_t)(*it)->int32Data() == seqNum) {
        ALOGW("Discarding duplicate buffer");
        return false;
    }

    mQueue.insert(it, buffer);

    return true;
}

void ARTPSource::byeReceived() {
    if (mAssembler != NULL) {
        mAssembler->onByeReceived();
    }
}

void ARTPSource::addFIR(const sp<ABuffer> &buffer) {
    if (!mIssueFIRRequests && !mIssueFIRByAssembler) {
        return;
    }

    bool send = false;
    int64_t nowUs = ALooper::GetNowUs();
    int64_t usecsSinceLastFIR = nowUs - mLastFIRRequestUs;
    if (mLastFIRRequestUs < 0) {
        // A first FIR, just send it.
        send = true;
    }  else if (mIssueFIRByAssembler && (usecsSinceLastFIR > 1000000)) {
        // A FIR issued by Assembler.
        // Send it if last FIR is not sent within a sec.
        send = true;
    } else if (mIssueFIRRequests && (usecsSinceLastFIR > 5000000)) {
        // A FIR issued periodically reagardless packet loss.
        // Send it if last FIR is not sent within 5 secs.
        send = true;
    }

    if (!send) {
        return;
    }

    mLastFIRRequestUs = nowUs;

    if (buffer->size() + 20 > buffer->capacity()) {
        ALOGW("RTCP buffer too small to accommodate FIR.");
        return;
    }

    uint8_t *data = buffer->data() + buffer->size();

    data[0] = 0x80 | 4;
    data[1] = 206;  // PSFB
    data[2] = 0;
    data[3] = 4;    // total (4+1) * sizeof(int32_t) = 20 bytes
    data[4] = kSourceID >> 24;
    data[5] = (kSourceID >> 16) & 0xff;
    data[6] = (kSourceID >> 8) & 0xff;
    data[7] = kSourceID & 0xff;

    data[8] = 0x00;  // SSRC of media source (unused)
    data[9] = 0x00;
    data[10] = 0x00;
    data[11] = 0x00;

    data[12] = mID >> 24;
    data[13] = (mID >> 16) & 0xff;
    data[14] = (mID >> 8) & 0xff;
    data[15] = mID & 0xff;

    data[16] = mNextFIRSeqNo++;  // Seq Nr.

    data[17] = 0x00;  // Reserved
    data[18] = 0x00;
    data[19] = 0x00;

    buffer->setRange(buffer->offset(), buffer->size() + (data[3] + 1) * sizeof(int32_t));

    mIssueFIRByAssembler = false;

    ALOGV("Added FIR request.");
}

void ARTPSource::addReceiverReport(const sp<ABuffer> &buffer) {
    if (buffer->size() + 32 > buffer->capacity()) {
        ALOGW("RTCP buffer too small to accommodate RR.");
        return;
    }

    uint8_t fraction = 0;

    // According to appendix A.3 in RFC 3550
    uint32_t expected = mHighestSeqNumber - mBaseSeqNumber + 1;
    int64_t intervalExpected = expected - mPrevExpectedForRR;
    int64_t intervalReceived = mNumBuffersReceived - mPrevNumBuffersReceivedForRR;
    int64_t intervalPacketLost = intervalExpected - intervalReceived;

    if (intervalExpected > 0 && intervalPacketLost > 0) {
        fraction = (intervalPacketLost << 8) / intervalExpected;
    }

    mPrevExpectedForRR = expected;
    mPrevNumBuffersReceivedForRR = mNumBuffersReceived;
    int32_t cumulativePacketLost = (int32_t)expected - mNumBuffersReceived;

    uint8_t *data = buffer->data() + buffer->size();

    data[0] = 0x80 | 1;
    data[1] = 201;  // RR
    data[2] = 0;
    data[3] = 7;    // total (7+1) * sizeof(int32_t) = 32 bytes
    data[4] = kSourceID >> 24;
    data[5] = (kSourceID >> 16) & 0xff;
    data[6] = (kSourceID >> 8) & 0xff;
    data[7] = kSourceID & 0xff;

    data[8] = mID >> 24;
    data[9] = (mID >> 16) & 0xff;
    data[10] = (mID >> 8) & 0xff;
    data[11] = mID & 0xff;

    data[12] = fraction;  // fraction lost

    data[13] = cumulativePacketLost >> 16;  // cumulative lost
    data[14] = (cumulativePacketLost >> 8) & 0xff;
    data[15] = cumulativePacketLost & 0xff;

    data[16] = mHighestSeqNumber >> 24;
    data[17] = (mHighestSeqNumber >> 16) & 0xff;
    data[18] = (mHighestSeqNumber >> 8) & 0xff;
    data[19] = mHighestSeqNumber & 0xff;

    data[20] = 0x00;  // Interarrival jitter
    data[21] = 0x00;
    data[22] = 0x00;
    data[23] = 0x00;

    uint32_t LSR = 0;
    uint32_t DLSR = 0;
    if (mLastNTPTime != 0) {
        LSR = (mLastNTPTime >> 16) & 0xffffffff;

        DLSR = (uint32_t)
            ((ALooper::GetNowUs() - mLastNTPTimeUpdateUs) * 65536.0 / 1E6);
    }

    data[24] = LSR >> 24;
    data[25] = (LSR >> 16) & 0xff;
    data[26] = (LSR >> 8) & 0xff;
    data[27] = LSR & 0xff;

    data[28] = DLSR >> 24;
    data[29] = (DLSR >> 16) & 0xff;
    data[30] = (DLSR >> 8) & 0xff;
    data[31] = DLSR & 0xff;

    buffer->setRange(buffer->offset(), buffer->size() + (data[3] + 1) * sizeof(int32_t));
}

void ARTPSource::addTMMBR(const sp<ABuffer> &buffer, int32_t targetBitrate) {
    if (buffer->size() + 20 > buffer->capacity()) {
        ALOGW("RTCP buffer too small to accommodate RR.");
        return;
    }

    if (targetBitrate <= 0) {
        return;
    }

    uint8_t *data = buffer->data() + buffer->size();

    data[0] = 0x80 | 3; // TMMBR
    data[1] = 205;      // TSFB
    data[2] = 0;
    data[3] = 4;        // total (4+1) * sizeof(int32_t) = 20 bytes
    data[4] = kSourceID >> 24;
    data[5] = (kSourceID >> 16) & 0xff;
    data[6] = (kSourceID >> 8) & 0xff;
    data[7] = kSourceID & 0xff;

    *(int32_t*)(&data[8]) = 0;  // 4 bytes blank

    data[12] = mID >> 24;
    data[13] = (mID >> 16) & 0xff;
    data[14] = (mID >> 8) & 0xff;
    data[15] = mID & 0xff;

    int32_t exp, mantissa;

    // Round off to the nearest 2^4th
    ALOGI("UE -> Op Req Rx bitrate : %d ", targetBitrate & 0xfffffff0);
    for (exp=4 ; exp < 32 ; exp++)
        if (((targetBitrate >> exp) & 0x01) != 0)
            break;
    mantissa = targetBitrate >> exp;

    data[16] = ((exp << 2) & 0xfc) | ((mantissa & 0x18000) >> 15);
    data[17] =                        (mantissa & 0x07f80) >> 7;
    data[18] =                        (mantissa & 0x0007f) << 1;
    data[19] = 40;              // 40 bytes overhead;

    buffer->setRange(buffer->offset(), buffer->size() + (data[3] + 1) * sizeof(int32_t));
}

int ARTPSource::addNACK(const sp<ABuffer> &buffer) {
    constexpr size_t kMaxFCIs = 10; // max number of FCIs
    if (buffer->size() + (3 + kMaxFCIs) * sizeof(int32_t) > buffer->capacity()) {
        ALOGW("RTCP buffer too small to accommodate NACK.");
        return -1;
    }

    uint8_t *data = buffer->data() + buffer->size();

    data[0] = 0x80 | 1; // Generic NACK
    data[1] = 205;      // TSFB
    data[2] = 0;
    data[3] = 0;        // will be decided later
    data[4] = kSourceID >> 24;
    data[5] = (kSourceID >> 16) & 0xff;
    data[6] = (kSourceID >> 8) & 0xff;
    data[7] = kSourceID & 0xff;

    data[8] = mID >> 24;
    data[9] = (mID >> 16) & 0xff;
    data[10] = (mID >> 8) & 0xff;
    data[11] = mID & 0xff;

    List<int> list;
    List<int>::iterator it;
    getSeqNumToNACK(list, kMaxFCIs);
    size_t cnt = 0;

    int *FCI = (int *)(data + 12);
    for (it = list.begin(); it != list.end() && cnt < kMaxFCIs; it++) {
        *(FCI + cnt) = *it;
        cnt++;
    }

    data[3] = (3 + cnt) - 1;  // total (3 + #ofFCI) * sizeof(int32_t) byte

    buffer->setRange(buffer->offset(), buffer->size() + (data[3] + 1) * sizeof(int32_t));

    return cnt;
}

int ARTPSource::getSeqNumToNACK(List<int>& list, int size) {
    AutoMutex _l(mMapLock);
    int cnt = 0;

    std::map<uint16_t, infoNACK>::iterator it;
    for(it = mNACKMap.begin(); it != mNACKMap.end() && cnt < size; it++) {
        infoNACK &info_it = it->second;
        if (info_it.needToNACK) {
            info_it.needToNACK = false;
            // switch LSB to MSB for sending N/W
            uint32_t FCI;
            uint8_t *temp = (uint8_t *)&FCI;
            temp[0] = (info_it.seqNum >> 8) & 0xff;
            temp[1] = (info_it.seqNum)      & 0xff;
            temp[2] = (info_it.mask >> 8)   & 0xff;
            temp[3] = (info_it.mask)        & 0xff;

            list.push_back(FCI);
            cnt++;
        }
    }

    return cnt;
}

void ARTPSource::setSeqNumToNACK(uint16_t seqNum, uint16_t mask, uint16_t nowJitterHeadSeqNum) {
    AutoMutex _l(mMapLock);
    infoNACK info = {seqNum, mask, nowJitterHeadSeqNum, true};
    std::map<uint16_t, infoNACK>::iterator it;

    it = mNACKMap.find(seqNum);
    if (it != mNACKMap.end()) {
        infoNACK &info_it = it->second;
        // renew if (mask or head seq) is changed
        if ((info_it.mask != mask) || (info_it.nowJitterHeadSeqNum != nowJitterHeadSeqNum)) {
            info_it = info;
        }
    } else {
        mNACKMap[seqNum] = info;
    }

    // delete all NACK far from current Jitter's first sequence number
    it = mNACKMap.begin();
    while (it != mNACKMap.end()) {
        infoNACK &info_it = it->second;

        int diff = nowJitterHeadSeqNum - info_it.nowJitterHeadSeqNum;
        if (diff > 100) {
            ALOGV("Delete %d pkt from NACK map ", info_it.seqNum);
            it = mNACKMap.erase(it);
        } else {
            it++;
        }
    }

}

uint32_t ARTPSource::getSelfID() {
    return kSourceID;
}

void ARTPSource::setSelfID(const uint32_t selfID) {
    kSourceID = selfID;
}

void ARTPSource::setJbTime(const uint32_t jbTimeMs) {
    mJbTimeMs = jbTimeMs;
}

void ARTPSource::setPeriodicFIR(bool enable) {
    ALOGD("setPeriodicFIR %d", enable);
    mIssueFIRRequests = enable;
}

void ARTPSource::notifyPktInfo(int32_t bitrate, int64_t /*time*/) {
    sp<AMessage> notify = mNotify->dup();
    notify->setInt32("rtcp-event", 1);
    notify->setInt32("payload-type", 102);
    notify->setInt32("feedback-type", 0);
    // sending target bitrate up to application to share rtp quality.
    notify->setInt32("bit-rate", bitrate);
    notify->setInt32("highest-seq-num", mHighestSeqNumber);
    notify->setInt32("base-seq-num", mBaseSeqNumber);
    notify->setInt32("prev-expected", mPrevExpected);
    notify->setInt32("num-buf-recv", mNumBuffersReceived);
    notify->setInt32("prev-num-buf-recv", mPrevNumBuffersReceived);
    notify->post();

    uint32_t expected = mHighestSeqNumber - mBaseSeqNumber + 1;
    mPrevExpected = expected;
    mPrevNumBuffersReceived = mNumBuffersReceived;
}

void ARTPSource::onIssueFIRByAssembler() {
    mIssueFIRByAssembler = true;
}

void ARTPSource::noticeAbandonBuffer(int cnt) {
    mNumBuffersReceived -= cnt;
}
}  // namespace android
