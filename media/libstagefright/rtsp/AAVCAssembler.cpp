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
#define LOG_TAG "AAVCAssembler"
#include <utils/Log.h>

#include "AAVCAssembler.h"

#include "ARTPSource.h"

#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/hexdump.h>

#include <stdint.h>

namespace android {

// static
AAVCAssembler::AAVCAssembler(const sp<AMessage> &notify)
    : mNotifyMsg(notify),
      mAccessUnitRTPTime(0),
      mNextExpectedSeqNoValid(false),
      mNextExpectedSeqNo(0),
      mAccessUnitDamaged(false),
      mFirstIFrameProvided(false),
      mLastIFrameProvidedAtMs(0) {
}

AAVCAssembler::~AAVCAssembler() {
}

int32_t AAVCAssembler::addNack(
        const sp<ARTPSource> &source) {
    List<sp<ABuffer>> *queue = source->queue();
    int32_t nackCount = 0;

    List<sp<ABuffer> >::iterator it = queue->begin();

    if (it == queue->end()) {
        return nackCount /* 0 */;
    }

    uint16_t queueHeadSeqNum = (*it)->int32Data();

    // move to the packet after which RTCP:NACK was sent.
    for (; it != queue->end(); ++it) {
        int32_t seqNum = (*it)->int32Data();
        if (seqNum >= source->mHighestNackNumber) {
            break;
        }
    }

    int32_t nackStartAt = -1;

    while (it != queue->end()) {
        int32_t seqBeforeLast = (*it)->int32Data();
        // increase iterator.
        if ((++it) == queue->end()) {
            break;
        }
        int32_t seqLast = (*it)->int32Data();

        if ((seqLast - seqBeforeLast) < 0) {
            ALOGD("addNack: found end of seqNum from(%d) to(%d)", seqBeforeLast, seqLast);
            source->mHighestNackNumber = 0;
        }

        // missed packet found
        if (seqLast > (seqBeforeLast + 1) &&
                // we didn't send RTCP:NACK for this packet yet.
                (seqLast - 1) > source->mHighestNackNumber) {
            source->mHighestNackNumber = seqLast - 1;
            nackStartAt = seqBeforeLast + 1;
            break;
        }

    }

    if (nackStartAt != -1) {
        nackCount = source->mHighestNackNumber - nackStartAt + 1;
        ALOGD("addNack: nackCount=%d, nackFrom=%d, nackTo=%d", nackCount,
                nackStartAt, source->mHighestNackNumber);

        uint16_t mask = (uint16_t)(0xffff) >> (16 - nackCount + 1);
        source->setSeqNumToNACK(nackStartAt, mask, queueHeadSeqNum);
    }

    return nackCount;
}

ARTPAssembler::AssemblyStatus AAVCAssembler::addNALUnit(
        const sp<ARTPSource> &source) {
    List<sp<ABuffer> > *queue = source->queue();

    if (queue->empty()) {
        return NOT_ENOUGH_DATA;
    }

    sp<ABuffer> buffer = *queue->begin();
    uint32_t rtpTime;
    CHECK(buffer->meta()->findInt32("rtp-time", (int32_t *)&rtpTime));
    int64_t startTime = source->mFirstSysTime / 1000;
    int64_t nowTime = ALooper::GetNowUs() / 1000;
    int64_t playedTime = nowTime - startTime;
    int64_t playedTimeRtp =
        source->mFirstRtpTime + (((uint32_t)playedTime) * (source->mClockRate / 1000));
    const uint32_t jitterTime =
        (uint32_t)(source->mClockRate / ((float)1000 / (source->mJbTimeMs)));
    uint32_t expiredTimeInJb = rtpTime + jitterTime;
    bool isExpired = expiredTimeInJb <= (playedTimeRtp);
    bool isTooLate200 = expiredTimeInJb < (playedTimeRtp - jitterTime);
    bool isTooLate300 = expiredTimeInJb < (playedTimeRtp - (jitterTime * 3 / 2));

    if (mShowQueue && mShowQueueCnt < 20) {
        showCurrentQueue(queue);
        printNowTimeUs(startTime, nowTime, playedTime);
        printRTPTime(rtpTime, playedTimeRtp, expiredTimeInJb, isExpired);
        mShowQueueCnt++;
    }

    AAVCAssembler::addNack(source);

    if (!isExpired) {
        ALOGV("buffering in jitter buffer.");
        return NOT_ENOUGH_DATA;
    }

    if (isTooLate200) {
        ALOGW("=== WARNING === buffer arrived 200ms late. === WARNING === ");
    }

    if (isTooLate300) {
        ALOGW("buffer arrived after 300ms ... \t Diff in Jb=%lld \t Seq# %d",
              ((long long)playedTimeRtp) - expiredTimeInJb, buffer->int32Data());
        printNowTimeUs(startTime, nowTime, playedTime);
        printRTPTime(rtpTime, playedTimeRtp, expiredTimeInJb, isExpired);

        mNextExpectedSeqNo = pickProperSeq(queue, jitterTime, playedTimeRtp);
    }

    if (mNextExpectedSeqNoValid) {
        int32_t size = queue->size();
        int32_t cntRemove = deleteUnitUnderSeq(queue, mNextExpectedSeqNo);

        if (cntRemove > 0) {
            source->noticeAbandonBuffer(cntRemove);
            ALOGW("delete %d of %d buffers", cntRemove, size);
        }
        if (queue->empty()) {
            return NOT_ENOUGH_DATA;
        }
    }

    buffer = *queue->begin();

    if (!mNextExpectedSeqNoValid) {
        mNextExpectedSeqNoValid = true;
        mNextExpectedSeqNo = (uint32_t)buffer->int32Data();
    } else if ((uint32_t)buffer->int32Data() != mNextExpectedSeqNo) {
        ALOGV("Not the sequence number I expected");

        return WRONG_SEQUENCE_NUMBER;
    }

    const uint8_t *data = buffer->data();
    size_t size = buffer->size();

    if (size < 1 || (data[0] & 0x80)) {
        // Corrupt.

        ALOGV("Ignoring corrupt buffer.");
        queue->erase(queue->begin());

        ++mNextExpectedSeqNo;
        return MALFORMED_PACKET;
    }

    unsigned nalType = data[0] & 0x1f;
    if (nalType >= 1 && nalType <= 23) {
        addSingleNALUnit(buffer);
        queue->erase(queue->begin());
        ++mNextExpectedSeqNo;
        return OK;
    } else if (nalType == 28) {
        // FU-A
        return addFragmentedNALUnit(queue);
    } else if (nalType == 24) {
        // STAP-A
        bool success = addSingleTimeAggregationPacket(buffer);
        queue->erase(queue->begin());
        ++mNextExpectedSeqNo;

        return success ? OK : MALFORMED_PACKET;
    } else if (nalType == 0) {
        ALOGV("Ignoring undefined nal type.");

        queue->erase(queue->begin());
        ++mNextExpectedSeqNo;

        return OK;
    } else {
        ALOGV("Ignoring unsupported buffer (nalType=%d)", nalType);

        queue->erase(queue->begin());
        ++mNextExpectedSeqNo;

        return MALFORMED_PACKET;
    }
}

void AAVCAssembler::checkIFrameProvided(const sp<ABuffer> &buffer) {
    if (buffer->size() == 0) {
        return;
    }
    const uint8_t *data = buffer->data();
    unsigned nalType = data[0] & 0x1f;
    if (nalType == 0x5) {
        mFirstIFrameProvided = true;
        mLastIFrameProvidedAtMs = ALooper::GetNowUs() / 1000;

        uint32_t rtpTime;
        CHECK(buffer->meta()->findInt32("rtp-time", (int32_t *)&rtpTime));
        ALOGD("got First I-frame to be decoded. rtpTime=%u, size=%zu", rtpTime, buffer->size());
    }
}

void AAVCAssembler::addSingleNALUnit(const sp<ABuffer> &buffer) {
    ALOGV("addSingleNALUnit of size %zu", buffer->size());
#if !LOG_NDEBUG
    hexdump(buffer->data(), buffer->size());
#endif

    checkIFrameProvided(buffer);

    uint32_t rtpTime;
    CHECK(buffer->meta()->findInt32("rtp-time", (int32_t *)&rtpTime));

    if (!mNALUnits.empty() && rtpTime != mAccessUnitRTPTime) {
        submitAccessUnit();
    }
    mAccessUnitRTPTime = rtpTime;

    mNALUnits.push_back(buffer);
}

bool AAVCAssembler::addSingleTimeAggregationPacket(const sp<ABuffer> &buffer) {
    const uint8_t *data = buffer->data();
    size_t size = buffer->size();

    if (size < 3) {
        ALOGV("Discarding too small STAP-A packet.");
        return false;
    }

    ++data;
    --size;
    while (size >= 2) {
        size_t nalSize = (data[0] << 8) | data[1];

        if (size < nalSize + 2) {
            ALOGV("Discarding malformed STAP-A packet.");
            return false;
        }

        sp<ABuffer> unit = new ABuffer(nalSize);
        memcpy(unit->data(), &data[2], nalSize);

        CopyTimes(unit, buffer);

        addSingleNALUnit(unit);

        data += 2 + nalSize;
        size -= 2 + nalSize;
    }

    if (size != 0) {
        ALOGV("Unexpected padding at end of STAP-A packet.");
    }

    return true;
}

ARTPAssembler::AssemblyStatus AAVCAssembler::addFragmentedNALUnit(
        List<sp<ABuffer> > *queue) {
    CHECK(!queue->empty());

    sp<ABuffer> buffer = *queue->begin();
    const uint8_t *data = buffer->data();
    size_t size = buffer->size();

    CHECK(size > 0);
    unsigned indicator = data[0];

    CHECK((indicator & 0x1f) == 28);

    if (size < 2) {
        ALOGV("Ignoring malformed FU buffer (size = %zu)", size);

        queue->erase(queue->begin());
        ++mNextExpectedSeqNo;
        return MALFORMED_PACKET;
    }

    if (!(data[1] & 0x80)) {
        // Start bit not set on the first buffer.

        ALOGV("Start bit not set on first buffer");

        queue->erase(queue->begin());
        ++mNextExpectedSeqNo;
        return MALFORMED_PACKET;
    }

    uint32_t nalType = data[1] & 0x1f;
    uint32_t nri = (data[0] >> 5) & 3;

    uint32_t expectedSeqNo = (uint32_t)buffer->int32Data() + 1;
    size_t totalSize = size - 2;
    size_t totalCount = 1;
    bool complete = false;

    uint32_t rtpTimeStartAt;
    CHECK(buffer->meta()->findInt32("rtp-time", (int32_t *)&rtpTimeStartAt));
    uint32_t startSeqNo = buffer->int32Data();
    bool pFrame = nalType == 0x1;

    if (data[1] & 0x40) {
        // Huh? End bit also set on the first buffer.

        ALOGV("Grrr. This isn't fragmented at all.");

        complete = true;
    } else {
        List<sp<ABuffer> >::iterator it = ++queue->begin();
        int32_t connected = 1;
        bool snapped = false;
        while (it != queue->end()) {
            ALOGV("sequence length %zu", totalCount);

            const sp<ABuffer> &buffer = *it;

            const uint8_t *data = buffer->data();
            size_t size = buffer->size();

            if ((uint32_t)buffer->int32Data() != expectedSeqNo) {
                ALOGD("sequence not complete, expected seqNo %u, got %u, nalType %u",
                     expectedSeqNo, (unsigned)buffer->int32Data(), nalType);
                snapped = true;

                if (!pFrame) {
                    return WRONG_SEQUENCE_NUMBER;
                }
            }

            if (!snapped) {
                connected++;
            }

            uint32_t rtpTime;
            CHECK(buffer->meta()->findInt32("rtp-time", (int32_t *)&rtpTime));
            if (size < 2
                    || data[0] != indicator
                    || (data[1] & 0x1f) != nalType
                    || (data[1] & 0x80)
                    || rtpTime != rtpTimeStartAt) {
                ALOGV("Ignoring malformed FU buffer.");

                // Delete the whole start of the FU.

                mNextExpectedSeqNo = expectedSeqNo + 1;
                deleteUnitUnderSeq(queue, mNextExpectedSeqNo);

                return MALFORMED_PACKET;
            }

            totalSize += size - 2;
            ++totalCount;

            expectedSeqNo = (uint32_t)buffer->int32Data() + 1;

            if (data[1] & 0x40) {
                if (pFrame && !recycleUnit(startSeqNo, expectedSeqNo,
                            connected, totalCount, 0.5f)) {
                    mNextExpectedSeqNo = expectedSeqNo;
                    deleteUnitUnderSeq(queue, mNextExpectedSeqNo);

                    return MALFORMED_PACKET;
                }

                // This is the last fragment.
                complete = true;
                break;
            }

            ++it;
        }
    }

    if (!complete) {
        return NOT_ENOUGH_DATA;
    }

    mNextExpectedSeqNo = expectedSeqNo;

    // We found all the fragments that make up the complete NAL unit.

    // Leave room for the header. So far totalSize did not include the
    // header byte.
    ++totalSize;

    sp<ABuffer> unit = new ABuffer(totalSize);
    CopyTimes(unit, *queue->begin());

    unit->data()[0] = (nri << 5) | nalType;

    size_t offset = 1;
    int32_t cvo = -1;
    List<sp<ABuffer> >::iterator it = queue->begin();
    for (size_t i = 0; i < totalCount; ++i) {
        const sp<ABuffer> &buffer = *it;

        ALOGV("piece #%zu/%zu", i + 1, totalCount);
#if !LOG_NDEBUG
        hexdump(buffer->data(), buffer->size());
#endif

        memcpy(unit->data() + offset, buffer->data() + 2, buffer->size() - 2);

        buffer->meta()->findInt32("cvo", &cvo);
        offset += buffer->size() - 2;

        it = queue->erase(it);
    }

    unit->setRange(0, totalSize);

    if (cvo >= 0) {
        unit->meta()->setInt32("cvo", cvo);
    }

    addSingleNALUnit(unit);

    ALOGV("successfully assembled a NAL unit from fragments.");

    return OK;
}

void AAVCAssembler::submitAccessUnit() {
    CHECK(!mNALUnits.empty());

    ALOGV("Access unit complete (%zu nal units)", mNALUnits.size());

    size_t totalSize = 0;
    for (List<sp<ABuffer> >::iterator it = mNALUnits.begin();
         it != mNALUnits.end(); ++it) {
        totalSize += 4 + (*it)->size();
    }

    sp<ABuffer> accessUnit = new ABuffer(totalSize);
    size_t offset = 0;
    int32_t cvo = -1;
    for (List<sp<ABuffer> >::iterator it = mNALUnits.begin();
         it != mNALUnits.end(); ++it) {
        memcpy(accessUnit->data() + offset, "\x00\x00\x00\x01", 4);
        offset += 4;

        sp<ABuffer> nal = *it;
        memcpy(accessUnit->data() + offset, nal->data(), nal->size());
        offset += nal->size();

        nal->meta()->findInt32("cvo", &cvo);
    }

    CopyTimes(accessUnit, *mNALUnits.begin());

#if 0
    printf(mAccessUnitDamaged ? "X" : ".");
    fflush(stdout);
#endif
    if (cvo >= 0) {
        accessUnit->meta()->setInt32("cvo", cvo);
    }

    if (mAccessUnitDamaged) {
        accessUnit->meta()->setInt32("damaged", true);
    }

    mNALUnits.clear();
    mAccessUnitDamaged = false;

    sp<AMessage> msg = mNotifyMsg->dup();
    msg->setBuffer("access-unit", accessUnit);
    msg->post();
}

int32_t AAVCAssembler::pickProperSeq(const Queue *queue, uint32_t jit, int64_t play) {
    sp<ABuffer> buffer = *(queue->begin());
    uint32_t rtpTime;
    int32_t nextSeqNo = buffer->int32Data();

    Queue::const_iterator it = queue->begin();
    while (it != queue->end()) {
        CHECK((*it)->meta()->findInt32("rtp-time", (int32_t *)&rtpTime));
        // if pkt in time exists, that should be the next pivot
        if (rtpTime + jit >= play) {
            nextSeqNo = (*it)->int32Data();
            break;
        }
        it++;
    }
    return nextSeqNo;
}

bool AAVCAssembler::recycleUnit(uint32_t start, uint32_t end, uint32_t connected,
        size_t avail, float goodRatio) {
    float total = end - start;
    float valid = connected;
    float exist = avail;
    bool isRecycle = (valid / total) >= goodRatio;

    ALOGV("checking p-frame losses.. recvBufs %f valid %f diff %f recycle? %d",
            exist, valid, total, isRecycle);

    return isRecycle;
}

int32_t AAVCAssembler::deleteUnitUnderSeq(Queue *queue, uint32_t seq) {
    int32_t initSize = queue->size();
    Queue::iterator it = queue->begin();
    while (it != queue->end()) {
        if ((uint32_t)(*it)->int32Data() >= seq) {
            break;
        }
        it++;
    }
    queue->erase(queue->begin(), it);
    return initSize - queue->size();
}

inline void AAVCAssembler::printNowTimeUs(int64_t start, int64_t now, int64_t play) {
    ALOGD("start=%lld, now=%lld, played=%lld",
            (long long)start, (long long)now, (long long)play);
}

inline void AAVCAssembler::printRTPTime(uint32_t rtp, int64_t play, uint32_t exp, bool isExp) {
    ALOGD("rtp-time(JB)=%u, played-rtp-time(JB)=%lld, expired-rtp-time(JB)=%u isExpired=%d",
            rtp, (long long)play, exp, isExp);
}

ARTPAssembler::AssemblyStatus AAVCAssembler::assembleMore(
        const sp<ARTPSource> &source) {
    AssemblyStatus status = addNALUnit(source);
    if (status == MALFORMED_PACKET) {
        uint64_t msecsSinceLastIFrame = (ALooper::GetNowUs() / 1000) - mLastIFrameProvidedAtMs;
        if (msecsSinceLastIFrame > 1000) {
            ALOGV("request FIR to get a new I-Frame, time since "
                    "last I-Frame %llu ms", (unsigned long long)msecsSinceLastIFrame);
            source->onIssueFIRByAssembler();
        }
    }
    return status;
}

void AAVCAssembler::packetLost() {
    CHECK(mNextExpectedSeqNoValid);
    ALOGD("packetLost (expected %u)", mNextExpectedSeqNo);
    ++mNextExpectedSeqNo;
}

void AAVCAssembler::onByeReceived() {
    sp<AMessage> msg = mNotifyMsg->dup();
    msg->setInt32("eos", true);
    msg->post();
}

}  // namespace android
