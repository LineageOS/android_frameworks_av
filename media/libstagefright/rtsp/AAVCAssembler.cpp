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
      mAccessUnitDamaged(false) {
}

AAVCAssembler::~AAVCAssembler() {
}

ARTPAssembler::AssemblyStatus AAVCAssembler::addNALUnit(
        const sp<ARTPSource> &source) {
    List<sp<ABuffer> > *queue = source->queue();

    if (queue->empty()) {
        return NOT_ENOUGH_DATA;
    }

    sp<ABuffer> buffer = *queue->begin();
    int32_t rtpTime;
    CHECK(buffer->meta()->findInt32("rtp-time", &rtpTime));
    int64_t startTime = source->mFirstSysTime / 1000;
    int64_t nowTime = ALooper::GetNowUs() / 1000;
    int64_t playedTime = nowTime - startTime;
    int32_t playedTimeRtp = source->mFirstRtpTime +
        (((uint32_t)playedTime) * (source->mClockRate / 1000));
    const int32_t jitterTime = source->mClockRate / 5;  // 200ms
    int32_t expiredTimeInJb = rtpTime + jitterTime;
    bool isExpired = expiredTimeInJb <= (playedTimeRtp);
    bool isTooLate = expiredTimeInJb < (playedTimeRtp - jitterTime);
    ALOGV("start=%lld, now=%lld, played=%lld", (long long)startTime,
            (long long)nowTime, (long long)playedTime);
    ALOGV("rtp-time(JB)=%d, played-rtp-time(JB)=%d, expired-rtp-time(JB)=%d isExpired=%d",
            rtpTime, playedTimeRtp, expiredTimeInJb, isExpired);

    if (!isExpired) {
        ALOGV("buffering in jitter buffer.");
        return NOT_ENOUGH_DATA;
    }

    if (isTooLate) {
        ALOGV("buffer arrived too lately..");
        ALOGW("start=%lld, now=%lld, played=%lld", (long long)startTime,
                (long long)nowTime, (long long)playedTime);
        ALOGW("rtp-time(JB)=%d, plyed-rtp-time(JB)=%d, exp-rtp-time(JB)=%d diff=%lld isExpired=%d",
                rtpTime, playedTimeRtp, expiredTimeInJb,
                ((long long)playedTimeRtp) - expiredTimeInJb, isExpired);
        ALOGW("expected Seq. NO =%d", buffer->int32Data());

        List<sp<ABuffer> >::iterator it = queue->begin();
        while (it != queue->end()) {
            CHECK((*it)->meta()->findInt32("rtp-time", &rtpTime));
            if (rtpTime + jitterTime >= playedTimeRtp) {
                mNextExpectedSeqNo = (*it)->int32Data();
                break;
            }
            it++;
        }
        source->noticeAbandonBuffer();
    }

    if (mNextExpectedSeqNoValid) {
        int32_t size = queue->size();
        int32_t cnt = 0;
        List<sp<ABuffer> >::iterator it = queue->begin();
        while (it != queue->end()) {
            if ((uint32_t)(*it)->int32Data() >= mNextExpectedSeqNo) {
                break;
            }

            it = queue->erase(it);
            cnt++;
        }

        if (cnt > 0) {
            source->noticeAbandonBuffer(cnt);
            ALOGW("delete %d of %d buffers", cnt, size);
        }
        if (queue->empty()) {
            return NOT_ENOUGH_DATA;
        }
    }

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

void AAVCAssembler::addSingleNALUnit(const sp<ABuffer> &buffer) {
    ALOGV("addSingleNALUnit of size %zu", buffer->size());
#if !LOG_NDEBUG
    hexdump(buffer->data(), buffer->size());
#endif

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

    if (data[1] & 0x40) {
        // Huh? End bit also set on the first buffer.

        ALOGV("Grrr. This isn't fragmented at all.");

        complete = true;
    } else {
        List<sp<ABuffer> >::iterator it = ++queue->begin();
        while (it != queue->end()) {
            ALOGV("sequence length %zu", totalCount);

            const sp<ABuffer> &buffer = *it;

            const uint8_t *data = buffer->data();
            size_t size = buffer->size();

            if ((uint32_t)buffer->int32Data() != expectedSeqNo) {
                ALOGV("sequence not complete, expected seqNo %d, got %d",
                     expectedSeqNo, (uint32_t)buffer->int32Data());

                return WRONG_SEQUENCE_NUMBER;
            }

            if (size < 2
                    || data[0] != indicator
                    || (data[1] & 0x1f) != nalType
                    || (data[1] & 0x80)) {
                ALOGV("Ignoring malformed FU buffer.");

                // Delete the whole start of the FU.

                it = queue->begin();
                for (size_t i = 0; i <= totalCount; ++i) {
                    it = queue->erase(it);
                }

                mNextExpectedSeqNo = expectedSeqNo + 1;

                return MALFORMED_PACKET;
            }

            totalSize += size - 2;
            ++totalCount;

            expectedSeqNo = expectedSeqNo + 1;

            if (data[1] & 0x40) {
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

ARTPAssembler::AssemblyStatus AAVCAssembler::assembleMore(
        const sp<ARTPSource> &source) {
    AssemblyStatus status = addNALUnit(source);
    if (status == MALFORMED_PACKET) {
        mAccessUnitDamaged = true;
    }
    return status;
}

void AAVCAssembler::packetLost() {
    CHECK(mNextExpectedSeqNoValid);
    ALOGV("packetLost (expected %d)", mNextExpectedSeqNo);

    ++mNextExpectedSeqNo;

    mAccessUnitDamaged = true;
}

void AAVCAssembler::onByeReceived() {
    sp<AMessage> msg = mNotifyMsg->dup();
    msg->setInt32("eos", true);
    msg->post();
}

}  // namespace android
