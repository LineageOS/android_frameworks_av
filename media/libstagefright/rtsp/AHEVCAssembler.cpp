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
#define LOG_TAG "AHEVCAssembler"
#include <utils/Log.h>

#include <media/stagefright/rtsp/AHEVCAssembler.h>

#include <media/stagefright/rtsp/ARTPSource.h>

#include <HevcUtils.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/hexdump.h>

#include <stdint.h>

#define H265_NALU_MASK 0x3F
#define H265_NALU_VPS 0x20
#define H265_NALU_SPS 0x21
#define H265_NALU_PPS 0x22
#define H265_NALU_AP 0x30
#define H265_NALU_FU 0x31
#define H265_NALU_PACI 0x32


namespace android {

const double JITTER_MULTIPLE = 1.5f;

// static
AHEVCAssembler::AHEVCAssembler(const sp<AMessage> &notify)
    : mNotifyMsg(notify),
      mAccessUnitRTPTime(0),
      mNextExpectedSeqNoValid(false),
      mNextExpectedSeqNo(0),
      mAccessUnitDamaged(false),
      mFirstIFrameProvided(false),
      mLastCvo(-1),
      mLastIFrameProvidedAtMs(0),
      mLastRtpTimeJitterDataUs(0),
      mWidth(0),
      mHeight(0) {

      ALOGV("Constructor");
}

AHEVCAssembler::~AHEVCAssembler() {
}

int32_t AHEVCAssembler::addNack(
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
            source->mHighestNackNumber = seqLast -1;
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

ARTPAssembler::AssemblyStatus AHEVCAssembler::addNALUnit(
        const sp<ARTPSource> &source) {
    List<sp<ABuffer> > *queue = source->queue();
    const uint32_t firstRTPTime = source->mFirstRtpTime;

    if (queue->empty()) {
        return NOT_ENOUGH_DATA;
    }

    sp<ABuffer> buffer = *queue->begin();
    buffer->meta()->setObject("source", source);

    /**
     * RFC3550 calculates the interarrival jitter time for 'ALL packets'.
     * But that is not useful as an ingredient of buffering time.
     * Instead, we calculates the time only for all 'NAL units'.
     */
    int64_t rtpTime = findRTPTime(firstRTPTime, buffer);
    int64_t nowTimeUs = ALooper::GetNowUs();
    if (rtpTime != mLastRtpTimeJitterDataUs) {
        source->putBaseJitterData(rtpTime, nowTimeUs);
        mLastRtpTimeJitterDataUs = rtpTime;
    }
    source->putInterArrivalJitterData(rtpTime, nowTimeUs);

    const int64_t startTimeMs = source->mSysAnchorTime / 1000;
    const int64_t nowTimeMs = nowTimeUs / 1000;
    const int32_t staticJitterTimeMs = source->getStaticJitterTimeMs();
    const int32_t baseJitterTimeMs = source->getBaseJitterTimeMs();
    const int32_t dynamicJitterTimeMs = source->getInterArrivalJitterTimeMs();
    const int64_t clockRate = source->mClockRate;

    int64_t playedTimeMs = nowTimeMs - startTimeMs;
    int64_t playedTimeRtp = source->mFirstRtpTime + MsToRtp(playedTimeMs, clockRate);

    /**
     * Based on experiences in real commercial network services,
     * 300 ms is a maximum heuristic jitter buffer time for video RTP service.
     */

    /**
     * The base jitter is an expected additional propagation time.
     * We can drop packets if the time doesn't meet our standards.
     * If it gets shorter, we can get faster response but should drop delayed packets.
     * Expecting range : 50ms ~ 1000ms (But 300 ms would be practical upper bound)
     */
    const int32_t baseJbTimeMs = std::min(std::max(staticJitterTimeMs, baseJitterTimeMs), 300);
    /**
     * Dynamic jitter is a variance of interarrival time as defined in the 6.4.1 of RFC 3550.
     * We can regard this as a tolerance of every data putting moments.
     * Expecting range : 0ms ~ 150ms (Not to over 300 ms practically)
     */
    const int32_t dynamicJbTimeMs = std::min(dynamicJitterTimeMs, 150);
    const int64_t dynamicJbTimeRtp = MsToRtp(dynamicJbTimeMs, clockRate);
    /* Fundamental jitter time */
    const int32_t jitterTimeMs = baseJbTimeMs;
    const int64_t jitterTimeRtp = MsToRtp(jitterTimeMs, clockRate);

    // Till (T), this assembler waits unconditionally to collect current NAL unit
    int64_t expiredTimeRtp = rtpTime + jitterTimeRtp;       // When does this buffer expire ? (T)
    int64_t diffTimeRtp = playedTimeRtp - expiredTimeRtp;
    bool isExpired = (diffTimeRtp >= 0);                    // It's expired if T is passed away

    // From (T), this assembler tries to complete the NAL till (T + try)
    int32_t tryJbTimeMs = baseJitterTimeMs / 2 + dynamicJbTimeMs;
    int64_t tryJbTimeRtp = MsToRtp(tryJbTimeMs, clockRate);
    bool isFirstLineBroken = (diffTimeRtp > tryJbTimeRtp);

    // After (T + try), it gives last chance till (T + try + a) with warning messages.
    int64_t alpha = dynamicJbTimeRtp * JITTER_MULTIPLE;     // Use Dyn as 'a'
    bool isSecondLineBroken = (diffTimeRtp > (tryJbTimeRtp + alpha));   // The Maginot line

    if (mShowQueueCnt < 20) {
        showCurrentQueue(queue);
        printNowTimeMs(startTimeMs, nowTimeMs, playedTimeMs);
        printRTPTime(rtpTime, playedTimeRtp, expiredTimeRtp, isExpired);
        mShowQueueCnt++;
    }

    AHEVCAssembler::addNack(source);

    if (!isExpired) {
        ALOGV("buffering in jitter buffer.");
        // set an alarm for jitter buffer time expiration.
        // adding 1ms because jitter buffer time is keep changing.
        int64_t expTimeUs = (RtpToMs(std::abs(diffTimeRtp), clockRate) + 1) * 1000;
        source->setJbAlarmTime(nowTimeUs, expTimeUs);
        return NOT_ENOUGH_DATA;
    }

    if (isFirstLineBroken) {
        int64_t totalDiffTimeMs = RtpToMs(diffTimeRtp + jitterTimeRtp, clockRate);
        String8 info;
        info.appendFormat("RTP diff from exp =%lld \t MS diff from stamp = %lld\t\t"
                    "Seq# %d \t ExpSeq# %d \t"
                    "JitterMs %d + (%d + %d * %.3f)",
                    (long long)diffTimeRtp, (long long)totalDiffTimeMs,
                    buffer->int32Data(), mNextExpectedSeqNo,
                    jitterTimeMs, tryJbTimeMs, dynamicJbTimeMs, JITTER_MULTIPLE);
        if (isSecondLineBroken) {
            ALOGE("%s", info.string());
            printNowTimeMs(startTimeMs, nowTimeMs, playedTimeMs);
            printRTPTime(rtpTime, playedTimeRtp, expiredTimeRtp, isExpired);

        }  else {
            ALOGW("%s", info.string());
        }
    }

    if (mNextExpectedSeqNoValid) {
        mNextExpectedSeqNo = pickStartSeq(queue, firstRTPTime, playedTimeRtp, jitterTimeRtp);
        int32_t cntRemove = deleteUnitUnderSeq(queue, mNextExpectedSeqNo);

        if (cntRemove > 0) {
            int32_t size = queue->size();
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

    unsigned nalType = (data[0] >> 1) & H265_NALU_MASK;
    if (nalType > 0 && nalType < H265_NALU_AP) {
        addSingleNALUnit(buffer);
        queue->erase(queue->begin());
        ++mNextExpectedSeqNo;
        return OK;
    } else if (nalType == H265_NALU_FU) {
        // FU-A
        return addFragmentedNALUnit(queue);
    } else if (nalType == H265_NALU_AP) {
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

void AHEVCAssembler::checkSpsUpdated(const sp<ABuffer> &buffer) {
    if (buffer->size() == 0) {
        return;
    }
    const uint8_t *data = buffer->data();
    HevcParameterSets paramSets;
    unsigned nalType = (data[0] >> 1) & H265_NALU_MASK;
    if (nalType == H265_NALU_SPS) {
        int32_t width = 0, height = 0;
        paramSets.FindHEVCDimensions(buffer, &width, &height);
        ALOGV("existing resolution (%u x %u)", mWidth, mHeight);
        if (width != mWidth || height != mHeight) {
            mFirstIFrameProvided = false;
            mWidth = width;
            mHeight = height;
            ALOGD("found a new resolution (%u x %u)", mWidth, mHeight);
        }
    }
}

void AHEVCAssembler::checkIFrameProvided(const sp<ABuffer> &buffer) {
    if (buffer->size() == 0) {
        return;
    }
    const uint8_t *data = buffer->data();
    unsigned nalType = (data[0] >> 1) & H265_NALU_MASK;
    if (nalType > 0x0F && nalType < 0x18) {
        mLastIFrameProvidedAtMs = ALooper::GetNowUs() / 1000;
        if (!mFirstIFrameProvided) {
            mFirstIFrameProvided = true;
            uint32_t rtpTime;
            CHECK(buffer->meta()->findInt32("rtp-time", (int32_t *)&rtpTime));
            ALOGD("got First I-frame to be decoded. rtpTime=%d, size=%zu", rtpTime, buffer->size());
        }
    }
}

bool AHEVCAssembler::dropFramesUntilIframe(const sp<ABuffer> &buffer) {
    if (buffer->size() == 0) {
        return false;
    }
    const uint8_t *data = buffer->data();
    unsigned nalType = (data[0] >> 1) & H265_NALU_MASK;
    return !mFirstIFrameProvided && nalType < 0x10;
}

void AHEVCAssembler::addSingleNALUnit(const sp<ABuffer> &buffer) {
    ALOGV("addSingleNALUnit of size %zu", buffer->size());
#if !LOG_NDEBUG
    hexdump(buffer->data(), buffer->size());
#endif
    checkSpsUpdated(buffer);
    checkIFrameProvided(buffer);

    uint32_t rtpTime;
    CHECK(buffer->meta()->findInt32("rtp-time", (int32_t *)&rtpTime));

    if (dropFramesUntilIframe(buffer)) {
        sp<ARTPSource> source = nullptr;
        buffer->meta()->findObject("source", (sp<android::RefBase>*)&source);
        if (source != nullptr) {
            ALOGD("Issued FIR to get the I-frame");
            source->onIssueFIRByAssembler();
        }
        ALOGD("drop P-frames till an I-frame provided. rtpTime %u", rtpTime);
        return;
    }

    if (!mNALUnits.empty() && rtpTime != mAccessUnitRTPTime) {
        submitAccessUnit();
    }
    mAccessUnitRTPTime = rtpTime;

    mNALUnits.push_back(buffer);
}

bool AHEVCAssembler::addSingleTimeAggregationPacket(const sp<ABuffer> &buffer) {
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

ARTPAssembler::AssemblyStatus AHEVCAssembler::addFragmentedNALUnit(
        List<sp<ABuffer> > *queue) {
    CHECK(!queue->empty());

    sp<ABuffer> buffer = *queue->begin();
    const uint8_t *data = buffer->data();
    size_t size = buffer->size();

    CHECK(size > 0);
    /*   H265 payload header is 16 bit
        0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |F|     Type  |  Layer ID | TID |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    unsigned indicator = (data[0] >> 1);

    CHECK((indicator & H265_NALU_MASK) == H265_NALU_FU);

    if (size < 3) {
        ALOGV("Ignoring malformed FU buffer (size = %zu)", size);

        queue->erase(queue->begin());
        ++mNextExpectedSeqNo;
        return MALFORMED_PACKET;
    }

    if (!(data[2] & 0x80)) {
        // Start bit not set on the first buffer.

        ALOGV("Start bit not set on first buffer");

        queue->erase(queue->begin());
        ++mNextExpectedSeqNo;
        return MALFORMED_PACKET;
    }

    /*  FU INDICATOR HDR
        0 1 2 3 4 5 6 7
       +-+-+-+-+-+-+-+-+
       |S|E|   Type    |
       +-+-+-+-+-+-+-+-+
     */
    uint32_t nalType = data[2] & H265_NALU_MASK;
    uint32_t tid = data[1] & 0x7;
    ALOGV("nalType =%u, tid =%u", nalType, tid);

    uint32_t expectedSeqNo = (uint32_t)buffer->int32Data() + 1;
    size_t totalSize = size - 3;
    size_t totalCount = 1;
    bool complete = false;

    uint32_t rtpTimeStartAt;
    CHECK(buffer->meta()->findInt32("rtp-time", (int32_t *)&rtpTimeStartAt));
    uint32_t startSeqNo = buffer->int32Data();

    if (data[2] & 0x40) {
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
                ALOGV("sequence not complete, expected seqNo %u, got %u, nalType %u",
                     expectedSeqNo, (unsigned)buffer->int32Data(), nalType);
            }

            uint32_t rtpTime;
            CHECK(buffer->meta()->findInt32("rtp-time", (int32_t *)&rtpTime));
            if (size < 3) {
                ALOGV("Ignoring malformed FU buffer.");
                it = queue->erase(it);
                continue;
            }
            if (((data[0] >> 1) & H265_NALU_MASK) != indicator
                    || (data[2] & H265_NALU_MASK) != nalType
                    || (data[2] & 0x80)
                    || rtpTime != rtpTimeStartAt) {
                // Assembler already have given enough time by jitter buffer
                ALOGD("Seems another frame. Incomplete frame [%d ~ %d) \t %d FUs",
                        startSeqNo, expectedSeqNo, (int)queue->distance(queue->begin(), it));
                expectedSeqNo = (uint32_t)buffer->int32Data();
                complete = true;
                break;
            }

            totalSize += size - 3;
            ++totalCount;

            expectedSeqNo = (uint32_t)buffer->int32Data() + 1;

            if (data[2] & 0x40) {
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
    totalSize += 2;

    sp<ABuffer> unit = new ABuffer(totalSize);
    CopyTimes(unit, *queue->begin());

    unit->data()[0] = (nalType << 1);
    unit->data()[1] = tid;

    size_t offset = 2;
    int32_t cvo = -1;
    List<sp<ABuffer> >::iterator it = queue->begin();
    for (size_t i = 0; i < totalCount; ++i) {
        const sp<ABuffer> &buffer = *it;

        ALOGV("piece #%zu/%zu", i + 1, totalCount);
#if !LOG_NDEBUG
        hexdump(buffer->data(), buffer->size());
#endif

        memcpy(unit->data() + offset, buffer->data() + 3, buffer->size() - 3);
        buffer->meta()->findInt32("cvo", &cvo);
        offset += buffer->size() - 3;

        it = queue->erase(it);
    }

    unit->setRange(0, totalSize);

    if (cvo >= 0) {
        unit->meta()->setInt32("cvo", cvo);
        mLastCvo = cvo;
    } else if (mLastCvo >= 0) {
        unit->meta()->setInt32("cvo", mLastCvo);
    }

    addSingleNALUnit(unit);

    ALOGV("successfully assembled a NAL unit from fragments.");

    return OK;
}

void AHEVCAssembler::submitAccessUnit() {
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

int32_t AHEVCAssembler::pickStartSeq(const Queue *queue,
        uint32_t first, int64_t play, int64_t jit) {
    CHECK(!queue->empty());
    // pick the first sequence number has the start bit.
    sp<ABuffer> buffer = *(queue->begin());
    int32_t firstSeqNo = buffer->int32Data();

    // This only works for FU-A type & non-start sequence
    if (buffer->size() < 3 || (buffer->data()[0] & 0x1f) != 28 || buffer->data()[2] & 0x80) {
        return firstSeqNo;
    }

    for (auto it : *queue) {
        const uint8_t *data = it->data();
        int64_t rtpTime = findRTPTime(first, it);
        if (rtpTime + jit >= play) {
            break;
        }
        if (it->size() >= 3 && (data[2] & 0x80)) {
            const int32_t seqNo = it->int32Data();
            ALOGE("finding [HEAD] pkt. \t Seq# (%d ~ )[%d", firstSeqNo, seqNo);
            firstSeqNo = seqNo;
            break;
        }
    }
    return firstSeqNo;
}

int32_t AHEVCAssembler::deleteUnitUnderSeq(Queue *queue, uint32_t seq) {
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

ARTPAssembler::AssemblyStatus AHEVCAssembler::assembleMore(
        const sp<ARTPSource> &source) {
    AssemblyStatus status = addNALUnit(source);
    if (status == MALFORMED_PACKET) {
        uint64_t msecsSinceLastIFrame = (ALooper::GetNowUs() / 1000) - mLastIFrameProvidedAtMs;
        if (msecsSinceLastIFrame > 1000) {
            ALOGV("request FIR to get a new I-Frame, time after "
                    "last I-Frame in %llu ms", (unsigned long long)msecsSinceLastIFrame);
            source->onIssueFIRByAssembler();
        }
    }
    return status;
}

void AHEVCAssembler::packetLost() {
    CHECK(mNextExpectedSeqNoValid);
    ALOGD("packetLost (expected %u)", mNextExpectedSeqNo);

    ++mNextExpectedSeqNo;
}

void AHEVCAssembler::onByeReceived() {
    sp<AMessage> msg = mNotifyMsg->dup();
    msg->setInt32("eos", true);
    msg->post();
}

}  // namespace android
