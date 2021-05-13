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

#ifndef A_RTP_ASSEMBLER_H_

#define A_RTP_ASSEMBLER_H_

#include <media/stagefright/foundation/ABase.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <utils/List.h>
#include <utils/RefBase.h>

namespace android {

struct ABuffer;
struct ARTPSource;

struct ARTPAssembler : public RefBase {
    enum AssemblyStatus {
        MALFORMED_PACKET,
        WRONG_SEQUENCE_NUMBER,
        NOT_ENOUGH_DATA,
        OK
    };

    ARTPAssembler();

    void onPacketReceived(const sp<ARTPSource> &source);
    virtual void onByeReceived() = 0;
    virtual bool initCheck() { return true; }

protected:
    virtual AssemblyStatus assembleMore(const sp<ARTPSource> &source) = 0;
    virtual void packetLost() = 0;

    static void CopyTimes(const sp<ABuffer> &to, const sp<ABuffer> &from);

    static sp<ABuffer> MakeADTSCompoundFromAACFrames(
            unsigned profile,
            unsigned samplingFreqIndex,
            unsigned channelConfig,
            const List<sp<ABuffer> > &frames);

    static sp<ABuffer> MakeCompoundFromPackets(
            const List<sp<ABuffer> > &frames);

    void showCurrentQueue(List<sp<ABuffer> > *queue);

    bool mShowQueue;
    int32_t mShowQueueCnt;

    // Utility functions
    inline int64_t findRTPTime(const uint32_t& firstRTPTime, const sp<ABuffer>& buffer);
    inline int64_t MsToRtp(int64_t ms, int64_t clockRate);
    inline int64_t RtpToMs(int64_t rtp, int64_t clockRate);
    inline void printNowTimeMs(int64_t start, int64_t now, int64_t play);
    inline void printRTPTime(int64_t rtp, int64_t play, int64_t exp, bool isExp);

private:
    int64_t mFirstFailureTimeUs;

    DISALLOW_EVIL_CONSTRUCTORS(ARTPAssembler);
};

inline int64_t ARTPAssembler::findRTPTime(const uint32_t& firstRTPTime, const sp<ABuffer>& buffer) {
    /* If you want to +,-,* rtpTime, recommend to declare rtpTime as int64_t.
       Because rtpTime can be near UINT32_MAX. Beware the overflow. */
    int64_t rtpTime = 0;
    CHECK(buffer->meta()->findInt32("rtp-time", (int32_t *)&rtpTime));
    // If the first overs 2^31 and rtp unders 2^31, the rtp value is overflowed one.
    int64_t overflowMask = (firstRTPTime & 0x80000000 & ~rtpTime) << 1;
    return rtpTime | overflowMask;
}

inline int64_t ARTPAssembler::MsToRtp(int64_t ms, int64_t clockRate) {
    return ms * clockRate / 1000;
}

inline int64_t ARTPAssembler::RtpToMs(int64_t rtp, int64_t clockRate) {
    return rtp * 1000 / clockRate;
}

inline void ARTPAssembler::printNowTimeMs(int64_t start, int64_t now, int64_t play) {
    ALOGD("start=%lld, now=%lld, played=%lld",
            (long long)start, (long long)now, (long long)play);
}

inline void ARTPAssembler::printRTPTime(int64_t rtp, int64_t play, int64_t exp, bool isExp) {
    ALOGD("rtp-time(JB)=%lld, played-rtp-time(JB)=%lld, expired-rtp-time(JB)=%lld expired=%d",
            (long long)rtp, (long long)play, (long long)exp, isExp);
}

}  // namespace android

#endif  // A_RTP_ASSEMBLER_H_
