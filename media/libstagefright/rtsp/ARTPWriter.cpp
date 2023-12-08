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
#define LOG_TAG "ARTPWriter"
#include <utils/Log.h>

#include <media/stagefright/rtsp/ARTPWriter.h>

#include <media/stagefright/MediaSource.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/hexdump.h>
#include <media/stagefright/MediaBuffer.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MetaData.h>
#include <utils/ByteOrder.h>

#include <fcntl.h>
#include <strings.h>

#define PT      97
#define PT_STR  "97"

#define H264_NALU_MASK 0x1F
#define H264_NALU_SPS 0x7
#define H264_NALU_PPS 0x8
#define H264_NALU_IFRAME 0x5
#define H264_NALU_PFRAME 0x1

#define H265_NALU_MASK 0x3F
#define H265_NALU_VPS 0x20
#define H265_NALU_SPS 0x21
#define H265_NALU_PPS 0x22

#define IPV4_HEADER_SIZE 20
#define IPV6_HEADER_SIZE 40
#define UDP_HEADER_SIZE 8
#define TCPIPV4_HEADER_SIZE (IPV4_HEADER_SIZE + UDP_HEADER_SIZE)
#define TCPIPV6_HEADER_SIZE (IPV6_HEADER_SIZE + UDP_HEADER_SIZE)
#define TCPIP_HEADER_SIZE TCPIPV4_HEADER_SIZE
#define RTP_HEADER_SIZE 12
#define RTP_HEADER_EXT_SIZE 8
#define RTP_FU_HEADER_SIZE 2
#define RTP_PAYLOAD_ROOM_SIZE 100 // ROOM size for IPv6 header, ESP and etc.


namespace android {

// static const size_t kMaxPacketSize = 65507;  // maximum payload in UDP over IP
static const size_t kMaxPacketSize = 1280;
static char kCNAME[255] = "someone@somewhere";

static const size_t kTrafficRecorderMaxEntries = 128;
static const size_t kTrafficRecorderMaxTimeSpanMs = 2000;

static int UniformRand(int limit) {
    return ((double)rand() * limit) / RAND_MAX;
}

ARTPWriter::ARTPWriter(int fd)
    : mFlags(0),
      mFd(dup(fd)),
      mLooper(new ALooper),
      mReflector(new AHandlerReflector<ARTPWriter>(this)),
      mTrafficRec(new TrafficRecorder<uint32_t /* Time */, Bytes>(
              kTrafficRecorderMaxEntries, kTrafficRecorderMaxTimeSpanMs)) {
    CHECK_GE(fd, 0);
    mIsIPv6 = false;

    mLooper->setName("rtp writer");
    mLooper->registerHandler(mReflector);
    mLooper->start();

    mRTPSocket = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK_GE(mRTPSocket, 0);
    mRTCPSocket = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK_GE(mRTCPSocket, 0);

    memset(mRTPAddr.sin_zero, 0, sizeof(mRTPAddr.sin_zero));
    mRTPAddr.sin_family = AF_INET;

#if 1
    mRTPAddr.sin_addr.s_addr = INADDR_ANY;
#else
    mRTPAddr.sin_addr.s_addr = inet_addr("172.19.18.246");
#endif

    mRTPAddr.sin_port = htons(5634);
    CHECK_EQ(0, ntohs(mRTPAddr.sin_port) & 1);

    mRTCPAddr = mRTPAddr;
    mRTCPAddr.sin_port = htons(ntohs(mRTPAddr.sin_port) | 1);
    mVPSBuf = NULL;
    mSPSBuf = NULL;
    mPPSBuf = NULL;

#if LOG_TO_FILES
    mRTPFd = open(
            "/data/misc/rtpout.bin",
            O_WRONLY | O_CREAT | O_TRUNC,
            0644);
    CHECK_GE(mRTPFd, 0);

    mRTCPFd = open(
            "/data/misc/rtcpout.bin",
            O_WRONLY | O_CREAT | O_TRUNC,
            0644);
    CHECK_GE(mRTCPFd, 0);
#endif
}

ARTPWriter::ARTPWriter(int fd, String8& localIp, int localPort, String8& remoteIp,
    int remotePort, uint32_t seqNo)
    : mFlags(0),
      mFd(dup(fd)),
      mLooper(new ALooper),
      mReflector(new AHandlerReflector<ARTPWriter>(this)),
      mTrafficRec(new TrafficRecorder<uint32_t /* Time */, Bytes>(
              kTrafficRecorderMaxEntries, kTrafficRecorderMaxTimeSpanMs)) {
    CHECK_GE(fd, 0);
    mIsIPv6 = false;

    mLooper->setName("rtp writer");
    mLooper->registerHandler(mReflector);
    mLooper->start();

    makeSocketPairAndBind(localIp, localPort, remoteIp , remotePort);
    mVPSBuf = NULL;
    mSPSBuf = NULL;
    mPPSBuf = NULL;

    initState();
    mSeqNo = seqNo;     // Must use explicit # of seq for RTP continuity

#if LOG_TO_FILES
    mRTPFd = open(
            "/data/misc/rtpout.bin",
            O_WRONLY | O_CREAT | O_TRUNC,
            0644);
    CHECK_GE(mRTPFd, 0);

    mRTCPFd = open(
            "/data/misc/rtcpout.bin",
            O_WRONLY | O_CREAT | O_TRUNC,
            0644);
    CHECK_GE(mRTCPFd, 0);
#endif
}

ARTPWriter::~ARTPWriter() {
    if (mVPSBuf != NULL) {
        mVPSBuf->release();
        mVPSBuf = NULL;
    }

    if (mSPSBuf != NULL) {
        mSPSBuf->release();
        mSPSBuf = NULL;
    }

    if (mPPSBuf != NULL) {
        mPPSBuf->release();
        mPPSBuf = NULL;
    }

#if LOG_TO_FILES
    close(mRTCPFd);
    mRTCPFd = -1;

    close(mRTPFd);
    mRTPFd = -1;
#endif

    close(mRTPSocket);
    mRTPSocket = -1;

    close(mRTCPSocket);
    mRTCPSocket = -1;

    close(mFd);
    mFd = -1;
}

void ARTPWriter::initState() {
    if (mSourceID == 0)
        mSourceID = rand();
    mPayloadType = 0;
    if (mSeqNo == 0)
        mSeqNo = UniformRand(65536);
    mRTPTimeBase = 0;
    mNumRTPSent = 0;
    mNumRTPOctetsSent = 0;

    mOpponentID = 0;
    mBitrate = 192000;

    mNumSRsSent = 0;
    mRTPCVOExtMap = -1;
    mRTPCVODegrees = 0;
    mRTPSockNetwork = 0;

    mMode = INVALID;
    mClockRate = 16000;
}

status_t ARTPWriter::addSource(const sp<MediaSource> &source) {
    mSource = source;
    return OK;
}

bool ARTPWriter::reachedEOS() {
    Mutex::Autolock autoLock(mLock);
    return (mFlags & kFlagEOS) != 0;
}

status_t ARTPWriter::start(MetaData * params) {
    Mutex::Autolock autoLock(mLock);
    if (mFlags & kFlagStarted) {
        return INVALID_OPERATION;
    }

    mFlags &= ~kFlagEOS;
    initState();

    const char *mime;
    CHECK(mSource->getFormat()->findCString(kKeyMIMEType, &mime));

    int32_t selfID = 0;
    if (params->findInt32(kKeySelfID, &selfID))
        mSourceID = selfID;

    int32_t payloadType = 0;
    if (params->findInt32(kKeyPayloadType, &payloadType))
        mPayloadType = payloadType;

    int32_t rtpExtMap = 0;
    if (params->findInt32(kKeyRtpExtMap, &rtpExtMap))
        mRTPCVOExtMap = rtpExtMap;

    int32_t rtpCVODegrees = 0;
    if (params->findInt32(kKeyRtpCvoDegrees, &rtpCVODegrees))
        mRTPCVODegrees = rtpCVODegrees;

    bool needToSetSockOpt = false;
    int32_t dscp = 0;
    if (params->findInt32(kKeyRtpDscp, &dscp)) {
        mRtpLayer3Dscp = dscp << 2;
        needToSetSockOpt = true;
    }

    int32_t ecn = 0;
    if (params->findInt32(kKeyRtpEcn, &ecn)) {
        /*
         * @ecn, possible value for ECN.
         *  +-----+-----+
         *  | ECN FIELD |
         *  +-----+-----+
         *    ECT   CE         [Obsolete] RFC 2481 names for the ECN bits.
         *     0     0         Not-ECT
         *     0     1         ECT (ECN-Capable Transport) (1)
         *     1     0         ECT (ECN-Capable Transport) (0)
         *     1     1         CE (Congestion Experienced)
         *
         */
        mRtpSockOptEcn = ecn;
        needToSetSockOpt = true;
    }

    if (needToSetSockOpt) {
        updateSocketOpt();
    }

    int64_t sockNetwork = 0;
    if (params->findInt64(kKeySocketNetwork, &sockNetwork))
        updateSocketNetwork(sockNetwork);

    if (!strcasecmp(mime, MEDIA_MIMETYPE_VIDEO_AVC)) {
        // rfc6184: RTP Payload Format for H.264 Video
        // The clock rate in the "a=rtpmap" line MUST be 90000.
        mMode = H264;
        mClockRate = 90000;
    } else if (!strcasecmp(mime, MEDIA_MIMETYPE_VIDEO_HEVC)) {
        // rfc7798: RTP Payload Format for High Efficiency Video Coding (HEVC)
        // The clock rate in the "a=rtpmap" line MUST be 90000.
        mMode = H265;
        mClockRate = 90000;
    } else if (!strcasecmp(mime, MEDIA_MIMETYPE_VIDEO_H263)) {
        mMode = H263;
        // rfc4629: RTP Payload Format for ITU-T Rec. H.263 Video
        // The clock rate in the "a=rtpmap" line MUST be 90000.
        mClockRate = 90000;
    } else if (!strcasecmp(mime, MEDIA_MIMETYPE_AUDIO_AMR_NB)) {
        mMode = AMR_NB;
        // rfc4867: RTP Payload Format ... (AMR) and (AMR-WB)
        // The RTP clock rate in "a=rtpmap" MUST be 8000 for AMR and 16000 for AMR-WB
        mClockRate = 8000;
    } else if (!strcasecmp(mime, MEDIA_MIMETYPE_AUDIO_AMR_WB)) {
        mMode = AMR_WB;
        mClockRate = 16000;
    } else {
        TRESPASS();
    }

    (new AMessage(kWhatStart, mReflector))->post();

    while (!(mFlags & kFlagStarted)) {
        mCondition.wait(mLock);
    }

    return OK;
}

status_t ARTPWriter::stop() {
    Mutex::Autolock autoLock(mLock);
    if (!(mFlags & kFlagStarted)) {
        return OK;
    }

    (new AMessage(kWhatStop, mReflector))->post();

    while (mFlags & kFlagStarted) {
        mCondition.wait(mLock);
    }
    return OK;
}

status_t ARTPWriter::pause() {
    return OK;
}

static void StripStartcode(MediaBufferBase *buffer) {
    if (buffer->range_length() < 4) {
        return;
    }

    const uint8_t *ptr =
        (const uint8_t *)buffer->data() + buffer->range_offset();

    if (!memcmp(ptr, "\x00\x00\x00\x01", 4)) {
        buffer->set_range(
                buffer->range_offset() + 4, buffer->range_length() - 4);
    }
}

static const uint8_t SPCSize = 4;      // Start Prefix Code Size
static const uint8_t startPrefixCode[SPCSize] = {0, 0, 0, 1};
static const uint8_t spcKMPidx[SPCSize] = {0, 0, 2, 0};
static void SpsPpsParser(MediaBufferBase *buffer,
        MediaBufferBase **spsBuffer, MediaBufferBase **ppsBuffer) {

    while (buffer->range_length() > 0) {
        const uint8_t *NALPtr = (const uint8_t *)buffer->data() + buffer->range_offset();
        uint8_t nalType = (*NALPtr) & H264_NALU_MASK;

        MediaBufferBase **targetPtr = NULL;
        if (nalType == H264_NALU_SPS) {
            targetPtr = spsBuffer;
        } else if (nalType == H264_NALU_PPS) {
            targetPtr = ppsBuffer;
        } else {
            return;
        }
        ALOGV("SPS(7) or PPS(8) found. Type %d", nalType);

        uint32_t bufferSize = buffer->range_length();
        MediaBufferBase *&target = *targetPtr;
        uint32_t i = 0, j = 0;
        bool isBoundFound = false;
        for (i = 0; i < bufferSize; i++) {
            while (j > 0 && NALPtr[i] != startPrefixCode[j]) {
                j = spcKMPidx[j - 1];
            }
            if (NALPtr[i] == startPrefixCode[j]) {
                j++;
                if (j == SPCSize) {
                    isBoundFound = true;
                    break;
                }
            }
        }

        uint32_t targetSize;
        if (target != NULL) {
            target->release();
        }
        // note that targetSize is never 0 as the first byte is never part
        // of a start prefix
        if (isBoundFound) {
            targetSize = i - SPCSize + 1;
            target = MediaBufferBase::Create(targetSize);
            memcpy(target->data(),
                   (const uint8_t *)buffer->data() + buffer->range_offset(),
                   targetSize);
            buffer->set_range(buffer->range_offset() + targetSize + SPCSize,
                              buffer->range_length() - targetSize - SPCSize);
        } else {
            targetSize = bufferSize;
            target = MediaBufferBase::Create(targetSize);
            memcpy(target->data(),
                   (const uint8_t *)buffer->data() + buffer->range_offset(),
                   targetSize);
            buffer->set_range(buffer->range_offset() + bufferSize, 0);
            return;
        }
    }
}

static void VpsSpsPpsParser(MediaBufferBase *buffer,
        MediaBufferBase **vpsBuffer, MediaBufferBase **spsBuffer, MediaBufferBase **ppsBuffer) {

    while (buffer->range_length() > 0) {
        const uint8_t *NALPtr = (const uint8_t *)buffer->data() + buffer->range_offset();
        uint8_t nalType = ((*NALPtr) >> 1) & H265_NALU_MASK;

        MediaBufferBase **targetPtr = NULL;
        if (nalType == H265_NALU_VPS) {
            targetPtr = vpsBuffer;
        } else if (nalType == H265_NALU_SPS) {
            targetPtr = spsBuffer;
        } else if (nalType == H265_NALU_PPS) {
            targetPtr = ppsBuffer;
        } else {
            return;
        }
        ALOGV("VPS(32) SPS(33) or PPS(34) found. Type %d", nalType);

        uint32_t bufferSize = buffer->range_length();
        MediaBufferBase *&target = *targetPtr;
        uint32_t i = 0, j = 0;
        bool isBoundFound = false;
        for (i = 0; i < bufferSize; i++) {
            while (j > 0 && NALPtr[i] != startPrefixCode[j]) {
                j = spcKMPidx[j - 1];
            }
            if (NALPtr[i] == startPrefixCode[j]) {
                j++;
                if (j == SPCSize) {
                    isBoundFound = true;
                    break;
                }
            }
        }

        uint32_t targetSize;
        if (target != NULL) {
            target->release();
        }
        // note that targetSize is never 0 as the first byte is never part
        // of a start prefix
        if (isBoundFound) {
            targetSize = i - SPCSize + 1;
            target = MediaBufferBase::Create(targetSize);
            memcpy(target->data(),
                   (const uint8_t *)buffer->data() + buffer->range_offset(),
                   targetSize);
            buffer->set_range(buffer->range_offset() + targetSize + SPCSize,
                              buffer->range_length() - targetSize - SPCSize);
        } else {
            targetSize = bufferSize;
            target = MediaBufferBase::Create(targetSize);
            memcpy(target->data(),
                   (const uint8_t *)buffer->data() + buffer->range_offset(),
                   targetSize);
            buffer->set_range(buffer->range_offset() + bufferSize, 0);
            return;
        }
    }
}

void ARTPWriter::onMessageReceived(const sp<AMessage> &msg) {
    switch (msg->what()) {
        case kWhatStart:
        {
            sp<MetaData> meta = new MetaData();
            meta->setInt64(kKeyTime, 10ll);
            CHECK_EQ(mSource->start(meta.get()), (status_t)OK);

#if 0
            if (mMode == H264) {
                MediaBufferBase *buffer;
                CHECK_EQ(mSource->read(&buffer), (status_t)OK);

                StripStartcode(buffer);
                makeH264SPropParamSets(buffer);
                buffer->release();
                buffer = NULL;
            }

            dumpSessionDesc();
#endif

            {
                Mutex::Autolock autoLock(mLock);
                mFlags |= kFlagStarted;
                mCondition.signal();
            }

            (new AMessage(kWhatRead, mReflector))->post();
            (new AMessage(kWhatSendSR, mReflector))->post();
            break;
        }

        case kWhatStop:
        {
            CHECK_EQ(mSource->stop(), (status_t)OK);

            sendBye();

            {
                Mutex::Autolock autoLock(mLock);
                mFlags &= ~kFlagStarted;
                mCondition.signal();
            }
            break;
        }

        case kWhatRead:
        {
            {
                Mutex::Autolock autoLock(mLock);
                if (!(mFlags & kFlagStarted)) {
                    break;
                }
            }

            onRead(msg);
            break;
        }

        case kWhatSendSR:
        {
            {
                Mutex::Autolock autoLock(mLock);
                if (!(mFlags & kFlagStarted)) {
                    break;
                }
            }

            onSendSR(msg);
            break;
        }

        default:
            TRESPASS();
            break;
    }
}

void ARTPWriter::setTMMBNInfo(uint32_t opponentID, uint32_t bitrate) {
    mOpponentID = opponentID;
    mBitrate = bitrate;

    sp<ABuffer> buffer = new ABuffer(65536);
    buffer->setRange(0, 0);

    addTMMBN(buffer);

    send(buffer, true /* isRTCP */);
}

void ARTPWriter::onRead(const sp<AMessage> &msg) {
    MediaBufferBase *mediaBuf;
    status_t err = mSource->read(&mediaBuf);

    if (err != OK) {
        ALOGI("reached EOS.");

        Mutex::Autolock autoLock(mLock);
        mFlags |= kFlagEOS;
        return;
    }

    if (mediaBuf->range_length() > 0) {
        ALOGV("read buffer of size %zu", mediaBuf->range_length());

        if (mMode == H264) {
            StripStartcode(mediaBuf);
            SpsPpsParser(mediaBuf, &mSPSBuf, &mPPSBuf);
            if (mediaBuf->range_length() > 0) {
                sendAVCData(mediaBuf);
            }
        } else if (mMode == H265) {
            StripStartcode(mediaBuf);
            VpsSpsPpsParser(mediaBuf, &mVPSBuf, &mSPSBuf, &mPPSBuf);
            if (mediaBuf->range_length() > 0) {
                sendHEVCData(mediaBuf);
            }
        } else if (mMode == H263) {
            sendH263Data(mediaBuf);
        } else if (mMode == AMR_NB || mMode == AMR_WB) {
            sendAMRData(mediaBuf);
        }
    }

    mediaBuf->release();
    mediaBuf = NULL;

    msg->post();
}

void ARTPWriter::onSendSR(const sp<AMessage> &msg) {
    sp<ABuffer> buffer = new ABuffer(65536);
    buffer->setRange(0, 0);

    addSR(buffer);
    addSDES(buffer);

    send(buffer, true /* isRTCP */);

    ++mNumSRsSent;
    msg->post(3000000);
}

void ARTPWriter::send(const sp<ABuffer> &buffer, bool isRTCP) {
    int sizeSockSt;
    struct sockaddr *remAddr;

    if (mIsIPv6) {
        sizeSockSt = sizeof(struct sockaddr_in6);
        if (isRTCP)
            remAddr = (struct sockaddr *)&mRTCPAddr6;
        else
            remAddr = (struct sockaddr *)&mRTPAddr6;
    } else {
        sizeSockSt = sizeof(struct sockaddr_in);
        if (isRTCP)
            remAddr = (struct sockaddr *)&mRTCPAddr;
        else
            remAddr = (struct sockaddr *)&mRTPAddr;
    }

    // Unseal code if moderator is needed (prevent overflow of instant bandwidth)
    // Set limit bits per period through the moderator.
    // ex) 6KByte/10ms = 48KBit/10ms = 4.8MBit/s instant limit
    // ModerateInstantTraffic(10, 6 * 1024);

    ssize_t n = sendto(isRTCP ? mRTCPSocket : mRTPSocket,
            buffer->data(), buffer->size(), 0, remAddr, sizeSockSt);

    if (n != (ssize_t)buffer->size()) {
        ALOGW("packets can not be sent. ret=%d, buf=%d", (int)n, (int)buffer->size());
    } else {
        // Record current traffic & Print bits while last 1sec (1000ms)
        mTrafficRec->writeBytes(buffer->size() +
                (mIsIPv6 ? TCPIPV6_HEADER_SIZE : TCPIPV4_HEADER_SIZE));
        mTrafficRec->printAccuBitsForLastPeriod(1000, 1000);
    }

#if LOG_TO_FILES
    int fd = isRTCP ? mRTCPFd : mRTPFd;

    uint32_t ms = tolel(ALooper::GetNowUs() / 1000ll);
    uint32_t length = tolel(buffer->size());
    write(fd, &ms, sizeof(ms));
    write(fd, &length, sizeof(length));
    write(fd, buffer->data(), buffer->size());
#endif
}

void ARTPWriter::addSR(const sp<ABuffer> &buffer) {
    uint8_t *data = buffer->data() + buffer->size();

    data[0] = 0x80 | 0;
    data[1] = 200;  // SR
    data[2] = 0;
    data[3] = 6;
    data[4] = mSourceID >> 24;
    data[5] = (mSourceID >> 16) & 0xff;
    data[6] = (mSourceID >> 8) & 0xff;
    data[7] = mSourceID & 0xff;

    uint64_t ntpTime = GetNowNTP();
    data[8] = ntpTime >> (64 - 8);
    data[9] = (ntpTime >> (64 - 16)) & 0xff;
    data[10] = (ntpTime >> (64 - 24)) & 0xff;
    data[11] = (ntpTime >> 32) & 0xff;
    data[12] = (ntpTime >> 24) & 0xff;
    data[13] = (ntpTime >> 16) & 0xff;
    data[14] = (ntpTime >> 8) & 0xff;
    data[15] = ntpTime & 0xff;

    // A current rtpTime can be calculated from ALooper::GetNowUs().
    // This is expecting a timestamp of raw frame from a media source is
    // on the same time context across components in android media framework
    // which can be queried by ALooper::GetNowUs().
    // In other words, ALooper::GetNowUs() is on the same timeline as the time
    // of kKeyTime in a MediaBufferBase
    uint32_t rtpTime = getRtpTime(ALooper::GetNowUs());
    data[16] = (rtpTime >> 24) & 0xff;
    data[17] = (rtpTime >> 16) & 0xff;
    data[18] = (rtpTime >> 8) & 0xff;
    data[19] = rtpTime & 0xff;

    data[20] = mNumRTPSent >> 24;
    data[21] = (mNumRTPSent >> 16) & 0xff;
    data[22] = (mNumRTPSent >> 8) & 0xff;
    data[23] = mNumRTPSent & 0xff;

    data[24] = mNumRTPOctetsSent >> 24;
    data[25] = (mNumRTPOctetsSent >> 16) & 0xff;
    data[26] = (mNumRTPOctetsSent >> 8) & 0xff;
    data[27] = mNumRTPOctetsSent & 0xff;

    buffer->setRange(buffer->offset(), buffer->size() + 28);
}

void ARTPWriter::addSDES(const sp<ABuffer> &buffer) {
    uint8_t *data = buffer->data() + buffer->size();
    data[0] = 0x80 | 1;
    data[1] = 202;  // SDES
    data[4] = mSourceID >> 24;
    data[5] = (mSourceID >> 16) & 0xff;
    data[6] = (mSourceID >> 8) & 0xff;
    data[7] = mSourceID & 0xff;

    size_t offset = 8;

    data[offset++] = 1;  // CNAME

    data[offset++] = strlen(kCNAME);

    memcpy(&data[offset], kCNAME, strlen(kCNAME));
    offset += strlen(kCNAME);

    data[offset++] = 7;  // NOTE

    static const char *kNOTE = "Hell's frozen over.";
    data[offset++] = strlen(kNOTE);

    memcpy(&data[offset], kNOTE, strlen(kNOTE));
    offset += strlen(kNOTE);

    data[offset++] = 0;

    if ((offset % 4) > 0) {
        size_t count = 4 - (offset % 4);
        switch (count) {
            case 3:
                data[offset++] = 0;
                [[fallthrough]];
            case 2:
                data[offset++] = 0;
                [[fallthrough]];
            case 1:
                data[offset++] = 0;
        }
    }

    size_t numWords = (offset / 4) - 1;
    data[2] = numWords >> 8;
    data[3] = numWords & 0xff;

    buffer->setRange(buffer->offset(), buffer->size() + offset);
}

void ARTPWriter::addTMMBN(const sp<ABuffer> &buffer) {
    if (buffer->size() + 20 > buffer->capacity()) {
        ALOGW("RTCP buffer too small to accommodate SR.");
        return;
    }
    if (mOpponentID == 0)
        return;

    uint8_t *data = buffer->data() + buffer->size();

    data[0] = 0x80 | 4; // TMMBN
    data[1] = 205;      // TSFB
    data[2] = 0;
    data[3] = 4;        // total (4+1) * sizeof(int32_t) = 20 bytes
    data[4] = mSourceID >> 24;
    data[5] = (mSourceID >> 16) & 0xff;
    data[6] = (mSourceID >> 8) & 0xff;
    data[7] = mSourceID & 0xff;

    *(int32_t*)(&data[8]) = 0;  // 4 bytes blank

    data[12] = mOpponentID >> 24;
    data[13] = (mOpponentID >> 16) & 0xff;
    data[14] = (mOpponentID >> 8) & 0xff;
    data[15] = mOpponentID & 0xff;

    // Find the first bit '1' from left & right side of the value.
    int32_t leftEnd = 31 - __builtin_clz(mBitrate);
    int32_t rightEnd = ffs(mBitrate) - 1;

    // Mantissa have only 17bit space by RTCP specification.
    if ((leftEnd - rightEnd) > 16) {
        rightEnd = leftEnd - 16;
    }
    int32_t mantissa = mBitrate >> rightEnd;

    data[16] = ((rightEnd << 2) & 0xfc) | ((mantissa & 0x18000) >> 15);
    data[17] =                             (mantissa & 0x07f80) >> 7;
    data[18] =                             (mantissa & 0x0007f) << 1;
    data[19] = 40;              // 40 bytes overhead;

    buffer->setRange(buffer->offset(), buffer->size() + 20);

    ALOGI("UE -> Op Noti Tx bitrate : %d ", mantissa << rightEnd);
}

// static
uint64_t ARTPWriter::GetNowNTP() {
    uint64_t nowUs = systemTime(SYSTEM_TIME_REALTIME) / 1000ll;

    nowUs += ((70LL * 365 + 17) * 24) * 60 * 60 * 1000000LL;

    uint64_t hi = nowUs / 1000000LL;
    uint64_t lo = ((1LL << 32) * (nowUs % 1000000LL)) / 1000000LL;

    return (hi << 32) | lo;
}

uint32_t ARTPWriter::getRtpTime(int64_t timeUs) {
    int32_t clockPerMs = mClockRate / 1000;
    int64_t rtpTime = mRTPTimeBase + (timeUs * clockPerMs / 1000LL);

    return (uint32_t)rtpTime;
}

void ARTPWriter::dumpSessionDesc() {
    AString sdp;
    sdp = "v=0\r\n";

    sdp.append("o=- ");

    uint64_t ntp = GetNowNTP();
    sdp.append(ntp);
    sdp.append(" ");
    sdp.append(ntp);
    sdp.append(" IN IP4 127.0.0.0\r\n");

    sdp.append(
          "s=Sample\r\n"
          "i=Playing around\r\n"
          "c=IN IP4 ");

    struct in_addr addr;
    addr.s_addr = ntohl(INADDR_LOOPBACK);

    sdp.append(inet_ntoa(addr));

    sdp.append(
          "\r\n"
          "t=0 0\r\n"
          "a=range:npt=now-\r\n");

    sp<MetaData> meta = mSource->getFormat();

    if (mMode == H264 || mMode == H263) {
        sdp.append("m=video ");
    } else {
        sdp.append("m=audio ");
    }

    sdp.append(AStringPrintf("%d", mIsIPv6 ? ntohs(mRTPAddr6.sin6_port) : ntohs(mRTPAddr.sin_port)));
    sdp.append(
          " RTP/AVP " PT_STR "\r\n"
          "b=AS 320000\r\n"
          "a=rtpmap:" PT_STR " ");

    if (mMode == H264) {
        sdp.append("H264/90000");
    } else if (mMode == H263) {
        sdp.append("H263-1998/90000");
    } else if (mMode == AMR_NB || mMode == AMR_WB) {
        int32_t sampleRate, numChannels;
        CHECK(mSource->getFormat()->findInt32(kKeySampleRate, &sampleRate));
        CHECK(mSource->getFormat()->findInt32(kKeyChannelCount, &numChannels));

        CHECK_EQ(numChannels, 1);
        CHECK_EQ(sampleRate, (mMode == AMR_NB) ? 8000 : 16000);

        sdp.append(mMode == AMR_NB ? "AMR" : "AMR-WB");
        sdp.append(AStringPrintf("/%d/%d", sampleRate, numChannels));
    } else {
        TRESPASS();
    }

    sdp.append("\r\n");

    if (mMode == H264 || mMode == H263) {
        int32_t width, height;
        CHECK(meta->findInt32(kKeyWidth, &width));
        CHECK(meta->findInt32(kKeyHeight, &height));

        sdp.append("a=cliprect 0,0,");
        sdp.append(height);
        sdp.append(",");
        sdp.append(width);
        sdp.append("\r\n");

        sdp.append(
              "a=framesize:" PT_STR " ");
        sdp.append(width);
        sdp.append("-");
        sdp.append(height);
        sdp.append("\r\n");
    }

    if (mMode == H264) {
        sdp.append(
              "a=fmtp:" PT_STR " profile-level-id=");
        sdp.append(mProfileLevel);
        sdp.append(";sprop-parameter-sets=");

        sdp.append(mSeqParamSet);
        sdp.append(",");
        sdp.append(mPicParamSet);
        sdp.append(";packetization-mode=1\r\n");
    } else if (mMode == AMR_NB || mMode == AMR_WB) {
        sdp.append("a=fmtp:" PT_STR " octed-align\r\n");
    }

    ALOGI("%s", sdp.c_str());
}

void ARTPWriter::makeH264SPropParamSets(MediaBufferBase *buffer) {
    static const char kStartCode[] = "\x00\x00\x00\x01";

    const uint8_t *data =
        (const uint8_t *)buffer->data() + buffer->range_offset();
    size_t size = buffer->range_length();

    CHECK_GE(size, 0u);

    size_t startCodePos = 0;
    while (startCodePos + 3 < size
            && memcmp(kStartCode, &data[startCodePos], 4)) {
        ++startCodePos;
    }

    CHECK_LT(startCodePos + 3, size);

    CHECK_EQ((unsigned)data[0], 0x67u);

    mProfileLevel =
        AStringPrintf("%02X%02X%02X", data[1], data[2], data[3]);

    encodeBase64(data, startCodePos, &mSeqParamSet);

    encodeBase64(&data[startCodePos + 4], size - startCodePos - 4,
                 &mPicParamSet);
}

void ARTPWriter::sendBye() {
    sp<ABuffer> buffer = new ABuffer(8);
    uint8_t *data = buffer->data();
    *data++ = (2 << 6) | 1;
    *data++ = 203;
    *data++ = 0;
    *data++ = 1;
    *data++ = mSourceID >> 24;
    *data++ = (mSourceID >> 16) & 0xff;
    *data++ = (mSourceID >> 8) & 0xff;
    *data++ = mSourceID & 0xff;
    buffer->setRange(0, 8);

    send(buffer, true /* isRTCP */);
}

void ARTPWriter::sendSPSPPSIfIFrame(MediaBufferBase *mediaBuf, int64_t timeUs) {
    CHECK(mediaBuf->range_length() > 0);
    const uint8_t *mediaData =
        (const uint8_t *)mediaBuf->data() + mediaBuf->range_offset();

    if ((mediaData[0] & H264_NALU_MASK) != H264_NALU_IFRAME) {
        return;
    }

    if (mSPSBuf != NULL) {
        mSPSBuf->meta_data().setInt64(kKeyTime, timeUs);
        mSPSBuf->meta_data().setInt32(kKeySps, 1);
        sendAVCData(mSPSBuf);
    }

    if (mPPSBuf != NULL) {
        mPPSBuf->meta_data().setInt64(kKeyTime, timeUs);
        mPPSBuf->meta_data().setInt32(kKeyPps, 1);
        sendAVCData(mPPSBuf);
    }
}

void ARTPWriter::sendVPSSPSPPSIfIFrame(MediaBufferBase *mediaBuf, int64_t timeUs) {
    CHECK(mediaBuf->range_length() > 0);
    const uint8_t *mediaData =
        (const uint8_t *)mediaBuf->data() + mediaBuf->range_offset();

    int nalType = ((mediaData[0] >> 1) & H265_NALU_MASK);
    if (!(nalType >= 16 && nalType <= 21) /*H265_NALU_IFRAME*/) {
        return;
    }

    if (mVPSBuf != NULL) {
        mVPSBuf->meta_data().setInt64(kKeyTime, timeUs);
        mVPSBuf->meta_data().setInt32(kKeyVps, 1);
        sendHEVCData(mVPSBuf);
    }

    if (mSPSBuf != NULL) {
        mSPSBuf->meta_data().setInt64(kKeyTime, timeUs);
        mSPSBuf->meta_data().setInt32(kKeySps, 1);
        sendHEVCData(mSPSBuf);
    }

    if (mPPSBuf != NULL) {
        mPPSBuf->meta_data().setInt64(kKeyTime, timeUs);
        mPPSBuf->meta_data().setInt32(kKeyPps, 1);
        sendHEVCData(mPPSBuf);
    }
}

void ARTPWriter::sendHEVCData(MediaBufferBase *mediaBuf) {
    // 12 bytes RTP header + 2 bytes for the FU-indicator and FU-header.
    CHECK_GE(kMaxPacketSize, 12u + 2u);

    int64_t timeUs;
    CHECK(mediaBuf->meta_data().findInt64(kKeyTime, &timeUs));

    sendVPSSPSPPSIfIFrame(mediaBuf, timeUs);

    uint32_t rtpTime = getRtpTime(timeUs);

    CHECK(mediaBuf->range_length() > 0);
    const uint8_t *mediaData =
        (const uint8_t *)mediaBuf->data() + mediaBuf->range_offset();

    int32_t isNonVCL = 0;
    if (mediaBuf->meta_data().findInt32(kKeyVps, &isNonVCL) ||
            mediaBuf->meta_data().findInt32(kKeySps, &isNonVCL) ||
            mediaBuf->meta_data().findInt32(kKeyPps, &isNonVCL)) {
        isNonVCL = 1;
    }

    sp<ABuffer> buffer = new ABuffer(kMaxPacketSize);
    if (mediaBuf->range_length() + TCPIP_HEADER_SIZE + RTP_HEADER_SIZE + RTP_HEADER_EXT_SIZE
            + RTP_PAYLOAD_ROOM_SIZE <= buffer->capacity()) {
        // The data fits into a single packet
        uint8_t *data = buffer->data();
        data[0] = 0x80;
        if (mRTPCVOExtMap > 0) {
            data[0] |= 0x10;
        }
        if (isNonVCL) {
            data[1] = mPayloadType;  // Marker bit should not be set in case of Non-VCL
        } else {
            data[1] = (1 << 7) | mPayloadType;  // M-bit
        }
        data[2] = (mSeqNo >> 8) & 0xff;
        data[3] = mSeqNo & 0xff;
        data[4] = rtpTime >> 24;
        data[5] = (rtpTime >> 16) & 0xff;
        data[6] = (rtpTime >> 8) & 0xff;
        data[7] = rtpTime & 0xff;
        data[8] = mSourceID >> 24;
        data[9] = (mSourceID >> 16) & 0xff;
        data[10] = (mSourceID >> 8) & 0xff;
        data[11] = mSourceID & 0xff;

        int rtpExtIndex = 0;
        if (mRTPCVOExtMap > 0) {
            /*
                0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               |       0xBE    |    0xDE       |           length=3            |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               |  ID   | L=0   |     data      |  ID   |  L=1  |   data...
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     ...data   |    0 (pad)    |    0 (pad)    |  ID   | L=3   |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               |                          data                                 |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


              In the one-byte header form of extensions, the 16-bit value required
              by the RTP specification for a header extension, labeled in the RTP
              specification as "defined by profile", takes the fixed bit pattern
              0xBEDE (the first version of this specification was written on the
              feast day of the Venerable Bede).
            */
            data[12] = 0xBE;
            data[13] = 0xDE;
            // put a length of RTP Extension.
            data[14] = 0x00;
            data[15] = 0x01;
            // put extmap of RTP assigned for CVO.
            data[16] = (mRTPCVOExtMap << 4) | 0x0;
            // put image degrees as per CVO specification.
            data[17] = mRTPCVODegrees;
            data[18] = 0x0;
            data[19] = 0x0;
            rtpExtIndex = 8;
        }

        memcpy(&data[12 + rtpExtIndex],
               mediaData, mediaBuf->range_length());

        buffer->setRange(0, mediaBuf->range_length() + (12 + rtpExtIndex));

        send(buffer, false /* isRTCP */);

        ++mSeqNo;
        ++mNumRTPSent;
        mNumRTPOctetsSent += buffer->size() - (12 + rtpExtIndex);
    } else {
        // FU-A

        unsigned nalType = (mediaData[0] >> 1) & H265_NALU_MASK;
        ALOGV("H265 nalType 0x%x, data[0]=0x%x", nalType, mediaData[0]);
        size_t offset = 2; //H265 payload header is 16 bit.

        bool firstPacket = true;
        while (offset < mediaBuf->range_length()) {
            size_t size = mediaBuf->range_length() - offset;
            bool lastPacket = true;
            if (size + TCPIP_HEADER_SIZE + RTP_HEADER_SIZE + RTP_HEADER_EXT_SIZE +
                    RTP_FU_HEADER_SIZE + RTP_PAYLOAD_ROOM_SIZE > buffer->capacity()) {
                lastPacket = false;
                size = buffer->capacity() - TCPIP_HEADER_SIZE - RTP_HEADER_SIZE -
                    RTP_HEADER_EXT_SIZE - RTP_FU_HEADER_SIZE - RTP_PAYLOAD_ROOM_SIZE;
            }

            uint8_t *data = buffer->data();
            data[0] = 0x80;
            if (lastPacket && mRTPCVOExtMap > 0) {
                data[0] |= 0x10;
            }
            data[1] = (lastPacket ? (1 << 7) : 0x00) | mPayloadType;  // M-bit
            data[2] = (mSeqNo >> 8) & 0xff;
            data[3] = mSeqNo & 0xff;
            data[4] = rtpTime >> 24;
            data[5] = (rtpTime >> 16) & 0xff;
            data[6] = (rtpTime >> 8) & 0xff;
            data[7] = rtpTime & 0xff;
            data[8] = mSourceID >> 24;
            data[9] = (mSourceID >> 16) & 0xff;
            data[10] = (mSourceID >> 8) & 0xff;
            data[11] = mSourceID & 0xff;

            int rtpExtIndex = 0;
            if (lastPacket && mRTPCVOExtMap > 0) {
                data[12] = 0xBE;
                data[13] = 0xDE;
                data[14] = 0x00;
                data[15] = 0x01;
                data[16] = (mRTPCVOExtMap << 4) | 0x0;
                data[17] = mRTPCVODegrees;
                data[18] = 0x0;
                data[19] = 0x0;
                rtpExtIndex = 8;
            }

            /*  H265 payload header is 16 bit
                 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |F|    Type   |  Layer ID | TID |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            */
            ALOGV("H265 payload header 0x%x %x", mediaData[0], mediaData[1]);
            // excludes Type from 1st byte of H265 payload header.
            data[12 + rtpExtIndex] = mediaData[0] & 0x81;
            // fills Type as FU (49 == 0x31)
            data[12 + rtpExtIndex] = data[12 + rtpExtIndex] | (0x31 << 1);
            data[13 + rtpExtIndex] = mediaData[1];

            ALOGV("H265 FU header 0x%x %x", data[12 + rtpExtIndex], data[13 + rtpExtIndex]);

            CHECK(!firstPacket || !lastPacket);
            /*
                FU INDICATOR HDR
                 0 1 2 3 4 5 6 7
                +-+-+-+-+-+-+-+-+
                |S|E|   Type    |
                +-+-+-+-+-+-+-+-+
            */

            data[14 + rtpExtIndex] =
                (firstPacket ? 0x80 : 0x00)
                | (lastPacket ? 0x40 : 0x00)
                | (nalType & H265_NALU_MASK);
            ALOGV("H265 FU indicator 0x%x", data[14]);

            memcpy(&data[15 + rtpExtIndex], &mediaData[offset], size);

            buffer->setRange(0, 15 + rtpExtIndex + size);

            send(buffer, false /* isRTCP */);

            ++mSeqNo;
            ++mNumRTPSent;
            mNumRTPOctetsSent += buffer->size() - (12 + rtpExtIndex);

            firstPacket = false;
            offset += size;
        }
    }
}

void ARTPWriter::sendAVCData(MediaBufferBase *mediaBuf) {
    // 12 bytes RTP header + 2 bytes for the FU-indicator and FU-header.
    CHECK_GE(kMaxPacketSize, 12u + 2u);

    int64_t timeUs;
    CHECK(mediaBuf->meta_data().findInt64(kKeyTime, &timeUs));

    sendSPSPPSIfIFrame(mediaBuf, timeUs);

    uint32_t rtpTime = getRtpTime(timeUs);

    CHECK(mediaBuf->range_length() > 0);
    const uint8_t *mediaData =
        (const uint8_t *)mediaBuf->data() + mediaBuf->range_offset();

    int32_t sps, pps;
    bool isSpsPps = false;
    if (mediaBuf->meta_data().findInt32(kKeySps, &sps) ||
            mediaBuf->meta_data().findInt32(kKeyPps, &pps)) {
        isSpsPps = true;
    }

    mTrafficRec->updateClock(ALooper::GetNowUs() / 1000);
    sp<ABuffer> buffer = new ABuffer(kMaxPacketSize);
    if (mediaBuf->range_length() + TCPIP_HEADER_SIZE + RTP_HEADER_SIZE + RTP_HEADER_EXT_SIZE
            + RTP_PAYLOAD_ROOM_SIZE <= buffer->capacity()) {
        // The data fits into a single packet
        uint8_t *data = buffer->data();
        data[0] = 0x80;
        if (mRTPCVOExtMap > 0) {
            data[0] |= 0x10;
        }
        if (isSpsPps) {
            data[1] = mPayloadType;  // Marker bit should not be set in case of sps/pps
        } else {
            data[1] = (1 << 7) | mPayloadType;
        }
        data[2] = (mSeqNo >> 8) & 0xff;
        data[3] = mSeqNo & 0xff;
        data[4] = rtpTime >> 24;
        data[5] = (rtpTime >> 16) & 0xff;
        data[6] = (rtpTime >> 8) & 0xff;
        data[7] = rtpTime & 0xff;
        data[8] = mSourceID >> 24;
        data[9] = (mSourceID >> 16) & 0xff;
        data[10] = (mSourceID >> 8) & 0xff;
        data[11] = mSourceID & 0xff;

        int rtpExtIndex = 0;
        if (mRTPCVOExtMap > 0) {
            /*
                0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               |       0xBE    |    0xDE       |           length=3            |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               |  ID   | L=0   |     data      |  ID   |  L=1  |   data...
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     ...data   |    0 (pad)    |    0 (pad)    |  ID   | L=3   |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               |                          data                                 |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


              In the one-byte header form of extensions, the 16-bit value required
              by the RTP specification for a header extension, labeled in the RTP
              specification as "defined by profile", takes the fixed bit pattern
              0xBEDE (the first version of this specification was written on the
              feast day of the Venerable Bede).
            */
            data[12] = 0xBE;
            data[13] = 0xDE;
            // put a length of RTP Extension.
            data[14] = 0x00;
            data[15] = 0x01;
            // put extmap of RTP assigned for CVO.
            data[16] = (mRTPCVOExtMap << 4) | 0x0;
            // put image degrees as per CVO specification.
            data[17] = mRTPCVODegrees;
            data[18] = 0x0;
            data[19] = 0x0;
            rtpExtIndex = 8;
        }

        memcpy(&data[12 + rtpExtIndex],
               mediaData, mediaBuf->range_length());

        buffer->setRange(0, mediaBuf->range_length() + (12 + rtpExtIndex));

        send(buffer, false /* isRTCP */);

        ++mSeqNo;
        ++mNumRTPSent;
        mNumRTPOctetsSent += buffer->size() - (12 + rtpExtIndex);
    } else {
        // FU-A

        unsigned nalType = mediaData[0] & H264_NALU_MASK;
        ALOGV("H264 nalType 0x%x, data[0]=0x%x", nalType, mediaData[0]);
        size_t offset = 1;

        bool firstPacket = true;
        while (offset < mediaBuf->range_length()) {
            size_t size = mediaBuf->range_length() - offset;
            bool lastPacket = true;
            if (size + TCPIP_HEADER_SIZE + RTP_HEADER_SIZE + RTP_HEADER_EXT_SIZE +
                    RTP_FU_HEADER_SIZE + RTP_PAYLOAD_ROOM_SIZE > buffer->capacity()) {
                lastPacket = false;
                size = buffer->capacity() - TCPIP_HEADER_SIZE - RTP_HEADER_SIZE -
                    RTP_HEADER_EXT_SIZE - RTP_FU_HEADER_SIZE - RTP_PAYLOAD_ROOM_SIZE;
            }

            uint8_t *data = buffer->data();
            data[0] = 0x80;
            if (lastPacket && mRTPCVOExtMap > 0) {
                data[0] |= 0x10;
            }
            data[1] = (lastPacket ? (1 << 7) : 0x00) | mPayloadType;  // M-bit
            data[2] = (mSeqNo >> 8) & 0xff;
            data[3] = mSeqNo & 0xff;
            data[4] = rtpTime >> 24;
            data[5] = (rtpTime >> 16) & 0xff;
            data[6] = (rtpTime >> 8) & 0xff;
            data[7] = rtpTime & 0xff;
            data[8] = mSourceID >> 24;
            data[9] = (mSourceID >> 16) & 0xff;
            data[10] = (mSourceID >> 8) & 0xff;
            data[11] = mSourceID & 0xff;

            int rtpExtIndex = 0;
            if (lastPacket && mRTPCVOExtMap > 0) {
                data[12] = 0xBE;
                data[13] = 0xDE;
                data[14] = 0x00;
                data[15] = 0x01;
                data[16] = (mRTPCVOExtMap << 4) | 0x0;
                data[17] = mRTPCVODegrees;
                data[18] = 0x0;
                data[19] = 0x0;
                rtpExtIndex = 8;
            }

            /*  H264 payload header is 8 bit
                 0 1 2 3 4 5 6 7
                +-+-+-+-+-+-+-+-+
                |F|NRI|  Type   |
                +-+-+-+-+-+-+-+-+
            */
            ALOGV("H264 payload header 0x%x", mediaData[0]);
            // excludes Type from 1st byte of H264 payload header.
            data[12 + rtpExtIndex] = mediaData[0] & 0xe0;
            // fills Type as FU (28 == 0x1C)
            data[12 + rtpExtIndex] = data[12 + rtpExtIndex] | 0x1C;

            CHECK(!firstPacket || !lastPacket);
            /*
                FU header
                 0 1 2 3 4 5 6 7
                +-+-+-+-+-+-+-+-+
                |S|E|R|  Type   |
                +-+-+-+-+-+-+-+-+
            */

            data[13 + rtpExtIndex] =
                (firstPacket ? 0x80 : 0x00)
                | (lastPacket ? 0x40 : 0x00)
                | (nalType & H264_NALU_MASK);
            ALOGV("H264 FU header 0x%x", data[13]);

            memcpy(&data[14 + rtpExtIndex], &mediaData[offset], size);

            buffer->setRange(0, 14 + rtpExtIndex + size);

            send(buffer, false /* isRTCP */);

            ++mSeqNo;
            ++mNumRTPSent;
            mNumRTPOctetsSent += buffer->size() - (12 + rtpExtIndex);

            firstPacket = false;
            offset += size;
        }
    }
}

void ARTPWriter::sendH263Data(MediaBufferBase *mediaBuf) {
    CHECK_GE(kMaxPacketSize, 12u + 2u);

    int64_t timeUs;
    CHECK(mediaBuf->meta_data().findInt64(kKeyTime, &timeUs));

    uint32_t rtpTime = getRtpTime(timeUs);

    const uint8_t *mediaData =
        (const uint8_t *)mediaBuf->data() + mediaBuf->range_offset();

    // hexdump(mediaData, mediaBuf->range_length());

    CHECK_EQ((unsigned)mediaData[0], 0u);
    CHECK_EQ((unsigned)mediaData[1], 0u);

    size_t offset = 2;
    size_t size = mediaBuf->range_length();

    while (offset < size) {
        sp<ABuffer> buffer = new ABuffer(kMaxPacketSize);
        // CHECK_LE(mediaBuf->range_length() -2 + 14, buffer->capacity());

        size_t remaining = size - offset;
        bool lastPacket = (remaining + 14 <= buffer->capacity());
        if (!lastPacket) {
            remaining = buffer->capacity() - 14;
        }

        uint8_t *data = buffer->data();
        data[0] = 0x80;
        data[1] = (lastPacket ? 0x80 : 0x00) | mPayloadType;  // M-bit
        data[2] = (mSeqNo >> 8) & 0xff;
        data[3] = mSeqNo & 0xff;
        data[4] = rtpTime >> 24;
        data[5] = (rtpTime >> 16) & 0xff;
        data[6] = (rtpTime >> 8) & 0xff;
        data[7] = rtpTime & 0xff;
        data[8] = mSourceID >> 24;
        data[9] = (mSourceID >> 16) & 0xff;
        data[10] = (mSourceID >> 8) & 0xff;
        data[11] = mSourceID & 0xff;

        data[12] = (offset == 2) ? 0x04 : 0x00;  // P=?, V=0
        data[13] = 0x00;  // PLEN = PEBIT = 0

        memcpy(&data[14], &mediaData[offset], remaining);
        offset += remaining;

        buffer->setRange(0, remaining + 14);

        send(buffer, false /* isRTCP */);

        ++mSeqNo;
        ++mNumRTPSent;
        mNumRTPOctetsSent += buffer->size() - 12;
    }
}

void ARTPWriter::updateCVODegrees(int32_t cvoDegrees) {
    Mutex::Autolock autoLock(mLock);
    mRTPCVODegrees = cvoDegrees;
}

void ARTPWriter::updatePayloadType(int32_t payloadType) {
    Mutex::Autolock autoLock(mLock);
    mPayloadType = payloadType;
}

/*
 * This function will set socket option in IP header
 */
void ARTPWriter::updateSocketOpt() {
    /*
     * 0     1     2     3     4     5     6     7
     * +-----+-----+-----+-----+-----+-----+-----+-----+
     * |          DS FIELD, DSCP           | ECN FIELD |
     * +-----+-----+-----+-----+-----+-----+-----+-----+
     */
    int sockOpt = mRtpLayer3Dscp ^ mRtpSockOptEcn;
    ALOGD("Update socket opt with sockopt=%d, mRtpLayer3Dscp=%d, mRtpSockOptEcn=%d",
                sockOpt, mRtpLayer3Dscp, mRtpSockOptEcn);

    /* sockOpt will be used to set socket option in IP header */
    if (setsockopt(mRTPSocket, mIsIPv6 ? IPPROTO_IPV6 : IPPROTO_IP, mIsIPv6 ? IPV6_TCLASS : IP_TOS,
                (int *)&sockOpt, sizeof(sockOpt)) < 0) {
        ALOGE("failed to set sockopt on rtpsock. err=%s", strerror(errno));
    } else {
        ALOGD("successfully set sockopt. opt=%d", sockOpt);
        setsockopt(mRTCPSocket, mIsIPv6 ? IPPROTO_IPV6 : IPPROTO_IP, mIsIPv6 ? IPV6_TCLASS : IP_TOS,
                (int *)&sockOpt, sizeof(sockOpt));
        ALOGD("successfully set sockopt rtcpsock. opt=%d", sockOpt);
    }
}

void ARTPWriter::updateSocketNetwork(int64_t socketNetwork) {
    mRTPSockNetwork = (net_handle_t)socketNetwork;
    ALOGI("trying to bind rtp socket(%d) to network(%llu).",
                mRTPSocket, (unsigned long long)mRTPSockNetwork);

    int result = android_setsocknetwork(mRTPSockNetwork, mRTPSocket);
    if (result != 0) {
        ALOGW("failed(%d) to bind rtp socket(%d) to network(%llu)",
                result, mRTPSocket, (unsigned long long)mRTPSockNetwork);
    }
    result = android_setsocknetwork(mRTPSockNetwork, mRTCPSocket);
    if (result != 0) {
        ALOGW("failed(%d) to bind rtcp socket(%d) to network(%llu)",
                result, mRTCPSocket, (unsigned long long)mRTPSockNetwork);
    }
    ALOGI("done. bind rtp socket(%d) to network(%llu)",
                mRTPSocket, (unsigned long long)mRTPSockNetwork);
}

uint32_t ARTPWriter::getSequenceNum() {
    return mSeqNo;
}

uint64_t ARTPWriter::getAccumulativeBytes() {
    return mTrafficRec->readBytesForTotal();
}

static size_t getFrameSize(bool isWide, unsigned FT) {
    static const size_t kFrameSizeNB[8] = {
        95, 103, 118, 134, 148, 159, 204, 244
    };
    static const size_t kFrameSizeWB[9] = {
        132, 177, 253, 285, 317, 365, 397, 461, 477
    };

    size_t frameSize = isWide ? kFrameSizeWB[FT] : kFrameSizeNB[FT];

    // Round up bits to bytes and add 1 for the header byte.
    frameSize = (frameSize + 7) / 8 + 1;

    return frameSize;
}

void ARTPWriter::sendAMRData(MediaBufferBase *mediaBuf) {
    const uint8_t *mediaData =
        (const uint8_t *)mediaBuf->data() + mediaBuf->range_offset();

    size_t mediaLength = mediaBuf->range_length();

    CHECK_GE(kMaxPacketSize, 12u + 1u + mediaLength);

    const bool isWide = (mMode == AMR_WB);

    int64_t timeUs;
    CHECK(mediaBuf->meta_data().findInt64(kKeyTime, &timeUs));
    uint32_t rtpTime = getRtpTime(timeUs);

    // hexdump(mediaData, mediaLength);

    Vector<uint8_t> tableOfContents;
    size_t srcOffset = 0;
    while (srcOffset < mediaLength) {
        uint8_t toc = mediaData[srcOffset];

        unsigned FT = (toc >> 3) & 0x0f;
        CHECK((isWide && FT <= 8) || (!isWide && FT <= 7));

        tableOfContents.push(toc);
        srcOffset += getFrameSize(isWide, FT);
    }
    CHECK_EQ(srcOffset, mediaLength);

    sp<ABuffer> buffer = new ABuffer(kMaxPacketSize);
    CHECK_LE(mediaLength + 12 + 1, buffer->capacity());

    // The data fits into a single packet
    uint8_t *data = buffer->data();
    data[0] = 0x80;
    data[1] = mPayloadType;
    if (mNumRTPSent == 0) {
        // Signal start of talk-spurt.
        data[1] |= 0x80;  // M-bit
    }
    data[2] = (mSeqNo >> 8) & 0xff;
    data[3] = mSeqNo & 0xff;
    data[4] = rtpTime >> 24;
    data[5] = (rtpTime >> 16) & 0xff;
    data[6] = (rtpTime >> 8) & 0xff;
    data[7] = rtpTime & 0xff;
    data[8] = mSourceID >> 24;
    data[9] = (mSourceID >> 16) & 0xff;
    data[10] = (mSourceID >> 8) & 0xff;
    data[11] = mSourceID & 0xff;

    data[12] = 0xf0;  // CMR=15, RR=0

    size_t dstOffset = 13;

    for (size_t i = 0; i < tableOfContents.size(); ++i) {
        uint8_t toc = tableOfContents[i];

        if (i + 1 < tableOfContents.size()) {
            toc |= 0x80;
        } else {
            toc &= ~0x80;
        }

        data[dstOffset++] = toc;
    }

    srcOffset = 0;
    for (size_t i = 0; i < tableOfContents.size(); ++i) {
        uint8_t toc = tableOfContents[i];
        unsigned FT = (toc >> 3) & 0x0f;
        size_t frameSize = getFrameSize(isWide, FT);

        ++srcOffset;  // skip toc
        memcpy(&data[dstOffset], &mediaData[srcOffset], frameSize - 1);
        srcOffset += frameSize - 1;
        dstOffset += frameSize - 1;
    }

    buffer->setRange(0, dstOffset);

    send(buffer, false /* isRTCP */);

    ++mSeqNo;
    ++mNumRTPSent;
    mNumRTPOctetsSent += buffer->size() - 12;
}

void ARTPWriter::makeSocketPairAndBind(String8& localIp, int localPort,
        String8& remoteIp, int remotePort) {
    static char kSomeone[16] = "someone@";
    int nameLength = strlen(kSomeone);
    memcpy(kCNAME, kSomeone, nameLength);
    memcpy(kCNAME + nameLength, localIp.c_str(), localIp.length() + 1);

    if (localIp.contains(":"))
        mIsIPv6 = true;
    else
        mIsIPv6 = false;

    mRTPSocket = socket(mIsIPv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    CHECK_GE(mRTPSocket, 0);
    mRTCPSocket = socket(mIsIPv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    CHECK_GE(mRTCPSocket, 0);

    int sockopt = 1;
    setsockopt(mRTPSocket, SOL_SOCKET, SO_REUSEADDR, (int *)&sockopt, sizeof(sockopt));
    setsockopt(mRTCPSocket, SOL_SOCKET, SO_REUSEADDR, (int *)&sockopt, sizeof(sockopt));

    if (mIsIPv6) {
        memset(&mLocalAddr6, 0, sizeof(mLocalAddr6));
        memset(&mRTPAddr6, 0, sizeof(mRTPAddr6));
        memset(&mRTCPAddr6, 0, sizeof(mRTCPAddr6));

        mLocalAddr6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, localIp.c_str(), &mLocalAddr6.sin6_addr);
        mLocalAddr6.sin6_port = htons((uint16_t)localPort);

        mRTPAddr6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, remoteIp.c_str(), &mRTPAddr6.sin6_addr);
        mRTPAddr6.sin6_port = htons((uint16_t)remotePort);

        mRTCPAddr6 = mRTPAddr6;
        mRTCPAddr6.sin6_port = htons((uint16_t)(remotePort + 1));
    } else {
        memset(&mLocalAddr, 0, sizeof(mLocalAddr));
        memset(&mRTPAddr, 0, sizeof(mRTPAddr));
        memset(&mRTCPAddr, 0, sizeof(mRTCPAddr));

        mLocalAddr.sin_family = AF_INET;
        mLocalAddr.sin_addr.s_addr = inet_addr(localIp.c_str());
        mLocalAddr.sin_port = htons((uint16_t)localPort);

        mRTPAddr.sin_family = AF_INET;
        mRTPAddr.sin_addr.s_addr = inet_addr(remoteIp.c_str());
        mRTPAddr.sin_port = htons((uint16_t)remotePort);

        mRTCPAddr = mRTPAddr;
        mRTCPAddr.sin_port = htons((uint16_t)(remotePort + 1));
    }

    struct sockaddr *localAddr = mIsIPv6 ?
        (struct sockaddr*)&mLocalAddr6 : (struct sockaddr*)&mLocalAddr;

    int sizeSockSt = mIsIPv6 ? sizeof(mLocalAddr6) : sizeof(mLocalAddr);

    if (bind(mRTPSocket, localAddr, sizeSockSt) == -1) {
        ALOGE("failed to bind rtp %s:%d err=%s", localIp.c_str(), localPort, strerror(errno));
    } else {
        ALOGD("succeed to bind rtp %s:%d", localIp.c_str(), localPort);
    }

    if (mIsIPv6)
        mLocalAddr6.sin6_port = htons((uint16_t)(localPort + 1));
    else
        mLocalAddr.sin_port = htons((uint16_t)(localPort + 1));

    if (bind(mRTCPSocket, localAddr, sizeSockSt) == -1) {
        ALOGE("failed to bind rtcp %s:%d err=%s", localIp.c_str(), localPort + 1, strerror(errno));
    } else {
        ALOGD("succeed to bind rtcp %s:%d", localIp.c_str(), localPort + 1);
    }
}

// TODO : Develop more advanced moderator based on AS & TMMBR value
void ARTPWriter::ModerateInstantTraffic(uint32_t samplePeriod, uint32_t limitBytes) {
    unsigned int bytes =  mTrafficRec->readBytesForLastPeriod(samplePeriod);
    if (bytes > limitBytes) {
        ALOGI("Nuclear moderator. #seq = %d \t\t %d bits / 10ms",
              mSeqNo, bytes * 8);
        usleep(4000);
        mTrafficRec->updateClock(ALooper::GetNowUs() / 1000);
    }
}

}  // namespace android
