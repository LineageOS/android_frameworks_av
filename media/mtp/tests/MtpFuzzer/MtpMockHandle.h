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

#ifndef _MTP_MOCK_HANDLE_H
#define _MTP_MOCK_HANDLE_H

#include <vector>

typedef std::vector<uint8_t> packet_t;

namespace android {
class MtpMockHandle : public IMtpHandle {
private:
    size_t mPacketNumber;
    size_t mPacketOffset;
    std::vector<packet_t> mPackets;

public:
    MtpMockHandle() : mPacketNumber(0), mPacketOffset(0) {}

    void add_packet(packet_t pkt) { mPackets.push_back(pkt); }

    // Return number of bytes read/written, or -1 and errno is set
    int read(void *data, size_t len) {
        if (mPacketNumber >= mPackets.size()) {
            return 0;
        } else {
            int readAmt = 0;
            packet_t pkt = mPackets[mPacketNumber];

            ALOGD("%s: sz %zu, pkt %zu+%zu/%zu\n", __func__, len, mPacketNumber, mPacketOffset,
                  pkt.size());

            // packet is bigger than what the caller can handle,
            if (pkt.size() - mPacketOffset > len) {
                memcpy(data, pkt.data() + mPacketOffset, len);

                mPacketOffset += len;
                readAmt = len;
                // packet is equal or smaller than the caller buffer
            } else {
                memcpy(data, pkt.data() + mPacketOffset, pkt.size() - mPacketOffset);

                mPacketNumber++;
                mPacketOffset = 0;
                readAmt = pkt.size() - mPacketOffset;
            }

            return readAmt;
        }
    }
    int write(const void *data, size_t len) {
        ALOGD("MockHandle %s: len=%zu\n", __func__, len);
        // fake the write
        return len;
    }

    // Return 0 if send/receive is successful, or -1 and errno is set
    int receiveFile(mtp_file_range mfr, bool zero_packet) {
        ALOGD("MockHandle %s\n", __func__);
        return 0;
    }
    int sendFile(mtp_file_range mfr) {
        ALOGD("MockHandle %s\n", __func__);
        return 0;
    }
    int sendEvent(mtp_event me) {
        ALOGD("MockHandle %s: len=%zu\n", __func__, me.length);
        return 0;
    }

    // Return 0 if operation is successful, or -1 else
    int start(bool ptp) { return 0; }

    void close() {}

    virtual ~MtpMockHandle() {}
};
}; // namespace android

#endif // _MTP_MOCK_HANDLE_H
