/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef _MTP_FFS_HANDLE_H
#define _MTP_FFS_HANDLE_H

#include <android-base/unique_fd.h>
#include <linux/aio_abi.h>
#include <mutex>
#include <sys/poll.h>
#include <time.h>
#include <thread>
#include <vector>

#include <IMtpHandle.h>

namespace android {

constexpr char FFS_MTP_EP0[] = "/dev/usb-ffs/mtp/ep0";

constexpr int NUM_IO_BUFS = 2;

struct io_buffer {
    std::vector<struct iocb> iocbs;     // Holds memory for all iocbs. Not used directly.
    std::vector<struct iocb*> iocb;     // Pointers to individual iocbs, for syscalls
    std::vector<unsigned char> bufs;    // A large buffer, used with filesystem io
    std::vector<unsigned char*> buf;    // Pointers within the larger buffer, for syscalls
    unsigned actual;                    // The number of buffers submitted for this request
};

template <class T> class MtpFfsHandleTest;
template <class T> class MtpFfsHandleTest_testControl_Test;

class MtpFfsHandle : public IMtpHandle {
    template <class T> friend class MtpFfsHandleTest;
    template <class T> friend class MtpFfsHandleTest_testControl_Test;
protected:
    bool initFunctionfs();
    bool writeDescriptors();
    void closeConfig();
    void closeEndpoints();
    void advise(int fd);
    int handleControlRequest(const struct usb_ctrlrequest *request);
    int doAsync(void* data, size_t len, bool read);
    int handleEvent();
    void cancelTransaction();
    void doSendEvent(mtp_event me);
    bool openEndpoints();

    static int getPacketSize(int ffs_fd);

    bool mPtp;
    bool mCanceled;

    std::timed_mutex mLock; // protects configure() vs main loop

    android::base::unique_fd mControl;
    // "in" from the host's perspective => sink for mtp server
    android::base::unique_fd mBulkIn;
    // "out" from the host's perspective => source for mtp server
    android::base::unique_fd mBulkOut;
    android::base::unique_fd mIntr;

    aio_context_t mCtx;

    android::base::unique_fd mEventFd;
    struct pollfd mPollFds[2];

    struct io_buffer mIobuf[NUM_IO_BUFS];

    // Submit an io request of given length. Return amount submitted or -1.
    int iobufSubmit(struct io_buffer *buf, int fd, unsigned length, bool read);

    // Cancel submitted requests from start to end in the given array. Return 0 or -1.
    int cancelEvents(struct iocb **iocb, struct io_event *events, unsigned start, unsigned end);

    // Wait for at minimum the given number of events. Returns the amount of data in the returned
    // events. Increments counter by the number of events returned.
    int waitEvents(struct io_buffer *buf, int min_events, struct io_event *events, int *counter);

public:
    int read(void *data, size_t len) override;
    int write(const void *data, size_t len) override;

    int receiveFile(mtp_file_range mfr, bool zero_packet) override;
    int sendFile(mtp_file_range mfr) override;
    int sendEvent(mtp_event me) override;

    int start() override;
    void close() override;

    int configure(bool ptp) override;

    MtpFfsHandle();
    ~MtpFfsHandle();
};

struct mtp_data_header {
    /* length of packet, including this header */
    __le32 length;
    /* container type (2 for data packet) */
    __le16 type;
    /* MTP command code */
    __le16 command;
    /* MTP transaction ID */
    __le32 transaction_id;
};

} // namespace android

#endif // _MTP_FFS_HANDLE_H

