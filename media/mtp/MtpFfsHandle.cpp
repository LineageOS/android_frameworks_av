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

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <asyncio/AsyncIO.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/endian.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "PosixAsyncIO.h"
#include "MtpFfsHandle.h"
#include "mtp.h"

namespace {

constexpr char FFS_MTP_EP_IN[] = "/dev/usb-ffs/mtp/ep1";
constexpr char FFS_MTP_EP_OUT[] = "/dev/usb-ffs/mtp/ep2";
constexpr char FFS_MTP_EP_INTR[] = "/dev/usb-ffs/mtp/ep3";

constexpr int MAX_PACKET_SIZE_FS = 64;
constexpr int MAX_PACKET_SIZE_HS = 512;
constexpr int MAX_PACKET_SIZE_SS = 1024;
constexpr int MAX_PACKET_SIZE_EV = 28;

constexpr unsigned AIO_BUFS_MAX = 128;
constexpr unsigned AIO_BUF_LEN = 16384;

constexpr unsigned FFS_NUM_EVENTS = 5;

constexpr unsigned MAX_FILE_CHUNK_SIZE = AIO_BUFS_MAX * AIO_BUF_LEN;

constexpr uint32_t MAX_MTP_FILE_SIZE = 0xFFFFFFFF;

struct timespec ZERO_TIMEOUT = { 0, 0 };

struct func_desc {
    struct usb_interface_descriptor intf;
    struct usb_endpoint_descriptor_no_audio sink;
    struct usb_endpoint_descriptor_no_audio source;
    struct usb_endpoint_descriptor_no_audio intr;
} __attribute__((packed));

struct ss_func_desc {
    struct usb_interface_descriptor intf;
    struct usb_endpoint_descriptor_no_audio sink;
    struct usb_ss_ep_comp_descriptor sink_comp;
    struct usb_endpoint_descriptor_no_audio source;
    struct usb_ss_ep_comp_descriptor source_comp;
    struct usb_endpoint_descriptor_no_audio intr;
    struct usb_ss_ep_comp_descriptor intr_comp;
} __attribute__((packed));

struct desc_v1 {
    struct usb_functionfs_descs_head_v1 {
        __le32 magic;
        __le32 length;
        __le32 fs_count;
        __le32 hs_count;
    } __attribute__((packed)) header;
    struct func_desc fs_descs, hs_descs;
} __attribute__((packed));

struct desc_v2 {
    struct usb_functionfs_descs_head_v2 header;
    // The rest of the structure depends on the flags in the header.
    __le32 fs_count;
    __le32 hs_count;
    __le32 ss_count;
    __le32 os_count;
    struct func_desc fs_descs, hs_descs;
    struct ss_func_desc ss_descs;
    struct usb_os_desc_header os_header;
    struct usb_ext_compat_desc os_desc;
} __attribute__((packed));

const struct usb_interface_descriptor mtp_interface_desc = {
    .bLength = USB_DT_INTERFACE_SIZE,
    .bDescriptorType = USB_DT_INTERFACE,
    .bInterfaceNumber = 0,
    .bNumEndpoints = 3,
    .bInterfaceClass = USB_CLASS_STILL_IMAGE,
    .bInterfaceSubClass = 1,
    .bInterfaceProtocol = 1,
    .iInterface = 1,
};

const struct usb_interface_descriptor ptp_interface_desc = {
    .bLength = USB_DT_INTERFACE_SIZE,
    .bDescriptorType = USB_DT_INTERFACE,
    .bInterfaceNumber = 0,
    .bNumEndpoints = 3,
    .bInterfaceClass = USB_CLASS_STILL_IMAGE,
    .bInterfaceSubClass = 1,
    .bInterfaceProtocol = 1,
};

const struct usb_endpoint_descriptor_no_audio fs_sink = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 1 | USB_DIR_IN,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_FS,
};

const struct usb_endpoint_descriptor_no_audio fs_source = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 2 | USB_DIR_OUT,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_FS,
};

const struct usb_endpoint_descriptor_no_audio intr = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 3 | USB_DIR_IN,
    .bmAttributes = USB_ENDPOINT_XFER_INT,
    .wMaxPacketSize = MAX_PACKET_SIZE_EV,
    .bInterval = 6,
};

const struct usb_endpoint_descriptor_no_audio hs_sink = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 1 | USB_DIR_IN,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_HS,
};

const struct usb_endpoint_descriptor_no_audio hs_source = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 2 | USB_DIR_OUT,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_HS,
};

const struct usb_endpoint_descriptor_no_audio ss_sink = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 1 | USB_DIR_IN,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_SS,
};

const struct usb_endpoint_descriptor_no_audio ss_source = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 2 | USB_DIR_OUT,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_SS,
};

const struct usb_ss_ep_comp_descriptor ss_sink_comp = {
    .bLength = sizeof(ss_sink_comp),
    .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
    .bMaxBurst = 6,
};

const struct usb_ss_ep_comp_descriptor ss_source_comp = {
    .bLength = sizeof(ss_source_comp),
    .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
    .bMaxBurst = 6,
};

const struct usb_ss_ep_comp_descriptor ss_intr_comp = {
    .bLength = sizeof(ss_intr_comp),
    .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
};

const struct func_desc mtp_fs_descriptors = {
    .intf = mtp_interface_desc,
    .sink = fs_sink,
    .source = fs_source,
    .intr = intr,
};

const struct func_desc mtp_hs_descriptors = {
    .intf = mtp_interface_desc,
    .sink = hs_sink,
    .source = hs_source,
    .intr = intr,
};

const struct ss_func_desc mtp_ss_descriptors = {
    .intf = mtp_interface_desc,
    .sink = ss_sink,
    .sink_comp = ss_sink_comp,
    .source = ss_source,
    .source_comp = ss_source_comp,
    .intr = intr,
    .intr_comp = ss_intr_comp,
};

const struct func_desc ptp_fs_descriptors = {
    .intf = ptp_interface_desc,
    .sink = fs_sink,
    .source = fs_source,
    .intr = intr,
};

const struct func_desc ptp_hs_descriptors = {
    .intf = ptp_interface_desc,
    .sink = hs_sink,
    .source = hs_source,
    .intr = intr,
};

const struct ss_func_desc ptp_ss_descriptors = {
    .intf = ptp_interface_desc,
    .sink = ss_sink,
    .sink_comp = ss_sink_comp,
    .source = ss_source,
    .source_comp = ss_source_comp,
    .intr = intr,
    .intr_comp = ss_intr_comp,
};

#define STR_INTERFACE "MTP"
const struct {
    struct usb_functionfs_strings_head header;
    struct {
        __le16 code;
        const char str1[sizeof(STR_INTERFACE)];
    } __attribute__((packed)) lang0;
} __attribute__((packed)) strings = {
    .header = {
        .magic = htole32(FUNCTIONFS_STRINGS_MAGIC),
        .length = htole32(sizeof(strings)),
        .str_count = htole32(1),
        .lang_count = htole32(1),
    },
    .lang0 = {
        .code = htole16(0x0409),
        .str1 = STR_INTERFACE,
    },
};

struct usb_os_desc_header mtp_os_desc_header = {
    .interface = htole32(1),
    .dwLength = htole32(sizeof(usb_os_desc_header) + sizeof(usb_ext_compat_desc)),
    .bcdVersion = htole16(1),
    .wIndex = htole16(4),
    .bCount = htole16(1),
    .Reserved = htole16(0),
};

struct usb_ext_compat_desc mtp_os_desc_compat = {
    .bFirstInterfaceNumber = 0,
    .Reserved1 = htole32(1),
    .CompatibleID = { 'M', 'T', 'P' },
    .SubCompatibleID = {0},
    .Reserved2 = {0},
};

struct usb_ext_compat_desc ptp_os_desc_compat = {
    .bFirstInterfaceNumber = 0,
    .Reserved1 = htole32(1),
    .CompatibleID = { 'P', 'T', 'P' },
    .SubCompatibleID = {0},
    .Reserved2 = {0},
};

struct mtp_device_status {
    uint16_t  wLength;
    uint16_t  wCode;
};

} // anonymous namespace

namespace android {

int MtpFfsHandle::getPacketSize(int ffs_fd) {
    struct usb_endpoint_descriptor desc;
    if (ioctl(ffs_fd, FUNCTIONFS_ENDPOINT_DESC, reinterpret_cast<unsigned long>(&desc))) {
        PLOG(ERROR) << "Could not get FFS bulk-in descriptor";
        return MAX_PACKET_SIZE_HS;
    } else {
        return desc.wMaxPacketSize;
    }
}

MtpFfsHandle::MtpFfsHandle() {}

MtpFfsHandle::~MtpFfsHandle() {}

void MtpFfsHandle::closeEndpoints() {
    mIntr.reset();
    mBulkIn.reset();
    mBulkOut.reset();
}

bool MtpFfsHandle::openEndpoints() {
    if (mBulkIn < 0) {
        mBulkIn.reset(TEMP_FAILURE_RETRY(open(FFS_MTP_EP_IN, O_RDWR)));
        if (mBulkIn < 0) {
            PLOG(ERROR) << FFS_MTP_EP_IN << ": cannot open bulk in ep";
            return false;
        }
    }

    if (mBulkOut < 0) {
        mBulkOut.reset(TEMP_FAILURE_RETRY(open(FFS_MTP_EP_OUT, O_RDWR)));
        if (mBulkOut < 0) {
            PLOG(ERROR) << FFS_MTP_EP_OUT << ": cannot open bulk out ep";
            return false;
        }
    }

    if (mIntr < 0) {
        mIntr.reset(TEMP_FAILURE_RETRY(open(FFS_MTP_EP_INTR, O_RDWR)));
        if (mIntr < 0) {
            PLOG(ERROR) << FFS_MTP_EP_INTR << ": cannot open intr ep";
            return false;
        }
    }
    return true;
}

void MtpFfsHandle::advise(int fd) {
    for (unsigned i = 0; i < NUM_IO_BUFS; i++) {
        if (posix_madvise(mIobuf[i].bufs.data(), MAX_FILE_CHUNK_SIZE,
                POSIX_MADV_SEQUENTIAL | POSIX_MADV_WILLNEED) < 0)
            PLOG(ERROR) << "Failed to madvise";
    }
    if (posix_fadvise(fd, 0, 0,
                POSIX_FADV_SEQUENTIAL | POSIX_FADV_NOREUSE | POSIX_FADV_WILLNEED) < 0)
        PLOG(ERROR) << "Failed to fadvise";
}

bool MtpFfsHandle::initFunctionfs() {
    ssize_t ret;
    struct desc_v1 v1_descriptor;
    struct desc_v2 v2_descriptor;

    v2_descriptor.header.magic = htole32(FUNCTIONFS_DESCRIPTORS_MAGIC_V2);
    v2_descriptor.header.length = htole32(sizeof(v2_descriptor));
    v2_descriptor.header.flags = FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC |
                                 FUNCTIONFS_HAS_SS_DESC | FUNCTIONFS_HAS_MS_OS_DESC;
    v2_descriptor.fs_count = 4;
    v2_descriptor.hs_count = 4;
    v2_descriptor.ss_count = 7;
    v2_descriptor.os_count = 1;
    v2_descriptor.fs_descs = mPtp ? ptp_fs_descriptors : mtp_fs_descriptors;
    v2_descriptor.hs_descs = mPtp ? ptp_hs_descriptors : mtp_hs_descriptors;
    v2_descriptor.ss_descs = mPtp ? ptp_ss_descriptors : mtp_ss_descriptors;
    v2_descriptor.os_header = mtp_os_desc_header;
    v2_descriptor.os_desc = mPtp ? ptp_os_desc_compat : mtp_os_desc_compat;

    if (mControl < 0) { // might have already done this before
        mControl.reset(TEMP_FAILURE_RETRY(open(FFS_MTP_EP0, O_RDWR)));
        if (mControl < 0) {
            PLOG(ERROR) << FFS_MTP_EP0 << ": cannot open control endpoint";
            goto err;
        }

        ret = TEMP_FAILURE_RETRY(::write(mControl, &v2_descriptor, sizeof(v2_descriptor)));
        if (ret < 0) {
            v1_descriptor.header.magic = htole32(FUNCTIONFS_DESCRIPTORS_MAGIC);
            v1_descriptor.header.length = htole32(sizeof(v1_descriptor));
            v1_descriptor.header.fs_count = 4;
            v1_descriptor.header.hs_count = 4;
            v1_descriptor.fs_descs = mPtp ? ptp_fs_descriptors : mtp_fs_descriptors;
            v1_descriptor.hs_descs = mPtp ? ptp_hs_descriptors : mtp_hs_descriptors;
            PLOG(ERROR) << FFS_MTP_EP0 << "Switching to V1 descriptor format";
            ret = TEMP_FAILURE_RETRY(::write(mControl, &v1_descriptor, sizeof(v1_descriptor)));
            if (ret < 0) {
                PLOG(ERROR) << FFS_MTP_EP0 << "Writing descriptors failed";
                goto err;
            }
        }
        ret = TEMP_FAILURE_RETRY(::write(mControl, &strings, sizeof(strings)));
        if (ret < 0) {
            PLOG(ERROR) << FFS_MTP_EP0 << "Writing strings failed";
            goto err;
        }
    }

    return true;

err:
    closeConfig();
    return false;
}

void MtpFfsHandle::closeConfig() {
    mControl.reset();
}

int MtpFfsHandle::doAsync(void* data, size_t len, bool read) {
    struct io_event ioevs[1];
    if (len > AIO_BUF_LEN) {
        LOG(ERROR) << "Mtp read/write too large " << len;
        errno = EINVAL;
        return -1;
    }
    mIobuf[0].buf[0] = reinterpret_cast<unsigned char*>(data);
    if (iobufSubmit(&mIobuf[0], read ? mBulkOut : mBulkIn, len, read) == -1)
        return -1;
    int ret = waitEvents(&mIobuf[0], 1, ioevs, nullptr);
    mIobuf[0].buf[0] = mIobuf[0].bufs.data();
    return ret;
}

int MtpFfsHandle::read(void* data, size_t len) {
    return doAsync(data, len, true);
}

int MtpFfsHandle::write(const void* data, size_t len) {
    return doAsync(const_cast<void*>(data), len, false);
}

int MtpFfsHandle::handleEvent() {

    std::vector<usb_functionfs_event> events(FFS_NUM_EVENTS);
    usb_functionfs_event *event = events.data();
    int nbytes = TEMP_FAILURE_RETRY(::read(mControl, event,
                events.size() * sizeof(usb_functionfs_event)));
    if (nbytes == -1) {
        return -1;
    }
    int ret = 0;
    for (size_t n = nbytes / sizeof *event; n; --n, ++event) {
        switch (event->type) {
        case FUNCTIONFS_BIND:
        case FUNCTIONFS_ENABLE:
        case FUNCTIONFS_RESUME:
            ret = 0;
            errno = 0;
            break;
        case FUNCTIONFS_SUSPEND:
        case FUNCTIONFS_UNBIND:
        case FUNCTIONFS_DISABLE:
            errno = ESHUTDOWN;
            ret = -1;
            break;
        case FUNCTIONFS_SETUP:
            if (handleControlRequest(&event->u.setup) == -1)
                ret = -1;
            break;
        default:
            LOG(ERROR) << "Mtp Event " << event->type << " (unknown)";
        }
    }
    return ret;
}

int MtpFfsHandle::handleControlRequest(const struct usb_ctrlrequest *setup) {
    uint8_t type = setup->bRequestType;
    uint8_t code = setup->bRequest;
    uint16_t length = setup->wLength;
    uint16_t index = setup->wIndex;
    uint16_t value = setup->wValue;
    std::vector<char> buf;
    buf.resize(length);
    int ret = 0;

    if (!(type & USB_DIR_IN)) {
        if (::read(mControl, buf.data(), length) != length) {
            PLOG(ERROR) << "Mtp error ctrlreq read data";
        }
    }

    if ((type & USB_TYPE_MASK) == USB_TYPE_CLASS && index == 0 && value == 0) {
        switch(code) {
        case MTP_REQ_RESET:
        case MTP_REQ_CANCEL:
            errno = ECANCELED;
            ret = -1;
            break;
        case MTP_REQ_GET_DEVICE_STATUS:
        {
            if (length < sizeof(struct mtp_device_status) + 4) {
                errno = EINVAL;
                return -1;
            }
            struct mtp_device_status *st = reinterpret_cast<struct mtp_device_status*>(buf.data());
            st->wLength = htole16(sizeof(st));
            if (mCanceled) {
                st->wLength += 4;
                st->wCode = MTP_RESPONSE_TRANSACTION_CANCELLED;
                uint16_t *endpoints = reinterpret_cast<uint16_t*>(st + 1);
                endpoints[0] = ioctl(mBulkIn, FUNCTIONFS_ENDPOINT_REVMAP);
                endpoints[1] = ioctl(mBulkOut, FUNCTIONFS_ENDPOINT_REVMAP);
                mCanceled = false;
            } else {
                st->wCode = MTP_RESPONSE_OK;
            }
            length = st->wLength;
            break;
        }
        default:
            LOG(ERROR) << "Unrecognized Mtp class request! " << code;
        }
    } else {
        LOG(ERROR) << "Unrecognized request type " << type;
    }

    if (type & USB_DIR_IN) {
        if (::write(mControl, buf.data(), length) != length) {
            PLOG(ERROR) << "Mtp error ctrlreq write data";
        }
    }
    return 0;
}

int MtpFfsHandle::start() {
    mLock.lock();

    if (!openEndpoints())
        return -1;

    for (unsigned i = 0; i < NUM_IO_BUFS; i++) {
        mIobuf[i].bufs.resize(MAX_FILE_CHUNK_SIZE);
        mIobuf[i].iocb.resize(AIO_BUFS_MAX);
        mIobuf[i].iocbs.resize(AIO_BUFS_MAX);
        mIobuf[i].buf.resize(AIO_BUFS_MAX);
        for (unsigned j = 0; j < AIO_BUFS_MAX; j++) {
            mIobuf[i].buf[j] = mIobuf[i].bufs.data() + j * AIO_BUF_LEN;
            mIobuf[i].iocb[j] = &mIobuf[i].iocbs[j];
        }
    }

    memset(&mCtx, 0, sizeof(mCtx));
    if (io_setup(AIO_BUFS_MAX, &mCtx) < 0) {
        PLOG(ERROR) << "unable to setup aio";
        return -1;
    }
    mEventFd.reset(eventfd(0, EFD_NONBLOCK));
    mPollFds[0].fd = mControl;
    mPollFds[0].events = POLLIN;
    mPollFds[1].fd = mEventFd;
    mPollFds[1].events = POLLIN;

    mCanceled = false;
    return 0;
}

int MtpFfsHandle::configure(bool usePtp) {
    // Wait till previous server invocation has closed
    if (!mLock.try_lock_for(std::chrono::milliseconds(1000))) {
        LOG(ERROR) << "MtpServer was unable to get configure lock";
        return -1;
    }
    int ret = 0;

    // If ptp is changed, the configuration must be rewritten
    if (mPtp != usePtp) {
        closeEndpoints();
        closeConfig();
    }
    mPtp = usePtp;

    if (!initFunctionfs()) {
        ret = -1;
    }

    mLock.unlock();
    return ret;
}

void MtpFfsHandle::close() {
    io_destroy(mCtx);
    closeEndpoints();
    mLock.unlock();
}

int MtpFfsHandle::waitEvents(struct io_buffer *buf, int min_events, struct io_event *events,
        int *counter) {
    int num_events = 0;
    int ret = 0;
    int error = 0;

    while (num_events < min_events) {
        if (poll(mPollFds, 2, 0) == -1) {
            PLOG(ERROR) << "Mtp error during poll()";
            return -1;
        }
        if (mPollFds[0].revents & POLLIN) {
            mPollFds[0].revents = 0;
            if (handleEvent() == -1) {
                error = errno;
            }
        }
        if (mPollFds[1].revents & POLLIN) {
            mPollFds[1].revents = 0;
            uint64_t ev_cnt = 0;

            if (::read(mEventFd, &ev_cnt, sizeof(ev_cnt)) == -1) {
                PLOG(ERROR) << "Mtp unable to read eventfd";
                error = errno;
                continue;
            }

            // It's possible that io_getevents will return more events than the eventFd reported,
            // since events may appear in the time between the calls. In this case, the eventFd will
            // show up as readable next iteration, but there will be fewer or no events to actually
            // wait for. Thus we never want io_getevents to block.
            int this_events = TEMP_FAILURE_RETRY(io_getevents(mCtx, 0, AIO_BUFS_MAX, events, &ZERO_TIMEOUT));
            if (this_events == -1) {
                PLOG(ERROR) << "Mtp error getting events";
                error = errno;
            }
            // Add up the total amount of data and find errors on the way.
            for (unsigned j = 0; j < static_cast<unsigned>(this_events); j++) {
                if (events[j].res < 0) {
                    errno = -events[j].res;
                    PLOG(ERROR) << "Mtp got error event at " << j << " and " << buf->actual << " total";
                    error = errno;
                }
                ret += events[j].res;
            }
            num_events += this_events;
            if (counter)
                *counter += this_events;
        }
        if (error) {
            errno = error;
            ret = -1;
            break;
        }
    }
    return ret;
}

void MtpFfsHandle::cancelTransaction() {
    // Device cancels by stalling both bulk endpoints.
    if (::read(mBulkIn, nullptr, 0) != -1 || errno != EBADMSG)
        PLOG(ERROR) << "Mtp stall failed on bulk in";
    if (::write(mBulkOut, nullptr, 0) != -1 || errno != EBADMSG)
        PLOG(ERROR) << "Mtp stall failed on bulk out";
    mCanceled = true;
    errno = ECANCELED;
}

int MtpFfsHandle::cancelEvents(struct iocb **iocb, struct io_event *events, unsigned start,
        unsigned end) {
    // Some manpages for io_cancel are out of date and incorrect.
    // io_cancel will return -EINPROGRESS on success and does
    // not place the event in the given memory. We have to use
    // io_getevents to wait for all the events we cancelled.
    int ret = 0;
    unsigned num_events = 0;
    int save_errno = errno;
    errno = 0;

    for (unsigned j = start; j < end; j++) {
        if (io_cancel(mCtx, iocb[j], nullptr) != -1 || errno != EINPROGRESS) {
            PLOG(ERROR) << "Mtp couldn't cancel request " << j;
        } else {
            num_events++;
        }
    }
    if (num_events != end - start) {
        ret = -1;
        errno = EIO;
    }
    int evs = TEMP_FAILURE_RETRY(io_getevents(mCtx, num_events, AIO_BUFS_MAX, events, nullptr));
    if (static_cast<unsigned>(evs) != num_events) {
        PLOG(ERROR) << "Mtp couldn't cancel all requests, got " << evs;
        ret = -1;
    }

    uint64_t ev_cnt = 0;
    if (num_events && ::read(mEventFd, &ev_cnt, sizeof(ev_cnt)) == -1)
        PLOG(ERROR) << "Mtp Unable to read event fd";

    if (ret == 0) {
        // Restore errno since it probably got overriden with EINPROGRESS.
        errno = save_errno;
    }
    return ret;
}

int MtpFfsHandle::iobufSubmit(struct io_buffer *buf, int fd, unsigned length, bool read) {
    int ret = 0;
    buf->actual = AIO_BUFS_MAX;
    for (unsigned j = 0; j < AIO_BUFS_MAX; j++) {
        unsigned rq_length = std::min(AIO_BUF_LEN, length - AIO_BUF_LEN * j);
        io_prep(buf->iocb[j], fd, buf->buf[j], rq_length, 0, read);
        buf->iocb[j]->aio_flags |= IOCB_FLAG_RESFD;
        buf->iocb[j]->aio_resfd = mEventFd;

        // Not enough data, so table is truncated.
        if (rq_length < AIO_BUF_LEN || length == AIO_BUF_LEN * (j + 1)) {
            buf->actual = j + 1;
            break;
        }
    }

    ret = io_submit(mCtx, buf->actual, buf->iocb.data());
    if (ret != static_cast<int>(buf->actual)) {
        PLOG(ERROR) << "Mtp io_submit got " << ret << " expected " << buf->actual;
        if (ret != -1) {
            errno = EIO;
        }
        ret = -1;
    }
    return ret;
}

int MtpFfsHandle::receiveFile(mtp_file_range mfr, bool zero_packet) {
    // When receiving files, the incoming length is given in 32 bits.
    // A >=4G file is given as 0xFFFFFFFF
    uint32_t file_length = mfr.length;
    uint64_t offset = mfr.offset;

    struct aiocb aio;
    aio.aio_fildes = mfr.fd;
    aio.aio_buf = nullptr;
    struct aiocb *aiol[] = {&aio};

    int ret = -1;
    unsigned i = 0;
    size_t length;
    struct io_event ioevs[AIO_BUFS_MAX];
    bool has_write = false;
    bool error = false;
    bool write_error = false;
    int packet_size = getPacketSize(mBulkOut);
    bool short_packet = false;
    advise(mfr.fd);

    // Break down the file into pieces that fit in buffers
    while (file_length > 0 || has_write) {
        // Queue an asynchronous read from USB.
        if (file_length > 0) {
            length = std::min(static_cast<uint32_t>(MAX_FILE_CHUNK_SIZE), file_length);
            if (iobufSubmit(&mIobuf[i], mBulkOut, length, true) == -1)
                error = true;
        }

        // Get the return status of the last write request.
        if (has_write) {
            aio_suspend(aiol, 1, nullptr);
            int written = aio_return(&aio);
            if (static_cast<size_t>(written) < aio.aio_nbytes) {
                errno = written == -1 ? aio_error(&aio) : EIO;
                PLOG(ERROR) << "Mtp error writing to disk";
                write_error = true;
            }
            has_write = false;
        }

        if (error) {
            return -1;
        }

        // Get the result of the read request, and queue a write to disk.
        if (file_length > 0) {
            unsigned num_events = 0;
            ret = 0;
            unsigned short_i = mIobuf[i].actual;
            while (num_events < short_i) {
                // Get all events up to the short read, if there is one.
                // We must wait for each event since data transfer could end at any time.
                int this_events = 0;
                int event_ret = waitEvents(&mIobuf[i], 1, ioevs, &this_events);
                num_events += this_events;

                if (event_ret == -1) {
                    cancelEvents(mIobuf[i].iocb.data(), ioevs, num_events, mIobuf[i].actual);
                    return -1;
                }
                ret += event_ret;
                for (int j = 0; j < this_events; j++) {
                    // struct io_event contains a pointer to the associated struct iocb as a __u64.
                    if (static_cast<__u64>(ioevs[j].res) <
                            reinterpret_cast<struct iocb*>(ioevs[j].obj)->aio_nbytes) {
                        // We've found a short event. Store the index since
                        // events won't necessarily arrive in the order they are queued.
                        short_i = (ioevs[j].obj - reinterpret_cast<uint64_t>(mIobuf[i].iocbs.data()))
                            / sizeof(struct iocb) + 1;
                        short_packet = true;
                    }
                }
            }
            if (short_packet) {
                if (cancelEvents(mIobuf[i].iocb.data(), ioevs, short_i, mIobuf[i].actual)) {
                    write_error = true;
                }
            }
            if (file_length == MAX_MTP_FILE_SIZE) {
                // For larger files, receive until a short packet is received.
                if (static_cast<size_t>(ret) < length) {
                    file_length = 0;
                }
            } else if (ret < static_cast<int>(length)) {
                // If file is less than 4G and we get a short packet, it's an error.
                errno = EIO;
                LOG(ERROR) << "Mtp got unexpected short packet";
                return -1;
            } else {
                file_length -= ret;
            }

            if (write_error) {
                cancelTransaction();
                return -1;
            }

            // Enqueue a new write request
            aio_prepare(&aio, mIobuf[i].bufs.data(), ret, offset);
            aio_write(&aio);

            offset += ret;
            i = (i + 1) % NUM_IO_BUFS;
            has_write = true;
        }
    }
    if ((ret % packet_size == 0 && !short_packet) || zero_packet) {
        // Receive an empty packet if size is a multiple of the endpoint size
        // and we didn't already get an empty packet from the header or large file.
        if (read(mIobuf[0].bufs.data(), packet_size) != 0) {
            return -1;
        }
    }
    return 0;
}

int MtpFfsHandle::sendFile(mtp_file_range mfr) {
    uint64_t file_length = mfr.length;
    uint32_t given_length = std::min(static_cast<uint64_t>(MAX_MTP_FILE_SIZE),
            file_length + sizeof(mtp_data_header));
    uint64_t offset = mfr.offset;
    int packet_size = getPacketSize(mBulkIn);

    // If file_length is larger than a size_t, truncating would produce the wrong comparison.
    // Instead, promote the left side to 64 bits, then truncate the small result.
    int init_read_len = std::min(
            static_cast<uint64_t>(packet_size - sizeof(mtp_data_header)), file_length);

    advise(mfr.fd);

    struct aiocb aio;
    aio.aio_fildes = mfr.fd;
    struct aiocb *aiol[] = {&aio};
    int ret = 0;
    int length, num_read;
    unsigned i = 0;
    struct io_event ioevs[AIO_BUFS_MAX];
    bool error = false;
    bool has_write = false;

    // Send the header data
    mtp_data_header *header = reinterpret_cast<mtp_data_header*>(mIobuf[0].bufs.data());
    header->length = htole32(given_length);
    header->type = htole16(2); // data packet
    header->command = htole16(mfr.command);
    header->transaction_id = htole32(mfr.transaction_id);

    // Some hosts don't support header/data separation even though MTP allows it
    // Handle by filling first packet with initial file data
    if (TEMP_FAILURE_RETRY(pread(mfr.fd, mIobuf[0].bufs.data() +
                    sizeof(mtp_data_header), init_read_len, offset))
            != init_read_len) return -1;
    if (write(mIobuf[0].bufs.data(), sizeof(mtp_data_header) + init_read_len) == -1)
        return -1;
    file_length -= init_read_len;
    offset += init_read_len;
    ret = init_read_len + sizeof(mtp_data_header);

    // Break down the file into pieces that fit in buffers
    while(file_length > 0 || has_write) {
        if (file_length > 0) {
            // Queue up a read from disk.
            length = std::min(static_cast<uint64_t>(MAX_FILE_CHUNK_SIZE), file_length);
            aio_prepare(&aio, mIobuf[i].bufs.data(), length, offset);
            aio_read(&aio);
        }

        if (has_write) {
            // Wait for usb write. Cancel unwritten portion if there's an error.
            int num_events = 0;
            if (waitEvents(&mIobuf[(i-1)%NUM_IO_BUFS], mIobuf[(i-1)%NUM_IO_BUFS].actual, ioevs,
                        &num_events) != ret) {
                error = true;
                cancelEvents(mIobuf[(i-1)%NUM_IO_BUFS].iocb.data(), ioevs, num_events,
                        mIobuf[(i-1)%NUM_IO_BUFS].actual);
            }
            has_write = false;
        }

        if (file_length > 0) {
            // Wait for the previous read to finish
            aio_suspend(aiol, 1, nullptr);
            num_read = aio_return(&aio);
            if (static_cast<size_t>(num_read) < aio.aio_nbytes) {
                errno = num_read == -1 ? aio_error(&aio) : EIO;
                PLOG(ERROR) << "Mtp error reading from disk";
                cancelTransaction();
                return -1;
            }

            file_length -= num_read;
            offset += num_read;

            if (error) {
                return -1;
            }

            // Queue up a write to usb.
            if (iobufSubmit(&mIobuf[i], mBulkIn, num_read, false) == -1) {
                return -1;
            }
            has_write = true;
            ret = num_read;
        }

        i = (i + 1) % NUM_IO_BUFS;
    }

    if (ret % packet_size == 0) {
        // If the last packet wasn't short, send a final empty packet
        if (write(mIobuf[0].bufs.data(), 0) != 0) {
            return -1;
        }
    }
    return 0;
}

int MtpFfsHandle::sendEvent(mtp_event me) {
    // Mimic the behavior of f_mtp by sending the event async.
    // Events aren't critical to the connection, so we don't need to check the return value.
    char *temp = new char[me.length];
    memcpy(temp, me.data, me.length);
    me.data = temp;
    std::thread t([this, me]() { return this->doSendEvent(me); });
    t.detach();
    return 0;
}

void MtpFfsHandle::doSendEvent(mtp_event me) {
    unsigned length = me.length;
    int ret = ::write(mIntr, me.data, length);
    if (static_cast<unsigned>(ret) != length)
        PLOG(ERROR) << "Mtp error sending event thread!";
    delete[] reinterpret_cast<char*>(me.data);
}

} // namespace android

