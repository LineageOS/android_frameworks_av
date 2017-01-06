/*
 * Copyright (C) 2013 The Android Open Source Project
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

#define LOG_TAG "NBLog"
//#define LOG_NDEBUG 0

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <new>
#include <audio_utils/roundup.h>
#include <media/nbaio/NBLog.h>
#include <utils/Log.h>
#include <utils/String8.h>

namespace android {

int NBLog::Entry::readAt(size_t offset) const
{
    // FIXME This is too slow, despite the name it is used during writing
    if (offset == 0)
        return mEvent;
    else if (offset == 1)
        return mLength;
    else if (offset < (size_t) (mLength + 2))
        return ((char *) mData)[offset - 2];
    else if (offset == (size_t) (mLength + 2))
        return mLength;
    else
        return 0;
}

// ---------------------------------------------------------------------------

#if 0   // FIXME see note in NBLog.h
NBLog::Timeline::Timeline(size_t size, void *shared)
    : mSize(roundup(size)), mOwn(shared == NULL),
      mShared((Shared *) (mOwn ? new char[sharedSize(size)] : shared))
{
    new (mShared) Shared;
}

NBLog::Timeline::~Timeline()
{
    mShared->~Shared();
    if (mOwn) {
        delete[] (char *) mShared;
    }
}
#endif

/*static*/
size_t NBLog::Timeline::sharedSize(size_t size)
{
    // TODO fifo now supports non-power-of-2 buffer sizes, so could remove the roundup
    return sizeof(Shared) + roundup(size);
}

// ---------------------------------------------------------------------------

NBLog::Writer::Writer()
    : mShared(NULL), mFifo(NULL), mFifoWriter(NULL), mEnabled(false)
{
}

NBLog::Writer::Writer(void *shared, size_t size)
    : mShared((Shared *) shared),
      mFifo(mShared != NULL ?
        new audio_utils_fifo(size, sizeof(uint8_t),
            mShared->mBuffer, mShared->mRear, NULL /*throttlesFront*/) : NULL),
      mFifoWriter(mFifo != NULL ? new audio_utils_fifo_writer(*mFifo) : NULL),
      mEnabled(mFifoWriter != NULL)
{
}

NBLog::Writer::Writer(const sp<IMemory>& iMemory, size_t size)
    : Writer(iMemory != 0 ? (Shared *) iMemory->pointer() : NULL, size)
{
    mIMemory = iMemory;
}

NBLog::Writer::~Writer()
{
    delete mFifoWriter;
    delete mFifo;
}

void NBLog::Writer::log(const char *string)
{
    if (!mEnabled) {
        return;
    }
    size_t length = strlen(string);
    if (length > Entry::kMaxLength) {
        length = Entry::kMaxLength;
    }
    log(EVENT_STRING, string, length);
}

void NBLog::Writer::logf(const char *fmt, ...)
{
    if (!mEnabled) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    Writer::logvf(fmt, ap);     // the Writer:: is needed to avoid virtual dispatch for LockedWriter
    va_end(ap);
}

void NBLog::Writer::logvf(const char *fmt, va_list ap)
{
    if (!mEnabled) {
        return;
    }
    char buffer[Entry::kMaxLength + 1 /*NUL*/];
    int length = vsnprintf(buffer, sizeof(buffer), fmt, ap);
    if (length >= (int) sizeof(buffer)) {
        length = sizeof(buffer) - 1;
        // NUL termination is not required
        // buffer[length] = '\0';
    }
    if (length >= 0) {
        log(EVENT_STRING, buffer, length);
    }
}

void NBLog::Writer::logTimestamp()
{
    if (!mEnabled) {
        return;
    }
    struct timespec ts;
    if (!clock_gettime(CLOCK_MONOTONIC, &ts)) {
        log(EVENT_TIMESTAMP, &ts, sizeof(struct timespec));
    }
}

void NBLog::Writer::logTimestamp(const struct timespec& ts)
{
    if (!mEnabled) {
        return;
    }
    log(EVENT_TIMESTAMP, &ts, sizeof(struct timespec));
}

void NBLog::Writer::log(Event event, const void *data, size_t length)
{
    if (!mEnabled) {
        return;
    }
    if (data == NULL || length > Entry::kMaxLength) {
        // TODO Perhaps it makes sense to display truncated data or at least a
        //      message that the data is too long?  The current behavior can create
        //      a confusion for a programmer debugging their code.
        return;
    }
    switch (event) {
    case EVENT_STRING:
    case EVENT_TIMESTAMP:
        break;
    case EVENT_RESERVED:
    default:
        return;
    }
    Entry entry(event, data, length);
    log(&entry, true /*trusted*/);
}

void NBLog::Writer::log(const NBLog::Entry *entry, bool trusted)
{
    if (!mEnabled) {
        return;
    }
    if (!trusted) {
        log(entry->mEvent, entry->mData, entry->mLength);
        return;
    }
    size_t need = entry->mLength + Entry::kOverhead;    // mEvent, mLength, data[length], mLength
                                                        // need = number of bytes remaining to write

    // FIXME optimize this using memcpy for the data part of the Entry.
    // The Entry could have a method copyTo(ptr, offset, size) to optimize the copy.
    uint8_t temp[Entry::kMaxLength + Entry::kOverhead];
    for (size_t i = 0; i < need; i++) {
        temp[i] = entry->readAt(i);
    }
    mFifoWriter->write(temp, need);
}

bool NBLog::Writer::isEnabled() const
{
    return mEnabled;
}

bool NBLog::Writer::setEnabled(bool enabled)
{
    bool old = mEnabled;
    mEnabled = enabled && mShared != NULL;
    return old;
}

// ---------------------------------------------------------------------------

NBLog::LockedWriter::LockedWriter()
    : Writer()
{
}

NBLog::LockedWriter::LockedWriter(void *shared, size_t size)
    : Writer(shared, size)
{
}

void NBLog::LockedWriter::log(const char *string)
{
    Mutex::Autolock _l(mLock);
    Writer::log(string);
}

void NBLog::LockedWriter::logf(const char *fmt, ...)
{
    // FIXME should not take the lock until after formatting is done
    Mutex::Autolock _l(mLock);
    va_list ap;
    va_start(ap, fmt);
    Writer::logvf(fmt, ap);
    va_end(ap);
}

void NBLog::LockedWriter::logvf(const char *fmt, va_list ap)
{
    // FIXME should not take the lock until after formatting is done
    Mutex::Autolock _l(mLock);
    Writer::logvf(fmt, ap);
}

void NBLog::LockedWriter::logTimestamp()
{
    // FIXME should not take the lock until after the clock_gettime() syscall
    Mutex::Autolock _l(mLock);
    Writer::logTimestamp();
}

void NBLog::LockedWriter::logTimestamp(const struct timespec& ts)
{
    Mutex::Autolock _l(mLock);
    Writer::logTimestamp(ts);
}

bool NBLog::LockedWriter::isEnabled() const
{
    Mutex::Autolock _l(mLock);
    return Writer::isEnabled();
}

bool NBLog::LockedWriter::setEnabled(bool enabled)
{
    Mutex::Autolock _l(mLock);
    return Writer::setEnabled(enabled);
}

// ---------------------------------------------------------------------------

NBLog::Reader::Reader(const void *shared, size_t size)
    : mShared((/*const*/ Shared *) shared), /*mIMemory*/
      mFd(-1), mIndent(0),
      mFifo(mShared != NULL ?
        new audio_utils_fifo(size, sizeof(uint8_t),
            mShared->mBuffer, mShared->mRear, NULL /*throttlesFront*/) : NULL),
      mFifoReader(mFifo != NULL ? new audio_utils_fifo_reader(*mFifo) : NULL)
{
}

NBLog::Reader::Reader(const sp<IMemory>& iMemory, size_t size)
    : Reader(iMemory != 0 ? (Shared *) iMemory->pointer() : NULL, size)
{
    mIMemory = iMemory;
}

NBLog::Reader::~Reader()
{
    delete mFifoReader;
    delete mFifo;
}

void NBLog::Reader::dump(int fd, size_t indent)
{
    if (mFifoReader == NULL) {
        return;
    }
    // make a copy to avoid race condition with writer
    size_t capacity = mFifo->capacity();

    // TODO Stack-based allocation of large objects may fail.
    //      Currently the log buffers are a page or two, which should be safe.
    //      But if the log buffers ever get a lot larger,
    //      then change this to allocate from heap when necessary.
    static size_t kReasonableStackObjectSize = 32768;
    ALOGW_IF(capacity > kReasonableStackObjectSize, "Stack-based allocation of object may fail");
    uint8_t copy[capacity];

    size_t lost;
    ssize_t actual = mFifoReader->read(copy, capacity, NULL /*timeout*/, &lost);
    ALOG_ASSERT(actual <= capacity);
    size_t avail = actual > 0 ? (size_t) actual : 0;
    size_t i = avail;
    Event event;
    size_t length;
    struct timespec ts;
    time_t maxSec = -1;
    while (i >= Entry::kOverhead) {
        length = copy[i - 1];
        if (length + Entry::kOverhead > i || copy[i - length - 2] != length) {
            break;
        }
        event = (Event) copy[i - length - Entry::kOverhead];
        if (event == EVENT_TIMESTAMP) {
            if (length != sizeof(struct timespec)) {
                // corrupt
                break;
            }
            memcpy(&ts, &copy[i - length - 1], sizeof(struct timespec));
            if (ts.tv_sec > maxSec) {
                maxSec = ts.tv_sec;
            }
        }
        i -= length + Entry::kOverhead;
    }
    mFd = fd;
    mIndent = indent;
    String8 timestamp, body;
    lost += i;
    if (lost > 0) {
        body.appendFormat("warning: lost %zu bytes worth of events", lost);
        // TODO timestamp empty here, only other choice to wait for the first timestamp event in the
        //      log to push it out.  Consider keeping the timestamp/body between calls to readAt().
        dumpLine(timestamp, body);
    }
    size_t width = 1;
    while (maxSec >= 10) {
        ++width;
        maxSec /= 10;
    }
    if (maxSec >= 0) {
        timestamp.appendFormat("[%*s]", (int) width + 4, "");
    }
    bool deferredTimestamp = false;
    while (i < avail) {
        event = (Event) copy[i];
        length = copy[i + 1];
        const void *data = &copy[i + 2];
        size_t advance = length + Entry::kOverhead;
        switch (event) {
        case EVENT_STRING:
            body.appendFormat("%.*s", (int) length, (const char *) data);
            break;
        case EVENT_TIMESTAMP: {
            // already checked that length == sizeof(struct timespec);
            memcpy(&ts, data, sizeof(struct timespec));
            long prevNsec = ts.tv_nsec;
            long deltaMin = LONG_MAX;
            long deltaMax = -1;
            long deltaTotal = 0;
            size_t j = i;
            for (;;) {
                j += sizeof(struct timespec) + 3 /*Entry::kOverhead?*/;
                if (j >= avail || (Event) copy[j] != EVENT_TIMESTAMP) {
                    break;
                }
                struct timespec tsNext;
                memcpy(&tsNext, &copy[j + 2], sizeof(struct timespec));
                if (tsNext.tv_sec != ts.tv_sec) {
                    break;
                }
                long delta = tsNext.tv_nsec - prevNsec;
                if (delta < 0) {
                    break;
                }
                if (delta < deltaMin) {
                    deltaMin = delta;
                }
                if (delta > deltaMax) {
                    deltaMax = delta;
                }
                deltaTotal += delta;
                prevNsec = tsNext.tv_nsec;
            }
            size_t n = (j - i) / (sizeof(struct timespec) + 3 /*Entry::kOverhead?*/);
            if (deferredTimestamp) {
                dumpLine(timestamp, body);
                deferredTimestamp = false;
            }
            timestamp.clear();
            if (n >= kSquashTimestamp) {
                timestamp.appendFormat("[%d.%03d to .%.03d by .%.03d to .%.03d]",
                        (int) ts.tv_sec, (int) (ts.tv_nsec / 1000000),
                        (int) ((ts.tv_nsec + deltaTotal) / 1000000),
                        (int) (deltaMin / 1000000), (int) (deltaMax / 1000000));
                i = j;
                advance = 0;
                break;
            }
            timestamp.appendFormat("[%d.%03d]", (int) ts.tv_sec,
                    (int) (ts.tv_nsec / 1000000));
            deferredTimestamp = true;
            } break;
        case EVENT_RESERVED:
        default:
            body.appendFormat("warning: unknown event %d", event);
            break;
        }
        i += advance;

        if (!body.isEmpty()) {
            dumpLine(timestamp, body);
            deferredTimestamp = false;
        }
    }
    if (deferredTimestamp) {
        dumpLine(timestamp, body);
    }
}

void NBLog::Reader::dumpLine(const String8& timestamp, String8& body)
{
    if (mFd >= 0) {
        dprintf(mFd, "%.*s%s %s\n", mIndent, "", timestamp.string(), body.string());
    } else {
        ALOGI("%.*s%s %s", mIndent, "", timestamp.string(), body.string());
    }
    body.clear();
}

bool NBLog::Reader::isIMemory(const sp<IMemory>& iMemory) const
{
    return iMemory != 0 && mIMemory != 0 && iMemory->pointer() == mIMemory->pointer();
}

}   // namespace android
