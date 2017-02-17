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
#include <sys/prctl.h>
#include <time.h>
#include <new>
#include <audio_utils/roundup.h>
#include <media/nbaio/NBLog.h>
#include <utils/Log.h>
#include <utils/String8.h>

#include <queue>

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

NBLog::FormatEntry::FormatEntry(const uint8_t *entry) : mEntry(entry) {
    ALOGW_IF(entry[0] != EVENT_START_FMT,
             "Created format entry with invalid event type %d",
             entry[0]);
}

const char *NBLog::FormatEntry::formatString() const {
    return (const char*) mEntry + 2;
}

size_t NBLog::FormatEntry::formatStringLength() const {
    return mEntry[1];
}

const uint8_t *NBLog::FormatEntry::args() const {
    const uint8_t *ptr = mEntry + mEntry[1] + NBLog::Entry::kOverhead;
    if (ptr[0] != EVENT_TIMESTAMP) { // skip author if present
        ptr += ptr[1] + NBLog::Entry::kOverhead;
    }
    return ptr + ptr[1] + NBLog::Entry::kOverhead;
}

timespec NBLog::FormatEntry::timestamp() const {
    const uint8_t *ptr = mEntry + mEntry[1] + NBLog::Entry::kOverhead;
    if (ptr[0] != EVENT_TIMESTAMP) { // skip authors if present
        ptr += ptr[1] + NBLog::Entry::kOverhead;
    }
    // by this point, we should be standing in the timestamp entry
    return *((struct timespec*) (&ptr[2]));
}

pid_t NBLog::FormatEntry::author() const {
    size_t authorOffset = mEntry[1] + NBLog::Entry::kOverhead;
    // return -1 if the entry has no author
    if (mEntry[authorOffset] != EVENT_AUTHOR) {
        return -1;
    }
    return *(pid_t*)(mEntry + authorOffset + 2);
}

size_t NBLog::FormatEntry::copyTo(std::unique_ptr<audio_utils_fifo_writer> &dst, int author) const {
    // copy fmt start entry
    size_t entryOffset = copyEntry(dst, mEntry);
    // insert author entry
    size_t authorEntrySize = NBLog::Entry::kOverhead + sizeof(author);
    uint8_t authorEntry[authorEntrySize];
    authorEntry[0] = EVENT_AUTHOR;
    authorEntry[1] = authorEntry[authorEntrySize - 1] = sizeof(author);
    *(int*) (&authorEntry[2]) = author;
    dst->write(authorEntry, authorEntrySize);
    // copy rest of entries
    Event lastEvent = EVENT_TIMESTAMP;
    while (lastEvent != EVENT_END_FMT) {
        lastEvent = (Event) mEntry[entryOffset];
        entryOffset += copyEntry(dst, mEntry + entryOffset);
    }
    return entryOffset;
}


size_t NBLog::FormatEntry::copyEntry(std::unique_ptr<audio_utils_fifo_writer> &dst,
                                     const uint8_t *src) const {
    size_t length = src[1] + NBLog::Entry::kOverhead;
    dst->write(src, length);
    return length;
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
    : mShared(NULL), mFifo(NULL), mFifoWriter(NULL), mEnabled(false), mPidTag(NULL), mPidTagSize(0)
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
    // caching pid and process name
    pid_t id = ::getpid();
    char procName[16];
    int status = prctl(PR_GET_NAME, procName);
    if (status) {  // error getting process name
        procName[0] = '\0';
    }
    size_t length = strlen(procName);
    mPidTagSize = length + sizeof(pid_t);
    mPidTag = new char[mPidTagSize];
    memcpy(mPidTag, &id, sizeof(pid_t));
    memcpy(mPidTag + sizeof(pid_t), procName, length);
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
    delete[] mPidTag;
}

void NBLog::Writer::log(const char *string)
{
    if (!mEnabled) {
        return;
    }
    LOG_ALWAYS_FATAL_IF(string == NULL, "Attempted to log NULL string");
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
        log(EVENT_TIMESTAMP, &ts, sizeof(ts));
    }
}

void NBLog::Writer::logTimestamp(const struct timespec &ts)
{
    if (!mEnabled) {
        return;
    }
    log(EVENT_TIMESTAMP, &ts, sizeof(ts));
}

void NBLog::Writer::logInteger(const int x)
{
    if (!mEnabled) {
        return;
    }
    log(EVENT_INTEGER, &x, sizeof(x));
}

void NBLog::Writer::logFloat(const float x)
{
    if (!mEnabled) {
        return;
    }
    log(EVENT_FLOAT, &x, sizeof(x));
}

void NBLog::Writer::logPID()
{
    if (!mEnabled) {
        return;
    }
    log(EVENT_PID, mPidTag, mPidTagSize);
}

void NBLog::Writer::logStart(const char *fmt)
{
    if (!mEnabled) {
        return;
    }
    size_t length = strlen(fmt);
    if (length > Entry::kMaxLength) {
        length = Entry::kMaxLength;
    }
    log(EVENT_START_FMT, fmt, length);
}

void NBLog::Writer::logEnd()
{
    if (!mEnabled) {
        return;
    }
    Entry entry = Entry(EVENT_END_FMT, NULL, 0);
    log(&entry, true);
}

void NBLog::Writer::logFormat(const char *fmt, ...)
{
    if (!mEnabled) {
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    Writer::logVFormat(fmt, ap);
    va_end(ap);
}

void NBLog::Writer::logVFormat(const char *fmt, va_list argp)
{
    if (!mEnabled) {
        return;
    }
    Writer::logStart(fmt);
    int i;
    double f;
    char* s;
    struct timespec t;
    Writer::logTimestamp();
    for (const char *p = fmt; *p != '\0'; p++) {
        // TODO: implement more complex formatting such as %.3f
        if (*p != '%') {
            continue;
        }
        switch(*++p) {
        case 's': // string
            s = va_arg(argp, char *);
            Writer::log(s);
            break;

        case 't': // timestamp
            t = va_arg(argp, struct timespec);
            Writer::logTimestamp(t);
            break;

        case 'd': // integer
            i = va_arg(argp, int);
            Writer::logInteger(i);
            break;

        case 'f': // float
            f = va_arg(argp, double); // float arguments are promoted to double in vararg lists
            Writer::logFloat((float)f);
            break;

        case 'p': // pid
            Writer::logPID();
            break;

        // the "%\0" case finishes parsing
        case '\0':
            --p;
            break;

        case '%':
            break;

        default:
            ALOGW("NBLog Writer parsed invalid format specifier: %c", *p);
            break;
        }
    }
    Writer::logEnd();
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
    case EVENT_INTEGER:
    case EVENT_FLOAT:
    case EVENT_PID:
    case EVENT_START_FMT:
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

void NBLog::LockedWriter::logTimestamp(const struct timespec &ts)
{
    Mutex::Autolock _l(mLock);
    Writer::logTimestamp(ts);
}

void NBLog::LockedWriter::logInteger(const int x)
{
    Mutex::Autolock _l(mLock);
    Writer::logInteger(x);
}

void NBLog::LockedWriter::logFloat(const float x)
{
    Mutex::Autolock _l(mLock);
    Writer::logFloat(x);
}

void NBLog::LockedWriter::logPID()
{
    Mutex::Autolock _l(mLock);
    Writer::logPID();
}

void NBLog::LockedWriter::logStart(const char *fmt)
{
    Mutex::Autolock _l(mLock);
    Writer::logStart(fmt);
}


void NBLog::LockedWriter::logEnd()
{
    Mutex::Autolock _l(mLock);
    Writer::logEnd();
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

std::unique_ptr<NBLog::Reader::Snapshot> NBLog::Reader::getSnapshot()
{
    if (mFifoReader == NULL) {
        return std::unique_ptr<NBLog::Reader::Snapshot>(new Snapshot());
    }
    // make a copy to avoid race condition with writer
    size_t capacity = mFifo->capacity();

    std::unique_ptr<Snapshot> snapshot(new Snapshot(capacity));

    ssize_t actual = mFifoReader->read((void*) snapshot->mData, capacity, NULL /*timeout*/,
                                       &(snapshot->mLost));
    ALOG_ASSERT(actual <= capacity);
    snapshot->mAvail = actual > 0 ? (size_t) actual : 0;
    return snapshot;
}

void NBLog::Reader::dump(int fd, size_t indent, NBLog::Reader::Snapshot &snapshot)
{
    size_t i = snapshot.available();
    const uint8_t *snapData = snapshot.data();
    Event event;
    size_t length;
    struct timespec ts;
    time_t maxSec = -1;
    while (i >= Entry::kOverhead) {
        length = snapData[i - 1];
        if (length + Entry::kOverhead > i || snapData[i - length - 2] != length) {

            break;
        }
        event = (Event) snapData[i - length - Entry::kOverhead];
        if (event == EVENT_TIMESTAMP) {
            if (length != sizeof(struct timespec)) {
                // corrupt
                break;
            }
            memcpy(&ts, &snapData[i - length - 1], sizeof(struct timespec));
            if (ts.tv_sec > maxSec) {
                maxSec = ts.tv_sec;
            }
        }
        i -= length + Entry::kOverhead;
    }
    mFd = fd;
    mIndent = indent;
    String8 timestamp, body;
    size_t lost = snapshot.lost() + i;
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
    while (i < snapshot.available()) {
        event = (Event) snapData[i];
        length = snapData[i + 1];
        const void *data = &snapData[i + 2];
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
                if (j >= snapshot.available() || (Event) snapData[j] != EVENT_TIMESTAMP) {
                    break;
                }
                struct timespec tsNext;
                memcpy(&tsNext, &snapData[j + 2], sizeof(struct timespec));
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
        case EVENT_INTEGER:
            appendInt(&body, data);
            break;
        case EVENT_FLOAT:
            appendFloat(&body, data);
            break;
        case EVENT_PID:
            appendPID(&body, data, length);
            break;
        case EVENT_START_FMT:
            advance += handleFormat(FormatEntry(snapData + i), &timestamp, &body);
            break;
        case EVENT_END_FMT:
            body.appendFormat("warning: got to end format event");
            break;
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

void NBLog::Reader::dump(int fd, size_t indent)
{
    // get a snapshot, dump it
    std::unique_ptr<Snapshot> snap = getSnapshot();
    dump(fd, indent, *snap);
}

void NBLog::Reader::dumpLine(const String8 &timestamp, String8 &body)
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

void NBLog::appendTimestamp(String8 *body, const void *data) {
    struct timespec ts;
    memcpy(&ts, data, sizeof(struct timespec));
    body->appendFormat("[%d.%03d]", (int) ts.tv_sec,
                    (int) (ts.tv_nsec / 1000000));
}

void NBLog::appendInt(String8 *body, const void *data) {
    int x = *((int*) data);
    body->appendFormat("<%d>", x);
}

void NBLog::appendFloat(String8 *body, const void *data) {
    float f;
    memcpy(&f, data, sizeof(float));
    body->appendFormat("<%f>", f);
}

void NBLog::appendPID(String8 *body, const void* data, size_t length) {
    pid_t id = *((pid_t*) data);
    char * name = &((char*) data)[sizeof(pid_t)];
    body->appendFormat("<PID: %d, name: %.*s>", id, (int) (length - sizeof(pid_t)), name);
}

int NBLog::Reader::handleFormat(const FormatEntry &fmtEntry, String8 *timestamp, String8 *body) {
    // log timestamp
    struct timespec ts = fmtEntry.timestamp();
    timestamp->clear();
    timestamp->appendFormat("[%d.%03d]", (int) ts.tv_sec,
                    (int) (ts.tv_nsec / 1000000));
    size_t fullLength = NBLog::Entry::kOverhead + sizeof(ts);

    // log author (if present)
    fullLength += handleAuthor(fmtEntry, body);

    // log string
    const uint8_t *args = fmtEntry.args();
    size_t args_offset = 0;

    const char* fmt = fmtEntry.formatString();
    size_t fmt_length = fmtEntry.formatStringLength();

    for (size_t fmt_offset = 0; fmt_offset < fmt_length; ++fmt_offset) {
        if (fmt[fmt_offset] != '%') {
            body->append(&fmt[fmt_offset], 1); // TODO optimize to write consecutive strings at once
            continue;
        }
        if (fmt[++fmt_offset] == '%') {
            body->append("%");
            continue;
        }
        if (fmt_offset == fmt_length) {
            continue;
        }

        NBLog::Event event = (NBLog::Event) args[args_offset];
        size_t length = args[args_offset + 1];

        // TODO check length for event type is correct
        if(length != args[args_offset + length + 2]) {
            ALOGW("NBLog Reader received different lengths %zu and %d for event %d", length,
                  args[args_offset + length + 2], event);
            body->append("<invalid entry>");
            ++fmt_offset;
            continue;
        }

        // TODO: implement more complex formatting such as %.3f
        void * datum = (void*) &args[args_offset + 2]; // pointer to the current event args
        switch(fmt[fmt_offset])
        {
        case 's': // string
            ALOGW_IF(event != EVENT_STRING,
                "NBLog Reader incompatible event for string specifier: %d", event);
            body->append((const char*) datum, length);
            break;

        case 't': // timestamp
            ALOGW_IF(event != EVENT_TIMESTAMP,
                "NBLog Reader incompatible event for timestamp specifier: %d", event);
            appendTimestamp(body, datum);
            break;

        case 'd': // integer
            ALOGW_IF(event != EVENT_INTEGER,
                "NBLog Reader incompatible event for integer specifier: %d", event);
            appendInt(body, datum);
            break;

        case 'f': // float
            ALOGW_IF(event != EVENT_FLOAT,
                "NBLog Reader incompatible event for float specifier: %d", event);
            appendFloat(body, datum);
            break;

        case 'p': // pid
            ALOGW_IF(event != EVENT_PID,
                "NBLog Reader incompatible event for pid specifier: %d", event);
            appendPID(body, datum, length);
            break;

        default:
            ALOGW("NBLog Reader encountered unknown character %c", fmt[fmt_offset]);
        }

        args_offset += length + Entry::kOverhead;

    }
    fullLength += args_offset + Entry::kOverhead;
    return fullLength;
}

// ---------------------------------------------------------------------------

NBLog::Merger::Merger(const void *shared, size_t size):
      mBuffer(NULL),
      mShared((Shared *) shared),
      mFifo(mShared != NULL ?
        new audio_utils_fifo(size, sizeof(uint8_t),
            mShared->mBuffer, mShared->mRear, NULL /*throttlesFront*/) : NULL),
      mFifoWriter(mFifo != NULL ? new audio_utils_fifo_writer(*mFifo) : NULL)
      {}

void NBLog::Merger::addReader(const NBLog::NamedReader &reader) {
    mNamedReaders.push_back(reader);
}

// items placed in priority queue during merge
// composed by a timestamp and the index of the snapshot where the timestamp came from
struct MergeItem
{
    struct timespec ts;
    int index;
    MergeItem(struct timespec ts, int index): ts(ts), index(index) {}
};

// operators needed for priority queue in merge
bool operator>(const struct timespec &t1, const struct timespec &t2) {
    return t1.tv_sec > t2.tv_sec || (t1.tv_sec == t2.tv_sec && t1.tv_nsec > t2.tv_nsec);
}

bool operator>(const struct MergeItem &i1, const struct MergeItem &i2) {
    return i1.ts > i2.ts ||
        (i1.ts.tv_sec == i2.ts.tv_sec && i1.ts.tv_nsec == i2.ts.tv_nsec && i1.index > i2.index);
}

// Merge registered readers, sorted by timestamp
void NBLog::Merger::merge() {
    int nLogs = mNamedReaders.size();
    std::vector<std::unique_ptr<NBLog::Reader::Snapshot>> snapshots(nLogs);
    for (int i = 0; i < nLogs; ++i) {
        snapshots[i] = mNamedReaders[i].reader()->getSnapshot();
    }
    // initialize offsets
    std::vector<size_t> offsets(nLogs, 0);
    // TODO custom heap implementation could allow to update top, improving performance
    // for bursty buffers
    std::priority_queue<MergeItem, std::vector<MergeItem>, std::greater<MergeItem>> timestamps;
    for (int i = 0; i < nLogs; ++i)
    {
        if (snapshots[i]->available() > 0) {
            timespec ts = FormatEntry(snapshots[i]->data()).timestamp();
            MergeItem item(ts, i);
            timestamps.push(item);
        }
    }

    while (!timestamps.empty()) {
        // find minimum timestamp
        int index = timestamps.top().index;
        // copy it to the log
        size_t length = FormatEntry(snapshots[index]->data() + offsets[index]).copyTo(
            mFifoWriter, index);
        // update data structures
        offsets[index] += length;
        ALOGW_IF(offsets[index] > snapshots[index]->available(), "Overflown snapshot capacity");
        timestamps.pop();
        if (offsets[index] != snapshots[index]->available()) {
            timespec ts = FormatEntry(snapshots[index]->data() + offsets[index]).timestamp();
            MergeItem item(ts, index);
            timestamps.emplace(item);
        }
    }
}

const std::vector<NBLog::NamedReader> *NBLog::Merger::getNamedReaders() const {
    return &mNamedReaders;
}

NBLog::MergeReader::MergeReader(const void *shared, size_t size, Merger &merger)
    : Reader(shared, size), mNamedReaders(merger.getNamedReaders()) {}

size_t NBLog::MergeReader::handleAuthor(const NBLog::FormatEntry &fmtEntry, String8 *body) {
    int author = fmtEntry.author();
    const char* name = (*mNamedReaders)[author].name();
    body->appendFormat("%s: ", name);
    return NBLog::Entry::kOverhead + sizeof(author);
}

}   // namespace android
