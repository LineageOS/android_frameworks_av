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

#include <climits>
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
    ALOGW_IF(entry[offsetof(struct entry, type)] != EVENT_START_FMT,
        "Created format entry with invalid event type %d", entry[offsetof(struct entry, type)]);
}

NBLog::FormatEntry::FormatEntry(const NBLog::FormatEntry::iterator &it) : FormatEntry(it.ptr) {}

const char *NBLog::FormatEntry::formatString() const {
    return (const char*) mEntry + offsetof(entry, data);
}

size_t NBLog::FormatEntry::formatStringLength() const {
    return mEntry[offsetof(entry, length)];
}

NBLog::FormatEntry::iterator NBLog::FormatEntry::args() const {
    auto it = begin();
    // skip start fmt
    ++it;
    // skip timestamp
    ++it;
    // Skip author if present
    if (it->type == EVENT_AUTHOR) {
        ++it;
    }
    return it;
}

timespec NBLog::FormatEntry::timestamp() const {
    auto it = begin();
    // skip start fmt
    ++it;
    return it.payload<timespec>();
}

pid_t NBLog::FormatEntry::author() const {
    auto it = begin();
    // skip start fmt
    ++it;
    // skip timestamp
    ++it;
    // if there is an author entry, return it, return -1 otherwise
    if (it->type == EVENT_AUTHOR) {
        return it.payload<int>();
    }
    return -1;
}

NBLog::FormatEntry::iterator NBLog::FormatEntry::copyWithAuthor(
        std::unique_ptr<audio_utils_fifo_writer> &dst, int author) const {
    auto it = begin();
    // copy fmt start entry
    it.copyTo(dst);
    // copy timestamp
    (++it).copyTo(dst);
    // insert author entry
    size_t authorEntrySize = NBLog::Entry::kOverhead + sizeof(author);
    uint8_t authorEntry[authorEntrySize];
    authorEntry[offsetof(entry, type)] = EVENT_AUTHOR;
    authorEntry[offsetof(entry, length)] =
        authorEntry[authorEntrySize + NBLog::Entry::kPreviousLengthOffset] =
        sizeof(author);
    *(int*) (&authorEntry[offsetof(entry, data)]) = author;
    dst->write(authorEntry, authorEntrySize);
    // copy rest of entries
    while ((++it)->type != EVENT_END_FMT) {
        it.copyTo(dst);
    }
    it.copyTo(dst);
    ++it;
    return it;
}

void NBLog::FormatEntry::iterator::copyTo(std::unique_ptr<audio_utils_fifo_writer> &dst) const {
    size_t length = ptr[offsetof(entry, length)] + NBLog::Entry::kOverhead;
    dst->write(ptr, length);
}

void NBLog::FormatEntry::iterator::copyData(uint8_t *dst) const {
    memcpy((void*) dst, ptr + offsetof(entry, data), ptr[offsetof(entry, length)]);
}

NBLog::FormatEntry::iterator NBLog::FormatEntry::begin() const {
    return iterator(mEntry);
}

NBLog::FormatEntry::iterator::iterator()
    : ptr(nullptr) {}

NBLog::FormatEntry::iterator::iterator(const uint8_t *entry)
    : ptr(entry) {}

NBLog::FormatEntry::iterator::iterator(const NBLog::FormatEntry::iterator &other)
    : ptr(other.ptr) {}

const NBLog::FormatEntry::entry& NBLog::FormatEntry::iterator::operator*() const {
    return *(entry*) ptr;
}

const NBLog::FormatEntry::entry* NBLog::FormatEntry::iterator::operator->() const {
    return (entry*) ptr;
}

NBLog::FormatEntry::iterator& NBLog::FormatEntry::iterator::operator++() {
    ptr += ptr[offsetof(entry, length)] + NBLog::Entry::kOverhead;
    return *this;
}

NBLog::FormatEntry::iterator& NBLog::FormatEntry::iterator::operator--() {
    ptr -= ptr[NBLog::Entry::kPreviousLengthOffset] + NBLog::Entry::kOverhead;
    return *this;
}

NBLog::FormatEntry::iterator NBLog::FormatEntry::iterator::next() const {
    iterator aux(*this);
    return ++aux;
}

NBLog::FormatEntry::iterator NBLog::FormatEntry::iterator::prev() const {
    iterator aux(*this);
    return --aux;
}

int NBLog::FormatEntry::iterator::operator-(const NBLog::FormatEntry::iterator &other) const {
    return ptr - other.ptr;
}

bool NBLog::FormatEntry::iterator::operator!=(const iterator &other) const {
    return ptr != other.ptr;
}

bool NBLog::FormatEntry::iterator::hasConsistentLength() const {
    return ptr[offsetof(entry, length)] == ptr[ptr[offsetof(entry, length)] +
        NBLog::Entry::kOverhead + NBLog::Entry::kPreviousLengthOffset];
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

uint8_t *NBLog::Reader::findLastEntryOfType(uint8_t *front, uint8_t *back, uint8_t type) {
    while (back + Entry::kPreviousLengthOffset >= front) {
        uint8_t *prev = back - back[Entry::kPreviousLengthOffset] - Entry::kOverhead;
        if (prev < front || prev + prev[offsetof(FormatEntry::entry, length)] +
                            Entry::kOverhead != back) {

            // prev points to an out of limits or inconsistent entry
            return nullptr;
        }
        if (prev[offsetof(FormatEntry::entry, type)] == type) {
            return prev;
        }
        back = prev;
    }
    return nullptr; // no entry found
}

std::unique_ptr<NBLog::Reader::Snapshot> NBLog::Reader::getSnapshot()
{
    if (mFifoReader == NULL) {
        return std::unique_ptr<NBLog::Reader::Snapshot>(new Snapshot());
    }
    // make a copy to avoid race condition with writer
    size_t capacity = mFifo->capacity();

    // This emulates the behaviour of audio_utils_fifo_reader::read, but without incrementing the
    // reader index. The index is incremented after handling corruption, to after the last complete
    // entry of the buffer
    size_t lost;
    audio_utils_iovec iovec[2];
    ssize_t availToRead = mFifoReader->obtain(iovec, capacity, NULL /*timeout*/, &lost);
    if (availToRead <= 0) {
        return std::unique_ptr<NBLog::Reader::Snapshot>(new Snapshot());
    }

    std::unique_ptr<Snapshot> snapshot(new Snapshot(availToRead));
    memcpy(snapshot->mData, (const char *) mFifo->buffer() + iovec[0].mOffset, iovec[0].mLength);
    if (iovec[1].mLength > 0) {
        memcpy(snapshot->mData + (iovec[0].mLength),
            (const char *) mFifo->buffer() + iovec[1].mOffset, iovec[1].mLength);
    }

    // Handle corrupted buffer
    // Potentially, a buffer has corrupted data on both beginning (due to overflow) and end
    // (due to incomplete format entry). But even if the end format entry is incomplete,
    // it ends in a complete entry (which is not an END_FMT). So is safe to traverse backwards.
    // TODO: handle client corruption (in the middle of a buffer)

    uint8_t *back = snapshot->mData + availToRead;
    uint8_t *front = snapshot->mData;

    // Find last END_FMT. <back> is sitting on an entry which might be the middle of a FormatEntry.
    // We go backwards until we find an EVENT_END_FMT.
    uint8_t *lastEnd = findLastEntryOfType(front, back, EVENT_END_FMT);
    if (lastEnd == nullptr) {
        snapshot->mEnd = snapshot->mBegin = FormatEntry::iterator(front);
    } else {
        // end of snapshot points to after last END_FMT entry
        snapshot->mEnd = FormatEntry::iterator(lastEnd + Entry::kOverhead);
        // find first START_FMT
        uint8_t *firstStart = nullptr;
        uint8_t *firstStartTmp = lastEnd;
        while ((firstStartTmp = findLastEntryOfType(front, firstStartTmp, EVENT_START_FMT))
                != nullptr) {
            firstStart = firstStartTmp;
        }
        // firstStart is null if no START_FMT entry was found before lastEnd
        if (firstStart == nullptr) {
            snapshot->mBegin = snapshot->mEnd;
        } else {
            snapshot->mBegin = FormatEntry::iterator(firstStart);
        }
    }

    // advance fifo reader index to after last entry read.
    mFifoReader->release(snapshot->mEnd - front);

    snapshot->mLost = lost;
    return snapshot;

}

void NBLog::Reader::dump(int fd, size_t indent, NBLog::Reader::Snapshot &snapshot)
{
#if 0
    struct timespec ts;
    time_t maxSec = -1;
    while (entry - start >= (int) Entry::kOverhead) {
        if (prevEntry - start < 0 || !prevEntry.hasConsistentLength()) {
            break;
        }
        if (prevEntry->type == EVENT_TIMESTAMP) {
            if (prevEntry->length != sizeof(struct timespec)) {
                // corrupt
                break;
            }
            prevEntry.copyData((uint8_t*) &ts);
            if (ts.tv_sec > maxSec) {
                maxSec = ts.tv_sec;
            }
        }
        --entry;
        --prevEntry;
    }
#endif
    mFd = fd;
    mIndent = indent;
    String8 timestamp, body;
    size_t lost = snapshot.lost() + (snapshot.begin() - FormatEntry::iterator(snapshot.data()));
    if (lost > 0) {
        body.appendFormat("warning: lost %zu bytes worth of events", lost);
        // TODO timestamp empty here, only other choice to wait for the first timestamp event in the
        //      log to push it out.  Consider keeping the timestamp/body between calls to readAt().
        dumpLine(timestamp, body);
    }
#if 0
    size_t width = 1;
    while (maxSec >= 10) {
        ++width;
        maxSec /= 10;
    }
    if (maxSec >= 0) {
        timestamp.appendFormat("[%*s]", (int) width + 4, "");
    }
    bool deferredTimestamp = false;
#endif
    for (auto entry = snapshot.begin(); entry != snapshot.end();) {
        switch (entry->type) {
#if 0
        case EVENT_STRING:
            body.appendFormat("%.*s", (int) entry.length(), entry.data());
            break;
        case EVENT_TIMESTAMP: {
            // already checked that length == sizeof(struct timespec);
            entry.copyData((const uint8_t*) &ts);
            long prevNsec = ts.tv_nsec;
            long deltaMin = LONG_MAX;
            long deltaMax = -1;
            long deltaTotal = 0;
            auto aux(entry);
            for (;;) {
                ++aux;
                if (end - aux >= 0 || aux.type() != EVENT_TIMESTAMP) {
                    break;
                }
                struct timespec tsNext;
                aux.copyData((const uint8_t*) &tsNext);
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
            size_t n = (aux - entry) / (sizeof(struct timespec) + 3 /*Entry::kOverhead?*/);
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
                entry = aux;
                // advance = 0;
                break;
            }
            timestamp.appendFormat("[%d.%03d]", (int) ts.tv_sec,
                    (int) (ts.tv_nsec / 1000000));
            deferredTimestamp = true;
            }
            break;
        case EVENT_INTEGER:
            appendInt(&body, entry.data());
            break;
        case EVENT_FLOAT:
            appendFloat(&body, entry.data());
            break;
        case EVENT_PID:
            appendPID(&body, entry.data(), entry.length());
            break;
#endif
        case EVENT_START_FMT:
            // right now, this is the only supported case
            entry = handleFormat(FormatEntry(entry), &timestamp, &body);
            break;
        case EVENT_END_FMT:
            body.appendFormat("warning: got to end format event");
            ++entry;
            break;
        case EVENT_RESERVED:
        default:
            body.appendFormat("warning: unexpected event %d", entry->type);
            ++entry;
            break;
        }

        if (!body.isEmpty()) {
            dumpLine(timestamp, body);
            // deferredTimestamp = false;
        }
    }
    // if (deferredTimestamp) {
    //     dumpLine(timestamp, body);
    // }
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

NBLog::FormatEntry::iterator NBLog::Reader::handleFormat(const FormatEntry &fmtEntry,
                                                         String8 *timestamp,
                                                         String8 *body) {
    // log timestamp
    struct timespec ts = fmtEntry.timestamp();
    timestamp->clear();
    timestamp->appendFormat("[%d.%03d]", (int) ts.tv_sec,
                    (int) (ts.tv_nsec / 1000000));

    // log author (if present)
    handleAuthor(fmtEntry, body);

    // log string
    NBLog::FormatEntry::iterator arg = fmtEntry.args();

    const char* fmt = fmtEntry.formatString();
    size_t fmt_length = fmtEntry.formatStringLength();

    for (size_t fmt_offset = 0; fmt_offset < fmt_length; ++fmt_offset) {
        if (fmt[fmt_offset] != '%') {
            body->append(&fmt[fmt_offset], 1); // TODO optimize to write consecutive strings at once
            continue;
        }
        // case "%%""
        if (fmt[++fmt_offset] == '%') {
            body->append("%");
            continue;
        }
        // case "%\0"
        if (fmt_offset == fmt_length) {
            continue;
        }

        NBLog::Event event = (NBLog::Event) arg->type;
        size_t length = arg->length;

        // TODO check length for event type is correct

        if (event == EVENT_END_FMT) {
            break;
        }

        // TODO: implement more complex formatting such as %.3f
        const uint8_t *datum = arg->data; // pointer to the current event args
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
        ++arg;
    }
    ALOGW_IF(arg->type != EVENT_END_FMT, "Expected end of format, got %d", arg->type);
    ++arg;
    return arg;
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
    std::vector<NBLog::FormatEntry::iterator> offsets(nLogs);
    for (int i = 0; i < nLogs; ++i) {
        snapshots[i] = mNamedReaders[i].reader()->getSnapshot();
        offsets[i] = snapshots[i]->begin();
    }
    // initialize offsets
    // TODO custom heap implementation could allow to update top, improving performance
    // for bursty buffers
    std::priority_queue<MergeItem, std::vector<MergeItem>, std::greater<MergeItem>> timestamps;
    for (int i = 0; i < nLogs; ++i)
    {
        if (offsets[i] != snapshots[i]->end()) {
            timespec ts = FormatEntry(offsets[i]).timestamp();
            timestamps.emplace(ts, i);
        }
    }

    while (!timestamps.empty()) {
        // find minimum timestamp
        int index = timestamps.top().index;
        // copy it to the log, increasing offset
        offsets[index] = FormatEntry(offsets[index]).copyWithAuthor(mFifoWriter, index);
        // update data structures
        timestamps.pop();
        if (offsets[index] != snapshots[index]->end()) {
            timespec ts = FormatEntry(offsets[index]).timestamp();
            timestamps.emplace(ts, index);
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

NBLog::MergeThread::MergeThread(NBLog::Merger &merger)
    : mMerger(merger),
      mTimeoutUs(0) {}

NBLog::MergeThread::~MergeThread() {
    // set exit flag, set timeout to 0 to force threadLoop to exit and wait for the thread to join
    requestExit();
    setTimeoutUs(0);
    join();
}

bool NBLog::MergeThread::threadLoop() {
    bool doMerge;
    {
        AutoMutex _l(mMutex);
        // If mTimeoutUs is negative, wait on the condition variable until it's positive.
        // If it's positive, wait kThreadSleepPeriodUs and then merge
        nsecs_t waitTime = mTimeoutUs > 0 ? kThreadSleepPeriodUs * 1000 : LLONG_MAX;
        mCond.waitRelative(mMutex, waitTime);
        doMerge = mTimeoutUs > 0;
        mTimeoutUs -= kThreadSleepPeriodUs;
    }
    if (doMerge) {
        mMerger.merge();
    }
    return true;
}

void NBLog::MergeThread::wakeup() {
    setTimeoutUs(kThreadWakeupPeriodUs);
}

void NBLog::MergeThread::setTimeoutUs(int time) {
    AutoMutex _l(mMutex);
    mTimeoutUs = time;
    mCond.signal();
}

}   // namespace android
