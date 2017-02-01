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

// Non-blocking event logger intended for safe communication between processes via shared memory

#ifndef ANDROID_MEDIA_NBLOG_H
#define ANDROID_MEDIA_NBLOG_H

#include <binder/IMemory.h>
#include <utils/Mutex.h>
#include <audio_utils/fifo.h>

namespace android {

class String8;

class NBLog {

public:

class Writer;
class Reader;

private:

enum Event {
    EVENT_RESERVED,
    EVENT_STRING,               // ASCII string, not NUL-terminated
    EVENT_TIMESTAMP,            // clock_gettime(CLOCK_MONOTONIC)
    EVENT_INTEGER,
    EVENT_FLOAT,
    EVENT_PID,
    EVENT_START_FMT,            // logFormat start event: entry includes format string, following
                                // entries contain format arguments
    EVENT_END_FMT,              // end of logFormat argument list
};

// ---------------------------------------------------------------------------

// representation of a single log entry in private memory
struct Entry {
    Entry(Event event, const void *data, size_t length)
        : mEvent(event), mLength(length), mData(data) { }
    /*virtual*/ ~Entry() { }

    int     readAt(size_t offset) const;

private:
    friend class Writer;
    Event       mEvent;     // event type
    uint8_t     mLength;    // length of additional data, 0 <= mLength <= kMaxLength
    const void *mData;      // event type-specific data
    static const size_t kMaxLength = 255;
public:
    static const size_t kOverhead = 3;  // mEvent, mLength, mData[...], duplicate mLength
};

// representation of a single log entry in shared memory
//  byte[0]             mEvent
//  byte[1]             mLength
//  byte[2]             mData[0]
//  ...
//  byte[2+i]           mData[i]
//  ...
//  byte[2+mLength-1]   mData[mLength-1]
//  byte[2+mLength]     duplicate copy of mLength to permit reverse scan
//  byte[3+mLength]     start of next log entry

    static void    appendInt(String8 *body, const void *data);
    static void    appendFloat(String8 *body, const void *data);
    static void    appendPID(String8 *body, const void *data, size_t length);
    static int     handleFormat(const char *fmt, size_t length, const uint8_t *data,
                                String8 *timestamp, String8 *body);
    static void    appendTimestamp(String8 *body, const void *data);

public:

// Located in shared memory, must be POD.
// Exactly one process must explicitly call the constructor or use placement new.
// Since this is a POD, the destructor is empty and unnecessary to call it explicitly.
struct Shared {
    Shared() /* mRear initialized via default constructor */ { }
    /*virtual*/ ~Shared() { }

    audio_utils_fifo_index  mRear;  // index one byte past the end of most recent Entry
    char    mBuffer[0];             // circular buffer for entries
};

public:

// ---------------------------------------------------------------------------

// FIXME Timeline was intended to wrap Writer and Reader, but isn't actually used yet.
// For now it is just a namespace for sharedSize().
class Timeline : public RefBase {
public:
#if 0
    Timeline(size_t size, void *shared = NULL);
    virtual ~Timeline();
#endif

    // Input parameter 'size' is the desired size of the timeline in byte units.
    // Returns the size rounded up to a power-of-2, plus the constant size overhead for indices.
    static size_t sharedSize(size_t size);

#if 0
private:
    friend class    Writer;
    friend class    Reader;

    const size_t    mSize;      // circular buffer size in bytes, must be a power of 2
    bool            mOwn;       // whether I own the memory at mShared
    Shared* const   mShared;    // pointer to shared memory
#endif
};

// ---------------------------------------------------------------------------

// Writer is thread-safe with respect to Reader, but not with respect to multiple threads
// calling Writer methods.  If you need multi-thread safety for writing, use LockedWriter.
class Writer : public RefBase {
public:
    Writer();                   // dummy nop implementation without shared memory

    // Input parameter 'size' is the desired size of the timeline in byte units.
    // The size of the shared memory must be at least Timeline::sharedSize(size).
    Writer(void *shared, size_t size);
    Writer(const sp<IMemory>& iMemory, size_t size);

    virtual ~Writer();

    virtual void    log(const char *string);
    virtual void    logf(const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));
    virtual void    logvf(const char *fmt, va_list ap);
    virtual void    logTimestamp();
    virtual void    logTimestamp(const struct timespec &ts);
    virtual void    logInteger(const int x);
    virtual void    logFloat(const float x);
    virtual void    logPID();
    virtual void    logFormat(const char *fmt, ...);
    virtual void    logVFormat(const char *fmt, va_list ap);
    virtual void    logStart(const char *fmt);
    virtual void    logEnd();


    virtual bool    isEnabled() const;

    // return value for all of these is the previous isEnabled()
    virtual bool    setEnabled(bool enabled);   // but won't enable if no shared memory
            bool    enable()    { return setEnabled(true); }
            bool    disable()   { return setEnabled(false); }

    sp<IMemory>     getIMemory() const  { return mIMemory; }

private:
    // 0 <= length <= kMaxLength
    void    log(Event event, const void *data, size_t length);
    void    log(const Entry *entry, bool trusted = false);

    Shared* const   mShared;    // raw pointer to shared memory
    sp<IMemory>     mIMemory;   // ref-counted version, initialized in constructor and then const
    audio_utils_fifo * const mFifo;                 // FIFO itself,
                                                    // non-NULL unless constructor fails
    audio_utils_fifo_writer * const mFifoWriter;    // used to write to FIFO,
                                                    // non-NULL unless dummy constructor used
    bool            mEnabled;   // whether to actually log

    // cached pid and process name to use in %p format specifier
    // total tag length is mPidTagSize and process name is not zero terminated
    char   *mPidTag;
    size_t  mPidTagSize;
};

// ---------------------------------------------------------------------------

// Similar to Writer, but safe for multiple threads to call concurrently
class LockedWriter : public Writer {
public:
    LockedWriter();
    LockedWriter(void *shared, size_t size);

    virtual void    log(const char *string);
    virtual void    logf(const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));
    virtual void    logvf(const char *fmt, va_list ap);
    virtual void    logTimestamp();
    virtual void    logTimestamp(const struct timespec &ts);
    virtual void    logInteger(const int x);
    virtual void    logFloat(const float x);
    virtual void    logPID();
    virtual void    logStart(const char *fmt);
    virtual void    logEnd();

    virtual bool    isEnabled() const;
    virtual bool    setEnabled(bool enabled);

private:
    mutable Mutex   mLock;
};

// ---------------------------------------------------------------------------

class Reader : public RefBase {
public:

    // Input parameter 'size' is the desired size of the timeline in byte units.
    // The size of the shared memory must be at least Timeline::sharedSize(size).
    Reader(const void *shared, size_t size);
    Reader(const sp<IMemory>& iMemory, size_t size);

    virtual ~Reader();

    void    dump(int fd, size_t indent = 0);
    bool    isIMemory(const sp<IMemory>& iMemory) const;

private:
    /*const*/ Shared* const mShared;    // raw pointer to shared memory, actually const but not
                                        // declared as const because audio_utils_fifo() constructor
    sp<IMemory> mIMemory;       // ref-counted version, assigned only in constructor
    int     mFd;                // file descriptor
    int     mIndent;            // indentation level
    audio_utils_fifo * const mFifo;                 // FIFO itself,
                                                    // non-NULL unless constructor fails
    audio_utils_fifo_reader * const mFifoReader;    // used to read from FIFO,
                                                    // non-NULL unless constructor fails

    void    dumpLine(const String8& timestamp, String8& body);

    static const size_t kSquashTimestamp = 5; // squash this many or more adjacent timestamps
};

};  // class NBLog

}   // namespace android

#endif  // ANDROID_MEDIA_NBLOG_H
