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
#include <audio_utils/fifo.h>
#include <utils/Mutex.h>
#include <utils/threads.h>

#include <vector>

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
    // TODO: make timestamp optional
    EVENT_TIMESTAMP,            // clock_gettime(CLOCK_MONOTONIC)
    EVENT_INTEGER,              // integer value entry
    EVENT_FLOAT,                // floating point value entry
    EVENT_PID,                  // process ID and process name
    EVENT_AUTHOR,               // author index (present in merged logs) tracks entry's original log
    EVENT_START_FMT,            // logFormat start event: entry includes format string, following
                                // entries contain format arguments
    EVENT_END_FMT,              // end of logFormat argument list
};


// ---------------------------------------------------------------------------
// API for handling format entry operations

// a formatted entry has the following structure:
//    * START_FMT entry, containing the format string
//    * TIMESTAMP entry
//    * author entry of the thread that generated it (optional, present in merged log)
//    * format arg1
//    * format arg2
//    * ...
//    * END_FMT entry

class FormatEntry {
public:
    // build a Format Entry starting in the given pointer
    class iterator;
    explicit FormatEntry(const uint8_t *entry);
    explicit FormatEntry(const iterator &it);

    // entry representation in memory
    struct entry {
        const uint8_t type;
        const uint8_t length;
        const uint8_t data[0];
    };

    // entry tail representation (after data)
    struct ending {
        uint8_t length;
        uint8_t next[0];
    };

    // entry iterator
    class iterator {
    public:
        iterator();
        iterator(const uint8_t *entry);
        iterator(const iterator &other);

        // dereference underlying entry
        const entry&    operator*() const;
        const entry*    operator->() const;
        // advance to next entry
        iterator&       operator++(); // ++i
        // back to previous entry
        iterator&       operator--(); // --i
        iterator        next() const;
        iterator        prev() const;
        bool            operator!=(const iterator &other) const;
        int             operator-(const iterator &other) const;

        bool            hasConsistentLength() const;
        void            copyTo(std::unique_ptr<audio_utils_fifo_writer> &dst) const;
        void            copyData(uint8_t *dst) const;

        template<typename T>
        inline const T& payload() {
            return *reinterpret_cast<const T *>(ptr + offsetof(entry, data));
        }

    private:
        friend class FormatEntry;
        const uint8_t  *ptr;
    };

    // Entry's format string
    const char* formatString() const;

    // Enrty's format string length
    size_t      formatStringLength() const;

    // Format arguments (excluding format string, timestamp and author)
    iterator    args() const;

    // get format entry timestamp
    timespec    timestamp() const;

    // entry's author index (-1 if none present)
    // a Merger has a vector of Readers, author simply points to the index of the
    // Reader that originated the entry
    int         author() const;

    // copy entry, adding author before timestamp, returns size of original entry
    iterator    copyWithAuthor(std::unique_ptr<audio_utils_fifo_writer> &dst, int author) const;

    iterator    begin() const;

private:
    // copies ordinary entry from src to dst, and returns length of entry
    // size_t      copyEntry(audio_utils_fifo_writer *dst, const iterator &it);
    const uint8_t  *mEntry;
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
    // mEvent, mLength, mData[...], duplicate mLength
    static const size_t kOverhead = sizeof(FormatEntry::entry) + sizeof(FormatEntry::ending);
    // endind length of previous entry
    static const size_t kPreviousLengthOffset = - sizeof(FormatEntry::ending) +
                                                offsetof(FormatEntry::ending, length);
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
    static void    appendTimestamp(String8 *body, const void *data);
    static size_t  fmtEntryLength(const uint8_t *data);

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

    // A snapshot of a readers buffer
    class Snapshot {
    public:
        Snapshot() : mData(NULL), mLost(0) {}

        Snapshot(size_t bufferSize) : mData(new uint8_t[bufferSize]) {}

        ~Snapshot() { delete[] mData; }

        // copy of the buffer
        uint8_t *data() const { return mData; }

        // amount of data lost (given by audio_utils_fifo_reader)
        size_t   lost() const { return mLost; }

        // iterator to beginning of readable segment of snapshot
        // data between begin and end has valid entries
        FormatEntry::iterator begin() { return mBegin; }

        // iterator to end of readable segment of snapshot
        FormatEntry::iterator end() { return mEnd; }


    private:
        friend class Reader;
        uint8_t              *mData;
        size_t                mLost;
        FormatEntry::iterator mBegin;
        FormatEntry::iterator mEnd;
    };

    // Input parameter 'size' is the desired size of the timeline in byte units.
    // The size of the shared memory must be at least Timeline::sharedSize(size).
    Reader(const void *shared, size_t size);
    Reader(const sp<IMemory>& iMemory, size_t size);

    virtual ~Reader();

    // get snapshot of readers fifo buffer, effectively consuming the buffer
    std::unique_ptr<Snapshot> getSnapshot();
    // dump a particular snapshot of the reader
    void     dump(int fd, size_t indent, Snapshot & snap);
    // dump the current content of the reader's buffer
    void     dump(int fd, size_t indent = 0);
    bool     isIMemory(const sp<IMemory>& iMemory) const;

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

    FormatEntry::iterator   handleFormat(const FormatEntry &fmtEntry,
                                         String8 *timestamp,
                                         String8 *body);
    // dummy method for handling absent author entry
    virtual size_t handleAuthor(const FormatEntry &fmtEntry, String8 *body) { return 0; }

    // Searches for the last entry of type <type> in the range [front, back)
    // back has to be entry-aligned. Returns nullptr if none enconuntered.
    static uint8_t *findLastEntryOfType(uint8_t *front, uint8_t *back, uint8_t type);

    static const size_t kSquashTimestamp = 5; // squash this many or more adjacent timestamps
};

// Wrapper for a reader with a name. Contains a pointer to the reader and a pointer to the name
class NamedReader {
public:
    NamedReader() { mName[0] = '\0'; } // for Vector
    NamedReader(const sp<NBLog::Reader>& reader, const char *name) :
        mReader(reader)
        { strlcpy(mName, name, sizeof(mName)); }
    ~NamedReader() { }
    const sp<NBLog::Reader>&  reader() const { return mReader; }
    const char*               name() const { return mName; }

private:
    sp<NBLog::Reader>   mReader;
    static const size_t kMaxName = 32;
    char                mName[kMaxName];
};

// ---------------------------------------------------------------------------

class Merger : public RefBase {
public:
    Merger(const void *shared, size_t size);

    virtual ~Merger() {}

    void addReader(const NamedReader &reader);
    // TODO add removeReader
    void merge();
    const std::vector<NamedReader> *getNamedReaders() const;
private:
    // vector of the readers the merger is supposed to merge from.
    // every reader reads from a writer's buffer
    std::vector<NamedReader> mNamedReaders;
    uint8_t *mBuffer;
    Shared * const mShared;
    std::unique_ptr<audio_utils_fifo> mFifo;
    std::unique_ptr<audio_utils_fifo_writer> mFifoWriter;

    static struct timespec getTimestamp(const uint8_t *data);
};

class MergeReader : public Reader {
public:
    MergeReader(const void *shared, size_t size, Merger &merger);
private:
    const std::vector<NamedReader> *mNamedReaders;
    // handle author entry by looking up the author's name and appending it to the body
    // returns number of bytes read from fmtEntry
    size_t handleAuthor(const FormatEntry &fmtEntry, String8 *body);
};

// MergeThread is a thread that contains a Merger. It works as a retriggerable one-shot:
// when triggered, it awakes for a lapse of time, during which it periodically merges; if
// retriggered, the timeout is reset.
// The thread is triggered on AudioFlinger binder activity.
class MergeThread : public Thread {
public:
    MergeThread(Merger &merger);
    virtual ~MergeThread() override;

    // Reset timeout and activate thread to merge periodically if it's idle
    void wakeup();

    // Set timeout period until the merging thread goes idle again
    void setTimeoutUs(int time);

private:
    virtual bool threadLoop() override;

    // the merger who actually does the work of merging the logs
    Merger&     mMerger;

    // mutex for the condition variable
    Mutex       mMutex;

    // condition variable to activate merging on timeout >= 0
    Condition   mCond;

    // time left until the thread blocks again (in microseconds)
    int         mTimeoutUs;

    // merging period when the thread is awake
    static const int  kThreadSleepPeriodUs = 1000000 /*1s*/;

    // initial timeout value when triggered
    static const int  kThreadWakeupPeriodUs = 3000000 /*3s*/;
};

};  // class NBLog

}   // namespace android

#endif  // ANDROID_MEDIA_NBLOG_H
