/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <map>
#include <memory>
#include <type_traits>
#include <unordered_set>
#include <vector>

#include <audio_utils/fifo.h>
#include <binder/IMemory.h>
#include <media/nblog/PerformanceAnalysis.h>
#include <media/nblog/ReportPerformance.h>
#include <utils/Mutex.h>
#include <utils/threads.h>
#include <utils/Timers.h>

namespace android {

class String8;

class NBLog {

public:

    using log_hash_t = uint64_t;

    // FIXME Everything needed for client (writer API and registration) should be isolated
    //       from the rest of the implementation.
    class Writer;
    class Reader;

    // TODO have a comment somewhere explaining the whole process for adding a new EVENT_

    // NBLog Event types. The Events are named to provide contextual meaning for what is logged.
    // If adding a new standalone Event here, update the event-to-type mapping by adding a
    // MAP_EVENT_TO_TYPE statement below.
    enum Event : uint8_t {
        EVENT_RESERVED,
        EVENT_STRING,               // ASCII string, not NUL-terminated
                                    // TODO: make timestamp optional
        EVENT_TIMESTAMP,            // clock_gettime(CLOCK_MONOTONIC)

        // Types for Format Entry, i.e. formatted entry
        EVENT_FMT_START,            // logFormat start event: entry includes format string,
                                    // following entries contain format arguments
        // format arguments
        EVENT_FMT_TIMESTAMP,        // timestamp value entry
        EVENT_FMT_HASH,             // unique HASH of log origin, originates from hash of file name
                                    // and line number
        EVENT_FMT_STRING,           // string value entry
        EVENT_FMT_INTEGER,          // integer value entry
        EVENT_FMT_FLOAT,            // floating point value entry
        EVENT_FMT_PID,              // process ID and process name
        EVENT_FMT_AUTHOR,           // author index (present in merged logs) tracks entry's
                                    // original log
        // end of format arguments
        EVENT_FMT_END,              // end of logFormat argument list

        // Types for wakeup timestamp histograms
        EVENT_HISTOGRAM_ENTRY_TS,   // single datum for timestamp histogram
        EVENT_AUDIO_STATE,          // audio on/off event: logged on FastMixer::onStateChange call

        // Types representing audio performance metrics
        EVENT_THREAD_INFO,          // thread type, frameCount and sampleRate, which give context
                                    // for the metrics below.
        EVENT_LATENCY,              // difference between frames presented by HAL and frames
                                    // written to HAL output sink, divided by sample rate.
        EVENT_WORK_TIME,            // the time a thread takes to do work, e.g. read, write, etc.
        EVENT_WARMUP_TIME,          // thread warmup time
        EVENT_UNDERRUN,             // predicted thread underrun event timestamp
        EVENT_OVERRUN,              // predicted thread overrun event timestamp

        EVENT_UPPER_BOUND,          // to check for invalid events
    };

    // NBLog custom-defined structs. Some NBLog Event types map to these structs.

    // mapped from EVENT_THREAD_INFO
    struct thread_info_t {
        // TODO make type an enum
        int type;               // Thread type: 0 for MIXER, 1 for CAPTURE,
                                // 2 for FASTMIXER, 3 for FASTCAPTURE
        size_t frameCount;      // number of frames per read or write buffer
        unsigned sampleRate;    // in frames per second
    };

    template <Event E> struct get_mapped;
#define MAP_EVENT_TO_TYPE(E, T) \
    template<> struct get_mapped<E> { \
        static_assert(std::is_trivially_copyable<T>::value \
                && !std::is_pointer<T>::value, \
                "NBLog::Event must map to trivially copyable, non-pointer type."); \
        typedef T type; \
    }

    // Maps an NBLog Event type to a C++ POD type.
    MAP_EVENT_TO_TYPE(EVENT_THREAD_INFO, thread_info_t);
    MAP_EVENT_TO_TYPE(EVENT_LATENCY, double);
    MAP_EVENT_TO_TYPE(EVENT_WORK_TIME, int64_t);
    MAP_EVENT_TO_TYPE(EVENT_WARMUP_TIME, double);
    MAP_EVENT_TO_TYPE(EVENT_UNDERRUN, int64_t);
    MAP_EVENT_TO_TYPE(EVENT_OVERRUN, int64_t);

private:

    // ---------------------------------------------------------------------------

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
    class EntryIterator {
    public:
        // Used for dummy initialization. Performing operations on a default-constructed
        // EntryIterator other than assigning it to another valid EntryIterator
        // is undefined behavior.
        EntryIterator();
        // Caller's responsibility to make sure entry is not nullptr.
        // Passing in nullptr can result in undefined behavior.
        explicit EntryIterator(const uint8_t *entry);
        EntryIterator(const EntryIterator &other);

        // dereference underlying entry
        const entry&    operator*() const;
        const entry*    operator->() const;
        // advance to next entry
        EntryIterator&       operator++(); // ++i
        // back to previous entry
        EntryIterator&       operator--(); // --i
        // returns an EntryIterator corresponding to the next entry
        EntryIterator        next() const;
        // returns an EntryIterator corresponding to the previous entry
        EntryIterator        prev() const;
        bool            operator!=(const EntryIterator &other) const;
        int             operator-(const EntryIterator &other) const;

        bool            hasConsistentLength() const;
        void            copyTo(std::unique_ptr<audio_utils_fifo_writer> &dst) const;
        void            copyData(uint8_t *dst) const;

        // memcpy preferred to reinterpret_cast to avoid potentially unsupported
        // unaligned memory access.
#if 0
        template<typename T>
        inline const T& payload() {
            return *reinterpret_cast<const T *>(mPtr + offsetof(entry, data));
        }
#else
        template<typename T>
        inline T payload() const {
            static_assert(std::is_trivially_copyable<T>::value
                    && !std::is_pointer<T>::value,
                    "NBLog::EntryIterator payload must be trivially copyable, non-pointer type.");
            T payload;
            memcpy(&payload, mPtr + offsetof(entry, data), sizeof(payload));
            return payload;
        }
#endif

        inline operator const uint8_t*() const {
            return mPtr;
        }

    private:
        const uint8_t  *mPtr;   // Should not be nullptr except for dummy initialization
    };

    // ---------------------------------------------------------------------------
    // The following classes are used for merging into the Merger's buffer.

    class AbstractEntry {
    public:
        virtual ~AbstractEntry() {}

        // build concrete entry of appropriate class from ptr.
        static std::unique_ptr<AbstractEntry> buildEntry(const uint8_t *ptr);

        // get format entry timestamp
        virtual int64_t      timestamp() const = 0;

        // get format entry's unique id
        virtual log_hash_t   hash() const = 0;

        // entry's author index (-1 if none present)
        // a Merger has a vector of Readers, author simply points to the index of the
        // Reader that originated the entry
        // TODO consider changing to uint32_t
        virtual int          author() const = 0;

        // copy entry, adding author before timestamp, returns iterator to end of entry
        virtual EntryIterator    copyWithAuthor(std::unique_ptr<audio_utils_fifo_writer> &dst,
                                                int author) const = 0;

    protected:
        // Entry starting in the given pointer, which shall not be nullptr.
        explicit AbstractEntry(const uint8_t *entry);
        // copies ordinary entry from src to dst, and returns length of entry
        // size_t      copyEntry(audio_utils_fifo_writer *dst, const iterator &it);
        const uint8_t  *mEntry;
    };

    // API for handling format entry operations

    // a formatted entry has the following structure:
    //    * FMT_START entry, containing the format string
    //    * TIMESTAMP entry
    //    * HASH entry
    //    * author entry of the thread that generated it (optional, present in merged log)
    //    * format arg1
    //    * format arg2
    //    * ...
    //    * FMT_END entry
    class FormatEntry : public AbstractEntry {
    public:
        // explicit FormatEntry(const EntryIterator &it);
        explicit FormatEntry(const uint8_t *ptr) : AbstractEntry(ptr) {}
        virtual ~FormatEntry() {}

        EntryIterator begin() const;

        // Entry's format string
        const   char* formatString() const;

        // Enrty's format string length
        size_t      formatStringLength() const;

        // Format arguments (excluding format string, timestamp and author)
        EntryIterator    args() const;

        // get format entry timestamp
        virtual int64_t     timestamp() const override;

        // get format entry's unique id
        virtual log_hash_t  hash() const override;

        // entry's author index (-1 if none present)
        // a Merger has a vector of Readers, author simply points to the index of the
        // Reader that originated the entry
        virtual int         author() const override;

        // copy entry, adding author before timestamp, returns size of original entry
        virtual EntryIterator    copyWithAuthor(std::unique_ptr<audio_utils_fifo_writer> &dst,
                                                int author) const override;
    };

    class HistogramEntry : public AbstractEntry {
    public:
        explicit HistogramEntry(const uint8_t *ptr) : AbstractEntry(ptr) {
        }
        virtual ~HistogramEntry() {}

        virtual int64_t     timestamp() const override;

        virtual log_hash_t  hash() const override;

        virtual int         author() const override;

        virtual EntryIterator    copyWithAuthor(std::unique_ptr<audio_utils_fifo_writer> &dst,
                                                int author) const override;
    };

    // ---------------------------------------------------------------------------

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
    class Entry {
    public:
        Entry(Event event, const void *data, size_t length)
            : mEvent(event), mLength(length), mData(data) { }
        /*virtual*/ ~Entry() { }

        // used during writing to format Entry information as follows:
        // [type][length][data ... ][length]
        int     copyEntryDataAt(size_t offset) const;

    private:
        friend class Writer;
        Event       mEvent;     // event type
        uint8_t     mLength;    // length of additional data, 0 <= mLength <= kMaxLength
        const void *mData;      // event type-specific data
        static const size_t kMaxLength = 255;
    public:
        // mEvent, mLength, mData[...], duplicate mLength
        static const size_t kOverhead = sizeof(entry) + sizeof(ending);
        // endind length of previous entry
        static const ssize_t kPreviousLengthOffset = - sizeof(ending) +
            offsetof(ending, length);
    };

    // TODO move these somewhere else
    struct HistTsEntry {
        log_hash_t hash;
        int64_t ts;
    }; //TODO __attribute__((packed));

    struct HistTsEntryWithAuthor {
        log_hash_t hash;
        int64_t ts;
        int author;
    }; //TODO __attribute__((packed));

    struct HistIntEntry {
        log_hash_t hash;
        int value;
    }; //TODO __attribute__((packed));

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
    // NBLog Writer API
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

        // FIXME needs comments, and some should be private
        void    log(const char *string);
        void    logf(const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));
        void    logTimestamp();
        void    logFormat(const char *fmt, log_hash_t hash, ...);
        void    logEventHistTs(Event event, log_hash_t hash);

        // Log data related to Event E. See the event-to-type mapping for the type of data
        // corresponding to the event. For example, if you see a mapping statement:
        //     MAP_TYPE_TO_EVENT(E, T);
        // then the usage of this method would be:
        //     T data = doComputation();
        //     tlNBLogWriter->log<NBLog::E>(data);
        template<Event E>
        void    log(typename get_mapped<E>::type data) {
            log(E, &data, sizeof(data));
        }

        virtual bool    isEnabled() const;

        // return value for all of these is the previous isEnabled()
        virtual bool    setEnabled(bool enabled);   // but won't enable if no shared memory
        bool    enable()    { return setEnabled(true); }
        bool    disable()   { return setEnabled(false); }

        sp<IMemory>     getIMemory() const  { return mIMemory; }

        // Public logging function implementations should always use one of the
        // two log() function calls below to write to shared memory.
    protected:
        // Writes a single Entry to the FIFO if the writer is enabled.
        // This is protected and virtual because LockedWriter uses a lock to protect
        // writing to the FIFO before writing to this function.
        virtual void log(const Entry &entry, bool trusted = false);

    private:
        // 0 <= length <= kMaxLength
        // Log a single Entry with corresponding event, data, and length.
        void    log(Event event, const void *data, size_t length);

        void    logvf(const char *fmt, va_list ap);
        // helper functions for logging parts of a formatted entry
        void    logStart(const char *fmt);
        void    logTimestampFormat();
        void    logVFormat(const char *fmt, log_hash_t hash, va_list ap);

        Shared* const   mShared;    // raw pointer to shared memory
        sp<IMemory>     mIMemory;   // ref-counted version, initialized in constructor
                                    // and then const
        audio_utils_fifo * const mFifo;                 // FIFO itself, non-NULL
                                                        // unless constructor fails
        audio_utils_fifo_writer * const mFifoWriter;    // used to write to FIFO, non-NULL
                                                        // unless dummy constructor used
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

        bool    isEnabled() const override;
        bool    setEnabled(bool enabled) override;

    private:
        // Lock needs to be obtained before writing to FIFO.
        void log(const Entry &entry, bool trusted = false) override;
        mutable Mutex   mLock;
    };

    // ---------------------------------------------------------------------------
    // NBLog Reader API
    // ---------------------------------------------------------------------------

    class Snapshot;     // Forward declaration needed for Reader::getSnapshot()

    class Reader : public RefBase {
    public:
        // Input parameter 'size' is the desired size of the timeline in byte units.
        // The size of the shared memory must be at least Timeline::sharedSize(size).
        Reader(const void *shared, size_t size, const std::string &name);
        Reader(const sp<IMemory>& iMemory, size_t size, const std::string &name);
        virtual ~Reader();

        // get snapshot of readers fifo buffer, effectively consuming the buffer
        std::unique_ptr<Snapshot> getSnapshot();
        bool     isIMemory(const sp<IMemory>& iMemory) const;
        const std::string &name() const { return mName; }

    private:
        // Amount of tries for reader to catch up with writer in getSnapshot().
        static constexpr int kMaxObtainTries = 3;
        // invalidBeginTypes and invalidEndTypes are used to align the Snapshot::begin() and
        // Snapshot::end() EntryIterators to valid entries.
        static const std::unordered_set<Event> invalidBeginTypes;
        static const std::unordered_set<Event> invalidEndTypes;
        // declared as const because audio_utils_fifo() constructor
        sp<IMemory> mIMemory;       // ref-counted version, assigned only in constructor

        const std::string mName;            // name of reader (actually name of writer)
        /*const*/ Shared* const mShared;    // raw pointer to shared memory, actually const but not
        audio_utils_fifo * const mFifo;                 // FIFO itself,
                                                        // non-NULL unless constructor fails
        audio_utils_fifo_reader * const mFifoReader;    // used to read from FIFO,
                                                        // non-NULL unless constructor fails

        // Searches for the last valid entry in the range [front, back)
        // back has to be entry-aligned. Returns nullptr if none enconuntered.
        static const uint8_t *findLastValidEntry(const uint8_t *front, const uint8_t *back,
                                                   const std::unordered_set<Event> &invalidTypes);
    };

    // A snapshot of a readers buffer
    // This is raw data. No analysis has been done on it
    class Snapshot {
    public:
        ~Snapshot() { delete[] mData; }

        // amount of data lost (given by audio_utils_fifo_reader)
        size_t   lost() const { return mLost; }

        // iterator to beginning of readable segment of snapshot
        // data between begin and end has valid entries
        EntryIterator begin() const { return mBegin; }

        // iterator to end of readable segment of snapshot
        EntryIterator end() const { return mEnd; }

    private:
        Snapshot() = default;
        explicit Snapshot(size_t bufferSize) : mData(new uint8_t[bufferSize]) {}
        friend std::unique_ptr<Snapshot> Reader::getSnapshot();
        uint8_t * const       mData = nullptr;
        size_t                mLost = 0;
        EntryIterator mBegin;
        EntryIterator mEnd;
    };

    // TODO move this to MediaLogService?
    class DumpReader : public Reader {
    public:
        DumpReader(const void *shared, size_t size, const std::string &name)
            : Reader(shared, size, name) {}
        DumpReader(const sp<IMemory>& iMemory, size_t size, const std::string &name)
            : Reader(iMemory, size, name) {}
        void dump(int fd, size_t indent = 0);
    private:
        void handleAuthor(const AbstractEntry& fmtEntry __unused, String8* body __unused) {}
        EntryIterator handleFormat(const FormatEntry &fmtEntry, String8 *timestamp, String8 *body);

        static void    appendInt(String8 *body, const void *data);
        static void    appendFloat(String8 *body, const void *data);
        static void    appendPID(String8 *body, const void *data, size_t length);
        static void    appendTimestamp(String8 *body, const void *data);
        // The bufferDump functions are used for debugging only.
        static String8 bufferDump(const uint8_t *buffer, size_t size);
        static String8 bufferDump(const EntryIterator &it);
    };

    // ---------------------------------------------------------------------------
    // TODO move Merger, MergeReader, and MergeThread to a separate file.

    // This class is used to read data from each thread's individual FIFO in shared memory
    // and write it to a single FIFO in local memory.
    class Merger : public RefBase {
    public:
        Merger(const void *shared, size_t size);

        virtual ~Merger() {}

        void addReader(const sp<NBLog::Reader> &reader);
        // TODO add removeReader
        void merge();

        // FIXME This is returning a reference to a shared variable that needs a lock
        const std::vector<sp<Reader>>& getReaders() const;

    private:
        // vector of the readers the merger is supposed to merge from.
        // every reader reads from a writer's buffer
        // FIXME Needs to be protected by a lock
        std::vector<sp<Reader>> mReaders;

        Shared * const mShared; // raw pointer to shared memory
        std::unique_ptr<audio_utils_fifo> mFifo; // FIFO itself
        std::unique_ptr<audio_utils_fifo_writer> mFifoWriter; // used to write to FIFO
    };

    // This class has a pointer to the FIFO in local memory which stores the merged
    // data collected by NBLog::Merger from all Readers. It is used to process
    // this data and write the result to PerformanceAnalysis.
    class MergeReader : public Reader {
    public:
        MergeReader(const void *shared, size_t size, Merger &merger);

        void dump(int fd, int indent = 0);
        // process a particular snapshot of the reader
        void processSnapshot(Snapshot &snap, int author);
        // call getSnapshot of the content of the reader's buffer and process the data
        void getAndProcessSnapshot();

    private:
        // FIXME Needs to be protected by a lock,
        //       because even though our use of it is read-only there may be asynchronous updates
        // The object is owned by the Merger class.
        const std::vector<sp<Reader>>& mReaders;

        // analyzes, compresses and stores the merged data
        // contains a separate instance for every author (thread), and for every source file
        // location within each author
        ReportPerformance::PerformanceAnalysisMap mThreadPerformanceAnalysis;

        // compresses and stores audio performance data from each thread's buffers.
        std::map<int /*author, i.e. thread index*/, PerformanceData> mThreadPerformanceData;

        // handle author entry by looking up the author's name and appending it to the body
        // returns number of bytes read from fmtEntry
        void handleAuthor(const AbstractEntry &fmtEntry, String8 *body);
    };

    // MergeThread is a thread that contains a Merger. It works as a retriggerable one-shot:
    // when triggered, it awakes for a lapse of time, during which it periodically merges; if
    // retriggered, the timeout is reset.
    // The thread is triggered on AudioFlinger binder activity.
    class MergeThread : public Thread {
    public:
        MergeThread(Merger &merger, MergeReader &mergeReader);
        virtual ~MergeThread() override;

        // Reset timeout and activate thread to merge periodically if it's idle
        void wakeup();

        // Set timeout period until the merging thread goes idle again
        void setTimeoutUs(int time);

    private:
        virtual bool threadLoop() override;

        // the merger who actually does the work of merging the logs
        Merger&     mMerger;

        // the mergereader used to process data merged by mMerger
        MergeReader& mMergeReader;

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
