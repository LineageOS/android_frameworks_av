/*
 * Copyright 2025, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef CODEC_TRACE_H_
#define CODEC_TRACE_H_
#include <list>
#include <vector>
#include <audio_utils/Trace.h>
#include <media/stagefright/foundation/AMessage.h>
////////////////////////////////////////////////////////////////////////////////
/*
 * Tracer - For logging mediacodec instant event to Perfetto
 * To make it simple and lock-free, tracer and its events are
 * by itself not designed to be used from different threads.
 * This is currently used only within the looper where all events are
 * serialized.
 * The definitions for traces are below. Two types of events are defined:
 *  1. StateEvent
 *      - These are for logging mediacodec states.
 *  2. BufferEvent
 *      - These are for logging buffer events.
 *          -   queueInputBuffer
 *          -   onInputBufferAvailable
 *          -   queueOutputBuffer
 *          -   onOutputBufferAvailable
 * As buffer events can be several in a sec, these events are batched while
 * logging by the tracer. State events are logged immediately as they happen.
 */
////////////////////////////////////////////////////////////////////////////////
namespace android {

// state events
const char *const kCodecTraceStateAllocated = "allocated";
const char *const kCodecTraceStateConfigured = "configured";
const char *const kCodecTraceStateStarted = "started";
const char *const kCodecTraceStateStopped = "stopped";
const char *const kCodecTraceStateFlushed = "flushed";
const char *const kCodecTraceStateReleased = "released";
//buffer events
// For input buffers into mediacodec from client
// qib - queueInputBuffer
const char *const kCodecTraceActionQueueInputBuffer = "qib";
// For input buffers going out from mediacodec to client
// oiba - onInputBufferAvailable
const char *const kCodecTraceActionOnInputBufferAvailable = "oiba";
// For output buffers into mediacodec from client
// qob - queueOutputBuffer
const char *const kCodecTraceActionQueueOutputBuffer = "qob";
// For output buffers going out from mediacodec to client
// ooba - onOutputBufferAvailable
const char *const kCodecTraceActionOnOutputBufferAvailable = "ooba";
// metadata keys for buffer events
const char *const kCodecTracerMetaKeyRender = "render";
const char *const kCodecTraceMetaKeyInputFormat = "inputFormat";
const char *const kCodecTraceMetaKeyOutputFormat = "outputFormat";

struct Tracer;
struct CodecEvent {
public:

    virtual ~CodecEvent() {
    }

    // Called when an event is triggered
    void onEvent();

    // Clear this event immediately, all history of this event is cleared.
    virtual void clear();

    // Gets all information associated with this event.
    virtual void getInfos(std::vector<audio_utils::trace::Object> &infos) const;

    // Expose only specific settings as atrace cannot
    // handle nested messages
    void setInt32(const std::string key, const int32_t v);

    // This will cause the base info to be duplicated
    // while logging events.
    void setMessage(const std::string key, const sp<AMessage> &msg);

    // Sets a key value pair for this event.
    void setString(const std::string key, const std::string v);

protected:
    CodecEvent(std::string name, std::string eventType);

    void convertToTrace(const sp<AMessage> &msg, audio_utils::trace::Object &trace) const;

    void getType(std::string &type) const;

    void getName(std::string &name) const;

    bool isActive() const;

    void getBaseInfo(audio_utils::trace::Object &info) const;

    const std::string mEventType;
    const std::string mName;
    // Extra infos that will become as part of the base info.
    const sp<AMessage> mMeta;
    // Due to limiation in parsing atrace strings,
    // mMessageInfo will be duplicated for the same event
    std::list<audio_utils::trace::Object> mMessageInfos;
    uint64_t mEventCtr = 0;
    bool mActive = false;

    friend struct Tracer;
};

struct StateEvent : public CodecEvent {
public:
    StateEvent(std::string name);

    virtual ~StateEvent() {}
};

struct BufferEvent : public CodecEvent {

public:
    BufferEvent(const std::string name);
    virtual ~BufferEvent() {}

protected:
    // As buffer events are batched, this event can be cleared only by tracer.
    using CodecEvent::clear;

    void getInfos(std::vector<audio_utils::trace::Object> &infos) const override;
private:

    friend struct Tracer;
};

struct Tracer {
public:
    // If initialization from mediacodec happens with kNoPid/kNoUid
    // then we will try to get pid and uid using AIBinder_getCallingPid()
    // and AIBinder_getCallingUid().
    static constexpr pid_t kNoPid = -1;
    static constexpr uid_t kNoUid = -1;

    // Every action messages in the trace has pid and uid.
    // These ids along with process tables are used
    // to track the apps and processes using the codec.
    Tracer(const uint_t uid, const pid_t pid);
    virtual ~Tracer();

    // name and id will be used to create unique perfetto tracks
    void setCodecInfo(std::string name, uint64_t id) {
        mCodecName = name;
        mCodecId = id;
        mCodecNameId = name + "." + std::to_string(id);
    }

    // BufferEvents are pre-defined and is meant to be requested from
    // the tracer. The Tracer aggregates events and may use
    // delayed logging.
    std::shared_ptr<BufferEvent> getBufferEvent(const std::string name) const;

    // Typically used for state events. This event is logged immediately.
    void trace(const CodecEvent * const event);

    // process all buffer events. By default it will be delayed.
    // But 'delayed' can override to make it log right away.
    void process(const bool delayed = true);
private:
    // Internal function for logging events
    void traceInternal(const CodecEvent * const event);
    std::vector<std::shared_ptr<BufferEvent>> mBufferEvents;
    int64_t mLastTraced = 0;
    uint64_t mCodecId = 0;
    std::string mCodecName;
    std::string mCodecNameId;
    const pid_t mPid;
    const uid_t mUid;
};

}  // namespace android

#endif  // CODEC_TRACE_H_
