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
#define LOG_TAG "CodecTrace"
#define ATRACE_TAG  ATRACE_TAG_VIDEO
#include <utils/Log.h>
#include <utils/Trace.h>
#include <android/binder_ibinder.h>
#include <media/stagefright/CodecTrace.h>
#include <media/stagefright/foundation/ABuffer.h>

// Tracks and trace definitions
// Track definitions
static const char *const kCodecTracePrefixTrackState = "codec.track.state.";
static const char *const kCodecTracePrefixTrackAction = "codec.track.action.";
static const char *const kCodecTraceObjectKeyEvent = "event";
static const char *const kCodecTraceObjectKeyMetadata = "metadata";

// buffers
static const uint32_t kCodecTraceValueBufferCountIntervalMs = 5000;

// reserved keys for traces
static const char *const kCodecTraceObjectKeyPid = "pid";
static const char *const kCodecTraceObjectKeyUid = "uid";
static const char *const kCodecTraceObjectKeyBufferCount = "ctr";
static const char *const kCodecTraceObjectKeyBufferCountIntervalMs = "intervalMs";
namespace android {
// CodecEvent base class
CodecEvent::CodecEvent(std::string name, std::string eventType):
        mEventType(eventType), mName(name), mMeta(new AMessage()) {
}

void CodecEvent::onEvent() {
    if (ATRACE_ENABLED()) [[unlikely]] {
	    mEventCtr++;
	    mActive = true;
	    ALOGV("Event %s fired with value %lld", mName.c_str(), (long long)mEventCtr);
    }
}

void CodecEvent::clear() {
    mEventCtr = 0;
    mMeta->clear();
    mMessageInfos.clear();
    mActive = false;
}

void CodecEvent::getInfos(std::vector<audio_utils::trace::Object> &infos) const {
    if (mMessageInfos.empty()) {
        audio_utils::trace::Object info;
        CodecEvent::getBaseInfo(info);
        infos.push_back(info);
    } else {
        audio_utils::trace::Object info;
        for (const audio_utils::trace::Object &msgInfo : mMessageInfos) {
            info.clear();
            info = msgInfo;
            CodecEvent::getBaseInfo(info);
            infos.push_back(info);
        }
    }
}

void CodecEvent::getType(std::string &type) const {
    type = mEventType;
}

void CodecEvent::getName(std::string &name) const {
    name = mName;
}

// Expose only specific settings as atrace cannot
// handle nested messages
void CodecEvent::setInt32(std::string key, int32_t v) {
    if (key.empty()) {
        return;
    }
    if (ATRACE_ENABLED()) [[unlikely]] {
        mMeta->setInt32(key.c_str(), v);
    }
}

// This will cause the base info to be duplicated
// while logging events.
void CodecEvent::setMessage(const std::string key, const sp<AMessage> &msg) {
    if (key.empty() || msg == nullptr) {
        return;
    }
    if (ATRACE_ENABLED()) [[unlikely]] {
        audio_utils::trace::Object trace;
        trace.set(kCodecTraceObjectKeyMetadata, key);
        convertToTrace(msg, trace);
        mMessageInfos.push_back(trace);
    }
}

void CodecEvent::setString(const std::string key, const std::string v) {
    if (key.empty() || v.empty()) {
        return;
    }
    if (ATRACE_ENABLED()) [[unlikely]] {
        mMeta->setString(key.c_str(), v.c_str());
    }
}

void CodecEvent::getBaseInfo(audio_utils::trace::Object &info) const {
    if (ATRACE_ENABLED()) [[unlikely]] {
        info.set(kCodecTraceObjectKeyEvent, mName);
        convertToTrace(mMeta, info);
    }
}

bool CodecEvent::isActive() const {
    return mActive;
}


void CodecEvent::convertToTrace(const sp<AMessage> &msg, audio_utils::trace::Object &trace) const {
    if (ATRACE_ENABLED()) [[unlikely]] {
        if (msg == nullptr) {
            return;
        }
        size_t numEntries = msg->countEntries();
        AMessage::Type type;
        for (size_t i = 0; i < numEntries; ++i) {
            const char *name = msg->getEntryNameAt(i, &type);
            AMessage::ItemData itemData = msg->getEntryAt(i);
            switch (type) {
                case AMessage::kTypeInt32: {
                    int32_t value;
                    itemData.find(&value);
                    trace.set(name, value);
                    break;
                }
                case AMessage::kTypeInt64: {
                    int64_t value;
                    itemData.find(&value);
                    trace.set(name, value);
                    break;
                }
                case AMessage::kTypeDouble: {
                    double value;
                    itemData.find(&value);
                    trace.set(name, value);
                    break;
                }
                case AMessage::kTypeString: {
                    AString value;
                    itemData.find(&value);
                    trace.set(name, value.c_str());
                    break;
                }
                // TODO: add support for other types
                default:
                    ALOGV("Trace values not updated");
            }
        }
    }
}

// StateEvent
StateEvent::StateEvent(const std::string name):
		CodecEvent(name, kCodecTracePrefixTrackState){
}

//BufferEvent
BufferEvent::BufferEvent(const std::string name):
        CodecEvent(name, kCodecTracePrefixTrackAction) {
}

void BufferEvent::getInfos(std::vector<audio_utils::trace::Object> &infos) const {
    if (ATRACE_ENABLED()) [[unlikely]] {
        audio_utils::trace::Object info;
        auto fillBufferInfo = [&info, this]() {
            CodecEvent::getBaseInfo(info);
            info.set(kCodecTraceObjectKeyBufferCount, mEventCtr);
        };
        if (mMessageInfos.empty()) {
            info.clear();
            fillBufferInfo();
            infos.push_back(info);
        } else {
            for (const audio_utils::trace::Object &msgInfo : mMessageInfos) {
                info.clear();
                info = msgInfo;
                fillBufferInfo();
                infos.push_back(info);
            }
        }
    }
}

// Tracer
Tracer::Tracer(const uid_t uid, const pid_t pid)
        :mPid(pid == Tracer::kNoPid ? AIBinder_getCallingPid() : pid),
         mUid(uid == Tracer::kNoUid ? AIBinder_getCallingUid() : uid) {
    ALOGI("Constructing Tracer with uid : %u", mUid);
    std::string bufferEvents[] = {
        kCodecTraceActionOnOutputBufferAvailable
    };
    if (ATRACE_ENABLED()) [[unlikely]] {
        for (std::string &bufferEvent : bufferEvents) {
            std::shared_ptr<BufferEvent> e(new BufferEvent(bufferEvent));
            mBufferEvents.push_back(e);
        }
    }
}

Tracer::~Tracer() {
    process(false);
    ALOGV("Destructing Tracer");
}

std::shared_ptr<BufferEvent> Tracer::getBufferEvent(
        const std::string name) const {
    if (name.empty()) {
        return nullptr;
    }
    std::string eventName;
    for (int i = 0 ; i < mBufferEvents.size(); i++) {
        mBufferEvents[i]->getName(eventName);
        if (eventName == name) {
            return mBufferEvents[i];
        }
    }
    return nullptr;
}

void Tracer::trace(const CodecEvent * const event) {
    if (ATRACE_ENABLED()) [[unlikely]] {
        if (event == nullptr) {
            return;
        }
        std::string name;
        event->getName(name);
        if (name == kCodecTraceStateReleased) {
            // we have to log all buffer events now.
            process(false);
        }
        traceInternal(event);
    }
}

void Tracer::traceInternal(const CodecEvent * const event) {
    if (event == nullptr) {
        return;
    }
    std::string trackName;
    std::string eType, eName;
    std::vector<audio_utils::trace::Object> eventInfo;
    event->getType(eType);
    trackName = eType + mCodecNameId;
    event->getInfos(eventInfo);
    event->getName(eName);
    for (auto &info : eventInfo) {
        if (eName.find(kCodecTraceStateAllocated) != eName.npos) {
            info.set(kCodecTraceObjectKeyPid, mPid)
                    .set(kCodecTraceObjectKeyUid, mUid)
                    .set(kCodecTraceObjectKeyBufferCountIntervalMs,
                            kCodecTraceValueBufferCountIntervalMs);

        }
        ATRACE_INSTANT_FOR_TRACK(trackName.c_str(), info.toTrace().c_str());
    }
}

void Tracer::process(const bool delayed) {
    if (ATRACE_ENABLED()) [[unlikely]] {
        std::string _s;
        int64_t now = ALooper::GetNowUs();
        int64_t delayUs = (kCodecTraceValueBufferCountIntervalMs * 1000);
        int64_t diff = delayed ? (now - mLastTraced) : delayUs;
        if (mLastTraced == 0 || diff >= delayUs) {
            ALOGV("Now: %lld LastTraced: %lld diff: %lld",
                    (long long)now, (long long)mLastTraced, (long long)diff);
            for (auto &event : mBufferEvents) {
                if (event && event->isActive()) {
                    trace(event.get());
                    event->clear();
                }
            }
            mLastTraced = now;
        }
    } else {
        // clear any events already present
        for (int i = 0; i < mBufferEvents.size(); i++) {
            mBufferEvents[i]->clear();
        }
    }
}

}