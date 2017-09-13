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

//#define LOG_NDEBUG 0
#define LOG_TAG "CCodec"
#include <utils/Log.h>

// XXX: HACK
#include "codecs/avcdec/C2SoftAvcDec.h"

#include <thread>

#include <gui/Surface.h>
#include <media/stagefright/CCodec.h>

#include "include/CCodecBufferChannel.h"

using namespace std::chrono_literals;

namespace android {

namespace {

class CCodecWatchdog : public AHandler {
private:
    enum {
        kWhatRegister,
        kWhatWatch,
    };
    constexpr static int64_t kWatchIntervalUs = 3000000;  // 3 secs

public:
    static sp<CCodecWatchdog> getInstance() {
        Mutexed<sp<CCodecWatchdog>>::Locked instance(sInstance);
        if (*instance == nullptr) {
            *instance = new CCodecWatchdog;
            (*instance)->init();
        }
        return *instance;
    }

    ~CCodecWatchdog() = default;

    void registerCodec(CCodec *codec) {
        sp<AMessage> msg = new AMessage(kWhatRegister, this);
        msg->setPointer("codec", codec);
        msg->post();
    }

protected:
    void onMessageReceived(const sp<AMessage> &msg) {
        switch (msg->what()) {
            case kWhatRegister: {
                void *ptr = nullptr;
                CHECK(msg->findPointer("codec", &ptr));
                Mutexed<std::list<wp<CCodec>>>::Locked codecs(mCodecs);
                codecs->emplace_back((CCodec *)ptr);
                break;
            }

            case kWhatWatch: {
                Mutexed<std::list<wp<CCodec>>>::Locked codecs(mCodecs);
                for (auto it = codecs->begin(); it != codecs->end(); ) {
                    sp<CCodec> codec = it->promote();
                    if (codec == nullptr) {
                        it = codecs->erase(it);
                        continue;
                    }
                    codec->initiateReleaseIfStuck();
                    ++it;
                }
                msg->post(kWatchIntervalUs);
                break;
            }

            default: {
                TRESPASS("CCodecWatchdog: unrecognized message");
            }
        }
    }

private:
    CCodecWatchdog() : mLooper(new ALooper) {}

    void init() {
        mLooper->setName("CCodecWatchdog");
        mLooper->registerHandler(this);
        mLooper->start();
        (new AMessage(kWhatWatch, this))->post(kWatchIntervalUs);
    }

    static Mutexed<sp<CCodecWatchdog>> sInstance;

    sp<ALooper> mLooper;
    Mutexed<std::list<wp<CCodec>>> mCodecs;
};

Mutexed<sp<CCodecWatchdog>> CCodecWatchdog::sInstance;

class CCodecListener : public C2Component::Listener {
public:
    CCodecListener(const std::shared_ptr<CCodecBufferChannel> &channel)
        : mChannel(channel) {
    }

    virtual void onWorkDone_nb(
            std::weak_ptr<C2Component> component,
            std::vector<std::unique_ptr<C2Work>> workItems) override {
        (void) component;
        mChannel->onWorkDone(std::move(workItems));
    }

    virtual void onTripped_nb(
            std::weak_ptr<C2Component> component,
            std::vector<std::shared_ptr<C2SettingResult>> settingResult) override {
        // TODO
        (void) component;
        (void) settingResult;
    }

    virtual void onError_nb(std::weak_ptr<C2Component> component, uint32_t errorCode) override {
        // TODO
        (void) component;
        (void) errorCode;
    }

private:
    std::shared_ptr<CCodecBufferChannel> mChannel;
};

}  // namespace

CCodec::CCodec()
    : mChannel(new CCodecBufferChannel([this] (status_t err, enum ActionCode actionCode) {
          mCallback->onError(err, actionCode);
      })) {
    CCodecWatchdog::getInstance()->registerCodec(this);
}

CCodec::~CCodec() {
}

std::shared_ptr<BufferChannelBase> CCodec::getBufferChannel() {
    return mChannel;
}

void CCodec::initiateAllocateComponent(const sp<AMessage> &msg) {
    {
        Mutexed<State>::Locked state(mState);
        if (state->mState != RELEASED) {
            mCallback->onError(INVALID_OPERATION, ACTION_CODE_FATAL);
            return;
        }
        state->mState = ALLOCATING;
    }

    AString componentName;
    if (!msg->findString("componentName", &componentName)) {
        // TODO: find componentName appropriate with the media type
    }

    sp<AMessage> allocMsg(new AMessage(kWhatAllocate, this));
    allocMsg->setString("componentName", componentName);
    allocMsg->post();
}

void CCodec::allocate(const AString &componentName) {
    // TODO: use C2ComponentStore to create component
    mListener.reset(new CCodecListener(mChannel));

    std::shared_ptr<C2Component> comp(new C2SoftAvcDec(componentName.c_str(), 0));
    comp->setListener_sm(mListener);
    {
        Mutexed<State>::Locked state(mState);
        if (state->mState != ALLOCATING) {
            state->mState = RELEASED;
            state.unlock();
            mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
            state.lock();
            return;
        }
        state->mState = ALLOCATED;
        state->mComp = comp;
    }
    mChannel->setComponent(comp);
    mCallback->onComponentAllocated(comp->intf()->getName().c_str());
}

void CCodec::initiateConfigureComponent(const sp<AMessage> &format) {
    {
        Mutexed<State>::Locked state(mState);
        if (state->mState != ALLOCATED) {
            mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
            return;
        }
    }

    sp<AMessage> msg(new AMessage(kWhatConfigure, this));
    msg->setMessage("format", format);
    msg->post();
}

void CCodec::configure(const sp<AMessage> &msg) {
    sp<AMessage> inputFormat(new AMessage);
    sp<AMessage> outputFormat(new AMessage);
    if (status_t err = [=] {
        AString mime;
        if (!msg->findString("mime", &mime)) {
            return BAD_VALUE;
        }

        int32_t encoder;
        if (!msg->findInt32("encoder", &encoder)) {
            encoder = false;
        }

        sp<RefBase> obj;
        if (msg->findObject("native-window", &obj)) {
            sp<Surface> surface = static_cast<Surface *>(obj.get());
            setSurface(surface);
        }

        // TODO

        return OK;
    }() != OK) {
        mCallback->onError(err, ACTION_CODE_FATAL);
        return;
    }

    {
        Mutexed<Formats>::Locked formats(mFormats);
        formats->mInputFormat = inputFormat;
        formats->mOutputFormat = outputFormat;
    }
    mCallback->onComponentConfigured(inputFormat, outputFormat);
}


void CCodec::initiateCreateInputSurface() {
    // TODO
}

void CCodec::initiateSetInputSurface(const sp<PersistentSurface> &surface) {
    // TODO
    (void) surface;
}

void CCodec::initiateStart() {
    {
        Mutexed<State>::Locked state(mState);
        if (state->mState != ALLOCATED) {
            state.unlock();
            mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
            state.lock();
            return;
        }
        state->mState = STARTING;
    }

    (new AMessage(kWhatStart, this))->post();
}

void CCodec::start() {
    std::shared_ptr<C2Component> comp;
    {
        Mutexed<State>::Locked state(mState);
        if (state->mState != STARTING) {
            state.unlock();
            mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
            state.lock();
            return;
        }
        comp = state->mComp;
    }
    c2_status_t err = comp->start();
    if (err != C2_OK) {
        // TODO: convert err into status_t
        mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
        return;
    }
    sp<AMessage> inputFormat;
    sp<AMessage> outputFormat;
    {
        Mutexed<Formats>::Locked formats(mFormats);
        inputFormat = formats->mInputFormat;
        outputFormat = formats->mOutputFormat;
    }
    mChannel->start(inputFormat, outputFormat);

    {
        Mutexed<State>::Locked state(mState);
        if (state->mState != STARTING) {
            state.unlock();
            mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
            state.lock();
            return;
        }
        state->mState = RUNNING;
    }
    mCallback->onStartCompleted();
}

void CCodec::initiateShutdown(bool keepComponentAllocated) {
    if (keepComponentAllocated) {
        initiateStop();
    } else {
        initiateRelease();
    }
}

void CCodec::initiateStop() {
    {
        Mutexed<State>::Locked state(mState);
        if (state->mState == ALLOCATED
                || state->mState  == RELEASED
                || state->mState == STOPPING
                || state->mState == RELEASING) {
            // We're already stopped, released, or doing it right now.
            state.unlock();
            mCallback->onStopCompleted();
            state.lock();
            return;
        }
        state->mState = STOPPING;
    }

    (new AMessage(kWhatStop, this))->post();
}

void CCodec::stop() {
    std::shared_ptr<C2Component> comp;
    {
        Mutexed<State>::Locked state(mState);
        if (state->mState == RELEASING) {
            state.unlock();
            // We're already stopped or release is in progress.
            mCallback->onStopCompleted();
            state.lock();
            return;
        } else if (state->mState != STOPPING) {
            state.unlock();
            mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
            state.lock();
            return;
        }
        comp = state->mComp;
    }
    mChannel->stop();
    status_t err = comp->stop();
    if (err != C2_OK) {
        // TODO: convert err into status_t
        mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
    }

    {
        Mutexed<State>::Locked state(mState);
        if (state->mState == STOPPING) {
            state->mState = ALLOCATED;
        }
    }
    mCallback->onStopCompleted();
}

void CCodec::initiateRelease(bool sendCallback /* = true */) {
    {
        Mutexed<State>::Locked state(mState);
        if (state->mState == RELEASED || state->mState == RELEASING) {
            // We're already released or doing it right now.
            if (sendCallback) {
                state.unlock();
                mCallback->onReleaseCompleted();
                state.lock();
            }
            return;
        }
        if (state->mState == ALLOCATING) {
            state->mState = RELEASING;
            // With the altered state allocate() would fail and clean up.
            if (sendCallback) {
                state.unlock();
                mCallback->onReleaseCompleted();
                state.lock();
            }
            return;
        }
        state->mState = RELEASING;
    }

    std::thread([this, sendCallback] { release(sendCallback); }).detach();
}

void CCodec::release(bool sendCallback) {
    std::shared_ptr<C2Component> comp;
    {
        Mutexed<State>::Locked state(mState);
        if (state->mState == RELEASED) {
            if (sendCallback) {
                state.unlock();
                mCallback->onReleaseCompleted();
                state.lock();
            }
            return;
        }
        comp = state->mComp;
    }
    mChannel->stop();
    comp->release();

    {
        Mutexed<State>::Locked state(mState);
        state->mState = RELEASED;
        state->mComp.reset();
    }
    if (sendCallback) {
        mCallback->onReleaseCompleted();
    }
}

status_t CCodec::setSurface(const sp<Surface> &surface) {
    return mChannel->setSurface(surface);
}

void CCodec::signalFlush() {
    {
        Mutexed<State>::Locked state(mState);
        if (state->mState != RUNNING) {
            mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
            return;
        }
        state->mState = FLUSHING;
    }

    (new AMessage(kWhatFlush, this))->post();
}

void CCodec::flush() {
    std::shared_ptr<C2Component> comp;
    {
        Mutexed<State>::Locked state(mState);
        if (state->mState != FLUSHING) {
            state.unlock();
            mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
            state.lock();
            return;
        }
        comp = state->mComp;
    }

    mChannel->stop();

    std::list<std::unique_ptr<C2Work>> flushedWork;
    c2_status_t err = comp->flush_sm(C2Component::FLUSH_COMPONENT, &flushedWork);
    if (err != C2_OK) {
        // TODO: convert err into status_t
        mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
    }

    mChannel->flush(flushedWork);

    {
        Mutexed<State>::Locked state(mState);
        state->mState = FLUSHED;
    }
    mCallback->onFlushCompleted();
}

void CCodec::signalResume() {
    {
        Mutexed<State>::Locked state(mState);
        if (state->mState != FLUSHED) {
            state.unlock();
            mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
            state.lock();
            return;
        }
        state->mState = RESUMING;
    }

    mChannel->start(nullptr, nullptr);

    {
        Mutexed<State>::Locked state(mState);
        if (state->mState != RESUMING) {
            state.unlock();
            mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
            state.lock();
            return;
        }
        state->mState = RUNNING;
    }
}

void CCodec::signalSetParameters(const sp<AMessage> &msg) {
    // TODO
    (void) msg;
}

void CCodec::signalEndOfInputStream() {
}

void CCodec::signalRequestIDRFrame() {
    // TODO
}

void CCodec::onMessageReceived(const sp<AMessage> &msg) {
    TimePoint now = std::chrono::steady_clock::now();
    switch (msg->what()) {
        case kWhatAllocate: {
            // C2ComponentStore::createComponent() should return within 100ms.
            setDeadline(now + 150ms);
            AString componentName;
            CHECK(msg->findString("componentName", &componentName));
            allocate(componentName);
            break;
        }
        case kWhatConfigure: {
            // C2Component::commit_sm() should return within 5ms.
            setDeadline(now + 50ms);
            sp<AMessage> format;
            CHECK(msg->findMessage("format", &format));
            configure(format);
            break;
        }
        case kWhatStart: {
            // C2Component::start() should return within 500ms.
            setDeadline(now + 550ms);
            start();
            break;
        }
        case kWhatStop: {
            // C2Component::stop() should return within 500ms.
            setDeadline(now + 550ms);
            stop();
            break;
        }
        case kWhatFlush: {
            // C2Component::flush_sm() should return within 5ms.
            setDeadline(now + 50ms);
            flush();
            break;
        }
        default: {
            ALOGE("unrecognized message");
            break;
        }
    }
    setDeadline(TimePoint::max());
}

void CCodec::setDeadline(const TimePoint &newDeadline) {
    Mutexed<TimePoint>::Locked deadline(mDeadline);
    *deadline = newDeadline;
}

void CCodec::initiateReleaseIfStuck() {
    {
        Mutexed<TimePoint>::Locked deadline(mDeadline);
        if (*deadline >= std::chrono::steady_clock::now()) {
            // We're not stuck.
            return;
        }
    }

    mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
    initiateRelease();
}

}  // namespace android
