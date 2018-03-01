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
#include <cutils/properties.h>
#include <utils/Log.h>

#include <thread>

#include <C2PlatformSupport.h>
#include <C2V4l2Support.h>

#include <android/IOMXBufferSource.h>
#include <gui/bufferqueue/1.0/H2BGraphicBufferProducer.h>
#include <gui/Surface.h>
#include <media/stagefright/codec2/1.0/InputSurface.h>
#include <media/stagefright/BufferProducerWrapper.h>
#include <media/stagefright/CCodec.h>
#include <media/stagefright/PersistentSurface.h>

#include "include/C2OMXNode.h"
#include "include/CCodecBufferChannel.h"
#include "include/InputSurfaceWrapper.h"

namespace android {

using namespace std::chrono_literals;
using ::android::hardware::graphics::bufferqueue::V1_0::utils::H2BGraphicBufferProducer;

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
    explicit CCodecListener(const wp<CCodec> &codec) : mCodec(codec) {}

    virtual void onWorkDone_nb(
            std::weak_ptr<C2Component> component,
            std::list<std::unique_ptr<C2Work>> workItems) override {
        (void)component;
        sp<CCodec> codec(mCodec.promote());
        if (!codec) {
            return;
        }
        codec->onWorkDone(workItems);
    }

    virtual void onTripped_nb(
            std::weak_ptr<C2Component> component,
            std::vector<std::shared_ptr<C2SettingResult>> settingResult) override {
        // TODO
        (void)component;
        (void)settingResult;
    }

    virtual void onError_nb(std::weak_ptr<C2Component> component, uint32_t errorCode) override {
        // TODO
        (void)component;
        (void)errorCode;
    }

private:
    wp<CCodec> mCodec;
};

class C2InputSurfaceWrapper : public InputSurfaceWrapper {
public:
    explicit C2InputSurfaceWrapper(const sp<InputSurface> &surface) : mSurface(surface) {}
    ~C2InputSurfaceWrapper() override = default;

    status_t connect(const std::shared_ptr<C2Component> &comp) override {
        if (mConnection != nullptr) {
            return ALREADY_EXISTS;
        }
        mConnection = mSurface->connectToComponent(comp);
        return OK;
    }

    void disconnect() override {
        if (mConnection != nullptr) {
            mConnection->disconnect();
            mConnection.clear();
        }
    }

private:
    sp<InputSurface> mSurface;
    sp<InputSurfaceConnection> mConnection;
};

class GraphicBufferSourceWrapper : public InputSurfaceWrapper {
public:
    explicit GraphicBufferSourceWrapper(const sp<IGraphicBufferSource> &source) : mSource(source) {}
    ~GraphicBufferSourceWrapper() override = default;

    status_t connect(const std::shared_ptr<C2Component> &comp) override {
        // TODO: proper color aspect & dataspace
        android_dataspace dataSpace = HAL_DATASPACE_BT709;

        mNode = new C2OMXNode(comp);
        mSource->configure(mNode, dataSpace);

        // TODO: configure according to intf().

        sp<IOMXBufferSource> source = mNode->getSource();
        if (source == nullptr) {
            return NO_INIT;
        }
        constexpr size_t kNumSlots = 16;
        for (size_t i = 0; i < kNumSlots; ++i) {
            source->onInputBufferAdded(i);
        }
        source->onOmxExecuting();
        return OK;
    }

    void disconnect() override {
        if (mNode == nullptr) {
            return;
        }
        sp<IOMXBufferSource> source = mNode->getSource();
        if (source == nullptr) {
            ALOGD("GBSWrapper::disconnect: node is not configured with OMXBufferSource.");
            return;
        }
        source->onOmxIdle();
        source->onOmxLoaded();
        mNode.clear();
    }

private:
    sp<IGraphicBufferSource> mSource;
    sp<C2OMXNode> mNode;
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

status_t CCodec::tryAndReportOnError(std::function<status_t()> job) {
    status_t err = job();
    if (err != C2_OK) {
        mCallback->onError(err, ACTION_CODE_FATAL);
    }
    return err;
}

void CCodec::initiateAllocateComponent(const sp<AMessage> &msg) {
    auto setAllocating = [this] {
        Mutexed<State>::Locked state(mState);
        if (state->get() != RELEASED) {
            return INVALID_OPERATION;
        }
        state->set(ALLOCATING);
        return OK;
    };
    if (tryAndReportOnError(setAllocating) != OK) {
        return;
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
    ALOGV("allocate(%s)", componentName.c_str());
    mListener.reset(new CCodecListener(this));

    std::shared_ptr<C2Component> comp;
    c2_status_t err = GetCodec2PlatformComponentStore()->createComponent(
            componentName.c_str(), &comp);
    static bool v4l2Enabled =
            property_get_bool("debug.stagefright.ccodec_v4l2", false);
    if (err != C2_OK && v4l2Enabled) {
        err = GetCodec2VDAComponentStore()->createComponent(
                componentName.c_str(), &comp);
    }
    if (err != C2_OK) {
        ALOGE("Failed Create component: %s", componentName.c_str());
        Mutexed<State>::Locked state(mState);
        state->set(RELEASED);
        state.unlock();
        mCallback->onError(err, ACTION_CODE_FATAL);
        state.lock();
        return;
    }
    ALOGV("Success Create component: %s", componentName.c_str());
    comp->setListener_vb(mListener, C2_MAY_BLOCK);
    mChannel->setComponent(comp);
    auto setAllocated = [this, comp] {
        Mutexed<State>::Locked state(mState);
        if (state->get() != ALLOCATING) {
            state->set(RELEASED);
            return UNKNOWN_ERROR;
        }
        state->set(ALLOCATED);
        state->comp = comp;
        return OK;
    };
    if (tryAndReportOnError(setAllocated) != OK) {
        return;
    }
    mCallback->onComponentAllocated(comp->intf()->getName().c_str());
}

void CCodec::initiateConfigureComponent(const sp<AMessage> &format) {
    auto checkAllocated = [this] {
        Mutexed<State>::Locked state(mState);
        return (state->get() != ALLOCATED) ? UNKNOWN_ERROR : OK;
    };
    if (tryAndReportOnError(checkAllocated) != OK) {
        return;
    }

    sp<AMessage> msg(new AMessage(kWhatConfigure, this));
    msg->setMessage("format", format);
    msg->post();
}

void CCodec::configure(const sp<AMessage> &msg) {
    std::shared_ptr<C2ComponentInterface> intf;
    auto checkAllocated = [this, &intf] {
        Mutexed<State>::Locked state(mState);
        if (state->get() != ALLOCATED) {
            state->set(RELEASED);
            return UNKNOWN_ERROR;
        }
        intf = state->comp->intf();
        return OK;
    };
    if (tryAndReportOnError(checkAllocated) != OK) {
        return;
    }

    sp<AMessage> inputFormat(new AMessage);
    sp<AMessage> outputFormat(new AMessage);
    auto doConfig = [=] {
        AString mime;
        if (!msg->findString("mime", &mime)) {
            return BAD_VALUE;
        }

        int32_t encoder;
        if (!msg->findInt32("encoder", &encoder)) {
            encoder = false;
        }

        // TODO: read from intf()
        if ((!encoder) != (intf->getName().find("encoder") == std::string::npos)) {
            return UNKNOWN_ERROR;
        }

        sp<RefBase> obj;
        if (msg->findObject("native-window", &obj)) {
            sp<Surface> surface = static_cast<Surface *>(obj.get());
            setSurface(surface);
        }

        std::vector<std::unique_ptr<C2Param>> params;
        std::initializer_list<C2Param::Index> indices {
            C2PortMimeConfig::input::PARAM_TYPE,
            C2PortMimeConfig::output::PARAM_TYPE,
        };
        c2_status_t c2err = intf->query_vb(
                {},
                indices,
                C2_DONT_BLOCK,
                &params);
        if (c2err != C2_OK) {
            ALOGE("Failed to query component interface: %d", c2err);
            return UNKNOWN_ERROR;
        }
        if (params.size() != indices.size()) {
            ALOGE("Component returns wrong number of params");
            return UNKNOWN_ERROR;
        }
        if (!params[0] || !params[1]) {
            ALOGE("Component returns null params");
            return UNKNOWN_ERROR;
        }
        inputFormat->setString("mime", ((C2PortMimeConfig *)params[0].get())->m.value);
        outputFormat->setString("mime", ((C2PortMimeConfig *)params[1].get())->m.value);

        // XXX: hack
        bool audio = mime.startsWithIgnoreCase("audio/");
        if (encoder) {
            if (audio) {
                inputFormat->setInt32("channel-count", 1);
                inputFormat->setInt32("sample-rate", 44100);
                outputFormat->setInt32("channel-count", 1);
                outputFormat->setInt32("sample-rate", 44100);
            } else {
                outputFormat->setInt32("width", 1080);
                outputFormat->setInt32("height", 1920);
            }
        } else {
            if (audio) {
                outputFormat->setInt32("channel-count", 2);
                outputFormat->setInt32("sample-rate", 44100);
            }
        }

        // TODO

        return OK;
    };
    if (tryAndReportOnError(doConfig) != OK) {
        return;
    }

    {
        Mutexed<Formats>::Locked formats(mFormats);
        formats->inputFormat = inputFormat;
        formats->outputFormat = outputFormat;
    }
    mCallback->onComponentConfigured(inputFormat, outputFormat);
}

void CCodec::initiateCreateInputSurface() {
    status_t err = [this] {
        Mutexed<State>::Locked state(mState);
        if (state->get() != ALLOCATED) {
            return UNKNOWN_ERROR;
        }
        // TODO: read it from intf() properly.
        if (state->comp->intf()->getName().find("encoder") == std::string::npos) {
            return INVALID_OPERATION;
        }
        return OK;
    }();
    if (err != OK) {
        mCallback->onInputSurfaceCreationFailed(err);
        return;
    }

    (new AMessage(kWhatCreateInputSurface, this))->post();
}

void CCodec::createInputSurface() {
    // TODO: get this from codec process
    sp<InputSurface> surface(InputSurface::Create());

    // TODO: get proper error code.
    status_t err = (surface == nullptr) ? UNKNOWN_ERROR : OK;
    if (err != OK) {
        ALOGE("Failed to initialize input surface: %d", err);
        mCallback->onInputSurfaceCreationFailed(err);
        return;
    }

    err = setupInputSurface(std::make_shared<C2InputSurfaceWrapper>(surface));
    if (err != OK) {
        ALOGE("Failed to set up input surface: %d", err);
        mCallback->onInputSurfaceCreationFailed(err);
        return;
    }

    sp<AMessage> inputFormat;
    sp<AMessage> outputFormat;
    {
        Mutexed<Formats>::Locked formats(mFormats);
        inputFormat = formats->inputFormat;
        outputFormat = formats->outputFormat;
    }
    mCallback->onInputSurfaceCreated(
            inputFormat,
            outputFormat,
            new BufferProducerWrapper(new H2BGraphicBufferProducer(surface)));
}

status_t CCodec::setupInputSurface(const std::shared_ptr<InputSurfaceWrapper> &surface) {
    status_t err = mChannel->setInputSurface(surface);
    if (err != OK) {
        return err;
    }

    // TODO: configure |surface| with other settings.
    return OK;
}

void CCodec::initiateSetInputSurface(const sp<PersistentSurface> &surface) {
    sp<AMessage> msg = new AMessage(kWhatSetInputSurface, this);
    msg->setObject("surface", surface);
    msg->post();
}

void CCodec::setInputSurface(const sp<PersistentSurface> &surface) {
    status_t err = setupInputSurface(std::make_shared<GraphicBufferSourceWrapper>(
            surface->getBufferSource()));
    if (err != OK) {
        ALOGE("Failed to set up input surface: %d", err);
        mCallback->onInputSurfaceDeclined(err);
        return;
    }

    sp<AMessage> inputFormat;
    sp<AMessage> outputFormat;
    {
        Mutexed<Formats>::Locked formats(mFormats);
        inputFormat = formats->inputFormat;
        outputFormat = formats->outputFormat;
    }
    mCallback->onInputSurfaceAccepted(inputFormat, outputFormat);
}

void CCodec::initiateStart() {
    auto setStarting = [this] {
        Mutexed<State>::Locked state(mState);
        if (state->get() != ALLOCATED) {
            return UNKNOWN_ERROR;
        }
        state->set(STARTING);
        return OK;
    };
    if (tryAndReportOnError(setStarting) != OK) {
        return;
    }

    (new AMessage(kWhatStart, this))->post();
}

void CCodec::start() {
    std::shared_ptr<C2Component> comp;
    auto checkStarting = [this, &comp] {
        Mutexed<State>::Locked state(mState);
        if (state->get() != STARTING) {
            return UNKNOWN_ERROR;
        }
        comp = state->comp;
        return OK;
    };
    if (tryAndReportOnError(checkStarting) != OK) {
        return;
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
        inputFormat = formats->inputFormat;
        outputFormat = formats->outputFormat;
    }
    status_t err2 = mChannel->start(inputFormat, outputFormat);
    if (err2 != OK) {
        mCallback->onError(err2, ACTION_CODE_FATAL);
        return;
    }

    auto setRunning = [this] {
        Mutexed<State>::Locked state(mState);
        if (state->get() != STARTING) {
            return UNKNOWN_ERROR;
        }
        state->set(RUNNING);
        return OK;
    };
    if (tryAndReportOnError(setRunning) != OK) {
        return;
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
        if (state->get() == ALLOCATED
                || state->get()  == RELEASED
                || state->get() == STOPPING
                || state->get() == RELEASING) {
            // We're already stopped, released, or doing it right now.
            state.unlock();
            mCallback->onStopCompleted();
            state.lock();
            return;
        }
        state->set(STOPPING);
    }

    (new AMessage(kWhatStop, this))->post();
}

void CCodec::stop() {
    std::shared_ptr<C2Component> comp;
    {
        Mutexed<State>::Locked state(mState);
        if (state->get() == RELEASING) {
            state.unlock();
            // We're already stopped or release is in progress.
            mCallback->onStopCompleted();
            state.lock();
            return;
        } else if (state->get() != STOPPING) {
            state.unlock();
            mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
            state.lock();
            return;
        }
        comp = state->comp;
    }
    mChannel->stop();
    status_t err = comp->stop();
    if (err != C2_OK) {
        // TODO: convert err into status_t
        mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
    }

    {
        Mutexed<State>::Locked state(mState);
        if (state->get() == STOPPING) {
            state->set(ALLOCATED);
        }
    }
    mCallback->onStopCompleted();
}

void CCodec::initiateRelease(bool sendCallback /* = true */) {
    {
        Mutexed<State>::Locked state(mState);
        if (state->get() == RELEASED || state->get() == RELEASING) {
            // We're already released or doing it right now.
            if (sendCallback) {
                state.unlock();
                mCallback->onReleaseCompleted();
                state.lock();
            }
            return;
        }
        if (state->get() == ALLOCATING) {
            state->set(RELEASING);
            // With the altered state allocate() would fail and clean up.
            if (sendCallback) {
                state.unlock();
                mCallback->onReleaseCompleted();
                state.lock();
            }
            return;
        }
        state->set(RELEASING);
    }

    std::thread([this, sendCallback] { release(sendCallback); }).detach();
}

void CCodec::release(bool sendCallback) {
    std::shared_ptr<C2Component> comp;
    {
        Mutexed<State>::Locked state(mState);
        if (state->get() == RELEASED) {
            if (sendCallback) {
                state.unlock();
                mCallback->onReleaseCompleted();
                state.lock();
            }
            return;
        }
        comp = state->comp;
    }
    mChannel->stop();
    comp->release();

    {
        Mutexed<State>::Locked state(mState);
        state->set(RELEASED);
        state->comp.reset();
    }
    if (sendCallback) {
        mCallback->onReleaseCompleted();
    }
}

status_t CCodec::setSurface(const sp<Surface> &surface) {
    return mChannel->setSurface(surface);
}

void CCodec::signalFlush() {
    status_t err = [this] {
        Mutexed<State>::Locked state(mState);
        if (state->get() == FLUSHED) {
            return ALREADY_EXISTS;
        }
        if (state->get() != RUNNING) {
            return UNKNOWN_ERROR;
        }
        state->set(FLUSHING);
        return OK;
    }();
    switch (err) {
        case ALREADY_EXISTS:
            mCallback->onFlushCompleted();
            return;
        case OK:
            break;
        default:
            mCallback->onError(err, ACTION_CODE_FATAL);
            return;
    }

    (new AMessage(kWhatFlush, this))->post();
}

void CCodec::flush() {
    std::shared_ptr<C2Component> comp;
    auto checkFlushing = [this, &comp] {
        Mutexed<State>::Locked state(mState);
        if (state->get() != FLUSHING) {
            return UNKNOWN_ERROR;
        }
        comp = state->comp;
        return OK;
    };
    if (tryAndReportOnError(checkFlushing) != OK) {
        return;
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
        state->set(FLUSHED);
    }
    mCallback->onFlushCompleted();
}

void CCodec::signalResume() {
    auto setResuming = [this] {
        Mutexed<State>::Locked state(mState);
        if (state->get() != FLUSHED) {
            return UNKNOWN_ERROR;
        }
        state->set(RESUMING);
        return OK;
    };
    if (tryAndReportOnError(setResuming) != OK) {
        return;
    }

    (void)mChannel->start(nullptr, nullptr);

    {
        Mutexed<State>::Locked state(mState);
        if (state->get() != RESUMING) {
            state.unlock();
            mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
            state.lock();
            return;
        }
        state->set(RUNNING);
    }
}

void CCodec::signalSetParameters(const sp<AMessage> &msg) {
    // TODO
    (void) msg;
}

void CCodec::signalEndOfInputStream() {
    // TODO
    mCallback->onSignaledInputEOS(INVALID_OPERATION);
}

void CCodec::signalRequestIDRFrame() {
    // TODO
}

void CCodec::onWorkDone(std::list<std::unique_ptr<C2Work>> &workItems) {
    Mutexed<std::list<std::unique_ptr<C2Work>>>::Locked queue(mWorkDoneQueue);
    queue->splice(queue->end(), workItems);
    (new AMessage(kWhatWorkDone, this))->post();
}

void CCodec::onMessageReceived(const sp<AMessage> &msg) {
    TimePoint now = std::chrono::steady_clock::now();
    switch (msg->what()) {
        case kWhatAllocate: {
            // C2ComponentStore::createComponent() should return within 100ms.
            setDeadline(now + 150ms, "allocate");
            AString componentName;
            CHECK(msg->findString("componentName", &componentName));
            allocate(componentName);
            break;
        }
        case kWhatConfigure: {
            // C2Component::commit_sm() should return within 5ms.
            setDeadline(now + 50ms, "configure");
            sp<AMessage> format;
            CHECK(msg->findMessage("format", &format));
            configure(format);
            break;
        }
        case kWhatStart: {
            // C2Component::start() should return within 500ms.
            setDeadline(now + 550ms, "start");
            start();
            break;
        }
        case kWhatStop: {
            // C2Component::stop() should return within 500ms.
            setDeadline(now + 550ms, "stop");
            stop();
            break;
        }
        case kWhatFlush: {
            // C2Component::flush_sm() should return within 5ms.
            setDeadline(now + 50ms, "flush");
            flush();
            break;
        }
        case kWhatCreateInputSurface: {
            // Surface operations may be briefly blocking.
            setDeadline(now + 100ms, "createInputSurface");
            createInputSurface();
            break;
        }
        case kWhatSetInputSurface: {
            // Surface operations may be briefly blocking.
            setDeadline(now + 100ms, "setInputSurface");
            sp<RefBase> obj;
            CHECK(msg->findObject("surface", &obj));
            sp<PersistentSurface> surface(static_cast<PersistentSurface *>(obj.get()));
            setInputSurface(surface);
            break;
        }
        case kWhatWorkDone: {
            std::unique_ptr<C2Work> work;
            {
                Mutexed<std::list<std::unique_ptr<C2Work>>>::Locked queue(mWorkDoneQueue);
                if (queue->empty()) {
                    break;
                }
                work.swap(queue->front());
                queue->pop_front();
                if (!queue->empty()) {
                    (new AMessage(kWhatWorkDone, this))->post();
                }
            }
            mChannel->onWorkDone(work);
            break;
        }
        default: {
            ALOGE("unrecognized message");
            break;
        }
    }
    setDeadline(TimePoint::max(), "none");
}

void CCodec::setDeadline(const TimePoint &newDeadline, const char *name) {
    Mutexed<NamedTimePoint>::Locked deadline(mDeadline);
    deadline->set(newDeadline, name);
}

void CCodec::initiateReleaseIfStuck() {
    std::string name;
    {
        Mutexed<NamedTimePoint>::Locked deadline(mDeadline);
        if (deadline->get() >= std::chrono::steady_clock::now()) {
            // We're not stuck.
            return;
        }
        name = deadline->getName();
    }

    ALOGW("previous call to %s exceeded timeout", name.c_str());
    initiateRelease(false);
    mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
}

}  // namespace android
