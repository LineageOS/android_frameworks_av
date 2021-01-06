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

#include <sstream>
#include <thread>

#include <C2Config.h>
#include <C2Debug.h>
#include <C2ParamInternal.h>
#include <C2PlatformSupport.h>

#include <android/IOMXBufferSource.h>
#include <android/hardware/media/c2/1.0/IInputSurface.h>
#include <android/hardware/media/omx/1.0/IGraphicBufferSource.h>
#include <android/hardware/media/omx/1.0/IOmx.h>
#include <android-base/stringprintf.h>
#include <cutils/properties.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/Surface.h>
#include <gui/bufferqueue/1.0/H2BGraphicBufferProducer.h>
#include <media/omx/1.0/WOmxNode.h>
#include <media/openmax/OMX_Core.h>
#include <media/openmax/OMX_IndexExt.h>
#include <media/stagefright/omx/1.0/WGraphicBufferSource.h>
#include <media/stagefright/omx/OmxGraphicBufferSource.h>
#include <media/stagefright/CCodec.h>
#include <media/stagefright/BufferProducerWrapper.h>
#include <media/stagefright/MediaCodecConstants.h>
#include <media/stagefright/PersistentSurface.h>

#include "C2OMXNode.h"
#include "CCodecBufferChannel.h"
#include "CCodecConfig.h"
#include "Codec2Mapper.h"
#include "InputSurfaceWrapper.h"

extern "C" android::PersistentSurface *CreateInputSurface();

namespace android {

using namespace std::chrono_literals;
using ::android::hardware::graphics::bufferqueue::V1_0::utils::H2BGraphicBufferProducer;
using android::base::StringPrintf;
using ::android::hardware::media::c2::V1_0::IInputSurface;

typedef hardware::media::omx::V1_0::IGraphicBufferSource HGraphicBufferSource;
typedef CCodecConfig Config;

namespace {

class CCodecWatchdog : public AHandler {
private:
    enum {
        kWhatWatch,
    };
    constexpr static int64_t kWatchIntervalUs = 3300000;  // 3.3 secs

public:
    static sp<CCodecWatchdog> getInstance() {
        static sp<CCodecWatchdog> instance(new CCodecWatchdog);
        static std::once_flag flag;
        // Call Init() only once.
        std::call_once(flag, Init, instance);
        return instance;
    }

    ~CCodecWatchdog() = default;

    void watch(sp<CCodec> codec) {
        bool shouldPost = false;
        {
            Mutexed<std::set<wp<CCodec>>>::Locked codecs(mCodecsToWatch);
            // If a watch message is in flight, piggy-back this instance as well.
            // Otherwise, post a new watch message.
            shouldPost = codecs->empty();
            codecs->emplace(codec);
        }
        if (shouldPost) {
            ALOGV("posting watch message");
            (new AMessage(kWhatWatch, this))->post(kWatchIntervalUs);
        }
    }

protected:
    void onMessageReceived(const sp<AMessage> &msg) {
        switch (msg->what()) {
            case kWhatWatch: {
                Mutexed<std::set<wp<CCodec>>>::Locked codecs(mCodecsToWatch);
                ALOGV("watch for %zu codecs", codecs->size());
                for (auto it = codecs->begin(); it != codecs->end(); ++it) {
                    sp<CCodec> codec = it->promote();
                    if (codec == nullptr) {
                        continue;
                    }
                    codec->initiateReleaseIfStuck();
                }
                codecs->clear();
                break;
            }

            default: {
                TRESPASS("CCodecWatchdog: unrecognized message");
            }
        }
    }

private:
    CCodecWatchdog() : mLooper(new ALooper) {}

    static void Init(const sp<CCodecWatchdog> &thiz) {
        ALOGV("Init");
        thiz->mLooper->setName("CCodecWatchdog");
        thiz->mLooper->registerHandler(thiz);
        thiz->mLooper->start();
    }

    sp<ALooper> mLooper;

    Mutexed<std::set<wp<CCodec>>> mCodecsToWatch;
};

class C2InputSurfaceWrapper : public InputSurfaceWrapper {
public:
    explicit C2InputSurfaceWrapper(
            const std::shared_ptr<Codec2Client::InputSurface> &surface) :
        mSurface(surface) {
    }

    ~C2InputSurfaceWrapper() override = default;

    status_t connect(const std::shared_ptr<Codec2Client::Component> &comp) override {
        if (mConnection != nullptr) {
            return ALREADY_EXISTS;
        }
        return toStatusT(comp->connectToInputSurface(mSurface, &mConnection));
    }

    void disconnect() override {
        if (mConnection != nullptr) {
            mConnection->disconnect();
            mConnection = nullptr;
        }
    }

    status_t start() override {
        // InputSurface does not distinguish started state
        return OK;
    }

    status_t signalEndOfInputStream() override {
        C2InputSurfaceEosTuning eos(true);
        std::vector<std::unique_ptr<C2SettingResult>> failures;
        c2_status_t err = mSurface->config({&eos}, C2_MAY_BLOCK, &failures);
        if (err != C2_OK) {
            return UNKNOWN_ERROR;
        }
        return OK;
    }

    status_t configure(Config &config __unused) {
        // TODO
        return OK;
    }

private:
    std::shared_ptr<Codec2Client::InputSurface> mSurface;
    std::shared_ptr<Codec2Client::InputSurfaceConnection> mConnection;
};

class GraphicBufferSourceWrapper : public InputSurfaceWrapper {
public:
    typedef hardware::media::omx::V1_0::Status OmxStatus;

    GraphicBufferSourceWrapper(
            const sp<HGraphicBufferSource> &source,
            uint32_t width,
            uint32_t height,
            uint64_t usage)
        : mSource(source), mWidth(width), mHeight(height) {
        mDataSpace = HAL_DATASPACE_BT709;
        mConfig.mUsage = usage;
    }
    ~GraphicBufferSourceWrapper() override = default;

    status_t connect(const std::shared_ptr<Codec2Client::Component> &comp) override {
        mNode = new C2OMXNode(comp);
        mOmxNode = new hardware::media::omx::V1_0::utils::TWOmxNode(mNode);
        mNode->setFrameSize(mWidth, mHeight);

        // Usage is queried during configure(), so setting it beforehand.
        OMX_U32 usage = mConfig.mUsage & 0xFFFFFFFF;
        (void)mNode->setParameter(
                (OMX_INDEXTYPE)OMX_IndexParamConsumerUsageBits,
                &usage, sizeof(usage));

        // NOTE: we do not use/pass through color aspects from GraphicBufferSource as we
        // communicate that directly to the component.
        mSource->configure(
                mOmxNode, static_cast<hardware::graphics::common::V1_0::Dataspace>(mDataSpace));
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
        mOmxNode.clear();
    }

    status_t GetStatus(hardware::Return<OmxStatus> &&status) {
        if (status.isOk()) {
            return static_cast<status_t>(status.withDefault(OmxStatus::UNKNOWN_ERROR));
        } else if (status.isDeadObject()) {
            return DEAD_OBJECT;
        }
        return UNKNOWN_ERROR;
    }

    status_t start() override {
        sp<IOMXBufferSource> source = mNode->getSource();
        if (source == nullptr) {
            return NO_INIT;
        }

        size_t numSlots = 16;
        // WORKAROUND: having more slots improve performance while consuming
        // more memory. This is a temporary workaround to reduce memory for
        // larger-than-4K scenario.
        if (mWidth * mHeight > 4096 * 2340) {
            constexpr OMX_U32 kPortIndexInput = 0;

            OMX_PARAM_PORTDEFINITIONTYPE param;
            param.nPortIndex = kPortIndexInput;
            status_t err = mNode->getParameter(OMX_IndexParamPortDefinition,
                                               &param, sizeof(param));
            if (err == OK) {
                numSlots = param.nBufferCountActual;
            }
        }

        for (size_t i = 0; i < numSlots; ++i) {
            source->onInputBufferAdded(i);
        }

        source->onOmxExecuting();
        return OK;
    }

    status_t signalEndOfInputStream() override {
        return GetStatus(mSource->signalEndOfInputStream());
    }

    status_t configure(Config &config) {
        std::stringstream status;
        status_t err = OK;

        // handle each configuration granually, in case we need to handle part of the configuration
        // elsewhere

        // TRICKY: we do not unset frame delay repeating
        if (config.mMinFps > 0 && config.mMinFps != mConfig.mMinFps) {
            int64_t us = 1e6 / config.mMinFps + 0.5;
            status_t res = GetStatus(mSource->setRepeatPreviousFrameDelayUs(us));
            status << " minFps=" << config.mMinFps << " => repeatDelayUs=" << us;
            if (res != OK) {
                status << " (=> " << asString(res) << ")";
                err = res;
            }
            mConfig.mMinFps = config.mMinFps;
        }

        // pts gap
        if (config.mMinAdjustedFps > 0 || config.mFixedAdjustedFps > 0) {
            if (mNode != nullptr) {
                OMX_PARAM_U32TYPE ptrGapParam = {};
                ptrGapParam.nSize = sizeof(OMX_PARAM_U32TYPE);
                float gap = (config.mMinAdjustedFps > 0)
                        ? c2_min(INT32_MAX + 0., 1e6 / config.mMinAdjustedFps + 0.5)
                        : c2_max(0. - INT32_MAX, -1e6 / config.mFixedAdjustedFps - 0.5);
                // float -> uint32_t is undefined if the value is negative.
                // First convert to int32_t to ensure the expected behavior.
                ptrGapParam.nU32 = int32_t(gap);
                (void)mNode->setParameter(
                        (OMX_INDEXTYPE)OMX_IndexParamMaxFrameDurationForBitrateControl,
                        &ptrGapParam, sizeof(ptrGapParam));
            }
        }

        // max fps
        // TRICKY: we do not unset max fps to 0 unless using fixed fps
        if ((config.mMaxFps > 0 || (config.mFixedAdjustedFps > 0 && config.mMaxFps == -1))
                && config.mMaxFps != mConfig.mMaxFps) {
            status_t res = GetStatus(mSource->setMaxFps(config.mMaxFps));
            status << " maxFps=" << config.mMaxFps;
            if (res != OK) {
                status << " (=> " << asString(res) << ")";
                err = res;
            }
            mConfig.mMaxFps = config.mMaxFps;
        }

        if (config.mTimeOffsetUs != mConfig.mTimeOffsetUs) {
            status_t res = GetStatus(mSource->setTimeOffsetUs(config.mTimeOffsetUs));
            status << " timeOffset " << config.mTimeOffsetUs << "us";
            if (res != OK) {
                status << " (=> " << asString(res) << ")";
                err = res;
            }
            mConfig.mTimeOffsetUs = config.mTimeOffsetUs;
        }

        if (config.mCaptureFps != mConfig.mCaptureFps || config.mCodedFps != mConfig.mCodedFps) {
            status_t res =
                GetStatus(mSource->setTimeLapseConfig(config.mCodedFps, config.mCaptureFps));
            status << " timeLapse " << config.mCaptureFps << "fps as " << config.mCodedFps << "fps";
            if (res != OK) {
                status << " (=> " << asString(res) << ")";
                err = res;
            }
            mConfig.mCaptureFps = config.mCaptureFps;
            mConfig.mCodedFps = config.mCodedFps;
        }

        if (config.mStartAtUs != mConfig.mStartAtUs
                || (config.mStopped != mConfig.mStopped && !config.mStopped)) {
            status_t res = GetStatus(mSource->setStartTimeUs(config.mStartAtUs));
            status << " start at " << config.mStartAtUs << "us";
            if (res != OK) {
                status << " (=> " << asString(res) << ")";
                err = res;
            }
            mConfig.mStartAtUs = config.mStartAtUs;
            mConfig.mStopped = config.mStopped;
        }

        // suspend-resume
        if (config.mSuspended != mConfig.mSuspended) {
            status_t res = GetStatus(mSource->setSuspend(config.mSuspended, config.mSuspendAtUs));
            status << " " << (config.mSuspended ? "suspend" : "resume")
                    << " at " << config.mSuspendAtUs << "us";
            if (res != OK) {
                status << " (=> " << asString(res) << ")";
                err = res;
            }
            mConfig.mSuspended = config.mSuspended;
            mConfig.mSuspendAtUs = config.mSuspendAtUs;
        }

        if (config.mStopped != mConfig.mStopped && config.mStopped) {
            status_t res = GetStatus(mSource->setStopTimeUs(config.mStopAtUs));
            status << " stop at " << config.mStopAtUs << "us";
            if (res != OK) {
                status << " (=> " << asString(res) << ")";
                err = res;
            } else {
                status << " delayUs";
                hardware::Return<void> trans = mSource->getStopTimeOffsetUs(
                        [&res, &delayUs = config.mInputDelayUs](
                                auto status, auto stopTimeOffsetUs) {
                            res = static_cast<status_t>(status);
                            delayUs = stopTimeOffsetUs;
                        });
                if (!trans.isOk()) {
                    res = trans.isDeadObject() ? DEAD_OBJECT : UNKNOWN_ERROR;
                }
                if (res != OK) {
                    status << " (=> " << asString(res) << ")";
                } else {
                    status << "=" << config.mInputDelayUs << "us";
                }
                mConfig.mInputDelayUs = config.mInputDelayUs;
            }
            mConfig.mStopAtUs = config.mStopAtUs;
            mConfig.mStopped = config.mStopped;
        }

        // color aspects (android._color-aspects)

        // consumer usage is queried earlier.

        if (status.str().empty()) {
            ALOGD("ISConfig not changed");
        } else {
            ALOGD("ISConfig%s", status.str().c_str());
        }
        return err;
    }

    void onInputBufferDone(c2_cntr64_t index) override {
        mNode->onInputBufferDone(index);
    }

private:
    sp<HGraphicBufferSource> mSource;
    sp<C2OMXNode> mNode;
    sp<hardware::media::omx::V1_0::IOmxNode> mOmxNode;
    uint32_t mWidth;
    uint32_t mHeight;
    Config mConfig;
};

class Codec2ClientInterfaceWrapper : public C2ComponentStore {
    std::shared_ptr<Codec2Client> mClient;

public:
    Codec2ClientInterfaceWrapper(std::shared_ptr<Codec2Client> client)
        : mClient(client) { }

    virtual ~Codec2ClientInterfaceWrapper() = default;

    virtual c2_status_t config_sm(
            const std::vector<C2Param *> &params,
            std::vector<std::unique_ptr<C2SettingResult>> *const failures) {
        return mClient->config(params, C2_MAY_BLOCK, failures);
    };

    virtual c2_status_t copyBuffer(
            std::shared_ptr<C2GraphicBuffer>,
            std::shared_ptr<C2GraphicBuffer>) {
        return C2_OMITTED;
    }

    virtual c2_status_t createComponent(
            C2String, std::shared_ptr<C2Component> *const component) {
        component->reset();
        return C2_OMITTED;
    }

    virtual c2_status_t createInterface(
            C2String, std::shared_ptr<C2ComponentInterface> *const interface) {
        interface->reset();
        return C2_OMITTED;
    }

    virtual c2_status_t query_sm(
            const std::vector<C2Param *> &stackParams,
            const std::vector<C2Param::Index> &heapParamIndices,
            std::vector<std::unique_ptr<C2Param>> *const heapParams) const {
        return mClient->query(stackParams, heapParamIndices, C2_MAY_BLOCK, heapParams);
    }

    virtual c2_status_t querySupportedParams_nb(
            std::vector<std::shared_ptr<C2ParamDescriptor>> *const params) const {
        return mClient->querySupportedParams(params);
    }

    virtual c2_status_t querySupportedValues_sm(
            std::vector<C2FieldSupportedValuesQuery> &fields) const {
        return mClient->querySupportedValues(fields, C2_MAY_BLOCK);
    }

    virtual C2String getName() const {
        return mClient->getName();
    }

    virtual std::shared_ptr<C2ParamReflector> getParamReflector() const {
        return mClient->getParamReflector();
    }

    virtual std::vector<std::shared_ptr<const C2Component::Traits>> listComponents() {
        return std::vector<std::shared_ptr<const C2Component::Traits>>();
    }
};

}  // namespace

// CCodec::ClientListener

struct CCodec::ClientListener : public Codec2Client::Listener {

    explicit ClientListener(const wp<CCodec> &codec) : mCodec(codec) {}

    virtual void onWorkDone(
            const std::weak_ptr<Codec2Client::Component>& component,
            std::list<std::unique_ptr<C2Work>>& workItems) override {
        (void)component;
        sp<CCodec> codec(mCodec.promote());
        if (!codec) {
            return;
        }
        codec->onWorkDone(workItems);
    }

    virtual void onTripped(
            const std::weak_ptr<Codec2Client::Component>& component,
            const std::vector<std::shared_ptr<C2SettingResult>>& settingResult
            ) override {
        // TODO
        (void)component;
        (void)settingResult;
    }

    virtual void onError(
            const std::weak_ptr<Codec2Client::Component>& component,
            uint32_t errorCode) override {
        // TODO
        (void)component;
        (void)errorCode;
    }

    virtual void onDeath(
            const std::weak_ptr<Codec2Client::Component>& component) override {
        { // Log the death of the component.
            std::shared_ptr<Codec2Client::Component> comp = component.lock();
            if (!comp) {
                ALOGE("Codec2 component died.");
            } else {
                ALOGE("Codec2 component \"%s\" died.", comp->getName().c_str());
            }
        }

        // Report to MediaCodec.
        sp<CCodec> codec(mCodec.promote());
        if (!codec || !codec->mCallback) {
            return;
        }
        codec->mCallback->onError(DEAD_OBJECT, ACTION_CODE_FATAL);
    }

    virtual void onFrameRendered(uint64_t bufferQueueId,
                                 int32_t slotId,
                                 int64_t timestampNs) override {
        // TODO: implement
        (void)bufferQueueId;
        (void)slotId;
        (void)timestampNs;
    }

    virtual void onInputBufferDone(
            uint64_t frameIndex, size_t arrayIndex) override {
        sp<CCodec> codec(mCodec.promote());
        if (codec) {
            codec->onInputBufferDone(frameIndex, arrayIndex);
        }
    }

private:
    wp<CCodec> mCodec;
};

// CCodecCallbackImpl

class CCodecCallbackImpl : public CCodecCallback {
public:
    explicit CCodecCallbackImpl(CCodec *codec) : mCodec(codec) {}
    ~CCodecCallbackImpl() override = default;

    void onError(status_t err, enum ActionCode actionCode) override {
        mCodec->mCallback->onError(err, actionCode);
    }

    void onOutputFramesRendered(int64_t mediaTimeUs, nsecs_t renderTimeNs) override {
        mCodec->mCallback->onOutputFramesRendered(
                {RenderedFrameInfo(mediaTimeUs, renderTimeNs)});
    }

    void onOutputBuffersChanged() override {
        mCodec->mCallback->onOutputBuffersChanged();
    }

private:
    CCodec *mCodec;
};

// CCodec

CCodec::CCodec()
    : mChannel(new CCodecBufferChannel(std::make_shared<CCodecCallbackImpl>(this))),
      mConfig(new CCodecConfig) {
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

    sp<RefBase> codecInfo;
    CHECK(msg->findObject("codecInfo", &codecInfo));
    // For Codec 2.0 components, componentName == codecInfo->getCodecName().

    sp<AMessage> allocMsg(new AMessage(kWhatAllocate, this));
    allocMsg->setObject("codecInfo", codecInfo);
    allocMsg->post();
}

void CCodec::allocate(const sp<MediaCodecInfo> &codecInfo) {
    if (codecInfo == nullptr) {
        mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
        return;
    }
    ALOGD("allocate(%s)", codecInfo->getCodecName());
    mClientListener.reset(new ClientListener(this));

    AString componentName = codecInfo->getCodecName();
    std::shared_ptr<Codec2Client> client;

    // set up preferred component store to access vendor store parameters
    client = Codec2Client::CreateFromService("default");
    if (client) {
        ALOGI("setting up '%s' as default (vendor) store", client->getServiceName().c_str());
        SetPreferredCodec2ComponentStore(
                std::make_shared<Codec2ClientInterfaceWrapper>(client));
    }

    std::shared_ptr<Codec2Client::Component> comp =
            Codec2Client::CreateComponentByName(
            componentName.c_str(),
            mClientListener,
            &client);
    if (!comp) {
        ALOGE("Failed Create component: %s", componentName.c_str());
        Mutexed<State>::Locked state(mState);
        state->set(RELEASED);
        state.unlock();
        mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
        state.lock();
        return;
    }
    ALOGI("Created component [%s]", componentName.c_str());
    mChannel->setComponent(comp);
    auto setAllocated = [this, comp, client] {
        Mutexed<State>::Locked state(mState);
        if (state->get() != ALLOCATING) {
            state->set(RELEASED);
            return UNKNOWN_ERROR;
        }
        state->set(ALLOCATED);
        state->comp = comp;
        mClient = client;
        return OK;
    };
    if (tryAndReportOnError(setAllocated) != OK) {
        return;
    }

    // initialize config here in case setParameters is called prior to configure
    Mutexed<std::unique_ptr<Config>>::Locked configLocked(mConfig);
    const std::unique_ptr<Config> &config = *configLocked;
    status_t err = config->initialize(mClient->getParamReflector(), comp);
    if (err != OK) {
        ALOGW("Failed to initialize configuration support");
        // TODO: report error once we complete implementation.
    }
    config->queryConfiguration(comp);

    mCallback->onComponentAllocated(componentName.c_str());
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
    std::shared_ptr<Codec2Client::Component> comp;
    auto checkAllocated = [this, &comp] {
        Mutexed<State>::Locked state(mState);
        if (state->get() != ALLOCATED) {
            state->set(RELEASED);
            return UNKNOWN_ERROR;
        }
        comp = state->comp;
        return OK;
    };
    if (tryAndReportOnError(checkAllocated) != OK) {
        return;
    }

    auto doConfig = [msg, comp, this]() -> status_t {
        AString mime;
        if (!msg->findString("mime", &mime)) {
            return BAD_VALUE;
        }

        int32_t encoder;
        if (!msg->findInt32("encoder", &encoder)) {
            encoder = false;
        }

        int32_t flags;
        if (!msg->findInt32("flags", &flags)) {
            return BAD_VALUE;
        }

        // TODO: read from intf()
        if ((!encoder) != (comp->getName().find("encoder") == std::string::npos)) {
            return UNKNOWN_ERROR;
        }

        int32_t storeMeta;
        if (encoder
                && msg->findInt32("android._input-metadata-buffer-type", &storeMeta)
                && storeMeta != kMetadataBufferTypeInvalid) {
            if (storeMeta != kMetadataBufferTypeANWBuffer) {
                ALOGD("Only ANW buffers are supported for legacy metadata mode");
                return BAD_VALUE;
            }
            mChannel->setMetaMode(CCodecBufferChannel::MODE_ANW);
        }

        sp<RefBase> obj;
        sp<Surface> surface;
        if (msg->findObject("native-window", &obj)) {
            surface = static_cast<Surface *>(obj.get());
            setSurface(surface);
        }

        Mutexed<std::unique_ptr<Config>>::Locked configLocked(mConfig);
        const std::unique_ptr<Config> &config = *configLocked;
        config->mUsingSurface = surface != nullptr;
        config->mBuffersBoundToCodec = ((flags & CONFIGURE_FLAG_USE_BLOCK_MODEL) == 0);
        ALOGD("[%s] buffers are %sbound to CCodec for this session",
              comp->getName().c_str(), config->mBuffersBoundToCodec ? "" : "not ");

        // Enforce required parameters
        int32_t i32;
        float flt;
        if (config->mDomain & Config::IS_AUDIO) {
            if (!msg->findInt32(KEY_SAMPLE_RATE, &i32)) {
                ALOGD("sample rate is missing, which is required for audio components.");
                return BAD_VALUE;
            }
            if (!msg->findInt32(KEY_CHANNEL_COUNT, &i32)) {
                ALOGD("channel count is missing, which is required for audio components.");
                return BAD_VALUE;
            }
            if ((config->mDomain & Config::IS_ENCODER)
                    && !mime.equalsIgnoreCase(MEDIA_MIMETYPE_AUDIO_FLAC)
                    && !msg->findInt32(KEY_BIT_RATE, &i32)
                    && !msg->findFloat(KEY_BIT_RATE, &flt)) {
                ALOGD("bitrate is missing, which is required for audio encoders.");
                return BAD_VALUE;
            }
        }
        if (config->mDomain & (Config::IS_IMAGE | Config::IS_VIDEO)) {
            if (!msg->findInt32(KEY_WIDTH, &i32)) {
                ALOGD("width is missing, which is required for image/video components.");
                return BAD_VALUE;
            }
            if (!msg->findInt32(KEY_HEIGHT, &i32)) {
                ALOGD("height is missing, which is required for image/video components.");
                return BAD_VALUE;
            }
            if ((config->mDomain & Config::IS_ENCODER) && (config->mDomain & Config::IS_VIDEO)) {
                int32_t mode = BITRATE_MODE_VBR;
                if (msg->findInt32(KEY_BITRATE_MODE, &mode) && mode == BITRATE_MODE_CQ) {
                    if (!msg->findInt32(KEY_QUALITY, &i32)) {
                        ALOGD("quality is missing, which is required for video encoders in CQ.");
                        return BAD_VALUE;
                    }
                } else {
                    if (!msg->findInt32(KEY_BIT_RATE, &i32)
                            && !msg->findFloat(KEY_BIT_RATE, &flt)) {
                        ALOGD("bitrate is missing, which is required for video encoders.");
                        return BAD_VALUE;
                    }
                }
                if (!msg->findInt32(KEY_I_FRAME_INTERVAL, &i32)
                        && !msg->findFloat(KEY_I_FRAME_INTERVAL, &flt)) {
                    ALOGD("I frame interval is missing, which is required for video encoders.");
                    return BAD_VALUE;
                }
                if (!msg->findInt32(KEY_FRAME_RATE, &i32)
                        && !msg->findFloat(KEY_FRAME_RATE, &flt)) {
                    ALOGD("frame rate is missing, which is required for video encoders.");
                    return BAD_VALUE;
                }
            }
        }

        /*
         * Handle input surface configuration
         */
        if ((config->mDomain & (Config::IS_VIDEO | Config::IS_IMAGE))
                && (config->mDomain & Config::IS_ENCODER)) {
            config->mISConfig.reset(new InputSurfaceWrapper::Config{});
            {
                config->mISConfig->mMinFps = 0;
                int64_t value;
                if (msg->findInt64(KEY_REPEAT_PREVIOUS_FRAME_AFTER, &value) && value > 0) {
                    config->mISConfig->mMinFps = 1e6 / value;
                }
                if (!msg->findFloat(
                        KEY_MAX_FPS_TO_ENCODER, &config->mISConfig->mMaxFps)) {
                    config->mISConfig->mMaxFps = -1;
                }
                config->mISConfig->mMinAdjustedFps = 0;
                config->mISConfig->mFixedAdjustedFps = 0;
                if (msg->findInt64(KEY_MAX_PTS_GAP_TO_ENCODER, &value)) {
                    if (value < 0 && value >= INT32_MIN) {
                        config->mISConfig->mFixedAdjustedFps = -1e6 / value;
                        config->mISConfig->mMaxFps = -1;
                    } else if (value > 0 && value <= INT32_MAX) {
                        config->mISConfig->mMinAdjustedFps = 1e6 / value;
                    }
                }
            }

            {
                bool captureFpsFound = false;
                double timeLapseFps;
                float captureRate;
                if (msg->findDouble("time-lapse-fps", &timeLapseFps)) {
                    config->mISConfig->mCaptureFps = timeLapseFps;
                    captureFpsFound = true;
                } else if (msg->findAsFloat(KEY_CAPTURE_RATE, &captureRate)) {
                    config->mISConfig->mCaptureFps = captureRate;
                    captureFpsFound = true;
                }
                if (captureFpsFound) {
                    (void)msg->findAsFloat(KEY_FRAME_RATE, &config->mISConfig->mCodedFps);
                }
            }

            {
                config->mISConfig->mSuspended = false;
                config->mISConfig->mSuspendAtUs = -1;
                int32_t value;
                if (msg->findInt32(KEY_CREATE_INPUT_SURFACE_SUSPENDED, &value) && value) {
                    config->mISConfig->mSuspended = true;
                }
            }
            config->mISConfig->mUsage = 0;
        }

        /*
         * Handle desired color format.
         */
        if ((config->mDomain & (Config::IS_VIDEO | Config::IS_IMAGE))) {
            int32_t format = -1;
            if (!msg->findInt32(KEY_COLOR_FORMAT, &format)) {
                /*
                 * Also handle default color format (encoders require color format, so this is only
                 * needed for decoders.
                 */
                if (!(config->mDomain & Config::IS_ENCODER)) {
                    format = (surface == nullptr) ? COLOR_FormatYUV420Planar : COLOR_FormatSurface;
                }
            }

            if (format >= 0) {
                msg->setInt32("android._color-format", format);
            }
        }

        int32_t subscribeToAllVendorParams;
        if (msg->findInt32("x-*", &subscribeToAllVendorParams) && subscribeToAllVendorParams) {
            if (config->subscribeToAllVendorParams(comp, C2_MAY_BLOCK) != OK) {
                ALOGD("[%s] Failed to subscribe to all vendor params", comp->getName().c_str());
            }
        }

        std::vector<std::unique_ptr<C2Param>> configUpdate;
        // NOTE: We used to ignore "video-bitrate" at configure; replicate
        //       the behavior here.
        sp<AMessage> sdkParams = msg;
        int32_t videoBitrate;
        if (sdkParams->findInt32(PARAMETER_KEY_VIDEO_BITRATE, &videoBitrate)) {
            sdkParams = msg->dup();
            sdkParams->removeEntryAt(sdkParams->findEntryByName(PARAMETER_KEY_VIDEO_BITRATE));
        }
        status_t err = config->getConfigUpdateFromSdkParams(
                comp, sdkParams, Config::IS_CONFIG, C2_DONT_BLOCK, &configUpdate);
        if (err != OK) {
            ALOGW("failed to convert configuration to c2 params");
        }

        int32_t maxBframes = 0;
        if ((config->mDomain & Config::IS_ENCODER)
                && (config->mDomain & Config::IS_VIDEO)
                && sdkParams->findInt32(KEY_MAX_B_FRAMES, &maxBframes)
                && maxBframes > 0) {
            std::unique_ptr<C2StreamGopTuning::output> gop =
                C2StreamGopTuning::output::AllocUnique(2 /* flexCount */, 0u /* stream */);
            gop->m.values[0] = { P_FRAME, UINT32_MAX };
            gop->m.values[1] = {
                C2Config::picture_type_t(P_FRAME | B_FRAME),
                uint32_t(maxBframes)
            };
            configUpdate.push_back(std::move(gop));
        }

        err = config->setParameters(comp, configUpdate, C2_DONT_BLOCK);
        if (err != OK) {
            ALOGW("failed to configure c2 params");
            return err;
        }

        std::vector<std::unique_ptr<C2Param>> params;
        C2StreamUsageTuning::input usage(0u, 0u);
        C2StreamMaxBufferSizeInfo::input maxInputSize(0u, 0u);
        C2PrependHeaderModeSetting prepend(PREPEND_HEADER_TO_NONE);

        std::initializer_list<C2Param::Index> indices {
        };
        c2_status_t c2err = comp->query(
                { &usage, &maxInputSize, &prepend },
                indices,
                C2_DONT_BLOCK,
                &params);
        if (c2err != C2_OK && c2err != C2_BAD_INDEX) {
            ALOGE("Failed to query component interface: %d", c2err);
            return UNKNOWN_ERROR;
        }
        if (params.size() != indices.size()) {
            ALOGE("Component returns wrong number of params: expected %zu actual %zu",
                    indices.size(), params.size());
            return UNKNOWN_ERROR;
        }
        if (usage) {
            if (usage.value & C2MemoryUsage::CPU_READ) {
                config->mInputFormat->setInt32("using-sw-read-often", true);
            }
            if (config->mISConfig) {
                C2AndroidMemoryUsage androidUsage(C2MemoryUsage(usage.value));
                config->mISConfig->mUsage = androidUsage.asGrallocUsage();
            }
        }

        // NOTE: we don't blindly use client specified input size if specified as clients
        // at times specify too small size. Instead, mimic the behavior from OMX, where the
        // client specified size is only used to ask for bigger buffers than component suggested
        // size.
        int32_t clientInputSize = 0;
        bool clientSpecifiedInputSize =
            msg->findInt32(KEY_MAX_INPUT_SIZE, &clientInputSize) && clientInputSize > 0;
        // TEMP: enforce minimum buffer size of 1MB for video decoders
        // and 16K / 4K for audio encoders/decoders
        if (maxInputSize.value == 0) {
            if (config->mDomain & Config::IS_AUDIO) {
                maxInputSize.value = encoder ? 16384 : 4096;
            } else if (!encoder) {
                maxInputSize.value = 1048576u;
            }
        }

        // verify that CSD fits into this size (if defined)
        if ((config->mDomain & Config::IS_DECODER) && maxInputSize.value > 0) {
            sp<ABuffer> csd;
            for (size_t ix = 0; msg->findBuffer(StringPrintf("csd-%zu", ix).c_str(), &csd); ++ix) {
                if (csd && csd->size() > maxInputSize.value) {
                    maxInputSize.value = csd->size();
                }
            }
        }

        // TODO: do this based on component requiring linear allocator for input
        if ((config->mDomain & Config::IS_DECODER) || (config->mDomain & Config::IS_AUDIO)) {
            if (clientSpecifiedInputSize) {
                // Warn that we're overriding client's max input size if necessary.
                if ((uint32_t)clientInputSize < maxInputSize.value) {
                    ALOGD("client requested max input size %d, which is smaller than "
                          "what component recommended (%u); overriding with component "
                          "recommendation.", clientInputSize, maxInputSize.value);
                    ALOGW("This behavior is subject to change. It is recommended that "
                          "app developers double check whether the requested "
                          "max input size is in reasonable range.");
                } else {
                    maxInputSize.value = clientInputSize;
                }
            }
            // Pass max input size on input format to the buffer channel (if supplied by the
            // component or by a default)
            if (maxInputSize.value) {
                config->mInputFormat->setInt32(
                        KEY_MAX_INPUT_SIZE,
                        (int32_t)(c2_min(maxInputSize.value, uint32_t(INT32_MAX))));
            }
        }

        int32_t clientPrepend;
        if ((config->mDomain & Config::IS_VIDEO)
                && (config->mDomain & Config::IS_ENCODER)
                && msg->findInt32(KEY_PREPEND_HEADERS_TO_SYNC_FRAMES, &clientPrepend)
                && clientPrepend
                && (!prepend || prepend.value != PREPEND_HEADER_TO_ALL_SYNC)) {
            ALOGE("Failed to set KEY_PREPEND_HEADERS_TO_SYNC_FRAMES");
            return BAD_VALUE;
        }

        if ((config->mDomain & (Config::IS_VIDEO | Config::IS_IMAGE))) {
            // propagate HDR static info to output format for both encoders and decoders
            // if component supports this info, we will update from component, but only the raw port,
            // so don't propagate if component already filled it in.
            sp<ABuffer> hdrInfo;
            if (msg->findBuffer(KEY_HDR_STATIC_INFO, &hdrInfo)
                    && !config->mOutputFormat->findBuffer(KEY_HDR_STATIC_INFO, &hdrInfo)) {
                config->mOutputFormat->setBuffer(KEY_HDR_STATIC_INFO, hdrInfo);
            }

            // Set desired color format from configuration parameter
            int32_t format;
            if (msg->findInt32("android._color-format", &format)) {
                if (config->mDomain & Config::IS_ENCODER) {
                    config->mInputFormat->setInt32(KEY_COLOR_FORMAT, format);
                } else {
                    config->mOutputFormat->setInt32(KEY_COLOR_FORMAT, format);
                }
            }
        }

        // propagate encoder delay and padding to output format
        if ((config->mDomain & Config::IS_DECODER) && (config->mDomain & Config::IS_AUDIO)) {
            int delay = 0;
            if (msg->findInt32("encoder-delay", &delay)) {
                config->mOutputFormat->setInt32("encoder-delay", delay);
            }
            int padding = 0;
            if (msg->findInt32("encoder-padding", &padding)) {
                config->mOutputFormat->setInt32("encoder-padding", padding);
            }
        }

        // set channel-mask
        if (config->mDomain & Config::IS_AUDIO) {
            int32_t mask;
            if (msg->findInt32(KEY_CHANNEL_MASK, &mask)) {
                if (config->mDomain & Config::IS_ENCODER) {
                    config->mInputFormat->setInt32(KEY_CHANNEL_MASK, mask);
                } else {
                    config->mOutputFormat->setInt32(KEY_CHANNEL_MASK, mask);
                }
            }
        }

        ALOGD("setup formats input: %s and output: %s",
                config->mInputFormat->debugString().c_str(),
                config->mOutputFormat->debugString().c_str());
        return OK;
    };
    if (tryAndReportOnError(doConfig) != OK) {
        return;
    }

    Mutexed<std::unique_ptr<Config>>::Locked configLocked(mConfig);
    const std::unique_ptr<Config> &config = *configLocked;

    mCallback->onComponentConfigured(config->mInputFormat, config->mOutputFormat);
}

void CCodec::initiateCreateInputSurface() {
    status_t err = [this] {
        Mutexed<State>::Locked state(mState);
        if (state->get() != ALLOCATED) {
            return UNKNOWN_ERROR;
        }
        // TODO: read it from intf() properly.
        if (state->comp->getName().find("encoder") == std::string::npos) {
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

sp<PersistentSurface> CCodec::CreateOmxInputSurface() {
    using namespace android::hardware::media::omx::V1_0;
    using namespace android::hardware::media::omx::V1_0::utils;
    using namespace android::hardware::graphics::bufferqueue::V1_0::utils;
    typedef android::hardware::media::omx::V1_0::Status OmxStatus;
    android::sp<IOmx> omx = IOmx::getService();
    typedef android::hardware::graphics::bufferqueue::V1_0::
            IGraphicBufferProducer HGraphicBufferProducer;
    typedef android::hardware::media::omx::V1_0::
            IGraphicBufferSource HGraphicBufferSource;
    OmxStatus s;
    android::sp<HGraphicBufferProducer> gbp;
    android::sp<HGraphicBufferSource> gbs;

    using ::android::hardware::Return;
    Return<void> transStatus = omx->createInputSurface(
            [&s, &gbp, &gbs](
                    OmxStatus status,
                    const android::sp<HGraphicBufferProducer>& producer,
                    const android::sp<HGraphicBufferSource>& source) {
                s = status;
                gbp = producer;
                gbs = source;
            });
    if (transStatus.isOk() && s == OmxStatus::OK) {
        return new PersistentSurface(new H2BGraphicBufferProducer(gbp), gbs);
    }

    return nullptr;
}

sp<PersistentSurface> CCodec::CreateCompatibleInputSurface() {
    sp<PersistentSurface> surface(CreateInputSurface());

    if (surface == nullptr) {
        surface = CreateOmxInputSurface();
    }

    return surface;
}

void CCodec::createInputSurface() {
    status_t err;
    sp<IGraphicBufferProducer> bufferProducer;

    sp<AMessage> inputFormat;
    sp<AMessage> outputFormat;
    uint64_t usage = 0;
    {
        Mutexed<std::unique_ptr<Config>>::Locked configLocked(mConfig);
        const std::unique_ptr<Config> &config = *configLocked;
        inputFormat = config->mInputFormat;
        outputFormat = config->mOutputFormat;
        usage = config->mISConfig ? config->mISConfig->mUsage : 0;
    }

    sp<PersistentSurface> persistentSurface = CreateCompatibleInputSurface();
    sp<hidl::base::V1_0::IBase> hidlTarget = persistentSurface->getHidlTarget();
    sp<IInputSurface> hidlInputSurface = IInputSurface::castFrom(hidlTarget);
    sp<HGraphicBufferSource> gbs = HGraphicBufferSource::castFrom(hidlTarget);

    if (hidlInputSurface) {
        std::shared_ptr<Codec2Client::InputSurface> inputSurface =
                std::make_shared<Codec2Client::InputSurface>(hidlInputSurface);
        err = setupInputSurface(std::make_shared<C2InputSurfaceWrapper>(
                inputSurface));
        bufferProducer = inputSurface->getGraphicBufferProducer();
    } else if (gbs) {
        int32_t width = 0;
        (void)outputFormat->findInt32("width", &width);
        int32_t height = 0;
        (void)outputFormat->findInt32("height", &height);
        err = setupInputSurface(std::make_shared<GraphicBufferSourceWrapper>(
                gbs, width, height, usage));
        bufferProducer = persistentSurface->getBufferProducer();
    } else {
        ALOGE("Corrupted input surface");
        mCallback->onInputSurfaceCreationFailed(UNKNOWN_ERROR);
        return;
    }

    if (err != OK) {
        ALOGE("Failed to set up input surface: %d", err);
        mCallback->onInputSurfaceCreationFailed(err);
        return;
    }

    mCallback->onInputSurfaceCreated(
            inputFormat,
            outputFormat,
            new BufferProducerWrapper(bufferProducer));
}

status_t CCodec::setupInputSurface(const std::shared_ptr<InputSurfaceWrapper> &surface) {
    Mutexed<std::unique_ptr<Config>>::Locked configLocked(mConfig);
    const std::unique_ptr<Config> &config = *configLocked;
    config->mUsingSurface = true;

    // we are now using surface - apply default color aspects to input format - as well as
    // get dataspace
    bool inputFormatChanged = config->updateFormats(Config::IS_INPUT);
    ALOGD("input format %s to %s",
            inputFormatChanged ? "changed" : "unchanged",
            config->mInputFormat->debugString().c_str());

    // configure dataspace
    static_assert(sizeof(int32_t) == sizeof(android_dataspace), "dataspace size mismatch");
    android_dataspace dataSpace = HAL_DATASPACE_UNKNOWN;
    (void)config->mInputFormat->findInt32("android._dataspace", (int32_t*)&dataSpace);
    surface->setDataSpace(dataSpace);

    status_t err = mChannel->setInputSurface(surface);
    if (err != OK) {
        // undo input format update
        config->mUsingSurface = false;
        (void)config->updateFormats(Config::IS_INPUT);
        return err;
    }
    config->mInputSurface = surface;

    if (config->mISConfig) {
        surface->configure(*config->mISConfig);
    } else {
        ALOGD("ISConfig: no configuration");
    }

    return OK;
}

void CCodec::initiateSetInputSurface(const sp<PersistentSurface> &surface) {
    sp<AMessage> msg = new AMessage(kWhatSetInputSurface, this);
    msg->setObject("surface", surface);
    msg->post();
}

void CCodec::setInputSurface(const sp<PersistentSurface> &surface) {
    sp<AMessage> inputFormat;
    sp<AMessage> outputFormat;
    uint64_t usage = 0;
    {
        Mutexed<std::unique_ptr<Config>>::Locked configLocked(mConfig);
        const std::unique_ptr<Config> &config = *configLocked;
        inputFormat = config->mInputFormat;
        outputFormat = config->mOutputFormat;
        usage = config->mISConfig ? config->mISConfig->mUsage : 0;
    }
    sp<hidl::base::V1_0::IBase> hidlTarget = surface->getHidlTarget();
    sp<IInputSurface> inputSurface = IInputSurface::castFrom(hidlTarget);
    sp<HGraphicBufferSource> gbs = HGraphicBufferSource::castFrom(hidlTarget);
    if (inputSurface) {
        status_t err = setupInputSurface(std::make_shared<C2InputSurfaceWrapper>(
                std::make_shared<Codec2Client::InputSurface>(inputSurface)));
        if (err != OK) {
            ALOGE("Failed to set up input surface: %d", err);
            mCallback->onInputSurfaceDeclined(err);
            return;
        }
    } else if (gbs) {
        int32_t width = 0;
        (void)outputFormat->findInt32("width", &width);
        int32_t height = 0;
        (void)outputFormat->findInt32("height", &height);
        status_t err = setupInputSurface(std::make_shared<GraphicBufferSourceWrapper>(
                gbs, width, height, usage));
        if (err != OK) {
            ALOGE("Failed to set up input surface: %d", err);
            mCallback->onInputSurfaceDeclined(err);
            return;
        }
    } else {
        ALOGE("Failed to set input surface: Corrupted surface.");
        mCallback->onInputSurfaceDeclined(UNKNOWN_ERROR);
        return;
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
    std::shared_ptr<Codec2Client::Component> comp;
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
        mCallback->onError(toStatusT(err, C2_OPERATION_Component_start),
                           ACTION_CODE_FATAL);
        return;
    }
    sp<AMessage> inputFormat;
    sp<AMessage> outputFormat;
    status_t err2 = OK;
    bool buffersBoundToCodec = false;
    {
        Mutexed<std::unique_ptr<Config>>::Locked configLocked(mConfig);
        const std::unique_ptr<Config> &config = *configLocked;
        inputFormat = config->mInputFormat;
        // start triggers format dup
        outputFormat = config->mOutputFormat = config->mOutputFormat->dup();
        if (config->mInputSurface) {
            err2 = config->mInputSurface->start();
        }
        buffersBoundToCodec = config->mBuffersBoundToCodec;
    }
    if (err2 != OK) {
        mCallback->onError(err2, ACTION_CODE_FATAL);
        return;
    }
    err2 = mChannel->start(inputFormat, outputFormat, buffersBoundToCodec);
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

    (void)mChannel->requestInitialInputBuffers();
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

    mChannel->reset();
    (new AMessage(kWhatStop, this))->post();
}

void CCodec::stop() {
    std::shared_ptr<Codec2Client::Component> comp;
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
    status_t err = comp->stop();
    if (err != C2_OK) {
        // TODO: convert err into status_t
        mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
    }

    {
        Mutexed<std::unique_ptr<Config>>::Locked configLocked(mConfig);
        const std::unique_ptr<Config> &config = *configLocked;
        if (config->mInputSurface) {
            config->mInputSurface->disconnect();
            config->mInputSurface = nullptr;
        }
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
    bool clearInputSurfaceIfNeeded = false;
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
        if (state->get() == STARTING
                || state->get() == RUNNING
                || state->get() == STOPPING) {
            // Input surface may have been started, so clean up is needed.
            clearInputSurfaceIfNeeded = true;
        }
        state->set(RELEASING);
    }

    if (clearInputSurfaceIfNeeded) {
        Mutexed<std::unique_ptr<Config>>::Locked configLocked(mConfig);
        const std::unique_ptr<Config> &config = *configLocked;
        if (config->mInputSurface) {
            config->mInputSurface->disconnect();
            config->mInputSurface = nullptr;
        }
    }

    mChannel->reset();
    // thiz holds strong ref to this while the thread is running.
    sp<CCodec> thiz(this);
    std::thread([thiz, sendCallback] { thiz->release(sendCallback); }).detach();
}

void CCodec::release(bool sendCallback) {
    std::shared_ptr<Codec2Client::Component> comp;
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
    comp->release();

    {
        Mutexed<State>::Locked state(mState);
        state->set(RELEASED);
        state->comp.reset();
    }
    (new AMessage(kWhatRelease, this))->post();
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

    mChannel->stop();
    (new AMessage(kWhatFlush, this))->post();
}

void CCodec::flush() {
    std::shared_ptr<Codec2Client::Component> comp;
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

    std::list<std::unique_ptr<C2Work>> flushedWork;
    c2_status_t err = comp->flush(C2Component::FLUSH_COMPONENT, &flushedWork);
    {
        Mutexed<std::list<std::unique_ptr<C2Work>>>::Locked queue(mWorkDoneQueue);
        flushedWork.splice(flushedWork.end(), *queue);
    }
    if (err != C2_OK) {
        // TODO: convert err into status_t
        mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
    }

    mChannel->flush(flushedWork);

    {
        Mutexed<State>::Locked state(mState);
        if (state->get() == FLUSHING) {
            state->set(FLUSHED);
        }
    }
    mCallback->onFlushCompleted();
}

void CCodec::signalResume() {
    std::shared_ptr<Codec2Client::Component> comp;
    auto setResuming = [this, &comp] {
        Mutexed<State>::Locked state(mState);
        if (state->get() != FLUSHED) {
            return UNKNOWN_ERROR;
        }
        state->set(RESUMING);
        comp = state->comp;
        return OK;
    };
    if (tryAndReportOnError(setResuming) != OK) {
        return;
    }

    {
        Mutexed<std::unique_ptr<Config>>::Locked configLocked(mConfig);
        const std::unique_ptr<Config> &config = *configLocked;
        config->queryConfiguration(comp);
    }

    (void)mChannel->start(nullptr, nullptr, [&]{
        Mutexed<std::unique_ptr<Config>>::Locked configLocked(mConfig);
        const std::unique_ptr<Config> &config = *configLocked;
        return config->mBuffersBoundToCodec;
    }());

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

    (void)mChannel->requestInitialInputBuffers();
}

void CCodec::signalSetParameters(const sp<AMessage> &msg) {
    std::shared_ptr<Codec2Client::Component> comp;
    auto checkState = [this, &comp] {
        Mutexed<State>::Locked state(mState);
        if (state->get() == RELEASED) {
            return INVALID_OPERATION;
        }
        comp = state->comp;
        return OK;
    };
    if (tryAndReportOnError(checkState) != OK) {
        return;
    }

    // NOTE: We used to ignore "bitrate" at setParameters; replicate
    //       the behavior here.
    sp<AMessage> params = msg;
    int32_t bitrate;
    if (params->findInt32(KEY_BIT_RATE, &bitrate)) {
        params = msg->dup();
        params->removeEntryAt(params->findEntryByName(KEY_BIT_RATE));
    }

    Mutexed<std::unique_ptr<Config>>::Locked configLocked(mConfig);
    const std::unique_ptr<Config> &config = *configLocked;

    /**
     * Handle input surface parameters
     */
    if ((config->mDomain & (Config::IS_VIDEO | Config::IS_IMAGE))
            && (config->mDomain & Config::IS_ENCODER)
            && config->mInputSurface && config->mISConfig) {
        (void)params->findInt64(PARAMETER_KEY_OFFSET_TIME, &config->mISConfig->mTimeOffsetUs);

        if (params->findInt64("skip-frames-before", &config->mISConfig->mStartAtUs)) {
            config->mISConfig->mStopped = false;
        } else if (params->findInt64("stop-time-us", &config->mISConfig->mStopAtUs)) {
            config->mISConfig->mStopped = true;
        }

        int32_t value;
        if (params->findInt32(PARAMETER_KEY_SUSPEND, &value)) {
            config->mISConfig->mSuspended = value;
            config->mISConfig->mSuspendAtUs = -1;
            (void)params->findInt64(PARAMETER_KEY_SUSPEND_TIME, &config->mISConfig->mSuspendAtUs);
        }

        (void)config->mInputSurface->configure(*config->mISConfig);
        if (config->mISConfig->mStopped) {
            config->mInputFormat->setInt64(
                    "android._stop-time-offset-us", config->mISConfig->mInputDelayUs);
        }
    }

    std::vector<std::unique_ptr<C2Param>> configUpdate;
    (void)config->getConfigUpdateFromSdkParams(
            comp, params, Config::IS_PARAM, C2_MAY_BLOCK, &configUpdate);
    // Prefer to pass parameters to the buffer channel, so they can be synchronized with the frames.
    // Parameter synchronization is not defined when using input surface. For now, route
    // these directly to the component.
    if (config->mInputSurface == nullptr
            && (property_get_bool("debug.stagefright.ccodec_delayed_params", false)
                    || comp->getName().find("c2.android.") == 0)) {
        mChannel->setParameters(configUpdate);
    } else {
        (void)config->setParameters(comp, configUpdate, C2_MAY_BLOCK);
    }
}

void CCodec::signalEndOfInputStream() {
    mCallback->onSignaledInputEOS(mChannel->signalEndOfInputStream());
}

void CCodec::signalRequestIDRFrame() {
    std::shared_ptr<Codec2Client::Component> comp;
    {
        Mutexed<State>::Locked state(mState);
        if (state->get() == RELEASED) {
            ALOGD("no IDR request sent since component is released");
            return;
        }
        comp = state->comp;
    }
    ALOGV("request IDR");
    Mutexed<std::unique_ptr<Config>>::Locked configLocked(mConfig);
    const std::unique_ptr<Config> &config = *configLocked;
    std::vector<std::unique_ptr<C2Param>> params;
    params.push_back(
            std::make_unique<C2StreamRequestSyncFrameTuning::output>(0u, true));
    config->setParameters(comp, params, C2_MAY_BLOCK);
}

void CCodec::onWorkDone(std::list<std::unique_ptr<C2Work>> &workItems) {
    if (!workItems.empty()) {
        Mutexed<std::list<std::unique_ptr<C2Work>>>::Locked queue(mWorkDoneQueue);
        queue->splice(queue->end(), workItems);
    }
    (new AMessage(kWhatWorkDone, this))->post();
}

void CCodec::onInputBufferDone(uint64_t frameIndex, size_t arrayIndex) {
    mChannel->onInputBufferDone(frameIndex, arrayIndex);
    if (arrayIndex == 0) {
        // We always put no more than one buffer per work, if we use an input surface.
        Mutexed<std::unique_ptr<Config>>::Locked configLocked(mConfig);
        const std::unique_ptr<Config> &config = *configLocked;
        if (config->mInputSurface) {
            config->mInputSurface->onInputBufferDone(frameIndex);
        }
    }
}

void CCodec::onMessageReceived(const sp<AMessage> &msg) {
    TimePoint now = std::chrono::steady_clock::now();
    CCodecWatchdog::getInstance()->watch(this);
    switch (msg->what()) {
        case kWhatAllocate: {
            // C2ComponentStore::createComponent() should return within 100ms.
            setDeadline(now, 1500ms, "allocate");
            sp<RefBase> obj;
            CHECK(msg->findObject("codecInfo", &obj));
            allocate((MediaCodecInfo *)obj.get());
            break;
        }
        case kWhatConfigure: {
            // C2Component::commit_sm() should return within 5ms.
            setDeadline(now, 1500ms, "configure");
            sp<AMessage> format;
            CHECK(msg->findMessage("format", &format));
            configure(format);
            break;
        }
        case kWhatStart: {
            // C2Component::start() should return within 500ms.
            setDeadline(now, 1500ms, "start");
            start();
            break;
        }
        case kWhatStop: {
            // C2Component::stop() should return within 500ms.
            setDeadline(now, 1500ms, "stop");
            stop();
            break;
        }
        case kWhatFlush: {
            // C2Component::flush_sm() should return within 5ms.
            setDeadline(now, 1500ms, "flush");
            flush();
            break;
        }
        case kWhatRelease: {
            mChannel->release();
            mClient.reset();
            mClientListener.reset();
            break;
        }
        case kWhatCreateInputSurface: {
            // Surface operations may be briefly blocking.
            setDeadline(now, 1500ms, "createInputSurface");
            createInputSurface();
            break;
        }
        case kWhatSetInputSurface: {
            // Surface operations may be briefly blocking.
            setDeadline(now, 1500ms, "setInputSurface");
            sp<RefBase> obj;
            CHECK(msg->findObject("surface", &obj));
            sp<PersistentSurface> surface(static_cast<PersistentSurface *>(obj.get()));
            setInputSurface(surface);
            break;
        }
        case kWhatWorkDone: {
            std::unique_ptr<C2Work> work;
            bool shouldPost = false;
            {
                Mutexed<std::list<std::unique_ptr<C2Work>>>::Locked queue(mWorkDoneQueue);
                if (queue->empty()) {
                    break;
                }
                work.swap(queue->front());
                queue->pop_front();
                shouldPost = !queue->empty();
            }
            if (shouldPost) {
                (new AMessage(kWhatWorkDone, this))->post();
            }

            // handle configuration changes in work done
            Mutexed<std::unique_ptr<Config>>::Locked configLocked(mConfig);
            const std::unique_ptr<Config> &config = *configLocked;
            bool changed = false;
            Config::Watcher<C2StreamInitDataInfo::output> initData =
                config->watch<C2StreamInitDataInfo::output>();
            if (!work->worklets.empty()
                    && (work->worklets.front()->output.flags
                            & C2FrameData::FLAG_DISCARD_FRAME) == 0) {

                // copy buffer info to config
                std::vector<std::unique_ptr<C2Param>> updates;
                for (const std::unique_ptr<C2Param> &param
                        : work->worklets.front()->output.configUpdate) {
                    updates.push_back(C2Param::Copy(*param));
                }
                unsigned stream = 0;
                for (const std::shared_ptr<C2Buffer> &buf : work->worklets.front()->output.buffers) {
                    for (const std::shared_ptr<const C2Info> &info : buf->info()) {
                        // move all info into output-stream #0 domain
                        updates.emplace_back(C2Param::CopyAsStream(*info, true /* output */, stream));
                    }
                    for (const C2ConstGraphicBlock &block : buf->data().graphicBlocks()) {
                        // ALOGV("got output buffer with crop %u,%u+%u,%u and size %u,%u",
                        //      block.crop().left, block.crop().top,
                        //      block.crop().width, block.crop().height,
                        //      block.width(), block.height());
                        updates.emplace_back(new C2StreamCropRectInfo::output(stream, block.crop()));
                        updates.emplace_back(new C2StreamPictureSizeInfo::output(
                                stream, block.crop().width, block.crop().height));
                        break; // for now only do the first block
                    }
                    ++stream;
                }

                if (config->updateConfiguration(updates, config->mOutputDomain)) {
                    changed = true;
                }

                // copy standard infos to graphic buffers if not already present (otherwise, we
                // may overwrite the actual intermediate value with a final value)
                stream = 0;
                const static std::vector<C2Param::Index> stdGfxInfos = {
                    C2StreamRotationInfo::output::PARAM_TYPE,
                    C2StreamColorAspectsInfo::output::PARAM_TYPE,
                    C2StreamDataSpaceInfo::output::PARAM_TYPE,
                    C2StreamHdrStaticInfo::output::PARAM_TYPE,
                    C2StreamHdr10PlusInfo::output::PARAM_TYPE,
                    C2StreamPixelAspectRatioInfo::output::PARAM_TYPE,
                    C2StreamSurfaceScalingInfo::output::PARAM_TYPE
                };
                for (const std::shared_ptr<C2Buffer> &buf : work->worklets.front()->output.buffers) {
                    if (buf->data().graphicBlocks().size()) {
                        for (C2Param::Index ix : stdGfxInfos) {
                            if (!buf->hasInfo(ix)) {
                                const C2Param *param =
                                    config->getConfigParameterValue(ix.withStream(stream));
                                if (param) {
                                    std::shared_ptr<C2Param> info(C2Param::Copy(*param));
                                    buf->setInfo(std::static_pointer_cast<C2Info>(info));
                                }
                            }
                        }
                    }
                    ++stream;
                }
            }
            if (config->mInputSurface) {
                config->mInputSurface->onInputBufferDone(work->input.ordinal.frameIndex);
            }
            mChannel->onWorkDone(
                    std::move(work), changed ? config->mOutputFormat->dup() : nullptr,
                    initData.hasChanged() ? initData.update().get() : nullptr);
            break;
        }
        case kWhatWatch: {
            // watch message already posted; no-op.
            break;
        }
        default: {
            ALOGE("unrecognized message");
            break;
        }
    }
    setDeadline(TimePoint::max(), 0ms, "none");
}

void CCodec::setDeadline(
        const TimePoint &now,
        const std::chrono::milliseconds &timeout,
        const char *name) {
    int32_t mult = std::max(1, property_get_int32("debug.stagefright.ccodec_timeout_mult", 1));
    Mutexed<NamedTimePoint>::Locked deadline(mDeadline);
    deadline->set(now + (timeout * mult), name);
}

void CCodec::initiateReleaseIfStuck() {
    std::string name;
    bool pendingDeadline = false;
    {
        Mutexed<NamedTimePoint>::Locked deadline(mDeadline);
        if (deadline->get() < std::chrono::steady_clock::now()) {
            name = deadline->getName();
        }
        if (deadline->get() != TimePoint::max()) {
            pendingDeadline = true;
        }
    }
    if (name.empty()) {
        constexpr std::chrono::steady_clock::duration kWorkDurationThreshold = 3s;
        std::chrono::steady_clock::duration elapsed = mChannel->elapsed();
        if (elapsed >= kWorkDurationThreshold) {
            name = "queue";
        }
        if (elapsed > 0s) {
            pendingDeadline = true;
        }
    }
    if (name.empty()) {
        // We're not stuck.
        if (pendingDeadline) {
            // If we are not stuck yet but still has deadline coming up,
            // post watch message to check back later.
            (new AMessage(kWhatWatch, this))->post();
        }
        return;
    }

    ALOGW("previous call to %s exceeded timeout", name.c_str());
    initiateRelease(false);
    mCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
}

// static
PersistentSurface *CCodec::CreateInputSurface() {
    using namespace android;
    using ::android::hardware::media::omx::V1_0::implementation::TWGraphicBufferSource;
    // Attempt to create a Codec2's input surface.
    std::shared_ptr<Codec2Client::InputSurface> inputSurface =
            Codec2Client::CreateInputSurface();
    if (!inputSurface) {
        if (property_get_int32("debug.stagefright.c2inputsurface", 0) == -1) {
            sp<IGraphicBufferProducer> gbp;
            sp<OmxGraphicBufferSource> gbs = new OmxGraphicBufferSource();
            status_t err = gbs->initCheck();
            if (err != OK) {
                ALOGE("Failed to create persistent input surface: error %d", err);
                return nullptr;
            }
            return new PersistentSurface(
                    gbs->getIGraphicBufferProducer(), new TWGraphicBufferSource(gbs));
        } else {
            return nullptr;
        }
    }
    return new PersistentSurface(
            inputSurface->getGraphicBufferProducer(),
            static_cast<sp<android::hidl::base::V1_0::IBase>>(
            inputSurface->getHalInterface()));
}

class IntfCache {
public:
    IntfCache() = default;

    status_t init(const std::string &name) {
        std::shared_ptr<Codec2Client::Interface> intf{
            Codec2Client::CreateInterfaceByName(name.c_str())};
        if (!intf) {
            ALOGW("IntfCache [%s]: Unrecognized interface name", name.c_str());
            mInitStatus = NO_INIT;
            return NO_INIT;
        }
        const static C2StreamUsageTuning::input sUsage{0u /* stream id */};
        mFields.push_back(C2FieldSupportedValuesQuery::Possible(
                C2ParamField{&sUsage, &sUsage.value}));
        c2_status_t err = intf->querySupportedValues(mFields, C2_MAY_BLOCK);
        if (err != C2_OK) {
            ALOGW("IntfCache [%s]: failed to query usage supported value (err=%d)",
                    name.c_str(), err);
            mFields[0].status = err;
        }
        std::vector<std::unique_ptr<C2Param>> params;
        err = intf->query(
                {&mApiFeatures},
                {C2PortAllocatorsTuning::input::PARAM_TYPE},
                C2_MAY_BLOCK,
                &params);
        if (err != C2_OK && err != C2_BAD_INDEX) {
            ALOGW("IntfCache [%s]: failed to query api features (err=%d)",
                    name.c_str(), err);
        }
        while (!params.empty()) {
            C2Param *param = params.back().release();
            params.pop_back();
            if (!param) {
                continue;
            }
            if (param->type() == C2PortAllocatorsTuning::input::PARAM_TYPE) {
                mInputAllocators.reset(
                        C2PortAllocatorsTuning::input::From(params[0].get()));
            }
        }
        mInitStatus = OK;
        return OK;
    }

    status_t initCheck() const { return mInitStatus; }

    const C2FieldSupportedValuesQuery &getUsageSupportedValues() const {
        CHECK_EQ(1u, mFields.size());
        return mFields[0];
    }

    const C2ApiFeaturesSetting &getApiFeatures() const {
        return mApiFeatures;
    }

    const C2PortAllocatorsTuning::input &getInputAllocators() const {
        static std::unique_ptr<C2PortAllocatorsTuning::input> sInvalidated = []{
            std::unique_ptr<C2PortAllocatorsTuning::input> param =
                C2PortAllocatorsTuning::input::AllocUnique(0);
            param->invalidate();
            return param;
        }();
        return mInputAllocators ? *mInputAllocators : *sInvalidated;
    }

private:
    status_t mInitStatus{NO_INIT};

    std::vector<C2FieldSupportedValuesQuery> mFields;
    C2ApiFeaturesSetting mApiFeatures;
    std::unique_ptr<C2PortAllocatorsTuning::input> mInputAllocators;
};

static const IntfCache &GetIntfCache(const std::string &name) {
    static IntfCache sNullIntfCache;
    static std::mutex sMutex;
    static std::map<std::string, IntfCache> sCache;
    std::unique_lock<std::mutex> lock{sMutex};
    auto it = sCache.find(name);
    if (it == sCache.end()) {
        lock.unlock();
        IntfCache intfCache;
        status_t err = intfCache.init(name);
        if (err != OK) {
            return sNullIntfCache;
        }
        lock.lock();
        it = sCache.insert({name, std::move(intfCache)}).first;
    }
    return it->second;
}

static status_t GetCommonAllocatorIds(
        const std::vector<std::string> &names,
        C2Allocator::type_t type,
        std::set<C2Allocator::id_t> *ids) {
    int poolMask = GetCodec2PoolMask();
    C2PlatformAllocatorStore::id_t preferredLinearId = GetPreferredLinearAllocatorId(poolMask);
    C2Allocator::id_t defaultAllocatorId =
        (type == C2Allocator::LINEAR) ? preferredLinearId : C2PlatformAllocatorStore::GRALLOC;

    ids->clear();
    if (names.empty()) {
        return OK;
    }
    bool firstIteration = true;
    for (const std::string &name : names) {
        const IntfCache &intfCache = GetIntfCache(name);
        if (intfCache.initCheck() != OK) {
            continue;
        }
        const C2PortAllocatorsTuning::input &allocators = intfCache.getInputAllocators();
        if (firstIteration) {
            firstIteration = false;
            if (allocators && allocators.flexCount() > 0) {
                ids->insert(allocators.m.values,
                            allocators.m.values + allocators.flexCount());
            }
            if (ids->empty()) {
                // The component does not advertise allocators. Use default.
                ids->insert(defaultAllocatorId);
            }
            continue;
        }
        bool filtered = false;
        if (allocators && allocators.flexCount() > 0) {
            filtered = true;
            for (auto it = ids->begin(); it != ids->end(); ) {
                bool found = false;
                for (size_t j = 0; j < allocators.flexCount(); ++j) {
                    if (allocators.m.values[j] == *it) {
                        found = true;
                        break;
                    }
                }
                if (found) {
                    ++it;
                } else {
                    it = ids->erase(it);
                }
            }
        }
        if (!filtered) {
            // The component does not advertise supported allocators. Use default.
            bool containsDefault = (ids->count(defaultAllocatorId) > 0u);
            if (ids->size() != (containsDefault ? 1 : 0)) {
                ids->clear();
                if (containsDefault) {
                    ids->insert(defaultAllocatorId);
                }
            }
        }
    }
    // Finally, filter with pool masks
    for (auto it = ids->begin(); it != ids->end(); ) {
        if ((poolMask >> *it) & 1) {
            ++it;
        } else {
            it = ids->erase(it);
        }
    }
    return OK;
}

static status_t CalculateMinMaxUsage(
        const std::vector<std::string> &names, uint64_t *minUsage, uint64_t *maxUsage) {
    static C2StreamUsageTuning::input sUsage{0u /* stream id */};
    *minUsage = 0;
    *maxUsage = ~0ull;
    for (const std::string &name : names) {
        const IntfCache &intfCache = GetIntfCache(name);
        if (intfCache.initCheck() != OK) {
            continue;
        }
        const C2FieldSupportedValuesQuery &usageSupportedValues =
            intfCache.getUsageSupportedValues();
        if (usageSupportedValues.status != C2_OK) {
            continue;
        }
        const C2FieldSupportedValues &supported = usageSupportedValues.values;
        if (supported.type != C2FieldSupportedValues::FLAGS) {
            continue;
        }
        if (supported.values.empty()) {
            *maxUsage = 0;
            continue;
        }
        *minUsage |= supported.values[0].u64;
        int64_t currentMaxUsage = 0;
        for (const C2Value::Primitive &flags : supported.values) {
            currentMaxUsage |= flags.u64;
        }
        *maxUsage &= currentMaxUsage;
    }
    return OK;
}

// static
status_t CCodec::CanFetchLinearBlock(
        const std::vector<std::string> &names, const C2MemoryUsage &usage, bool *isCompatible) {
    for (const std::string &name : names) {
        const IntfCache &intfCache = GetIntfCache(name);
        if (intfCache.initCheck() != OK) {
            continue;
        }
        const C2ApiFeaturesSetting &features = intfCache.getApiFeatures();
        if (features && !(features.value & API_SAME_INPUT_BUFFER)) {
            *isCompatible = false;
            return OK;
        }
    }
    uint64_t minUsage = usage.expected;
    uint64_t maxUsage = ~0ull;
    std::set<C2Allocator::id_t> allocators;
    GetCommonAllocatorIds(names, C2Allocator::LINEAR, &allocators);
    if (allocators.empty()) {
        *isCompatible = false;
        return OK;
    }
    CalculateMinMaxUsage(names, &minUsage, &maxUsage);
    *isCompatible = ((maxUsage & minUsage) == minUsage);
    return OK;
}

static std::shared_ptr<C2BlockPool> GetPool(C2Allocator::id_t allocId) {
    static std::mutex sMutex{};
    static std::map<C2Allocator::id_t, std::shared_ptr<C2BlockPool>> sPools;
    std::unique_lock<std::mutex> lock{sMutex};
    std::shared_ptr<C2BlockPool> pool;
    auto it = sPools.find(allocId);
    if (it == sPools.end()) {
        c2_status_t err = CreateCodec2BlockPool(allocId, nullptr, &pool);
        if (err == OK) {
            sPools.emplace(allocId, pool);
        } else {
            pool.reset();
        }
    } else {
        pool = it->second;
    }
    return pool;
}

// static
std::shared_ptr<C2LinearBlock> CCodec::FetchLinearBlock(
        size_t capacity, const C2MemoryUsage &usage, const std::vector<std::string> &names) {
    uint64_t minUsage = usage.expected;
    uint64_t maxUsage = ~0ull;
    std::set<C2Allocator::id_t> allocators;
    GetCommonAllocatorIds(names, C2Allocator::LINEAR, &allocators);
    if (allocators.empty()) {
        allocators.insert(C2PlatformAllocatorStore::DEFAULT_LINEAR);
    }
    CalculateMinMaxUsage(names, &minUsage, &maxUsage);
    if ((maxUsage & minUsage) != minUsage) {
        allocators.clear();
        allocators.insert(C2PlatformAllocatorStore::DEFAULT_LINEAR);
    }
    std::shared_ptr<C2LinearBlock> block;
    for (C2Allocator::id_t allocId : allocators) {
        std::shared_ptr<C2BlockPool> pool = GetPool(allocId);
        if (!pool) {
            continue;
        }
        c2_status_t err = pool->fetchLinearBlock(capacity, C2MemoryUsage{minUsage}, &block);
        if (err != C2_OK || !block) {
            block.reset();
            continue;
        }
        break;
    }
    return block;
}

// static
status_t CCodec::CanFetchGraphicBlock(
        const std::vector<std::string> &names, bool *isCompatible) {
    uint64_t minUsage = 0;
    uint64_t maxUsage = ~0ull;
    std::set<C2Allocator::id_t> allocators;
    GetCommonAllocatorIds(names, C2Allocator::GRAPHIC, &allocators);
    if (allocators.empty()) {
        *isCompatible = false;
        return OK;
    }
    CalculateMinMaxUsage(names, &minUsage, &maxUsage);
    *isCompatible = ((maxUsage & minUsage) == minUsage);
    return OK;
}

// static
std::shared_ptr<C2GraphicBlock> CCodec::FetchGraphicBlock(
        int32_t width,
        int32_t height,
        int32_t format,
        uint64_t usage,
        const std::vector<std::string> &names) {
    uint32_t halPixelFormat = HAL_PIXEL_FORMAT_YCBCR_420_888;
    if (!C2Mapper::mapPixelFormatFrameworkToCodec(format, &halPixelFormat)) {
        ALOGD("Unrecognized pixel format: %d", format);
        return nullptr;
    }
    uint64_t minUsage = 0;
    uint64_t maxUsage = ~0ull;
    std::set<C2Allocator::id_t> allocators;
    GetCommonAllocatorIds(names, C2Allocator::GRAPHIC, &allocators);
    if (allocators.empty()) {
        allocators.insert(C2PlatformAllocatorStore::DEFAULT_GRAPHIC);
    }
    CalculateMinMaxUsage(names, &minUsage, &maxUsage);
    minUsage |= usage;
    if ((maxUsage & minUsage) != minUsage) {
        allocators.clear();
        allocators.insert(C2PlatformAllocatorStore::DEFAULT_GRAPHIC);
    }
    std::shared_ptr<C2GraphicBlock> block;
    for (C2Allocator::id_t allocId : allocators) {
        std::shared_ptr<C2BlockPool> pool;
        c2_status_t err = CreateCodec2BlockPool(allocId, nullptr, &pool);
        if (err != C2_OK || !pool) {
            continue;
        }
        err = pool->fetchGraphicBlock(
                width, height, halPixelFormat, C2MemoryUsage{minUsage}, &block);
        if (err != C2_OK || !block) {
            block.reset();
            continue;
        }
        break;
    }
    return block;
}

}  // namespace android

