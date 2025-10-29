/*
 * Copyright 2024 The Android Open Source Project
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
#define LOG_TAG "Codec2-InputSurface"
#include <android-base/logging.h>
#include <android/binder_auto_utils.h>
#include <android/binder_interface_utils.h>

#include <mutex>

#include <C2Config.h>

#include <codec2/aidl/inputsurface/InputSurface.h>
#include <codec2/aidl/inputsurface/InputSurfaceConnection.h>
#include <codec2/aidl/inputsurface/InputSurfaceSource.h>


namespace aidl::android::hardware::media::c2::utils {

using implementation::InputSurfaceSource;

using ImageConfig = InputSurface::ImageConfig;
using StreamConfig = InputSurface::StreamConfig;
using WorkStatusConfig = InputSurface::WorkStatusConfig;

template <typename T>
static C2R BasicSetter(bool, C2InterfaceHelper::C2P<T> &) {
    return C2R::Ok();
}

// Derived class of C2InterfaceHelper
class InputSurface::Interface : public C2InterfaceHelper {
public:
    explicit Interface(
            const std::shared_ptr<C2ReflectorHelper> &helper)
        : C2InterfaceHelper(helper) {

        setDerivedInstance(this);

        addParameter(
                DefineParam(mBlockSize, C2_PARAMKEY_BLOCK_SIZE)
                .withDefault(new C2StreamBlockSizeInfo::output(
                        0u, kDefaultImageWidth, kDefaultImageHeight))
                .withFields({
                        C2F(mBlockSize, width).inRange(2, 8192, 2),
                        C2F(mBlockSize, height).inRange(2, 8192, 2),})
                .withSetter(BlockSizeSetter)
                .build());
        addParameter(
                DefineParam(mBlockCount, C2_PARAMKEY_BLOCK_COUNT)
                .withDefault(new C2StreamBlockCountInfo::output(
                    0u, kDefaultImageBufferCount))
                .withFields({C2F(mBlockCount, value).any()})
                .withSetter(BlockCountSetter)
                .build());
        addParameter(
                DefineParam(mPixelFormat, C2_PARAMKEY_PIXEL_FORMAT)
                .withDefault(new C2StreamPixelFormatInfo::output(
                        0u, HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED))
                .withFields({C2F(mPixelFormat, value).any()})
                .withSetter(BasicSetter<decltype(mPixelFormat)::element_type>)
                .build());
        addParameter(
                DefineParam(mUsage, C2_PARAMKEY_OUTPUT_STREAM_USAGE)
                .withDefault(new C2StreamUsageTuning::output(0u, 0ULL))
                .withFields({C2F(mUsage, value).any()})
                .withSetter(BasicSetter<decltype(mUsage)::element_type>)
                .build());
        addParameter(
                DefineParam(mDataspace, C2_PARAMKEY_DATA_SPACE)
                .withDefault(new C2StreamDataSpaceInfo::output(
                        0u, kDefaultImageDataspace))
                .withFields({C2F(mDataspace, value).any()})
                .withSetter(BasicSetter<decltype(mDataspace)::element_type>)
                .build());

        addParameter(
                DefineParam(mMinFps, C2_PARAMKEY_INPUT_SURFACE_MIN_FRAME_RATE)
                .withDefault(new C2PortMinFrameRateTuning::output(0.0))
                .withFields({C2F(mMinFps, value).any()})
                .withSetter(BasicSetter<decltype(mMinFps)::element_type>)
                .build());
        addParameter(
                DefineParam(mMaxFps, C2_PARAMKEY_INPUT_SURFACE_MAX_FRAME_RATE)
                .withDefault(new C2PortMaxFrameRateTuning::output(0.0))
                .withFields({C2F(mMaxFps, value).any()})
                .withSetter(BasicSetter<decltype(mMaxFps)::element_type>)
                .build());
        addParameter(
                DefineParam(mCaptureFps, C2_PARAMKEY_INPUT_SURFACE_CAPTURE_FRAME_RATE)
                .withDefault(new C2PortCaptureFrameRateTuning::output(0.0))
                .withFields({C2F(mCaptureFps, value).any()})
                .withSetter(BasicSetter<decltype(mCaptureFps)::element_type>)
                .build());
        addParameter(
                DefineParam(mCodedFps, C2_PARAMKEY_FRAME_RATE)
                .withDefault(new C2StreamFrameRateInfo::output(0u, 0.0))
                .withFields({C2F(mCodedFps, value).any()})
                .withSetter(BasicSetter<decltype(mCodedFps)::element_type>)
                .build());
        addParameter(
                DefineParam(mTimeOffset, C2_PARAMKEY_FRAME_RATE)
                .withDefault(new C2ComponentTimeOffsetTuning(0ULL))
                .withFields({C2F(mTimeOffset, value).any()})
                .withSetter(BasicSetter<decltype(mTimeOffset)::element_type>)
                .build());
        addParameter(
                DefineParam(mStarted, C2_PARAMKEY_INPUT_SURFACE_START_AT)
                .withDefault(new C2PortStartTimestampTuning::output(0ULL))
                .withFields({
                        C2F(mStarted, enabled).any(),
                        C2F(mStarted, timestamp).any()})
                .withSetter(BasicSetter<decltype(mStarted)::element_type>)
                .build());
        addParameter(
                DefineParam(mStopped, C2_PARAMKEY_INPUT_SURFACE_STOP_AT)
                .withDefault(new C2PortStopTimestampTuning::output())
                .withFields({
                        C2F(mStopped, enabled).any(),
                        C2F(mStopped, timestamp).any()})
                .withSetter(BasicSetter<decltype(mStopped)::element_type>)
                .build());
        addParameter(
                DefineParam(mSuspended, C2_PARAMKEY_INPUT_SURFACE_SUSPEND_AT)
                .withDefault(new C2PortSuspendTimestampTuning::output())
                .withFields({
                        C2F(mSuspended, enabled).any(),
                        C2F(mSuspended, timestamp).any()})
                .withSetter(BasicSetter<decltype(mSuspended)::element_type>)
                .build());
        addParameter(
                DefineParam(mResumed, C2_PARAMKEY_INPUT_SURFACE_RESUME_AT)
                .withDefault(new C2PortResumeTimestampTuning::output(0ULL))
                .withFields({
                        C2F(mResumed, enabled).any(),
                        C2F(mResumed, timestamp).any()})
                .withSetter(BasicSetter<decltype(mResumed)::element_type>)
                .build());
        addParameter(
                DefineParam(mGap, C2_PARAMKEY_INPUT_SURFACE_TIMESTAMP_ADJUSTMENT)
                .withDefault(new C2PortTimestampGapTuning::output(
                        C2TimestampGapAdjustmentStruct::NONE, 0ULL))
                .withFields({
                        C2F(mGap, mode)
                                .oneOf({
                                        C2TimestampGapAdjustmentStruct::NONE,
                                        C2TimestampGapAdjustmentStruct::MIN_GAP,
                                        C2TimestampGapAdjustmentStruct::FIXED_GAP}),
                        C2F(mGap, value).any()})
                .withSetter(BasicSetter<decltype(mGap)::element_type>)
                .build());
        addParameter(
                DefineParam(mStopTimeOffset, C2_PARAMKEY_INPUT_SURFACE_STOP_TIME_OFFSET)
                .withDefault(new C2PortStopTimeOffset::output(0ULL))
                .withFields({C2F(mStopTimeOffset, value).any()})
                .withSetter(BasicSetter<decltype(mStopTimeOffset)::element_type>)
                .build());

        addParameter(
                DefineParam(mInputDone, C2_PARAMKEY_OUTPUT_COUNTER)
                .withDefault(new C2PortConfigCounterTuning::output(UINT64_MAX))
                .withFields({C2F(mInputDone, value).any()})
                .withSetter(BasicSetter<decltype(mInputDone)::element_type>)
                .build());
        addParameter(
                DefineParam(mInputDoneCount, C2_PARAMKEY_LAYER_INDEX)
                .withDefault(new C2StreamLayerCountInfo::input(0u, 0))
                .withFields({C2F(mInputDoneCount, value).any()})
                .withSetter(BasicSetter<decltype(mInputDoneCount)::element_type>)
                .build());
        addParameter(
                DefineParam(mEmptyCount, C2_PARAMKEY_LAYER_COUNT)
                .withDefault(new C2StreamLayerCountInfo::output(0u, 0))
                .withFields({C2F(mEmptyCount, value).any()})
                .withSetter(BasicSetter<decltype(mEmptyCount)::element_type>)
                .build());
    }

    void getImageConfig(ImageConfig* _Nonnull config) {
        config->mWidth = mBlockSize->width;
        config->mHeight = mBlockSize->height;
        config->mFormat = mPixelFormat->value;
        config->mNumBuffers = mBlockCount->value;
        config->mUsage = mUsage->value;
        config->mDataspace = mDataspace->value;
    }

    void getStreamConfig(StreamConfig* _Nonnull config) {
        config->mMinFps = mMinFps->value;
        config->mMaxFps = mMaxFps->value;
        config->mCaptureFps = mCaptureFps->value;
        config->mCodedFps = mCodedFps->value;
        config->mTimeOffsetUs = mTimeOffset->value;

        bool suspended = mSuspended->enabled;
        bool resumed = mResumed->enabled;
        CHECK(resumed != suspended);
        config->mSuspended = suspended;
        config->mSuspendAtUs = mSuspended->timestamp;
        config->mResumeAtUs = mResumed->timestamp;
        bool stopped = mStopped->enabled;
        bool started = mStarted->enabled;
        CHECK(stopped != started);
        config->mStopped = stopped;
        config->mStopAtUs = mStopped->timestamp;
        config->mStartAtUs = mStarted->timestamp;

        config->mAdjustedFpsMode = mGap->mode;
        config->mAdjustedGapUs = mGap->value;
    }

    void getWorkStatusConfig(WorkStatusConfig* _Nonnull config) {
        config->mLastDoneIndex = mInputDone->value;
        config->mLastDoneCount = mInputDoneCount->value;
        config->mEmptyCount = mEmptyCount->value;
    }

private:
    // setters
    static C2R BlockSizeSetter(bool mayBlock,
            C2InterfaceHelper::C2P<C2StreamBlockSizeInfo::output> &me) {
        (void)mayBlock;
        uint32_t width_ = c2_min(me.v.width, 8192u);
        uint32_t height_ = c2_min(me.v.height, 8192u);
        if (width_ % 2 != 0) width_++;
        if (height_ % 2 != 0) height_++;
        me.set().width = width_;
        me.set().height = height_;
        return C2R::Ok();
    }
    static C2R BlockCountSetter(bool mayBlock,
            C2InterfaceHelper::C2P<C2StreamBlockCountInfo::output> &me) {
        (void)mayBlock;
        me.set().value = c2_min(me.v.value, kDefaultImageBufferCount);
        return C2R::Ok();
    }

private:
    // buffer configuraration
    std::shared_ptr<C2StreamBlockSizeInfo::output> mBlockSize;
    std::shared_ptr<C2StreamBlockCountInfo::output> mBlockCount;
    std::shared_ptr<C2StreamPixelFormatInfo::output> mPixelFormat;
    std::shared_ptr<C2StreamUsageTuning::output> mUsage;
    std::shared_ptr<C2StreamDataSpaceInfo::output> mDataspace;

    // input surface source configuration
    std::shared_ptr<C2PortMinFrameRateTuning::output> mMinFps;
    std::shared_ptr<C2PortMaxFrameRateTuning::output> mMaxFps;
    std::shared_ptr<C2PortCaptureFrameRateTuning::output> mCaptureFps;
    std::shared_ptr<C2StreamFrameRateInfo::output> mCodedFps;
    std::shared_ptr<C2ComponentTimeOffsetTuning> mTimeOffset; // unsigned, but
                                                              // signed
    std::shared_ptr<C2PortSuspendTimestampTuning::output> mSuspended;
    std::shared_ptr<C2PortResumeTimestampTuning::output> mResumed;
    std::shared_ptr<C2PortStartTimestampTuning::output> mStarted;
    std::shared_ptr<C2PortStopTimestampTuning::output> mStopped;
    std::shared_ptr<C2PortTimestampGapTuning::output> mGap;
    std::shared_ptr<C2PortStopTimeOffset::output> mStopTimeOffset; // query

    // current work status configuration
    // TODO: remove this and move this to onWorkDone()
    std::shared_ptr<C2PortConfigCounterTuning::output> mInputDone;
    std::shared_ptr<C2StreamLayerCountInfo::input> mInputDoneCount;
    std::shared_ptr<C2StreamLayerCountInfo::output> mEmptyCount;
};

class InputSurface::ConfigurableIntf : public ConfigurableC2Intf {
public:
    ConfigurableIntf(
            const std::shared_ptr<InputSurface::Interface> &intf,
            const std::shared_ptr<InputSurface> &surface)
        : ConfigurableC2Intf("input-surface", 0),
          mIntf(intf), mSurface(surface) {
    }

    virtual ~ConfigurableIntf() override = default;

    virtual c2_status_t query(
            const std::vector<C2Param::Index> &indices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const params
            ) const override {
        // std::lock_guard<std::mutex> l(mConfigLock);
        std::lock_guard<std::mutex> l(mConfigLock);
        return mIntf->query({}, indices, mayBlock, params);
    }

    virtual c2_status_t config(
            const std::vector<C2Param*> &params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures
            ) override {
        auto surface = mSurface.lock();
        if (!surface) {
            return C2_CORRUPTED;
        }

        if (params.size() == 1 &&
                params[0]->index() == C2InputSurfaceStartTuning::PARAM_TYPE) {
            c2_status_t res = surface->start();
            ALOGD("InputSurface started: res(%d)", res);
            return res;
        }
        c2_status_t err;
        {
            ImageConfig imageConfig;
            StreamConfig streamConfig;
            WorkStatusConfig workStatusConfig;
            int64_t inputDelayUs = 0;

            std::lock_guard<std::mutex> l(mConfigLock);
            err = mIntf->config(params, mayBlock, failures);

            mIntf->getImageConfig(&imageConfig);
            mIntf->getStreamConfig(&streamConfig);
            mIntf->getWorkStatusConfig(&workStatusConfig);
            if (surface->updateConfig(
                   imageConfig, streamConfig, workStatusConfig, &inputDelayUs)) {
                C2PortStopTimeOffset::output offsetConfig(inputDelayUs);
                std::vector<std::unique_ptr<C2SettingResult>> fail;
                c2_status_t updateErr = mIntf->config({&offsetConfig}, mayBlock, &fail);
            }
        }
        return err;
    }

    virtual c2_status_t querySupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>>* const params
            ) const override {
        std::lock_guard<std::mutex> l(mConfigLock);
        return mIntf->querySupportedParams(params);
    }

    virtual c2_status_t querySupportedValues(
            std::vector<C2FieldSupportedValuesQuery>& fields,
            c2_blocking_t mayBlock) const override {
        std::lock_guard<std::mutex> l(mConfigLock);
        return mIntf->querySupportedValues(fields, mayBlock);
    }

private:
    const std::shared_ptr<InputSurface::Interface> mIntf;
    const std::weak_ptr<InputSurface> mSurface;

    mutable std::mutex mConfigLock;
};

struct InputSurface::SourceEventCallback : public InputSurfaceSource::EventCallback {
    explicit SourceEventCallback(std::shared_ptr<InputSurface> surface) : mSurface{surface} {}

    virtual ~SourceEventCallback() override {}

    void onDataspaceChanged(int32_t dataspace, int32_t pixelFormat) override {
        // TODO, tricky since this might be called with a lock being held.
        (void) dataspace;
        (void) pixelFormat;
    }

    void onComponentReleased() override {
        // TODO
    }

    std::weak_ptr<InputSurface> mSurface;
};

InputSurface::InputSurface() {
    mIntf = std::make_shared<Interface>(
            std::make_shared<C2ReflectorHelper>());
    mSource = new InputSurfaceSource();
    // mConfigurable, mSourceEventcallback are initialized lazily.
}

InputSurface::~InputSurface() {
    release();
}

void InputSurface::init() {
    std::call_once(mInit, [this]() {
        mConfigurable = SharedRefBase::make<CachedConfigurable>(
                std::make_unique<ConfigurableIntf>(mIntf, this->ref<InputSurface>()));
        mSourceEventCallback = std::make_shared<SourceEventCallback>(this->ref<InputSurface>());
        mSource->setEventCallback(mSourceEventCallback);
    });
}

::ndk::ScopedAStatus InputSurface::getSurface(::aidl::android::view::Surface* surface) {
    init();
    std::lock_guard<std::mutex> l(mLock);
    ANativeWindow *window = mSource->getNativeWindow();
    if (window) {
        surface->reset(window);
        return ::ndk::ScopedAStatus::ok();
    }
    return ::ndk::ScopedAStatus::fromServiceSpecificError(C2_CORRUPTED);
}

::ndk::ScopedAStatus InputSurface::getConfigurable(
        std::shared_ptr<IConfigurable>* configurable) {
    init();
    if (mConfigurable) {
        *configurable = mConfigurable;
        return ::ndk::ScopedAStatus::ok();
    }
    return ::ndk::ScopedAStatus::fromServiceSpecificError(C2_CORRUPTED);
}

::ndk::ScopedAStatus InputSurface::connect(
        const std::shared_ptr<IInputSink>& sink,
        std::shared_ptr<IInputSurfaceConnection>* connection) {
    std::unique_lock<std::mutex> l(mLock);
    mConnection = SharedRefBase::make<InputSurfaceConnection>(sink, mSource);
    *connection = mConnection;
    c2_status_t c2Res = mSource->configure(
            mConnection,
            mImageConfig.mDataspace,
            mImageConfig.mNumBuffers,
            mImageConfig.mWidth,
            mImageConfig.mHeight,
            mImageConfig.mUsage);
    if (c2Res != C2_OK) {
        ALOGE("InputSurface connect: configuring source failed(%d)", c2Res);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(c2Res);
    }
    int numSlots = mImageConfig.mNumBuffers;
    for (size_t i = 0; i < numSlots; ++i) {
        mSource->onInputBufferAdded(i);
    }
    return ::ndk::ScopedAStatus::ok();
}

c2_status_t InputSurface::start() {
    std::unique_lock<std::mutex> l(mLock);
    c2_status_t c2Res = mSource->start();
    if (c2Res != C2_OK) {
        ALOGE("InputSurface connect: starting source failed(%d)", c2Res);
    }
    return c2Res;
}

void InputSurface::updateImageConfig(ImageConfig &config) {
    std::unique_lock<std::mutex> l(mLock);
    if (mImageConfig.mWidth != config.mWidth) {
        mImageConfig.mWidth = config.mWidth;
    }
    if (mImageConfig.mHeight != config.mHeight) {
        mImageConfig.mHeight = config.mHeight;
    }
    if (mImageConfig.mFormat != config.mFormat) {
        mImageConfig.mFormat = config.mFormat;
    }
    if (mImageConfig.mNumBuffers != config.mNumBuffers) {
        mImageConfig.mNumBuffers = config.mNumBuffers;
    }
    if (mImageConfig.mUsage != config.mUsage) {
        mImageConfig.mUsage = config.mUsage;
    }
    if (mImageConfig.mDataspace != config.mDataspace) {
        mImageConfig.mDataspace = config.mDataspace;
    }
}

bool InputSurface::updateStreamConfig(
        StreamConfig &config, int64_t *inputDelayUs) {
    std::stringstream status;
    c2_status_t err = C2_OK;
    bool inputDelayUpdated = false;

    std::unique_lock<std::mutex> l(mLock);
    // handle StreamConfig changes.
    // TRICKY: we do not unset frame delay repeating
    if (config.mMinFps > 0 && config.mMinFps != mStreamConfig.mMinFps) {
        int64_t us = 1e6 / config.mMinFps + 0.5;
        c2_status_t res = mSource->setRepeatPreviousFrameDelayUs(us);
        status << " minFps=" << config.mMinFps << " => repeatDelayUs=" << us;
        if (res != C2_OK) {
            status << " (=> " << asString(res) << ")";
            err = res;
        }
        mStreamConfig.mMinFps = config.mMinFps;
    }
    bool fixedModeUpdate = false;
    if (config.mAdjustedFpsMode != C2TimestampGapAdjustmentStruct::NONE && (
            config.mAdjustedFpsMode != mStreamConfig.mAdjustedFpsMode ||
            config.mAdjustedGapUs != mStreamConfig.mAdjustedGapUs)) {
        mStreamConfig.mAdjustedFpsMode = config.mAdjustedFpsMode;
        mStreamConfig.mAdjustedGapUs = config.mAdjustedGapUs;
        fixedModeUpdate = (config.mAdjustedFpsMode == C2TimestampGapAdjustmentStruct::FIXED_GAP);
        if (mConnection) {
            mConnection->setAdjustTimestampGapUs(mStreamConfig.mAdjustedGapUs);
        }
    }
    // TRICKY: we do not unset max fps to 0 unless using fixed fps
    if ((config.mMaxFps > 0 || (fixedModeUpdate && config.mMaxFps == -1))
            && config.mMaxFps != mStreamConfig.mMaxFps) {
        c2_status_t res = mSource->setMaxFps(config.mMaxFps);
        status << " maxFps=" << config.mMaxFps;
        if (res != C2_OK) {
            status << " (=> " << asString(res) << ")";
            err = res;
        }
        mStreamConfig.mMaxFps = config.mMaxFps;
    }
    if (config.mTimeOffsetUs != mStreamConfig.mTimeOffsetUs) {
        c2_status_t res = mSource->setTimeOffsetUs(config.mTimeOffsetUs);
        status << " timeOffset " << config.mTimeOffsetUs << "us";
        if (res != C2_OK) {
            status << " (=> " << asString(res) << ")";
            err = res;
        }
        mStreamConfig.mTimeOffsetUs = config.mTimeOffsetUs;
    }
    if (config.mCaptureFps != mStreamConfig.mCaptureFps ||
            config.mCodedFps != mStreamConfig.mCodedFps) {
        c2_status_t res = mSource->setTimeLapseConfig(
                config.mCodedFps, config.mCaptureFps);
        status << " timeLapse " << config.mCaptureFps << "fps as "
               << config.mCodedFps << "fps";
        if (res != C2_OK) {
            status << " (=> " << asString(res) << ")";
            err = res;
        }
        mStreamConfig.mCaptureFps = config.mCaptureFps;
        mStreamConfig.mCodedFps = config.mCodedFps;
    }
    if ((config.mStartAtUs != mStreamConfig.mStartAtUs ||
            config.mStopped != mStreamConfig.mStopped) &&
                !config.mStopped) {
        c2_status_t res = mSource->setStartTimeUs(config.mStartAtUs);
        status << " start at " << config.mStartAtUs << "us";
        if (res != C2_OK) {
            status << " (=> " << asString(res) << ")";
            err = res;
        }
        mStreamConfig.mStartAtUs = config.mStartAtUs;
        mStreamConfig.mStopped = config.mStopped;
    }
    if (config.mSuspended != mStreamConfig.mSuspended) {
        int64_t atUs = config.mSuspended ? config.mSuspendAtUs : config.mResumeAtUs;
        c2_status_t res = mSource->setSuspend(config.mSuspended, atUs);
        status << " " << (config.mSuspended ? "suspend" : "resume")
                << " at " << atUs << "us";
        if (res != C2_OK) {
            status << " (=> " << asString(res) << ")";
            err = res;
        }
        mStreamConfig.mSuspended = config.mSuspended;
        if (config.mSuspended) {
            mStreamConfig.mSuspendAtUs = atUs;
        } else {
            mStreamConfig.mResumeAtUs = atUs;
        }
    }
    if (config.mStopped != mStreamConfig.mStopped && config.mStopped) {
        // start time has changed or started from stop.
        c2_status_t res = mSource->setStopTimeUs(config.mStopAtUs);
        status << " stop at " << config.mStopAtUs << "us";
        if (res != C2_OK) {
            status << " (=> " << asString(res) << ")";
            err = res;
        } else {
            status << " delayUs";
            res = mSource->getStopTimeOffsetUs(inputDelayUs);
            if (res != C2_OK) {
                status << " (=> " << asString(res) << ")";
            } else {
                status << "=" << *inputDelayUs << "us";
                inputDelayUpdated = true;
            }
        }
        mStreamConfig.mStopAtUs = config.mStopAtUs;
        mStreamConfig.mStopped = config.mStopped;
    }
    if (status.str().empty()) {
        ALOGV("StreamConfig not changed");
    } else {
        ALOGD("StreamConfig%s", status.str().c_str());
    }
    return inputDelayUpdated;
}

void InputSurface::updateWorkStatusConfig(WorkStatusConfig &config) {
    std::unique_lock<std::mutex> l(mLock);
    if (!mConnection) {
        ALOGE("work status is updated though there is no connection.");
        return;
    }
    if (mWorkStatusConfig.mLastDoneIndex != config.mLastDoneIndex) {
        mWorkStatusConfig.mLastDoneIndex = config.mLastDoneIndex;
        mConnection->onInputBufferDone(mWorkStatusConfig.mLastDoneIndex);
    }
    if (mWorkStatusConfig.mLastDoneCount != config.mLastDoneCount) {
        mWorkStatusConfig.mLastDoneCount = config.mLastDoneCount;
    }
    if (mWorkStatusConfig.mEmptyCount != config.mEmptyCount) {
        mWorkStatusConfig.mEmptyCount = config.mEmptyCount;
        mConnection->onInputBufferEmptied();
    }
}

bool InputSurface::updateConfig(
        ImageConfig &imageConfig, StreamConfig &streamConfig,
        WorkStatusConfig &workStatusConfig, int64_t *inputDelayUs) {
    updateImageConfig(imageConfig);
    bool ret = updateStreamConfig(streamConfig, inputDelayUs);
    updateWorkStatusConfig(workStatusConfig);

    return ret;
}

void InputSurface::release() {
    ALOGD("all refs are gone");
    // TODO clean up
}

}  // namespace aidl::android::hardware::media::c2::utils
