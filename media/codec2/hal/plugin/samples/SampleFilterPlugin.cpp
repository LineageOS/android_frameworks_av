/*
 * Copyright 2020 The Android Open Source Project
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

#define LOG_TAG "SampleFilterPlugin"
#include <android-base/logging.h>

#include <chrono>
#include <thread>

#include <codec2/hidl/plugin/FilterPlugin.h>

#include <C2AllocatorGralloc.h>
#include <C2Config.h>
#include <C2PlatformSupport.h>
#include <Codec2Mapper.h>
#include <util/C2InterfaceHelper.h>

#include <renderengine/RenderEngine.h>
#include <system/window.h>
#include <ui/GraphicBuffer.h>
#include <utils/RefBase.h>

typedef C2StreamParam<C2Info, C2ColorAspectsStruct,
                kParamIndexColorAspects | C2Param::CoreIndex::IS_REQUEST_FLAG>
        C2StreamColorAspectsRequestInfo;

// In practice the vendor parameters will be defined in a separate header file,
// but for the purpose of this sample, we just define it here.

// Vendor-specific type index for filters start from this value. 0x7000 is added to
// avoid conflict with existing vendor type indices.
constexpr uint32_t kTypeIndexFilterStart = C2Param::TYPE_INDEX_VENDOR_START + 0x7000;
// Answer to the Ultimate Question of Life, the Universe, and Everything
// (Reference to The Hitchhiker's Guide to the Galaxy by Douglas Adams)
constexpr uint32_t kParamIndexVendorUltimateAnswer = kTypeIndexFilterStart + 0;
typedef C2StreamParam<C2Info, C2Int32Value, kParamIndexVendorUltimateAnswer>
        C2StreamVendorUltimateAnswerInfo;
constexpr char C2_PARAMKEY_VENDOR_ULTIMATE_ANSWER[] = "ultimate-answer";

namespace android {

using namespace std::literals::chrono_literals;

class SampleToneMappingFilter
    : public C2Component, public std::enable_shared_from_this<SampleToneMappingFilter> {
public:
    class Interface : public C2ComponentInterface {
    public:
        static const std::string NAME;
        static const FilterPlugin_V1::Descriptor DESCRIPTOR;

        Interface(c2_node_id_t id, const std::shared_ptr<C2ReflectorHelper> &reflector)
            : mId(id),
              mHelper(reflector) {
        }
        ~Interface() override = default;
        C2String getName() const override { return NAME; }
        c2_node_id_t getId() const override { return mId; }

        c2_status_t query_vb(
                const std::vector<C2Param*> &stackParams,
                const std::vector<C2Param::Index> &heapParamIndices,
                c2_blocking_t mayBlock,
                std::vector<std::unique_ptr<C2Param>>* const heapParams) const override {
            return mHelper.query(stackParams, heapParamIndices, mayBlock, heapParams);
        }
        c2_status_t config_vb(
                const std::vector<C2Param*> &params,
                c2_blocking_t mayBlock,
                std::vector<std::unique_ptr<C2SettingResult>>* const failures) override {
            return mHelper.config(params, mayBlock, failures);
        }
        c2_status_t querySupportedParams_nb(
                std::vector<std::shared_ptr<C2ParamDescriptor>> * const params) const override {
            return mHelper.querySupportedParams(params);
        }
        c2_status_t querySupportedValues_vb(
                std::vector<C2FieldSupportedValuesQuery> &fields,
                c2_blocking_t mayBlock) const override {
            return mHelper.querySupportedValues(fields, mayBlock);
        }
        c2_status_t createTunnel_sm(c2_node_id_t) override { return C2_OMITTED; }
        c2_status_t releaseTunnel_sm(c2_node_id_t) override { return C2_OMITTED; }

        uint32_t getDataSpace() {
            Helper::Lock lock = mHelper.lock();
            uint32_t dataspace = HAL_DATASPACE_UNKNOWN;
            C2Mapper::map(
                    mHelper.mInputColorAspectInfo->range,
                    mHelper.mInputColorAspectInfo->primaries,
                    mHelper.mInputColorAspectInfo->matrix,
                    mHelper.mInputColorAspectInfo->transfer,
                    &dataspace);
            return dataspace;
        }
        std::shared_ptr<C2StreamHdrStaticInfo::input> getHdrStaticMetadata() {
            Helper::Lock lock = mHelper.lock();
            return mHelper.mInputHdrStaticInfo;
        }
        C2BlockPool::local_id_t getPoolId() {
            Helper::Lock lock = mHelper.lock();
            return mHelper.mOutputPoolIds->m.values[0];
        }

        static bool IsFilteringEnabled(const std::shared_ptr<C2ComponentInterface> &intf) {
            C2StreamColorAspectsRequestInfo::output info(0u);
            std::vector<std::unique_ptr<C2Param>> heapParams;
            c2_status_t err = intf->query_vb({&info}, {}, C2_MAY_BLOCK, &heapParams);
            if (err != C2_OK && err != C2_BAD_INDEX) {
                LOG(WARNING) << "SampleToneMappingFilter::Interface::IsFilteringEnabled: "
                        << "query failed for " << intf->getName();
                return false;
            }
            return info && info.transfer == C2Color::TRANSFER_170M;
        }

        static c2_status_t QueryParamsForPreviousComponent(
                [[maybe_unused]] const std::shared_ptr<C2ComponentInterface> &intf,
                std::vector<std::unique_ptr<C2Param>> *params) {
            params->emplace_back(new C2StreamUsageTuning::output(
                    0u, C2AndroidMemoryUsage::HW_TEXTURE_READ));
            params->emplace_back(new C2StreamPixelFormatInfo::output(
                    0u, HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED));
            return C2_OK;
        }
    private:
        const c2_node_id_t mId;
        struct Helper : public C2InterfaceHelper {
            explicit Helper(std::shared_ptr<C2ReflectorHelper> reflector)
                : C2InterfaceHelper(reflector) {
                setDerivedInstance(this);

                addParameter(
                        DefineParam(mApiFeatures, C2_PARAMKEY_API_FEATURES)
                        .withConstValue(new C2ApiFeaturesSetting(C2Config::api_feature_t(
                                API_REFLECTION |
                                API_VALUES |
                                API_CURRENT_VALUES |
                                API_DEPENDENCY |
                                API_SAME_INPUT_BUFFER)))
                        .build());

                mName = C2ComponentNameSetting::AllocShared(NAME.size() + 1);
                strncpy(mName->m.value, NAME.c_str(), NAME.size() + 1);
                addParameter(
                        DefineParam(mName, C2_PARAMKEY_COMPONENT_NAME)
                        .withConstValue(mName)
                        .build());

                addParameter(
                        DefineParam(mKind, C2_PARAMKEY_COMPONENT_KIND)
                        .withConstValue(new C2ComponentKindSetting(C2Component::KIND_OTHER))
                        .build());

                addParameter(
                        DefineParam(mDomain, C2_PARAMKEY_COMPONENT_DOMAIN)
                        .withConstValue(new C2ComponentDomainSetting(C2Component::DOMAIN_VIDEO))
                        .build());

                addParameter(
                        DefineParam(mInputStreamCount, C2_PARAMKEY_INPUT_STREAM_COUNT)
                        .withConstValue(new C2PortStreamCountTuning::input(1))
                        .build());

                addParameter(
                        DefineParam(mOutputStreamCount, C2_PARAMKEY_OUTPUT_STREAM_COUNT)
                        .withConstValue(new C2PortStreamCountTuning::output(1))
                        .build());

                addParameter(
                        DefineParam(mInputFormat, C2_PARAMKEY_INPUT_STREAM_BUFFER_TYPE)
                        .withConstValue(new C2StreamBufferTypeSetting::input(
                                0u, C2BufferData::GRAPHIC))
                        .build());

                static const std::string kRawMediaType = "video/raw";
                mInputMediaType = C2PortMediaTypeSetting::input::AllocShared(
                        kRawMediaType.size() + 1);
                strncpy(mInputMediaType->m.value, kRawMediaType.c_str(), kRawMediaType.size() + 1);
                addParameter(
                        DefineParam(mInputMediaType, C2_PARAMKEY_INPUT_MEDIA_TYPE)
                        .withConstValue(mInputMediaType)
                        .build());

                addParameter(
                        DefineParam(mOutputFormat, C2_PARAMKEY_OUTPUT_STREAM_BUFFER_TYPE)
                        .withConstValue(new C2StreamBufferTypeSetting::output(
                                0u, C2BufferData::GRAPHIC))
                        .build());

                mOutputMediaType = C2PortMediaTypeSetting::output::AllocShared(
                        kRawMediaType.size() + 1);
                strncpy(mOutputMediaType->m.value, kRawMediaType.c_str(), kRawMediaType.size() + 1);
                addParameter(
                        DefineParam(mOutputMediaType, C2_PARAMKEY_OUTPUT_MEDIA_TYPE)
                        .withConstValue(mOutputMediaType)
                        .build());

                addParameter(
                        DefineParam(mActualInputDelay, C2_PARAMKEY_INPUT_DELAY)
                        .withConstValue(new C2PortActualDelayTuning::input(0u))
                        .build());

                addParameter(
                        DefineParam(mActualOutputDelay, C2_PARAMKEY_OUTPUT_DELAY)
                        .withConstValue(new C2PortActualDelayTuning::output(0u))
                        .build());

                addParameter(
                        DefineParam(mActualPipelineDelay, C2_PARAMKEY_PIPELINE_DELAY)
                        .withConstValue(new C2ActualPipelineDelayTuning(0u))
                        .build());

                C2BlockPool::local_id_t outputPoolIds[1] = { C2BlockPool::BASIC_GRAPHIC };
                addParameter(
                        DefineParam(mOutputPoolIds, C2_PARAMKEY_OUTPUT_BLOCK_POOLS)
                        .withDefault(C2PortBlockPoolsTuning::output::AllocShared(outputPoolIds))
                        .withFields({ C2F(mOutputPoolIds, m.values[0]).any(),
                                      C2F(mOutputPoolIds, m.values).inRange(0, 1) })
                        .withSetter(OutputBlockPoolSetter)
                        .build());

                addParameter(
                        DefineParam(mInputHdrStaticInfo, C2_PARAMKEY_HDR_STATIC_INFO)
                        .withDefault(new C2StreamHdrStaticInfo::input(0u))
                        .withFields({
                            C2F(mInputHdrStaticInfo, mastering.red.x).any(),
                        })
                        .withSetter(HdrStaticInfoSetter)
                        .build());

                addParameter(
                        DefineParam(mOutputHdrStaticInfo, C2_PARAMKEY_HDR_STATIC_INFO)
                        .withConstValue(new C2StreamHdrStaticInfo::output(0u))
                        .build());

                addParameter(
                        DefineParam(mInputColorAspectInfo, C2_PARAMKEY_COLOR_ASPECTS)
                        .withDefault(new C2StreamColorAspectsInfo::input(0u))
                        .withFields({
                            C2F(mInputColorAspectInfo, range).any(),
                            C2F(mInputColorAspectInfo, primaries).any(),
                            C2F(mInputColorAspectInfo, transfer).any(),
                            C2F(mInputColorAspectInfo, matrix).any(),
                        })
                        .withSetter(InputColorAspectsSetter)
                        .build());

                addParameter(
                        DefineParam(
                            mColorAspectRequestInfo,
                            (std::string(C2_PARAMKEY_COLOR_ASPECTS) + ".request").c_str())
                        .withDefault(new C2StreamColorAspectsRequestInfo::output(0u))
                        .withFields({
                            C2F(mColorAspectRequestInfo, range).any(),
                            C2F(mColorAspectRequestInfo, primaries).any(),
                            C2F(mColorAspectRequestInfo, transfer).oneOf({
                                C2Color::TRANSFER_UNSPECIFIED,
                                C2Color::TRANSFER_170M,
                            }),
                            C2F(mColorAspectRequestInfo, matrix).any(),
                        })
                        .withSetter(ColorAspectsRequestSetter)
                        .build());

                addParameter(
                        DefineParam(mVendorUltimateAnswerInfo, C2_PARAMKEY_VENDOR_ULTIMATE_ANSWER)
                        .withDefault(new C2StreamVendorUltimateAnswerInfo::input(0u))
                        .withFields({
                            C2F(mVendorUltimateAnswerInfo, value).any(),
                        })
                        .withSetter(VendorUltimateAnswerSetter)
                        .build());

                addParameter(
                        DefineParam(mOutputColorAspectInfo, C2_PARAMKEY_COLOR_ASPECTS)
                        .withDefault(new C2StreamColorAspectsInfo::output(0u))
                        .withFields({
                            C2F(mOutputColorAspectInfo, range).any(),
                            C2F(mOutputColorAspectInfo, primaries).any(),
                            C2F(mOutputColorAspectInfo, transfer).any(),
                            C2F(mOutputColorAspectInfo, matrix).any(),
                        })
                        .withSetter(OutputColorAspectsSetter,
                                    mInputColorAspectInfo,
                                    mColorAspectRequestInfo)
                        .build());
            }

            static C2R OutputBlockPoolSetter(
                    bool mayBlock,
                    C2P<C2PortBlockPoolsTuning::output> &me) {
                (void)mayBlock, (void)me;
                return C2R::Ok();
            }

            static C2R HdrStaticInfoSetter(
                    bool mayBlock,
                    C2P<C2StreamHdrStaticInfo::input> &me) {
                (void)mayBlock, (void)me;
                return C2R::Ok();
            }

            static C2R InputColorAspectsSetter(
                    bool mayBlock,
                    C2P<C2StreamColorAspectsInfo::input> &me) {
                (void)mayBlock, (void)me;
                return C2R::Ok();
            }

            static C2R OutputColorAspectsSetter(
                    bool mayBlock,
                    C2P<C2StreamColorAspectsInfo::output> &me,
                    const C2P<C2StreamColorAspectsInfo::input> &inputColor,
                    const C2P<C2StreamColorAspectsRequestInfo::output> &request) {
                (void)mayBlock;
                me.set().range = inputColor.v.range;
                me.set().primaries = inputColor.v.primaries;
                me.set().transfer = inputColor.v.transfer;
                if (request.v.transfer == C2Color::TRANSFER_170M) {
                    me.set().transfer = C2Color::TRANSFER_170M;
                }
                me.set().matrix = inputColor.v.matrix;
                return C2R::Ok();
            }

            static C2R ColorAspectsRequestSetter(
                    bool mayBlock,
                    C2P<C2StreamColorAspectsRequestInfo::output> &me) {
                (void)mayBlock;
                if (me.v.range != C2Color::RANGE_UNSPECIFIED) {
                    me.set().range = C2Color::RANGE_UNSPECIFIED;
                }
                if (me.v.primaries != C2Color::PRIMARIES_UNSPECIFIED) {
                    me.set().primaries = C2Color::PRIMARIES_UNSPECIFIED;
                }
                if (me.v.transfer != C2Color::TRANSFER_170M) {
                    me.set().transfer = C2Color::TRANSFER_UNSPECIFIED;
                }
                if (me.v.matrix != C2Color::MATRIX_UNSPECIFIED) {
                    me.set().matrix = C2Color::MATRIX_UNSPECIFIED;
                }
                return C2R::Ok();
            }

            static C2R VendorUltimateAnswerSetter(
                    bool mayBlock,
                    C2P<C2StreamVendorUltimateAnswerInfo::input> &me) {
                (void)mayBlock;
                ALOGI("Answer to the Ultimate Question of Life, the Universe, and Everything "
                      "set to %d", me.v.value);
                return C2R::Ok();
            }

            std::shared_ptr<C2ApiFeaturesSetting> mApiFeatures;

            std::shared_ptr<C2ComponentNameSetting> mName;
            std::shared_ptr<C2ComponentAliasesSetting> mAliases;
            std::shared_ptr<C2ComponentKindSetting> mKind;
            std::shared_ptr<C2ComponentDomainSetting> mDomain;

            std::shared_ptr<C2PortMediaTypeSetting::input> mInputMediaType;
            std::shared_ptr<C2PortMediaTypeSetting::output> mOutputMediaType;
            std::shared_ptr<C2StreamBufferTypeSetting::input> mInputFormat;
            std::shared_ptr<C2StreamBufferTypeSetting::output> mOutputFormat;

            std::shared_ptr<C2PortActualDelayTuning::input> mActualInputDelay;
            std::shared_ptr<C2PortActualDelayTuning::output> mActualOutputDelay;
            std::shared_ptr<C2ActualPipelineDelayTuning> mActualPipelineDelay;

            std::shared_ptr<C2PortStreamCountTuning::input> mInputStreamCount;
            std::shared_ptr<C2PortStreamCountTuning::output> mOutputStreamCount;

            std::shared_ptr<C2PortBlockPoolsTuning::output> mOutputPoolIds;

            std::shared_ptr<C2StreamHdrStaticInfo::input> mInputHdrStaticInfo;
            std::shared_ptr<C2StreamHdrStaticInfo::output> mOutputHdrStaticInfo;
            std::shared_ptr<C2StreamColorAspectsInfo::input> mInputColorAspectInfo;
            std::shared_ptr<C2StreamColorAspectsInfo::output> mOutputColorAspectInfo;
            std::shared_ptr<C2StreamColorAspectsRequestInfo::output> mColorAspectRequestInfo;

            std::shared_ptr<C2StreamVendorUltimateAnswerInfo::input> mVendorUltimateAnswerInfo;
        } mHelper;
    };

    SampleToneMappingFilter(c2_node_id_t id, const std::shared_ptr<C2ReflectorHelper> &reflector)
        : mIntf(std::make_shared<Interface>(id, reflector)) {
    }
    ~SampleToneMappingFilter() override {
        if (mProcessingThread.joinable()) {
            mProcessingThread.join();
        }
    }

    c2_status_t setListener_vb(
            const std::shared_ptr<Listener> &listener, c2_blocking_t mayBlock) override {
        std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::now() + 5ms;
        {
            std::unique_lock lock(mStateMutex);
            if (mState == RELEASED) {
                return C2_BAD_STATE;
            }
            if (mState == RUNNING && listener) {
                return C2_BAD_STATE;
            }
            if (mState != STOPPED) {
                return C2_BAD_STATE;
            }
        }
        std::unique_lock lock(mListenerMutex, std::try_to_lock);
        if (lock) {
            mListener = listener;
            return C2_OK;
        }
        if (mayBlock == C2_DONT_BLOCK) {
            return C2_BLOCKING;
        }
        lock.try_lock_until(deadline);
        if (!lock) {
            return C2_TIMED_OUT;
        }
        mListener = listener;
        return C2_OK;
    }

    c2_status_t queue_nb(std::list<std::unique_ptr<C2Work>>* const items) override {
        if (!items) {
            return C2_BAD_VALUE;
        }
        {
            std::unique_lock lock(mStateMutex);
            if (mState != RUNNING) {
                return C2_BAD_STATE;
            }
        }
        std::unique_lock lock(mQueueMutex);
        mQueue.splice(mQueue.end(), *items);
        mQueueCondition.notify_all();
        return C2_OK;
    }

    c2_status_t announce_nb(const std::vector<C2WorkOutline> &) override { return C2_OMITTED; }

    c2_status_t flush_sm(
            flush_mode_t mode,
            std::list<std::unique_ptr<C2Work>>* const flushedWork) override {
        if (!flushedWork) {
            return C2_BAD_VALUE;
        }
        if (mode == FLUSH_CHAIN) {
            return C2_BAD_VALUE;
        }
        {
            std::unique_lock lock(mStateMutex);
            if (mState != RUNNING) {
                return C2_BAD_STATE;
            }
        }
        {
            std::unique_lock lock(mQueueMutex);
            mQueue.swap(*flushedWork);
        }
        // NOTE: this component does not have internal state to flush.
        return C2_OK;
    }

    c2_status_t drain_nb(drain_mode_t mode) override {
        if (mode == DRAIN_CHAIN) {
            return C2_BAD_VALUE;
        }
        {
            std::unique_lock lock(mStateMutex);
            if (mState != RUNNING) {
                return C2_BAD_STATE;
            }
        }
        // NOTE: this component does not wait for work items before processing.
        return C2_OK;
    }

    c2_status_t start() override {
        //std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::now() + 500ms;
        {
            std::unique_lock lock(mStateMutex);
            if (mState == STARTING) {
                return C2_DUPLICATE;
            }
            if (mState != STOPPED) {
                return C2_BAD_STATE;
            }
            mState = STARTING;
        }
        {
            std::unique_lock lock(mProcessingMutex);
            if (!mProcessingThread.joinable()) {
                mProcessingThread = std::thread([this]() {
                    processLoop(shared_from_this());
                });
            }
        }
        {
            std::unique_lock lock(mStateMutex);
            mState = RUNNING;
        }
        return C2_OK;
    }

    c2_status_t stop() override {
        //std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::now() + 500ms;
        {
            std::unique_lock lock(mStateMutex);
            if (mState == STOPPING) {
                return C2_DUPLICATE;
            }
            if (mState != RUNNING) {
                return C2_BAD_STATE;
            }
            mState = STOPPING;
        }
        {
            std::unique_lock lock(mQueueMutex);
            mQueueCondition.notify_all();
        }
        {
            std::unique_lock lock(mProcessingMutex);
            if (mProcessingThread.joinable()) {
                mProcessingThread.join();
            }
        }
        {
            std::unique_lock lock(mStateMutex);
            mState = STOPPED;
        }
        return C2_OK;
    }

    c2_status_t reset() override {
        //std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::now() + 500ms;
        {
            std::unique_lock lock(mStateMutex);
            if (mState == RESETTING) {
                return C2_DUPLICATE;
            }
            if (mState == RELEASED) {
                return C2_BAD_STATE;
            }
            mState = RESETTING;
        }
        {
            std::unique_lock lock(mQueueMutex);
            mQueueCondition.notify_all();
        }
        {
            std::unique_lock lock(mProcessingMutex);
            if (mProcessingThread.joinable()) {
                mProcessingThread.join();
            }
        }
        {
            std::unique_lock lock(mStateMutex);
            mState = STOPPED;
        }
        return C2_OK;
    }

    c2_status_t release() override {
        //std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::now() + 500ms;
        {
            std::unique_lock lock(mStateMutex);
            if (mState == RELEASED || mState == RELEASING) {
                return C2_DUPLICATE;
            }
            // TODO: return C2_BAD_STATE if not stopped
            mState = RELEASING;
        }
        {
            std::unique_lock lock(mQueueMutex);
            mQueueCondition.notify_all();
        }
        {
            std::unique_lock lock(mProcessingMutex);
            if (mProcessingThread.joinable()) {
                mProcessingThread.join();
            }
        }
        {
            std::unique_lock lock(mStateMutex);
            mState = RELEASED;
        }
        return C2_OK;
    }

    std::shared_ptr<C2ComponentInterface> intf() override {
        return mIntf;
    }

private:
    void processLoop(std::shared_ptr<SampleToneMappingFilter> thiz) {
        constexpr float kDefaultMaxLumiance = 500.0;
        constexpr float kDefaultMaxMasteringLuminance = 1000.0;
        constexpr float kDefaultMaxContentLuminance = 1000.0;
        constexpr uint32_t kDstUsage =
                GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN |
                GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_TEXTURE;

        int32_t workCount = 0;
        std::unique_ptr<renderengine::RenderEngine> renderEngine = renderengine::RenderEngine::create(
                renderengine::RenderEngineCreationArgs::Builder()
                    .setPixelFormat(static_cast<int>(ui::PixelFormat::RGBA_8888))
                    .setImageCacheSize(2 /*maxFrameBufferAcquiredBuffers*/)
                    .setUseColorManagerment(true)
                    .setEnableProtectedContext(false)
                    .setPrecacheToneMapperShaderOnly(true)
                    .setContextPriority(renderengine::RenderEngine::ContextPriority::LOW)
                    .build());
        if (!renderEngine) {
            std::unique_lock lock(mListenerMutex);
            mListener->onError_nb(thiz, C2_CORRUPTED);
            return;
        }
        uint32_t textureName = 0;
        renderEngine->genTextures(1, &textureName);

        while (true) {
            // Before doing anything, verify the state
            {
                std::unique_lock lock(mStateMutex);
                if (mState != RUNNING) {
                    break;
                }
            }
            // Extract one work item
            std::unique_ptr<C2Work> work;
            {
                std::unique_lock lock(mQueueMutex);
                if (mQueue.empty()) {
                    mQueueCondition.wait_for(lock, 1s);
                }
                if (mQueue.empty()) {
                    continue;
                }
                mQueue.front().swap(work);
                mQueue.pop_front();
                ++workCount;
            }
            LOG(VERBOSE) << "work #" << workCount << ": flags=" << work->input.flags
                    << " timestamp=" << work->input.ordinal.timestamp.peek();;

            std::vector<C2Param *> configUpdate;
            for (const std::unique_ptr<C2Param> &param : work->input.configUpdate) {
                configUpdate.push_back(param.get());
            }
            std::vector<std::unique_ptr<C2SettingResult>> failures;
            mIntf->config_vb(configUpdate, C2_MAY_BLOCK, &failures);

            std::shared_ptr<C2StreamHdrStaticInfo::input> hdrStaticInfo =
                mIntf->getHdrStaticMetadata();
            uint32_t dataspace = mIntf->getDataSpace();

            std::shared_ptr<C2Buffer> buffer;
            if (!work->input.buffers.empty()) {
                buffer = work->input.buffers.front();
            }
            std::shared_ptr<C2Buffer> outC2Buffer;
            status_t err = OK;
            if (buffer) {
                if (buffer->hasInfo(C2StreamHdrStaticInfo::output::PARAM_TYPE)) {
                    std::shared_ptr<const C2Info> info =
                        buffer->getInfo(C2StreamHdrStaticInfo::output::PARAM_TYPE);
                    std::unique_ptr<C2Param> flipped = C2Param::CopyAsStream(
                            *info, false /* output */, info->stream());
                    hdrStaticInfo.reset(static_cast<C2StreamHdrStaticInfo::input *>(
                            flipped.release()));
                }
                const C2Handle *c2Handle =
                    buffer->data().graphicBlocks().front().handle();
                uint32_t width, height, format, stride, igbp_slot, generation;
                uint64_t usage, igbp_id;
                _UnwrapNativeCodec2GrallocMetadata(
                        c2Handle, &width, &height, &format, &usage, &stride, &generation,
                        &igbp_id, &igbp_slot);
                native_handle_t *grallocHandle = UnwrapNativeCodec2GrallocHandle(c2Handle);
                sp<GraphicBuffer> srcBuffer = new GraphicBuffer(
                        grallocHandle, GraphicBuffer::CLONE_HANDLE,
                        width, height, format, 1, usage, stride);

                native_handle_delete(grallocHandle);
                std::shared_ptr<C2GraphicBlock> dstBlock;
                C2BlockPool::local_id_t poolId = mIntf->getPoolId();
                std::shared_ptr<C2BlockPool> pool;
                GetCodec2BlockPool(poolId, thiz, &pool);
                pool->fetchGraphicBlock(
                        width, height, HAL_PIXEL_FORMAT_RGBA_8888, C2AndroidMemoryUsage::FromGrallocUsage(kDstUsage),
                        &dstBlock);
                outC2Buffer = C2Buffer::CreateGraphicBuffer(
                        dstBlock->share(C2Rect(width, height), C2Fence()));
                c2Handle = dstBlock->handle();
                _UnwrapNativeCodec2GrallocMetadata(
                        c2Handle, &width, &height, &format, &usage, &stride, &generation,
                        &igbp_id, &igbp_slot);
                grallocHandle = UnwrapNativeCodec2GrallocHandle(c2Handle);
                sp<GraphicBuffer> dstBuffer = new GraphicBuffer(
                        grallocHandle, GraphicBuffer::CLONE_HANDLE,
                        width, height, format, 1, usage, stride);

                native_handle_delete(grallocHandle);
                Rect sourceCrop(0, 0, width, height);

                renderengine::DisplaySettings clientCompositionDisplay;
                std::vector<const renderengine::LayerSettings*> clientCompositionLayers;

                clientCompositionDisplay.physicalDisplay = sourceCrop;
                clientCompositionDisplay.clip = sourceCrop;

                clientCompositionDisplay.outputDataspace = ui::Dataspace::V0_SRGB;
                clientCompositionDisplay.maxLuminance = kDefaultMaxLumiance;
                clientCompositionDisplay.clearRegion = Region::INVALID_REGION;
                renderengine::LayerSettings layerSettings;
                layerSettings.geometry.boundaries = sourceCrop.toFloatRect();
                layerSettings.alpha = 1.0f;

                layerSettings.sourceDataspace = static_cast<ui::Dataspace>(dataspace);

                // from BufferLayer
                layerSettings.source.buffer.buffer = srcBuffer;
                layerSettings.source.buffer.isOpaque = true;
                // TODO: fence
                layerSettings.source.buffer.fence = Fence::NO_FENCE;
                layerSettings.source.buffer.textureName = textureName;
                layerSettings.source.buffer.usePremultipliedAlpha = false;
                layerSettings.source.buffer.maxMasteringLuminance =
                    (hdrStaticInfo && *hdrStaticInfo &&
                     hdrStaticInfo->mastering.maxLuminance > 0 &&
                     hdrStaticInfo->mastering.minLuminance > 0)
                        ? hdrStaticInfo->mastering.maxLuminance : kDefaultMaxMasteringLuminance;
                layerSettings.source.buffer.maxContentLuminance =
                    (hdrStaticInfo && *hdrStaticInfo && hdrStaticInfo->maxCll > 0)
                        ? hdrStaticInfo->maxCll : kDefaultMaxContentLuminance;

                // Set filtering to false since the capture itself doesn't involve
                // any scaling, metadata retriever JNI is scaling the bitmap if
                // display size is different from decoded size. If that scaling
                // needs to be handled by server side, consider enable this based
                // display size vs decoded size.
                layerSettings.source.buffer.useTextureFiltering = false;
                layerSettings.source.buffer.textureTransform = mat4();
                clientCompositionLayers.push_back(&layerSettings);

                // Use an empty fence for the buffer fence, since we just created the buffer so
                // there is no need for synchronization with the GPU.
                base::unique_fd bufferFence;
                base::unique_fd drawFence;
                renderEngine->useProtectedContext(false);
                err = renderEngine->drawLayers(
                        clientCompositionDisplay, clientCompositionLayers, dstBuffer.get(),
                        /*useFramebufferCache=*/false, std::move(bufferFence), &drawFence);

                sp<Fence> fence = new Fence(std::move(drawFence));

                // We can move waiting for fence & sending it back on a separate thread to improve
                // efficiency, but leaving it here for simplicity.
                if (err != OK) {
                    LOG(ERROR) << "drawLayers returned err " << err;
                } else {
                    err = fence->wait(500);
                    if (err != OK) {
                        LOG(WARNING) << "wait for fence returned err " << err;
                    }
                }
                renderEngine->cleanupPostRender(renderengine::RenderEngine::CleanupMode::CLEAN_ALL);
            }

            work->worklets.front()->output.ordinal = work->input.ordinal;
            work->worklets.front()->output.flags = work->input.flags;
            if (err == OK) {
                work->workletsProcessed = 1;
                if (outC2Buffer) {
                    work->worklets.front()->output.buffers.push_back(outC2Buffer);
                }
                work->result = C2_OK;
            } else {
                work->result = C2_CORRUPTED;
            }
            std::list<std::unique_ptr<C2Work>> items;
            items.push_back(std::move(work));

            std::unique_lock lock(mListenerMutex);
            mListener->onWorkDone_nb(thiz, std::move(items));
            LOG(VERBOSE) << "sent work #" << workCount;
        }
    }

    mutable std::timed_mutex mListenerMutex;
    std::shared_ptr<Listener> mListener;

    mutable std::mutex mQueueMutex;
    mutable std::condition_variable mQueueCondition;
    std::list<std::unique_ptr<C2Work>> mQueue;

    const std::shared_ptr<Interface> mIntf;

    mutable std::mutex mStateMutex;
    enum State {
        STOPPED,
        RUNNING,
        RELEASED,
        STARTING,   // STOPPED -> RUNNING
        STOPPING,   // RUNNING -> STOPPED
        RESETTING,  // <<ANY>> -> STOPPED
        RELEASING,  // STOPPED -> RELEASED
    } mState;

    mutable std::mutex mProcessingMutex;
    std::thread mProcessingThread;

};

// static
const std::string SampleToneMappingFilter::Interface::NAME = "c2.sample.tone-mapper";
// static
const FilterPlugin_V1::Descriptor SampleToneMappingFilter::Interface::DESCRIPTOR = {
    // controlParams
    {
        C2StreamColorAspectsRequestInfo::output::PARAM_TYPE,
        C2StreamVendorUltimateAnswerInfo::input::PARAM_TYPE,
    },
    // affectedParams
    {
        C2StreamHdrStaticInfo::output::PARAM_TYPE,
        C2StreamColorAspectsInfo::output::PARAM_TYPE,
    },
};

class SampleC2ComponentStore : public C2ComponentStore {
public:
    SampleC2ComponentStore()
        : mReflector(std::make_shared<C2ReflectorHelper>()),
          mIntf(mReflector),
          mFactories(CreateFactories(mReflector)) {
    }
    ~SampleC2ComponentStore() = default;

    C2String getName() const override { return "android.sample.filter-plugin-store"; }
    c2_status_t createComponent(
            C2String name, std::shared_ptr<C2Component>* const component) override {
        if (mFactories.count(name) == 0) {
            return C2_BAD_VALUE;
        }
        return mFactories.at(name)->createComponent(++mNodeId, component);
    }
    c2_status_t createInterface(
            C2String name, std::shared_ptr<C2ComponentInterface>* const interface) override {
        if (mFactories.count(name) == 0) {
            return C2_BAD_VALUE;
        }
        return mFactories.at(name)->createInterface(++mNodeId, interface);
    }
    std::vector<std::shared_ptr<const C2Component::Traits>> listComponents() override {
        std::vector<std::shared_ptr<const C2Component::Traits>> ret;
        for (const auto &[name, factory] : mFactories) {
            ret.push_back(factory->getTraits());
        }
        return ret;
    }
    c2_status_t copyBuffer(
            std::shared_ptr<C2GraphicBuffer>, std::shared_ptr<C2GraphicBuffer>) override {
        return C2_OMITTED;
    }
    c2_status_t query_sm(
            const std::vector<C2Param*> &stackParams,
            const std::vector<C2Param::Index> &heapParamIndices,
            std::vector<std::unique_ptr<C2Param>>* const heapParams) const override {
        return mIntf.query(stackParams, heapParamIndices, C2_MAY_BLOCK, heapParams);
    }
    c2_status_t config_sm(
            const std::vector<C2Param*> &params,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures) override {
        return mIntf.config(params, C2_MAY_BLOCK, failures);
    }
    std::shared_ptr<C2ParamReflector> getParamReflector() const override {
        return mReflector;
    }
    c2_status_t querySupportedParams_nb(
            std::vector<std::shared_ptr<C2ParamDescriptor>> * const params) const override {
        return mIntf.querySupportedParams(params);
    }
    c2_status_t querySupportedValues_sm(
            std::vector<C2FieldSupportedValuesQuery> &fields) const override {
        return mIntf.querySupportedValues(fields, C2_MAY_BLOCK);
    }

private:
    class ComponentFactory {
    public:
        virtual ~ComponentFactory() = default;

        const std::shared_ptr<const C2Component::Traits> &getTraits() { return mTraits; }

        virtual c2_status_t createComponent(
                c2_node_id_t id,
                std::shared_ptr<C2Component>* const component) const = 0;
        virtual c2_status_t createInterface(
                c2_node_id_t id,
                std::shared_ptr<C2ComponentInterface>* const interface) const = 0;
    protected:
        ComponentFactory(const std::shared_ptr<const C2Component::Traits> &traits)
            : mTraits(traits) {
        }
    private:
        const std::shared_ptr<const C2Component::Traits> mTraits;
    };

    template <class T>
    struct ComponentFactoryImpl : public ComponentFactory {
    public:
        ComponentFactoryImpl(
                const std::shared_ptr<const C2Component::Traits> &traits,
                const std::shared_ptr<C2ReflectorHelper> &reflector)
            : ComponentFactory(traits),
              mReflector(reflector) {
        }
        ~ComponentFactoryImpl() override = default;
        c2_status_t createComponent(
                c2_node_id_t id,
                std::shared_ptr<C2Component>* const component) const override {
            *component = std::make_shared<T>(id, mReflector);
            return C2_OK;
        }
        c2_status_t createInterface(
                c2_node_id_t id,
                std::shared_ptr<C2ComponentInterface>* const interface) const override {
            *interface = std::make_shared<typename T::Interface>(id, mReflector);
            return C2_OK;
        }
    private:
        std::shared_ptr<C2ReflectorHelper> mReflector;
    };

    template <class T>
    static void AddFactory(
            std::map<C2String, std::unique_ptr<ComponentFactory>> *factories,
            const std::shared_ptr<C2ReflectorHelper> &reflector) {
        std::shared_ptr<C2ComponentInterface> intf{new typename T::Interface(0, reflector)};
        std::shared_ptr<C2Component::Traits> traits(new (std::nothrow) C2Component::Traits);
        CHECK(C2InterfaceUtils::FillTraitsFromInterface(traits.get(), intf))
                << "Failed to fill traits from interface";
        factories->emplace(
                traits->name,
                new ComponentFactoryImpl<T>(traits, reflector));
    }

    static std::map<C2String, std::unique_ptr<ComponentFactory>> CreateFactories(
            const std::shared_ptr<C2ReflectorHelper> &reflector) {
        std::map<C2String, std::unique_ptr<ComponentFactory>> factories;
        AddFactory<SampleToneMappingFilter>(&factories, reflector);
        return factories;
    }


    std::shared_ptr<C2ReflectorHelper> mReflector;
    struct Interface : public C2InterfaceHelper {
        explicit Interface(std::shared_ptr<C2ReflectorHelper> reflector)
            : C2InterfaceHelper(reflector) {
        }
    } mIntf;

    const std::map<C2String, std::unique_ptr<ComponentFactory>> mFactories;

    std::atomic_int32_t mNodeId{0};
};

class SampleFilterPlugin : public FilterPlugin_V1 {
public:
    SampleFilterPlugin() : mStore(new SampleC2ComponentStore) {}
    ~SampleFilterPlugin() override = default;

    std::shared_ptr<C2ComponentStore> getComponentStore() override {
        return mStore;
    }

    bool describe(C2String name, Descriptor *desc) override {
        if (name == SampleToneMappingFilter::Interface::NAME) {
            *desc = SampleToneMappingFilter::Interface::DESCRIPTOR;
            return true;
        }
        return false;
    }

    bool isFilteringEnabled(const std::shared_ptr<C2ComponentInterface> &intf) override {
        if (intf->getName() == SampleToneMappingFilter::Interface::NAME) {
            return SampleToneMappingFilter::Interface::IsFilteringEnabled(intf);
        }
        return false;
    }

    c2_status_t queryParamsForPreviousComponent(
            const std::shared_ptr<C2ComponentInterface> &intf,
            std::vector<std::unique_ptr<C2Param>> *params) override {
        if (intf->getName() == SampleToneMappingFilter::Interface::NAME) {
            return SampleToneMappingFilter::Interface::QueryParamsForPreviousComponent(
                    intf, params);
        }
        return C2_BAD_VALUE;
    }

private:
    std::shared_ptr<C2ComponentStore> mStore;
};

}  // namespace android

extern "C" {

int32_t GetFilterPluginVersion() {
    return ::android::SampleFilterPlugin::VERSION;
}

void *CreateFilterPlugin() {
    return new ::android::SampleFilterPlugin;
}

void DestroyFilterPlugin(void *plugin) {
    delete (::android::SampleFilterPlugin *)plugin;
}

}  // extern "C"
