/*
 * Copyright 2016 The Android Open Source Project
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

#define LOG_NDEBUG 0
#define LOG_TAG "C2SoftAvcDec"
#include <utils/Log.h>

#include <cmath>
#include <thread>

#include "ih264_typedefs.h"
#include "iv.h"
#include "ivd.h"
#include "ih264d.h"
#include "C2SoftAvcDec.h"

#include <C2PlatformSupport.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/MediaDefs.h>
#include <utils/misc.h>

#include "ih264d_defs.h"

namespace {

template <class T>
inline int32_t floor32(T arg) {
   return (int32_t) std::llround(std::floor(arg));
}

} // namespace

namespace android {

struct iv_obj_t : public ::iv_obj_t {};
struct ivd_video_decode_ip_t : public ::ivd_video_decode_ip_t {};
struct ivd_video_decode_op_t : public ::ivd_video_decode_op_t {};

#define PRINT_TIME  ALOGV

#define componentName                   "video_decoder.avc"
// #define codingType                      OMX_VIDEO_CodingAVC
#define CODEC_MIME_TYPE                 MEDIA_MIMETYPE_VIDEO_AVC

/** Function and structure definitions to keep code similar for each codec */
#define ivdec_api_function              ih264d_api_function
#define ivdext_create_ip_t              ih264d_create_ip_t
#define ivdext_create_op_t              ih264d_create_op_t
#define ivdext_delete_ip_t              ih264d_delete_ip_t
#define ivdext_delete_op_t              ih264d_delete_op_t
#define ivdext_ctl_set_num_cores_ip_t   ih264d_ctl_set_num_cores_ip_t
#define ivdext_ctl_set_num_cores_op_t   ih264d_ctl_set_num_cores_op_t

#define IVDEXT_CMD_CTL_SET_NUM_CORES    \
        (IVD_CONTROL_API_COMMAND_TYPE_T)IH264D_CMD_CTL_SET_NUM_CORES

namespace {

using SupportedValuesWithFields = C2SoftAvcDecIntf::SupportedValuesWithFields;

uint32_t restoreIndex(const C2Param *param) {
    return (param->forStream() ? (0x02000000 | ((param->stream() << 17) & 0x01FE0000)) : 0)
            | param->type();
}

struct ValidateParam {
    explicit ValidateParam(
            const std::map<C2ParamField, SupportedValuesWithFields> &supportedValues)
        : mSupportedValues(supportedValues) {}

    template <class T, bool SIGNED = std::is_signed<T>::value, size_t SIZE = sizeof(T)>
    struct Getter {
        static T get(const C2Value::Primitive &) {
            static_assert(!std::is_arithmetic<T>::value, "non-arithmetic type");
            static_assert(!std::is_floating_point<T>::value || std::is_same<T, float>::value,
                    "float is the only supported floating point type");
            static_assert(sizeof(T) <= 8, "type exceeds 64-bit");
        }
    };

    template <class T>
    bool validateField(
            const C2FieldSupportedValues &supportedValues, const T &value) {
        switch (supportedValues.type) {
        case C2FieldSupportedValues::EMPTY:
            {
                return false;
            }
        case C2FieldSupportedValues::RANGE:
            {
                // TODO: handle step, nom, denom
                return Getter<T>::get(supportedValues.range.min) <= value
                        && value <= Getter<T>::get(supportedValues.range.max);
            }
        case C2FieldSupportedValues::VALUES:
            {
                for (const auto &val : supportedValues.values) {
                    if (Getter<T>::get(val) == value) {
                        return true;
                    }
                }
                return false;
            }
        case C2FieldSupportedValues::FLAGS:
            // TODO
            return false;
        }
        return false;
    }

protected:
    const std::map<C2ParamField, SupportedValuesWithFields> &mSupportedValues;
};

template <>
struct ValidateParam::Getter<float> {
    static float get(const C2Value::Primitive &value) { return value.fp; }
};
template <class T>
struct ValidateParam::Getter<T, true, 8u> {
    static int64_t get(const C2Value::Primitive &value) { return value.i64; }
};
template <class T>
struct ValidateParam::Getter<T, true, 4u> {
    static int32_t get(const C2Value::Primitive &value) { return value.i32; }
};
template <class T>
struct ValidateParam::Getter<T, false, 8u> {
    static uint64_t get(const C2Value::Primitive &value) { return value.u64; }
};
template <class T>
struct ValidateParam::Getter<T, false, 4u> {
    static uint32_t get(const C2Value::Primitive &value) { return value.u32; }
};

template <class T>
struct ValidateSimpleParam : public ValidateParam {
    explicit ValidateSimpleParam(
            const std::map<C2ParamField, SupportedValuesWithFields> &supportedValues)
        : ValidateParam(supportedValues) {}

    std::unique_ptr<C2SettingResult> operator() (C2Param *c2param) {
        T* param = (T*)c2param;
        C2ParamField field(param, &T::mValue);
        const C2FieldSupportedValues &supportedValues = mSupportedValues.at(field).supported;
        if (!validateField(supportedValues, param->mValue)) {
            return std::unique_ptr<C2SettingResult>(
                    new C2SettingResult {C2SettingResult::BAD_VALUE, {field, nullptr}, {}});
        }
        return nullptr;
    }
};

template <class T>
struct ValidateVideoSize : public ValidateParam {
    explicit ValidateVideoSize(
            const std::map<C2ParamField, SupportedValuesWithFields> &supportedValues)
        : ValidateParam(supportedValues) {}

    std::unique_ptr<C2SettingResult> operator() (C2Param *c2param) {
        T* param = (T*)c2param;
        C2ParamField field(param, &T::mWidth);
        const C2FieldSupportedValues &supportedWidth = mSupportedValues.at(field).supported;
        if (!validateField(supportedWidth, param->mWidth)) {
            return std::unique_ptr<C2SettingResult>(
                    new C2SettingResult {C2SettingResult::BAD_VALUE, {field, nullptr}, {}});
        }
        field = C2ParamField(param, &T::mHeight);
        const C2FieldSupportedValues &supportedHeight = mSupportedValues.at(field).supported;
        if (!validateField(supportedHeight, param->mHeight)) {
            return std::unique_ptr<C2SettingResult>(
                    new C2SettingResult {C2SettingResult::BAD_VALUE, {field, nullptr}, {}});
        }
        return nullptr;
    }
};

template <class T>
struct ValidateCString {
    explicit ValidateCString(const char *expected) : mExpected(expected) {}

    std::unique_ptr<C2SettingResult> operator() (C2Param *c2param) {
        T* param = (T*)c2param;
        if (strncmp(param->m.mValue, mExpected, param->flexCount()) != 0) {
            return std::unique_ptr<C2SettingResult>(
                    new C2SettingResult {C2SettingResult::BAD_VALUE, {C2ParamField(param, &T::m), nullptr}, {}});
        }
        return nullptr;
    }

private:
    const char *mExpected;
};

class GraphicBuffer : public C2Buffer {
public:
    explicit GraphicBuffer(const std::shared_ptr<C2GraphicBlock> &block)
        : C2Buffer({ block->share(C2Rect(block->width(), block->height()), ::android::C2Fence()) }) {}
};

}  // namespace

#define CASE(member) \
    case decltype(component->member)::coreIndex: \
        return std::unique_ptr<C2StructDescriptor>(new C2StructDescriptor( \
                static_cast<decltype(component->member) *>(nullptr)))

class C2SoftAvcDecIntf::ParamReflector : public C2ParamReflector {
public:
    virtual std::unique_ptr<C2StructDescriptor> describe(C2Param::BaseIndex coreIndex) override {
        constexpr C2SoftAvcDecIntf *component = nullptr;
        switch (coreIndex.coreIndex()) {
        CASE(mDomainInfo);
        CASE(mInputStreamCount);
        CASE(mInputStreamFormat);
        // Output counterparts for the above would be redundant.
        CASE(mVideoSize);
        CASE(mMaxVideoSizeHint);

        // port mime configs are stored as unique_ptr.
        case C2PortMimeConfig::coreIndex:
            return std::unique_ptr<C2StructDescriptor>(new C2StructDescriptor(
                    static_cast<C2PortMimeConfig *>(nullptr)));
        }
        return nullptr;
    }
};
#undef CASE

// static const CodecProfileLevel kProfileLevels[] = {
//     { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel52 },
//     { OMX_VIDEO_AVCProfileMain,     OMX_VIDEO_AVCLevel52 },
//     { OMX_VIDEO_AVCProfileHigh,     OMX_VIDEO_AVCLevel52 },
// };
C2SoftAvcDecIntf::C2SoftAvcDecIntf(const char *name, c2_node_id_t id)
    : mName(name),
      mId(id),
      mDomainInfo(C2DomainVideo),
      mInputStreamCount(1u),
      mOutputStreamCount(1u),
      mInputStreamFormat(0u, C2FormatCompressed),
      mOutputStreamFormat(0u, C2FormatVideo),
      mProfile(0u, kAvcProfileUnknown),
      mLevel(0u, kAvcLevelUnknown),
      mBlockSize(0u),
      mAlignment(0u),
      mFrameRate(0u, 0),
      mBlocksPerSecond(0u, 0),
      mParamReflector(new ParamReflector) {
    ALOGV("in %s", __func__);
    mInputPortMime = C2PortMimeConfig::input::alloc_unique(strlen(CODEC_MIME_TYPE) + 1);
    strcpy(mInputPortMime->m.mValue, CODEC_MIME_TYPE);
    mOutputPortMime = C2PortMimeConfig::output::alloc_unique(strlen(MEDIA_MIMETYPE_VIDEO_RAW) + 1);
    strcpy(mOutputPortMime->m.mValue, MEDIA_MIMETYPE_VIDEO_RAW);

    mVideoSize.mWidth = 320;
    mVideoSize.mHeight = 240;
    mBlockSize.mWidth = 16;
    mBlockSize.mHeight = 16;
    mAlignment.mWidth = 2;
    mAlignment.mHeight = 2;

    mMaxVideoSizeHint.mWidth = H264_MAX_FRAME_WIDTH;
    mMaxVideoSizeHint.mHeight = H264_MAX_FRAME_HEIGHT;

    mOutputBlockPools = C2PortBlockPoolsTuning::output::alloc_unique({});

    auto insertParam = [&params = mParams] (C2Param *param) {
        params[restoreIndex(param)] = param;
    };

    auto markReadOnly = [&supported = mSupportedValues] (auto *param) {
        supported.emplace(
                C2ParamField(param, &std::remove_pointer<decltype(param)>::type::mValue),
                C2FieldSupportedValues(false /* flags */, {}));
    };

    auto markReadOnlyVideoSize = [&supported = mSupportedValues] (auto *param) {
        supported.emplace(
                C2ParamField(param, &std::remove_pointer<decltype(param)>::type::mWidth),
                C2FieldSupportedValues(false /* flags */, {}));
        supported.emplace(
                C2ParamField(param, &std::remove_pointer<decltype(param)>::type::mHeight),
                C2FieldSupportedValues(false /* flags */, {}));
    };

    insertParam(&mDomainInfo);
    markReadOnly(&mDomainInfo);
    mFieldVerifiers[restoreIndex(&mDomainInfo)] =
            ValidateSimpleParam<decltype(mDomainInfo)>(mSupportedValues);

    insertParam(mInputPortMime.get());
    mFieldVerifiers[restoreIndex(mInputPortMime.get())] =
            ValidateCString<std::remove_reference<decltype(*mInputPortMime)>::type>(CODEC_MIME_TYPE);

    insertParam(&mInputStreamCount);
    markReadOnly(&mInputStreamCount);
    mFieldVerifiers[restoreIndex(&mInputStreamCount)] =
            ValidateSimpleParam<decltype(mInputStreamCount)>(mSupportedValues);

    insertParam(mOutputPortMime.get());
    mFieldVerifiers[restoreIndex(mOutputPortMime.get())] =
            ValidateCString<std::remove_reference<decltype(*mOutputPortMime)>::type>(MEDIA_MIMETYPE_VIDEO_RAW);

    insertParam(&mOutputStreamCount);
    markReadOnly(&mOutputStreamCount);
    mFieldVerifiers[restoreIndex(&mOutputStreamCount)] =
            ValidateSimpleParam<decltype(mOutputStreamCount)>(mSupportedValues);

    insertParam(&mInputStreamFormat);
    markReadOnly(&mInputStreamFormat);
    mFieldVerifiers[restoreIndex(&mInputStreamFormat)] =
            ValidateSimpleParam<decltype(mInputStreamFormat)>(mSupportedValues);

    insertParam(&mOutputStreamFormat);
    markReadOnly(&mOutputStreamFormat);
    mFieldVerifiers[restoreIndex(&mOutputStreamFormat)] =
            ValidateSimpleParam<decltype(mOutputStreamFormat)>(mSupportedValues);

    insertParam(&mVideoSize);
    markReadOnlyVideoSize(&mVideoSize);
    mFieldVerifiers[restoreIndex(&mVideoSize)] =
            ValidateVideoSize<decltype(mVideoSize)>(mSupportedValues);

    insertParam(&mMaxVideoSizeHint);
    mSupportedValues.emplace(
            C2ParamField(&mMaxVideoSizeHint, &C2MaxVideoSizeHintPortSetting::mWidth),
            C2FieldSupportedValues(H264_MIN_FRAME_WIDTH, H264_MAX_FRAME_WIDTH, mAlignment.mWidth));
    mSupportedValues.emplace(
            C2ParamField(&mMaxVideoSizeHint, &C2MaxVideoSizeHintPortSetting::mHeight),
            C2FieldSupportedValues(H264_MIN_FRAME_HEIGHT, H264_MAX_FRAME_HEIGHT, mAlignment.mHeight));
    mFieldVerifiers[restoreIndex(&mMaxVideoSizeHint)] =
            ValidateVideoSize<decltype(mMaxVideoSizeHint)>(mSupportedValues);

    insertParam(&mProfile);
    mSupportedValues.emplace(
            C2ParamField(&mProfile, &C2AvcProfileInfo::mValue),
            C2FieldSupportedValues(false /* flags */, {
                kAvcProfileUnknown,
                kAvcProfileBaseline,
                kAvcProfileMain,
                kAvcProfileHigh,
            }));
    mFieldVerifiers[restoreIndex(&mProfile)] =
            ValidateSimpleParam<decltype(mProfile)>(mSupportedValues);

    insertParam(&mLevel);
    mSupportedValues.emplace(
            C2ParamField(&mLevel, &C2AvcLevelInfo::mValue),
            C2FieldSupportedValues(false /* flags */, {
                kAvcLevelUnknown,
                kAvcLevel10,
                kAvcLevel1b,
                kAvcLevel11,
                kAvcLevel12,
                kAvcLevel13,
                kAvcLevel20,
                kAvcLevel21,
                kAvcLevel22,
                kAvcLevel30,
                kAvcLevel31,
                kAvcLevel32,
                kAvcLevel40,
                kAvcLevel41,
                kAvcLevel42,
                kAvcLevel50,
                kAvcLevel51,
                kAvcLevel52,
            }));
    mFieldVerifiers[restoreIndex(&mLevel)] =
            ValidateSimpleParam<decltype(mLevel)>(mSupportedValues);

    insertParam(&mBlockSize);
    markReadOnlyVideoSize(&mBlockSize);
    mFieldVerifiers[restoreIndex(&mBlockSize)] =
            ValidateVideoSize<decltype(mBlockSize)>(mSupportedValues);

    insertParam(&mAlignment);
    markReadOnlyVideoSize(&mAlignment);
    mFieldVerifiers[restoreIndex(&mAlignment)] =
            ValidateVideoSize<decltype(mAlignment)>(mSupportedValues);

    insertParam(&mFrameRate);
    mSupportedValues.emplace(
            C2ParamField(&mFrameRate, &C2FrameRateInfo::mValue),
            C2FieldSupportedValues(0, 240));
    mFieldVerifiers[restoreIndex(&mFrameRate)] =
            ValidateSimpleParam<decltype(mFrameRate)>(mSupportedValues);

    insertParam(&mBlocksPerSecond);
    mSupportedValues.emplace(
            C2ParamField(&mFrameRate, &C2BlocksPerSecondInfo::mValue),
            C2FieldSupportedValues(0, 244800));
    mFieldVerifiers[restoreIndex(&mBlocksPerSecond)] =
            ValidateSimpleParam<decltype(mBlocksPerSecond)>(mSupportedValues);

    mParamDescs.push_back(std::make_shared<C2ParamDescriptor>(
            true, "_domain", &mDomainInfo));
    mParamDescs.push_back(std::make_shared<C2ParamDescriptor>(
            true, "_input_port_mime", mInputPortMime.get()));
    mParamDescs.push_back(std::make_shared<C2ParamDescriptor>(
            true, "_input_stream_count", &mInputStreamCount));
    mParamDescs.push_back(std::make_shared<C2ParamDescriptor>(
            true, "_output_port_mime", mOutputPortMime.get()));
    mParamDescs.push_back(std::make_shared<C2ParamDescriptor>(
            true, "_output_stream_count", &mOutputStreamCount));
    mParamDescs.push_back(std::make_shared<C2ParamDescriptor>(
            true, "_input_stream_format", &mInputStreamFormat));
    mParamDescs.push_back(std::make_shared<C2ParamDescriptor>(
            true, "_output_stream_format", &mOutputStreamFormat));
    mParamDescs.push_back(std::make_shared<C2ParamDescriptor>(
            false, "_video_size", &mVideoSize));
    mParamDescs.push_back(std::make_shared<C2ParamDescriptor>(
            false, "_max_video_size_hint", &mMaxVideoSizeHint));
    mParamDescs.push_back(std::make_shared<C2ParamDescriptor>(
            false, "_output_block_pools", mOutputBlockPools.get()));
}

C2SoftAvcDecIntf::~C2SoftAvcDecIntf() {
    ALOGV("in %s", __func__);
}

C2String C2SoftAvcDecIntf::getName() const {
    return mName;
}

c2_node_id_t C2SoftAvcDecIntf::getId() const {
    return mId;
}

c2_status_t C2SoftAvcDecIntf::query_nb(
        const std::vector<C2Param* const> & stackParams,
        const std::vector<C2Param::Index> & heapParamIndices,
        std::vector<std::unique_ptr<C2Param>>* const heapParams) const {
    for (C2Param* const param : stackParams) {
        if (!*param) {
            continue;
        }

        uint32_t index = restoreIndex(param);
        if (!mParams.count(index)) {
            // TODO: add support for output-block-pools (this will be done when we move all
            // config to shared ptr)
            continue;
        }

        C2Param *myParam = mParams.find(index)->second;
        if (myParam->size() != param->size()) {
            param->invalidate();
            continue;
        }

        param->updateFrom(*myParam);
    }

    for (const C2Param::Index index : heapParamIndices) {
        if (mParams.count(index)) {
            C2Param *myParam = mParams.find(index)->second;
            heapParams->emplace_back(C2Param::Copy(*myParam));
        }
    }

    return C2_OK;
}

c2_status_t C2SoftAvcDecIntf::config_nb(
        const std::vector<C2Param* const> &params,
        std::vector<std::unique_ptr<C2SettingResult>>* const failures) {
    c2_status_t err = C2_OK;
    for (C2Param *param : params) {
        uint32_t index = restoreIndex(param);
        if (param->index() == mOutputBlockPools.get()->index()) {
            // setting output block pools
            mOutputBlockPools.reset(
                    (C2PortBlockPoolsTuning::output *)C2Param::Copy(*param).release());
            continue;
        }

        if (mParams.count(index) == 0) {
            // We can't create C2SettingResult with no field, so just skipping in this case.
            err = C2_BAD_INDEX;
            continue;
        }
        C2Param *myParam = mParams.find(index)->second;
        std::unique_ptr<C2SettingResult> result;
        if (!(result = mFieldVerifiers[index](param))) {
            myParam->updateFrom(*param);
            updateSupportedValues();
        } else {
            failures->push_back(std::move(result));
            err = C2_BAD_VALUE;
        }
    }
    return err;
}

c2_status_t C2SoftAvcDecIntf::commit_sm(
        const std::vector<C2Param* const> &params,
        std::vector<std::unique_ptr<C2SettingResult>>* const failures) {
    // TODO
    return config_nb(params, failures);
}

c2_status_t C2SoftAvcDecIntf::createTunnel_sm(c2_node_id_t targetComponent) {
    // Tunneling is not supported
    (void) targetComponent;
    return C2_OMITTED;
}

c2_status_t C2SoftAvcDecIntf::releaseTunnel_sm(c2_node_id_t targetComponent) {
    // Tunneling is not supported
    (void) targetComponent;
    return C2_OMITTED;
}

std::shared_ptr<C2ParamReflector> C2SoftAvcDecIntf::getParamReflector() const {
    return mParamReflector;
}

c2_status_t C2SoftAvcDecIntf::querySupportedParams_nb(
        std::vector<std::shared_ptr<C2ParamDescriptor>> * const params) const {
    params->insert(params->begin(), mParamDescs.begin(), mParamDescs.end());
    return C2_OK;
}

c2_status_t C2SoftAvcDecIntf::querySupportedValues_nb(
        std::vector<C2FieldSupportedValuesQuery> &fields) const {
    c2_status_t res = C2_OK;
    for (C2FieldSupportedValuesQuery &query : fields) {
        if (mSupportedValues.count(query.field) == 0) {
            query.status = C2_BAD_INDEX;
            res = C2_BAD_INDEX;
        } else {
            query.status = C2_OK;
            query.values = mSupportedValues.at(query.field).supported;
        }
    }
    return res;
}

void C2SoftAvcDecIntf::updateSupportedValues() {
    int32_t maxWidth = H264_MAX_FRAME_WIDTH;
    int32_t maxHeight = H264_MAX_FRAME_HEIGHT;
    // cf: Rec. ITU-T H.264 A.3
    int maxFrameRate = 172;
    std::vector<C2ParamField> fields;
    if (mLevel.mValue != kAvcLevelUnknown) {
        // cf: Rec. ITU-T H.264 Table A-1
        constexpr int MaxFS[] = {
        //  0       1       2       3       4       5       6       7       8       9
            0,      0,      0,      0,      0,      0,      0,      0,      0,      99,
            99,     396,    396,    396,    0,      0,      0,      0,      0,      0,
            396,    792,    1620,   0,      0,      0,      0,      0,      0,      0,
            1620,   3600,   5120,   0,      0,      0,      0,      0,      0,      0,
            8192,   8192,   8704,   0,      0,      0,      0,      0,      0,      0,
            22080,  36864,  36864,
        };
        constexpr int MaxMBPS[] = {
        //  0       1       2       3       4       5       6       7       8       9
            0,      0,      0,      0,      0,      0,      0,      0,      0,      1485,
            1485,   3000,   6000,   11880,  0,      0,      0,      0,      0,      0,
            11880,  19800,  20250,  0,      0,      0,      0,      0,      0,      0,
            40500,  108000, 216000, 0,      0,      0,      0,      0,      0,      0,
            245760, 245760, 522240, 0,      0,      0,      0,      0,      0,      0,
            589824, 983040, 2073600,
        };

        // cf: Rec. ITU-T H.264 A.3.1
        maxWidth = std::min(maxWidth, floor32(std::sqrt(MaxFS[mLevel.mValue] * 8)) * MB_SIZE);
        maxHeight = std::min(maxHeight, floor32(std::sqrt(MaxFS[mLevel.mValue] * 8)) * MB_SIZE);
        int32_t MBs = ((mVideoSize.mWidth + 15) / 16) * ((mVideoSize.mHeight + 15) / 16);
        maxFrameRate = std::min(maxFrameRate, MaxMBPS[mLevel.mValue] / MBs);
        fields.push_back(C2ParamField(&mLevel, &C2AvcLevelInfo::mValue));
    }

    SupportedValuesWithFields &maxWidthVals = mSupportedValues.at(
            C2ParamField(&mMaxVideoSizeHint, &C2MaxVideoSizeHintPortSetting::mWidth));
    maxWidthVals.supported.range.max = maxWidth;
    maxWidthVals.restrictingFields.clear();
    maxWidthVals.restrictingFields.insert(fields.begin(), fields.end());

    SupportedValuesWithFields &maxHeightVals = mSupportedValues.at(
            C2ParamField(&mMaxVideoSizeHint, &C2MaxVideoSizeHintPortSetting::mHeight));
    maxHeightVals.supported.range.max = maxHeight;
    maxHeightVals.restrictingFields.clear();
    maxHeightVals.restrictingFields.insert(fields.begin(), fields.end());

    SupportedValuesWithFields &frameRate = mSupportedValues.at(
            C2ParamField(&mFrameRate, &C2FrameRateInfo::mValue));
    frameRate.supported.range.max = maxFrameRate;
    frameRate.restrictingFields.clear();
    frameRate.restrictingFields.insert(fields.begin(), fields.end());
}

///////////////////////////////////////////////////////////////////////////////

class C2SoftAvcDec::QueueProcessThread {
public:
    QueueProcessThread() : mExitRequested(false), mRunning(false) {}

    ~QueueProcessThread() {
        if (mThread && mThread->joinable()) {
            mExitRequested = true;
            mThread->join();
        }
    }

    void start(std::weak_ptr<C2SoftAvcDec> component) {
        mThread.reset(new std::thread([this, component] () {
            mRunning = true;
            while (auto comp = component.lock()) {
                if (mExitRequested) break;
                comp->processQueue();
            }
            mRunning = false;
        }));
    }

    void requestExit() {
        mExitRequested = true;
    }

    bool isRunning() {
        return mRunning;
    }

private:
    std::atomic_bool mExitRequested;
    std::atomic_bool mRunning;
    std::unique_ptr<std::thread> mThread;
};

C2SoftAvcDec::C2SoftAvcDec(
        const char *name,
        c2_node_id_t id)
    : mIntf(std::make_shared<C2SoftAvcDecIntf>(name, id)),
      mThread(new QueueProcessThread),
      mCodecCtx(NULL),
      mFlushOutBuffer(NULL),
      mIvColorFormat(IV_YUV_420P),
      mChangingResolution(false),
      mSignalledError(false),
      mWidth(320),
      mHeight(240),
      mInputOffset(0) {
    ALOGV("in %s", __func__);
    GETTIME(&mTimeStart, NULL);

    // If input dump is enabled, then open create an empty file
    GENERATE_FILE_NAMES();
    CREATE_DUMP_FILE(mInFile);
}

C2SoftAvcDec::~C2SoftAvcDec() {
    ALOGV("in %s", __func__);
    CHECK_EQ(deInitDecoder(), (status_t)OK);
}

c2_status_t C2SoftAvcDec::setListener_sm(
        const std::shared_ptr<C2Component::Listener> &listener) {
    std::unique_lock<std::mutex> lock(mListenerLock);
    // TODO: we really need to lock the running check as well
    if (listener && mThread->isRunning()) {
        return C2_BAD_STATE;
    }
    mListener = listener;
    if (mActiveListener && !listener) {
        // wait until no active listeners are in use
        mActiveListenerChanged.wait(lock, [this]{ return !mActiveListener; });
    }
    return C2_OK;
}

c2_status_t C2SoftAvcDec::queue_nb(
        std::list<std::unique_ptr<C2Work>>* const items) {
    if (!mThread->isRunning()) {
        return C2_CORRUPTED;
    }
    std::unique_lock<std::mutex> lock(mQueueLock);
    while (!items->empty()) {
        // TODO: examine item and update width/height?
        mQueue.emplace_back(std::move(items->front()));
        items->pop_front();
    }
    mQueueCond.notify_all();
    return C2_OK;
}

c2_status_t C2SoftAvcDec::announce_nb(const std::vector<C2WorkOutline> &items) {
    // Tunneling is not supported
    (void) items;
    return C2_OMITTED;
}

c2_status_t C2SoftAvcDec::flush_sm(
        flush_mode_t mode, std::list<std::unique_ptr<C2Work>>* const flushedWork) {
    // Tunneling is not supported
    (void) mode;

    if (!mThread->isRunning()) {
        return C2_CORRUPTED;
    }
    {
        std::unique_lock<std::mutex> lock(mQueueLock);
        while (!mQueue.empty()) {
            flushedWork->emplace_back(std::move(mQueue.front()));
            mQueue.pop_front();
        }
        mQueueCond.notify_all();
    }
    {
        std::unique_lock<std::mutex> lock(mPendingLock);
        for (auto &elem : mPendingWork) {
            flushedWork->emplace_back(std::move(elem.second));
        }
        mPendingWork.clear();
    }
    return C2_OK;
}

c2_status_t C2SoftAvcDec::drain_nb(drain_mode_t mode) {
    // Tunneling is not supported
    (void) mode;

    if (!mThread->isRunning()) {
        return C2_CORRUPTED;
    }
    std::unique_lock<std::mutex> lock(mQueueLock);
    if (!mQueue.empty()) {
        C2BufferPack &lastInput = mQueue.back()->input;
        lastInput.flags = (C2BufferPack::flags_t)(lastInput.flags | C2BufferPack::FLAG_END_OF_STREAM);
        mQueueCond.notify_all();
    }
    return C2_OK;
}

c2_status_t C2SoftAvcDec::start() {
    if (!mThread->isRunning()) {
        mThread->start(shared_from_this());
    }
    return C2_OK;
}

c2_status_t C2SoftAvcDec::stop() {
    ALOGV("stop");
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    std::chrono::system_clock::time_point deadline = now + std::chrono::milliseconds(500);

    mThread->requestExit();
    while (mThread->isRunning() && (now = std::chrono::system_clock::now()) < deadline) {
        std::this_thread::yield();
        std::unique_lock<std::mutex> lock(mQueueLock);
        mQueueCond.notify_all();
    }
    if (mThread->isRunning()) {
        return C2_TIMED_OUT;
    }

    mSignalledError = false;
    resetDecoder();
    resetPlugin();

    return C2_OK;
}

void C2SoftAvcDec::reset() {
    if (mThread->isRunning()) {
        stop();
    }
    // TODO
}

void C2SoftAvcDec::release() {
    if (mThread->isRunning()) {
        stop();
    }
    // TODO
}

std::shared_ptr<C2ComponentInterface> C2SoftAvcDec::intf() {
    return mIntf;
}

void C2SoftAvcDec::processQueue() {
#if 0
    if (mIsInFlush) {
        setFlushMode();

        /* Allocate a picture buffer to flushed data */
        uint32_t displayStride = mWidth;
        uint32_t displayHeight = mHeight;

        uint32_t bufferSize = displayStride * displayHeight * 3 / 2;
        mFlushOutBuffer = (uint8_t *)memalign(128, bufferSize);
        if (NULL == mFlushOutBuffer) {
            ALOGE("Could not allocate flushOutputBuffer of size %u", bufferSize);
            return;
        }

        while (true) {
            ivd_video_decode_ip_t s_dec_ip;
            ivd_video_decode_op_t s_dec_op;
            IV_API_CALL_STATUS_T status;
            size_t sizeY, sizeUV;

            setDecodeArgs(&s_dec_ip, &s_dec_op, NULL, NULL, 0, 0u);

            status = ivdec_api_function(mCodecCtx, (void *)&s_dec_ip, (void *)&s_dec_op);
            if (0 == s_dec_op.u4_output_present) {
                resetPlugin();
                break;
            }
        }

        if (mFlushOutBuffer) {
            free(mFlushOutBuffer);
            mFlushOutBuffer = NULL;
        }
        mIsInFlush = false;
    }
#endif

    std::unique_ptr<C2Work> work;
    if (!mIsInFlush) {
        std::unique_lock<std::mutex> lock(mQueueLock);
        if (mQueue.empty()) {
            mQueueCond.wait(lock);
        }
        if (mQueue.empty()) {
            ALOGV("empty queue");
            return;
        }
        work.swap(mQueue.front());
        mQueue.pop_front();
    }

    // Process the work
    process(work);

    std::vector<std::unique_ptr<C2Work>> done;
    if (work) {
        std::unique_lock<std::mutex> lock(mPendingLock);
        uint32_t index = work->input.ordinal.frame_index;
        mPendingWork[index].swap(work);

        if (work) {
            work->result = C2_CORRUPTED;
            done.emplace_back(std::move(work));
        }
    }

    if (!done.empty()) {
        std::unique_lock<std::mutex> lock(mListenerLock);
        mActiveListener = mListener;

        if (mActiveListener) {
            lock.unlock();
            mActiveListener->onWorkDone_nb(shared_from_this(), std::move(done));
            lock.lock();
            mActiveListener.reset();
            mActiveListenerChanged.notify_all();
        }
    }
}


static void *ivd_aligned_malloc(void *ctxt, WORD32 alignment, WORD32 size) {
    (void) ctxt;
    return memalign(alignment, size);
}

static void ivd_aligned_free(void *ctxt, void *buf) {
    (void) ctxt;
    free(buf);
    return;
}

static size_t GetCPUCoreCount() {
    long cpuCoreCount = 1;
#if defined(_SC_NPROCESSORS_ONLN)
    cpuCoreCount = sysconf(_SC_NPROCESSORS_ONLN);
#else
    // _SC_NPROC_ONLN must be defined...
    cpuCoreCount = sysconf(_SC_NPROC_ONLN);
#endif
    CHECK(cpuCoreCount >= 1);
    ALOGV("Number of CPU cores: %ld", cpuCoreCount);
    return (size_t)cpuCoreCount;
}

void C2SoftAvcDec::logVersion() {
    ivd_ctl_getversioninfo_ip_t s_ctl_ip;
    ivd_ctl_getversioninfo_op_t s_ctl_op;
    UWORD8 au1_buf[512];
    IV_API_CALL_STATUS_T status;

    s_ctl_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_ctl_ip.e_sub_cmd = IVD_CMD_CTL_GETVERSION;
    s_ctl_ip.u4_size = sizeof(ivd_ctl_getversioninfo_ip_t);
    s_ctl_op.u4_size = sizeof(ivd_ctl_getversioninfo_op_t);
    s_ctl_ip.pv_version_buffer = au1_buf;
    s_ctl_ip.u4_version_buffer_size = sizeof(au1_buf);

    status =
        ivdec_api_function(mCodecCtx, (void *)&s_ctl_ip, (void *)&s_ctl_op);

    if (status != IV_SUCCESS) {
        ALOGE("Error in getting version number: 0x%x",
                s_ctl_op.u4_error_code);
    } else {
        ALOGV("Ittiam decoder version number: %s",
                (char *)s_ctl_ip.pv_version_buffer);
    }
    return;
}

status_t C2SoftAvcDec::setParams(size_t stride) {
    ivd_ctl_set_config_ip_t s_ctl_ip;
    ivd_ctl_set_config_op_t s_ctl_op;
    IV_API_CALL_STATUS_T status;
    s_ctl_ip.u4_disp_wd = (UWORD32)stride;
    s_ctl_ip.e_frm_skip_mode = IVD_SKIP_NONE;

    s_ctl_ip.e_frm_out_mode = IVD_DISPLAY_FRAME_OUT;
    s_ctl_ip.e_vid_dec_mode = IVD_DECODE_FRAME;
    s_ctl_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_ctl_ip.e_sub_cmd = IVD_CMD_CTL_SETPARAMS;
    s_ctl_ip.u4_size = sizeof(ivd_ctl_set_config_ip_t);
    s_ctl_op.u4_size = sizeof(ivd_ctl_set_config_op_t);

    ALOGV("Set the run-time (dynamic) parameters stride = %zu", stride);
    status = ivdec_api_function(mCodecCtx, (void *)&s_ctl_ip, (void *)&s_ctl_op);

    if (status != IV_SUCCESS) {
        ALOGE("Error in setting the run-time parameters: 0x%x",
                s_ctl_op.u4_error_code);

        return UNKNOWN_ERROR;
    }
    return OK;
}

status_t C2SoftAvcDec::resetPlugin() {
    mReceivedEOS = false;
    mInputOffset = 0;

    /* Initialize both start and end times */
    gettimeofday(&mTimeStart, NULL);
    gettimeofday(&mTimeEnd, NULL);

    return OK;
}

status_t C2SoftAvcDec::resetDecoder() {
    ivd_ctl_reset_ip_t s_ctl_ip;
    ivd_ctl_reset_op_t s_ctl_op;
    IV_API_CALL_STATUS_T status;

    s_ctl_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_ctl_ip.e_sub_cmd = IVD_CMD_CTL_RESET;
    s_ctl_ip.u4_size = sizeof(ivd_ctl_reset_ip_t);
    s_ctl_op.u4_size = sizeof(ivd_ctl_reset_op_t);

    status = ivdec_api_function(mCodecCtx, (void *)&s_ctl_ip, (void *)&s_ctl_op);
    if (IV_SUCCESS != status) {
        ALOGE("Error in reset: 0x%x", s_ctl_op.u4_error_code);
        return UNKNOWN_ERROR;
    }
    mSignalledError = false;

    /* Set number of cores/threads to be used by the codec */
    setNumCores();

    mStride = 0;
    return OK;
}

status_t C2SoftAvcDec::setNumCores() {
    ivdext_ctl_set_num_cores_ip_t s_set_cores_ip;
    ivdext_ctl_set_num_cores_op_t s_set_cores_op;
    IV_API_CALL_STATUS_T status;
    s_set_cores_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_set_cores_ip.e_sub_cmd = IVDEXT_CMD_CTL_SET_NUM_CORES;
    s_set_cores_ip.u4_num_cores = MIN(mNumCores, CODEC_MAX_NUM_CORES);
    s_set_cores_ip.u4_size = sizeof(ivdext_ctl_set_num_cores_ip_t);
    s_set_cores_op.u4_size = sizeof(ivdext_ctl_set_num_cores_op_t);
    status = ivdec_api_function(
            mCodecCtx, (void *)&s_set_cores_ip, (void *)&s_set_cores_op);
    if (IV_SUCCESS != status) {
        ALOGE("Error in setting number of cores: 0x%x",
                s_set_cores_op.u4_error_code);
        return UNKNOWN_ERROR;
    }
    return OK;
}

status_t C2SoftAvcDec::setFlushMode() {
    ALOGV("setFlushMode");
    IV_API_CALL_STATUS_T status;
    ivd_ctl_flush_ip_t s_video_flush_ip;
    ivd_ctl_flush_op_t s_video_flush_op;

    s_video_flush_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_video_flush_ip.e_sub_cmd = IVD_CMD_CTL_FLUSH;
    s_video_flush_ip.u4_size = sizeof(ivd_ctl_flush_ip_t);
    s_video_flush_op.u4_size = sizeof(ivd_ctl_flush_op_t);

    /* Set the decoder in Flush mode, subsequent decode() calls will flush */
    status = ivdec_api_function(
            mCodecCtx, (void *)&s_video_flush_ip, (void *)&s_video_flush_op);

    if (status != IV_SUCCESS) {
        ALOGE("Error in setting the decoder in flush mode: (%d) 0x%x", status,
                s_video_flush_op.u4_error_code);
        return UNKNOWN_ERROR;
    }
    mIsInFlush = true;
    return OK;
}

status_t C2SoftAvcDec::initDecoder() {
    IV_API_CALL_STATUS_T status;

    mNumCores = GetCPUCoreCount();
    mCodecCtx = NULL;

    mStride = mWidth;

    /* Initialize the decoder */
    {
        ivdext_create_ip_t s_create_ip;
        ivdext_create_op_t s_create_op;

        void *dec_fxns = (void *)ivdec_api_function;

        s_create_ip.s_ivd_create_ip_t.u4_size = sizeof(ivdext_create_ip_t);
        s_create_ip.s_ivd_create_ip_t.e_cmd = IVD_CMD_CREATE;
        s_create_ip.s_ivd_create_ip_t.u4_share_disp_buf = 0;
        s_create_op.s_ivd_create_op_t.u4_size = sizeof(ivdext_create_op_t);
        s_create_ip.s_ivd_create_ip_t.e_output_format = (IV_COLOR_FORMAT_T)mIvColorFormat;
        s_create_ip.s_ivd_create_ip_t.pf_aligned_alloc = ivd_aligned_malloc;
        s_create_ip.s_ivd_create_ip_t.pf_aligned_free = ivd_aligned_free;
        s_create_ip.s_ivd_create_ip_t.pv_mem_ctxt = NULL;

        status = ivdec_api_function(mCodecCtx, (void *)&s_create_ip, (void *)&s_create_op);

        mCodecCtx = (iv_obj_t*)s_create_op.s_ivd_create_op_t.pv_handle;
        mCodecCtx->pv_fxns = dec_fxns;
        mCodecCtx->u4_size = sizeof(iv_obj_t);

        if (status != IV_SUCCESS) {
            ALOGE("Error in create: 0x%x",
                    s_create_op.s_ivd_create_op_t.u4_error_code);
            deInitDecoder();
            mCodecCtx = NULL;
            return UNKNOWN_ERROR;
        }
    }

    /* Reset the plugin state */
    resetPlugin();

    /* Set the run time (dynamic) parameters */
    setParams(mStride);

    /* Set number of cores/threads to be used by the codec */
    setNumCores();

    /* Get codec version */
    logVersion();

    mFlushNeeded = false;
    return OK;
}

status_t C2SoftAvcDec::deInitDecoder() {
    IV_API_CALL_STATUS_T status;

    if (mCodecCtx) {
        ivdext_delete_ip_t s_delete_ip;
        ivdext_delete_op_t s_delete_op;

        s_delete_ip.s_ivd_delete_ip_t.u4_size = sizeof(ivdext_delete_ip_t);
        s_delete_ip.s_ivd_delete_ip_t.e_cmd = IVD_CMD_DELETE;

        s_delete_op.s_ivd_delete_op_t.u4_size = sizeof(ivdext_delete_op_t);

        status = ivdec_api_function(mCodecCtx, (void *)&s_delete_ip, (void *)&s_delete_op);
        if (status != IV_SUCCESS) {
            ALOGE("Error in delete: 0x%x",
                    s_delete_op.s_ivd_delete_op_t.u4_error_code);
            return UNKNOWN_ERROR;
        }
    }


    mChangingResolution = false;

    return OK;
}

bool C2SoftAvcDec::getVUIParams() {
    IV_API_CALL_STATUS_T status;
    ih264d_ctl_get_vui_params_ip_t s_ctl_get_vui_params_ip;
    ih264d_ctl_get_vui_params_op_t s_ctl_get_vui_params_op;

    s_ctl_get_vui_params_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_ctl_get_vui_params_ip.e_sub_cmd =
        (IVD_CONTROL_API_COMMAND_TYPE_T)IH264D_CMD_CTL_GET_VUI_PARAMS;

    s_ctl_get_vui_params_ip.u4_size =
        sizeof(ih264d_ctl_get_vui_params_ip_t);

    s_ctl_get_vui_params_op.u4_size = sizeof(ih264d_ctl_get_vui_params_op_t);

    status = ivdec_api_function(
            (iv_obj_t *)mCodecCtx, (void *)&s_ctl_get_vui_params_ip,
            (void *)&s_ctl_get_vui_params_op);

    if (status != IV_SUCCESS) {
        ALOGW("Error in getting VUI params: 0x%x",
                s_ctl_get_vui_params_op.u4_error_code);
        return false;
    }

    int32_t primaries = s_ctl_get_vui_params_op.u1_colour_primaries;
    int32_t transfer = s_ctl_get_vui_params_op.u1_tfr_chars;
    int32_t coeffs = s_ctl_get_vui_params_op.u1_matrix_coeffs;
    bool fullRange = s_ctl_get_vui_params_op.u1_video_full_range_flag;

    ColorAspects colorAspects;
    ColorUtils::convertIsoColorAspectsToCodecAspects(
            primaries, transfer, coeffs, fullRange, colorAspects);

    // Update color aspects if necessary.
    if (colorAspectsDiffer(colorAspects, mBitstreamColorAspects)) {
        mBitstreamColorAspects = colorAspects;
        status_t err = handleColorAspectsChange();
        CHECK(err == OK);
    }
    return true;
}

bool C2SoftAvcDec::setDecodeArgs(
        ivd_video_decode_ip_t *ps_dec_ip,
        ivd_video_decode_op_t *ps_dec_op,
        C2ReadView *inBuffer,
        C2GraphicView *outBuffer,
        uint32_t workIndex,
        size_t inOffset) {
    size_t width = mWidth;
    size_t height = mHeight;
    size_t sizeY = width * height;
    size_t sizeUV;

    ps_dec_ip->u4_size = sizeof(ivd_video_decode_ip_t);
    ps_dec_op->u4_size = sizeof(ivd_video_decode_op_t);

    ps_dec_ip->e_cmd = IVD_CMD_VIDEO_DECODE;

    /* When in flush and after EOS with zero byte input,
     * inBuffer is set to zero. Hence check for non-null */
    if (inBuffer) {
        ps_dec_ip->u4_ts = workIndex;
        ps_dec_ip->pv_stream_buffer = const_cast<uint8_t *>(inBuffer->data()) + inOffset;
        ps_dec_ip->u4_num_Bytes = inBuffer->capacity() - inOffset;
    } else {
        ps_dec_ip->u4_ts = 0;
        ps_dec_ip->pv_stream_buffer = NULL;
        ps_dec_ip->u4_num_Bytes = 0;
    }

    sizeUV = sizeY / 4;
    ps_dec_ip->s_out_buffer.u4_min_out_buf_size[0] = sizeY;
    ps_dec_ip->s_out_buffer.u4_min_out_buf_size[1] = sizeUV;
    ps_dec_ip->s_out_buffer.u4_min_out_buf_size[2] = sizeUV;

    if (outBuffer) {
        if (outBuffer->width() < width ||
                outBuffer->height() < height) {
            ALOGE("Output buffer too small: provided (%dx%d) required (%zux%zu)",
                  outBuffer->width(), outBuffer->height(), width, height);
            return false;
        }
        ps_dec_ip->s_out_buffer.pu1_bufs[0] = outBuffer->data()[0];
        ps_dec_ip->s_out_buffer.pu1_bufs[1] = outBuffer->data()[1];
        ps_dec_ip->s_out_buffer.pu1_bufs[2] = outBuffer->data()[2];
    } else {
        // mFlushOutBuffer always has the right size.
        ps_dec_ip->s_out_buffer.pu1_bufs[0] = mFlushOutBuffer;
        ps_dec_ip->s_out_buffer.pu1_bufs[1] = mFlushOutBuffer + sizeY;
        ps_dec_ip->s_out_buffer.pu1_bufs[2] = mFlushOutBuffer + sizeY + sizeUV;
    }

    ps_dec_ip->s_out_buffer.u4_num_bufs = 3;
    return true;
}

void C2SoftAvcDec::process(std::unique_ptr<C2Work> &work) {
    if (mSignalledError) {
        return;
    }
    if (NULL == mCodecCtx) {
        if (OK != initDecoder()) {
            ALOGE("Failed to initialize decoder");
            // TODO: notify(OMX_EventError, OMX_ErrorUnsupportedSetting, 0, NULL);
            mSignalledError = true;
            return;
        }
    }
    if (mWidth != mStride) {
        /* Set the run-time (dynamic) parameters */
        mStride = mWidth;
        setParams(mStride);
    }

    uint32_t workIndex = 0;
    std::unique_ptr<C2ReadView> input;
    if (work) {
        work->result = C2_OK;

        const C2ConstLinearBlock &buffer =
                work->input.buffers[0]->data().linearBlocks().front();
        if (buffer.capacity() == 0) {
            // TODO: result?

            std::vector<std::unique_ptr<C2Work>> done;
            done.emplace_back(std::move(work));
            mListener->onWorkDone_nb(shared_from_this(), std::move(done));
            if (!(work->input.flags & C2BufferPack::FLAG_END_OF_STREAM)) {
                return;
            }

            mReceivedEOS = true;
            // TODO: flush
        } else if (work->input.flags & C2BufferPack::FLAG_END_OF_STREAM) {
            ALOGV("input EOS: %llu", work->input.ordinal.frame_index);
            mReceivedEOS = true;
        }

        input.reset(new C2ReadView(work->input.buffers[0]->data().linearBlocks().front().map().get()));
        workIndex = work->input.ordinal.frame_index & 0xFFFFFFFF;
    }

    size_t inOffset = 0u;
    while (!input || inOffset < input->capacity()) {
        if (!input) {
            ALOGV("flushing");
        }
        // TODO: populate --- assume display order?
        if (!mAllocatedBlock) {
            // TODO: error handling
            // TODO: format & usage
            uint32_t format = HAL_PIXEL_FORMAT_YV12;
            C2MemoryUsage usage = { C2MemoryUsage::kSoftwareRead, C2MemoryUsage::kSoftwareWrite };
            // TODO: lock access to interface
            C2BlockPool::local_id_t poolId =
                mIntf->mOutputBlockPools->flexCount() ?
                        mIntf->mOutputBlockPools->m.mValues[0] : C2BlockPool::BASIC_GRAPHIC;
            if (!mOutputBlockPool || mOutputBlockPool->getLocalId() != poolId) {
                c2_status_t err = GetCodec2BlockPool(poolId, shared_from_this(), &mOutputBlockPool);
                if (err != C2_OK) {
                    // TODO: trip
                }
            }
            ALOGE("using allocator %u", mOutputBlockPool->getAllocatorId());

            (void)mOutputBlockPool->fetchGraphicBlock(
                    mWidth, mHeight, format, usage, &mAllocatedBlock);
            ALOGE("provided (%dx%d) required (%dx%d)", mAllocatedBlock->width(), mAllocatedBlock->height(), mWidth, mHeight);
        }
        C2GraphicView output = mAllocatedBlock->map().get();
        if (output.error() != OK) {
            ALOGE("mapped err = %d", output.error());
        }

        ivd_video_decode_ip_t s_dec_ip;
        ivd_video_decode_op_t s_dec_op;
        WORD32 timeDelay, timeTaken;
        size_t sizeY, sizeUV;

        if (!setDecodeArgs(&s_dec_ip, &s_dec_op, input.get(), &output, workIndex, inOffset)) {
            ALOGE("Decoder arg setup failed");
            // TODO: notify(OMX_EventError, OMX_ErrorUndefined, 0, NULL);
            mSignalledError = true;
            return;
        }
        ALOGV("Decoder arg setup succeeded");
        // If input dump is enabled, then write to file
        DUMP_TO_FILE(mInFile, s_dec_ip.pv_stream_buffer, s_dec_ip.u4_num_Bytes, mInputOffset);

        GETTIME(&mTimeStart, NULL);
        /* Compute time elapsed between end of previous decode()
         * to start of current decode() */
        TIME_DIFF(mTimeEnd, mTimeStart, timeDelay);

        IV_API_CALL_STATUS_T status;
        status = ivdec_api_function(mCodecCtx, (void *)&s_dec_ip, (void *)&s_dec_op);

        bool unsupportedResolution =
            (IVD_STREAM_WIDTH_HEIGHT_NOT_SUPPORTED == (s_dec_op.u4_error_code & 0xFF));

        /* Check for unsupported dimensions */
        if (unsupportedResolution) {
            ALOGE("Unsupported resolution : %dx%d", mWidth, mHeight);
            // TODO: notify(OMX_EventError, OMX_ErrorUnsupportedSetting, 0, NULL);
            mSignalledError = true;
            return;
        }

        bool allocationFailed = (IVD_MEM_ALLOC_FAILED == (s_dec_op.u4_error_code & 0xFF));
        if (allocationFailed) {
            ALOGE("Allocation failure in decoder");
            // TODO: notify(OMX_EventError, OMX_ErrorUnsupportedSetting, 0, NULL);
            mSignalledError = true;
            return;
        }

        bool resChanged = (IVD_RES_CHANGED == (s_dec_op.u4_error_code & 0xFF));

        getVUIParams();

        GETTIME(&mTimeEnd, NULL);
        /* Compute time taken for decode() */
        TIME_DIFF(mTimeStart, mTimeEnd, timeTaken);

        PRINT_TIME("timeTaken=%6d delay=%6d numBytes=%6d", timeTaken, timeDelay,
               s_dec_op.u4_num_bytes_consumed);
        if (input) {
            ALOGI("bytes total=%u", input->capacity());
        }
        if (s_dec_op.u4_frame_decoded_flag && !mFlushNeeded) {
            mFlushNeeded = true;
        }

        if (1 != s_dec_op.u4_frame_decoded_flag && work) {
            /* If the input did not contain picture data, return work without
             * buffer */
            ALOGV("no picture data");
            std::vector<std::unique_ptr<C2Work>> done;
            done.push_back(std::move(work));
            done[0]->worklets.front()->output.flags = (C2BufferPack::flags_t)0;
            done[0]->worklets.front()->output.buffers.clear();
            done[0]->worklets.front()->output.buffers.emplace_back(nullptr);
            done[0]->worklets.front()->output.ordinal = done[0]->input.ordinal;
            mListener->onWorkDone_nb(shared_from_this(), std::move(done));
        }

        // If the decoder is in the changing resolution mode and there is no output present,
        // that means the switching is done and it's ready to reset the decoder and the plugin.
        if (mChangingResolution && !s_dec_op.u4_output_present) {
            ALOGV("changing resolution");
            mChangingResolution = false;
            resetDecoder();
            resetPlugin();
            mStride = mWidth;
            setParams(mStride);
            return;
        }

        if (resChanged) {
            ALOGV("res changed");
            mChangingResolution = true;
            if (mFlushNeeded) {
                setFlushMode();
            }
            return;
        }

        // Combine the resolution change and coloraspects change in one PortSettingChange event
        // if necessary.
        if ((0 < s_dec_op.u4_pic_wd) && (0 < s_dec_op.u4_pic_ht)) {
            uint32_t width = s_dec_op.u4_pic_wd;
            uint32_t height = s_dec_op.u4_pic_ht;
            ALOGV("width = %u height = %u", width, height);
            if (width != mWidth || height != mHeight) {
                mAllocatedBlock.reset();
                mWidth = width;
                mHeight = height;
            }
        } else if (mUpdateColorAspects) {
            //notify(OMX_EventPortSettingsChanged, kOutputPortIndex,
            //    kDescribeColorAspectsIndex, NULL);
            ALOGV("update color aspect");
            mUpdateColorAspects = false;
            return;
        }

        if (s_dec_op.u4_output_present) {
            ALOGV("output_present: %d", s_dec_op.u4_ts);
            std::vector<std::unique_ptr<C2Work>> done;
            {
                std::unique_lock<std::mutex> lock(mPendingLock);
                done.push_back(std::move(mPendingWork[s_dec_op.u4_ts]));
                mPendingWork.erase(s_dec_op.u4_ts);
            }
            uint32_t flags = 0;
            if (done[0]->input.flags & C2BufferPack::FLAG_END_OF_STREAM) {
                flags |= C2BufferPack::FLAG_END_OF_STREAM;
                ALOGV("EOS");
            }
            done[0]->worklets.front()->output.flags = (C2BufferPack::flags_t)flags;
            done[0]->worklets.front()->output.buffers.clear();
            done[0]->worklets.front()->output.buffers.emplace_back(
                    std::make_shared<GraphicBuffer>(std::move(mAllocatedBlock)));
            done[0]->worklets.front()->output.ordinal = done[0]->input.ordinal;
            mListener->onWorkDone_nb(shared_from_this(), std::move(done));
        } else if (mIsInFlush) {
            ALOGV("flush");
            /* If in flush mode and no output is returned by the codec,
             * then come out of flush mode */
            mIsInFlush = false;

            /* If EOS was recieved on input port and there is no output
             * from the codec, then signal EOS on output port */
            if (mReceivedEOS) {
                std::vector<std::unique_ptr<C2Work>> done;
                {
                    std::unique_lock<std::mutex> lock(mPendingLock);
                    if (!mPendingWork.empty()) {
                        done.push_back(std::move(mPendingWork.begin()->second));
                        mPendingWork.erase(mPendingWork.begin());
                    }
                }
                if (!done.empty()) {
                    ALOGV("sending empty EOS buffer");
                    done[0]->worklets.front()->output.flags = C2BufferPack::FLAG_END_OF_STREAM;
                    done[0]->worklets.front()->output.buffers.clear();
                    done[0]->worklets.front()->output.buffers.emplace_back(nullptr);
                    done[0]->worklets.front()->output.ordinal = done[0]->input.ordinal;
                    mListener->onWorkDone_nb(shared_from_this(), std::move(done));
                }

                resetPlugin();
                return;
            }
        }
        inOffset += s_dec_op.u4_num_bytes_consumed;
    }
    /* If input EOS is seen and decoder is not in flush mode,
     * set the decoder in flush mode.
     * There can be a case where EOS is sent along with last picture data
     * In that case, only after decoding that input data, decoder has to be
     * put in flush. This case is handled here  */

    if (mReceivedEOS && !mIsInFlush) {
        setFlushMode();
    }
}

bool C2SoftAvcDec::colorAspectsDiffer(
        const ColorAspects &a, const ColorAspects &b) {
    if (a.mRange != b.mRange
        || a.mPrimaries != b.mPrimaries
        || a.mTransfer != b.mTransfer
        || a.mMatrixCoeffs != b.mMatrixCoeffs) {
        return true;
    }
    return false;
}

void C2SoftAvcDec::updateFinalColorAspects(
        const ColorAspects &otherAspects, const ColorAspects &preferredAspects) {
    Mutex::Autolock autoLock(mColorAspectsLock);
    ColorAspects newAspects;
    newAspects.mRange = preferredAspects.mRange != ColorAspects::RangeUnspecified ?
        preferredAspects.mRange : otherAspects.mRange;
    newAspects.mPrimaries = preferredAspects.mPrimaries != ColorAspects::PrimariesUnspecified ?
        preferredAspects.mPrimaries : otherAspects.mPrimaries;
    newAspects.mTransfer = preferredAspects.mTransfer != ColorAspects::TransferUnspecified ?
        preferredAspects.mTransfer : otherAspects.mTransfer;
    newAspects.mMatrixCoeffs = preferredAspects.mMatrixCoeffs != ColorAspects::MatrixUnspecified ?
        preferredAspects.mMatrixCoeffs : otherAspects.mMatrixCoeffs;

    // Check to see if need update mFinalColorAspects.
    if (colorAspectsDiffer(mFinalColorAspects, newAspects)) {
        mFinalColorAspects = newAspects;
        mUpdateColorAspects = true;
    }
}

status_t C2SoftAvcDec::handleColorAspectsChange() {
//    int perference = getColorAspectPreference();
//    ALOGD("Color Aspects preference: %d ", perference);
//
//     if (perference == kPreferBitstream) {
//         updateFinalColorAspects(mDefaultColorAspects, mBitstreamColorAspects);
//     } else if (perference == kPreferContainer) {
//         updateFinalColorAspects(mBitstreamColorAspects, mDefaultColorAspects);
//     } else {
//         return OMX_ErrorUnsupportedSetting;
//     }
    updateFinalColorAspects(mDefaultColorAspects, mBitstreamColorAspects);
    return C2_OK;
}

class C2SoftAvcDecFactory : public C2ComponentFactory {
public:
    virtual c2_status_t createComponent(
            c2_node_id_t id, std::shared_ptr<C2Component>* const component,
            std::function<void(::android::C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(new C2SoftAvcDec("avc", id), deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id, std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(::android::C2ComponentInterface*)> deleter) override {
        *interface =
            std::shared_ptr<C2ComponentInterface>(new C2SoftAvcDecIntf("avc", id), deleter);
        return C2_OK;
    }

    virtual ~C2SoftAvcDecFactory() override = default;
};

}  // namespace android

extern "C" ::android::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftAvcDecFactory();
}

extern "C" void DestroyCodec2Factory(::android::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
