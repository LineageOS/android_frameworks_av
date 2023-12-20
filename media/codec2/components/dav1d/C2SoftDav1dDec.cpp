/*
 * Copyright (C) 2023 The Android Open Source Project
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

// #define LOG_NDEBUG 0
#define LOG_TAG "C2SoftDav1dDec"
#include <android-base/properties.h>
#include <cutils/properties.h>
#include <thread>

#include <C2Debug.h>
#include <C2PlatformSupport.h>
#include <Codec2BufferUtils.h>
#include <Codec2CommonUtils.h>
#include <Codec2Mapper.h>
#include <SimpleC2Interface.h>
#include <log/log.h>
#include <media/stagefright/foundation/AUtils.h>
#include <media/stagefright/foundation/MediaDefs.h>
#include "C2SoftDav1dDec.h"

namespace android {

// The number of threads used for the dav1d decoder.
static const int NUM_THREADS_DAV1D_DEFAULT = 0;
static const char NUM_THREADS_DAV1D_PROPERTY[] = "debug.dav1d.numthreads";

// codecname set and passed in as a compile flag from Android.bp
constexpr char COMPONENT_NAME[] = CODECNAME;

constexpr size_t kMinInputBufferSize = 2 * 1024 * 1024;

constexpr uint32_t kOutputDelay = 4;

class C2SoftDav1dDec::IntfImpl : public SimpleInterface<void>::BaseParams {
  public:
    explicit IntfImpl(const std::shared_ptr<C2ReflectorHelper>& helper)
        : SimpleInterface<void>::BaseParams(helper, COMPONENT_NAME, C2Component::KIND_DECODER,
                                            C2Component::DOMAIN_VIDEO, MEDIA_MIMETYPE_VIDEO_AV1) {
        noPrivateBuffers();
        noInputReferences();
        noOutputReferences();
        noInputLatency();
        noTimeStretch();

        addParameter(DefineParam(mAttrib, C2_PARAMKEY_COMPONENT_ATTRIBUTES)
                             .withConstValue(new C2ComponentAttributesSetting(
                                     C2Component::ATTRIB_IS_TEMPORAL))
                             .build());

        addParameter(DefineParam(mSize, C2_PARAMKEY_PICTURE_SIZE)
                             .withDefault(new C2StreamPictureSizeInfo::output(0u, 320, 240))
                             .withFields({
                                     C2F(mSize, width).inRange(2, 4096),
                                     C2F(mSize, height).inRange(2, 4096),
                             })
                             .withSetter(SizeSetter)
                             .build());

        addParameter(DefineParam(mProfileLevel, C2_PARAMKEY_PROFILE_LEVEL)
                             .withDefault(new C2StreamProfileLevelInfo::input(
                                     0u, C2Config::PROFILE_AV1_0, C2Config::LEVEL_AV1_2_1))
                             .withFields({C2F(mProfileLevel, profile)
                                                  .oneOf({C2Config::PROFILE_AV1_0,
                                                          C2Config::PROFILE_AV1_1}),
                                          C2F(mProfileLevel, level)
                                                  .oneOf({
                                                          C2Config::LEVEL_AV1_2,
                                                          C2Config::LEVEL_AV1_2_1,
                                                          C2Config::LEVEL_AV1_2_2,
                                                          C2Config::LEVEL_AV1_2_3,
                                                          C2Config::LEVEL_AV1_3,
                                                          C2Config::LEVEL_AV1_3_1,
                                                          C2Config::LEVEL_AV1_3_2,
                                                          C2Config::LEVEL_AV1_3_3,
                                                          C2Config::LEVEL_AV1_4,
                                                          C2Config::LEVEL_AV1_4_1,
                                                          C2Config::LEVEL_AV1_4_2,
                                                          C2Config::LEVEL_AV1_4_3,
                                                          C2Config::LEVEL_AV1_5,
                                                          C2Config::LEVEL_AV1_5_1,
                                                          C2Config::LEVEL_AV1_5_2,
                                                          C2Config::LEVEL_AV1_5_3,
                                                  })})
                             .withSetter(ProfileLevelSetter, mSize)
                             .build());

        mHdr10PlusInfoInput = C2StreamHdr10PlusInfo::input::AllocShared(0);
        addParameter(DefineParam(mHdr10PlusInfoInput, C2_PARAMKEY_INPUT_HDR10_PLUS_INFO)
                             .withDefault(mHdr10PlusInfoInput)
                             .withFields({
                                     C2F(mHdr10PlusInfoInput, m.value).any(),
                             })
                             .withSetter(Hdr10PlusInfoInputSetter)
                             .build());

        mHdr10PlusInfoOutput = C2StreamHdr10PlusInfo::output::AllocShared(0);
        addParameter(DefineParam(mHdr10PlusInfoOutput, C2_PARAMKEY_OUTPUT_HDR10_PLUS_INFO)
                             .withDefault(mHdr10PlusInfoOutput)
                             .withFields({
                                     C2F(mHdr10PlusInfoOutput, m.value).any(),
                             })
                             .withSetter(Hdr10PlusInfoOutputSetter)
                             .build());

        // default static info
        C2HdrStaticMetadataStruct defaultStaticInfo{};
        helper->addStructDescriptors<C2MasteringDisplayColorVolumeStruct, C2ColorXyStruct>();
        addParameter(
                DefineParam(mHdrStaticInfo, C2_PARAMKEY_HDR_STATIC_INFO)
                        .withDefault(new C2StreamHdrStaticInfo::output(0u, defaultStaticInfo))
                        .withFields({C2F(mHdrStaticInfo, mastering.red.x).inRange(0, 1),
                                     C2F(mHdrStaticInfo, mastering.red.y).inRange(0, 1),
                                     C2F(mHdrStaticInfo, mastering.green.x).inRange(0, 1),
                                     C2F(mHdrStaticInfo, mastering.green.y).inRange(0, 1),
                                     C2F(mHdrStaticInfo, mastering.blue.x).inRange(0, 1),
                                     C2F(mHdrStaticInfo, mastering.blue.y).inRange(0, 1),
                                     C2F(mHdrStaticInfo, mastering.white.x).inRange(0, 1),
                                     C2F(mHdrStaticInfo, mastering.white.x).inRange(0, 1),
                                     C2F(mHdrStaticInfo, mastering.maxLuminance).inRange(0, 65535),
                                     C2F(mHdrStaticInfo, mastering.minLuminance).inRange(0, 6.5535),
                                     C2F(mHdrStaticInfo, maxCll).inRange(0, 0XFFFF),
                                     C2F(mHdrStaticInfo, maxFall).inRange(0, 0XFFFF)})
                        .withSetter(HdrStaticInfoSetter)
                        .build());

        addParameter(DefineParam(mMaxSize, C2_PARAMKEY_MAX_PICTURE_SIZE)
                             .withDefault(new C2StreamMaxPictureSizeTuning::output(0u, 320, 240))
                             .withFields({
                                     C2F(mSize, width).inRange(2, 2048, 2),
                                     C2F(mSize, height).inRange(2, 2048, 2),
                             })
                             .withSetter(MaxPictureSizeSetter, mSize)
                             .build());

        addParameter(
                DefineParam(mMaxInputSize, C2_PARAMKEY_INPUT_MAX_BUFFER_SIZE)
                        .withDefault(new C2StreamMaxBufferSizeInfo::input(0u, kMinInputBufferSize))
                        .withFields({
                                C2F(mMaxInputSize, value).any(),
                        })
                        .calculatedAs(MaxInputSizeSetter, mMaxSize)
                        .build());

        C2ChromaOffsetStruct locations[1] = {C2ChromaOffsetStruct::ITU_YUV_420_0()};
        std::shared_ptr<C2StreamColorInfo::output> defaultColorInfo =
                C2StreamColorInfo::output::AllocShared(1u, 0u, 8u /* bitDepth */, C2Color::YUV_420);
        memcpy(defaultColorInfo->m.locations, locations, sizeof(locations));

        defaultColorInfo = C2StreamColorInfo::output::AllocShared(
                {C2ChromaOffsetStruct::ITU_YUV_420_0()}, 0u, 8u /* bitDepth */, C2Color::YUV_420);
        helper->addStructDescriptors<C2ChromaOffsetStruct>();

        addParameter(DefineParam(mColorInfo, C2_PARAMKEY_CODED_COLOR_INFO)
                             .withConstValue(defaultColorInfo)
                             .build());

        addParameter(DefineParam(mDefaultColorAspects, C2_PARAMKEY_DEFAULT_COLOR_ASPECTS)
                             .withDefault(new C2StreamColorAspectsTuning::output(
                                     0u, C2Color::RANGE_UNSPECIFIED, C2Color::PRIMARIES_UNSPECIFIED,
                                     C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
                             .withFields({C2F(mDefaultColorAspects, range)
                                                  .inRange(C2Color::RANGE_UNSPECIFIED,
                                                           C2Color::RANGE_OTHER),
                                          C2F(mDefaultColorAspects, primaries)
                                                  .inRange(C2Color::PRIMARIES_UNSPECIFIED,
                                                           C2Color::PRIMARIES_OTHER),
                                          C2F(mDefaultColorAspects, transfer)
                                                  .inRange(C2Color::TRANSFER_UNSPECIFIED,
                                                           C2Color::TRANSFER_OTHER),
                                          C2F(mDefaultColorAspects, matrix)
                                                  .inRange(C2Color::MATRIX_UNSPECIFIED,
                                                           C2Color::MATRIX_OTHER)})
                             .withSetter(DefaultColorAspectsSetter)
                             .build());

        addParameter(DefineParam(mCodedColorAspects, C2_PARAMKEY_VUI_COLOR_ASPECTS)
                             .withDefault(new C2StreamColorAspectsInfo::input(
                                     0u, C2Color::RANGE_LIMITED, C2Color::PRIMARIES_UNSPECIFIED,
                                     C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
                             .withFields({C2F(mCodedColorAspects, range)
                                                  .inRange(C2Color::RANGE_UNSPECIFIED,
                                                           C2Color::RANGE_OTHER),
                                          C2F(mCodedColorAspects, primaries)
                                                  .inRange(C2Color::PRIMARIES_UNSPECIFIED,
                                                           C2Color::PRIMARIES_OTHER),
                                          C2F(mCodedColorAspects, transfer)
                                                  .inRange(C2Color::TRANSFER_UNSPECIFIED,
                                                           C2Color::TRANSFER_OTHER),
                                          C2F(mCodedColorAspects, matrix)
                                                  .inRange(C2Color::MATRIX_UNSPECIFIED,
                                                           C2Color::MATRIX_OTHER)})
                             .withSetter(CodedColorAspectsSetter)
                             .build());

        addParameter(
                DefineParam(mColorAspects, C2_PARAMKEY_COLOR_ASPECTS)
                        .withDefault(new C2StreamColorAspectsInfo::output(
                                0u, C2Color::RANGE_UNSPECIFIED, C2Color::PRIMARIES_UNSPECIFIED,
                                C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
                        .withFields(
                                {C2F(mColorAspects, range)
                                         .inRange(C2Color::RANGE_UNSPECIFIED, C2Color::RANGE_OTHER),
                                 C2F(mColorAspects, primaries)
                                         .inRange(C2Color::PRIMARIES_UNSPECIFIED,
                                                  C2Color::PRIMARIES_OTHER),
                                 C2F(mColorAspects, transfer)
                                         .inRange(C2Color::TRANSFER_UNSPECIFIED,
                                                  C2Color::TRANSFER_OTHER),
                                 C2F(mColorAspects, matrix)
                                         .inRange(C2Color::MATRIX_UNSPECIFIED,
                                                  C2Color::MATRIX_OTHER)})
                        .withSetter(ColorAspectsSetter, mDefaultColorAspects, mCodedColorAspects)
                        .build());

        std::vector<uint32_t> pixelFormats = {HAL_PIXEL_FORMAT_YCBCR_420_888};
        if (isHalPixelFormatSupported((AHardwareBuffer_Format)HAL_PIXEL_FORMAT_YCBCR_P010)) {
            pixelFormats.push_back(HAL_PIXEL_FORMAT_YCBCR_P010);
        }
        // If color format surface isn't added to supported formats, there is no way to know
        // when the color-format is configured to surface. This is necessary to be able to
        // choose 10-bit format while decoding 10-bit clips in surface mode.
        pixelFormats.push_back(HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED);

        // TODO: support more formats?
        addParameter(DefineParam(mPixelFormat, C2_PARAMKEY_PIXEL_FORMAT)
                             .withDefault(new C2StreamPixelFormatInfo::output(
                                     0u, HAL_PIXEL_FORMAT_YCBCR_420_888))
                             .withFields({C2F(mPixelFormat, value).oneOf(pixelFormats)})
                             .withSetter((Setter<decltype(*mPixelFormat)>::StrictValueWithNoDeps))
                             .build());

        addParameter(
                DefineParam(mActualOutputDelay, C2_PARAMKEY_OUTPUT_DELAY)
                .withDefault(new C2PortActualDelayTuning::output(kOutputDelay))
                .withFields({C2F(mActualOutputDelay, value).inRange(0, kOutputDelay)})
                .withSetter(Setter<decltype(*mActualOutputDelay)>::StrictValueWithNoDeps)
                .build());
    }

    static C2R SizeSetter(bool mayBlock, const C2P<C2StreamPictureSizeInfo::output>& oldMe,
                          C2P<C2StreamPictureSizeInfo::output>& me) {
        (void)mayBlock;
        C2R res = C2R::Ok();
        if (!me.F(me.v.width).supportsAtAll(me.v.width)) {
            res = res.plus(C2SettingResultBuilder::BadValue(me.F(me.v.width)));
            me.set().width = oldMe.v.width;
        }
        if (!me.F(me.v.height).supportsAtAll(me.v.height)) {
            res = res.plus(C2SettingResultBuilder::BadValue(me.F(me.v.height)));
            me.set().height = oldMe.v.height;
        }
        return res;
    }

    static C2R MaxPictureSizeSetter(bool mayBlock, C2P<C2StreamMaxPictureSizeTuning::output>& me,
                                    const C2P<C2StreamPictureSizeInfo::output>& size) {
        (void)mayBlock;
        // TODO: get max width/height from the size's field helpers vs.
        // hardcoding
        me.set().width = c2_min(c2_max(me.v.width, size.v.width), 4096u);
        me.set().height = c2_min(c2_max(me.v.height, size.v.height), 4096u);
        return C2R::Ok();
    }

    static C2R MaxInputSizeSetter(bool mayBlock, C2P<C2StreamMaxBufferSizeInfo::input>& me,
                                  const C2P<C2StreamMaxPictureSizeTuning::output>& maxSize) {
        (void)mayBlock;
        // assume compression ratio of 2, but enforce a floor
        me.set().value =
                c2_max((((maxSize.v.width + 63) / 64) * ((maxSize.v.height + 63) / 64) * 3072),
                       kMinInputBufferSize);
        return C2R::Ok();
    }

    static C2R DefaultColorAspectsSetter(bool mayBlock,
                                         C2P<C2StreamColorAspectsTuning::output>& me) {
        (void)mayBlock;
        if (me.v.range > C2Color::RANGE_OTHER) {
            me.set().range = C2Color::RANGE_OTHER;
        }
        if (me.v.primaries > C2Color::PRIMARIES_OTHER) {
            me.set().primaries = C2Color::PRIMARIES_OTHER;
        }
        if (me.v.transfer > C2Color::TRANSFER_OTHER) {
            me.set().transfer = C2Color::TRANSFER_OTHER;
        }
        if (me.v.matrix > C2Color::MATRIX_OTHER) {
            me.set().matrix = C2Color::MATRIX_OTHER;
        }
        return C2R::Ok();
    }

    static C2R CodedColorAspectsSetter(bool mayBlock, C2P<C2StreamColorAspectsInfo::input>& me) {
        (void)mayBlock;
        if (me.v.range > C2Color::RANGE_OTHER) {
            me.set().range = C2Color::RANGE_OTHER;
        }
        if (me.v.primaries > C2Color::PRIMARIES_OTHER) {
            me.set().primaries = C2Color::PRIMARIES_OTHER;
        }
        if (me.v.transfer > C2Color::TRANSFER_OTHER) {
            me.set().transfer = C2Color::TRANSFER_OTHER;
        }
        if (me.v.matrix > C2Color::MATRIX_OTHER) {
            me.set().matrix = C2Color::MATRIX_OTHER;
        }
        return C2R::Ok();
    }

    static C2R ColorAspectsSetter(bool mayBlock, C2P<C2StreamColorAspectsInfo::output>& me,
                                  const C2P<C2StreamColorAspectsTuning::output>& def,
                                  const C2P<C2StreamColorAspectsInfo::input>& coded) {
        (void)mayBlock;
        // take default values for all unspecified fields, and coded values for specified ones
        me.set().range = coded.v.range == RANGE_UNSPECIFIED ? def.v.range : coded.v.range;
        me.set().primaries =
                coded.v.primaries == PRIMARIES_UNSPECIFIED ? def.v.primaries : coded.v.primaries;
        me.set().transfer =
                coded.v.transfer == TRANSFER_UNSPECIFIED ? def.v.transfer : coded.v.transfer;
        me.set().matrix = coded.v.matrix == MATRIX_UNSPECIFIED ? def.v.matrix : coded.v.matrix;
        return C2R::Ok();
    }

    static C2R ProfileLevelSetter(bool mayBlock, C2P<C2StreamProfileLevelInfo::input>& me,
                                  const C2P<C2StreamPictureSizeInfo::output>& size) {
        (void)mayBlock;
        (void)size;
        (void)me;  // TODO: validate
        return C2R::Ok();
    }

    std::shared_ptr<C2StreamColorAspectsTuning::output> getDefaultColorAspects_l() {
        return mDefaultColorAspects;
    }

    std::shared_ptr<C2StreamColorAspectsInfo::output> getColorAspects_l() { return mColorAspects; }

    static C2R Hdr10PlusInfoInputSetter(bool mayBlock, C2P<C2StreamHdr10PlusInfo::input>& me) {
        (void)mayBlock;
        (void)me;  // TODO: validate
        return C2R::Ok();
    }

    static C2R Hdr10PlusInfoOutputSetter(bool mayBlock, C2P<C2StreamHdr10PlusInfo::output>& me) {
        (void)mayBlock;
        (void)me;  // TODO: validate
        return C2R::Ok();
    }

    // unsafe getters
    std::shared_ptr<C2StreamPixelFormatInfo::output> getPixelFormat_l() const {
        return mPixelFormat;
    }

    static C2R HdrStaticInfoSetter(bool mayBlock, C2P<C2StreamHdrStaticInfo::output>& me) {
        (void)mayBlock;
        if (me.v.mastering.red.x > 1) {
            me.set().mastering.red.x = 1;
        }
        if (me.v.mastering.red.y > 1) {
            me.set().mastering.red.y = 1;
        }
        if (me.v.mastering.green.x > 1) {
            me.set().mastering.green.x = 1;
        }
        if (me.v.mastering.green.y > 1) {
            me.set().mastering.green.y = 1;
        }
        if (me.v.mastering.blue.x > 1) {
            me.set().mastering.blue.x = 1;
        }
        if (me.v.mastering.blue.y > 1) {
            me.set().mastering.blue.y = 1;
        }
        if (me.v.mastering.white.x > 1) {
            me.set().mastering.white.x = 1;
        }
        if (me.v.mastering.white.y > 1) {
            me.set().mastering.white.y = 1;
        }
        if (me.v.mastering.maxLuminance > 65535.0) {
            me.set().mastering.maxLuminance = 65535.0;
        }
        if (me.v.mastering.minLuminance > 6.5535) {
            me.set().mastering.minLuminance = 6.5535;
        }
        if (me.v.maxCll > 65535.0) {
            me.set().maxCll = 65535.0;
        }
        if (me.v.maxFall > 65535.0) {
            me.set().maxFall = 65535.0;
        }
        return C2R::Ok();
    }

  private:
    std::shared_ptr<C2StreamProfileLevelInfo::input> mProfileLevel;
    std::shared_ptr<C2StreamPictureSizeInfo::output> mSize;
    std::shared_ptr<C2StreamMaxPictureSizeTuning::output> mMaxSize;
    std::shared_ptr<C2StreamMaxBufferSizeInfo::input> mMaxInputSize;
    std::shared_ptr<C2StreamColorInfo::output> mColorInfo;
    std::shared_ptr<C2StreamPixelFormatInfo::output> mPixelFormat;
    std::shared_ptr<C2StreamColorAspectsTuning::output> mDefaultColorAspects;
    std::shared_ptr<C2StreamColorAspectsInfo::input> mCodedColorAspects;
    std::shared_ptr<C2StreamColorAspectsInfo::output> mColorAspects;
    std::shared_ptr<C2StreamHdr10PlusInfo::input> mHdr10PlusInfoInput;
    std::shared_ptr<C2StreamHdr10PlusInfo::output> mHdr10PlusInfoOutput;
    std::shared_ptr<C2StreamHdrStaticInfo::output> mHdrStaticInfo;
};

C2SoftDav1dDec::C2SoftDav1dDec(const char* name, c2_node_id_t id,
                               const std::shared_ptr<IntfImpl>& intfImpl)
    : SimpleC2Component(std::make_shared<SimpleInterface<IntfImpl>>(name, id, intfImpl)),
      mIntf(intfImpl) {
    mTimeStart = mTimeEnd = systemTime();
}

C2SoftDav1dDec::~C2SoftDav1dDec() {
    onRelease();
}

c2_status_t C2SoftDav1dDec::onInit() {
    return initDecoder() ? C2_OK : C2_CORRUPTED;
}

c2_status_t C2SoftDav1dDec::onStop() {
    // TODO: b/277797541 - investigate if the decoder needs to be flushed.
    mSignalledError = false;
    mSignalledOutputEos = false;
    return C2_OK;
}

void C2SoftDav1dDec::onReset() {
    (void)onStop();
    c2_status_t err = onFlush_sm();
    if (err != C2_OK) {
        ALOGW("Failed to flush the av1 decoder. Trying to hard reset.");
        destroyDecoder();
        if (!initDecoder()) {
            ALOGE("Hard reset failed.");
        }
    }
}

void C2SoftDav1dDec::flushDav1d() {
    if (mDav1dCtx) {
        Dav1dPicture p;

        int res = 0;
        while (true) {
            memset(&p, 0, sizeof(p));

            if ((res = dav1d_get_picture(mDav1dCtx, &p)) < 0) {
                if (res != DAV1D_ERR(EAGAIN)) {
                    ALOGE("Error decoding frame: %s\n", strerror(DAV1D_ERR(res)));
                    break;
                } else {
                    res = 0;
                    break;
                }
            } else {
                dav1d_picture_unref(&p);
            }
        }

        dav1d_flush(mDav1dCtx);
    }
}

void C2SoftDav1dDec::onRelease() {
    destroyDecoder();
}

c2_status_t C2SoftDav1dDec::onFlush_sm() {
    flushDav1d();

    mSignalledError = false;
    mSignalledOutputEos = false;

    return C2_OK;
}

static int GetCPUCoreCount() {
    int cpuCoreCount = 1;
#if defined(_SC_NPROCESSORS_ONLN)
    cpuCoreCount = sysconf(_SC_NPROCESSORS_ONLN);
#else
    // _SC_NPROC_ONLN must be defined...
    cpuCoreCount = sysconf(_SC_NPROC_ONLN);
#endif
    CHECK(cpuCoreCount >= 1);
    ALOGV("Number of CPU cores: %d", cpuCoreCount);
    return cpuCoreCount;
}

bool C2SoftDav1dDec::initDecoder() {
#ifdef FILE_DUMP_ENABLE
    mC2SoftDav1dDump.initDumping();
#endif
    mSignalledError = false;
    mSignalledOutputEos = false;
    mHalPixelFormat = HAL_PIXEL_FORMAT_YV12;
    {
        IntfImpl::Lock lock = mIntf->lock();
        mPixelFormatInfo = mIntf->getPixelFormat_l();
    }

    const char* version = dav1d_version();

    Dav1dSettings lib_settings;
    dav1d_default_settings(&lib_settings);
    int cpu_count = GetCPUCoreCount();
    lib_settings.n_threads = std::max(cpu_count / 2, 1);  // use up to half the cores by default.

    int32_t numThreads =
            android::base::GetIntProperty(NUM_THREADS_DAV1D_PROPERTY, NUM_THREADS_DAV1D_DEFAULT);
    if (numThreads > 0) lib_settings.n_threads = numThreads;

    lib_settings.max_frame_delay = kOutputDelay;

    int res = 0;
    if ((res = dav1d_open(&mDav1dCtx, &lib_settings))) {
        ALOGE("dav1d_open failed. status: %d.", res);
        return false;
    } else {
        ALOGD("dav1d_open succeeded(n_threads=%d,version=%s).", lib_settings.n_threads, version);
    }

    return true;
}

void C2SoftDav1dDec::destroyDecoder() {
    if (mDav1dCtx) {
        dav1d_close(&mDav1dCtx);
        mDav1dCtx = nullptr;
        mOutputBufferIndex = 0;
        mInputBufferIndex = 0;
    }
#ifdef FILE_DUMP_ENABLE
    mC2SoftDav1dDump.destroyDumping();
#endif
}

void fillEmptyWork(const std::unique_ptr<C2Work>& work) {
    uint32_t flags = 0;
    if (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) {
        flags |= C2FrameData::FLAG_END_OF_STREAM;
        ALOGV("signalling end_of_stream.");
    }
    work->worklets.front()->output.flags = (C2FrameData::flags_t)flags;
    work->worklets.front()->output.buffers.clear();
    work->worklets.front()->output.ordinal = work->input.ordinal;
    work->workletsProcessed = 1u;
}

void C2SoftDav1dDec::finishWork(uint64_t index, const std::unique_ptr<C2Work>& work,
                                const std::shared_ptr<C2GraphicBlock>& block,
                                const Dav1dPicture &img) {
    std::shared_ptr<C2Buffer> buffer = createGraphicBuffer(block, C2Rect(mWidth, mHeight));
    {
        IntfImpl::Lock lock = mIntf->lock();
        buffer->setInfo(mIntf->getColorAspects_l());
    }

    auto fillWork = [buffer, index, img, this](const std::unique_ptr<C2Work>& work) {
        uint32_t flags = 0;
        if ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) &&
            (c2_cntr64_t(index) == work->input.ordinal.frameIndex)) {
            flags |= C2FrameData::FLAG_END_OF_STREAM;
            ALOGV("signalling end_of_stream.");
        }
        getHDRStaticParams(&img, work);
        getHDR10PlusInfoData(&img, work);

        work->worklets.front()->output.flags = (C2FrameData::flags_t)flags;
        work->worklets.front()->output.buffers.clear();
        work->worklets.front()->output.buffers.push_back(buffer);
        work->worklets.front()->output.ordinal = work->input.ordinal;
        work->workletsProcessed = 1u;
    };
    if (work && c2_cntr64_t(index) == work->input.ordinal.frameIndex) {
        fillWork(work);
    } else {
        finish(index, fillWork);
    }
}

void C2SoftDav1dDec::process(const std::unique_ptr<C2Work>& work,
                             const std::shared_ptr<C2BlockPool>& pool) {
    work->result = C2_OK;
    work->workletsProcessed = 0u;
    work->worklets.front()->output.configUpdate.clear();
    work->worklets.front()->output.flags = work->input.flags;
    if (mSignalledError || mSignalledOutputEos) {
        work->result = C2_BAD_VALUE;
        return;
    }

    size_t inOffset = 0u;
    size_t inSize = 0u;
    C2ReadView rView = mDummyReadView;
    if (!work->input.buffers.empty()) {
        rView = work->input.buffers[0]->data().linearBlocks().front().map().get();
        inSize = rView.capacity();
        if (inSize && rView.error()) {
            ALOGE("read view map failed %d", rView.error());
            work->result = C2_CORRUPTED;
            return;
        }
    }

    bool codecConfig = ((work->input.flags & C2FrameData::FLAG_CODEC_CONFIG) != 0);
    bool end_of_stream = ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0);

    if (codecConfig) {
        fillEmptyWork(work);
        return;
    }

    int64_t in_frameIndex = work->input.ordinal.frameIndex.peekll();
    if (inSize) {
        mInputBufferIndex = in_frameIndex;

        uint8_t* bitstream = const_cast<uint8_t*>(rView.data() + inOffset);

        mTimeStart = systemTime();
        nsecs_t delay = mTimeStart - mTimeEnd;

        // Send the bitstream data (inputBuffer) to dav1d.
        if (mDav1dCtx) {
            int i_ret = 0;

            Dav1dSequenceHeader seq;
            int res = dav1d_parse_sequence_header(&seq, bitstream, inSize);
            if (res == 0) {
                ALOGV("dav1d found a sequenceHeader (%dx%d) for in_frameIndex=%ld.", seq.max_width,
                      seq.max_height, (long)in_frameIndex);
            }

            // insert OBU TD if it is not present.
            // TODO: b/286852962
            uint8_t obu_type = (bitstream[0] >> 3) & 0xf;
            Dav1dData data;

            uint8_t* ptr = (obu_type == DAV1D_OBU_TD) ? dav1d_data_create(&data, inSize)
                                                      : dav1d_data_create(&data, inSize + 2);
            if (ptr == nullptr) {
                ALOGE("dav1d_data_create failed!");
                i_ret = -1;

            } else {
                data.m.timestamp = in_frameIndex;

                int new_Size;
                if (obu_type != DAV1D_OBU_TD) {
                    new_Size = (int)(inSize + 2);

                    // OBU TD
                    ptr[0] = 0x12;
                    ptr[1] = 0;

                    memcpy(ptr + 2, bitstream, inSize);
                } else {
                    new_Size = (int)(inSize);
                    // TODO: b/277797541 - investigate how to wrap this pointer in Dav1dData to
                    // avoid memcopy operations.
                    memcpy(ptr, bitstream, new_Size);
                }

                // ALOGV("memcpy(ptr,bitstream,inSize=%ld,new_Size=%d,in_frameIndex=%ld,timestamp=%ld,"
                //       "ptr[0,1,2,3,4]=%x,%x,%x,%x,%x)",
                //       inSize, new_Size, frameIndex, data.m.timestamp, ptr[0], ptr[1], ptr[2],
                //       ptr[3], ptr[4]);

                // Dump the bitstream data (inputBuffer) if dumping is enabled.
#ifdef FILE_DUMP_ENABLE
                mC2SoftDav1dDump.dumpInput(ptr, new_Size);
#endif

                bool b_draining = false;
                int res;

                do {
                    res = dav1d_send_data(mDav1dCtx, &data);
                    if (res < 0 && res != DAV1D_ERR(EAGAIN)) {
                        ALOGE("Decoder feed error %s!", strerror(DAV1D_ERR(res)));
                        /* bitstream decoding errors (typically DAV1D_ERR(EINVAL), are assumed
                         * to be recoverable. Other errors returned from this function are
                         * either unexpected, or considered critical failures.
                         */
                        i_ret = res == DAV1D_ERR(EINVAL) ? 0 : -1;
                        break;
                    }

                    outputBuffer(pool, work);

                } while (res == DAV1D_ERR(EAGAIN));

                if (data.sz > 0) {
                    ALOGE("unexpected data.sz=%zu after dav1d_send_data", data.sz);
                    dav1d_data_unref(&data);
                }
            }

            mTimeEnd = systemTime();
            nsecs_t decodeTime = mTimeEnd - mTimeStart;
            // ALOGV("decodeTime=%4" PRId64 " delay=%4" PRId64 "\n", decodeTime, delay);

            if (i_ret != 0) {
                ALOGE("av1 decoder failed to decode frame. status: %d.", i_ret);
                work->result = C2_CORRUPTED;
                work->workletsProcessed = 1u;
                mSignalledError = true;
                return;
            }
        }
    }

    if (end_of_stream) {
        drainInternal(DRAIN_COMPONENT_WITH_EOS, pool, work);
        mSignalledOutputEos = true;
    } else if (!inSize) {
        fillEmptyWork(work);
    }
}

void C2SoftDav1dDec::getHDRStaticParams(const Dav1dPicture* picture,
                                        const std::unique_ptr<C2Work>& work) {
    C2StreamHdrStaticMetadataInfo::output hdrStaticMetadataInfo{};
    bool infoPresent = false;

    if (picture != nullptr) {
        if (picture->mastering_display != nullptr) {
            hdrStaticMetadataInfo.mastering.red.x =
                    picture->mastering_display->primaries[0][0] / 65536.0;
            hdrStaticMetadataInfo.mastering.red.y =
                    picture->mastering_display->primaries[0][1] / 65536.0;

            hdrStaticMetadataInfo.mastering.green.x =
                    picture->mastering_display->primaries[1][0] / 65536.0;
            hdrStaticMetadataInfo.mastering.green.y =
                    picture->mastering_display->primaries[1][1] / 65536.0;

            hdrStaticMetadataInfo.mastering.blue.x =
                    picture->mastering_display->primaries[2][0] / 65536.0;
            hdrStaticMetadataInfo.mastering.blue.y =
                    picture->mastering_display->primaries[2][1] / 65536.0;

            hdrStaticMetadataInfo.mastering.white.x =
                    picture->mastering_display->white_point[0] / 65536.0;
            hdrStaticMetadataInfo.mastering.white.y =
                    picture->mastering_display->white_point[1] / 65536.0;

            hdrStaticMetadataInfo.mastering.maxLuminance =
                    picture->mastering_display->max_luminance / 256.0;
            hdrStaticMetadataInfo.mastering.minLuminance =
                    picture->mastering_display->min_luminance / 16384.0;

            infoPresent = true;
        }

        if (picture->content_light != nullptr) {
            hdrStaticMetadataInfo.maxCll = picture->content_light->max_content_light_level;
            hdrStaticMetadataInfo.maxFall = picture->content_light->max_frame_average_light_level;
            infoPresent = true;
        }
    }

    // if (infoPresent) {
    //   ALOGD("received a hdrStaticMetadataInfo (mastering.red=%f,%f mastering.green=%f,%f
    //   mastering.blue=%f,%f mastering.white=%f,%f mastering.maxLuminance=%f
    //   mastering.minLuminance=%f maxCll=%f maxFall=%f) at mOutputBufferIndex=%d.",
    //   hdrStaticMetadataInfo.mastering.red.x,hdrStaticMetadataInfo.mastering.red.y,
    //   hdrStaticMetadataInfo.mastering.green.x,hdrStaticMetadataInfo.mastering.green.y,
    //   hdrStaticMetadataInfo.mastering.blue.x,hdrStaticMetadataInfo.mastering.blue.y,
    //   hdrStaticMetadataInfo.mastering.white.x,hdrStaticMetadataInfo.mastering.white.y,
    //   hdrStaticMetadataInfo.mastering.maxLuminance,hdrStaticMetadataInfo.mastering.minLuminance,
    //   hdrStaticMetadataInfo.maxCll,
    //   hdrStaticMetadataInfo.maxFall,
    //   mOutputBufferIndex);
    // }

    // config if static info has changed
    if (infoPresent && !(hdrStaticMetadataInfo == mHdrStaticMetadataInfo)) {
        mHdrStaticMetadataInfo = hdrStaticMetadataInfo;
        work->worklets.front()->output.configUpdate.push_back(
                C2Param::Copy(mHdrStaticMetadataInfo));
    }
}

void C2SoftDav1dDec::getHDR10PlusInfoData(const Dav1dPicture* picture,
                                          const std::unique_ptr<C2Work>& work) {
    if (picture != nullptr) {
        if (picture->itut_t35 != nullptr) {
            std::vector<uint8_t> payload;
            size_t payloadSize = picture->itut_t35->payload_size;
            if (payloadSize > 0) {
                payload.push_back(picture->itut_t35->country_code);
                if (picture->itut_t35->country_code == 0xFF) {
                    payload.push_back(picture->itut_t35->country_code_extension_byte);
                }
                payload.insert(payload.end(), picture->itut_t35->payload,
                               picture->itut_t35->payload + picture->itut_t35->payload_size);
            }

            std::unique_ptr<C2StreamHdr10PlusInfo::output> hdr10PlusInfo =
                    C2StreamHdr10PlusInfo::output::AllocUnique(payload.size());
            if (!hdr10PlusInfo) {
                ALOGE("Hdr10PlusInfo allocation failed");
                mSignalledError = true;
                work->result = C2_NO_MEMORY;
                return;
            }
            memcpy(hdr10PlusInfo->m.value, payload.data(), payload.size());

            // ALOGD("Received a hdr10PlusInfo from picture->itut_t32
            // (payload_size=%ld,country_code=%d) at mOutputBufferIndex=%d.",
            // picture->itut_t35->payload_size,
            // picture->itut_t35->country_code,
            // mOutputBufferIndex);

            // config if hdr10Plus info has changed
            if (nullptr == mHdr10PlusInfo || !(*hdr10PlusInfo == *mHdr10PlusInfo)) {
                mHdr10PlusInfo = std::move(hdr10PlusInfo);
                work->worklets.front()->output.configUpdate.push_back(std::move(mHdr10PlusInfo));
            }
        }
    }
}

void C2SoftDav1dDec::getVuiParams(const Dav1dPicture* picture) {
    VuiColorAspects vuiColorAspects;

    if (picture) {
        vuiColorAspects.primaries = picture->seq_hdr->pri;
        vuiColorAspects.transfer = picture->seq_hdr->trc;
        vuiColorAspects.coeffs = picture->seq_hdr->mtrx;
        vuiColorAspects.fullRange = picture->seq_hdr->color_range;

        // ALOGD("Received a vuiColorAspects from dav1d
        //       (primaries = % d, transfer = % d, coeffs = % d, fullRange = % d)
        //               at mOutputBufferIndex = % d,
        //       out_frameIndex = % ld.",
        //                          vuiColorAspects.primaries,
        //       vuiColorAspects.transfer, vuiColorAspects.coeffs, vuiColorAspects.fullRange,
        //       mOutputBufferIndex, picture->m.timestamp);
    }

    // convert vui aspects to C2 values if changed
    if (!(vuiColorAspects == mBitstreamColorAspects)) {
        mBitstreamColorAspects = vuiColorAspects;
        ColorAspects sfAspects;
        C2StreamColorAspectsInfo::input codedAspects = {0u};
        ColorUtils::convertIsoColorAspectsToCodecAspects(
                vuiColorAspects.primaries, vuiColorAspects.transfer, vuiColorAspects.coeffs,
                vuiColorAspects.fullRange, sfAspects);
        if (!C2Mapper::map(sfAspects.mPrimaries, &codedAspects.primaries)) {
            codedAspects.primaries = C2Color::PRIMARIES_UNSPECIFIED;
        }
        if (!C2Mapper::map(sfAspects.mRange, &codedAspects.range)) {
            codedAspects.range = C2Color::RANGE_UNSPECIFIED;
        }
        if (!C2Mapper::map(sfAspects.mMatrixCoeffs, &codedAspects.matrix)) {
            codedAspects.matrix = C2Color::MATRIX_UNSPECIFIED;
        }
        if (!C2Mapper::map(sfAspects.mTransfer, &codedAspects.transfer)) {
            codedAspects.transfer = C2Color::TRANSFER_UNSPECIFIED;
        }
        std::vector<std::unique_ptr<C2SettingResult>> failures;
        mIntf->config({&codedAspects}, C2_MAY_BLOCK, &failures);
    }
}

void C2SoftDav1dDec::setError(const std::unique_ptr<C2Work>& work, c2_status_t error) {
    mSignalledError = true;
    work->result = error;
    work->workletsProcessed = 1u;
}

bool C2SoftDav1dDec::allocTmpFrameBuffer(size_t size) {
    if (size > mTmpFrameBufferSize) {
        mTmpFrameBuffer = std::make_unique<uint16_t[]>(size);
        if (mTmpFrameBuffer == nullptr) {
            mTmpFrameBufferSize = 0;
            return false;
        }
        mTmpFrameBufferSize = size;
    }
    return true;
}

bool C2SoftDav1dDec::outputBuffer(const std::shared_ptr<C2BlockPool>& pool,
                                  const std::unique_ptr<C2Work>& work) {
    if (!(work && pool)) return false;
    if (mDav1dCtx == nullptr) return false;

    // Get a decoded picture from dav1d if it is enabled.
    Dav1dPicture img;
    memset(&img, 0, sizeof(img));

    int res = 0;
    res = dav1d_get_picture(mDav1dCtx, &img);
    if (res == DAV1D_ERR(EAGAIN)) {
        ALOGV("Not enough data to output a picture.");
        return false;
    } else if (res != 0) {
        ALOGE("The AV1 decoder failed to get a picture (res=%s).", strerror(DAV1D_ERR(res)));
        return false;
    }

    const int width = img.p.w;
    const int height = img.p.h;
    if (width != mWidth || height != mHeight) {
        mWidth = width;
        mHeight = height;

        C2StreamPictureSizeInfo::output size(0u, mWidth, mHeight);
        std::vector<std::unique_ptr<C2SettingResult>> failures;
        c2_status_t err = mIntf->config({&size}, C2_MAY_BLOCK, &failures);
        if (err == C2_OK) {
            work->worklets.front()->output.configUpdate.push_back(C2Param::Copy(size));
        } else {
            ALOGE("Config update size failed");
            mSignalledError = true;
            work->result = C2_CORRUPTED;
            work->workletsProcessed = 1u;
            return false;
        }
    }

    getVuiParams(&img);

    // out_frameIndex that the decoded picture returns from dav1d.
    int64_t out_frameIndex = img.m.timestamp;

    const bool isMonochrome = img.p.layout == DAV1D_PIXEL_LAYOUT_I400;

    int bitdepth = img.p.bpc;

    std::shared_ptr<C2GraphicBlock> block;
    uint32_t format = HAL_PIXEL_FORMAT_YV12;
    std::shared_ptr<C2StreamColorAspectsInfo::output> codedColorAspects;
    if (bitdepth == 10 && mPixelFormatInfo->value != HAL_PIXEL_FORMAT_YCBCR_420_888) {
        IntfImpl::Lock lock = mIntf->lock();
        codedColorAspects = mIntf->getColorAspects_l();
        bool allowRGBA1010102 = false;
        if (codedColorAspects->primaries == C2Color::PRIMARIES_BT2020 &&
            codedColorAspects->matrix == C2Color::MATRIX_BT2020 &&
            codedColorAspects->transfer == C2Color::TRANSFER_ST2084) {
            allowRGBA1010102 = true;
        }
        format = getHalPixelFormatForBitDepth10(allowRGBA1010102);
    }

    if (mHalPixelFormat != format) {
        C2StreamPixelFormatInfo::output pixelFormat(0u, format);
        std::vector<std::unique_ptr<C2SettingResult>> failures;
        c2_status_t err = mIntf->config({&pixelFormat}, C2_MAY_BLOCK, &failures);
        if (err == C2_OK) {
            work->worklets.front()->output.configUpdate.push_back(C2Param::Copy(pixelFormat));
        } else {
            ALOGE("Config update pixelFormat failed");
            mSignalledError = true;
            work->workletsProcessed = 1u;
            work->result = C2_CORRUPTED;
            return UNKNOWN_ERROR;
        }
        mHalPixelFormat = format;
    }

    C2MemoryUsage usage = {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE};

    // We always create a graphic block that is width aligned to 16 and height
    // aligned to 2. We set the correct "crop" value of the image in the call to
    // createGraphicBuffer() by setting the correct image dimensions.
    c2_status_t err =
            pool->fetchGraphicBlock(align(mWidth, 16), align(mHeight, 2), format, usage, &block);

    if (err != C2_OK) {
        ALOGE("fetchGraphicBlock for Output failed with status %d", err);
        work->result = err;
        return false;
    }

    C2GraphicView wView = block->map().get();

    if (wView.error()) {
        ALOGE("graphic view map failed %d", wView.error());
        work->result = C2_CORRUPTED;
        return false;
    }

    // ALOGV("provided (%dx%d) required (%dx%d), out frameindex %d", block->width(),
    //       block->height(), mWidth, mHeight, (int)out_frameIndex);

    mOutputBufferIndex = out_frameIndex;

    uint8_t* dstY = const_cast<uint8_t*>(wView.data()[C2PlanarLayout::PLANE_Y]);
    uint8_t* dstU = const_cast<uint8_t*>(wView.data()[C2PlanarLayout::PLANE_U]);
    uint8_t* dstV = const_cast<uint8_t*>(wView.data()[C2PlanarLayout::PLANE_V]);

    C2PlanarLayout layout = wView.layout();
    size_t dstYStride = layout.planes[C2PlanarLayout::PLANE_Y].rowInc;
    size_t dstUStride = layout.planes[C2PlanarLayout::PLANE_U].rowInc;
    size_t dstVStride = layout.planes[C2PlanarLayout::PLANE_V].rowInc;

    CONV_FORMAT_T convFormat;
    switch (img.p.layout) {
        case DAV1D_PIXEL_LAYOUT_I444:
            convFormat = CONV_FORMAT_I444;
            break;
        case DAV1D_PIXEL_LAYOUT_I422:
            convFormat = CONV_FORMAT_I422;
            break;
        default:
            convFormat = CONV_FORMAT_I420;
            break;
    }

    if (bitdepth == 10) {
        // TODO: b/277797541 - Investigate if we can ask DAV1D to output the required format during
        // decompression to avoid color conversion.
        const uint16_t* srcY = (const uint16_t*)img.data[0];
        const uint16_t* srcU = (const uint16_t*)img.data[1];
        const uint16_t* srcV = (const uint16_t*)img.data[2];
        size_t srcYStride = img.stride[0] / 2;
        size_t srcUStride = img.stride[1] / 2;
        size_t srcVStride = img.stride[1] / 2;

        if (format == HAL_PIXEL_FORMAT_RGBA_1010102) {
            if (isMonochrome) {
                const size_t tmpSize = mWidth;
                const bool needFill = tmpSize > mTmpFrameBufferSize;
                if (!allocTmpFrameBuffer(tmpSize)) {
                    ALOGE("Error allocating temp conversion buffer (%zu bytes)", tmpSize);
                    setError(work, C2_NO_MEMORY);
                    return false;
                }
                srcU = srcV = mTmpFrameBuffer.get();
                srcUStride = srcVStride = 0;
                if (needFill) {
                    std::fill_n(mTmpFrameBuffer.get(), tmpSize, 512);
                }
            }
            convertPlanar16ToY410OrRGBA1010102(
                    dstY, srcY, srcU, srcV, srcYStride, srcUStride, srcVStride,
                    dstYStride, mWidth, mHeight,
                    std::static_pointer_cast<const C2ColorAspectsStruct>(codedColorAspects),
                    convFormat);
        } else if (format == HAL_PIXEL_FORMAT_YCBCR_P010) {
            dstYStride /= 2;
            dstUStride /= 2;
            dstVStride /= 2;
            size_t tmpSize = 0;
            if ((img.p.layout == DAV1D_PIXEL_LAYOUT_I444) ||
                (img.p.layout == DAV1D_PIXEL_LAYOUT_I422)) {
                tmpSize = dstYStride * mHeight + dstUStride * align(mHeight, 2);
                if (!allocTmpFrameBuffer(tmpSize)) {
                    ALOGE("Error allocating temp conversion buffer (%zu bytes)", tmpSize);
                    setError(work, C2_NO_MEMORY);
                    return false;
                }
            }
            convertPlanar16ToP010((uint16_t*)dstY, (uint16_t*)dstU, srcY, srcU, srcV, srcYStride,
                                  srcUStride, srcVStride, dstYStride, dstUStride, dstVStride,
                                  mWidth, mHeight, isMonochrome, convFormat, mTmpFrameBuffer.get(),
                                  tmpSize);
        } else {
            size_t tmpSize = 0;
            if (img.p.layout == DAV1D_PIXEL_LAYOUT_I444) {
                tmpSize = dstYStride * mHeight + dstUStride * align(mHeight, 2);
                if (!allocTmpFrameBuffer(tmpSize)) {
                    ALOGE("Error allocating temp conversion buffer (%zu bytes)", tmpSize);
                    setError(work, C2_NO_MEMORY);
                    return false;
                }
            }
            convertPlanar16ToYV12(dstY, dstU, dstV, srcY, srcU, srcV, srcYStride, srcUStride,
                                  srcVStride, dstYStride, dstUStride, dstVStride, mWidth, mHeight,
                                  isMonochrome, convFormat, mTmpFrameBuffer.get(), tmpSize);
        }

        // if(mOutputBufferIndex % 100 == 0)
        ALOGV("output a 10bit picture %dx%d from dav1d "
              "(mInputBufferIndex=%d,mOutputBufferIndex=%d,format=%d).",
              mWidth, mHeight, mInputBufferIndex, mOutputBufferIndex, format);

        // Dump the output buffer if dumping is enabled (debug only).
#ifdef FILE_DUMP_ENABLE
        mC2SoftDav1dDump.dumpOutput<uint16_t>(srcY, srcU, srcV, srcYStride, srcUStride, srcVStride,
                                              mWidth, mHeight);
#endif
    } else {
        const uint8_t* srcY = (const uint8_t*)img.data[0];
        const uint8_t* srcU = (const uint8_t*)img.data[1];
        const uint8_t* srcV = (const uint8_t*)img.data[2];

        size_t srcYStride = img.stride[0];
        size_t srcUStride = img.stride[1];
        size_t srcVStride = img.stride[1];

        // if(mOutputBufferIndex % 100 == 0)
        ALOGV("output a 8bit picture %dx%d from dav1d "
              "(mInputBufferIndex=%d,mOutputBufferIndex=%d,format=%d).",
              mWidth, mHeight, mInputBufferIndex, mOutputBufferIndex, format);

        // Dump the output buffer is dumping is enabled (debug only)
#ifdef FILE_DUMP_ENABLE
        mC2SoftDav1dDump.dumpOutput<uint8_t>(srcY, srcU, srcV, srcYStride, srcUStride, srcVStride,
                                             mWidth, mHeight);
#endif
        convertPlanar8ToYV12(dstY, dstU, dstV, srcY, srcU, srcV, srcYStride, srcUStride, srcVStride,
                             dstYStride, dstUStride, dstVStride, mWidth, mHeight, isMonochrome,
                             convFormat);
    }

    finishWork(out_frameIndex, work, std::move(block), img);
    dav1d_picture_unref(&img);
    block = nullptr;
    return true;
}

c2_status_t C2SoftDav1dDec::drainInternal(uint32_t drainMode,
                                          const std::shared_ptr<C2BlockPool>& pool,
                                          const std::unique_ptr<C2Work>& work) {
    if (drainMode == NO_DRAIN) {
        ALOGW("drain with NO_DRAIN: no-op");
        return C2_OK;
    }
    if (drainMode == DRAIN_CHAIN) {
        ALOGW("DRAIN_CHAIN not supported");
        return C2_OMITTED;
    }

    while (outputBuffer(pool, work)) {
    }

    if (drainMode == DRAIN_COMPONENT_WITH_EOS && work && work->workletsProcessed == 0u) {
        fillEmptyWork(work);
    }

    return C2_OK;
}

c2_status_t C2SoftDav1dDec::drain(uint32_t drainMode, const std::shared_ptr<C2BlockPool>& pool) {
    return drainInternal(drainMode, pool, nullptr);
}

class C2SoftDav1dFactory : public C2ComponentFactory {
  public:
    C2SoftDav1dFactory()
        : mHelper(std::static_pointer_cast<C2ReflectorHelper>(
                  GetCodec2PlatformComponentStore()->getParamReflector())) {}

    virtual c2_status_t createComponent(c2_node_id_t id,
                                        std::shared_ptr<C2Component>* const component,
                                        std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(
                new C2SoftDav1dDec(COMPONENT_NAME, id,
                                   std::make_shared<C2SoftDav1dDec::IntfImpl>(mHelper)),
                deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id, std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = std::shared_ptr<C2ComponentInterface>(
                new SimpleInterface<C2SoftDav1dDec::IntfImpl>(
                        COMPONENT_NAME, id, std::make_shared<C2SoftDav1dDec::IntfImpl>(mHelper)),
                deleter);
        return C2_OK;
    }

    virtual ~C2SoftDav1dFactory() override = default;

  private:
    std::shared_ptr<C2ReflectorHelper> mHelper;
};

}  // namespace android

__attribute__((cfi_canonical_jump_table)) extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftDav1dFactory();
}

__attribute__((cfi_canonical_jump_table)) extern "C" void DestroyCodec2Factory(
        ::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
