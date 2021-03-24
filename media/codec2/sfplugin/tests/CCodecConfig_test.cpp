/*
 * Copyright 2019 The Android Open Source Project
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

#include "CCodecConfig.h"

#include <set>

#include <gtest/gtest.h>

#include <codec2/hidl/1.0/Configurable.h>
#include <codec2/hidl/client.h>
#include <util/C2InterfaceHelper.h>

#include <media/stagefright/MediaCodecConstants.h>

namespace {

enum ExtendedC2ParamIndexKind : C2Param::type_index_t {
    kParamIndexVendorInt32 = C2Param::TYPE_INDEX_VENDOR_START,
    kParamIndexVendorInt64,
    kParamIndexVendorString,
};

typedef C2PortParam<C2Info, C2Int32Value, kParamIndexVendorInt32> C2PortVendorInt32Info;
constexpr char C2_PARAMKEY_VENDOR_INT32[] = "example.int32";
constexpr char KEY_VENDOR_INT32[] = "vendor.example.int32.value";

typedef C2StreamParam<C2Info, C2Int64Value, kParamIndexVendorInt64> C2StreamVendorInt64Info;
constexpr char C2_PARAMKEY_VENDOR_INT64[] = "example.int64";
constexpr char KEY_VENDOR_INT64[] = "vendor.example.int64.value";

typedef C2PortParam<C2Info, C2StringValue, kParamIndexVendorString> C2PortVendorStringInfo;
constexpr char C2_PARAMKEY_VENDOR_STRING[] = "example.string";
constexpr char KEY_VENDOR_STRING[] = "vendor.example.string.value";

}  // namespace

namespace android {

class CCodecConfigTest : public ::testing::Test {
public:
    constexpr static int32_t kCodec2Int32 = 0xC0DEC2;
    constexpr static int64_t kCodec2Int64 = 0xC0DEC2C0DEC2ll;
    constexpr static char kCodec2Str[] = "codec2";

    CCodecConfigTest()
        : mReflector{std::make_shared<C2ReflectorHelper>()} {
    }

    void init(
            C2Component::domain_t domain,
            C2Component::kind_t kind,
            const char *mediaType) {
        sp<hardware::media::c2::V1_0::utils::CachedConfigurable> cachedConfigurable =
            new hardware::media::c2::V1_0::utils::CachedConfigurable(
                    std::make_unique<Configurable>(mReflector, domain, kind, mediaType));
        cachedConfigurable->init(std::make_shared<Cache>());
        mConfigurable = std::make_shared<Codec2Client::Configurable>(cachedConfigurable);
    }

    struct Cache : public hardware::media::c2::V1_0::utils::ParameterCache {
        c2_status_t validate(const std::vector<std::shared_ptr<C2ParamDescriptor>>&) override {
            return C2_OK;
        }
    };

    class Configurable : public hardware::media::c2::V1_0::utils::ConfigurableC2Intf {
    public:
        Configurable(
                const std::shared_ptr<C2ReflectorHelper> &reflector,
                C2Component::domain_t domain,
                C2Component::kind_t kind,
                const char *mediaType)
            : ConfigurableC2Intf("name", 0u),
              mImpl(reflector, domain, kind, mediaType) {
        }

        c2_status_t query(
                const std::vector<C2Param::Index> &indices,
                c2_blocking_t mayBlock,
                std::vector<std::unique_ptr<C2Param>>* const params) const override {
            return mImpl.query({}, indices, mayBlock, params);
        }

        c2_status_t config(
                const std::vector<C2Param*> &params,
                c2_blocking_t mayBlock,
                std::vector<std::unique_ptr<C2SettingResult>>* const failures) override {
            return mImpl.config(params, mayBlock, failures);
        }

        c2_status_t querySupportedParams(
                std::vector<std::shared_ptr<C2ParamDescriptor>>* const params) const override {
            return mImpl.querySupportedParams(params);
        }

        c2_status_t querySupportedValues(
                std::vector<C2FieldSupportedValuesQuery>& fields,
                c2_blocking_t mayBlock) const override {
            return mImpl.querySupportedValues(fields, mayBlock);
        }

    private:
        class Impl : public C2InterfaceHelper {
        public:
            Impl(const std::shared_ptr<C2ReflectorHelper> &reflector,
                    C2Component::domain_t domain,
                    C2Component::kind_t kind,
                    const char *mediaType)
                : C2InterfaceHelper{reflector} {

                setDerivedInstance(this);

                addParameter(
                        DefineParam(mDomain, C2_PARAMKEY_COMPONENT_DOMAIN)
                        .withConstValue(new C2ComponentDomainSetting(domain))
                        .build());

                addParameter(
                        DefineParam(mKind, C2_PARAMKEY_COMPONENT_KIND)
                        .withConstValue(new C2ComponentKindSetting(kind))
                        .build());

                addParameter(
                        DefineParam(mInputStreamCount, C2_PARAMKEY_INPUT_STREAM_COUNT)
                        .withConstValue(new C2PortStreamCountTuning::input(1))
                        .build());

                addParameter(
                        DefineParam(mOutputStreamCount, C2_PARAMKEY_OUTPUT_STREAM_COUNT)
                        .withConstValue(new C2PortStreamCountTuning::output(1))
                        .build());

                const char *rawMediaType = "";
                switch (domain) {
                    case C2Component::DOMAIN_IMAGE: [[fallthrough]];
                    case C2Component::DOMAIN_VIDEO:
                        rawMediaType = MIMETYPE_VIDEO_RAW;
                        break;
                    case C2Component::DOMAIN_AUDIO:
                        rawMediaType = MIMETYPE_AUDIO_RAW;
                        break;
                    default:
                        break;
                }
                bool isEncoder = kind == C2Component::KIND_ENCODER;
                std::string inputMediaType{isEncoder ? rawMediaType : mediaType};
                std::string outputMediaType{isEncoder ? mediaType : rawMediaType};

                auto allocSharedString = [](const auto &param, const std::string &str) {
                    typedef typename std::remove_reference<decltype(param)>::type::element_type T;
                    std::shared_ptr<T> ret = T::AllocShared(str.length() + 1);
                    strcpy(ret->m.value, str.c_str());
                    return ret;
                };

                addParameter(
                        DefineParam(mInputMediaType, C2_PARAMKEY_INPUT_MEDIA_TYPE)
                        .withConstValue(allocSharedString(mInputMediaType, inputMediaType))
                        .build());

                addParameter(
                        DefineParam(mOutputMediaType, C2_PARAMKEY_OUTPUT_MEDIA_TYPE)
                        .withConstValue(allocSharedString(mOutputMediaType, outputMediaType))
                        .build());

                addParameter(
                        DefineParam(mInt32Input, C2_PARAMKEY_VENDOR_INT32)
                        .withDefault(new C2PortVendorInt32Info::input(0))
                        .withFields({C2F(mInt32Input, value).any()})
                        .withSetter(Setter<decltype(mInt32Input)::element_type>)
                        .build());

                addParameter(
                        DefineParam(mInt64Output, C2_PARAMKEY_VENDOR_INT64)
                        .withDefault(new C2StreamVendorInt64Info::output(0u, 0))
                        .withFields({C2F(mInt64Output, value).any()})
                        .withSetter(Setter<decltype(mInt64Output)::element_type>)
                        .build());

                addParameter(
                        DefineParam(mStringInput, C2_PARAMKEY_VENDOR_STRING)
                        .withDefault(decltype(mStringInput)::element_type::AllocShared(1, ""))
                        .withFields({C2F(mStringInput, m.value).any()})
                        .withSetter(Setter<decltype(mStringInput)::element_type>)
                        .build());

                addParameter(
                        DefineParam(mPixelAspectRatio, C2_PARAMKEY_PIXEL_ASPECT_RATIO)
                        .withDefault(new C2StreamPixelAspectRatioInfo::output(0u, 1, 1))
                        .withFields({
                            C2F(mPixelAspectRatio, width).any(),
                            C2F(mPixelAspectRatio, height).any(),
                        })
                        .withSetter(Setter<C2StreamPixelAspectRatioInfo::output>)
                        .build());

                if (isEncoder) {
                    addParameter(
                            DefineParam(mInputBitrate, C2_PARAMKEY_BITRATE)
                            .withDefault(new C2StreamBitrateInfo::input(0u))
                            .withFields({C2F(mInputBitrate, value).any()})
                            .withSetter(Setter<C2StreamBitrateInfo::input>)
                            .build());

                    addParameter(
                            DefineParam(mOutputBitrate, C2_PARAMKEY_BITRATE)
                            .withDefault(new C2StreamBitrateInfo::output(0u))
                            .withFields({C2F(mOutputBitrate, value).any()})
                            .calculatedAs(
                                Copy<C2StreamBitrateInfo::output, C2StreamBitrateInfo::input>,
                                mInputBitrate)
                            .build());
                }

                // TODO: more SDK params
            }
        private:
            std::shared_ptr<C2ComponentDomainSetting> mDomain;
            std::shared_ptr<C2ComponentKindSetting> mKind;
            std::shared_ptr<C2PortStreamCountTuning::input> mInputStreamCount;
            std::shared_ptr<C2PortStreamCountTuning::output> mOutputStreamCount;
            std::shared_ptr<C2PortMediaTypeSetting::input> mInputMediaType;
            std::shared_ptr<C2PortMediaTypeSetting::output> mOutputMediaType;
            std::shared_ptr<C2PortVendorInt32Info::input> mInt32Input;
            std::shared_ptr<C2StreamVendorInt64Info::output> mInt64Output;
            std::shared_ptr<C2PortVendorStringInfo::input> mStringInput;
            std::shared_ptr<C2StreamPixelAspectRatioInfo::output> mPixelAspectRatio;
            std::shared_ptr<C2StreamBitrateInfo::input> mInputBitrate;
            std::shared_ptr<C2StreamBitrateInfo::output> mOutputBitrate;

            template<typename T>
            static C2R Setter(bool, C2P<T> &) {
                return C2R::Ok();
            }

            template<typename ME, typename DEP>
            static C2R Copy(bool, C2P<ME> &me, const C2P<DEP> &dep) {
                me.set().value = dep.v.value;
                return C2R::Ok();
            }
        };

        Impl mImpl;
    };

    std::shared_ptr<C2ReflectorHelper> mReflector;
    std::shared_ptr<Codec2Client::Configurable> mConfigurable;
    CCodecConfig mConfig;
};

using D = CCodecConfig::Domain;

template<typename T>
T *FindParam(const std::vector<std::unique_ptr<C2Param>> &vec) {
    for (const std::unique_ptr<C2Param> &param : vec) {
        if (param->coreIndex() == T::CORE_INDEX) {
            return static_cast<T *>(param.get());
        }
    }
    return nullptr;
}

TEST_F(CCodecConfigTest, SetVendorParam) {
    // Test at audio domain, as video domain has a few local parameters that
    // interfere with the testing.
    init(C2Component::DOMAIN_AUDIO, C2Component::KIND_DECODER, MIMETYPE_AUDIO_AAC);

    ASSERT_EQ(OK, mConfig.initialize(mReflector, mConfigurable));

    sp<AMessage> format{new AMessage};
    format->setInt32(KEY_VENDOR_INT32, kCodec2Int32);
    format->setInt64(KEY_VENDOR_INT64, kCodec2Int64);
    format->setString(KEY_VENDOR_STRING, kCodec2Str);

    std::vector<std::unique_ptr<C2Param>> configUpdate;
    ASSERT_EQ(OK, mConfig.getConfigUpdateFromSdkParams(
            mConfigurable, format, D::ALL, C2_MAY_BLOCK, &configUpdate));

    ASSERT_EQ(3u, configUpdate.size());
    C2PortVendorInt32Info::input *i32 =
        FindParam<std::remove_pointer<decltype(i32)>::type>(configUpdate);
    ASSERT_NE(nullptr, i32);
    ASSERT_EQ(kCodec2Int32, i32->value);

    C2StreamVendorInt64Info::output *i64 =
        FindParam<std::remove_pointer<decltype(i64)>::type>(configUpdate);
    ASSERT_NE(nullptr, i64);
    ASSERT_EQ(kCodec2Int64, i64->value);

    C2PortVendorStringInfo::input *str =
        FindParam<std::remove_pointer<decltype(str)>::type>(configUpdate);
    ASSERT_NE(nullptr, str);
    ASSERT_STREQ(kCodec2Str, str->m.value);
}

TEST_F(CCodecConfigTest, VendorParamUpdate_Unsubscribed) {
    // Test at audio domain, as video domain has a few local parameters that
    // interfere with the testing.
    init(C2Component::DOMAIN_AUDIO, C2Component::KIND_DECODER, MIMETYPE_AUDIO_AAC);

    ASSERT_EQ(OK, mConfig.initialize(mReflector, mConfigurable));

    std::vector<std::unique_ptr<C2Param>> configUpdate;
    C2PortVendorInt32Info::input i32(kCodec2Int32);
    C2StreamVendorInt64Info::output i64(0u, kCodec2Int64);
    std::unique_ptr<C2PortVendorStringInfo::input> str =
        C2PortVendorStringInfo::input::AllocUnique(strlen(kCodec2Str) + 1, kCodec2Str);
    configUpdate.push_back(C2Param::Copy(i32));
    configUpdate.push_back(C2Param::Copy(i64));
    configUpdate.push_back(std::move(str));

    // The vendor parameters are not yet subscribed
    ASSERT_FALSE(mConfig.updateConfiguration(configUpdate, D::ALL));

    int32_t vendorInt32{0};
    ASSERT_FALSE(mConfig.mInputFormat->findInt32(KEY_VENDOR_INT32, &vendorInt32))
            << "mInputFormat = " << mConfig.mInputFormat->debugString().c_str();
    ASSERT_FALSE(mConfig.mOutputFormat->findInt32(KEY_VENDOR_INT32, &vendorInt32))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();

    int64_t vendorInt64{0};
    ASSERT_FALSE(mConfig.mInputFormat->findInt64(KEY_VENDOR_INT64, &vendorInt64))
            << "mInputFormat = " << mConfig.mInputFormat->debugString().c_str();
    ASSERT_FALSE(mConfig.mOutputFormat->findInt64(KEY_VENDOR_INT64, &vendorInt64))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();

    AString vendorString;
    ASSERT_FALSE(mConfig.mInputFormat->findString(KEY_VENDOR_STRING, &vendorString))
            << "mInputFormat = " << mConfig.mInputFormat->debugString().c_str();
    ASSERT_FALSE(mConfig.mOutputFormat->findString(KEY_VENDOR_STRING, &vendorString))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();
}

TEST_F(CCodecConfigTest, VendorParamUpdate_AllSubscribed) {
    // Test at audio domain, as video domain has a few local parameters that
    // interfere with the testing.
    init(C2Component::DOMAIN_AUDIO, C2Component::KIND_DECODER, MIMETYPE_AUDIO_AAC);

    ASSERT_EQ(OK, mConfig.initialize(mReflector, mConfigurable));

    // Force subscribe to all vendor params
    ASSERT_EQ(OK, mConfig.subscribeToAllVendorParams(mConfigurable, C2_MAY_BLOCK));

    std::vector<std::unique_ptr<C2Param>> configUpdate;
    C2PortVendorInt32Info::input i32(kCodec2Int32);
    C2StreamVendorInt64Info::output i64(0u, kCodec2Int64);
    std::unique_ptr<C2PortVendorStringInfo::input> str =
        C2PortVendorStringInfo::input::AllocUnique(strlen(kCodec2Str) + 1, kCodec2Str);
    configUpdate.push_back(C2Param::Copy(i32));
    configUpdate.push_back(C2Param::Copy(i64));
    configUpdate.push_back(std::move(str));

    ASSERT_TRUE(mConfig.updateConfiguration(configUpdate, D::ALL));

    int32_t vendorInt32{0};
    ASSERT_TRUE(mConfig.mInputFormat->findInt32(KEY_VENDOR_INT32, &vendorInt32))
            << "mInputFormat = " << mConfig.mInputFormat->debugString().c_str();
    ASSERT_EQ(kCodec2Int32, vendorInt32);
    ASSERT_FALSE(mConfig.mOutputFormat->findInt32(KEY_VENDOR_INT32, &vendorInt32))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();

    int64_t vendorInt64{0};
    ASSERT_FALSE(mConfig.mInputFormat->findInt64(KEY_VENDOR_INT64, &vendorInt64))
            << "mInputFormat = " << mConfig.mInputFormat->debugString().c_str();
    ASSERT_TRUE(mConfig.mOutputFormat->findInt64(KEY_VENDOR_INT64, &vendorInt64))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();
    ASSERT_EQ(kCodec2Int64, vendorInt64);

    AString vendorString;
    ASSERT_TRUE(mConfig.mInputFormat->findString(KEY_VENDOR_STRING, &vendorString))
            << "mInputFormat = " << mConfig.mInputFormat->debugString().c_str();
    ASSERT_STREQ(kCodec2Str, vendorString.c_str());
    ASSERT_FALSE(mConfig.mOutputFormat->findString(KEY_VENDOR_STRING, &vendorString))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();
}

TEST_F(CCodecConfigTest, VendorParamUpdate_PartiallySubscribed) {
    // Test at audio domain, as video domain has a few local parameters that
    // interfere with the testing.
    init(C2Component::DOMAIN_AUDIO, C2Component::KIND_DECODER, MIMETYPE_AUDIO_AAC);

    ASSERT_EQ(OK, mConfig.initialize(mReflector, mConfigurable));

    // Subscribe to example.int32 only
    std::vector<std::unique_ptr<C2Param>> configUpdate;
    sp<AMessage> format{new AMessage};
    format->setInt32(KEY_VENDOR_INT32, 0);
    configUpdate.clear();
    ASSERT_EQ(OK, mConfig.getConfigUpdateFromSdkParams(
            mConfigurable, format, D::ALL, C2_MAY_BLOCK, &configUpdate));
    ASSERT_EQ(OK, mConfig.setParameters(mConfigurable, configUpdate, C2_MAY_BLOCK));

    C2PortVendorInt32Info::input i32(kCodec2Int32);
    C2StreamVendorInt64Info::output i64(0u, kCodec2Int64);
    std::unique_ptr<C2PortVendorStringInfo::input> str =
        C2PortVendorStringInfo::input::AllocUnique(strlen(kCodec2Str) + 1, kCodec2Str);
    configUpdate.clear();
    configUpdate.push_back(C2Param::Copy(i32));
    configUpdate.push_back(C2Param::Copy(i64));
    configUpdate.push_back(std::move(str));

    // Only example.i32 should be updated
    ASSERT_TRUE(mConfig.updateConfiguration(configUpdate, D::ALL));

    int32_t vendorInt32{0};
    ASSERT_TRUE(mConfig.mInputFormat->findInt32(KEY_VENDOR_INT32, &vendorInt32))
            << "mInputFormat = " << mConfig.mInputFormat->debugString().c_str();
    ASSERT_EQ(kCodec2Int32, vendorInt32);
    ASSERT_FALSE(mConfig.mOutputFormat->findInt32(KEY_VENDOR_INT32, &vendorInt32))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();

    int64_t vendorInt64{0};
    ASSERT_FALSE(mConfig.mInputFormat->findInt64(KEY_VENDOR_INT64, &vendorInt64))
            << "mInputFormat = " << mConfig.mInputFormat->debugString().c_str();
    ASSERT_FALSE(mConfig.mOutputFormat->findInt64(KEY_VENDOR_INT64, &vendorInt64))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();

    AString vendorString;
    ASSERT_FALSE(mConfig.mInputFormat->findString(KEY_VENDOR_STRING, &vendorString))
            << "mInputFormat = " << mConfig.mInputFormat->debugString().c_str();
    ASSERT_FALSE(mConfig.mOutputFormat->findString(KEY_VENDOR_STRING, &vendorString))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();
}

TEST_F(CCodecConfigTest, SetPixelAspectRatio) {
    init(C2Component::DOMAIN_VIDEO, C2Component::KIND_DECODER, MIMETYPE_VIDEO_AVC);

    ASSERT_EQ(OK, mConfig.initialize(mReflector, mConfigurable));

    sp<AMessage> format{new AMessage};
    format->setInt32(KEY_PIXEL_ASPECT_RATIO_WIDTH, 12);
    format->setInt32(KEY_PIXEL_ASPECT_RATIO_HEIGHT, 11);

    std::vector<std::unique_ptr<C2Param>> configUpdate;
    ASSERT_EQ(OK, mConfig.getConfigUpdateFromSdkParams(
            mConfigurable, format, D::ALL, C2_MAY_BLOCK, &configUpdate));

    ASSERT_EQ(1u, configUpdate.size());
    C2StreamPixelAspectRatioInfo::output *par =
        FindParam<std::remove_pointer<decltype(par)>::type>(configUpdate);
    ASSERT_NE(nullptr, par);
    ASSERT_EQ(12, par->width);
    ASSERT_EQ(11, par->height);
}

TEST_F(CCodecConfigTest, PixelAspectRatioUpdate) {
    init(C2Component::DOMAIN_VIDEO, C2Component::KIND_DECODER, MIMETYPE_VIDEO_AVC);

    ASSERT_EQ(OK, mConfig.initialize(mReflector, mConfigurable));

    std::vector<std::unique_ptr<C2Param>> configUpdate;
    C2StreamPixelAspectRatioInfo::output par(0u, 12, 11);
    configUpdate.push_back(C2Param::Copy(par));

    ASSERT_TRUE(mConfig.updateConfiguration(configUpdate, D::ALL));

    int32_t parWidth{0};
    ASSERT_TRUE(mConfig.mOutputFormat->findInt32(KEY_PIXEL_ASPECT_RATIO_WIDTH, &parWidth))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();
    ASSERT_EQ(12, parWidth);
    ASSERT_FALSE(mConfig.mInputFormat->findInt32(KEY_PIXEL_ASPECT_RATIO_WIDTH, &parWidth))
            << "mInputFormat = " << mConfig.mInputFormat->debugString().c_str();

    int32_t parHeight{0};
    ASSERT_TRUE(mConfig.mOutputFormat->findInt32(KEY_PIXEL_ASPECT_RATIO_HEIGHT, &parHeight))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();
    ASSERT_EQ(11, parHeight);
    ASSERT_FALSE(mConfig.mInputFormat->findInt32(KEY_PIXEL_ASPECT_RATIO_HEIGHT, &parHeight))
            << "mInputFormat = " << mConfig.mInputFormat->debugString().c_str();
}

TEST_F(CCodecConfigTest, DataspaceUpdate) {
    init(C2Component::DOMAIN_VIDEO, C2Component::KIND_ENCODER, MIMETYPE_VIDEO_AVC);

    ASSERT_EQ(OK, mConfig.initialize(mReflector, mConfigurable));
    class InputSurfaceStub : public InputSurfaceWrapper {
    public:
        ~InputSurfaceStub() override = default;
        status_t connect(const std::shared_ptr<Codec2Client::Component> &) override {
            return OK;
        }
        void disconnect() override {}
        status_t start() override { return OK; }
        status_t signalEndOfInputStream() override { return OK; }
        status_t configure(Config &) override { return OK; }
    };
    mConfig.mInputSurface = std::make_shared<InputSurfaceStub>();

    sp<AMessage> format{new AMessage};
    format->setInt32(KEY_COLOR_RANGE, COLOR_RANGE_LIMITED);
    format->setInt32(KEY_COLOR_STANDARD, COLOR_STANDARD_BT709);
    format->setInt32(KEY_COLOR_TRANSFER, COLOR_TRANSFER_SDR_VIDEO);
    format->setInt32(KEY_BIT_RATE, 100);

    std::vector<std::unique_ptr<C2Param>> configUpdate;
    ASSERT_EQ(OK, mConfig.getConfigUpdateFromSdkParams(
            mConfigurable, format, D::ALL, C2_MAY_BLOCK, &configUpdate));
    ASSERT_TRUE(mConfig.updateConfiguration(configUpdate, D::ALL));

    int32_t range{0};
    ASSERT_TRUE(mConfig.mOutputFormat->findInt32(KEY_COLOR_RANGE, &range))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();
    EXPECT_EQ(COLOR_RANGE_LIMITED, range)
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();

    int32_t standard{0};
    ASSERT_TRUE(mConfig.mOutputFormat->findInt32(KEY_COLOR_STANDARD, &standard))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();
    EXPECT_EQ(COLOR_STANDARD_BT709, standard)
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();

    int32_t transfer{0};
    ASSERT_TRUE(mConfig.mOutputFormat->findInt32(KEY_COLOR_TRANSFER, &transfer))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();
    EXPECT_EQ(COLOR_TRANSFER_SDR_VIDEO, transfer)
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();

    mConfig.mInputSurface->setDataSpace(HAL_DATASPACE_BT2020_PQ);

    // Dataspace from input surface should override the configured setting
    mConfig.updateFormats(D::ALL);

    ASSERT_TRUE(mConfig.mOutputFormat->findInt32(KEY_COLOR_RANGE, &range))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();
    EXPECT_EQ(COLOR_RANGE_FULL, range)
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();

    ASSERT_TRUE(mConfig.mOutputFormat->findInt32(KEY_COLOR_STANDARD, &standard))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();
    EXPECT_EQ(COLOR_STANDARD_BT2020, standard)
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();

    ASSERT_TRUE(mConfig.mOutputFormat->findInt32(KEY_COLOR_TRANSFER, &transfer))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();
    EXPECT_EQ(COLOR_TRANSFER_ST2084, transfer)
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();

    // Simulate bitrate update
    format = new AMessage;
    format->setInt32(KEY_BIT_RATE, 200);
    configUpdate.clear();
    ASSERT_EQ(OK, mConfig.getConfigUpdateFromSdkParams(
            mConfigurable, format, D::ALL, C2_MAY_BLOCK, &configUpdate));
    ASSERT_EQ(OK, mConfig.setParameters(mConfigurable, configUpdate, C2_MAY_BLOCK));

    // Color information should remain the same
    mConfig.updateFormats(D::ALL);

    ASSERT_TRUE(mConfig.mOutputFormat->findInt32(KEY_COLOR_RANGE, &range))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();
    EXPECT_EQ(COLOR_RANGE_FULL, range)
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();

    ASSERT_TRUE(mConfig.mOutputFormat->findInt32(KEY_COLOR_STANDARD, &standard))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();
    EXPECT_EQ(COLOR_STANDARD_BT2020, standard)
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();

    ASSERT_TRUE(mConfig.mOutputFormat->findInt32(KEY_COLOR_TRANSFER, &transfer))
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();
    EXPECT_EQ(COLOR_TRANSFER_ST2084, transfer)
            << "mOutputFormat = " << mConfig.mOutputFormat->debugString().c_str();
}

} // namespace android
