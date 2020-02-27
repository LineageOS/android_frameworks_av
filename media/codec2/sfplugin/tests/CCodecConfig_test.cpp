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
        sp<hardware::media::c2::V1_0::utils::CachedConfigurable> cachedConfigurable =
            new hardware::media::c2::V1_0::utils::CachedConfigurable(
                    std::make_unique<Configurable>(mReflector));
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
        explicit Configurable(const std::shared_ptr<C2ReflectorHelper> &reflector)
            : ConfigurableC2Intf("name", 0u),
              mImpl(reflector) {
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
            explicit Impl(const std::shared_ptr<C2ReflectorHelper> &reflector)
                : C2InterfaceHelper{reflector} {
                setDerivedInstance(this);

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

                // TODO: SDK params
            }
        private:
            std::shared_ptr<C2PortVendorInt32Info::input> mInt32Input;
            std::shared_ptr<C2StreamVendorInt64Info::output> mInt64Output;
            std::shared_ptr<C2PortVendorStringInfo::input> mStringInput;

            template<typename T>
            static C2R Setter(bool, C2P<T> &) {
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
    ASSERT_EQ(OK, mConfig.initialize(mReflector, mConfigurable));

    sp<AMessage> format{new AMessage};
    format->setInt32(KEY_VENDOR_INT32, kCodec2Int32);
    format->setInt64(KEY_VENDOR_INT64, kCodec2Int64);
    format->setString(KEY_VENDOR_STRING, kCodec2Str);

    std::vector<std::unique_ptr<C2Param>> configUpdate;
    ASSERT_EQ(OK, mConfig.getConfigUpdateFromSdkParams(
            mConfigurable, format, D::IS_INPUT | D::IS_OUTPUT, C2_MAY_BLOCK, &configUpdate));

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
    ASSERT_FALSE(mConfig.updateConfiguration(configUpdate, D::IS_INPUT | D::IS_OUTPUT));

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

    ASSERT_TRUE(mConfig.updateConfiguration(configUpdate, D::IS_INPUT | D::IS_OUTPUT));

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
    ASSERT_EQ(OK, mConfig.initialize(mReflector, mConfigurable));

    // Subscribe to example.int32 only
    std::vector<std::unique_ptr<C2Param>> configUpdate;
    sp<AMessage> format{new AMessage};
    format->setInt32(KEY_VENDOR_INT32, 0);
    configUpdate.clear();
    ASSERT_EQ(OK, mConfig.getConfigUpdateFromSdkParams(
            mConfigurable, format, D::IS_INPUT | D::IS_OUTPUT, C2_MAY_BLOCK, &configUpdate));
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
    ASSERT_TRUE(mConfig.updateConfiguration(configUpdate, D::IS_INPUT | D::IS_OUTPUT));

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

} // namespace android
