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

#include <algorithm>
#include <regex>
#include <type_traits>

#define LOG_TAG "AidlConversionNdkCpp"
#include <utils/Log.h>

#include <android-base/expected.h>
#include <android/binder_auto_utils.h>
#include <android/binder_enums.h>
#include <android/binder_parcel.h>
#include <binder/Enums.h>
#include <media/AidlConversionNdkCpp.h>
#include <media/AidlConversionUtil.h>

using aidl::android::aidl_utils::statusTFromBinderStatusT;

namespace android {

namespace {

bool isVendorExtension(const std::string& s) {
    // Per definition in AudioAttributes.aidl and {Playback|Record}TrackMetadata.aidl
    static const std::regex vendorExtension("VX_[A-Z0-9]{3,}_[_A-Z0-9]+");
    return std::regex_match(s.begin(), s.end(), vendorExtension);
}

inline bool isNotVendorExtension(const std::string& s) { return !isVendorExtension(s); }

void filterOutNonVendorTagsInPlace(std::vector<std::string>& tags) {
    if (std::find_if(tags.begin(), tags.end(), isNotVendorExtension) == tags.end()) {
        return;
    }
    std::vector<std::string> temp;
    temp.reserve(tags.size());
    std::copy_if(tags.begin(), tags.end(), std::back_inserter(temp), isVendorExtension);
    tags = std::move(temp);
}

// cpp2ndk and ndk2cpp are universal converters which work for any type,
// however they are not the most efficient way to convert due to extra
// marshaling / unmarshaling step.

template<typename NdkType, typename CppType>
ConversionResult<NdkType> cpp2ndk(const CppType& cpp) {
    Parcel cppParcel;
    RETURN_IF_ERROR(cpp.writeToParcel(&cppParcel));
    ::ndk::ScopedAParcel ndkParcel(AParcel_create());
    const int32_t ndkParcelBegin = AParcel_getDataPosition(ndkParcel.get());
    RETURN_IF_ERROR(statusTFromBinderStatusT(AParcel_unmarshal(
                            ndkParcel.get(), cppParcel.data(), cppParcel.dataSize())));
    RETURN_IF_ERROR(statusTFromBinderStatusT(AParcel_setDataPosition(
                            ndkParcel.get(), ndkParcelBegin)));
    NdkType ndk;
    RETURN_IF_ERROR(statusTFromBinderStatusT(ndk.readFromParcel(ndkParcel.get())));
    return ndk;
}

template<typename CppType, typename NdkType>
ConversionResult<CppType> ndk2cpp(const NdkType& ndk) {
    ::ndk::ScopedAParcel ndkParcel(AParcel_create());
    RETURN_IF_ERROR(statusTFromBinderStatusT(ndk.writeToParcel(ndkParcel.get())));
    const int32_t ndkParcelDataSize = AParcel_getDataSize(ndkParcel.get());
    if (ndkParcelDataSize < 0) {
        return base::unexpected(BAD_VALUE);
    }
    // Parcel does not expose its data in a mutable form, we have to use an intermediate buffer.
    std::vector<uint8_t> parcelData(static_cast<size_t>(ndkParcelDataSize));
    RETURN_IF_ERROR(statusTFromBinderStatusT(AParcel_marshal(
                            ndkParcel.get(), parcelData.data(), 0, ndkParcelDataSize)));
    Parcel cppParcel;
    RETURN_IF_ERROR(cppParcel.setData(parcelData.data(), parcelData.size()));
    CppType cpp;
    RETURN_IF_ERROR(cpp.readFromParcel(&cppParcel));
    return cpp;
}

// cpp2ndk_Enum and ndk2cpp_Enum are more efficient implementations specifically for enums.

template<typename OutEnum, typename OutEnumRange, typename InEnum>
        ConversionResult<OutEnum> convertEnum(const OutEnumRange& range, InEnum e) {
    using InIntType = std::underlying_type_t<InEnum>;
    static_assert(std::is_same_v<InIntType, std::underlying_type_t<OutEnum>>);

    InIntType inEnumIndex = static_cast<InIntType>(e);
    OutEnum outEnum = static_cast<OutEnum>(inEnumIndex);
    if (std::find(range.begin(), range.end(), outEnum) == range.end()) {
        return base::unexpected(BAD_VALUE);
    }
    return outEnum;
}

template<typename NdkEnum, typename CppEnum>
        ConversionResult<NdkEnum> cpp2ndk_Enum(CppEnum cpp) {
    return convertEnum<NdkEnum>(::ndk::enum_range<NdkEnum>(), cpp);
}

template<typename CppEnum, typename NdkEnum>
        ConversionResult<CppEnum> ndk2cpp_Enum(NdkEnum ndk) {
    return convertEnum<CppEnum>(enum_range<CppEnum>(), ndk);
}

}  // namespace

#define GENERATE_CONVERTERS(packageName, className) \
    GENERATE_CONVERTERS_IMPL(packageName, _, className)

#define GENERATE_CONVERTERS_IMPL(packageName, prefix, className)        \
    ConversionResult<::aidl::packageName::className> cpp2ndk##prefix##className( \
            const ::packageName::className& cpp) {                      \
        return cpp2ndk<::aidl::packageName::className>(cpp);            \
    }                                                                   \
    ConversionResult<::packageName::className> ndk2cpp##prefix##className( \
            const ::aidl::packageName::className& ndk) {                \
        return ndk2cpp<::packageName::className>(ndk);                  \
    }

#define GENERATE_ENUM_CONVERTERS(packageName, className)                \
    ConversionResult<::aidl::packageName::className> cpp2ndk_##className( \
            const ::packageName::className& cpp) {                      \
        return cpp2ndk_Enum<::aidl::packageName::className>(cpp);       \
    }                                                                   \
    ConversionResult<::packageName::className> ndk2cpp_##className(     \
            const ::aidl::packageName::className& ndk) {                \
        return ndk2cpp_Enum<::packageName::className>(ndk);             \
}

GENERATE_CONVERTERS(android::media::audio::common, AudioFormatDescription);
GENERATE_CONVERTERS_IMPL(android::media::audio::common, _Impl_, AudioHalEngineConfig);
GENERATE_CONVERTERS(android::media::audio::common, AudioMMapPolicyInfo);
GENERATE_ENUM_CONVERTERS(android::media::audio::common, AudioMMapPolicyType);
GENERATE_ENUM_CONVERTERS(android::media::audio::common, AudioMode);
GENERATE_CONVERTERS(android::media::audio::common, AudioPort);

namespace {

// Filter out all AudioAttributes tags that do not conform to the vendor extension pattern.
template<typename T>
void filterOutNonVendorTags(T& audioHalEngineConfig) {
    for (auto& strategy : audioHalEngineConfig.productStrategies) {
        for (auto& group : strategy.attributesGroups) {
            for (auto& attr : group.attributes) {
                filterOutNonVendorTagsInPlace(attr.tags);
            }
        }
    }
}

}  // namespace

ConversionResult<::aidl::android::media::audio::common::AudioHalEngineConfig>
cpp2ndk_AudioHalEngineConfig(const ::android::media::audio::common::AudioHalEngineConfig& cpp) {
    auto conv = cpp2ndk_Impl_AudioHalEngineConfig(cpp);
    if (conv.ok()) {
        filterOutNonVendorTags(conv.value());
    }
    return conv;
}

ConversionResult<::android::media::audio::common::AudioHalEngineConfig>
ndk2cpp_AudioHalEngineConfig(
        const ::aidl::android::media::audio::common::AudioHalEngineConfig& ndk) {
    auto conv = ndk2cpp_Impl_AudioHalEngineConfig(ndk);
    if (conv.ok()) {
        filterOutNonVendorTags(conv.value());
    }
    return conv;
}


}  // namespace android
