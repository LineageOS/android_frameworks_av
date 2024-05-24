/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <VendorTagDescriptor.h>
#include <binder/Parcel.h>
#include <camera_metadata_tests_fake_vendor.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <system/camera_vendor_tags.h>

#include <camera_metadata_hidden.h>
#include "camera2common.h"

using namespace std;
using namespace android;

constexpr int32_t kRangeMin = 0;
constexpr int32_t kRangeMax = 1000;
constexpr int32_t kVendorTagDescriptorId = -1;
constexpr int8_t kMinLoopIterations = 1;
constexpr int8_t kMaxLoopIterations = 50;

extern "C" {

static int zero_get_tag_count(const vendor_tag_ops_t*) {
    return 0;
}

static int default_get_tag_count(const vendor_tag_ops_t*) {
    return VENDOR_TAG_COUNT_ERR;
}

static void default_get_all_tags(const vendor_tag_ops_t*, uint32_t*) {}

static const char* default_get_section_name(const vendor_tag_ops_t*, uint32_t) {
    return VENDOR_SECTION_NAME_ERR;
}

static const char* default_get_tag_name(const vendor_tag_ops_t*, uint32_t) {
    return VENDOR_TAG_NAME_ERR;
}

static int default_get_tag_type(const vendor_tag_ops_t*, uint32_t) {
    return VENDOR_TAG_TYPE_ERR;
}

} /*extern "C"*/

static void FillWithDefaults(vendor_tag_ops_t* vOps) {
    vOps->get_tag_count = default_get_tag_count;
    vOps->get_all_tags = default_get_all_tags;
    vOps->get_section_name = default_get_section_name;
    vOps->get_tag_name = default_get_tag_name;
    vOps->get_tag_type = default_get_tag_type;
}

class VendorTagDescriptorFuzzer {
  public:
    void process(const uint8_t* data, size_t size);
    ~VendorTagDescriptorFuzzer() {
        mVendorTagDescriptor.clear();
        mVendorTagDescriptorCache.clear();
    }

  private:
    void initVendorTagDescriptor();
    void invokeVendorTagDescriptor();
    void invokeVendorTagDescriptorCache();
    void invokeVendorTagErrorConditions();
    sp<VendorTagDescriptor> mVendorTagDescriptor = nullptr;
    sp<VendorTagDescriptorCache> mVendorTagDescriptorCache = nullptr;
    FuzzedDataProvider* mFDP = nullptr;
};

void VendorTagDescriptorFuzzer::initVendorTagDescriptor() {
    if (mFDP->ConsumeBool()) {
        mVendorTagDescriptor = new VendorTagDescriptor();
    } else {
        const vendor_tag_ops_t* vOps = &fakevendor_ops;
        VendorTagDescriptor::createDescriptorFromOps(vOps, mVendorTagDescriptor);
    }
}

void VendorTagDescriptorFuzzer::invokeVendorTagDescriptor() {
    initVendorTagDescriptor();

    sp<VendorTagDescriptor> vdesc = new VendorTagDescriptor();

    int8_t count = mFDP->ConsumeIntegralInRange<int8_t>(kMinLoopIterations, kMaxLoopIterations);
    while (--count > 0) {
        auto callVendorTagDescriptor = mFDP->PickValueInArray<const std::function<void()>>({
                [&]() {
                    int32_t tagCount = mVendorTagDescriptor->getTagCount();
                    if (tagCount > 0) {
                        uint32_t tagArray[tagCount];
                        mVendorTagDescriptor->getTagArray(tagArray);
                        uint32_t tag;
                        for (int32_t i = 0; i < tagCount; ++i) {
                            tag = tagArray[i];
                            get_local_camera_metadata_section_name_vendor_id(
                                    tag, kVendorTagDescriptorId);
                            get_local_camera_metadata_tag_name_vendor_id(tag,
                                                                         kVendorTagDescriptorId);
                            get_local_camera_metadata_tag_type_vendor_id(tag,
                                                                         kVendorTagDescriptorId);
                            mVendorTagDescriptor->getSectionIndex(tag);
                        }
                    }
                },
                [&]() {
                    if (mVendorTagDescriptor->getTagCount() > 0) {
                        mVendorTagDescriptor->getAllSectionNames();
                    }
                },
                [&]() { vdesc->copyFrom(*mVendorTagDescriptor); },
                [&]() {
                    VendorTagDescriptor::setAsGlobalVendorTagDescriptor(mVendorTagDescriptor);
                },
                [&]() { VendorTagDescriptor::getGlobalVendorTagDescriptor(); },
                [&]() {
                    String8 name((mFDP->ConsumeRandomLengthString()).c_str());
                    String8 section((mFDP->ConsumeRandomLengthString()).c_str());
                    uint32_t lookupTag;
                    mVendorTagDescriptor->lookupTag(name, section, &lookupTag);
                },
                [&]() {
                    int32_t fd = open("/dev/null", O_CLOEXEC | O_RDWR | O_CREAT);
                    int32_t verbosity = mFDP->ConsumeIntegralInRange<int32_t>(kRangeMin, kRangeMax);
                    int32_t indentation =
                            mFDP->ConsumeIntegralInRange<int32_t>(kRangeMin, kRangeMax);
                    mVendorTagDescriptor->dump(fd, verbosity, indentation);
                    close(fd);
                },
        });
        callVendorTagDescriptor();
    }

    // Do not keep invokeReadWrite() APIs in while loop to avoid possible OOM.
    if (mFDP->ConsumeBool()) {
        invokeReadWriteParcelsp<VendorTagDescriptor>(mVendorTagDescriptor);
    } else {
        invokeNewReadWriteParcelsp<VendorTagDescriptor>(mVendorTagDescriptor, *mFDP);
    }
    VendorTagDescriptor::clearGlobalVendorTagDescriptor();
}

void VendorTagDescriptorFuzzer::invokeVendorTagDescriptorCache() {
    mVendorTagDescriptorCache = new VendorTagDescriptorCache();
    uint64_t id = mFDP->ConsumeIntegral<uint64_t>();
    initVendorTagDescriptor();

    int8_t count = mFDP->ConsumeIntegralInRange<int8_t>(kMinLoopIterations, kMaxLoopIterations);
    while (--count > 0) {
        auto callVendorTagDescriptorCache = mFDP->PickValueInArray<const std::function<void()>>({
                [&]() { mVendorTagDescriptorCache->addVendorDescriptor(id, mVendorTagDescriptor); },
                [&]() {
                    VendorTagDescriptorCache::setAsGlobalVendorTagCache(mVendorTagDescriptorCache);
                },
                [&]() { VendorTagDescriptorCache::getGlobalVendorTagCache(); },
                [&]() {
                    sp<VendorTagDescriptor> tagDesc;
                    mVendorTagDescriptorCache->getVendorTagDescriptor(id, &tagDesc);
                },
                [&]() {
                    int32_t tagCount = mVendorTagDescriptorCache->getTagCount(id);
                    if (tagCount > 0) {
                        uint32_t tagArray[tagCount];
                        mVendorTagDescriptorCache->getTagArray(tagArray, id);
                        uint32_t tag;
                        for (int32_t i = 0; i < tagCount; ++i) {
                            tag = tagArray[i];
                            get_local_camera_metadata_section_name_vendor_id(tag, id);
                            get_local_camera_metadata_tag_name_vendor_id(tag, id);
                            get_local_camera_metadata_tag_type_vendor_id(tag, id);
                        }
                    }
                },
                [&]() {
                    int32_t fd = open("/dev/null", O_CLOEXEC | O_RDWR | O_CREAT);
                    int32_t verbosity = mFDP->ConsumeIntegralInRange<int>(kRangeMin, kRangeMax);
                    int32_t indentation = mFDP->ConsumeIntegralInRange<int>(kRangeMin, kRangeMax);
                    mVendorTagDescriptorCache->dump(fd, verbosity, indentation);
                    close(fd);
                },
                [&]() { VendorTagDescriptorCache::isVendorCachePresent(id); },
                [&]() { mVendorTagDescriptorCache->getVendorIdsAndTagDescriptors(); },
        });
        callVendorTagDescriptorCache();
    }

    // Do not keep invokeReadWrite() APIs in while loop to avoid possible OOM.
    if (mFDP->ConsumeBool()) {
        invokeReadWriteParcelsp<VendorTagDescriptorCache>(mVendorTagDescriptorCache);
    } else {
        invokeNewReadWriteParcelsp<VendorTagDescriptorCache>(mVendorTagDescriptorCache, *mFDP);
    }
    mVendorTagDescriptorCache->clearGlobalVendorTagCache();
}

void VendorTagDescriptorFuzzer::invokeVendorTagErrorConditions() {
    sp<VendorTagDescriptor> vDesc;
    vendor_tag_ops_t vOps;
    FillWithDefaults(&vOps);
    vOps.get_tag_count = zero_get_tag_count;

    if (mFDP->ConsumeBool()) {
        VendorTagDescriptor::createDescriptorFromOps(/*vOps*/ NULL, vDesc);
    } else {
        VendorTagDescriptor::createDescriptorFromOps(&vOps, vDesc);

        int8_t count = mFDP->ConsumeIntegralInRange<int8_t>(kMinLoopIterations, kMaxLoopIterations);
        while (--count > 0) {
            int32_t tagCount = vDesc->getTagCount();
            uint32_t badTag = mFDP->ConsumeIntegral<uint32_t>();
            uint32_t badTagArray[tagCount + 1];
            auto callVendorTagErrorConditions =
                    mFDP->PickValueInArray<const std::function<void()>>({
                            [&]() { vDesc->getTagArray(badTagArray); },
                            [&]() { vDesc->getSectionName(badTag); },
                            [&]() { vDesc->getTagName(badTag); },
                            [&]() { vDesc->getTagType(badTag); },
                            [&]() { VendorTagDescriptor::clearGlobalVendorTagDescriptor(); },
                            [&]() { VendorTagDescriptor::getGlobalVendorTagDescriptor(); },
                            [&]() { VendorTagDescriptor::setAsGlobalVendorTagDescriptor(vDesc); },
                    });
            callVendorTagErrorConditions();
        }
        invokeReadWriteNullParcelsp<VendorTagDescriptor>(vDesc);
    }
    vDesc.clear();
}

void VendorTagDescriptorFuzzer::process(const uint8_t* data, size_t size) {
    mFDP = new FuzzedDataProvider(data, size);
    while (mFDP->remaining_bytes()) {
        auto invokeVendorTagDescriptorFuzzer = mFDP->PickValueInArray<const std::function<void()>>({
                [&]() { invokeVendorTagDescriptor(); },
                [&]() { invokeVendorTagDescriptorCache(); },
                [&]() { invokeVendorTagErrorConditions(); },
        });
        invokeVendorTagDescriptorFuzzer();
    }
    delete mFDP;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    VendorTagDescriptorFuzzer vendorTagDescriptorFuzzer;
    vendorTagDescriptorFuzzer.process(data, size);
    return 0;
}
