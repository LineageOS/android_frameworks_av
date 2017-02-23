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

#ifndef MEDIA_CAS_DEFS_H_
#define MEDIA_CAS_DEFS_H_

#include <binder/Parcel.h>
#include <media/cas/CasAPI.h>
#include <media/cas/DescramblerAPI.h>
#include <media/stagefright/foundation/ABase.h>

namespace android {
class IMemory;
namespace media {

namespace MediaCas {
class ParcelableCasData : public CasData,
                          public Parcelable {
public:
    ParcelableCasData() {}
    ParcelableCasData(const uint8_t *data, size_t size) :
        CasData(data, data + size) {}
    virtual ~ParcelableCasData() {}
    status_t readFromParcel(const Parcel* parcel) override;
    status_t writeToParcel(Parcel* parcel) const override;

private:
    DISALLOW_EVIL_CONSTRUCTORS(ParcelableCasData);
};

class ParcelableCasPluginDescriptor : public Parcelable {
public:
    ParcelableCasPluginDescriptor(int32_t CA_system_id, const char *name)
        : mCASystemId(CA_system_id), mName(name) {}

    ParcelableCasPluginDescriptor() : mCASystemId(0) {}

    ParcelableCasPluginDescriptor(ParcelableCasPluginDescriptor&& desc) = default;

    virtual ~ParcelableCasPluginDescriptor() {}

    status_t readFromParcel(const Parcel* parcel) override;
    status_t writeToParcel(Parcel* parcel) const override;

private:
    int32_t mCASystemId;
    String16 mName;
    DISALLOW_EVIL_CONSTRUCTORS(ParcelableCasPluginDescriptor);
};
}

namespace MediaDescrambler {
class DescrambleInfo : public Parcelable {
public:
    enum DestinationType {
        kDestinationTypeVmPointer,    // non-secure
        kDestinationTypeNativeHandle  // secure
    };

    DestinationType dstType;
    DescramblerPlugin::ScramblingControl scramblingControl;
    size_t numSubSamples;
    DescramblerPlugin::SubSample *subSamples;
    sp<IMemory> srcMem;
    int32_t srcOffset;
    void *dstPtr;
    int32_t dstOffset;

    DescrambleInfo();
    virtual ~DescrambleInfo();
    status_t readFromParcel(const Parcel* parcel) override;
    status_t writeToParcel(Parcel* parcel) const override;

private:

    DISALLOW_EVIL_CONSTRUCTORS(DescrambleInfo);
};
}

} // namespace media
} // namespace android


#endif // MEDIA_CAS_DEFS_H_
