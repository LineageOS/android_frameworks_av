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

#ifndef BINDING_SHAREDREGIONPARCELABLE_H
#define BINDING_SHAREDREGIONPARCELABLE_H

#include <stdint.h>

#include <sys/mman.h>
#include <binder/Parcelable.h>

#include <oboe/OboeDefinitions.h>

#include "binding/SharedMemoryParcelable.h"

using android::status_t;
using android::Parcel;
using android::Parcelable;

namespace oboe {

class SharedRegionParcelable : public Parcelable {
public:
    SharedRegionParcelable();
    virtual ~SharedRegionParcelable();

    void setup(int32_t sharedMemoryIndex, int32_t offsetInBytes, int32_t sizeInBytes);

    virtual status_t writeToParcel(Parcel* parcel) const override;

    virtual status_t readFromParcel(const Parcel* parcel) override;

    oboe_result_t resolve(SharedMemoryParcelable *memoryParcels, void **regionAddressPtr);

    oboe_result_t validate();

    void dump();

protected:
    int32_t mSharedMemoryIndex = -1;
    int32_t mOffsetInBytes     = 0;
    int32_t mSizeInBytes       = 0;
};

} /* namespace oboe */

#endif //BINDING_SHAREDREGIONPARCELABLE_H
