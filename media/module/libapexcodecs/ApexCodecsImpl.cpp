/*
 * Copyright (C) 2025 The Android Open Source Project
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

#include <android-base/no_destructor.h>
#include <apex/ApexCodecsImpl.h>

namespace android::apexcodecs {

class ApexComponentImpl : public ApexComponentIntf {
public:
    ApexComponentImpl(const std::shared_ptr<C2Component> &comp) : mComponent(comp) {}
    virtual ApexCodec_Status start() = 0;
    virtual ApexCodec_Status flush() = 0;
    virtual ApexCodec_Status reset() = 0;
    virtual ApexCodec_Configurable *getConfigurable() = 0;
    virtual ApexCodec_Status process(
            const ApexCodec_Buffer *input,
            ApexCodec_Buffer *output,
            size_t *consumed,
            size_t *produced) = 0;
private:
    std::shared_ptr<C2Component> mComponent;
};

}  // namespace android::apexcodecs