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

#pragma once

#include <span>
#include <vector>

#include <C2Param.h>
#include <apex/ApexCodecsImpl.h>
#include <media/stagefright/foundation/AUtils.h>
#include <media/stagefright/foundation/OpusHeader.h>

extern "C" {
    #include <opus.h>
    #include <opus_multistream.h>
}

namespace android::apexcodecs {

class C2ApexOpusDec : public ApexComponentIntf {
public:
    static constexpr char COMPONENT_NAME[] = "c2.android.inproc.opus.decoder";

private:
    class IntfImpl;

public:
    explicit C2ApexOpusDec(const std::shared_ptr<IntfImpl> &intfImpl);

    virtual ~C2ApexOpusDec() = default;

    static std::unique_ptr<ApexComponentIntf> Create(
            const std::shared_ptr<C2ReflectorHelper> &helper);
    static std::shared_ptr<C2Component::Traits> MakeTraits();
    static void *Map(void *addr, size_t size, int prot, int flags, int fd, off_t offset);
    static int Unmap(void *addr, size_t size);

    ApexCodec_Status start() override;
    ApexCodec_Status flush() override;
    ApexCodec_Status reset() override;
    std::unique_ptr<ApexConfigurableIntf> getConfigurable() override;
    ApexCodec_Status process(
            const ApexCodec_Buffer *input,
            ApexCodec_Buffer *output,
            size_t *consumed,
            size_t *produced) override;

    bool valid() const { return mInit; }

private:
    void initDecoderStates();

    template <typename... Args>
    static bool AppendParamsToVector(
            std::vector<uint8_t> *configUpdate,
            Args... paramsArg) {
        constexpr size_t PARAMS_ALIGNMENT = 8;

        if (!configUpdate) {
            return false;
        }
        // Convert arg list to std::array
        std::array<C2Param *, sizeof...(Args)> params{ static_cast<C2Param *>(paramsArg)... };
        if (params.size() == 0) {
            return false;
        }
        size_t offset = align(configUpdate->size(), PARAMS_ALIGNMENT);
        size_t size = offset;
        for (const C2Param *param : params) {
            if (!param || !(*param)) {
                return false;
            }
            size = align(size + param->size(), PARAMS_ALIGNMENT);
        }
        configUpdate->resize(size);
        for (const C2Param *param : params) {
            memcpy(configUpdate->data() + offset, param, param->size());
            offset = align(offset + param->size(), PARAMS_ALIGNMENT);
        }
        return true;
    }

    bool mInit;

    std::unique_ptr<ApexConfigurableImpl> mConfigurable;
    std::shared_ptr<IntfImpl> mIntf;
    OpusMSDecoder *mDecoder;
    OpusHeader mHeader;

    int64_t mCodecDelay;
    int64_t mSeekPreRoll;
    int64_t mSamplesToDiscard;
    size_t mInputBufferCount;
    bool mSignalledError;
    bool mSignalledOutputEos;
};

}  // namespace android::apexcodecs
