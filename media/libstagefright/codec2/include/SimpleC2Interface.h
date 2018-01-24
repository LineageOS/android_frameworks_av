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

#ifndef SIMPLE_C2_INTERFACE_H_
#define SIMPLE_C2_INTERFACE_H_

#include <C2Component.h>

namespace android {

class SimpleC2Interface : public C2ComponentInterface {
public:
    class Builder {
    public:
        inline Builder(
                const char *name,
                c2_node_id_t id,
                std::function<void(C2ComponentInterface*)> deleter =
                    std::default_delete<C2ComponentInterface>())
            : mIntf(new SimpleC2Interface(name, id), deleter) {}

        inline Builder &inputFormat(C2FormatKind input) {
            mIntf->mInputFormat.value = input;
            return *this;
        }

        inline Builder &outputFormat(C2FormatKind output) {
            mIntf->mOutputFormat.value = output;
            return *this;
        }

        inline Builder &inputMediaType(const char *mediaType, size_t maxLen = 128) {
            mIntf->mInputMediaType = C2PortMimeConfig::input::AllocShared(maxLen);
            std::strncpy(mIntf->mInputMediaType->m.value, mediaType, maxLen);
            return *this;
        }

        inline Builder &outputMediaType(const char *mediaType, size_t maxLen = 128) {
            mIntf->mOutputMediaType = C2PortMimeConfig::output::AllocShared(maxLen);
            std::strncpy(mIntf->mOutputMediaType->m.value, mediaType, maxLen);
            return *this;
        }

        template<size_t N>
        inline Builder &inputMediaType(const char mediaType[N]) {
            return inputMediaType(mediaType, N);
        }

        template<size_t N>
        inline Builder &outputMediaType(const char mediaType[N]) {
            return outputMediaType(mediaType, N);
        }

        inline std::shared_ptr<SimpleC2Interface> build() {
            return mIntf;
        }
    private:
        std::shared_ptr<SimpleC2Interface> mIntf;
    };

    virtual ~SimpleC2Interface() = default;

    // From C2ComponentInterface
    inline C2String getName() const override { return mName; }
    inline c2_node_id_t getId() const override { return mId; }
    c2_status_t query_vb(
            const std::vector<C2Param*> &stackParams,
            const std::vector<C2Param::Index> &heapParamIndices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const heapParams) const override;
    inline c2_status_t config_vb(
            const std::vector<C2Param*> &,
            c2_blocking_t,
            std::vector<std::unique_ptr<C2SettingResult>>* const) override {
        return C2_OMITTED;
    }
    inline c2_status_t createTunnel_sm(c2_node_id_t) override { return C2_OMITTED; }
    inline c2_status_t releaseTunnel_sm(c2_node_id_t) override { return C2_OMITTED; }
    inline c2_status_t querySupportedParams_nb(
            std::vector<std::shared_ptr<C2ParamDescriptor>> * const) const override {
        return C2_OMITTED;
    }
    c2_status_t querySupportedValues_vb(
            std::vector<C2FieldSupportedValuesQuery> &,
            c2_blocking_t) const override {
        return C2_OMITTED;
    }

private:
    inline SimpleC2Interface(const char *name, c2_node_id_t id)
        : mName(name), mId(id), mInputFormat(0u), mOutputFormat(0u) {}

    const C2String mName;
    const c2_node_id_t mId;
    C2StreamFormatConfig::input mInputFormat;
    C2StreamFormatConfig::output mOutputFormat;
    std::shared_ptr<C2PortMimeConfig::input> mInputMediaType;
    std::shared_ptr<C2PortMimeConfig::output> mOutputMediaType;

    SimpleC2Interface() = delete;
};

}  // namespace android

#endif  // SIMPLE_C2_INTERFACE_H_
