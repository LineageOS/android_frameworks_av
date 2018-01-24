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

//#define LOG_NDEBUG 0
#define LOG_TAG "SimpleC2Interface"
#include <utils/Log.h>

#include <SimpleC2Interface.h>

namespace android {

c2_status_t SimpleC2Interface::query_vb(
        const std::vector<C2Param*> &stackParams,
        const std::vector<C2Param::Index> &heapParamIndices,
        c2_blocking_t mayBlock,
        std::vector<std::unique_ptr<C2Param>>* const heapParams) const {
    (void)mayBlock;

    for (C2Param* const param : stackParams) {
        if (param->coreIndex() != C2StreamFormatConfig::CORE_INDEX
                || !param->forStream()
                || param->stream() != 0u) {
            param->invalidate();
            continue;
        }
        if (param->forInput()) {
            param->updateFrom(mInputFormat);
        } else {
            param->updateFrom(mOutputFormat);
        }
    }
    if (heapParams) {
        heapParams->clear();
        for (const auto &index : heapParamIndices) {
            switch (index.type()) {
                case C2StreamFormatConfig::input::PARAM_TYPE:
                    if (index.stream() == 0u) {
                        heapParams->push_back(C2Param::Copy(mInputFormat));
                    } else {
                        heapParams->push_back(nullptr);
                    }
                    break;
                case C2StreamFormatConfig::output::PARAM_TYPE:
                    if (index.stream() == 0u) {
                        heapParams->push_back(C2Param::Copy(mOutputFormat));
                    } else {
                        heapParams->push_back(nullptr);
                    }
                    break;
                case C2PortMimeConfig::input::PARAM_TYPE:
                    if (mInputMediaType) {
                        heapParams->push_back(C2Param::Copy(*mInputMediaType));
                    } else {
                        heapParams->push_back(nullptr);
                    }
                    break;
                case C2PortMimeConfig::output::PARAM_TYPE:
                    if (mOutputMediaType) {
                        heapParams->push_back(C2Param::Copy(*mOutputMediaType));
                    } else {
                        heapParams->push_back(nullptr);
                    }
                    break;
                default:
                    heapParams->push_back(nullptr);
                    break;
            }
        }
    }

    return C2_OK;
}

} // namespace android
