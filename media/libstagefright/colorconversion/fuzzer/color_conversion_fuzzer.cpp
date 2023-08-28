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
#include <media/stagefright/ColorConverter.h>
#include <media/stagefright/MediaCodecConstants.h>
#include <media/stagefright/foundation/AMessage.h>
#include <iostream>
#include <vector>
#include "fuzzer/FuzzedDataProvider.h"

using namespace android;
using ::android::sp;

static constexpr int32_t kMinFrameSize = 2;
static constexpr int32_t kMaxFrameSize = 8192;

static constexpr int32_t kSrcFormatType[] = {OMX_COLOR_FormatYUV420Planar,
                                             OMX_COLOR_FormatYUV420Planar16,
                                             OMX_COLOR_FormatYUV420SemiPlanar,
                                             OMX_TI_COLOR_FormatYUV420PackedSemiPlanar,
                                             OMX_COLOR_FormatCbYCrY,
                                             OMX_QCOM_COLOR_FormatYVU420SemiPlanar,
                                             COLOR_FormatYUVP010};

static constexpr int32_t kDstFormatType[] = {
        OMX_COLOR_Format16bitRGB565, OMX_COLOR_Format32BitRGBA8888, OMX_COLOR_Format32bitBGRA8888,
        OMX_COLOR_FormatYUV444Y410, COLOR_Format32bitABGR2101010};

class ColorConversionFuzzer {
  public:
    ColorConversionFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    FuzzedDataProvider mFdp;
    int32_t getFrameSize(OMX_COLOR_FORMATTYPE colorFormat, int32_t stride, int32_t height);
    bool isValidFormat(OMX_COLOR_FORMATTYPE srcFormat, OMX_COLOR_FORMATTYPE dstFormat);
};

int32_t ColorConversionFuzzer::getFrameSize(OMX_COLOR_FORMATTYPE colorFormat, int32_t stride,
                                          int32_t height) {
    int32_t frameSize;
    switch ((int32_t)colorFormat) {
        case OMX_COLOR_FormatCbYCrY:  // Interleaved YUV422
        case OMX_COLOR_Format16bitRGB565: {
            frameSize = 2 * stride * height;
            break;
        }
        case OMX_COLOR_FormatYUV420Planar16:
        case COLOR_FormatYUVP010:
        case OMX_COLOR_FormatYUV444Y410: {
            frameSize = 3 * stride * height;
            break;
        }
        case OMX_COLOR_Format32bitBGRA8888:
        case OMX_COLOR_Format32BitRGBA8888:
        case COLOR_Format32bitABGR2101010: {
            frameSize = 4 * stride * height;
            break;
        }
        case OMX_COLOR_FormatYUV420Planar:
        case OMX_COLOR_FormatYUV420SemiPlanar:
        case OMX_QCOM_COLOR_FormatYVU420SemiPlanar:
        case OMX_TI_COLOR_FormatYUV420PackedSemiPlanar:
        default: {
            frameSize = stride * height + 2 * (((stride + 1) / 2) * ((height + 1) / 2));
            break;
        }
    }
    return frameSize;
}

void ColorConversionFuzzer::process() {
    OMX_COLOR_FORMATTYPE srcColorFormat =
            static_cast<OMX_COLOR_FORMATTYPE>(mFdp.PickValueInArray(kSrcFormatType));
    OMX_COLOR_FORMATTYPE dstColorFormat =
            static_cast<OMX_COLOR_FORMATTYPE>(mFdp.PickValueInArray(kDstFormatType));
    std::unique_ptr<ColorConverter> converter(new ColorConverter(srcColorFormat, dstColorFormat));
    if (converter->isValid()) {
        int32_t srcLeft, srcTop, srcRight, srcBottom, width, height, stride;
        width = mFdp.ConsumeIntegralInRange<int32_t>(kMinFrameSize, kMaxFrameSize);
        height = mFdp.ConsumeIntegralInRange<int32_t>(kMinFrameSize, kMaxFrameSize);
        stride = mFdp.ConsumeIntegralInRange<int32_t>(width, 2 * kMaxFrameSize);

        srcLeft = mFdp.ConsumeIntegralInRange<int32_t>(0, width - 1);
        srcTop = mFdp.ConsumeIntegralInRange<int32_t>(0, height - 1);
        srcRight = mFdp.ConsumeIntegralInRange<int32_t>(srcLeft, width - 1);
        srcBottom = mFdp.ConsumeIntegralInRange<int32_t>(srcTop, height - 1);

        int32_t dstLeft, dstTop, dstRight, dstBottom;
        dstLeft = mFdp.ConsumeIntegralInRange<int32_t>(0, width - 1);
        dstTop = mFdp.ConsumeIntegralInRange<int32_t>(0, height - 1);
        dstRight = mFdp.ConsumeIntegralInRange<int32_t>(dstLeft, width - 1);
        dstBottom = mFdp.ConsumeIntegralInRange<int32_t>(dstTop, height - 1);

        int32_t srcFrameSize = getFrameSize(srcColorFormat, stride, height);
        int32_t dstFrameSize = getFrameSize(dstColorFormat, stride, height);
        std::vector<uint8_t> srcFrame(srcFrameSize), dstFrame(dstFrameSize);
        mFdp.ConsumeData(srcFrame.data(), srcFrameSize);
        converter->convert(srcFrame.data(), width, height, stride, srcLeft, srcTop, srcRight,
                           srcBottom, dstFrame.data(), width, height, stride, dstLeft, dstTop,
                           dstRight, dstBottom);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ColorConversionFuzzer colorConversionFuzzer(data, size);
    colorConversionFuzzer.process();
    return 0;
}
