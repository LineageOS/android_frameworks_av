/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <FrameDecoder.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <media/IMediaSource.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/foundation/AString.h>
#include "FrameDecoderHelpers.h"
#include "IMediaSourceFuzzImpl.h"

namespace android {

static const android_pixel_format_t kColorFormats[] = {
        HAL_PIXEL_FORMAT_RGBA_8888,
        HAL_PIXEL_FORMAT_RGB_565,
        HAL_PIXEL_FORMAT_BGRA_8888,
        HAL_PIXEL_FORMAT_RGBA_1010102,
        HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED, /* To cover the default case */
};

static const MediaSource::ReadOptions::SeekMode kSeekModes[] = {
        MediaSource::ReadOptions::SeekMode::SEEK_PREVIOUS_SYNC,
        MediaSource::ReadOptions::SeekMode::SEEK_NEXT_SYNC,
        MediaSource::ReadOptions::SeekMode::SEEK_CLOSEST_SYNC,
        MediaSource::ReadOptions::SeekMode::SEEK_CLOSEST,
        MediaSource::ReadOptions::SeekMode::SEEK_FRAME_INDEX,
};

static const std::string kComponentNames[] = {
        "c2.android.avc.decoder",  "c2.android.hevc.decoder", "c2.android.vp8.decoder",
        "c2.android.vp9.decoder",  "c2.android.av1.decoder",  "c2.android.mpeg4.decoder",
        "c2.android.h263.decoder",
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    std::string component = fdp.PickValueInArray(kComponentNames);
    AString componentName(component.c_str());
    sp<MetaData> trackMeta = generateMetaData(&fdp, component);
    sp<IMediaSource> source = sp<IMediaSourceFuzzImpl>::make(&fdp, gMaxMediaBufferSize);

    sp<FrameDecoder> decoder = nullptr;
    if (fdp.ConsumeBool()) {
        decoder = sp<MediaImageDecoder>::make(componentName, trackMeta, source);
    } else {
        decoder = sp<VideoFrameDecoder>::make(componentName, trackMeta, source);
    }

    if (decoder.get() &&
        decoder->init(fdp.ConsumeIntegral<uint64_t>() /* frameTimeUs */,
                      fdp.PickValueInArray(kSeekModes) /* option */,
                      fdp.PickValueInArray(kColorFormats) /* colorFormat */) == OK) {
        auto frameDecoderAPI = fdp.PickValueInArray<const std::function<void()>>({
                [&]() { decoder->extractFrame(); },
                [&]() {
                    FrameRect rect(fdp.ConsumeIntegral<int32_t>() /* left */,
                                   fdp.ConsumeIntegral<int32_t>() /* top */,
                                   fdp.ConsumeIntegral<int32_t>() /* right */,
                                   fdp.ConsumeIntegral<int32_t>() /* bottom */
                    );
                    decoder->extractFrame(&rect);
                },
                [&]() {
                    FrameDecoder::getMetadataOnly(
                            trackMeta, fdp.PickValueInArray(kColorFormats) /* colorFormat */,
                            fdp.ConsumeBool() /* thumbnail */);
                },
        });
        frameDecoderAPI();
    }
    return 0;
}

}  // namespace android
