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
#include <GLESRenderEngine.h>
#include <GLFramebuffer.h>
#include <GLImage.h>
#include <Program.h>
#include <ProgramCache.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <renderengine/RenderEngine.h>

using namespace android::renderengine;
using namespace android;

static constexpr int32_t kMinRenderAPI = 0;
static constexpr int32_t kMaxRenderAPI = 8;
static constexpr int32_t kMaxTextureCount = 100;
static constexpr int32_t KMaxDisplayWidth = 3840;
static constexpr int32_t KMaxDisplayHeight = 2160;
static constexpr int32_t kMinPixelFormat = 1;
static constexpr int32_t kMaxPixelFormat = 55;
static constexpr int32_t kMaxRenderLayer = 5;

static constexpr ui::Dataspace kDataSpace[] = {
        ui::Dataspace::UNKNOWN,
        ui::Dataspace::ARBITRARY,
        ui::Dataspace::STANDARD_SHIFT,
        ui::Dataspace::STANDARD_MASK,
        ui::Dataspace::STANDARD_UNSPECIFIED,
        ui::Dataspace::STANDARD_BT709,
        ui::Dataspace::STANDARD_BT601_625,
        ui::Dataspace::STANDARD_BT601_625_UNADJUSTED,
        ui::Dataspace::STANDARD_BT601_525,
        ui::Dataspace::STANDARD_BT601_525_UNADJUSTED,
        ui::Dataspace::STANDARD_BT2020,
        ui::Dataspace::STANDARD_BT2020_CONSTANT_LUMINANCE,
        ui::Dataspace::STANDARD_BT470M,
        ui::Dataspace::STANDARD_FILM,
        ui::Dataspace::STANDARD_DCI_P3,
        ui::Dataspace::STANDARD_ADOBE_RGB,
        ui::Dataspace::TRANSFER_SHIFT,
        ui::Dataspace::TRANSFER_MASK,
        ui::Dataspace::TRANSFER_UNSPECIFIED,
        ui::Dataspace::TRANSFER_LINEAR,
        ui::Dataspace::TRANSFER_SRGB,
        ui::Dataspace::TRANSFER_SMPTE_170M,
        ui::Dataspace::TRANSFER_GAMMA2_2,
        ui::Dataspace::TRANSFER_GAMMA2_6,
        ui::Dataspace::TRANSFER_GAMMA2_8,
        ui::Dataspace::TRANSFER_ST2084,
        ui::Dataspace::TRANSFER_HLG,
        ui::Dataspace::RANGE_SHIFT,
        ui::Dataspace::RANGE_MASK,
        ui::Dataspace::RANGE_UNSPECIFIED,
        ui::Dataspace::RANGE_FULL,
        ui::Dataspace::RANGE_LIMITED,
        ui::Dataspace::RANGE_EXTENDED,
        ui::Dataspace::SRGB_LINEAR,
        ui::Dataspace::V0_SRGB_LINEAR,
        ui::Dataspace::V0_SCRGB_LINEAR,
        ui::Dataspace::SRGB,
        ui::Dataspace::V0_SRGB,
        ui::Dataspace::V0_SCRGB,
        ui::Dataspace::JFIF,
        ui::Dataspace::V0_JFIF,
        ui::Dataspace::BT601_625,
        ui::Dataspace::V0_BT601_625,
        ui::Dataspace::BT601_525,
        ui::Dataspace::V0_BT601_525,
        ui::Dataspace::BT709,
        ui::Dataspace::V0_BT709,
        ui::Dataspace::DCI_P3_LINEAR,
        ui::Dataspace::DCI_P3,
        ui::Dataspace::DISPLAY_P3_LINEAR,
        ui::Dataspace::DISPLAY_P3,
        ui::Dataspace::ADOBE_RGB,
        ui::Dataspace::BT2020_LINEAR,
        ui::Dataspace::BT2020,
        ui::Dataspace::BT2020_PQ,
        ui::Dataspace::DEPTH,
        ui::Dataspace::SENSOR,
        ui::Dataspace::BT2020_ITU,
        ui::Dataspace::BT2020_ITU_PQ,
        ui::Dataspace::BT2020_ITU_HLG,
        ui::Dataspace::BT2020_HLG,
        ui::Dataspace::DISPLAY_BT2020,
        ui::Dataspace::DYNAMIC_DEPTH,
        ui::Dataspace::JPEG_APP_SEGMENTS,
        ui::Dataspace::HEIF,
};

static constexpr int32_t kReadBufferUsage[] = {
        GRALLOC_USAGE_SW_READ_NEVER, GRALLOC_USAGE_SW_READ_RARELY, GRALLOC_USAGE_SW_READ_OFTEN,
        GRALLOC_USAGE_SW_READ_MASK};

static constexpr int32_t kWriteBufferUsage[] = {
        GRALLOC_USAGE_SW_WRITE_NEVER, GRALLOC_USAGE_SW_WRITE_RARELY, GRALLOC_USAGE_SW_WRITE_OFTEN,
        GRALLOC_USAGE_SW_WRITE_MASK};

static constexpr int32_t kRenderBufferUsage[] = {
        GRALLOC_USAGE_HW_TEXTURE,
        GRALLOC_USAGE_HW_RENDER,
        GRALLOC_USAGE_HW_2D,
        GRALLOC_USAGE_HW_COMPOSER,
        GRALLOC_USAGE_HW_FB,
        GRALLOC_USAGE_EXTERNAL_DISP,
        GRALLOC_USAGE_PROTECTED,
        GRALLOC_USAGE_CURSOR,
        GRALLOC_USAGE_HW_VIDEO_ENCODER,
        GRALLOC_USAGE_HW_CAMERA_WRITE,
        GRALLOC_USAGE_HW_CAMERA_READ,
        GRALLOC_USAGE_HW_CAMERA_ZSL,
        GRALLOC_USAGE_HW_CAMERA_MASK,
        GRALLOC_USAGE_HW_MASK,
        GRALLOC_USAGE_RENDERSCRIPT,
        GRALLOC_USAGE_FOREIGN_BUFFERS,
        GRALLOC_USAGE_HW_IMAGE_ENCODER,
};

static constexpr RenderEngine::ContextPriority kSetContextPriority[] = {
        RenderEngine::ContextPriority::LOW, RenderEngine::ContextPriority::MEDIUM,
        RenderEngine::ContextPriority::HIGH};

static constexpr RenderEngine::RenderEngineType kSetRenderEngineType[] = {
        RenderEngine::RenderEngineType::GLES, RenderEngine::RenderEngineType::THREADED};

static constexpr RenderEngine::CleanupMode kCleanupMode[] = {
        RenderEngine::CleanupMode::CLEAN_OUTPUT_RESOURCES, RenderEngine::CleanupMode::CLEAN_ALL};

class RenderFrightFuzzer {
  public:
    RenderFrightFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    FuzzedDataProvider mFdp;
    void getLayerSetting(renderengine::LayerSettings& layerSetting, sp<GraphicBuffer> buffer,
                         const Rect& sourceCrop, uint32_t textureName);
};

void RenderFrightFuzzer::getLayerSetting(renderengine::LayerSettings& layerSetting,
                                         sp<GraphicBuffer> buffer, const Rect& sourceCrop,
                                         uint32_t textureName) {
    layerSetting.geometry.boundaries = sourceCrop.toFloatRect();
    layerSetting.geometry.roundedCornersRadius = mFdp.ConsumeFloatingPoint<float>();
    layerSetting.geometry.roundedCornersCrop = sourceCrop.toFloatRect();

    layerSetting.alpha = mFdp.ConsumeFloatingPoint<float>();
    layerSetting.sourceDataspace = mFdp.PickValueInArray(kDataSpace);
    layerSetting.backgroundBlurRadius = mFdp.ConsumeFloatingPoint<float>();
    layerSetting.source.buffer.buffer = buffer;
    layerSetting.source.buffer.isOpaque = mFdp.ConsumeBool();
    layerSetting.source.buffer.fence = Fence::NO_FENCE;
    layerSetting.source.buffer.textureName = textureName;
    layerSetting.source.buffer.usePremultipliedAlpha = mFdp.ConsumeBool();
    layerSetting.source.buffer.isY410BT2020 =
            (layerSetting.sourceDataspace == ui::Dataspace::BT2020_ITU_PQ ||
             layerSetting.sourceDataspace == ui::Dataspace::BT2020_ITU_HLG);
    layerSetting.source.buffer.maxMasteringLuminance = mFdp.ConsumeFloatingPoint<float>();
    layerSetting.source.buffer.maxContentLuminance = mFdp.ConsumeFloatingPoint<float>();

    layerSetting.shadow.lightPos =
            vec3(mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>(), 0);
    layerSetting.shadow.ambientColor = {
            mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>(),
            mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>()};
    layerSetting.shadow.spotColor = {
            mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>(),
            mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>()};
    layerSetting.shadow.length = mFdp.ConsumeFloatingPoint<float>();
    layerSetting.shadow.casterIsTranslucent = mFdp.ConsumeBool();
}

void RenderFrightFuzzer::process() {
    auto args = RenderEngineCreationArgs::Builder()
                        .setPixelFormat(mFdp.ConsumeIntegralInRange<int32_t>(kMinPixelFormat,
                                                                             kMaxPixelFormat))
                        .setImageCacheSize(mFdp.ConsumeIntegral<uint32_t>())
                        .setUseColorManagerment(mFdp.ConsumeBool())
                        .setEnableProtectedContext(mFdp.ConsumeBool())
                        .setPrecacheToneMapperShaderOnly(mFdp.ConsumeBool())
                        .setSupportsBackgroundBlur(mFdp.ConsumeBool())
                        .setContextPriority(mFdp.PickValueInArray(kSetContextPriority))
                        .setRenderEngineType(mFdp.PickValueInArray(kSetRenderEngineType))
                        .build();
    std::unique_ptr<RenderEngine> renderEngine = RenderEngine::create(args);

    std::vector<uint32_t> textures;
    int32_t maxCount = mFdp.ConsumeIntegralInRange<size_t>(0, kMaxTextureCount);
    for (size_t i = 0; i < maxCount; ++i) {
        textures.push_back(mFdp.ConsumeIntegral<uint32_t>());
    }

    while (mFdp.remaining_bytes()) {
        int32_t renderFrightAPIs =
                mFdp.ConsumeIntegralInRange<int32_t>(kMinRenderAPI, kMaxRenderAPI);
        switch (renderFrightAPIs) {
            case 0: {
                renderEngine->genTextures(textures.size(), textures.data());
                break;
            }
            case 1: {
                renderEngine->deleteTextures(textures.size(), textures.data());
                break;
            }
            case 2: {
                renderEngine->useProtectedContext(mFdp.ConsumeBool());
                break;
            }
            case 3: {
                renderEngine->cleanupPostRender(mFdp.PickValueInArray(kCleanupMode));
                break;
            }
            case 4: {
                renderEngine->unbindExternalTextureBuffer(mFdp.ConsumeIntegral<uint64_t>());
                break;
            }
            case 5: {
                renderEngine->primeCache();
                break;
            }
            case 6: {
                sp<Fence> fence = sp<Fence>::make();
                sp<GraphicBuffer> buffer = sp<GraphicBuffer>::make();
                renderEngine->bindExternalTextureBuffer(mFdp.ConsumeIntegral<uint32_t>(), buffer,
                                                        fence);
                break;
            }
            case 7: {
                sp<GraphicBuffer> buffer = sp<GraphicBuffer>::make();
                renderEngine->cacheExternalTextureBuffer(buffer);
                break;
            }
            case 8: {
                std::vector<const renderengine::LayerSettings*> layers;
                renderengine::LayerSettings layerSetting;
                int32_t width = mFdp.ConsumeIntegralInRange<int32_t>(0, KMaxDisplayWidth);
                int32_t height = mFdp.ConsumeIntegralInRange<int32_t>(0, KMaxDisplayHeight);
                Rect sourceCrop(mFdp.ConsumeIntegralInRange<int32_t>(0, width),
                                mFdp.ConsumeIntegralInRange<int32_t>(0, height));
                uint32_t textureName = 0;
                /* Get a single texture name to pass to layers */
                renderEngine->genTextures(1 /*numTextures*/, &textureName);
                sp<GraphicBuffer> buffer;
                const uint32_t usage = (mFdp.PickValueInArray(kReadBufferUsage) |
                                        mFdp.PickValueInArray(kWriteBufferUsage) |
                                        mFdp.PickValueInArray(kRenderBufferUsage));

                for (int i = 0; i < kMaxRenderLayer; ++i) {
                    buffer = new GraphicBuffer(
                            width, height,
                            mFdp.ConsumeIntegralInRange<int32_t>(PIXEL_FORMAT_RGBA_8888,
                                                                 PIXEL_FORMAT_RGBA_4444),
                            usage, "input");
                    getLayerSetting(layerSetting, buffer, sourceCrop, textureName);
                    layers.push_back(&layerSetting);
                }

                DisplaySettings settings;
                settings.physicalDisplay = sourceCrop;
                settings.clip = sourceCrop;
                settings.outputDataspace = mFdp.PickValueInArray(kDataSpace);
                settings.maxLuminance = mFdp.ConsumeFloatingPoint<float>();

                sp<GraphicBuffer> dstBuffer =
                        new GraphicBuffer(width, height,
                                          mFdp.ConsumeIntegralInRange<int32_t>(
                                                  PIXEL_FORMAT_RGBA_8888, PIXEL_FORMAT_RGBA_4444),
                                          usage, "output");
                base::unique_fd bufferFence;
                base::unique_fd drawFence;

                renderEngine->drawLayers(settings, layers, dstBuffer, mFdp.ConsumeBool(),
                                         std::move(bufferFence),
                                         (mFdp.ConsumeBool() ? nullptr : &drawFence));
            }
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    RenderFrightFuzzer renderFrightFuzzer(data, size);
    renderFrightFuzzer.process();
    return 0;
}
