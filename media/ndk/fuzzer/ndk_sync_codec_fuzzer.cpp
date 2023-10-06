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
#include <NdkMediaCodecFuzzerBase.h>

constexpr int32_t kMaxNdkCodecAPIs = 12;

class NdkSyncCodecFuzzer : public NdkMediaCodecFuzzerBase {
  public:
    NdkSyncCodecFuzzer(const uint8_t* data, size_t size)
        : NdkMediaCodecFuzzerBase(), mFdp(data, size) {
        setFdp(&mFdp);
    };
    void invokeSyncCodeConfigAPI();

    static void CodecOnFrameRendered(AMediaCodec* codec, void* userdata, int64_t mediaTimeUs,
                                     int64_t systemNano) {
        (void)codec;
        (void)userdata;
        (void)mediaTimeUs;
        (void)systemNano;
    };

  private:
    FuzzedDataProvider mFdp;
    AMediaCodec* mCodec = nullptr;
    void invokekSyncCodecAPIs(bool isEncoder);
};

void NdkSyncCodecFuzzer::invokekSyncCodecAPIs(bool isEncoder) {
    ANativeWindow* nativeWindow = nullptr;
    int32_t numOfFrames = mFdp.ConsumeIntegralInRange<size_t>(kMinIterations, kMaxIterations);
    int32_t count = 0;
    while (++count <= numOfFrames) {
        int32_t ndkcodecAPI = mFdp.ConsumeIntegralInRange<size_t>(kMinAPICase, kMaxNdkCodecAPIs);
        switch (ndkcodecAPI) {
            case 0: {  // configure the codec
                AMediaCodec_configure(mCodec, getCodecFormat(), nativeWindow, nullptr /* crypto */,
                                      (isEncoder ? AMEDIACODEC_CONFIGURE_FLAG_ENCODE : 0));
                break;
            }
            case 1: {  // start codec
                AMediaCodec_start(mCodec);
                break;
            }
            case 2: {  // stop codec
                AMediaCodec_stop(mCodec);
                break;
            }
            case 3: {  // create persistent input surface
                AMediaCodec_createPersistentInputSurface(&nativeWindow);
                break;
            }
            case 4: {  // buffer operation APIs
                invokeInputBufferOperationAPI(mCodec);
                break;
            }
            case 5: {
                invokeOutputBufferOperationAPI(mCodec);
                break;
            }
            case 6: {  // get input and output Format
                invokeCodecFormatAPI(mCodec);
                break;
            }
            case 7: {
                AMediaCodec_signalEndOfInputStream(mCodec);
                break;
            }
            case 8: {  // set parameters
                // Create a new parameter and set
                AMediaFormat* params = AMediaFormat_new();
                AMediaFormat_setInt32(
                        params, "video-bitrate",
                        mFdp.ConsumeIntegralInRange<size_t>(kMinIntKeyValue, kMaxIntKeyValue));
                AMediaCodec_setParameters(mCodec, params);
                AMediaFormat_delete(params);
                break;
            }
            case 9: {  // flush codec
                AMediaCodec_flush(mCodec);
                if (mFdp.ConsumeBool()) {
                    AMediaCodec_start(mCodec);
                }
                break;
            }
            case 10: {  // get the codec name
                char* name = nullptr;
                AMediaCodec_getName(mCodec, &name);
                AMediaCodec_releaseName(mCodec, name);
                break;
            }
            case 11: {  // set callback API for frame render output
                std::vector<uint8_t> userData = mFdp.ConsumeBytes<uint8_t>(
                        mFdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
                AMediaCodecOnFrameRendered callback = CodecOnFrameRendered;
                AMediaCodec_setOnFrameRenderedCallback(mCodec, callback, userData.data());
                break;
            }
            case 12:
            default: {  // set persistent input surface
                AMediaCodec_setInputSurface(mCodec, nativeWindow);
            }
        }
    }
    if (nativeWindow) {
        ANativeWindow_release(nativeWindow);
    }
}

void NdkSyncCodecFuzzer::invokeSyncCodeConfigAPI() {
    while (mFdp.remaining_bytes() > 0) {
        bool isEncoder = mFdp.ConsumeBool();
        mCodec = createCodec(isEncoder, mFdp.ConsumeBool() /* isCodecForClient */);
        if (mCodec) {
            invokekSyncCodecAPIs(isEncoder);
            AMediaCodec_delete(mCodec);
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    NdkSyncCodecFuzzer ndkSyncCodecFuzzer(data, size);
    ndkSyncCodecFuzzer.invokeSyncCodeConfigAPI();
    return 0;
}
