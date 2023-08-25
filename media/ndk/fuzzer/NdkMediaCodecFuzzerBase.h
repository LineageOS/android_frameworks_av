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
#pragma once
#include <android/native_window.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <media/NdkMediaCodec.h>
#include <media/NdkMediaCodecPlatform.h>
#include <media/NdkMediaFormat.h>
#include <media/stagefright/MediaCodecConstants.h>

constexpr int32_t kMinBytes = 1;
constexpr int32_t kMaxBytes = 256;
constexpr int32_t kMinIntKeyValue = 0;
constexpr int32_t kMaxIntKeyValue = 6000000;
constexpr int32_t kMinFloatKeyValue = 1.0f;
constexpr int32_t kMaxFloatKeyValue = 500.f;
constexpr int32_t kMinTimeOutUs = 0;
constexpr int32_t kMaxTimeOutUs = 5000;
constexpr int32_t kMinAPICase = 0;
constexpr int32_t kMaxCodecFormatAPIs = 2;
constexpr int32_t kMaxCryptoKey = 16;
constexpr int32_t kMinIterations = 10;
constexpr int32_t kMaxIterations = 100;
constexpr size_t kMinBufferIndex = 1;
constexpr size_t kMaxBufferIndex = 128;

class NdkMediaCodecFuzzerBase {
  public:
    NdkMediaCodecFuzzerBase() { mFormat = AMediaFormat_new(); }
    void invokeCodecFormatAPI(AMediaCodec* codec);
    void invokeInputBufferOperationAPI(AMediaCodec* codec);
    void invokeOutputBufferOperationAPI(AMediaCodec* codec);
    AMediaCodecCryptoInfo* getAMediaCodecCryptoInfo();
    AMediaCodec* createCodec(bool isEncoder, bool isCodecForClient);
    AMediaFormat* getCodecFormat() { return mFormat; };
    void setFdp(FuzzedDataProvider* fdp) { mFdp = fdp; }
    ~NdkMediaCodecFuzzerBase() {
        if (mFormat) {
            AMediaFormat_delete(mFormat);
        }
    }

  private:
    AMediaCodec* createAMediaCodecByname(bool isEncoder, bool isCodecForClient);
    AMediaCodec* createAMediaCodecByType(bool isEncoder, bool isCodecForClient);
    AMediaFormat* getSampleAudioFormat();
    AMediaFormat* getSampleVideoFormat();
    void setCodecFormat();
    AMediaFormat* mFormat = nullptr;
    FuzzedDataProvider* mFdp = nullptr;
};
