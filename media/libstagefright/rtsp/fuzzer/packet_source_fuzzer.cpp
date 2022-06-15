/*
 * Copyright (C) 2023 The Android Open Source Project
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
#include <fuzzer/FuzzedDataProvider.h>
#include <media/stagefright/foundation/AString.h>
#include <media/stagefright/foundation/base64.h>
#include <media/stagefright/rtsp/APacketSource.h>
#include <media/stagefright/rtsp/ASessionDescription.h>

using namespace android;

static constexpr int32_t kMinValue = 0;
static constexpr int32_t kMaxIPAddress = 255;
static constexpr int32_t kMaxFmt = 255;
static constexpr int32_t kMinAPICase = 0;
static constexpr int32_t kMaxPacketSourceAPI = 5;
static constexpr size_t kMinIndex = 1;
static constexpr size_t kMaxCodecConfigs = 4;

std::string kCodecs[] = {"opus",        "ISAC",         "VP8",
                         "google-data", "G722",         "PCMU",
                         "PCMA",        "CN",           "telephone-event",
                         "VP9",         "red",          "ulpfec",
                         "rtx",         "H264",         "iLBC",
                         "H261",        "MPV",          "H263",
                         "AMR",         "AC3",          "G723",
                         "G729A",       "H264",         "MP4V-ES",
                         "H265",        "H263-2000",    "H263-1998",
                         "AMR",         "AMR-WB",       "MP4A-LATM",
                         "MP2T",        "mpeg4-generic"};

std::string kFmtp[] = {"br=",
                       "bw=",
                       "ch-aw-recv=",
                       "mode-change-capability=",
                       "max-red =",
                       "octet-align=",
                       "mode-change-capability=",
                       "max-red=",
                       "profile-level-id=",
                       "packetization-mode=",
                       "profile=",
                       "level=",
                       "apt=",
                       "annexb=",
                       "protocol=",
                       "streamtype=",
                       "mode=",
                       "sizelength=",
                       "indexlength=",
                       "indexdeltalength=",
                       "minptime=",
                       "useinbandfec=",
                       "maxplaybackrate=",
                       "stereo=",
                       "level-asymmetry-allowed=",
                       "max-fs=",
                       "max-fr="};

std::string kCodecConfigString[kMaxCodecConfigs][2] = {{"H264", "profile-level-id="},
                                                       {"MP4A-LATM", "config="},
                                                       {"MP4V-ES", "config="},
                                                       {"mpeg4-generic", "mode="}};

class ASessionPacketFuzzer {
  public:
    ASessionPacketFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    FuzzedDataProvider mFdp;
};

bool checkFormatSupport(const std::string& codec, const std::string& format) {
    for (int i = 0; i < kMaxCodecConfigs; ++i) {
        if (codec == kCodecConfigString[i][0]) {
            if (format == kCodecConfigString[i][1]) {
                return true;
            } else {
                return false;
            }
        }
    }
    return true;
}

void ASessionPacketFuzzer::process() {
    AString inputString;
    const sp<ASessionDescription> sessionPacket = sp<ASessionDescription>::make();
    std::string codec = mFdp.PickValueInArray(kCodecs);
    std::string ipAddress =
            std::to_string(mFdp.ConsumeIntegralInRange(kMinValue, kMaxIPAddress)) + "." +
            std::to_string(mFdp.ConsumeIntegralInRange(kMinValue, kMaxIPAddress)) + "." +
            std::to_string(mFdp.ConsumeIntegralInRange(kMinValue, kMaxIPAddress)) + "." + "0";
    std::string format = mFdp.PickValueInArray(kFmtp);
    std::string fmptStr = format + std::to_string(mFdp.ConsumeIntegralInRange(kMinValue, kMaxFmt)) +
                          ";" + mFdp.PickValueInArray(kFmtp) +
                          std::to_string(mFdp.ConsumeIntegralInRange(kMinValue, kMaxFmt));
    sessionPacket->SDPStringFactory(
            inputString, ipAddress.c_str() /* ip */, mFdp.ConsumeBool() /* isAudio */,
            mFdp.ConsumeIntegral<unsigned int>() /* port */,
            mFdp.ConsumeIntegral<unsigned int>() /* payloadType */,
            mFdp.ConsumeIntegral<unsigned int>() /* as */, codec.c_str(), /* codec */
            fmptStr.c_str() /* fmtp */, mFdp.ConsumeIntegral<int32_t>() /* width */,
            mFdp.ConsumeIntegral<int32_t>() /* height */,
            mFdp.ConsumeIntegral<int32_t>() /* cvoExtMap */);
    sessionPacket->setTo(inputString.c_str(), inputString.size());
    size_t trackSize = sessionPacket->countTracks();
    AString desc = nullptr;
    while (mFdp.remaining_bytes()) {
        int32_t packetSourceAPI =
                mFdp.ConsumeIntegralInRange<size_t>(kMinAPICase, kMaxPacketSourceAPI);
        switch (packetSourceAPI) {
            case 0: {
                unsigned long payload = 0;
                AString params = nullptr;
                sessionPacket->getFormatType(mFdp.ConsumeIntegralInRange(kMinIndex, trackSize - 1),
                                             &payload, &desc, &params);
                break;
            }
            case 1: {
                int32_t width, height;
                unsigned long payload = mFdp.ConsumeIntegral<unsigned long>();
                sessionPacket->getDimensions(mFdp.ConsumeIntegralInRange(kMinIndex, trackSize - 1),
                                             payload, &width, &height);
                break;
            }
            case 2: {
                int32_t cvoExtMap = mFdp.ConsumeIntegral<int32_t>();
                sessionPacket->getCvoExtMap(mFdp.ConsumeIntegralInRange(kMinIndex, trackSize - 1),
                                            &cvoExtMap);
                break;
            }
            case 3: {
                int64_t durationUs = mFdp.ConsumeIntegral<int64_t>();
                sessionPacket->getDurationUs(&durationUs);
                break;
            }
            case 4: {
                int32_t timeScale, numChannels;
                if (desc != nullptr) {
                    sessionPacket->ParseFormatDesc(desc.c_str(), &timeScale, &numChannels);
                }
                break;
            }
            case 5: {
                if (checkFormatSupport(codec, format)) {
                    sp<APacketSource> packetSource = sp<APacketSource>::make(
                            sessionPacket, mFdp.ConsumeIntegralInRange(kMinIndex, trackSize - 1));
                }
                break;
            }
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ASessionPacketFuzzer packetSourceFuzzer(data, size);
    packetSourceFuzzer.process();
    return 0;
}
