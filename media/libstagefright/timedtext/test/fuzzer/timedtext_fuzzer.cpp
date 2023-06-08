/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <binder/Parcel.h>
#include <timedtext/TextDescriptions.h>
#include <timedtext_fuzz.pb.h>
#include "fuzzer/FuzzedDataProvider.h"
#include "src/libfuzzer/libfuzzer_macro.h"

using namespace android;
constexpr int32_t kTextBytes = 2;
constexpr int32_t kChunkBytes = 8;
constexpr int32_t kChunkTypeBytes = 4;
constexpr int32_t kGlobalTextOffset = 0;
constexpr size_t kByte3Mask = 0xff000000UL;
constexpr size_t kByte2Mask = 0x00ff0000UL;
constexpr size_t kByte1Mask = 0x0000ff00UL;
constexpr size_t kByte0Mask = 0x000000ffUL;

/**
 * Sets ChunkSize/ChunkType (uint32_t) in timedtext-description vector<uint8_t>
 * by extracting each byte from ChunkSize and populating the vector.
 */
void setChunkParameter(std::vector<uint8_t>& timedtext, size_t param, size_t paramOffset) {
    timedtext[paramOffset + 0] = (param & kByte3Mask) >> 24;
    timedtext[paramOffset + 1] = (param & kByte2Mask) >> 16;
    timedtext[paramOffset + 2] = (param & kByte1Mask) >> 8;
    timedtext[paramOffset + 3] = (param & kByte0Mask);
}

/**
 * Sets TextLength(uint16_t) in 3GPPLocal-description vector<uint8_t>
 * by extracting each byte from TextLength and populating the vector.
 */
void setTextSize(std::vector<uint8_t>& local3GPPDescription, int32_t textLength) {
    local3GPPDescription[0] = (textLength & kByte1Mask) >> 8;
    local3GPPDescription[1] = (textLength & kByte0Mask);
}

DEFINE_PROTO_FUZZER(const TimedText& input) {
    switch (input.handle()) {
        case flag3gppglobal: {
            size_t gppGlobalByteSize = input.global().ByteSizeLong();
            if (gppGlobalByteSize) {
                std::vector<uint8_t> global3GPPDescription(gppGlobalByteSize + kChunkBytes);
                setChunkParameter(global3GPPDescription, gppGlobalByteSize, kGlobalTextOffset);
                setChunkParameter(global3GPPDescription, tx3g, kGlobalTextOffset + kChunkTypeBytes);
                input.global().SerializeToArray(global3GPPDescription.data() + kChunkBytes,
                                                global3GPPDescription.size());
                Parcel* parcel = new Parcel();
                TextDescriptions::getParcelOfDescriptions(
                        global3GPPDescription.data(), global3GPPDescription.size(),
                        TextDescriptions::IN_BAND_TEXT_3GPP | TextDescriptions::GLOBAL_DESCRIPTIONS,
                        input.timems(), parcel);
                delete parcel;
            }
            break;
        }
        case flag3gpplocal: {
            size_t gppLocalByteSize = input.local().ByteSizeLong();
            if (gppLocalByteSize) {
                std::vector<uint8_t> local3GPPDescription(gppLocalByteSize + kChunkBytes +
                                                          kTextBytes);
                std::string text = input.local().localtext().text();
                int32_t textLength = text.size();
                setTextSize(local3GPPDescription, textLength);
                input.local().localtext().SerializeToArray(local3GPPDescription.data() + kTextBytes,
                                                           textLength);
                size_t gppLocalFormatSize = input.local().format().ByteSizeLong();
                size_t textOffset = textLength + kTextBytes;
                setChunkParameter(local3GPPDescription, gppLocalFormatSize, textOffset);
                switch (input.local().format().formatStyle_case()) {
                    case GPPLocalFormat::FormatStyleCase::kTextbox: {
                        setChunkParameter(local3GPPDescription, styl, textOffset + kChunkTypeBytes);
                        input.local().format().SerializeToArray(
                                local3GPPDescription.data() + textOffset + kChunkBytes,
                                gppLocalFormatSize);
                        break;
                    }
                    case GPPLocalFormat::FormatStyleCase::kHltbox: {
                        setChunkParameter(local3GPPDescription, hlit, textOffset + kChunkTypeBytes);
                        input.local().format().SerializeToArray(
                                local3GPPDescription.data() + textOffset + kChunkBytes,
                                gppLocalFormatSize);
                        break;
                    }
                    case GPPLocalFormat::FormatStyleCase::kHltcolor: {
                        setChunkParameter(local3GPPDescription, hclr, textOffset + kChunkTypeBytes);
                        input.local().format().SerializeToArray(
                                local3GPPDescription.data() + textOffset + kChunkBytes,
                                gppLocalFormatSize);
                        break;
                    }
                    case GPPLocalFormat::FormatStyleCase::kKrokbox: {
                        setChunkParameter(local3GPPDescription, krok, textOffset + kChunkTypeBytes);
                        input.local().format().SerializeToArray(
                                local3GPPDescription.data() + textOffset + kChunkBytes,
                                gppLocalFormatSize);
                        break;
                    }
                    case GPPLocalFormat::FormatStyleCase::kScrollDelay: {
                        setChunkParameter(local3GPPDescription, dlay, textOffset + kChunkTypeBytes);
                        input.local().format().SerializeToArray(
                                local3GPPDescription.data() + textOffset + kChunkBytes,
                                gppLocalFormatSize);
                        break;
                    }
                    case GPPLocalFormat::FormatStyleCase::kHrefBox: {
                        setChunkParameter(local3GPPDescription, href, textOffset + kChunkTypeBytes);
                        input.local().format().SerializeToArray(
                                local3GPPDescription.data() + textOffset + kChunkBytes,
                                gppLocalFormatSize);
                        break;
                    }
                    case GPPLocalFormat::FormatStyleCase::kBoxrecord: {
                        setChunkParameter(local3GPPDescription, tbox, textOffset + kChunkTypeBytes);
                        input.local().format().SerializeToArray(
                                local3GPPDescription.data() + textOffset + kChunkBytes,
                                gppLocalFormatSize);
                        break;
                    }
                    case GPPLocalFormat::FormatStyleCase::kBlinkBox: {
                        setChunkParameter(local3GPPDescription, blnk, textOffset + kChunkTypeBytes);
                        input.local().format().SerializeToArray(
                                local3GPPDescription.data() + textOffset + kChunkBytes,
                                gppLocalFormatSize);
                        break;
                    }
                    case GPPLocalFormat::FormatStyleCase::kWrapFlag: {
                        setChunkParameter(local3GPPDescription, txrp, textOffset + kChunkTypeBytes);
                        input.local().format().SerializeToArray(
                                local3GPPDescription.data() + textOffset + kChunkBytes,
                                gppLocalFormatSize);
                        break;
                    }
                    default: {
                        break;
                    }
                }
                Parcel* parcel = new Parcel();
                TextDescriptions::getParcelOfDescriptions(
                        local3GPPDescription.data(), local3GPPDescription.size(),
                        TextDescriptions::IN_BAND_TEXT_3GPP | TextDescriptions::LOCAL_DESCRIPTIONS,
                        input.timems(), parcel);
                delete parcel;
            }
            break;
        }
        case flagsrtlocal: {
            size_t srtByteSize = input.srt().ByteSizeLong();
            if (srtByteSize) {
                std::vector<uint8_t> srtLocalDescription(srtByteSize);
                input.srt().SerializeToArray(srtLocalDescription.data(),
                                             srtLocalDescription.size());
                Parcel* parcel = new Parcel();
                TextDescriptions::getParcelOfDescriptions(
                        srtLocalDescription.data(), srtLocalDescription.size(),
                        TextDescriptions::OUT_OF_BAND_TEXT_SRT |
                                TextDescriptions::LOCAL_DESCRIPTIONS,
                        input.timems(), parcel);
                delete parcel;
            }
            break;
        }
        default:
            break;
    }
}
