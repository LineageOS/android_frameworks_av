/*
 * Copyright 2020 The Android Open Source Project
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
// Authors: corbin.souffrant@leviathansecurity.com
//          dylan.katz@leviathansecurity.com

#include <android-base/file.h>
#include <ctype.h>
#include <media/mediarecorder.h>
#include <media/stagefright/MPEG4Writer.h>
#include <media/stagefright/MediaDefs.h>
#include <stdlib.h>
#include <utils/StrongPointer.h>
#include <utils/Vector.h>

#include <functional>
#include <string>

#include "FuzzerMediaUtility.h"
#include "fuzzer/FuzzedDataProvider.h"

static constexpr uint16_t kMaxOperations = 5000;
static constexpr uint8_t kMaxPackageNameLen = 50;
// For other strings in mpeg we want a higher limit.
static constexpr uint16_t kMaxMPEGStrLen = 1000;
static constexpr uint16_t kMaxMediaBlobSize = 1000;

namespace android {

std::string getFourCC(FuzzedDataProvider *fdp) {
    std::string fourCC = fdp->ConsumeRandomLengthString(4);
    // Replace any existing nulls
    for (size_t pos = 0; pos < fourCC.length(); pos++) {
        if (fourCC.at(pos) == '\0') {
            fourCC.replace(pos, 1, "a");
        }
    }

    // If our string is too short, fill the remainder with "a"s.
    while (fourCC.length() < 4) {
        fourCC += 'a';
    }
    return fourCC;
}

typedef std::vector<std::function<void(FuzzedDataProvider*,
                                    sp<MediaWriter>, sp<MetaData>, int tmpFileFd)>> OperationVec;
typedef std::vector<std::function<void(FuzzedDataProvider*, MPEG4Writer*)>> MPEG4OperationVec;
static const OperationVec operations = {
    [](FuzzedDataProvider*, sp<MediaWriter> mediaWriter, sp<MetaData>, int) {
        mediaWriter->pause();
    },
    [](FuzzedDataProvider *dataProvider, sp<MediaWriter> mediaWriter, sp<MetaData>, int tmpFd) {
        bool valid_fd = dataProvider->ConsumeBool();
        int fd = -1;
        if (valid_fd) {
            fd = tmpFd;
        }
        // Args don't seem to be used
        Vector<String16> args;
        mediaWriter->dump(fd, args);
    },
    [](FuzzedDataProvider *dataProvider, sp<MediaWriter> mediaWriter, sp<MetaData>, int tmpFd) {
        bool valid_fd = dataProvider->ConsumeBool();
        int fd = -1;
        if (valid_fd) {
            fd = tmpFd;
        }
        mediaWriter->setNextFd(fd);
    },
    [](FuzzedDataProvider *dataProvider, sp<MediaWriter> mediaWriter, sp<MetaData>, int) {
        mediaWriter->setCaptureRate(dataProvider->ConsumeFloatingPoint<float>());
    },
    [](FuzzedDataProvider *dataProvider, sp<MediaWriter> mediaWriter, sp<MetaData>, int) {
        mediaWriter->setMaxFileDuration(dataProvider->ConsumeIntegral<int64_t>());
    },
    [](FuzzedDataProvider *dataProvider, sp<MediaWriter> mediaWriter, sp<MetaData>, int) {
        mediaWriter->setStartTimeOffsetMs(dataProvider->ConsumeIntegral<int>());

        // Likely won't do much, but might as well as do a quick check
        // while we're here.
        mediaWriter->getStartTimeOffsetMs();
    },
    [](FuzzedDataProvider *dataProvider, sp<MediaWriter> mediaWriter, sp<MetaData>, int) {
        mediaWriter->setMaxFileDuration(dataProvider->ConsumeIntegral<int64_t>());
    },
    [](FuzzedDataProvider *dataProvider, sp<MediaWriter> mediaWriter, sp<MetaData>, int) {
        mediaWriter->setMaxFileDuration(dataProvider->ConsumeIntegral<int64_t>());
    },
};

static const MPEG4OperationVec mpeg4Operations = {
    [](FuzzedDataProvider*, MPEG4Writer *mediaWriter) { mediaWriter->notifyApproachingLimit(); },
    // Lower level write methods.
    // High-level startBox/endBox/etc are all called elsewhere,
    [](FuzzedDataProvider *dataProvider, MPEG4Writer *mediaWriter) {
        uint8_t val = dataProvider->ConsumeIntegral<uint8_t>();
        mediaWriter->writeInt8(val);
    },
    [](FuzzedDataProvider *dataProvider, MPEG4Writer *mediaWriter) {
        uint16_t val = dataProvider->ConsumeIntegral<uint16_t>();
        mediaWriter->writeInt16(val);
    },
    [](FuzzedDataProvider *dataProvider, MPEG4Writer *mediaWriter) {
        uint32_t val = dataProvider->ConsumeIntegral<uint32_t>();
        mediaWriter->writeInt32(val);
    },
    [](FuzzedDataProvider *dataProvider, MPEG4Writer *mediaWriter) {
        uint64_t val = dataProvider->ConsumeIntegral<uint64_t>();
        mediaWriter->writeInt64(val);
    },
    [](FuzzedDataProvider *dataProvider, MPEG4Writer *mediaWriter) {
        std::string strVal = dataProvider->ConsumeRandomLengthString(kMaxMPEGStrLen);
        mediaWriter->writeCString(strVal.c_str());
    },
    [](FuzzedDataProvider *dataProvider, MPEG4Writer *mediaWriter) {
        std::string fourCC = getFourCC(dataProvider);
        mediaWriter->writeFourcc(fourCC.c_str());
    },

    // Misc setters
    [](FuzzedDataProvider *dataProvider, MPEG4Writer *mediaWriter) {
        uint32_t layers = dataProvider->ConsumeIntegral<uint32_t>();
        mediaWriter->setTemporalLayerCount(layers);
    },
    [](FuzzedDataProvider *dataProvider, MPEG4Writer *mediaWriter) {
        uint32_t duration = dataProvider->ConsumeIntegral<uint32_t>();
        mediaWriter->setInterleaveDuration(duration);
    },
    [](FuzzedDataProvider *dataProvider, MPEG4Writer *mediaWriter) {
        int lat = dataProvider->ConsumeIntegral<int>();
        int lon = dataProvider->ConsumeIntegral<int>();
        mediaWriter->setGeoData(lat, lon);
    },
};

// Not all writers can always add new sources, so we'll need additional checks.
void addSource(FuzzedDataProvider *dataProvider, sp<MediaWriter> mediaWriter) {
    sp<MediaSource> mediaSource = genMediaSource(dataProvider, kMaxMediaBlobSize);
    if (mediaSource == NULL) {
        // There's a static check preventing NULLs in addSource.
        return;
    }
    mediaWriter->addSource(mediaSource);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider dataProvider(data, size);
    TemporaryFile tf;
    sp<MetaData> fileMeta = new MetaData;
    StandardWriters writerType = dataProvider.ConsumeEnum<StandardWriters>();
    sp<MediaWriter> writer = createWriter(tf.fd, writerType, fileMeta);

    std::string packageName = dataProvider.ConsumeRandomLengthString(kMaxPackageNameLen);

    sp<MediaRecorder> mr = new MediaRecorder(String16(packageName.c_str()));
    writer->setListener(mr);

    uint8_t baseOpLen = operations.size();
    uint8_t totalLen = baseOpLen;
    uint8_t maxSources;
    // Different writers support different amounts of sources.
    switch (writerType) {
        case StandardWriters::AAC:
        case StandardWriters::AAC_ADTS:
        case StandardWriters::AMR_NB:
        case StandardWriters::AMR_WB:
        case StandardWriters::OGG:
            maxSources = 1;
            break;
        case StandardWriters::WEBM:
            maxSources = 2;
            break;
        default:
            maxSources = UINT8_MAX;
            break;
    }
    // Initialize some number of sources and add them to our writer.
    uint8_t sourceCount = dataProvider.ConsumeIntegralInRange<uint8_t>(0, maxSources);
    for (uint8_t i = 0; i < sourceCount; i++) {
        addSource(&dataProvider, writer);
    }

    // Increase our range if additional operations are implemented.
    // Currently only MPEG4 has additiona public operations on their writer.
    if (writerType == StandardWriters::MPEG4) {
        totalLen += mpeg4Operations.size();
    }

    // Many operations require the writer to be started.
    writer->start(fileMeta.get());
    for (size_t ops_run = 0; dataProvider.remaining_bytes() > 0 && ops_run < kMaxOperations - 1;
            ops_run++) {
        uint8_t op = dataProvider.ConsumeIntegralInRange<uint8_t>(0, totalLen - 1);
        if (op < baseOpLen) {
            operations[op](&dataProvider, writer, fileMeta, tf.fd);
        } else if (writerType == StandardWriters::MPEG4) {
            mpeg4Operations[op - baseOpLen](&dataProvider, (MPEG4Writer*)writer.get());
        } else {
            // Here just in case, will error out.
            operations[op](&dataProvider, writer, fileMeta, tf.fd);
        }
    }
    writer->stop();

    writer.clear();
    writer = nullptr;
    return 0;
}
}  // namespace android
