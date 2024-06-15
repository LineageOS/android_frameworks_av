/*
 * Copyright (C) 2018 The Android Open Source Project
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
#define LOG_TAG "media_c2_hidl_test_common"
#include <stdio.h>
#include <numeric>
#include "media_c2_hidl_test_common.h"

#include <android/hardware/media/c2/1.0/IComponentStore.h>
#include <codec2/aidl/ParamTypes.h>

std::string sResourceDir = "";

std::string sComponentNamePrefix = "";

static constexpr struct option kArgOptions[] = {
        {"res", required_argument, 0, 'P'},
        {"prefix", required_argument, 0, 'p'},
        {"help", required_argument, 0, 'h'},
        {nullptr, 0, nullptr, 0},
};

void printUsage(char* me) {
    std::cerr << "VTS tests to test codec2 components \n";
    std::cerr << "Usage: " << me << " [options] \n";
    std::cerr << "\t -P,  --res:    Mandatory path to a folder that contains test resources \n";
    std::cerr << "\t -p,  --prefix: Optional prefix to select component/s to be tested \n";
    std::cerr << "\t                    All codecs are tested by default \n";
    std::cerr << "\t                    Eg: c2.android - test codecs starting with c2.android \n";
    std::cerr << "\t                    Eg: c2.android.aac.decoder - test a specific codec \n";
    std::cerr << "\t -h,  --help:   Print usage \n";
}

C2PooledBlockPool::BufferPoolVer getBufferPoolVer() {
    if (::aidl::android::hardware::media::c2::utils::IsSelected()) {
        return C2PooledBlockPool::VER_AIDL2;
    } else {
        return C2PooledBlockPool::VER_HIDL;
    }
}

void parseArgs(int argc, char** argv) {
    int arg;
    int option_index;
    while ((arg = getopt_long(argc, argv, ":P:p:h", kArgOptions, &option_index)) != -1) {
        switch (arg) {
            case 'P':
                sResourceDir = optarg;
                break;
            case 'p':
                sComponentNamePrefix = optarg;
                break;
            case 'h':
                printUsage(argv[0]);
                break;
            default:
                break;
        }
    }
}

// Test the codecs for NullBuffer, Empty Input Buffer with(out) flags set
void testInputBuffer(const std::shared_ptr<android::Codec2Client::Component>& component,
                     std::mutex& queueLock, std::list<std::unique_ptr<C2Work>>& workQueue,
                     uint32_t flags, bool isNullBuffer) {
    std::unique_ptr<C2Work> work;
    {
        typedef std::unique_lock<std::mutex> ULock;
        ULock l(queueLock);
        if (!workQueue.empty()) {
            work.swap(workQueue.front());
            workQueue.pop_front();
        } else {
            ASSERT_TRUE(false) << "workQueue Empty at the start of test";
        }
    }
    ASSERT_NE(work, nullptr);

    work->input.flags = (C2FrameData::flags_t)flags;
    work->input.ordinal.timestamp = 0;
    work->input.ordinal.frameIndex = 0;
    work->input.buffers.clear();
    if (isNullBuffer) {
        work->input.buffers.emplace_back(nullptr);
    }
    work->worklets.clear();
    work->worklets.emplace_back(new C2Worklet);

    std::list<std::unique_ptr<C2Work>> items;
    items.push_back(std::move(work));
    ASSERT_EQ(component->queue(&items), C2_OK);
}

// Wait for all the inputs to be consumed by the plugin.
void waitOnInputConsumption(std::mutex& queueLock, std::condition_variable& queueCondition,
                            std::list<std::unique_ptr<C2Work>>& workQueue, size_t bufferCount) {
    typedef std::unique_lock<std::mutex> ULock;
    uint32_t queueSize;
    uint32_t maxRetry = 0;
    {
        ULock l(queueLock);
        queueSize = workQueue.size();
    }
    while ((maxRetry < MAX_RETRY) && (queueSize < bufferCount)) {
        ULock l(queueLock);
        if (queueSize != workQueue.size()) {
            queueSize = workQueue.size();
            maxRetry = 0;
        } else {
            queueCondition.wait_for(l, TIME_OUT);
            maxRetry++;
        }
    }
}

// process onWorkDone received by Listener
void workDone(const std::shared_ptr<android::Codec2Client::Component>& component,
              std::unique_ptr<C2Work>& work, std::list<uint64_t>& flushedIndices,
              std::mutex& queueLock, std::condition_variable& queueCondition,
              std::list<std::unique_ptr<C2Work>>& workQueue, bool& eos, bool& csd,
              uint32_t& framesReceived) {
    // handle configuration changes in work done
    if (work->worklets.front()->output.configUpdate.size() != 0) {
        ALOGV("Config Update");
        std::vector<std::unique_ptr<C2Param>> updates =
                std::move(work->worklets.front()->output.configUpdate);
        std::vector<C2Param*> configParam;
        std::vector<std::unique_ptr<C2SettingResult>> failures;
        for (size_t i = 0; i < updates.size(); ++i) {
            C2Param* param = updates[i].get();
            if (param->index() == C2StreamInitDataInfo::output::PARAM_TYPE) {
                C2StreamInitDataInfo::output* csdBuffer = (C2StreamInitDataInfo::output*)(param);
                size_t csdSize = csdBuffer->flexCount();
                if (csdSize > 0) csd = true;
            } else if ((param->index() == C2StreamSampleRateInfo::output::PARAM_TYPE) ||
                       (param->index() == C2StreamChannelCountInfo::output::PARAM_TYPE) ||
                       (param->index() == C2StreamPictureSizeInfo::output::PARAM_TYPE)) {
                configParam.push_back(param);
            }
        }
        component->config(configParam, C2_DONT_BLOCK, &failures);
        ASSERT_EQ(failures.size(), 0u);
    }
    if (work->worklets.front()->output.flags != C2FrameData::FLAG_INCOMPLETE) {
        framesReceived++;
        eos = (work->worklets.front()->output.flags & C2FrameData::FLAG_END_OF_STREAM) != 0;
        auto frameIndexIt = std::find(flushedIndices.begin(), flushedIndices.end(),
                                      work->input.ordinal.frameIndex.peeku());
        ALOGV("WorkDone: frameID received %d",
              (int)work->worklets.front()->output.ordinal.frameIndex.peeku());
        work->input.buffers.clear();
        work->worklets.clear();
        {
            typedef std::unique_lock<std::mutex> ULock;
            ULock l(queueLock);
            workQueue.push_back(std::move(work));
            if (!flushedIndices.empty() && (frameIndexIt != flushedIndices.end())) {
                flushedIndices.erase(frameIndexIt);
            }
            queueCondition.notify_all();
        }
    }
}

// Return current time in micro seconds
int64_t getNowUs() {
    struct timeval tv;
    gettimeofday(&tv, NULL);

    return (int64_t)tv.tv_usec + tv.tv_sec * 1000000ll;
}

// Return all test parameters, a list of tuple of <instance, component>
const std::vector<TestParameters>& getTestParameters() {
    return getTestParameters(C2Component::DOMAIN_OTHER, C2Component::KIND_OTHER);
}

// Return all test parameters, a list of tuple of <instance, component> with matching domain and
// kind.
const std::vector<TestParameters>& getTestParameters(C2Component::domain_t domain,
                                                     C2Component::kind_t kind) {
    static std::vector<TestParameters> parameters;

    auto instances = android::Codec2Client::GetServiceNames();
    for (std::string instance : instances) {
        std::shared_ptr<android::Codec2Client> client =
                android::Codec2Client::CreateFromService(instance.c_str());
        std::vector<C2Component::Traits> components = client->listComponents();
        for (C2Component::Traits traits : components) {
            if (instance.compare(traits.owner)) continue;
            if (domain != C2Component::DOMAIN_OTHER &&
                (traits.domain != domain || traits.kind != kind)) {
                continue;
            }
            if (traits.name.rfind(sComponentNamePrefix, 0) != 0) {
                ALOGD("Skipping tests for %s. Prefix specified is %s", traits.name.c_str(),
                      sComponentNamePrefix.c_str());
                continue;
            }
            parameters.push_back(std::make_tuple(instance, traits.name));
        }
    }

    if (parameters.empty()) {
        ALOGE("No test parameters added. Verify component prefix passed to the test");
    }
    return parameters;
}

constexpr static std::initializer_list<std::pair<uint32_t, uint32_t>> flagList{
        {(1 << VTS_BIT_FLAG_SYNC_FRAME), 0},
        {(1 << VTS_BIT_FLAG_CSD_FRAME), C2FrameData::FLAG_CODEC_CONFIG},
};

/*
 * This is a conversion function that can be used to convert
 * VTS flags to C2 flags and vice-versa based on the initializer list.
 * @param flags can be a C2 flag or a VTS flag
 * @param toC2 if true, converts flags to a C2 flag
 *              if false, converts flags to a VTS flag
 */
static uint32_t convertFlags(uint32_t flags, bool toC2) {
    return std::transform_reduce(
            flagList.begin(), flagList.end(),
            0u,
            std::bit_or{},
            [flags, toC2](const std::pair<uint32_t, uint32_t> &entry) {
                if (toC2) {
                    return (flags & entry.first) ? entry.second : 0;
                } else {
                    return (flags & entry.second) ? entry.first : 0;
                }
            });
}

// Populate Info vector and return number of CSDs
int32_t populateInfoVector(std::string info, android::Vector<FrameInfo>* frameInfo,
                           bool timestampDevTest, std::list<uint64_t>* timestampUslist) {
    std::ifstream eleInfo;
    eleInfo.open(info);
    if (!eleInfo.is_open()) {
        ALOGE("Can't open info file");
        return -1;
    }
    int32_t numCsds = 0;
    int32_t bytesCount = 0;
    uint32_t flags = 0;
    uint32_t vtsFlags = 0;
    uint32_t timestamp = 0;
    uint32_t nLargeFrames = 0;
    while (1) {
        if (!(eleInfo >> bytesCount)) break;
        eleInfo >> flags;
        vtsFlags = mapInfoFlagstoVtsFlags(flags);
        if (vtsFlags == 0xFF) {
            ALOGE("unrecognized flag(0x%x) entry in info file %s", flags, info.c_str());
            return -1;
        }
        eleInfo >> timestamp;
        bool codecConfig = (vtsFlags & (1 << VTS_BIT_FLAG_CSD_FRAME)) != 0 ;
        if (codecConfig) numCsds++;
        bool nonDisplayFrame = (vtsFlags & (1 << VTS_BIT_FLAG_NO_SHOW_FRAME)) != 0;
        if (timestampDevTest && !codecConfig && !nonDisplayFrame) {
            timestampUslist->push_back(timestamp);
        }
        frameInfo->push_back({bytesCount, vtsFlags, timestamp, {}});
        if (vtsFlags & (1 << VTS_BIT_FLAG_LARGE_AUDIO_FRAME)) {
            eleInfo >> nLargeFrames;
            while(nLargeFrames-- > 0) {
                eleInfo >> bytesCount;
                eleInfo >> flags;
                eleInfo >> timestamp;
                uint32_t c2Flags = convertFlags(flags, true);
                frameInfo->editItemAt(frameInfo->size() - 1).largeFrameInfo.push_back(
                        {c2Flags, static_cast<uint32_t>(bytesCount), timestamp});
            }
        }
    }
    ALOGV("numCsds : %d", numCsds);
    eleInfo.close();
    return numCsds;
}

void verifyFlushOutput(std::list<std::unique_ptr<C2Work>>& flushedWork,
                       std::list<std::unique_ptr<C2Work>>& workQueue,
                       std::list<uint64_t>& flushedIndices, std::mutex& queueLock) {
    // Update mFlushedIndices based on the index received from flush()
    typedef std::unique_lock<std::mutex> ULock;
    uint64_t frameIndex;
    ULock l(queueLock);
    for (std::unique_ptr<C2Work>& work : flushedWork) {
        ASSERT_NE(work, nullptr);
        frameIndex = work->input.ordinal.frameIndex.peeku();
        std::list<uint64_t>::iterator frameIndexIt =
                std::find(flushedIndices.begin(), flushedIndices.end(), frameIndex);
        if (!flushedIndices.empty() && (frameIndexIt != flushedIndices.end())) {
            flushedIndices.erase(frameIndexIt);
            work->input.buffers.clear();
            work->worklets.clear();
            workQueue.push_back(std::move(work));
        }
    }
    ASSERT_EQ(flushedIndices.empty(), true);
    flushedWork.clear();
}

int mapInfoFlagstoVtsFlags(int infoFlags) {
    if (infoFlags == 0) return 0;
    else if (infoFlags == 0x1) return (1 << VTS_BIT_FLAG_SYNC_FRAME);
    else if (infoFlags == 0x10) return (1 << VTS_BIT_FLAG_NO_SHOW_FRAME);
    else if (infoFlags == 0x20) return (1 << VTS_BIT_FLAG_CSD_FRAME);
    else if (infoFlags == 0x40) return (1 << VTS_BIT_FLAG_LARGE_AUDIO_FRAME);
    else if (infoFlags == 0x80) {
        return (1 << VTS_BIT_FLAG_LARGE_AUDIO_FRAME) | (1 << VTS_BIT_FLAG_SYNC_FRAME);
    }
    return 0xFF;
}
