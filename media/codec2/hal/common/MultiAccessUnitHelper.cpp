/*
 * Copyright 2023 The Android Open Source Project
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
#define LOG_TAG "Codec2-MultiAccessUnitHelper"
#include <android-base/logging.h>

#include <com_android_media_codec_flags.h>

#include <codec2/common/MultiAccessUnitHelper.h>
#include <android-base/properties.h>

#include <C2BufferPriv.h>
#include <C2Debug.h>
#include <C2PlatformSupport.h>

namespace android {

static C2R MultiAccessUnitParamsSetter(
        bool mayBlock, C2InterfaceHelper::C2P<C2LargeFrame::output> &me) {
    (void)mayBlock;
    C2R res = C2R::Ok();
    if (!me.F(me.v.maxSize).supportsAtAll(me.v.maxSize)) {
        res = res.plus(C2SettingResultBuilder::BadValue(me.F(me.v.maxSize)));
    } else if (!me.F(me.v.thresholdSize).supportsAtAll(me.v.thresholdSize)) {
        res = res.plus(C2SettingResultBuilder::BadValue(me.F(me.v.thresholdSize)));
    } else if (me.v.maxSize < me.v.thresholdSize) {
        me.set().maxSize = me.v.thresholdSize;
    } else if (me.v.thresholdSize == 0 && me.v.maxSize > 0) {
        me.set().thresholdSize = me.v.maxSize;
    }
    std::vector<std::unique_ptr<C2SettingResult>> failures;
    res.retrieveFailures(&failures);
    if (!failures.empty()) {
        me.set().maxSize = 0;
        me.set().thresholdSize = 0;
    }
    return res;
}

MultiAccessUnitInterface::MultiAccessUnitInterface(
        const std::shared_ptr<C2ComponentInterface>& interface,
        std::shared_ptr<C2ReflectorHelper> helper)
        : C2InterfaceHelper(helper), mC2ComponentIntf(interface) {
    setDerivedInstance(this);
    addParameter(
            DefineParam(mLargeFrameParams, C2_PARAMKEY_OUTPUT_LARGE_FRAME)
            .withDefault(new C2LargeFrame::output(0u, 0, 0))
            .withFields({
                C2F(mLargeFrameParams, maxSize).inRange(
                        0, c2_min(UINT_MAX, 10 * 512000 * 8 * 2u)),
                C2F(mLargeFrameParams, thresholdSize).inRange(
                        0, c2_min(UINT_MAX, 10 * 512000 * 8 * 2u))
            })
            .withSetter(MultiAccessUnitParamsSetter)
            .build());
    std::vector<std::shared_ptr<C2ParamDescriptor>> supportedParams;
    querySupportedParams(&supportedParams);
    // Adding to set to do intf seperation in query/config
    for (std::shared_ptr<C2ParamDescriptor> &desc : supportedParams) {
        mSupportedParamIndexSet.insert(desc->index());
    }

    if (mC2ComponentIntf) {
        c2_status_t err = mC2ComponentIntf->query_vb({&mKind}, {}, C2_MAY_BLOCK, nullptr);
    }
}

bool MultiAccessUnitInterface::isParamSupported(C2Param::Index index) {
    return (mSupportedParamIndexSet.count(index) != 0);
}

C2LargeFrame::output MultiAccessUnitInterface::getLargeFrameParam() const {
    return *mLargeFrameParams;
}

C2Component::kind_t MultiAccessUnitInterface::kind() const {
    return (C2Component::kind_t)(mKind.value);
}

void MultiAccessUnitInterface::getDecoderSampleRateAndChannelCount(
        uint32_t &sampleRate_, uint32_t &channelCount_) const {
    if (mC2ComponentIntf) {
        C2StreamSampleRateInfo::output sampleRate;
        C2StreamChannelCountInfo::output channelCount;
        c2_status_t res = mC2ComponentIntf->query_vb(
                {&sampleRate, &channelCount}, {}, C2_MAY_BLOCK, nullptr);
        if (res == C2_OK) {
            sampleRate_ = sampleRate.value;
            channelCount_ = channelCount.value;
        }
    }
}

//C2MultiAccessUnitBuffer
class C2MultiAccessUnitBuffer : public C2Buffer {
    public:
        explicit C2MultiAccessUnitBuffer(
                const std::vector<C2ConstLinearBlock> &blocks):
                C2Buffer(blocks) {
        }
};

//MultiAccessUnitHelper
MultiAccessUnitHelper::MultiAccessUnitHelper(
        const std::shared_ptr<MultiAccessUnitInterface>& intf):
        mInit(false),
        mInterface(intf) {
    std::shared_ptr<C2AllocatorStore> store = GetCodec2PlatformAllocatorStore();
    if(store->fetchAllocator(C2AllocatorStore::DEFAULT_LINEAR, &mLinearAllocator) == C2_OK) {
        mLinearPool = std::make_shared<C2PooledBlockPool>(mLinearAllocator, ++mBlockPoolId);
        mInit = true;
    }
}

MultiAccessUnitHelper::~MultiAccessUnitHelper() {
    std::unique_lock<std::mutex> l(mLock);
    mFrameHolder.clear();
}

bool MultiAccessUnitHelper::isEnabledOnPlatform() {
    bool result = com::android::media::codec::flags::provider_->large_audio_frame();
    if (!result) {
        return false;
    }
    //TODO: remove this before launch
    result = ::android::base::GetBoolProperty("debug.media.c2.large.audio.frame", true);
    LOG(DEBUG) << "MultiAccessUnitHelper " << (result ? "enabled" : "disabled");
    return result;
}

std::shared_ptr<MultiAccessUnitInterface> MultiAccessUnitHelper::getInterface() {
    return mInterface;
}

bool MultiAccessUnitHelper::getStatus() {
    return mInit;
}

void MultiAccessUnitHelper::reset() {
    std::lock_guard<std::mutex> l(mLock);
    mFrameHolder.clear();
}

c2_status_t MultiAccessUnitHelper::error(
        std::list<std::unique_ptr<C2Work>> * const worklist) {
    if (worklist == nullptr) {
        LOG(ERROR) << "Provided null worklist for error()";
        return C2_OK;
    }
    std::unique_lock<std::mutex> l(mLock);
    for (auto frame = mFrameHolder.begin(); frame != mFrameHolder.end(); frame++) {
        if (frame->mLargeWork) {
            finalizeWork(*frame, 0, true);
            worklist->push_back(std::move(frame->mLargeWork));
            frame->reset();
        }
    }
    mFrameHolder.clear();
    return C2_OK;
}

c2_status_t MultiAccessUnitHelper::flush(
        std::list<std::unique_ptr<C2Work>>* const c2flushedWorks) {
    c2_status_t c2res = C2_OK;
    std::lock_guard<std::mutex> l(mLock);
    for (std::unique_ptr<C2Work>& w : *c2flushedWorks) {
        bool foundFlushedFrame = false;
        std::list<MultiAccessUnitInfo>::iterator frame =
                mFrameHolder.begin();
        while (frame != mFrameHolder.end() && !foundFlushedFrame) {
            auto it = frame->mComponentFrameIds.find(
                    w->input.ordinal.frameIndex.peekull());
            if (it != frame->mComponentFrameIds.end()) {
                LOG(DEBUG) << "Multi access-unit flush"
                        << w->input.ordinal.frameIndex.peekull()
                        << " with " << frame->inOrdinal.frameIndex.peekull();
                w->input.ordinal.frameIndex = frame->inOrdinal.frameIndex;
                bool removeEntry = w->worklets.empty()
                        || !w->worklets.front()
                        || (w->worklets.front()->output.flags
                        & C2FrameData::FLAG_INCOMPLETE) == 0;
                if (removeEntry) {
                    frame->mComponentFrameIds.erase(it);
                }
                foundFlushedFrame = true;
            }
            if (frame->mComponentFrameIds.empty()) {
                frame = mFrameHolder.erase(frame);
            } else {
                ++frame;
            }
        }
    }
    return c2res;
}

c2_status_t MultiAccessUnitHelper::scatter(
        std::list<std::unique_ptr<C2Work>> &largeWork,
        std::list<std::list<std::unique_ptr<C2Work>>>* const processedWork) {
    LOG(DEBUG) << "Multiple access-unit: scatter";
    if (processedWork == nullptr) {
        LOG(ERROR) << "MultiAccessUnitHelper provided with no work list";
        return C2_CORRUPTED;
    }
    for (std::unique_ptr<C2Work>& w : largeWork) {
        std::list<std::unique_ptr<C2Work>> sliceWork;
        C2WorkOrdinalStruct inputOrdinal = w->input.ordinal;
        // To hold correspondence and processing bits b/w input and output
        MultiAccessUnitInfo frameInfo(inputOrdinal);
        std::set<uint64_t>& frameSet = frameInfo.mComponentFrameIds;
        uint64_t newFrameIdx = mFrameIndex++;
        // TODO: Do not split buffers if component inherantly supports MultipleFrames.
        // if thats case, only replace frameindex.
        auto cloneInputWork = [&newFrameIdx](std::unique_ptr<C2Work>& inWork, uint32_t flags) {
            std::unique_ptr<C2Work> newWork(new C2Work);
            newWork->input.flags = (C2FrameData::flags_t)flags;
            newWork->input.ordinal = inWork->input.ordinal;
            newWork->input.ordinal.frameIndex = newFrameIdx;
            if (!inWork->input.configUpdate.empty()) {
                for (std::unique_ptr<C2Param>& param : inWork->input.configUpdate) {
                    newWork->input.configUpdate.push_back(
                            std::move(C2Param::Copy(*(param.get()))));
                }
            }
            newWork->input.infoBuffers = (inWork->input.infoBuffers);
            if (!inWork->worklets.empty() && inWork->worklets.front() != nullptr) {
                newWork->worklets.emplace_back(new C2Worklet);
                newWork->worklets.front()->component = inWork->worklets.front()->component;
                std::vector<std::unique_ptr<C2Tuning>> tunings;
                for (std::unique_ptr<C2Tuning>& tuning : inWork->worklets.front()->tunings) {
                    tunings.push_back(std::move(
                            std::unique_ptr<C2Tuning>(
                                    static_cast<C2Tuning*>(
                                            C2Param::Copy(*(tuning.get())).release()))));
                }
                newWork->worklets.front()->tunings = std::move(tunings);
            }
            return newWork;
        };
        if (w->input.buffers.empty()
                || (w->input.buffers.front() == nullptr)
                || (!w->input.buffers.front()->hasInfo(
                        C2AccessUnitInfos::input::PARAM_TYPE))) {
            LOG(DEBUG) << "Empty or MultiAU info buffer scatter frames with frameIndex "
                    << inputOrdinal.frameIndex.peekull()
                    << ") -> newFrameIndex " << newFrameIdx
                    <<" : input ts " << inputOrdinal.timestamp.peekull();
            sliceWork.push_back(std::move(cloneInputWork(w, w->input.flags)));
            if (!w->input.buffers.empty() && w->input.buffers.front() != nullptr) {
                sliceWork.back()->input.buffers = std::move(w->input.buffers);
            }
            frameSet.insert(newFrameIdx);
            processedWork->push_back(std::move(sliceWork));
        }  else {
            const std::vector<std::shared_ptr<C2Buffer>>& inBuffers = w->input.buffers;
            if (inBuffers.front()->data().linearBlocks().size() == 0) {
                LOG(ERROR) << "ERROR: Work has Large frame info but has no linear blocks.";
                return C2_CORRUPTED;
            }
            const std::vector<C2ConstLinearBlock>& multiAU =
                    inBuffers.front()->data().linearBlocks();
            std::shared_ptr<const C2AccessUnitInfos::input> auInfo =
                    std::static_pointer_cast<const C2AccessUnitInfos::input>(
                    w->input.buffers.front()->getInfo(C2AccessUnitInfos::input::PARAM_TYPE));
            uint32_t offset = 0; uint32_t multiAUSize = multiAU.front().size();
            bool sendEos = false;
            for (int idx = 0; idx < auInfo->flexCount(); ++idx) {
                std::vector<C2ConstLinearBlock> au;
                const C2AccessUnitInfosStruct &info = auInfo->m.values[idx];
                sendEos |= (info.flags & C2FrameData::FLAG_END_OF_STREAM);
                std::unique_ptr<C2Work> newWork = cloneInputWork(w, info.flags);
                frameSet.insert(newFrameIdx);
                newFrameIdx = mFrameIndex++;
                newWork->input.ordinal.timestamp = info.timestamp;
                au.push_back(multiAU.front().subBlock(offset, info.size));
                if ((offset + info.size) > multiAUSize) {
                    LOG(ERROR) << "ERROR: access-unit offset > buffer size"
                            << " current offset " << (offset + info.size)
                            << " buffer size " << multiAUSize;
                    return C2_CORRUPTED;
                }
                newWork->input.buffers.push_back(
                        std::shared_ptr<C2Buffer>(new C2MultiAccessUnitBuffer(au)));
                LOG(DEBUG) << "Frame scatter queuing frames WITH info in ordinal "
                        << inputOrdinal.frameIndex.peekull()
                        << " total offset " << offset << " info.size " << info.size
                        << " : TS " << newWork->input.ordinal.timestamp.peekull();
                // add to worklist
                sliceWork.push_back(std::move(newWork));
                processedWork->push_back(std::move(sliceWork));
                offset += info.size;
            }
            if (!sendEos && (w->input.flags & C2FrameData::FLAG_END_OF_STREAM)) {
                if (!processedWork->empty()) {
                    std::list<std::unique_ptr<C2Work>> &sliceWork = processedWork->back();
                    if (!sliceWork.empty()) {
                        std::unique_ptr<C2Work> &work = sliceWork.back();
                        if (work) {
                            work->input.flags = C2FrameData::FLAG_END_OF_STREAM;
                        }
                    }
                }
            }
        }
        if (!processedWork->empty()) {
            {
                C2LargeFrame::output multiAccessParams = mInterface->getLargeFrameParam();
                if (mInterface->kind() == C2Component::KIND_DECODER) {
                    uint32_t sampleRate = 0;
                    uint32_t channelCount = 0;
                    uint32_t frameSize = 0;
                    mInterface->getDecoderSampleRateAndChannelCount(
                            sampleRate, channelCount);
                    if (sampleRate > 0 && channelCount > 0) {
                        frameSize = channelCount * 2;
                        multiAccessParams.maxSize =
                                (multiAccessParams.maxSize / frameSize) * frameSize;
                        multiAccessParams.thresholdSize =
                                (multiAccessParams.thresholdSize / frameSize) * frameSize;
                    }
                }
                frameInfo.mLargeFrameTuning = multiAccessParams;
                std::lock_guard<std::mutex> l(mLock);
                mFrameHolder.push_back(std::move(frameInfo));
            }
        }
    }
    return C2_OK;
}

c2_status_t MultiAccessUnitHelper::gather(
        std::list<std::unique_ptr<C2Work>> &c2workItems,
        std::list<std::unique_ptr<C2Work>>* const processedWork) {
    LOG(DEBUG) << "Multi access-unit gather process";
    if (processedWork == nullptr) {
        LOG(ERROR) << "Nothing provided for processed work";
        return C2_CORRUPTED;
    }
    auto addOutWork = [&processedWork](std::unique_ptr<C2Work>& work) {
        processedWork->push_back(std::move(work));
    };
    {
        std::lock_guard<std::mutex> l(mLock);
        for (auto& work : c2workItems) {
            LOG(DEBUG) << "FrameHolder Size: " << mFrameHolder.size();
            uint64_t thisFrameIndex = work->input.ordinal.frameIndex.peekull();
            bool removeEntry = work->worklets.empty()
                    || !work->worklets.front()
                    || (work->worklets.front()->output.flags
                        & C2FrameData::FLAG_INCOMPLETE) == 0;
            bool foundFrame = false;
            std::list<MultiAccessUnitInfo>::iterator frame =
                    mFrameHolder.begin();
            while (!foundFrame && frame != mFrameHolder.end()) {
                auto it = frame->mComponentFrameIds.find(thisFrameIndex);
                if (it != frame->mComponentFrameIds.end()) {
                    foundFrame = true;
                    LOG(DEBUG) << "onWorkDone (frameIndex " << thisFrameIndex
                            << " worklstsSze " << work->worklets.size()
                            << ") -> frameIndex " << frame->inOrdinal.frameIndex.peekull();
                    if (work->result != C2_OK
                            || work->worklets.empty()
                            || !work->worklets.front()
                            || (frame->mLargeFrameTuning.thresholdSize == 0
                            || frame->mLargeFrameTuning.maxSize == 0)) {
                        if (removeEntry) {
                            frame->mComponentFrameIds.erase(it);
                            removeEntry = false;
                        }
                        if (frame->mLargeWork) {
                            finalizeWork(*frame);
                            addOutWork(frame->mLargeWork);
                            frame->reset();
                        }
                        c2_status_t workResult = work->result;
                        frame->mLargeWork = std::move(work);
                        frame->mLargeWork->input.ordinal.frameIndex =
                                frame->inOrdinal.frameIndex;
                        finalizeWork(*frame);
                        addOutWork(frame->mLargeWork);
                        frame->reset();
                        if (workResult != C2_OK) {
                            frame->mAccessUnitInfos.clear();
                        }
                    } else if (C2_OK != processWorklets(*frame, work, addOutWork)) {
                        LOG(DEBUG) << "Error while processing work";
                    }
                    if (removeEntry) {
                        LOG(DEBUG) << "Removing entry: " << thisFrameIndex
                                << " -> " << frame->inOrdinal.frameIndex.peekull();
                        frame->mComponentFrameIds.erase(it);
                    }
                    // This is to take care of the last bytes and to decide to send with
                    // FLAG_INCOMPLETE or not.
                    if ((frame->mWview
                            && (frame->mWview->offset() > frame->mLargeFrameTuning.thresholdSize))
                            || frame->mComponentFrameIds.empty()) {
                        if (frame->mLargeWork) {
                            finalizeWork(*frame);
                            addOutWork(frame->mLargeWork);
                            frame->reset();
                        }
                    }
                    if (frame->mComponentFrameIds.empty()) {
                        LOG(DEBUG) << "This frame is finished ID " << thisFrameIndex;
                        frame = mFrameHolder.erase(frame);
                        continue;
                    }
                } else {
                    LOG(DEBUG) << "Received an out-of-order output " << thisFrameIndex
                            << " expected: " <<mFrameHolder.front().inOrdinal.frameIndex.peekull();
                }
                frame++;
            }
            if (!foundFrame) {
                LOG(ERROR) <<" Error: Frame Holder reports no frame " << thisFrameIndex;
            }
        }
    }
    return C2_OK;
}

c2_status_t MultiAccessUnitHelper::createLinearBlock(MultiAccessUnitInfo &frame) {
    if (!mInit) {
        LOG(ERROR) << "Large buffer allocator failed";
        return C2_NO_MEMORY;
    }
    C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
    uint32_t maxOutSize = frame.mLargeFrameTuning.maxSize;
    c2_status_t err = mLinearPool->fetchLinearBlock(maxOutSize, usage, &frame.mBlock);
    LOG(DEBUG) << "Allocated block with offset : " << frame.mBlock->offset()
            << " size " << frame.mBlock->size() << " Capacity " << frame.mBlock->capacity();
    if (err != C2_OK) {
        LOG(ERROR) << "Error allocating Multi access-unit Buffer";
        return err;
    }
    frame.mWview = std::make_shared<C2WriteView>(frame.mBlock->map().get());
    LOG(DEBUG) << "Allocated buffer : requested size : " <<
            frame.mLargeFrameTuning.maxSize
            << " alloc size " << frame.mWview->size();
    return C2_OK;
}

/*
 * For every work from the component, we try to do aggregation of work here.
*/
c2_status_t MultiAccessUnitHelper::processWorklets(MultiAccessUnitInfo &frame,
        std::unique_ptr<C2Work>& work,
        const std::function <void(std::unique_ptr<C2Work>&)>& addWork) {
    // This will allocate work, worklet, c2Block
    auto allocateWork = [&](MultiAccessUnitInfo &frame,
            bool allocateWorket = false,
            bool allocateBuffer = false) {
        c2_status_t ret = C2_OK;
        if (frame.mLargeWork == nullptr) {
            frame.mLargeWork.reset(new C2Work);
            frame.mLargeWork->input.ordinal = frame.inOrdinal;
            frame.mLargeWork->input.ordinal.frameIndex = frame.inOrdinal.frameIndex;
        }
        if (allocateWorket) {
            if (frame.mLargeWork->worklets.size() == 0) {
                frame.mLargeWork->worklets.emplace_back(new C2Worklet);
            }
        }
        if (allocateBuffer) {
            if (frame.mWview == nullptr) {
                ret = createLinearBlock(frame);
            }
        }
        return ret;
    };
    // we will only have one worklet.
    bool foundEndOfStream = false;
    for (auto worklet = work->worklets.begin();
             worklet != work->worklets.end() && (*worklet) != nullptr; ++worklet) {
        uint32_t flagsForNoCopy = C2FrameData::FLAG_DROP_FRAME
                | C2FrameData::FLAG_DISCARD_FRAME
                | C2FrameData::FLAG_CORRUPT;
        if ((*worklet)->output.flags & flagsForNoCopy) {
            if (frame.mLargeWork) {
                finalizeWork(frame);
                addWork(frame.mLargeWork);
                frame.reset();
            }
            frame.mLargeWork = std::move(work);
            frame.mLargeWork->input.ordinal.frameIndex = frame.inOrdinal.frameIndex;
            finalizeWork(frame);
            addWork(frame.mLargeWork);
            frame.reset();
            return C2_OK;
        }
        c2_status_t c2ret = allocateWork(frame, true);
        if (c2ret != C2_OK) {
            return c2ret;
        }
        C2FrameData& outputFramedata = frame.mLargeWork->worklets.front()->output;
        if (!(*worklet)->output.configUpdate.empty()) {
            for (auto& configUpdate : (*worklet)->output.configUpdate) {
                outputFramedata.configUpdate.push_back(std::move(configUpdate));
            }
            (*worklet)->output.configUpdate.clear();
        }
        outputFramedata.infoBuffers.insert(outputFramedata.infoBuffers.begin(),
                (*worklet)->output.infoBuffers.begin(),
                (*worklet)->output.infoBuffers.end());
        int64_t sampleTimeUs = 0;
        uint32_t frameSize = 0;
        uint32_t sampleRate = 0;
        uint32_t channelCount = 0;
        mInterface->getDecoderSampleRateAndChannelCount(sampleRate, channelCount);
        if (sampleRate > 0 && channelCount > 0) {
            sampleTimeUs = (1000000u) / (sampleRate * channelCount * 2);
            frameSize = channelCount * 2;
        }
        LOG(DEBUG) << "maxOutSize " << frame.mLargeFrameTuning.maxSize
                << " threshold " << frame.mLargeFrameTuning.thresholdSize;
        if ((*worklet)->output.buffers.size() > 0) {
            allocateWork(frame, true, true);
        }
        LOG(DEBUG) << "This worklet has " << (*worklet)->output.buffers.size() << " buffers"
                << " ts: " << (*worklet)->output.ordinal.timestamp.peekull();
        int64_t workletTimestamp = (*worklet)->output.ordinal.timestamp.peekull();
        int64_t timestamp = workletTimestamp;
        uint32_t flagsForCopy =  ((*worklet)->output.flags) & C2FrameData::FLAG_CODEC_CONFIG;
        for (int bufIdx = 0; bufIdx < (*worklet)->output.buffers.size(); ++bufIdx) {
            std::shared_ptr<C2Buffer>& buffer = (*worklet)->output.buffers[bufIdx];
            if (!buffer || buffer->data().linearBlocks().empty()) {
                continue;
            }
            const std::vector<C2ConstLinearBlock>& blocks = buffer->data().linearBlocks();
            if (blocks.size() > 0) {
                uint32_t inputOffset = 0;
                uint32_t inputSize = blocks.front().size();
                frame.mInfos.insert(frame.mInfos.end(),
                        buffer->info().begin(), buffer->info().end());
                if (frameSize != 0 && (mInterface->kind() == C2Component::KIND_DECODER)) {
                    // For decoders we only split multiples of 16bChannelCount*2
                    inputSize -= (inputSize % frameSize);
                }
                while (inputOffset < inputSize) {
                    if (frame.mWview->offset() >= frame.mLargeFrameTuning.thresholdSize) {
                        frame.mLargeWork->result = C2_OK;
                        finalizeWork(frame, flagsForCopy);
                        addWork(frame.mLargeWork);
                        frame.reset();
                        allocateWork(frame, true, true);
                    }
                    if (mInterface->kind() == C2Component::KIND_ENCODER) {
                        if (inputSize > frame.mLargeFrameTuning.maxSize) {
                            LOG(ERROR) << "Enc: Output buffer too small for AU, configured with "
                                    << frame.mLargeFrameTuning.maxSize
                                    << " block size: " << blocks.front().size()
                                    << "alloc size " << frame.mWview->size();
                            if (frame.mLargeWork
                                    && frame.mWview && frame.mWview->offset() > 0) {
                                finalizeWork(frame, flagsForCopy);
                                addWork(frame.mLargeWork);
                                frame.reset();
                                allocateWork(frame, true, false);
                            }
                            frame.mLargeWork->result = C2_NO_MEMORY;
                            finalizeWork(frame, 0, true);
                            addWork(frame.mLargeWork);
                            frame.reset();
                            return C2_NO_MEMORY;
                        } else if (inputSize > frame.mWview->size()) {
                            LOG(DEBUG) << "Enc: Large frame hitting bufer limit, current size "
                                << frame.mWview->offset();
                            if (frame.mLargeWork
                                    && frame.mWview && frame.mWview->offset() > 0) {
                                finalizeWork(frame, flagsForCopy);
                                addWork(frame.mLargeWork);
                                frame.reset();
                                allocateWork(frame, true, true);
                            }
                        }
                    }
                    C2ReadView rView = blocks.front().map().get();
                    if (rView.error()) {
                        LOG(ERROR) << "Buffer read view error";
                        frame.mLargeWork->result = rView.error();
                        frame.mLargeWork->worklets.clear();
                        finalizeWork(frame, 0, true);
                        addWork(frame.mLargeWork);
                        frame.reset();
                        return C2_NO_MEMORY;
                    }
                    uint32_t toCopy = 0;
                    if (mInterface->kind() == C2Component::KIND_ENCODER) {
                        toCopy = inputSize;
                    } else {
                        toCopy = c2_min(frame.mWview->size(), (inputSize - inputOffset));
                        timestamp = workletTimestamp + inputOffset * sampleTimeUs;
                        LOG(DEBUG) << "ts " << timestamp
                                << " copiedOutput " << inputOffset
                                << " sampleTimeUs " << sampleTimeUs;
                    }
                    LOG(DEBUG) << " Copy size " << toCopy
                            << " ts " << timestamp;
                    memcpy(frame.mWview->data(), rView.data() + inputOffset, toCopy);
                    frame.mWview->setOffset(frame.mWview->offset() + toCopy);
                    inputOffset += toCopy;
                    mergeAccessUnitInfo(frame, flagsForCopy, toCopy, timestamp);
                }
            } else {
                frame.mLargeWork->worklets.front()->output.buffers.push_back(std::move(buffer));
                LOG(DEBUG) << "Copying worklets without linear buffer";
            }
        }
        uint32_t flagsForCsdOrEnd = (*worklet)->output.flags
                & (C2FrameData::FLAG_END_OF_STREAM | C2FrameData::FLAG_CODEC_CONFIG);
        if (flagsForCsdOrEnd) {
            LOG(DEBUG) << "Output worklet has CSD/EOS data";
            frame.mLargeWork->result = C2_OK;
            // we can assign timestamp as this will be evaluated in finalizeWork
            frame.mLargeWork->worklets.front()->output.ordinal.timestamp = timestamp;
            finalizeWork(frame, flagsForCsdOrEnd, true);
            addWork(frame.mLargeWork);
            frame.reset();
        }
    }
    return C2_OK;
}

c2_status_t MultiAccessUnitHelper::finalizeWork(
        MultiAccessUnitInfo& frame, uint32_t inFlags, bool forceComplete) {
    if (frame.mLargeWork == nullptr) {
        return C2_OK;
    }
    //prepare input ordinal
    frame.mLargeWork->input.ordinal = frame.inOrdinal;
    // remove this
    int64_t timeStampUs = frame.inOrdinal.timestamp.peekull();
    if (!frame.mAccessUnitInfos.empty()) {
        timeStampUs = frame.mAccessUnitInfos.front().timestamp;
    } else if (!frame.mLargeWork->worklets.empty()) {
        std::unique_ptr<C2Worklet> &worklet = frame.mLargeWork->worklets.front();
        if (worklet) {
            timeStampUs = worklet->output.ordinal.timestamp.peekull();
        }
    }
    LOG(DEBUG) << "Finalizing work with input Idx "
            << frame.mLargeWork->input.ordinal.frameIndex.peekull()
            << " timestamp " << timeStampUs;
    uint32_t finalFlags = 0;
    if ((!forceComplete)
            && (frame.mLargeWork->result == C2_OK)
            && (!frame.mComponentFrameIds.empty())) {
        finalFlags |= C2FrameData::FLAG_INCOMPLETE;
    }
    if (frame.mLargeWork->result == C2_OK) {
        finalFlags |= inFlags;
    }
    // update worklet if present
    if (!frame.mLargeWork->worklets.empty() &&
            frame.mLargeWork->worklets.front() != nullptr) {
        frame.mLargeWork->workletsProcessed = 1;
        C2FrameData& outFrameData = frame.mLargeWork->worklets.front()->output;
        outFrameData.ordinal.frameIndex = frame.inOrdinal.frameIndex.peekull();
        outFrameData.ordinal.timestamp = timeStampUs;
        finalFlags |= frame.mLargeWork->worklets.front()->output.flags;
        outFrameData.flags = (C2FrameData::flags_t)finalFlags;
        // update buffers
        if (frame.mBlock && (frame.mWview->offset() > 0)) {
            size_t size = frame.mWview->offset();
            LOG(DEBUG) << "Finalize : Block: Large frame size set as " << size
                    << " timestamp as " << timeStampUs
                    << "frameIndex " << outFrameData.ordinal.frameIndex.peekull();
            frame.mWview->setOffset(0);
            std::shared_ptr<C2Buffer> c2Buffer = C2Buffer::CreateLinearBuffer(
                    frame.mBlock->share(0, size, ::C2Fence()));
            if (frame.mAccessUnitInfos.size() > 0) {
                if (finalFlags & C2FrameData::FLAG_END_OF_STREAM) {
                    frame.mAccessUnitInfos.back().flags |=
                            C2FrameData::FLAG_END_OF_STREAM;
                }
                std::shared_ptr<C2AccessUnitInfos::output> largeFrame =
                        C2AccessUnitInfos::output::AllocShared(
                        frame.mAccessUnitInfos.size(), 0u, frame.mAccessUnitInfos);
                frame.mInfos.push_back(largeFrame);
                frame.mAccessUnitInfos.clear();
            }
            for (auto &info : frame.mInfos) {
                c2Buffer->setInfo(std::const_pointer_cast<C2Info>(info));
            }
            frame.mLargeWork->worklets.front()->output.buffers.push_back(std::move(c2Buffer));
            frame.mInfos.clear();
            frame.mBlock.reset();
            frame.mWview.reset();
        }
    }
    LOG(DEBUG) << "Multi access-unitflag setting as " << finalFlags;
    return C2_OK;
}

void MultiAccessUnitHelper::mergeAccessUnitInfo(
        MultiAccessUnitInfo &frame,
        uint32_t flags_,
        uint32_t size,
        int64_t timestamp) {
    // Remove flags that are not part of Access unit info
    uint32_t flags = flags_ & ~(C2FrameData::FLAG_INCOMPLETE
            | C2FrameData::FLAG_DISCARD_FRAME
            | C2FrameData::FLAG_CORRUPT
            | C2FrameData::FLAG_CORRECTED);
    if (frame.mAccessUnitInfos.empty()) {
        frame.mAccessUnitInfos.emplace_back(flags, size, timestamp);
        return;
    }
    if ((mInterface->kind() == C2Component::KIND_DECODER) &&
            (frame.mAccessUnitInfos.back().flags == flags)) {
        // merge access units here
        C2AccessUnitInfosStruct &s = frame.mAccessUnitInfos.back();
        s.size += size; // don't have to update timestamp
    } else {
        frame.mAccessUnitInfos.emplace_back(flags, size, timestamp);
    }
}

void MultiAccessUnitHelper::MultiAccessUnitInfo::reset() {
    mBlock.reset();
    mWview.reset();
    mInfos.clear();
    mAccessUnitInfos.clear();
    mLargeWork.reset();
}

}  // namespace android