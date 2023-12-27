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

#ifndef CODEC2_COMMON_MULTI_ACCESSUNIT_HELPER_H
#define CODEC2_COMMON_MULTI_ACCESSUNIT_HELPER_H

#include <hidl/Status.h>
#include <hwbinder/IBinder.h>

#include <C2Config.h>
#include <util/C2InterfaceHelper.h>
#include <C2Buffer.h>
#include <C2.h>

#include <set>
#include <memory>
#include <mutex>

namespace android {

struct MultiAccessUnitHelper;

struct MultiAccessUnitInterface : public C2InterfaceHelper {
    explicit MultiAccessUnitInterface(
            const std::shared_ptr<C2ComponentInterface>& interface,
            std::shared_ptr<C2ReflectorHelper> helper);

    bool isParamSupported(C2Param::Index index);
    C2LargeFrame::output getLargeFrameParam() const;
    C2Component::kind_t kind() const;

protected:
    void getDecoderSampleRateAndChannelCount(
            uint32_t &sampleRate_, uint32_t &channelCount_) const;
    const std::shared_ptr<C2ComponentInterface> mC2ComponentIntf;
    std::shared_ptr<C2LargeFrame::output> mLargeFrameParams;
    C2ComponentKindSetting mKind;
    std::set<C2Param::Index> mSupportedParamIndexSet;

    friend struct MultiAccessUnitHelper;
};

struct MultiAccessUnitHelper {
public:
    MultiAccessUnitHelper(
            const std::shared_ptr<MultiAccessUnitInterface>& intf);

    virtual ~MultiAccessUnitHelper();

    static bool isEnabledOnPlatform();

    /*
     * Scatters the incoming linear buffer into access-unit sized buffers
     * based on the access-unit info.
     */
    c2_status_t scatter(
            std::list<std::unique_ptr<C2Work>> &c2workItems,
            std::list<std::list<std::unique_ptr<C2Work>>> * const processedWork);

    /*
     * Gathers different access-units into a single buffer based on the scatter list
     * and the configured max and threshold sizes. This also generates the associated
     * access-unit information and attach it with the final result.
     */
    c2_status_t gather(
            std::list<std::unique_ptr<C2Work>> &c2workItems,
            std::list<std::unique_ptr<C2Work>> * const processedWork);

    /*
     * Flushes the codec and generated the list of flushed buffers.
     */
    c2_status_t flush(
            std::list<std::unique_ptr<C2Work>> * const c2flushedWorks);

    /*
     * Gets all the pending buffers under generation in c2workItems.
     */
    c2_status_t error(std::list<std::unique_ptr<C2Work>> * const c2workItems);

    /*
     * Get the interface object of this handler.
     */
    std::shared_ptr<MultiAccessUnitInterface> getInterface();

    /*
     * Gets the status of the object. This really is to make sure that
     * all the allocators are configured properly within the handler.
     */
    bool getStatus();

    /*
     * Resets the structures inside the handler.
     */
    void reset();

protected:

    struct MultiAccessUnitInfo {
        /*
         * From the input
         * Ordinal of the input frame
         */
        C2WorkOrdinalStruct inOrdinal;

        /*
         * Frame indexes of the scattered buffers
         */
        std::set<uint64_t> mComponentFrameIds;

        /*
         * For the output
         * Current output block.
         */
        std::shared_ptr<C2LinearBlock> mBlock;

        /*
         * Write view of current block
         */
        std::shared_ptr<C2WriteView> mWview;

        /*
         * C2Info related to the current mBlock
         */
        std::vector<std::shared_ptr<const C2Info>> mInfos;

        /*
         * C2AccessUnitInfos for the current buffer
         */
        std::vector<C2AccessUnitInfosStruct> mAccessUnitInfos;

        /*
         * Current tuning used to process this input work
         */
        C2LargeFrame::output mLargeFrameTuning;

        /*
         * Current output C2Work being processed
         */
        std::unique_ptr<C2Work> mLargeWork;

        MultiAccessUnitInfo(C2WorkOrdinalStruct ordinal):inOrdinal(ordinal) {

        }

        /*
         * Resets this frame
         */
        void reset();
    };

    /*
     * Creates a linear block to be used with work
     */
    c2_status_t createLinearBlock(MultiAccessUnitInfo &frame);

    /*
     * Processes worklets from the component
     */
    c2_status_t processWorklets(MultiAccessUnitInfo &frame,
                std::unique_ptr<C2Work> &work,
                const std::function <void(std::unique_ptr<C2Work>&)> &addWork);

    /*
     * Finalizes the work to be send out.
     */
    c2_status_t finalizeWork(MultiAccessUnitInfo &frame,
            uint32_t flags = 0, bool forceComplete = false);

    /*
     * Merges different access unit infos if possible
     */
    void mergeAccessUnitInfo(MultiAccessUnitInfo &frame,
            uint32_t flags,
            uint32_t size,
            int64_t timestamp);

    bool mInit;

    // Interface of this module
    std::shared_ptr<MultiAccessUnitInterface> mInterface;
    // Local pool id used for output buffer allocation
    C2BlockPool::local_id_t mBlockPoolId;
    // C2Blockpool for output buffer allocation
    std::shared_ptr<C2BlockPool> mLinearPool;
    // Allocator for output buffer allocation
    std::shared_ptr<C2Allocator> mLinearAllocator;
    // FrameIndex for the current outgoing work
    std::atomic_uint64_t mFrameIndex;
    // Mutex to protect mFrameHolder
    std::mutex mLock;
    // List of Infos that contains the input and
    // output work and buffer objects
    std::list<MultiAccessUnitInfo> mFrameHolder;
};

}  // namespace android

#endif  // CODEC2_COMMON_MULTI_ACCESSUNIT_HELPER_H
