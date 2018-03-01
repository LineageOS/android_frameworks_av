/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef SIMPLE_C2_COMPONENT_H_
#define SIMPLE_C2_COMPONENT_H_

#include <list>
#include <thread>
#include <unordered_map>

#include <C2Component.h>

#include <media/stagefright/foundation/Mutexed.h>

namespace android {

class SimpleC2Component
        : public C2Component, public std::enable_shared_from_this<SimpleC2Component> {
public:
    SimpleC2Component(
            const std::shared_ptr<C2ComponentInterface> &intf);
    virtual ~SimpleC2Component() = default;

    // C2Component
    // From C2Component
    virtual c2_status_t setListener_vb(
            const std::shared_ptr<Listener> &listener, c2_blocking_t mayBlock) override;
    virtual c2_status_t queue_nb(std::list<std::unique_ptr<C2Work>>* const items) override;
    virtual c2_status_t announce_nb(const std::vector<C2WorkOutline> &items) override;
    virtual c2_status_t flush_sm(
            flush_mode_t mode, std::list<std::unique_ptr<C2Work>>* const flushedWork) override;
    virtual c2_status_t drain_nb(drain_mode_t mode) override;
    virtual c2_status_t start() override;
    virtual c2_status_t stop() override;
    virtual c2_status_t reset() override;
    virtual c2_status_t release() override;
    virtual std::shared_ptr<C2ComponentInterface> intf() override;

    // for thread
    inline bool exitRequested() { return mExitRequested; }
    void processQueue();
    void signalExit();

protected:
    /**
     * Initialize internal states of the component according to the config set
     * in the interface.
     *
     * This method is called during start(), but only at the first invocation or
     * after reset().
     */
    virtual c2_status_t onInit() = 0;

    /**
     * Stop the component.
     */
    virtual c2_status_t onStop() = 0;

    /**
     * Reset the component.
     */
    virtual void onReset() = 0;

    /**
     * Release the component.
     */
    virtual void onRelease() = 0;

    /**
     * Flush the component.
     */
    virtual c2_status_t onFlush_sm() = 0;

    /**
     * Process the given work and finish pending work using finish().
     *
     * \param[in,out]   work    the work to process
     * \param[in]       pool    the pool to use for allocating output blocks.
     */
    virtual void process(
            const std::unique_ptr<C2Work> &work,
            const std::shared_ptr<C2BlockPool> &pool) = 0;

    /**
     * Drain the component and finish pending work using finish().
     *
     * \param[in]   drainMode   mode of drain.
     * \param[in]   pool        the pool to use for allocating output blocks.
     *
     * \retval C2_OK            The component has drained all pending output
     *                          work.
     * \retval C2_OMITTED       Unsupported mode (e.g. DRAIN_CHAIN)
     */
    virtual c2_status_t drain(
            uint32_t drainMode,
            const std::shared_ptr<C2BlockPool> &pool) = 0;

    // for derived classes
    /**
     * Finish pending work.
     *
     * This method will retrieve the pending work according to |frameIndex| and
     * feed the work into |fillWork| function. |fillWork| must be
     * "non-blocking". Once |fillWork| returns the filled work will be returned
     * to the client.
     *
     * \param[in]   frameIndex    the index of the pending work
     * \param[in]   fillWork      the function to fill the retrieved work.
     */
    void finish(uint64_t frameIndex, std::function<void(const std::unique_ptr<C2Work> &)> fillWork);

    std::shared_ptr<C2Buffer> createLinearBuffer(
            const std::shared_ptr<C2LinearBlock> &block);

    std::shared_ptr<C2Buffer> createLinearBuffer(
            const std::shared_ptr<C2LinearBlock> &block, size_t offset, size_t size);

    std::shared_ptr<C2Buffer> createGraphicBuffer(
            const std::shared_ptr<C2GraphicBlock> &block);

    std::shared_ptr<C2Buffer> createGraphicBuffer(
            const std::shared_ptr<C2GraphicBlock> &block,
            const C2Rect &crop);

    static constexpr uint32_t NO_DRAIN = ~0u;

private:
    const std::shared_ptr<C2ComponentInterface> mIntf;
    std::atomic_bool mExitRequested;

    enum {
        UNINITIALIZED,
        STOPPED,
        RUNNING,
    };

    struct ExecState {
        ExecState() : mState(UNINITIALIZED) {}

        int mState;
        std::thread mThread;
        std::shared_ptr<C2Component::Listener> mListener;
    };
    Mutexed<ExecState> mExecState;

    class WorkQueue {
    public:
        inline WorkQueue() : mFlush(false), mGeneration(0ul) {}

        inline uint64_t generation() const { return mGeneration; }
        inline void incGeneration() { ++mGeneration; mFlush = true; }

        std::unique_ptr<C2Work> pop_front();
        void push_back(std::unique_ptr<C2Work> work);
        bool empty() const;
        uint32_t drainMode() const;
        void markDrain(uint32_t drainMode);
        inline bool popPendingFlush() {
            bool flush = mFlush;
            mFlush = false;
            return flush;
        }
        void clear();

        Condition mCondition;

    private:
        struct Entry {
            std::unique_ptr<C2Work> work;
            uint32_t drainMode;
        };

        bool mFlush;
        uint64_t mGeneration;
        std::list<Entry> mQueue;
    };
    Mutexed<WorkQueue> mWorkQueue;

    typedef std::unordered_map<uint64_t, std::unique_ptr<C2Work>> PendingWork;
    Mutexed<PendingWork> mPendingWork;

    struct ExitMonitor {
        inline ExitMonitor() : mExited(false) {}
        Condition mCondition;
        bool mExited;
    };
    Mutexed<ExitMonitor> mExitMonitor;

    std::shared_ptr<C2BlockPool> mOutputBlockPool;

    SimpleC2Component() = delete;

    void requestExitAndWait(std::function<void()> job);
};

}  // namespace android

#endif  // SIMPLE_C2_COMPONENT_H_
