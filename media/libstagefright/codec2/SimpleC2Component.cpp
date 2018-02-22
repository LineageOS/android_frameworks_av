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

#define LOG_NDEBUG 0
#define LOG_TAG "SimpleC2Component"
#include <media/stagefright/foundation/ADebug.h>

#include <inttypes.h>

#include <C2PlatformSupport.h>
#include <SimpleC2Component.h>

namespace android {

std::unique_ptr<C2Work> SimpleC2Component::WorkQueue::pop_front() {
    std::unique_ptr<C2Work> work = std::move(mQueue.front().work);
    mQueue.pop_front();
    return work;
}

void SimpleC2Component::WorkQueue::push_back(std::unique_ptr<C2Work> work) {
    mQueue.push_back({ std::move(work), NO_DRAIN });
}

bool SimpleC2Component::WorkQueue::empty() const {
    return mQueue.empty();
}

void SimpleC2Component::WorkQueue::clear() {
    mQueue.clear();
}

uint32_t SimpleC2Component::WorkQueue::drainMode() const {
    return mQueue.front().drainMode;
}

void SimpleC2Component::WorkQueue::markDrain(uint32_t drainMode) {
    mQueue.push_back({ nullptr, drainMode });
}

SimpleC2Component::SimpleC2Component(
        const std::shared_ptr<C2ComponentInterface> &intf)
    : mIntf(intf) {
}

c2_status_t SimpleC2Component::setListener_vb(
        const std::shared_ptr<C2Component::Listener> &listener, c2_blocking_t mayBlock) {
    Mutexed<ExecState>::Locked state(mExecState);
    if (state->mState == RUNNING) {
        if (listener) {
            return C2_BAD_STATE;
        } else if (!mayBlock) {
            return C2_BLOCKING;
        }
    }
    state->mListener = listener;
    // TODO: wait for listener change to have taken place before returning
    // (e.g. if there is an ongoing listener callback)
    return C2_OK;
}

c2_status_t SimpleC2Component::queue_nb(std::list<std::unique_ptr<C2Work>> * const items) {
    {
        Mutexed<ExecState>::Locked state(mExecState);
        if (state->mState != RUNNING) {
            return C2_BAD_STATE;
        }
    }
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        while (!items->empty()) {
            queue->push_back(std::move(items->front()));
            items->pop_front();
        }
        queue->mCondition.broadcast();
    }
    return C2_OK;
}

c2_status_t SimpleC2Component::announce_nb(const std::vector<C2WorkOutline> &items) {
    (void) items;
    return C2_OMITTED;
}

c2_status_t SimpleC2Component::flush_sm(
        flush_mode_t flushThrough, std::list<std::unique_ptr<C2Work>>* const flushedWork) {
    (void) flushThrough;
    {
        Mutexed<ExecState>::Locked state(mExecState);
        if (state->mState != RUNNING) {
            return C2_BAD_STATE;
        }
    }
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        queue->incGeneration();
        while (!queue->empty()) {
            std::unique_ptr<C2Work> work = queue->pop_front();
            if (work) {
                flushedWork->push_back(std::move(work));
            }
        }
    }
    {
        Mutexed<PendingWork>::Locked pending(mPendingWork);
        while (!pending->empty()) {
            flushedWork->push_back(std::move(pending->begin()->second));
            pending->erase(pending->begin());
        }
    }

    return onFlush_sm();
}

c2_status_t SimpleC2Component::drain_nb(drain_mode_t drainMode) {
    if (drainMode == DRAIN_CHAIN) {
        return C2_OMITTED;
    }
    {
        Mutexed<ExecState>::Locked state(mExecState);
        if (state->mState != RUNNING) {
            return C2_BAD_STATE;
        }
    }
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        queue->markDrain(drainMode);
        queue->mCondition.broadcast();
    }

    return C2_OK;
}

c2_status_t SimpleC2Component::start() {
    Mutexed<ExecState>::Locked state(mExecState);
    if (state->mState == RUNNING) {
        return C2_BAD_STATE;
    }
    bool needsInit = (state->mState == UNINITIALIZED);
    if (needsInit) {
        state.unlock();
        c2_status_t err = onInit();
        if (err != C2_OK) {
            return err;
        }
        state.lock();
    }
    if (!state->mThread.joinable()) {
        mExitRequested = false;
        state->mThread = std::thread(
                [](std::weak_ptr<SimpleC2Component> wp) {
                    while (true) {
                        std::shared_ptr<SimpleC2Component> thiz = wp.lock();
                        if (!thiz) {
                            return;
                        }
                        if (thiz->exitRequested()) {
                            return;
                        }
                        thiz->processQueue();
                    }
                },
                shared_from_this());
    }
    state->mState = RUNNING;
    return C2_OK;
}

c2_status_t SimpleC2Component::stop() {
    {
        Mutexed<ExecState>::Locked state(mExecState);
        if (state->mState != RUNNING) {
            return C2_BAD_STATE;
        }
        state->mState = STOPPED;
    }
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        queue->clear();
    }
    {
        Mutexed<PendingWork>::Locked pending(mPendingWork);
        pending->clear();
    }
    c2_status_t err = onStop();
    if (err != C2_OK) {
        return err;
    }
    return C2_OK;
}

c2_status_t SimpleC2Component::reset() {
    {
        Mutexed<ExecState>::Locked state(mExecState);
        state->mState = UNINITIALIZED;
    }
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        queue->clear();
    }
    {
        Mutexed<PendingWork>::Locked pending(mPendingWork);
        pending->clear();
    }
    onReset();
    return C2_OK;
}

c2_status_t SimpleC2Component::release() {
    std::thread releasing;
    {
        Mutexed<ExecState>::Locked state(mExecState);
        releasing = std::move(state->mThread);
    }
    mExitRequested = true;
    releasing.join();
    onRelease();
    return C2_OK;
}

std::shared_ptr<C2ComponentInterface> SimpleC2Component::intf() {
    return mIntf;
}

namespace {

std::list<std::unique_ptr<C2Work>> vec(std::unique_ptr<C2Work> &work) {
    std::list<std::unique_ptr<C2Work>> ret;
    ret.push_back(std::move(work));
    return ret;
}

}  // namespace

void SimpleC2Component::finish(
        uint64_t frameIndex, std::function<void(const std::unique_ptr<C2Work> &)> fillWork) {
    std::unique_ptr<C2Work> work;
    {
        Mutexed<PendingWork>::Locked pending(mPendingWork);
        if (pending->count(frameIndex) == 0) {
            ALOGW("unknown frame index: %" PRIu64, frameIndex);
            return;
        }
        work = std::move(pending->at(frameIndex));
        pending->erase(frameIndex);
    }
    if (work) {
        fillWork(work);
        Mutexed<ExecState>::Locked state(mExecState);
        state->mListener->onWorkDone_nb(shared_from_this(), vec(work));
        ALOGV("returning pending work");
    }
}

void SimpleC2Component::processQueue() {
    std::unique_ptr<C2Work> work;
    uint64_t generation;
    int32_t drainMode;
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        nsecs_t deadline = systemTime() + ms2ns(250);
        while (queue->empty()) {
            nsecs_t now = systemTime();
            if (now >= deadline) {
                return;
            }
            status_t err = queue.waitForConditionRelative(queue->mCondition, deadline - now);
            if (err == TIMED_OUT) {
                return;
            }
        }

        generation = queue->generation();
        drainMode = queue->drainMode();
        work = queue->pop_front();
    }

    if (!mOutputBlockPool) {
        c2_status_t err = [this] {
            // TODO: don't use query_vb
            C2StreamFormatConfig::output outputFormat(0u);
            c2_status_t err = intf()->query_vb(
                    { &outputFormat },
                    {},
                    C2_DONT_BLOCK,
                    nullptr);
            if (err != C2_OK) {
                return err;
            }
            err = GetCodec2BlockPool(
                    (outputFormat.value == C2FormatVideo)
                    ? C2BlockPool::BASIC_GRAPHIC
                    : C2BlockPool::BASIC_LINEAR,
                    shared_from_this(),
                    &mOutputBlockPool);
            if (err != C2_OK) {
                return err;
            }
            return C2_OK;
        }();
        if (err != C2_OK) {
            Mutexed<ExecState>::Locked state(mExecState);
            state->mListener->onError_nb(shared_from_this(), err);
            return;
        }
    }

    if (!work) {
        c2_status_t err = drain(drainMode, mOutputBlockPool);
        if (err != C2_OK) {
            Mutexed<ExecState>::Locked state(mExecState);
            state->mListener->onError_nb(shared_from_this(), err);
        }
        return;
    }

    process(work, mOutputBlockPool);
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        if (queue->generation() != generation) {
            ALOGW("work form old generation: was %" PRIu64 " now %" PRIu64, queue->generation(), generation);
            work->result = C2_NOT_FOUND;
            queue.unlock();
            {
                Mutexed<ExecState>::Locked state(mExecState);
                state->mListener->onWorkDone_nb(shared_from_this(), vec(work));
            }
            queue.lock();
            return;
        }
    }
    if (work->workletsProcessed != 0u) {
        Mutexed<ExecState>::Locked state(mExecState);
        ALOGV("returning this work");
        state->mListener->onWorkDone_nb(shared_from_this(), vec(work));
    } else {
        ALOGV("queue pending work");
        std::unique_ptr<C2Work> unexpected;
        {
            Mutexed<PendingWork>::Locked pending(mPendingWork);
            uint64_t frameIndex = work->input.ordinal.frameIndex.peeku();
            if (pending->count(frameIndex) != 0) {
                unexpected = std::move(pending->at(frameIndex));
                pending->erase(frameIndex);
            }
            (void) pending->insert({ frameIndex, std::move(work) });
        }
        if (unexpected) {
            unexpected->result = C2_CORRUPTED;
            Mutexed<ExecState>::Locked state(mExecState);
            state->mListener->onWorkDone_nb(shared_from_this(), vec(unexpected));
        }
    }
}

std::shared_ptr<C2Buffer> SimpleC2Component::createLinearBuffer(
        const std::shared_ptr<C2LinearBlock> &block) {
    return createLinearBuffer(block, block->offset(), block->size());
}

std::shared_ptr<C2Buffer> SimpleC2Component::createLinearBuffer(
        const std::shared_ptr<C2LinearBlock> &block, size_t offset, size_t size) {
    return C2Buffer::CreateLinearBuffer(block->share(offset, size, ::android::C2Fence()));
}

std::shared_ptr<C2Buffer> SimpleC2Component::createGraphicBuffer(
        const std::shared_ptr<C2GraphicBlock> &block) {
    return createGraphicBuffer(block, C2Rect(0, 0, block->width(), block->height()));
}

std::shared_ptr<C2Buffer> SimpleC2Component::createGraphicBuffer(
        const std::shared_ptr<C2GraphicBlock> &block, const C2Rect &crop) {
    return C2Buffer::CreateGraphicBuffer(block->share(crop, ::android::C2Fence()));
}

} // namespace android
