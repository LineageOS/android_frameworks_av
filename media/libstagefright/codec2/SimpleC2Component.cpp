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

#include <C2PlatformSupport.h>

#include <SimpleC2Component.h>

namespace android {

SimpleC2Component::SimpleC2Component(
        const std::shared_ptr<C2ComponentInterface> &intf)
    : mIntf(intf) {
}

c2_status_t SimpleC2Component::setListener_sm(const std::shared_ptr<C2Component::Listener> &listener) {
    Mutexed<ExecState>::Locked state(mExecState);
    if (state->mState == RUNNING) {
        return C2_BAD_STATE;
    }
    state->mListener = listener;
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
            queue->mQueue.push_back(std::move(items->front()));
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
        ++queue->mGeneration;
        while (!queue->mQueue.empty()) {
            flushedWork->push_back(std::move(queue->mQueue.front()));
            queue->mQueue.pop_front();
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

c2_status_t SimpleC2Component::drain_nb(drain_mode_t drainThrough) {
    (void) drainThrough;
    {
        Mutexed<ExecState>::Locked state(mExecState);
        if (state->mState != RUNNING) {
            return C2_BAD_STATE;
        }
    }
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        if (!queue->mQueue.empty()) {
            const std::unique_ptr<C2Work> &work = queue->mQueue.back();
            work->input.flags = (C2BufferPack::flags_t)(work->input.flags | C2BufferPack::FLAG_END_OF_STREAM);
            return C2_OK;
        }
    }

    return onDrain_nb();
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
        queue->mQueue.clear();
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

void SimpleC2Component::reset() {
    {
        Mutexed<ExecState>::Locked state(mExecState);
        state->mState = UNINITIALIZED;
    }
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        queue->mQueue.clear();
    }
    {
        Mutexed<PendingWork>::Locked pending(mPendingWork);
        pending->clear();
    }
    onReset();
}

void SimpleC2Component::release() {
    {
        Mutexed<ExecState>::Locked state(mExecState);
        mExitRequested = true;
        state->mThread.join();
    }
    onRelease();
}

std::shared_ptr<C2ComponentInterface> SimpleC2Component::intf() {
    return mIntf;
}

namespace {

std::vector<std::unique_ptr<C2Work>> vec(std::unique_ptr<C2Work> &work) {
    std::vector<std::unique_ptr<C2Work>> ret;
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
            return;
        }
        work = std::move(pending->at(frameIndex));
        pending->erase(frameIndex);
    }
    if (work) {
        fillWork(work);
        Mutexed<ExecState>::Locked state(mExecState);
        state->mListener->onWorkDone_nb(shared_from_this(), vec(work));
    }
}

void SimpleC2Component::processQueue() {
    std::unique_ptr<C2Work> work;
    uint64_t generation;
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        nsecs_t deadline = systemTime() + ms2ns(250);
        while (queue->mQueue.empty()) {
            status_t err = queue.waitForConditionRelative(
                    queue->mCondition, std::max(deadline - systemTime(), (nsecs_t)0));
            if (err == TIMED_OUT) {
                return;
            }
        }

        generation = queue->mGeneration;
        work = std::move(queue->mQueue.front());
        queue->mQueue.pop_front();
    }
    if (!work) {
        return;
    }

    // TODO: grab pool ID from intf
    if (!mOutputBlockPool) {
        c2_status_t err = GetCodec2BlockPool(C2BlockPool::BASIC_GRAPHIC, shared_from_this(), &mOutputBlockPool);
        if (err != C2_OK) {
            Mutexed<ExecState>::Locked state(mExecState);
            state->mListener->onError_nb(shared_from_this(), err);
            return;
        }
    }

    bool done = process(work, mOutputBlockPool);
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        if (queue->mGeneration != generation) {
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
    if (done) {
        Mutexed<ExecState>::Locked state(mExecState);
        state->mListener->onWorkDone_nb(shared_from_this(), vec(work));
    } else {
        std::unique_ptr<C2Work> unexpected;
        {
            Mutexed<PendingWork>::Locked pending(mPendingWork);
            uint64_t frameIndex = work->input.ordinal.frame_index;
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

} // namespace android
