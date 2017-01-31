/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef OBOE_THREAD_H
#define OBOE_THREAD_H

#include <atomic>
#include <pthread.h>

#include <oboe/OboeDefinitions.h>

namespace oboe {

class Runnable {
public:
    Runnable() {};
    virtual ~Runnable() = default;

    virtual void run() {}
};

/**
 * Abstraction for a host thread.
 */
class OboeThread
{
public:
    OboeThread();
    OboeThread(Runnable *runnable);
    virtual ~OboeThread() = default;

    /**
     * Start the thread running.
     */
    oboe_result_t start(Runnable *runnable = nullptr);

    /**
     * Join the thread.
     * The caller must somehow tell the thread to exit before calling join().
     */
    oboe_result_t stop();

    /**
     * This will get called in the thread.
     * Override this or pass a Runnable to start().
     */
    virtual void run() {};

    void dispatch(); // called internally from 'C' thread wrapper

private:
    Runnable*                mRunnable = nullptr; // TODO make atomic with memory barrier?
    bool                     mHasThread = false;
    pthread_t                mThread; // initialized in constructor

};

} /* namespace oboe */

#endif ///OBOE_THREAD_H
