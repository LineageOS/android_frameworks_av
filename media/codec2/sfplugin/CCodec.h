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

#ifndef C_CODEC_H_
#define C_CODEC_H_

#include <chrono>
#include <list>
#include <memory>
#include <set>

#include <C2Component.h>
#include <codec2/hidl/client.h>

#include <android/native_window.h>
#include <media/hardware/MetadataBufferType.h>
#include <media/stagefright/foundation/Mutexed.h>
#include <media/stagefright/CodecBase.h>
#include <media/stagefright/FrameRenderTracker.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/SkipCutBuffer.h>
#include <utils/NativeHandle.h>
#include <hardware/gralloc.h>
#include <nativebase/nativebase.h>

#include "CCodecConfig.h"

namespace android {

class CCodecBufferChannel;
class InputSurfaceWrapper;
struct MediaCodecInfo;

class CCodec : public CodecBase {
public:
    CCodec();

    virtual std::shared_ptr<BufferChannelBase> getBufferChannel() override;
    virtual void initiateAllocateComponent(const sp<AMessage> &msg) override;
    virtual void initiateConfigureComponent(const sp<AMessage> &msg) override;
    virtual void initiateCreateInputSurface() override;
    virtual void initiateSetInputSurface(const sp<PersistentSurface> &surface) override;
    virtual void initiateStart() override;
    virtual void initiateShutdown(bool keepComponentAllocated = false) override;

    virtual status_t setSurface(const sp<Surface> &surface) override;

    virtual void signalFlush() override;
    virtual void signalResume() override;

    virtual void signalSetParameters(const sp<AMessage> &params) override;
    virtual void signalEndOfInputStream() override;
    virtual void signalRequestIDRFrame() override;

    void initiateReleaseIfStuck();
    void onWorkDone(std::list<std::unique_ptr<C2Work>> &workItems,
                    size_t numDiscardedInputBuffers);
    void onInputBufferDone(const std::shared_ptr<C2Buffer>& buffer);

protected:
    virtual ~CCodec();

    virtual void onMessageReceived(const sp<AMessage> &msg) override;

private:
    typedef std::chrono::time_point<std::chrono::steady_clock> TimePoint;

    status_t tryAndReportOnError(std::function<status_t()> job);

    void initiateStop();
    void initiateRelease(bool sendCallback = true);

    void allocate(const sp<MediaCodecInfo> &codecInfo);
    void configure(const sp<AMessage> &msg);
    void start();
    void stop();
    void flush();
    void release(bool sendCallback);

    void createInputSurface();
    void setInputSurface(const sp<PersistentSurface> &surface);
    status_t setupInputSurface(const std::shared_ptr<InputSurfaceWrapper> &surface);
    void setParameters(const sp<AMessage> &params);

    void setDeadline(
            const TimePoint &now,
            const std::chrono::milliseconds &timeout,
            const char *name);

    void onWorkQueued(bool eos);
    void subQueuedWorkCount(uint32_t count);

    enum {
        kWhatAllocate,
        kWhatConfigure,
        kWhatStart,
        kWhatFlush,
        kWhatStop,
        kWhatRelease,
        kWhatCreateInputSurface,
        kWhatSetInputSurface,
        kWhatSetParameters,

        kWhatWorkDone,
        kWhatWatch,
    };

    enum {
        RELEASED,
        ALLOCATED,
        FLUSHED,
        RUNNING,

        ALLOCATING,  // RELEASED -> ALLOCATED
        STARTING,    // ALLOCATED -> RUNNING
        STOPPING,    // RUNNING -> ALLOCATED
        FLUSHING,    // RUNNING -> FLUSHED
        RESUMING,    // FLUSHED -> RUNNING
        RELEASING,   // {ANY EXCEPT RELEASED} -> RELEASED
    };

    struct State {
        inline State() : mState(RELEASED) {}
        inline int get() const { return mState; }
        inline void set(int newState) { mState = newState; }

        std::shared_ptr<Codec2Client::Component> comp;
    private:
        int mState;
    };

    struct NamedTimePoint {
        NamedTimePoint() : mTimePoint(TimePoint::max()), mName("") {}

        inline void set(
                const TimePoint &timePoint,
                const char *name) {
            mTimePoint = timePoint;
            mName = name;
        }

        inline TimePoint get() const { return mTimePoint; }
        inline const char *getName() const { return mName; }
    private:
        TimePoint mTimePoint;
        const char *mName;
    };

    Mutexed<State> mState;
    std::shared_ptr<CCodecBufferChannel> mChannel;

    std::shared_ptr<Codec2Client> mClient;
    std::shared_ptr<Codec2Client::Listener> mClientListener;
    struct ClientListener;

    Mutexed<NamedTimePoint> mDeadline;
    std::atomic_int32_t mQueuedWorkCount;
    Mutexed<NamedTimePoint> mQueueDeadline;
    Mutexed<NamedTimePoint> mEosDeadline;
    typedef CCodecConfig Config;
    Mutexed<Config> mConfig;
    Mutexed<std::list<std::unique_ptr<C2Work>>> mWorkDoneQueue;
    Mutexed<std::list<size_t>> mNumDiscardedInputBuffersQueue;

    friend class CCodecCallbackImpl;

    DISALLOW_EVIL_CONSTRUCTORS(CCodec);
};

}  // namespace android

#endif  // C_CODEC_H_
