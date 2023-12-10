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

#ifndef ANDROID_HARDWARE_EFFECT_HAL_HIDL_H
#define ANDROID_HARDWARE_EFFECT_HAL_HIDL_H

#include PATH(android/hardware/audio/effect/COMMON_TYPES_FILE_VERSION/IEffect.h)
#include <media/audiohal/EffectHalInterface.h>
#include <fmq/EventFlag.h>
#include <fmq/MessageQueue.h>
#include <system/audio_effect.h>

#include "EffectConversionHelperHidl.h"

using ::android::hardware::EventFlag;
using ::android::hardware::MessageQueue;

namespace android {
namespace effect {

using namespace ::android::hardware::audio::effect::COMMON_TYPES_CPP_VERSION;

class EffectHalHidl : public EffectHalInterface, public EffectConversionHelperHidl
{
  public:
    // Set the input buffer.
    virtual status_t setInBuffer(const sp<EffectBufferHalInterface>& buffer);

    // Set the output buffer.
    virtual status_t setOutBuffer(const sp<EffectBufferHalInterface>& buffer);

    // Effect process function.
    virtual status_t process();

    // Process reverse stream function. This function is used to pass
    // a reference stream to the effect engine.
    virtual status_t processReverse();

    // Send a command and receive a response to/from effect engine.
    virtual status_t command(uint32_t cmdCode, uint32_t cmdSize, void *pCmdData,
            uint32_t *replySize, void *pReplyData);

    // Returns the effect descriptor.
    virtual status_t getDescriptor(effect_descriptor_t *pDescriptor);

    // Free resources on the remote side.
    virtual status_t close();

    virtual status_t dump(int fd);

    uint64_t effectId() const { return mEffectId; }

  private:
    friend class EffectsFactoryHalHidl;
    typedef MessageQueue<Result, hardware::kSynchronizedReadWrite> StatusMQ;

    sp<IEffect> mEffect;
    const uint64_t mEffectId;
    sp<EffectBufferHalInterface> mInBuffer;
    sp<EffectBufferHalInterface> mOutBuffer;
    bool mBuffersChanged;
    std::unique_ptr<StatusMQ> mStatusMQ;
    EventFlag* mEfGroup;
    bool mIsInput = false;
    static constexpr int32_t kRTPriorityMin = 1;
    static constexpr int32_t kRTPriorityMax = 3;
    static constexpr int kRTPriorityDisabled = 0;
    // Typical RealTime mHalThreadPriority ranges from 1 (low) to 3 (high).
    int mHalThreadPriority = kRTPriorityDisabled;

    // Can not be constructed directly by clients.
    EffectHalHidl(const sp<IEffect>& effect, uint64_t effectId);

    // The destructor automatically releases the effect.
    virtual ~EffectHalHidl();

    status_t getConfigImpl(uint32_t cmdCode, uint32_t *replySize, void *pReplyData);
    status_t prepareForProcessing();
    bool needToResetBuffers();
    status_t processImpl(uint32_t mqFlag);
    status_t setConfigImpl(
            uint32_t cmdCode, uint32_t cmdSize, void *pCmdData,
            uint32_t *replySize, void *pReplyData);
    status_t setProcessBuffers();
    status_t getHalPid(pid_t *pid) const;
    status_t getHalWorkerTid(pid_t *tid);
    bool requestHalThreadPriority(pid_t threadPid, pid_t threadId);
    status_t checkHalThreadPriority();
};

} // namespace effect
} // namespace android

#endif // ANDROID_HARDWARE_EFFECT_HAL_HIDL_H
