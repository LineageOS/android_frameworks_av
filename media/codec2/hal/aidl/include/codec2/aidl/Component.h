/*
 * Copyright 2018 The Android Open Source Project
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

#ifndef CODEC2_AIDL_UTILS_COMPONENT_H
#define CODEC2_AIDL_UTILS_COMPONENT_H

#include <codec2/aidl/ComponentInterface.h>
#include <codec2/aidl/Configurable.h>
#include <codec2/aidl/BufferTypes.h>
#include <codec2/aidl/ParamTypes.h>

#include <aidl/android/hardware/media/bufferpool2/IClientManager.h>
#include <aidl/android/hardware/media/c2/BnComponent.h>
#include <aidl/android/hardware/media/c2/IComponentInterface.h>
#include <aidl/android/hardware/media/c2/IComponentListener.h>
#include <aidl/android/hardware/media/c2/IComponentStore.h>

#include <C2Component.h>
#include <C2Buffer.h>
#include <C2.h>

#include <map>
#include <memory>
#include <mutex>

namespace aidl {
namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace utils {


struct ComponentStore;

struct Component : public BnComponent,
                   public std::enable_shared_from_this<Component> {
    Component(
            const std::shared_ptr<C2Component>&,
            const std::shared_ptr<IComponentListener>& listener,
            const std::shared_ptr<ComponentStore>& store,
            const std::shared_ptr<bufferpool2::IClientManager>& clientPoolManager);
    c2_status_t status() const;

    // Methods from IComponent follow.
    ::ndk::ScopedAStatus queue(const WorkBundle& workBundle) override;
    ::ndk::ScopedAStatus flush(WorkBundle *workBundle) override;
    ::ndk::ScopedAStatus drain(bool withEos) override;
    ::ndk::ScopedAStatus createBlockPool(
            const IComponent::BlockPoolAllocator &allocator,
            IComponent::BlockPool *blockPool) override;
    ::ndk::ScopedAStatus destroyBlockPool(int64_t blockPoolId) override;
    ::ndk::ScopedAStatus start() override;
    ::ndk::ScopedAStatus stop() override;
    ::ndk::ScopedAStatus reset() override;
    ::ndk::ScopedAStatus release() override;
    ::ndk::ScopedAStatus getInterface(
            std::shared_ptr<IComponentInterface> *intf) override;
    ::ndk::ScopedAStatus configureVideoTunnel(
            int32_t avSyncHwId,
            common::NativeHandle* handle) override;

protected:
    c2_status_t mInit;
    std::shared_ptr<C2Component> mComponent;
    std::shared_ptr<ComponentInterface> mInterface;
    std::shared_ptr<IComponentListener> mListener;
    std::shared_ptr<ComponentStore> mStore;
    DefaultBufferPoolSender mBufferPoolSender;

    std::mutex mBlockPoolsMutex;
    // This map keeps C2BlockPool objects that are created by createBlockPool()
    // alive. These C2BlockPool objects can be deleted by calling
    // destroyBlockPool(), reset() or release(), or by destroying the component.
    std::map<uint64_t, std::shared_ptr<C2BlockPool>> mBlockPools;

    void initListener(const std::shared_ptr<Component>& self);

    virtual ~Component() override;

    friend struct ComponentStore;

    struct Listener;

    ::ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;
    static void OnBinderDied(void *cookie);
    static void OnBinderUnlinked(void *cookie);
    struct DeathContext;
    DeathContext *mDeathContext;
};

}  // namespace utils
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android
}  // namespace aidl

#endif  // CODEC2_AIDL_UTILS_COMPONENT_H
