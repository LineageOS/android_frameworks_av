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

#ifndef CODEC2_CLIENT_INTERFACES_H_
#define CODEC2_CLIENT_INTERFACES_H_

#include <C2Component.h>
#include <C2Buffer.h>
#include <C2Param.h>
#include <C2.h>

#include <utils/StrongPointer.h>

#include <memory>

/**
 * This file contains minimal interfaces for the framework to access Codec2.0.
 *
 * Codec2Client is the main class that contains the following inner classes:
 * - Listener
 * - Configurable
 * - Interface
 * - Component
 *
 * Classes in Codec2Client, interfaces in Codec2.0, and  HIDL interfaces are
 * related as follows:
 * - Codec2Client <==> C2ComponentStore <==> IComponentStore
 * - Codec2Client::Listener <==> C2Component::Listener <==> IComponentListener
 * - Codec2Client::Configurable <==> [No equivalent] <==> IConfigurable
 * - Codec2Client::Interface <==> C2ComponentInterface <==> IComponentInterface
 * - Codec2Client::Component <==> C2Component <==> IComponent
 *
 * The entry point is Codec2Client::CreateFromService(), which creates a
 * Codec2Client object. From Codec2Client, Interface and Component objects can
 * be created by calling createComponent() and createInterface().
 *
 * createComponent() takes a Listener object, which must be implemented by the
 * user.
 *
 * At the present, createBlockPool() is the only method that yields a
 * Configurable object. Note, however, that Interface, Component and
 * Codec2Client are all subclasses of Configurable.
 */

// Forward declaration of HIDL interfaces
namespace vendor {
namespace google {
namespace media {
namespace c2 {
namespace V1_0 {
struct IConfigurable;
struct IComponentInterface;
struct IComponent;
struct IComponentStore;
} // namespace V1_0
} // namespace c2
} // namespace media
} // namespace google
} // namespace vendor

namespace android {

// This class is supposed to be called Codec2Client::Configurable, but forward
// declaration of an inner class is not possible.
struct Codec2ConfigurableClient {

    typedef ::vendor::google::media::c2::V1_0::IConfigurable Base;

    const C2String& getName() const;

    c2_status_t query(
            const std::vector<C2Param::Index> &indices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const params) const;

    c2_status_t config(
            const std::vector<C2Param*> &params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures
            );

    c2_status_t querySupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>>* const params
            ) const;

    c2_status_t querySupportedValues(
            std::vector<C2FieldSupportedValuesQuery>& fields,
            c2_blocking_t mayBlock) const;

    // base cannot be null.
    Codec2ConfigurableClient(const sp<Base>& base);

protected:
    C2String mName;
    sp<Base> mBase;

    Base* base() const;

    friend struct Codec2Client;
};

struct Codec2Client : public Codec2ConfigurableClient {

    typedef ::vendor::google::media::c2::V1_0::IComponentStore Base;

    struct Listener;

    typedef Codec2ConfigurableClient Configurable;

    typedef Configurable Interface; // These two types may diverge in the future.

    struct Component;

    typedef Codec2Client Store;

    c2_status_t createComponent(
            const C2String& name,
            const std::shared_ptr<Listener>& listener,
            std::shared_ptr<Component>* const component);

    c2_status_t createInterface(
            const C2String& name,
            std::shared_ptr<Interface>* const interface);

    const std::vector<C2Component::Traits>&
            listComponents() const;

    c2_status_t copyBuffer(
            const std::shared_ptr<C2Buffer>& src,
            const std::shared_ptr<C2Buffer>& dst);

    std::shared_ptr<C2ParamReflector> getParamReflector();

    static std::shared_ptr<Codec2Client> CreateFromService(
            const char* instanceName,
            bool waitForService = true);

    // base cannot be null.
    Codec2Client(const sp<Base>& base);

protected:
    mutable bool mListed;
    mutable std::vector<C2Component::Traits> mTraitsList;
    mutable std::vector<std::unique_ptr<std::vector<std::string>>>
            mAliasesBuffer;

    Base* base() const;
};

struct Codec2Client::Listener {

    virtual void onWorkDone(
            const std::weak_ptr<Codec2Client::Component>& comp,
            const std::list<std::unique_ptr<C2Work>>& workItems) = 0;

    virtual void onTripped(
            const std::weak_ptr<Codec2Client::Component>& comp,
            const std::vector<std::shared_ptr<C2SettingResult>>& settingResults
            ) = 0;

    virtual void onError(
            const std::weak_ptr<Codec2Client::Component>& comp,
            uint32_t errorCode) = 0;

    virtual ~Listener();

};

struct Codec2Client::Component : public Codec2Client::Configurable {

    typedef ::vendor::google::media::c2::V1_0::IComponent Base;

    c2_status_t createBlockPool(
            C2Allocator::id_t id,
            C2BlockPool::local_id_t* localId,
            std::shared_ptr<Codec2Client::Configurable>* configurable);

    c2_status_t queue(
            std::list<std::unique_ptr<C2Work>>* const items);

    c2_status_t flush(
            C2Component::flush_mode_t mode,
            std::list<std::unique_ptr<C2Work>>* const flushedWork);

    c2_status_t drain(C2Component::drain_mode_t mode);

    c2_status_t start();

    c2_status_t stop();

    c2_status_t reset();

    c2_status_t release();

    // base cannot be null.
    Component(const sp<Base>& base);

protected:
    Base* base() const;

    friend struct Codec2Client;
};

}  // namespace android

#endif  // CODEC2_CLIENT_INTERFACES_H_

