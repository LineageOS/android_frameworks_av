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

//#define LOG_NDEBUG 0
#define LOG_TAG "android.hardware.media.c2@1.1-service"

#include <android-base/logging.h>
#include <binder/ProcessState.h>
#include <codec2/hidl/1.1/ComponentStore.h>
#include <hidl/HidlTransportSupport.h>
#include <minijail.h>

#include <util/C2InterfaceHelper.h>
#include <C2Component.h>
#include <C2Config.h>

// This is the absolute on-device path of the prebuild_etc module
// "android.hardware.media.c2@1.1-default-seccomp_policy" in Android.bp.
static constexpr char kBaseSeccompPolicyPath[] =
        "/vendor/etc/seccomp_policy/"
        "android.hardware.media.c2@1.1-default-seccomp-policy";

// Additional seccomp permissions can be added in this file.
// This file does not exist by default.
static constexpr char kExtSeccompPolicyPath[] =
        "/vendor/etc/seccomp_policy/"
        "android.hardware.media.c2@1.1-extended-seccomp-policy";

class StoreImpl : public C2ComponentStore {
public:
    StoreImpl()
        : mReflectorHelper(std::make_shared<C2ReflectorHelper>()),
          mInterface(mReflectorHelper) {
    }

    virtual ~StoreImpl() override = default;

    virtual C2String getName() const override {
        return "default";
    }

    virtual c2_status_t createComponent(
            C2String /*name*/,
            std::shared_ptr<C2Component>* const /*component*/) override {
        return C2_NOT_FOUND;
    }

    virtual c2_status_t createInterface(
            C2String /* name */,
            std::shared_ptr<C2ComponentInterface>* const /* interface */) override {
        return C2_NOT_FOUND;
    }

    virtual std::vector<std::shared_ptr<const C2Component::Traits>>
            listComponents() override {
        return {};
    }

    virtual c2_status_t copyBuffer(
            std::shared_ptr<C2GraphicBuffer> /* src */,
            std::shared_ptr<C2GraphicBuffer> /* dst */) override {
        return C2_OMITTED;
    }

    virtual c2_status_t query_sm(
        const std::vector<C2Param*>& stackParams,
        const std::vector<C2Param::Index>& heapParamIndices,
        std::vector<std::unique_ptr<C2Param>>* const heapParams) const override {
        return mInterface.query(stackParams, heapParamIndices, C2_MAY_BLOCK, heapParams);
    }

    virtual c2_status_t config_sm(
            const std::vector<C2Param*>& params,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures) override {
        return mInterface.config(params, C2_MAY_BLOCK, failures);
    }

    virtual std::shared_ptr<C2ParamReflector> getParamReflector() const override {
        return mReflectorHelper;
    }

    virtual c2_status_t querySupportedParams_nb(
            std::vector<std::shared_ptr<C2ParamDescriptor>>* const params) const override {
        return mInterface.querySupportedParams(params);
    }

    virtual c2_status_t querySupportedValues_sm(
            std::vector<C2FieldSupportedValuesQuery>& fields) const override {
        return mInterface.querySupportedValues(fields, C2_MAY_BLOCK);
    }

private:
    class Interface : public C2InterfaceHelper {
    public:
        Interface(const std::shared_ptr<C2ReflectorHelper> &helper)
            : C2InterfaceHelper(helper) {
            setDerivedInstance(this);

            addParameter(
                DefineParam(mIonUsageInfo, "ion-usage")
                .withDefault(new C2StoreIonUsageInfo())
                .withFields({
                    C2F(mIonUsageInfo, usage).flags(
                            {C2MemoryUsage::CPU_READ | C2MemoryUsage::CPU_WRITE}),
                    C2F(mIonUsageInfo, capacity).inRange(0, UINT32_MAX, 1024),
                    C2F(mIonUsageInfo, heapMask).any(),
                    C2F(mIonUsageInfo, allocFlags).flags({}),
                    C2F(mIonUsageInfo, minAlignment).equalTo(0)
                })
                .withSetter(SetIonUsage)
                .build());
        }

        virtual ~Interface() = default;

    private:
        static C2R SetIonUsage(bool /* mayBlock */, C2P<C2StoreIonUsageInfo> &me) {
            // Vendor's TODO: put appropriate mapping logic
            me.set().heapMask = ~0;
            me.set().allocFlags = 0;
            me.set().minAlignment = 0;
            return C2R::Ok();
        }

        std::shared_ptr<C2StoreIonUsageInfo> mIonUsageInfo;
    };
    std::shared_ptr<C2ReflectorHelper> mReflectorHelper;
    Interface mInterface;
};

int main(int /* argc */, char** /* argv */) {
    using namespace ::android;
    LOG(DEBUG) << "android.hardware.media.c2@1.1-service starting...";

    // Set up minijail to limit system calls.
    signal(SIGPIPE, SIG_IGN);
    SetUpMinijail(kBaseSeccompPolicyPath, kExtSeccompPolicyPath);

    // Enable vndbinder to allow vendor-to-vendor binder calls.
    ProcessState::initWithDriver("/dev/vndbinder");

    ProcessState::self()->startThreadPool();
    // Extra threads may be needed to handle a stacked IPC sequence that
    // contains alternating binder and hwbinder calls. (See b/35283480.)
    hardware::configureRpcThreadpool(8, true /* callerWillJoin */);

    // Create IComponentStore service.
    {
        using namespace ::android::hardware::media::c2::V1_1;
        sp<IComponentStore> store;

        // TODO: Replace this with
        // store = new utils::ComponentStore(
        //         /* implementation of C2ComponentStore */);
        LOG(DEBUG) << "Instantiating Codec2's IComponentStore service...";
        store = new utils::ComponentStore(
                std::make_shared<StoreImpl>());

        if (store == nullptr) {
            LOG(ERROR) << "Cannot create Codec2's IComponentStore service.";
        } else {
            constexpr char const* serviceName = "default";
            if (store->registerAsService(serviceName) != OK) {
                LOG(ERROR) << "Cannot register Codec2's IComponentStore service"
                              " with instance name << \""
                           << serviceName << "\".";
            } else {
                LOG(DEBUG) << "Codec2's IComponentStore service registered. "
                              "Instance name: \"" << serviceName << "\".";
            }
        }
    }

    hardware::joinRpcThreadpool();
    return 0;
}
