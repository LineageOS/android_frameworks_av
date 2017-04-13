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

#ifndef CAS_IMPL_H_
#define CAS_IMPL_H_

#include <media/stagefright/foundation/ABase.h>
#include <android/media/BnCas.h>

namespace android {
namespace media {
class ICasListener;
}
using namespace media;
using namespace MediaCas;
using binder::Status;
class CasPlugin;
class SharedLibrary;

class CasImpl : public BnCas {
public:
    CasImpl(const sp<ICasListener> &listener);
    virtual ~CasImpl();

    static void OnEvent(
            void *appData,
            int32_t event,
            int32_t arg,
            uint8_t *data,
            size_t size);

    void init(const sp<SharedLibrary>& library, CasPlugin *plugin);
    void onEvent(
            int32_t event,
            int32_t arg,
            uint8_t *data,
            size_t size);

    // ICas inherits

    virtual Status setPrivateData(
            const CasData& pvtData) override;

    virtual Status openSession(CasSessionId* _aidl_return) override;

    virtual Status closeSession(const CasSessionId& sessionId) override;

    virtual Status setSessionPrivateData(
            const CasSessionId& sessionId,
            const CasData& pvtData) override;

    virtual Status processEcm(
            const CasSessionId& sessionId, const ParcelableCasData& ecm) override;

    virtual Status processEmm(const ParcelableCasData& emm) override;

    virtual Status sendEvent(
            int32_t event, int32_t arg, const ::std::unique_ptr<CasData> &eventData) override;

    virtual Status provision(const String16& provisionString) override;

    virtual Status refreshEntitlements(
            int32_t refreshType, const ::std::unique_ptr<CasData> &refreshData) override;

    virtual Status release() override;

private:
    struct PluginHolder;
    sp<SharedLibrary> mLibrary;
    sp<PluginHolder> mPluginHolder;
    sp<ICasListener> mListener;

    DISALLOW_EVIL_CONSTRUCTORS(CasImpl);
};

} // namespace android

#endif // CAS_IMPL_H_
