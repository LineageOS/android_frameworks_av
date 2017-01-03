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

#ifndef MEDIA_CAS_SERVICE_H_
#define MEDIA_CAS_SERVICE_H_

#include <android/media/BnMediaCasService.h>

#include "FactoryLoader.h"

namespace android {
using binder::Status;
struct CasFactory;
struct DescramblerFactory;

class MediaCasService : public BnMediaCasService {
public:
    static void instantiate();

    virtual Status enumeratePlugins(
            vector<ParcelableCasPluginDescriptor>* results) override;

    virtual Status isSystemIdSupported(
            int32_t CA_system_id, bool* result) override;

    virtual Status createPlugin(
            int32_t CA_system_id,
            const sp<ICasListener> &listener,
            sp<ICas>* result) override;

    virtual Status isDescramblerSupported(
            int32_t CA_system_id, bool* result) override;

    virtual Status createDescrambler(
            int32_t CA_system_id, sp<IDescrambler>* result) override;

private:
    FactoryLoader<CasFactory> *mCasLoader;
    FactoryLoader<DescramblerFactory> *mDescramblerLoader;

    MediaCasService();
    virtual ~MediaCasService();
};

} // namespace android

#endif // MEDIA_CAS_SERVICE_H_
