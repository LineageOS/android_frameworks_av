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

//#define LOG_NDEBUG 0
#define LOG_TAG "MediaCasService"

#include <binder/IServiceManager.h>
#include <media/cas/CasAPI.h>
#include <media/cas/DescramblerAPI.h>
#include <media/CasImpl.h>
#include <media/DescramblerImpl.h>
#include <utils/Log.h>
#include <utils/List.h>
#include "MediaCasService.h"
#include <android/media/ICasListener.h>

namespace android {

//static
void MediaCasService::instantiate() {
    defaultServiceManager()->addService(
            String16("media.cas"), new MediaCasService());
}

MediaCasService::MediaCasService() :
    mCasLoader(new FactoryLoader<CasFactory>("createCasFactory")),
    mDescramblerLoader(new FactoryLoader<DescramblerFactory>(
            "createDescramblerFactory")) {
}

MediaCasService::~MediaCasService() {
    delete mCasLoader;
    delete mDescramblerLoader;
}

Status MediaCasService::enumeratePlugins(
        vector<ParcelableCasPluginDescriptor>* results) {
    ALOGV("enumeratePlugins");

    mCasLoader->enumeratePlugins(results);

    return Status::ok();
}

Status MediaCasService::isSystemIdSupported(
        int32_t CA_system_id, bool* result) {
    ALOGV("isSystemIdSupported: CA_system_id=%d", CA_system_id);

    *result = mCasLoader->findFactoryForScheme(CA_system_id);

    return Status::ok();
}

Status MediaCasService::createPlugin(
        int32_t CA_system_id,
        const sp<ICasListener> &listener,
        sp<ICas>* result) {
    ALOGV("createPlugin: CA_system_id=%d", CA_system_id);

    result->clear();

    CasFactory *factory;
    sp<SharedLibrary> library;
    if (mCasLoader->findFactoryForScheme(CA_system_id, &library, &factory)) {
        CasPlugin *plugin = NULL;
        sp<CasImpl> casImpl = new CasImpl(listener);
        if (factory->createPlugin(CA_system_id, (uint64_t)casImpl.get(),
                &CasImpl::OnEvent, &plugin) == OK && plugin != NULL) {
            casImpl->init(library, plugin);
            *result = casImpl;
        }
    }

    return Status::ok();
}

Status MediaCasService::isDescramblerSupported(
        int32_t CA_system_id, bool* result) {
    ALOGV("isDescramblerSupported: CA_system_id=%d", CA_system_id);

    *result = mDescramblerLoader->findFactoryForScheme(CA_system_id);

    return Status::ok();
}

Status MediaCasService::createDescrambler(
        int32_t CA_system_id, sp<IDescrambler>* result) {
    ALOGV("createDescrambler: CA_system_id=%d", CA_system_id);

    result->clear();

    DescramblerFactory *factory;
    sp<SharedLibrary> library;
    if (mDescramblerLoader->findFactoryForScheme(
            CA_system_id, &library, &factory)) {
        DescramblerPlugin *plugin = NULL;
        if (factory->createPlugin(CA_system_id, &plugin) == OK
                && plugin != NULL) {
            *result = new DescramblerImpl(library, plugin);
        }
    }

    return Status::ok();
}

} // namespace android
