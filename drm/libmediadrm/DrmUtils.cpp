/*
 * Copyright (C) 2019 The Android Open Source Project
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
#define LOG_TAG "DrmUtils"

#include <utils/String16.h>
#include <binder/IInterface.h>
#include <binder/IServiceManager.h>
#include <cutils/properties.h>

#include <mediadrm/CryptoHal.h>
#include <mediadrm/DrmHal.h>
#include <mediadrm/DrmUtils.h>
#include <mediadrm/ICrypto.h>
#include <mediadrm/IDrm.h>
#include <mediadrm/IMediaDrmService.h>

namespace android {
namespace DrmUtils {

namespace {
template<typename Iface>
sp<Iface> MakeObjectWithService(status_t *pstatus) {
    status_t err = OK;
    status_t &status = pstatus ? *pstatus : err;
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("media.drm"));

    sp<IMediaDrmService> service = interface_cast<IMediaDrmService>(binder);
    if (service == NULL) {
        status = UNKNOWN_ERROR;
        return NULL;
    }

    auto obj = service->makeObject<Iface>();
    if (obj == NULL) {
        status = UNKNOWN_ERROR;
        return NULL;
    }

    status = obj->initCheck();
    if (status != OK && status != NO_INIT) {
        return NULL;
    }
    return obj;
}

template<typename Iface, typename Hal>
sp<Iface> MakeObject(status_t *pstatus) {
    if (UseDrmService()) {
        return MakeObjectWithService<Iface>(pstatus);
    } else {
        return new Hal();
    }
}
} // namespace

bool UseDrmService() {
    return property_get_bool("mediadrm.use_mediadrmserver", true);
}

sp<IDrm> MakeDrm(status_t *pstatus) {
    return MakeObject<IDrm, DrmHal>(pstatus);
}

sp<ICrypto> MakeCrypto(status_t *pstatus) {
    return MakeObject<ICrypto, CryptoHal>(pstatus);
}

}  // namespace DrmUtils
}  // namespace android
