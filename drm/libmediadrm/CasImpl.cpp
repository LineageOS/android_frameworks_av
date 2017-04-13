
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
#define LOG_TAG "CasImpl"

#include <android/media/ICasListener.h>
#include <media/cas/CasAPI.h>
#include <media/CasImpl.h>
#include <media/SharedLibrary.h>
#include <utils/Log.h>

namespace android {

static Status getBinderStatus(status_t err) {
    if (err == OK) {
        return Status::ok();
    }
    if (err == BAD_VALUE) {
        return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT);
    }
    if (err == INVALID_OPERATION) {
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE);
    }
    return Status::fromServiceSpecificError(err);
}

static String8 sessionIdToString(const CasSessionId &sessionId) {
    String8 result;
    for (size_t i = 0; i < sessionId.size(); i++) {
        result.appendFormat("%02x ", sessionId[i]);
    }
    if (result.isEmpty()) {
        result.append("(null)");
    }
    return result;
}

struct CasImpl::PluginHolder : public RefBase {
public:
    explicit PluginHolder(CasPlugin *plugin) : mPlugin(plugin) {}
    ~PluginHolder() { if (mPlugin != NULL) delete mPlugin; }
    CasPlugin* get() { return mPlugin; }

private:
    CasPlugin *mPlugin;
    DISALLOW_EVIL_CONSTRUCTORS(PluginHolder);
};

CasImpl::CasImpl(const sp<ICasListener> &listener)
    : mPluginHolder(NULL), mListener(listener) {
    ALOGV("CTOR");
}

CasImpl::~CasImpl() {
    ALOGV("DTOR");
    release();
}

//static
void CasImpl::OnEvent(
        void *appData,
        int32_t event,
        int32_t arg,
        uint8_t *data,
        size_t size) {
    if (appData == NULL) {
        ALOGE("Invalid appData!");
        return;
    }
    CasImpl *casImpl = static_cast<CasImpl *>(appData);
    casImpl->onEvent(event, arg, data, size);
}

void CasImpl::init(const sp<SharedLibrary>& library, CasPlugin *plugin) {
    mLibrary = library;
    mPluginHolder = new PluginHolder(plugin);
}

void CasImpl::onEvent(
        int32_t event, int32_t arg, uint8_t *data, size_t size) {
    if (mListener == NULL) {
        return;
    }

    std::unique_ptr<CasData> eventData;
    if (data != NULL && size > 0) {
        eventData.reset(new CasData(data, data + size));
    }

    mListener->onEvent(event, arg, eventData);
}

Status CasImpl::setPrivateData(const CasData& pvtData) {
    ALOGV("setPrivateData");
    sp<PluginHolder> holder = mPluginHolder;
    if (holder == NULL) {
        return getBinderStatus(INVALID_OPERATION);
    }
    return getBinderStatus(holder->get()->setPrivateData(pvtData));
}

Status CasImpl::openSession(CasSessionId* sessionId) {
    ALOGV("openSession");
    sp<PluginHolder> holder = mPluginHolder;
    if (holder == NULL) {
        return getBinderStatus(INVALID_OPERATION);
    }
    status_t err = holder->get()->openSession(sessionId);

    ALOGV("openSession: session opened, sessionId=%s",
            sessionIdToString(*sessionId).string());

    return getBinderStatus(err);
}

Status CasImpl::setSessionPrivateData(
        const CasSessionId &sessionId, const CasData& pvtData) {
    ALOGV("setSessionPrivateData: sessionId=%s",
            sessionIdToString(sessionId).string());
    sp<PluginHolder> holder = mPluginHolder;
    if (holder == NULL) {
        return getBinderStatus(INVALID_OPERATION);
    }
    return getBinderStatus(holder->get()->setSessionPrivateData(sessionId, pvtData));
}

Status CasImpl::closeSession(const CasSessionId &sessionId) {
    ALOGV("closeSession: sessionId=%s",
            sessionIdToString(sessionId).string());
    sp<PluginHolder> holder = mPluginHolder;
    if (holder == NULL) {
        return getBinderStatus(INVALID_OPERATION);
    }
    return getBinderStatus(holder->get()->closeSession(sessionId));
}

Status CasImpl::processEcm(const CasSessionId &sessionId, const ParcelableCasData& ecm) {
    ALOGV("processEcm: sessionId=%s",
            sessionIdToString(sessionId).string());
    sp<PluginHolder> holder = mPluginHolder;
    if (holder == NULL) {
        return getBinderStatus(INVALID_OPERATION);
    }

    return getBinderStatus(holder->get()->processEcm(sessionId, ecm));
}

Status CasImpl::processEmm(const ParcelableCasData& emm) {
    ALOGV("processEmm");
    sp<PluginHolder> holder = mPluginHolder;
    if (holder == NULL) {
        return getBinderStatus(INVALID_OPERATION);
    }

    return getBinderStatus(holder->get()->processEmm(emm));
}

Status CasImpl::sendEvent(
        int32_t event, int32_t arg, const ::std::unique_ptr<CasData> &eventData) {
    ALOGV("sendEvent");
    sp<PluginHolder> holder = mPluginHolder;
    if (holder == NULL) {
        return getBinderStatus(INVALID_OPERATION);
    }

    status_t err;
    if (eventData == nullptr) {
        err = holder->get()->sendEvent(event, arg, CasData());
    } else {
        err = holder->get()->sendEvent(event, arg, *eventData);
    }
    return getBinderStatus(err);
}

Status CasImpl::provision(const String16& provisionString) {
    ALOGV("provision: provisionString=%s", String8(provisionString).string());
    sp<PluginHolder> holder = mPluginHolder;
    if (holder == NULL) {
        return getBinderStatus(INVALID_OPERATION);
    }

    return getBinderStatus(holder->get()->provision(String8(provisionString)));
}

Status CasImpl::refreshEntitlements(
        int32_t refreshType, const ::std::unique_ptr<CasData> &refreshData) {
    ALOGV("refreshEntitlements");
    sp<PluginHolder> holder = mPluginHolder;
    if (holder == NULL) {
        return getBinderStatus(INVALID_OPERATION);
    }

    status_t err;
    if (refreshData == nullptr) {
        err = holder->get()->refreshEntitlements(refreshType, CasData());
    } else {
        err = holder->get()->refreshEntitlements(refreshType, *refreshData);
    }
    return getBinderStatus(err);
}

Status CasImpl::release() {
    ALOGV("release: plugin=%p",
            mPluginHolder == NULL ? mPluginHolder->get() : NULL);
    mPluginHolder.clear();
    return Status::ok();
}

} // namespace android

