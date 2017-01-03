
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
#define LOG_TAG "DescramblerImpl"

#include <media/cas/DescramblerAPI.h>
#include <media/DescramblerImpl.h>
#include <media/SharedLibrary.h>
#include <utils/Log.h>
#include <binder/IMemory.h>

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

DescramblerImpl::DescramblerImpl(
        const sp<SharedLibrary>& library, DescramblerPlugin *plugin) :
        mLibrary(library), mPlugin(plugin) {
    ALOGV("CTOR: mPlugin=%p", mPlugin);
}

DescramblerImpl::~DescramblerImpl() {
    ALOGV("DTOR: mPlugin=%p", mPlugin);
    release();
}

Status DescramblerImpl::setMediaCasSession(const CasSessionId& sessionId) {
    ALOGV("setMediaCasSession: sessionId=%s",
            sessionIdToString(sessionId).string());

    return getBinderStatus(mPlugin->setMediaCasSession(sessionId));
}

Status DescramblerImpl::requiresSecureDecoderComponent(
        const String16& mime, bool *result) {
    *result = mPlugin->requiresSecureDecoderComponent(String8(mime));

    return getBinderStatus(OK);
}

Status DescramblerImpl::descramble(
        const DescrambleInfo& info, int32_t *result) {
    ALOGV("descramble");

    *result = mPlugin->descramble(
            info.dstType != DescrambleInfo::kDestinationTypeVmPointer,
            info.scramblingControl,
            info.numSubSamples,
            info.subSamples,
            info.srcMem->pointer(),
            info.srcOffset,
            info.dstType == DescrambleInfo::kDestinationTypeVmPointer ?
                    info.srcMem->pointer() : info.dstPtr,
            info.dstOffset,
            NULL);

    return getBinderStatus(*result >= 0 ? OK : *result);
}

Status DescramblerImpl::release() {
    ALOGV("release: mPlugin=%p", mPlugin);

    if (mPlugin != NULL) {
        delete mPlugin;
        mPlugin = NULL;
    }
    return Status::ok();
}

} // namespace android

