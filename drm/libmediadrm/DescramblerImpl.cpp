
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
#include <media/stagefright/foundation/AUtils.h>
#include <binder/IMemory.h>
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

static inline bool validateRangeForSize(
        uint64_t offset, uint64_t length, uint64_t size) {
    return isInRange<uint64_t, uint64_t>(0, size, offset, length);
}

Status DescramblerImpl::descramble(
        const DescrambleInfo& info, int32_t *result) {
    ALOGV("descramble");

    if (info.srcMem == NULL || info.srcMem->pointer() == NULL) {
        ALOGE("srcMem is invalid");
        return getBinderStatus(BAD_VALUE);
    }

    // use 64-bit here to catch bad subsample size that might be overflowing.
    uint64_t totalBytesInSubSamples = 0;
    for (size_t i = 0; i < info.numSubSamples; i++) {
        totalBytesInSubSamples += (uint64_t)info.subSamples[i].mNumBytesOfClearData +
                info.subSamples[i].mNumBytesOfEncryptedData;
    }
    // validate if the specified srcOffset and requested total subsample size
    // is consistent with the source shared buffer size.
    if (!validateRangeForSize(info.srcOffset, totalBytesInSubSamples, info.srcMem->size())) {
        ALOGE("Invalid srcOffset and subsample size: "
                "srcOffset %llu, totalBytesInSubSamples %llu, srcMem size %llu",
                (unsigned long long) info.srcOffset,
                (unsigned long long) totalBytesInSubSamples,
                (unsigned long long) info.srcMem->size());
        android_errorWriteLog(0x534e4554, "67962232");
        return getBinderStatus(BAD_VALUE);
    }
    void *dstPtr = NULL;
    if (info.dstType == DescrambleInfo::kDestinationTypeVmPointer) {
        // When using shared memory, src buffer is also used as dst
        dstPtr = info.srcMem->pointer();

        // In this case the dst and src would be the same buffer, need to validate
        // dstOffset against the buffer size too.
        if (!validateRangeForSize(info.dstOffset, totalBytesInSubSamples, info.srcMem->size())) {
            ALOGE("Invalid dstOffset and subsample size: "
                    "dstOffset %llu, totalBytesInSubSamples %llu, srcBuffer size %llu",
                    (unsigned long long) info.dstOffset,
                    (unsigned long long) totalBytesInSubSamples,
                    (unsigned long long) info.srcMem->size());
            android_errorWriteLog(0x534e4554, "67962232");
            return getBinderStatus(BAD_VALUE);
        }
    } else {
        dstPtr = info.dstPtr;
    }

    *result = mPlugin->descramble(
            info.dstType != DescrambleInfo::kDestinationTypeVmPointer,
            info.scramblingControl,
            info.numSubSamples,
            info.subSamples,
            info.srcMem->pointer(),
            info.srcOffset,
            dstPtr,
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

