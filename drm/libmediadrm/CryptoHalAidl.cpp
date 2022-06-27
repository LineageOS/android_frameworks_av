/*
 * Copyright (C) 2021 The Android Open Source Project
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
#define LOG_TAG "CryptoHalAidl"

#include <aidlcommonsupport/NativeHandle.h>
#include <android/binder_auto_utils.h>
#include <android/binder_manager.h>
#include <media/hardware/CryptoAPI.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AString.h>
#include <media/stagefright/foundation/hexdump.h>
#include <mediadrm/CryptoHalAidl.h>
#include <mediadrm/DrmUtils.h>

using ::aidl::android::hardware::drm::CryptoSchemes;
using DestinationBufferAidl = ::aidl::android::hardware::drm::DestinationBuffer;
using ::aidl::android::hardware::drm::Mode;
using ::aidl::android::hardware::drm::Pattern;
using SharedBufferAidl = ::aidl::android::hardware::drm::SharedBuffer;
using ::aidl::android::hardware::drm::Status;
using ::aidl::android::hardware::drm::SubSample;
using ::aidl::android::hardware::drm::Uuid;
using ::aidl::android::hardware::drm::SecurityLevel;
using NativeHandleAidlCommon = ::aidl::android::hardware::common::NativeHandle;
using ::aidl::android::hardware::drm::DecryptArgs;

using ::android::sp;
using ::android::DrmUtils::statusAidlToStatusT;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_handle;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::HidlMemory;
using ::android::hardware::Return;
using ::android::hardware::Void;

using ::aidl::android::hardware::drm::Uuid;
// -------Hidl interface related-----------------
// TODO: replace before removing hidl interface

using BufferTypeHidl = ::android::hardware::drm::V1_0::BufferType;
using SharedBufferHidl = ::android::hardware::drm::V1_0::SharedBuffer;
using DestinationBufferHidl = ::android::hardware::drm::V1_0::DestinationBuffer;

// -------Hidl interface related end-------------

namespace android {

template <typename Byte = uint8_t>
static std::vector<Byte> toStdVec(const Vector<uint8_t>& vector) {
    auto v = reinterpret_cast<const Byte*>(vector.array());
    std::vector<Byte> vec(v, v + vector.size());
    return vec;
}

// -------Hidl interface related-----------------
// TODO: replace before removing hidl interface
status_t CryptoHalAidl::checkSharedBuffer(const SharedBufferHidl& buffer) {
    int32_t seqNum = static_cast<int32_t>(buffer.bufferId);
    // memory must be in one of the heaps that have been set
    if (mHeapSizes.indexOfKey(seqNum) < 0) {
        return UNKNOWN_ERROR;
    }

    // memory must be within the address space of the heap
    size_t heapSize = mHeapSizes.valueFor(seqNum);
    if (heapSize < buffer.offset + buffer.size || SIZE_MAX - buffer.offset < buffer.size) {
        android_errorWriteLog(0x534e4554, "76221123");
        return UNKNOWN_ERROR;
    }

    return OK;
}

static SharedBufferAidl hidlSharedBufferToAidlSharedBuffer(const SharedBufferHidl& buffer) {
    SharedBufferAidl aidlsb;
    aidlsb.bufferId = buffer.bufferId;
    aidlsb.offset = buffer.offset;
    aidlsb.size = buffer.size;
    return aidlsb;
}

static DestinationBufferAidl hidlDestinationBufferToAidlDestinationBuffer(
        const DestinationBufferHidl& buffer) {
    DestinationBufferAidl aidldb;
    // skip negative convert check as count of enum elements are 2
    switch(buffer.type) {
        case BufferTypeHidl::SHARED_MEMORY:
            aidldb.set<DestinationBufferAidl::Tag::nonsecureMemory>(
                hidlSharedBufferToAidlSharedBuffer(buffer.nonsecureMemory));
            break;
        default:
            auto handle = buffer.secureMemory.getNativeHandle();
            if (handle) {
                aidldb.set<DestinationBufferAidl::Tag::secureMemory>(
                    ::android::dupToAidl(handle));
            } else {
                NativeHandleAidlCommon emptyhandle;
                aidldb.set<DestinationBufferAidl::Tag::secureMemory>(
                    std::move(emptyhandle));
            }
            break;
    }

    return aidldb;
}

static hidl_vec<uint8_t> toHidlVec(const void* ptr, size_t size) {
    hidl_vec<uint8_t> vec;
    vec.resize(size);
    memcpy(vec.data(), ptr, size);
    return vec;
}

static const Vector<uint8_t> toVector(const std::vector<uint8_t>& vec) {
    Vector<uint8_t> vector;
    vector.appendArray(vec.data(), vec.size());
    return *const_cast<const Vector<uint8_t>*>(&vector);
}

static String8 toString8(const std::string& string) {
    return String8(string.c_str());
}

static std::vector<uint8_t> toStdVec(const uint8_t* ptr, size_t n) {
    if (!ptr) {
        return std::vector<uint8_t>();
    }
    return std::vector<uint8_t>(ptr, ptr + n);
}

// -------Hidl interface related end--------------

bool CryptoHalAidl::isCryptoSchemeSupportedInternal(const uint8_t uuid[16], int* factoryIdx) {
    Uuid uuidAidl = DrmUtils::toAidlUuid(uuid);
    for (size_t i = 0; i < mFactories.size(); i++) {
        CryptoSchemes schemes{};
        if (mFactories[i]->getSupportedCryptoSchemes(&schemes).isOk()) {
            if (std::count(schemes.uuids.begin(), schemes.uuids.end(), uuidAidl)) {
                if (factoryIdx != NULL) *factoryIdx = i;
                return true;
            }
        }
    }

    return false;
}

CryptoHalAidl::CryptoHalAidl()
    : mFactories(DrmUtils::makeDrmFactoriesAidl()),
      mInitCheck((mFactories.size() == 0) ? ERROR_UNSUPPORTED : NO_INIT),
      mHeapSeqNum(0) {}

CryptoHalAidl::~CryptoHalAidl() {}

status_t CryptoHalAidl::initCheck() const {
    return mInitCheck;
}

bool CryptoHalAidl::isCryptoSchemeSupported(const uint8_t uuid[16]) {
    Mutex::Autolock autoLock(mLock);

    return isCryptoSchemeSupportedInternal(uuid, NULL);
}

status_t CryptoHalAidl::createPlugin(const uint8_t uuid[16], const void* data, size_t size) {
    Mutex::Autolock autoLock(mLock);

    Uuid uuidAidl = DrmUtils::toAidlUuid(uuid);
    std::vector<uint8_t> dataAidl = toStdVec(toVector(toHidlVec(data, size)));
    int i = 0;
    if (isCryptoSchemeSupportedInternal(uuid, &i)) {
        mPlugin = makeCryptoPlugin(mFactories[i], uuidAidl, dataAidl);
    }

    if (mInitCheck == NO_INIT) {
        mInitCheck = mPlugin == NULL ? ERROR_UNSUPPORTED : OK;
    }

    return mInitCheck;
}

std::shared_ptr<ICryptoPluginAidl> CryptoHalAidl::makeCryptoPlugin(
        const std::shared_ptr<IDrmFactoryAidl>& factory, const Uuid& uuidAidl,
        const std::vector<uint8_t> initData) {
    std::shared_ptr<ICryptoPluginAidl> pluginAidl;
    if (factory->createCryptoPlugin(uuidAidl, initData, &pluginAidl).isOk()) {
        ALOGI("Create ICryptoPluginAidl. UUID:[%s]", uuidAidl.toString().c_str());
    } else {
        mInitCheck = DEAD_OBJECT;
        ALOGE("Failed to create ICryptoPluginAidl. UUID:[%s]", uuidAidl.toString().c_str());
    }

    return pluginAidl;
}

status_t CryptoHalAidl::destroyPlugin() {
    Mutex::Autolock autoLock(mLock);

    if (mInitCheck != OK) {
        return mInitCheck;
    }

    mPlugin.reset();
    mInitCheck = NO_INIT;
    return OK;
}

bool CryptoHalAidl::requiresSecureDecoderComponent(const char* mime) const {
    Mutex::Autolock autoLock(mLock);

    if (mInitCheck != OK) {
        return false;
    }

    std::string mimeStr = std::string(mime);
    bool result;
    if (!mPlugin->requiresSecureDecoderComponent(mimeStr, &result).isOk()) {
        ALOGE("Failed to requiresSecureDecoderComponent. mime:[%s]", mime);
        return false;
    }

    return result;
}

void CryptoHalAidl::notifyResolution(uint32_t width, uint32_t height) {
    Mutex::Autolock autoLock(mLock);

    if (mInitCheck != OK) {
        return;
    }

    // Check negative width and height after type conversion
    // Log error and return if any is negative
    if ((int32_t)width < 0 || (int32_t)height < 0) {
        ALOGE("Negative width: %d or height %d in notifyResolution", width, height);
        return;
    }

    ::ndk::ScopedAStatus status = mPlugin->notifyResolution(width, height);
    if (!status.isOk()) {
        ALOGE("notifyResolution txn failed status code: %d", status.getServiceSpecificError());
    }
}

status_t CryptoHalAidl::setMediaDrmSession(const Vector<uint8_t>& sessionId) {
    Mutex::Autolock autoLock(mLock);

    if (mInitCheck != OK) {
        return mInitCheck;
    }

    auto err = mPlugin->setMediaDrmSession(toStdVec(sessionId));
    return statusAidlToStatusT(err);
}

ssize_t CryptoHalAidl::decrypt(const uint8_t keyId[16], const uint8_t iv[16],
                               CryptoPlugin::Mode mode, const CryptoPlugin::Pattern& pattern,
                               const SharedBufferHidl& hSource, size_t offset,
                               const CryptoPlugin::SubSample* subSamples, size_t numSubSamples,
                               const DestinationBufferHidl& hDestination, AString* errorDetailMsg) {
    Mutex::Autolock autoLock(mLock);

    if (mInitCheck != OK) {
        return mInitCheck;
    }

    Mode aMode;
    switch (mode) {
        case CryptoPlugin::kMode_Unencrypted:
            aMode = Mode::UNENCRYPTED;
            break;
        case CryptoPlugin::kMode_AES_CTR:
            aMode = Mode::AES_CTR;
            break;
        case CryptoPlugin::kMode_AES_WV:
            aMode = Mode::AES_CBC_CTS;
            break;
        case CryptoPlugin::kMode_AES_CBC:
            aMode = Mode::AES_CBC;
            break;
        default:
            return UNKNOWN_ERROR;
    }

    Pattern aPattern;
    aPattern.encryptBlocks = pattern.mEncryptBlocks;
    aPattern.skipBlocks = pattern.mSkipBlocks;

    std::vector<SubSample> stdSubSamples;
    for (size_t i = 0; i < numSubSamples; i++) {
        SubSample subSample;
        subSample.numBytesOfClearData = subSamples[i].mNumBytesOfClearData;
        subSample.numBytesOfEncryptedData = subSamples[i].mNumBytesOfEncryptedData;
        stdSubSamples.push_back(subSample);
    }

    bool secure;
    if (hDestination.type == BufferTypeHidl::SHARED_MEMORY) {
        status_t status = checkSharedBuffer(hDestination.nonsecureMemory);
        if (status != OK) {
            return status;
        }
        secure = false;
    } else if (hDestination.type == BufferTypeHidl::NATIVE_HANDLE) {
        secure = true;
    } else {
        android_errorWriteLog(0x534e4554, "70526702");
        return UNKNOWN_ERROR;
    }

    status_t status = checkSharedBuffer(hSource);
    if (status != OK) {
        return status;
    }

    status_t err = UNKNOWN_ERROR;
    mLock.unlock();

    std::vector<uint8_t> keyIdAidl(toStdVec(keyId, 16));
    std::vector<uint8_t> ivAidl(toStdVec(iv, 16));

    DecryptArgs args;
    args.secure = secure;
    args.keyId = keyIdAidl;
    args.iv = ivAidl;
    args.mode = aMode;
    args.pattern = aPattern;
    args.subSamples = std::move(stdSubSamples);
    args.source = hidlSharedBufferToAidlSharedBuffer(hSource);
    args.offset = offset;
    args.destination = hidlDestinationBufferToAidlDestinationBuffer(hDestination);


    int32_t result = 0;
    ::ndk::ScopedAStatus statusAidl = mPlugin->decrypt(args, &result);

    err = statusAidlToStatusT(statusAidl);
    std::string msgStr(statusAidl.getMessage());
    if (errorDetailMsg != nullptr) {
        *errorDetailMsg = toString8(msgStr);
    }
    if (err != OK) {
        ALOGE("Failed on decrypt, error description:%s", statusAidl.getDescription().c_str());
        return err;
    }

    return result;
}

int32_t CryptoHalAidl::setHeap(const sp<HidlMemory>& heap) {
    if (heap == NULL || mHeapSeqNum < 0) {
        ALOGE("setHeap(): heap %p mHeapSeqNum %d", heap.get(), mHeapSeqNum);
        return -1;
    }

    Mutex::Autolock autoLock(mLock);

    if (mInitCheck != OK) {
        return -1;
    }

    int32_t seqNum = mHeapSeqNum++;
    uint32_t bufferId = static_cast<uint32_t>(seqNum);
    mHeapSizes.add(seqNum, heap->size());

    SharedBufferAidl memAidl;
    memAidl.handle = ::android::dupToAidl(heap->handle());
    memAidl.size = heap->size();
    memAidl.bufferId = bufferId;

    auto status = mPlugin->setSharedBufferBase(memAidl);
       ALOGE_IF(!status.isOk(),
             "setSharedBufferBase(): remote call failed");
    return seqNum;
}

void CryptoHalAidl::unsetHeap(int32_t seqNum) {
    Mutex::Autolock autoLock(mLock);

    /*
     * Clear the remote shared memory mapping by setting the shared
     * buffer base to a null hidl_memory.
     *
     * TODO: Add a releaseSharedBuffer method in a future DRM HAL
     * API version to make this explicit.
     */
    ssize_t index = mHeapSizes.indexOfKey(seqNum);
    if (index >= 0) {
        if (mPlugin != NULL) {
            uint32_t bufferId = static_cast<uint32_t>(seqNum);
            SharedBufferAidl memAidl{};
            memAidl.bufferId = bufferId;
            auto status = mPlugin->setSharedBufferBase(memAidl);
            ALOGE_IF(!status.isOk(),
                     "setSharedBufferBase(): remote call failed");
        }
        mHeapSizes.removeItem(seqNum);
    }
}

status_t CryptoHalAidl::getLogMessages(Vector<drm::V1_4::LogMessage>& logs) const {
    Mutex::Autolock autoLock(mLock);
    // Need to convert logmessage

    return DrmUtils::GetLogMessagesAidl<ICryptoPluginAidl>(mPlugin, logs);
}
}  // namespace android
