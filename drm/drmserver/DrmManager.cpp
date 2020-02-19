/*
 * Copyright (C) 2010 The Android Open Source Project
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
#define LOG_TAG "DrmManager(Native)"

#include <cutils/properties.h>
#include <utils/String8.h>
#include <utils/Log.h>

#include <binder/IPCThreadState.h>
#include <drm/DrmInfo.h>

#include <drm/DrmInfoEvent.h>
#include <drm/DrmRights.h>
#include <drm/DrmConstraints.h>
#include <drm/DrmMetadata.h>
#include <drm/DrmInfoStatus.h>
#include <drm/DrmInfoRequest.h>
#include <drm/DrmSupportInfo.h>
#include <drm/DrmConvertedStatus.h>
#include <media/MediaMetricsItem.h>
#include <IDrmEngine.h>

#include "DrmManager.h"
#include "ReadWriteUtils.h"

#include <algorithm>

#define DECRYPT_FILE_ERROR (-1)

using namespace android;

const String8 DrmManager::EMPTY_STRING("");

const std::map<const char*, size_t> DrmManager::kMethodIdMap {
    {"getConstraints"     , DrmManagerMethodId::GET_CONSTRAINTS       },
    {"getMetadata"        , DrmManagerMethodId::GET_METADATA          },
    {"canHandle"          , DrmManagerMethodId::CAN_HANDLE            },
    {"processDrmInfo"     , DrmManagerMethodId::PROCESS_DRM_INFO      },
    {"acquireDrmInfo"     , DrmManagerMethodId::ACQUIRE_DRM_INFO      },
    {"saveRights"         , DrmManagerMethodId::SAVE_RIGHTS           },
    {"getOriginalMimeType", DrmManagerMethodId::GET_ORIGINAL_MIME_TYPE},
    {"getDrmObjectType"   , DrmManagerMethodId::GET_DRM_OBJECT_TYPE   },
    {"checkRightsStatus"  , DrmManagerMethodId::CHECK_RIGHTS_STATUS   },
    {"removeRights"       , DrmManagerMethodId::REMOVE_RIGHTS         },
    {"removeAllRights"    , DrmManagerMethodId::REMOVE_ALL_RIGHTS     },
    {"openConvertSession" , DrmManagerMethodId::OPEN_CONVERT_SESSION  },
    {"openDecryptSession" , DrmManagerMethodId::OPEN_DECRYPT_SESSION  }
};

DrmManager::DrmManager() :
    mDecryptSessionId(0),
    mConvertId(0) {
    srand(time(NULL));
    memset(mUniqueIdArray, 0, sizeof(bool) * kMaxNumUniqueIds);
}

DrmManager::~DrmManager() {
    if (mMetricsLooper != NULL) {
        mMetricsLooper->stop();
    }
    flushEngineMetrics();
}

void DrmManager::initMetricsLooper() {
    if (mMetricsLooper != NULL) {
        return;
    }
    mMetricsLooper = new ALooper;
    mMetricsLooper->setName("DrmManagerMetricsLooper");
    mMetricsLooper->start();
    mMetricsLooper->registerHandler(this);

    sp<AMessage> msg = new AMessage(kWhatFlushMetrics, this);
    msg->post(getMetricsFlushPeriodUs());
}

void DrmManager::onMessageReceived(const sp<AMessage> &msg) {
    switch (msg->what()) {
        case kWhatFlushMetrics:
        {
            flushEngineMetrics();
            msg->post(getMetricsFlushPeriodUs());
            break;
        }
        default:
        {
            ALOGW("Unrecognized message type: %zd", msg->what());
        }
    }
}

int64_t DrmManager::getMetricsFlushPeriodUs() {
    return 1000 * 1000 * std::max(1ll, property_get_int64("drmmanager.metrics.period", 86400));
}

void DrmManager::recordEngineMetrics(
        const char func[], const String8& plugInId8, const String8& mimeType) {
    IDrmEngine& engine = mPlugInManager.getPlugIn(plugInId8);
    std::unique_ptr<DrmSupportInfo> info(engine.getSupportInfo(0));

    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    std::string plugInId(plugInId8.getPathLeaf().getBasePath().c_str());
    ALOGV("%d calling %s %s", callingUid, plugInId.c_str(), func);

    Mutex::Autolock _l(mMetricsLock);
    auto& metrics = mPluginMetrics[std::make_pair(callingUid, plugInId)];
    if (metrics.mPluginId.empty()) {
        metrics.mPluginId = plugInId;
        metrics.mCallingUid = callingUid;
        if (NULL != info) {
            metrics.mDescription = info->getDescription().c_str();
        }
    }

    if (!mimeType.isEmpty()) {
        metrics.mMimeTypes.insert(mimeType.c_str());
    } else if (NULL != info) {
        DrmSupportInfo::MimeTypeIterator mimeIter = info->getMimeTypeIterator();
        while (mimeIter.hasNext()) {
            metrics.mMimeTypes.insert(mimeIter.next().c_str());
        }
    }

    size_t methodId = kMethodIdMap.at(func);
    if (methodId < metrics.mMethodCounts.size()) {
        metrics.mMethodCounts[methodId]++;
    }
}

void DrmManager::flushEngineMetrics() {
    using namespace std::string_literals;
    Mutex::Autolock _l(mMetricsLock);
    for (auto kv : mPluginMetrics) {
        DrmManagerMetrics& metrics = kv.second;
        std::unique_ptr<mediametrics::Item> item(mediametrics::Item::create("drmmanager"));
        item->setUid(metrics.mCallingUid);
        item->setCString("plugin_id", metrics.mPluginId.c_str());
        item->setCString("description", metrics.mDescription.c_str());

        std::vector<std::string> mimeTypes(metrics.mMimeTypes.begin(), metrics.mMimeTypes.end());
        std::string mimeTypesStr(mimeTypes.empty() ? "" : mimeTypes[0]);
        for (size_t i = 1; i < mimeTypes.size() ; i++) {
            mimeTypesStr.append(",").append(mimeTypes[i]);
        }
        item->setCString("mime_types", mimeTypesStr.c_str());

        for (size_t i = 0; i < metrics.mMethodCounts.size() ; i++) {
            item->setInt64(("method"s + std::to_string(i)).c_str(), metrics.mMethodCounts[i]);
        }

        if (!item->selfrecord()) {
            ALOGE("Failed to record metrics");
        }
    }
    mPluginMetrics.clear();
}

int DrmManager::addUniqueId(bool isNative) {
    Mutex::Autolock _l(mLock);

    int uniqueId = -1;
    int random = rand();

    for (size_t index = 0; index < kMaxNumUniqueIds; ++index) {
        int temp = (random + index) % kMaxNumUniqueIds;
        if (!mUniqueIdArray[temp]) {
            uniqueId = temp;
            mUniqueIdArray[uniqueId] = true;

            if (isNative) {
                // set a flag to differentiate DrmManagerClient
                // created from native side and java side
                uniqueId |= 0x1000;
            }
            break;
        }
    }

    // -1 indicates that no unique id can be allocated.
    return uniqueId;
}

void DrmManager::removeUniqueId(int uniqueId) {
    Mutex::Autolock _l(mLock);
    if (uniqueId & 0x1000) {
        // clear the flag for the native side.
        uniqueId &= ~(0x1000);
    }

    if (uniqueId >= 0 && uniqueId < kMaxNumUniqueIds) {
        mUniqueIdArray[uniqueId] = false;
    }
}

status_t DrmManager::loadPlugIns() {
    String8 pluginDirPath("/system/lib/drm");
    loadPlugIns(pluginDirPath);
    return DRM_NO_ERROR;
}

status_t DrmManager::loadPlugIns(const String8& plugInDirPath) {
    mPlugInManager.loadPlugIns(plugInDirPath);
    Vector<String8> plugInPathList = mPlugInManager.getPlugInIdList();
    for (size_t i = 0; i < plugInPathList.size(); ++i) {
        String8 plugInPath = plugInPathList[i];
        DrmSupportInfo* info = mPlugInManager.getPlugIn(plugInPath).getSupportInfo(0);
        if (NULL != info) {
            if (mSupportInfoToPlugInIdMap.indexOfKey(*info) < 0) {
                mSupportInfoToPlugInIdMap.add(*info, plugInPath);
            }
            delete info;
        }
    }
    return DRM_NO_ERROR;
}

status_t DrmManager::unloadPlugIns() {
    Mutex::Autolock _l(mLock);
    mConvertSessionMap.clear();
    mDecryptSessionMap.clear();
    mPlugInManager.unloadPlugIns();
    mSupportInfoToPlugInIdMap.clear();
    return DRM_NO_ERROR;
}

status_t DrmManager::setDrmServiceListener(
            int uniqueId, const sp<IDrmServiceListener>& drmServiceListener) {
    Mutex::Autolock _l(mListenerLock);
    if (NULL != drmServiceListener.get()) {
        mServiceListeners.add(uniqueId, drmServiceListener);
    } else {
        mServiceListeners.removeItem(uniqueId);
    }
    return DRM_NO_ERROR;
}

void DrmManager::addClient(int uniqueId) {
    Mutex::Autolock _l(mLock);
    if (!mSupportInfoToPlugInIdMap.isEmpty()) {
        Vector<String8> plugInIdList = mPlugInManager.getPlugInIdList();
        for (size_t index = 0; index < plugInIdList.size(); index++) {
            IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInIdList.itemAt(index));
            rDrmEngine.initialize(uniqueId);
            rDrmEngine.setOnInfoListener(uniqueId, this);
        }
    }
}

void DrmManager::removeClient(int uniqueId) {
    Mutex::Autolock _l(mLock);
    Vector<String8> plugInIdList = mPlugInManager.getPlugInIdList();
    for (size_t index = 0; index < plugInIdList.size(); index++) {
        IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInIdList.itemAt(index));
        rDrmEngine.terminate(uniqueId);
    }
}

DrmConstraints* DrmManager::getConstraints(int uniqueId, const String8* path, const int action) {
    Mutex::Autolock _l(mLock);
    DrmConstraints *constraints = NULL;
    const String8 plugInId = getSupportedPlugInIdFromPath(uniqueId, *path);
    if (EMPTY_STRING != plugInId) {
        IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInId);
        constraints = rDrmEngine.getConstraints(uniqueId, path, action);
    }
    if (NULL != constraints) {
        recordEngineMetrics(__func__, plugInId);
    }
    return constraints;
}

DrmMetadata* DrmManager::getMetadata(int uniqueId, const String8* path) {
    Mutex::Autolock _l(mLock);
    DrmMetadata *meta = NULL;
    const String8 plugInId = getSupportedPlugInIdFromPath(uniqueId, *path);
    if (EMPTY_STRING != plugInId) {
        IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInId);
        meta = rDrmEngine.getMetadata(uniqueId, path);
    }
    if (NULL != meta) {
        recordEngineMetrics(__func__, plugInId);
    }
    return meta;
}

bool DrmManager::canHandle(int uniqueId, const String8& path, const String8& mimeType) {
    Mutex::Autolock _l(mLock);
    const String8 plugInId = getSupportedPlugInId(mimeType);
    bool result = (EMPTY_STRING != plugInId) ? true : false;

    if (result) {
        recordEngineMetrics(__func__, plugInId, mimeType);
    }

    if (0 < path.length()) {
        if (result) {
            IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInId);
            result = rDrmEngine.canHandle(uniqueId, path);
        } else {
            String8 extension = path.getPathExtension();
            if (String8("") != extension) {
                result = canHandle(uniqueId, path);
            }
        }
    }
    return result;
}

DrmInfoStatus* DrmManager::processDrmInfo(int uniqueId, const DrmInfo* drmInfo) {
    Mutex::Autolock _l(mLock);
    DrmInfoStatus *infoStatus = NULL;
    const String8 mimeType = drmInfo->getMimeType();
    const String8 plugInId = getSupportedPlugInId(mimeType);
    if (EMPTY_STRING != plugInId) {
        IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInId);
        infoStatus = rDrmEngine.processDrmInfo(uniqueId, drmInfo);
    }
    if (NULL != infoStatus) {
        recordEngineMetrics(__func__, plugInId, mimeType);
    }
    return infoStatus;
}

bool DrmManager::canHandle(int uniqueId, const String8& path) {
    bool result = false;
    Vector<String8> plugInPathList = mPlugInManager.getPlugInIdList();

    for (size_t i = 0; i < plugInPathList.size(); ++i) {
        IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInPathList[i]);
        result = rDrmEngine.canHandle(uniqueId, path);

        if (result) {
            recordEngineMetrics(__func__, plugInPathList[i]);
            break;
        }
    }
    return result;
}

DrmInfo* DrmManager::acquireDrmInfo(int uniqueId, const DrmInfoRequest* drmInfoRequest) {
    Mutex::Autolock _l(mLock);
    DrmInfo *info = NULL;
    const String8 mimeType = drmInfoRequest->getMimeType();
    const String8 plugInId = getSupportedPlugInId(mimeType);
    if (EMPTY_STRING != plugInId) {
        IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInId);
        info = rDrmEngine.acquireDrmInfo(uniqueId, drmInfoRequest);
    }
    if (NULL != info) {
        recordEngineMetrics(__func__, plugInId, mimeType);
    }
    return info;
}

status_t DrmManager::saveRights(int uniqueId, const DrmRights& drmRights,
            const String8& rightsPath, const String8& contentPath) {
    Mutex::Autolock _l(mLock);
    const String8 mimeType = drmRights.getMimeType();
    const String8 plugInId = getSupportedPlugInId(mimeType);
    status_t result = DRM_ERROR_UNKNOWN;
    if (EMPTY_STRING != plugInId) {
        IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInId);
        result = rDrmEngine.saveRights(uniqueId, drmRights, rightsPath, contentPath);
    }
    if (DRM_NO_ERROR == result) {
        recordEngineMetrics(__func__, plugInId, mimeType);
    }
    return result;
}

String8 DrmManager::getOriginalMimeType(int uniqueId, const String8& path, int fd) {
    Mutex::Autolock _l(mLock);
    String8 mimeType(EMPTY_STRING);
    const String8 plugInId = getSupportedPlugInIdFromPath(uniqueId, path);
    if (EMPTY_STRING != plugInId) {
        IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInId);
        mimeType = rDrmEngine.getOriginalMimeType(uniqueId, path, fd);
    }
    if (!mimeType.isEmpty()) {
        recordEngineMetrics(__func__, plugInId, mimeType);
    }
    return mimeType;
}

int DrmManager::getDrmObjectType(int uniqueId, const String8& path, const String8& mimeType) {
    Mutex::Autolock _l(mLock);
    int type = DrmObjectType::UNKNOWN;
    const String8 plugInId = getSupportedPlugInId(uniqueId, path, mimeType);
    if (EMPTY_STRING != plugInId) {
        IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInId);
        type = rDrmEngine.getDrmObjectType(uniqueId, path, mimeType);
    }
    if (DrmObjectType::UNKNOWN != type) {
        recordEngineMetrics(__func__, plugInId, mimeType);
    }
    return type;
}

int DrmManager::checkRightsStatus(int uniqueId, const String8& path, int action) {
    Mutex::Autolock _l(mLock);
    int rightsStatus = RightsStatus::RIGHTS_INVALID;
    const String8 plugInId = getSupportedPlugInIdFromPath(uniqueId, path);
    if (EMPTY_STRING != plugInId) {
        IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInId);
        rightsStatus = rDrmEngine.checkRightsStatus(uniqueId, path, action);
    }
    if (RightsStatus::RIGHTS_INVALID != rightsStatus) {
        recordEngineMetrics(__func__, plugInId);
    }
    return rightsStatus;
}

status_t DrmManager::consumeRights(
    int uniqueId, sp<DecryptHandle>& decryptHandle, int action, bool reserve) {
    status_t result = DRM_ERROR_UNKNOWN;
    Mutex::Autolock _l(mDecryptLock);
    if (mDecryptSessionMap.indexOfKey(decryptHandle->decryptId) != NAME_NOT_FOUND) {
        IDrmEngine* drmEngine = mDecryptSessionMap.valueFor(decryptHandle->decryptId);
        result = drmEngine->consumeRights(uniqueId, decryptHandle, action, reserve);
    }
    return result;
}

status_t DrmManager::setPlaybackStatus(
    int uniqueId, sp<DecryptHandle>& decryptHandle, int playbackStatus, int64_t position) {
    status_t result = DRM_ERROR_UNKNOWN;
    Mutex::Autolock _l(mDecryptLock);
    if (mDecryptSessionMap.indexOfKey(decryptHandle->decryptId) != NAME_NOT_FOUND) {
        IDrmEngine* drmEngine = mDecryptSessionMap.valueFor(decryptHandle->decryptId);
        result = drmEngine->setPlaybackStatus(uniqueId, decryptHandle, playbackStatus, position);
    }
    return result;
}

bool DrmManager::validateAction(
    int uniqueId, const String8& path, int action, const ActionDescription& description) {
    Mutex::Autolock _l(mLock);
    const String8 plugInId = getSupportedPlugInIdFromPath(uniqueId, path);
    if (EMPTY_STRING != plugInId) {
        IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInId);
        return rDrmEngine.validateAction(uniqueId, path, action, description);
    }
    return false;
}

status_t DrmManager::removeRights(int uniqueId, const String8& path) {
    Mutex::Autolock _l(mLock);
    const String8 plugInId = getSupportedPlugInIdFromPath(uniqueId, path);
    status_t result = DRM_ERROR_UNKNOWN;
    if (EMPTY_STRING != plugInId) {
        IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInId);
        result = rDrmEngine.removeRights(uniqueId, path);
    }
    if (DRM_NO_ERROR == result) {
        recordEngineMetrics(__func__, plugInId);
    }
    return result;
}

status_t DrmManager::removeAllRights(int uniqueId) {
    Vector<String8> plugInIdList = mPlugInManager.getPlugInIdList();
    status_t result = DRM_ERROR_UNKNOWN;
    for (size_t index = 0; index < plugInIdList.size(); index++) {
        IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInIdList.itemAt(index));
        result = rDrmEngine.removeAllRights(uniqueId);
        if (DRM_NO_ERROR != result) {
            break;
        }
        recordEngineMetrics(__func__, plugInIdList[index]);
    }
    return result;
}

int DrmManager::openConvertSession(int uniqueId, const String8& mimeType) {
    Mutex::Autolock _l(mConvertLock);
    int convertId = -1;

    const String8 plugInId = getSupportedPlugInId(mimeType);
    if (EMPTY_STRING != plugInId) {
        IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInId);

        if (DRM_NO_ERROR == rDrmEngine.openConvertSession(uniqueId, mConvertId + 1)) {
            ++mConvertId;
            convertId = mConvertId;
            mConvertSessionMap.add(convertId, &rDrmEngine);
            recordEngineMetrics(__func__, plugInId, mimeType);
        }
    }
    return convertId;
}

DrmConvertedStatus* DrmManager::convertData(
            int uniqueId, int convertId, const DrmBuffer* inputData) {
    DrmConvertedStatus *drmConvertedStatus = NULL;

    Mutex::Autolock _l(mConvertLock);
    if (mConvertSessionMap.indexOfKey(convertId) != NAME_NOT_FOUND) {
        IDrmEngine* drmEngine = mConvertSessionMap.valueFor(convertId);
        drmConvertedStatus = drmEngine->convertData(uniqueId, convertId, inputData);
    }
    return drmConvertedStatus;
}

DrmConvertedStatus* DrmManager::closeConvertSession(int uniqueId, int convertId) {
    Mutex::Autolock _l(mConvertLock);
    DrmConvertedStatus *drmConvertedStatus = NULL;

    if (mConvertSessionMap.indexOfKey(convertId) != NAME_NOT_FOUND) {
        IDrmEngine* drmEngine = mConvertSessionMap.valueFor(convertId);
        drmConvertedStatus = drmEngine->closeConvertSession(uniqueId, convertId);
        mConvertSessionMap.removeItem(convertId);
    }
    return drmConvertedStatus;
}

status_t DrmManager::getAllSupportInfo(
                    int /* uniqueId */, int* length, DrmSupportInfo** drmSupportInfoArray) {
    Mutex::Autolock _l(mLock);
    Vector<String8> plugInPathList = mPlugInManager.getPlugInIdList();
    int size = plugInPathList.size();
    int validPlugins = 0;

    if (0 < size) {
        Vector<DrmSupportInfo> drmSupportInfoList;

        for (int i = 0; i < size; ++i) {
            String8 plugInPath = plugInPathList[i];
            DrmSupportInfo* drmSupportInfo
                = mPlugInManager.getPlugIn(plugInPath).getSupportInfo(0);
            if (NULL != drmSupportInfo) {
                drmSupportInfoList.add(*drmSupportInfo);
                delete drmSupportInfo; drmSupportInfo = NULL;
            }
        }

        validPlugins = drmSupportInfoList.size();
        if (0 < validPlugins) {
            *drmSupportInfoArray = new DrmSupportInfo[validPlugins];
            for (int i = 0; i < validPlugins; ++i) {
                (*drmSupportInfoArray)[i] = drmSupportInfoList[i];
            }
        }
    }
    *length = validPlugins;
    return DRM_NO_ERROR;
}

sp<DecryptHandle> DrmManager::openDecryptSession(
        int uniqueId, int fd, off64_t offset, off64_t length, const char* mime) {

    Mutex::Autolock _l(mDecryptLock);
    status_t result = DRM_ERROR_CANNOT_HANDLE;
    Vector<String8> plugInIdList = mPlugInManager.getPlugInIdList();

    sp<DecryptHandle> handle = new DecryptHandle();
    if (NULL != handle.get()) {
        handle->decryptId = mDecryptSessionId + 1;

        for (size_t index = 0; index < plugInIdList.size(); index++) {
            const String8& plugInId = plugInIdList.itemAt(index);
            IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInId);
            result = rDrmEngine.openDecryptSession(uniqueId, handle, fd, offset, length, mime);

            if (DRM_NO_ERROR == result) {
                ++mDecryptSessionId;
                mDecryptSessionMap.add(mDecryptSessionId, &rDrmEngine);
                recordEngineMetrics(__func__, plugInId, String8(mime));
                break;
            }
        }
    }
    if (DRM_NO_ERROR != result) {
        handle.clear();
    }
    return handle;
}

sp<DecryptHandle> DrmManager::openDecryptSession(
        int uniqueId, const char* uri, const char* mime) {
    Mutex::Autolock _l(mDecryptLock);
    status_t result = DRM_ERROR_CANNOT_HANDLE;
    Vector<String8> plugInIdList = mPlugInManager.getPlugInIdList();

    sp<DecryptHandle> handle = new DecryptHandle();
    if (NULL != handle.get()) {
        handle->decryptId = mDecryptSessionId + 1;

        for (size_t index = 0; index < plugInIdList.size(); index++) {
            const String8& plugInId = plugInIdList.itemAt(index);
            IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInId);
            result = rDrmEngine.openDecryptSession(uniqueId, handle, uri, mime);

            if (DRM_NO_ERROR == result) {
                ++mDecryptSessionId;
                mDecryptSessionMap.add(mDecryptSessionId, &rDrmEngine);
                recordEngineMetrics(__func__, plugInId, String8(mime));
                break;
            }
        }
    }
    if (DRM_NO_ERROR != result) {
        handle.clear();
        ALOGV("DrmManager::openDecryptSession: no capable plug-in found");
    }
    return handle;
}

sp<DecryptHandle> DrmManager::openDecryptSession(
        int uniqueId, const DrmBuffer& buf, const String8& mimeType) {
    Mutex::Autolock _l(mDecryptLock);
    status_t result = DRM_ERROR_CANNOT_HANDLE;
    Vector<String8> plugInIdList = mPlugInManager.getPlugInIdList();

    sp<DecryptHandle> handle = new DecryptHandle();
    if (NULL != handle.get()) {
        handle->decryptId = mDecryptSessionId + 1;

        for (size_t index = 0; index < plugInIdList.size(); index++) {
            const String8& plugInId = plugInIdList.itemAt(index);
            IDrmEngine& rDrmEngine = mPlugInManager.getPlugIn(plugInId);
            result = rDrmEngine.openDecryptSession(uniqueId, handle, buf, mimeType);

            if (DRM_NO_ERROR == result) {
                ++mDecryptSessionId;
                mDecryptSessionMap.add(mDecryptSessionId, &rDrmEngine);
                recordEngineMetrics(__func__, plugInId, mimeType);
                break;
            }
        }
    }
    if (DRM_NO_ERROR != result) {
        handle.clear();
        ALOGV("DrmManager::openDecryptSession: no capable plug-in found");
    }
    return handle;
}

status_t DrmManager::closeDecryptSession(int uniqueId, sp<DecryptHandle>& decryptHandle) {
    Mutex::Autolock _l(mDecryptLock);
    status_t result = DRM_ERROR_UNKNOWN;
    if (mDecryptSessionMap.indexOfKey(decryptHandle->decryptId) != NAME_NOT_FOUND) {
        IDrmEngine* drmEngine = mDecryptSessionMap.valueFor(decryptHandle->decryptId);
        result = drmEngine->closeDecryptSession(uniqueId, decryptHandle);
        if (DRM_NO_ERROR == result && NULL != decryptHandle.get()) {
            mDecryptSessionMap.removeItem(decryptHandle->decryptId);
        }
    }
    return result;
}

status_t DrmManager::initializeDecryptUnit(
        int uniqueId, sp<DecryptHandle>& decryptHandle, int decryptUnitId,
        const DrmBuffer* headerInfo) {
    status_t result = DRM_ERROR_UNKNOWN;
    Mutex::Autolock _l(mDecryptLock);
    if (mDecryptSessionMap.indexOfKey(decryptHandle->decryptId) != NAME_NOT_FOUND) {
        IDrmEngine* drmEngine = mDecryptSessionMap.valueFor(decryptHandle->decryptId);
        result = drmEngine->initializeDecryptUnit(uniqueId, decryptHandle, decryptUnitId, headerInfo);
    }
    return result;
}

status_t DrmManager::decrypt(int uniqueId, sp<DecryptHandle>& decryptHandle, int decryptUnitId,
            const DrmBuffer* encBuffer, DrmBuffer** decBuffer, DrmBuffer* IV) {
    status_t result = DRM_ERROR_UNKNOWN;

    Mutex::Autolock _l(mDecryptLock);
    if (mDecryptSessionMap.indexOfKey(decryptHandle->decryptId) != NAME_NOT_FOUND) {
        IDrmEngine* drmEngine = mDecryptSessionMap.valueFor(decryptHandle->decryptId);
        result = drmEngine->decrypt(
                uniqueId, decryptHandle, decryptUnitId, encBuffer, decBuffer, IV);
    }
    return result;
}

status_t DrmManager::finalizeDecryptUnit(
            int uniqueId, sp<DecryptHandle>& decryptHandle, int decryptUnitId) {
    status_t result = DRM_ERROR_UNKNOWN;
    Mutex::Autolock _l(mDecryptLock);
    if (mDecryptSessionMap.indexOfKey(decryptHandle->decryptId) != NAME_NOT_FOUND) {
        IDrmEngine* drmEngine = mDecryptSessionMap.valueFor(decryptHandle->decryptId);
        result = drmEngine->finalizeDecryptUnit(uniqueId, decryptHandle, decryptUnitId);
    }
    return result;
}

ssize_t DrmManager::pread(int uniqueId, sp<DecryptHandle>& decryptHandle,
            void* buffer, ssize_t numBytes, off64_t offset) {
    ssize_t result = DECRYPT_FILE_ERROR;

    Mutex::Autolock _l(mDecryptLock);
    if (mDecryptSessionMap.indexOfKey(decryptHandle->decryptId) != NAME_NOT_FOUND) {
        IDrmEngine* drmEngine = mDecryptSessionMap.valueFor(decryptHandle->decryptId);
        result = drmEngine->pread(uniqueId, decryptHandle, buffer, numBytes, offset);
    }
    return result;
}

String8 DrmManager::getSupportedPlugInId(
            int uniqueId, const String8& path, const String8& mimeType) {
    String8 plugInId("");

    if (EMPTY_STRING != mimeType) {
        plugInId = getSupportedPlugInId(mimeType);
    } else {
        plugInId = getSupportedPlugInIdFromPath(uniqueId, path);
    }
    return plugInId;
}

String8 DrmManager::getSupportedPlugInId(const String8& mimeType) {
    String8 plugInId("");

    if (EMPTY_STRING != mimeType) {
        for (size_t index = 0; index < mSupportInfoToPlugInIdMap.size(); index++) {
            const DrmSupportInfo& drmSupportInfo = mSupportInfoToPlugInIdMap.keyAt(index);

            if (drmSupportInfo.isSupportedMimeType(mimeType)) {
                plugInId = mSupportInfoToPlugInIdMap.valueFor(drmSupportInfo);
                break;
            }
        }
    }
    return plugInId;
}

String8 DrmManager::getSupportedPlugInIdFromPath(int uniqueId, const String8& path) {
    String8 plugInId("");
    const String8 fileSuffix = path.getPathExtension();

    for (size_t index = 0; index < mSupportInfoToPlugInIdMap.size(); index++) {
        const DrmSupportInfo& drmSupportInfo = mSupportInfoToPlugInIdMap.keyAt(index);

        if (drmSupportInfo.isSupportedFileSuffix(fileSuffix)) {
            String8 key = mSupportInfoToPlugInIdMap.valueFor(drmSupportInfo);
            IDrmEngine& drmEngine = mPlugInManager.getPlugIn(key);

            if (drmEngine.canHandle(uniqueId, path)) {
                plugInId = key;
                break;
            }
        }
    }
    return plugInId;
}

void DrmManager::onInfo(const DrmInfoEvent& event) {
    Mutex::Autolock _l(mListenerLock);
    for (size_t index = 0; index < mServiceListeners.size(); index++) {
        int uniqueId = mServiceListeners.keyAt(index);

        if (uniqueId == event.getUniqueId()) {
            sp<IDrmServiceListener> serviceListener = mServiceListeners.valueFor(uniqueId);
            serviceListener->notify(event);
        }
    }
}

