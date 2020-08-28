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

#ifndef __DRM_MANAGER_H__
#define __DRM_MANAGER_H__

#include <drm/drm_framework_common.h>
#include <media/stagefright/foundation/AHandler.h>
#include <media/stagefright/foundation/ALooper.h>
#include <media/stagefright/foundation/AMessage.h>
#include <sys/types.h>
#include <utils/Errors.h>
#include <utils/threads.h>

#include "IDrmEngine.h"
#include "PlugInManager.h"
#include "IDrmServiceListener.h"

#include <array>
#include <cstddef>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace android {

class IDrmManager;
class DrmRegistrationInfo;
class DrmUnregistrationInfo;
class DrmRightsAcquisitionInfo;
class DrmConstraints;
class DrmMetadata;
class DrmRights;
class DrmInfo;
class DrmInfoStatus;
class DrmConvertedStatus;
class DrmInfoRequest;
class DrmSupportInfo;
class ActionDescription;

enum DrmManagerMethodId {
  GET_CONSTRAINTS,
  GET_METADATA,
  CAN_HANDLE,
  PROCESS_DRM_INFO,
  ACQUIRE_DRM_INFO,
  SAVE_RIGHTS,
  GET_ORIGINAL_MIME_TYPE,
  GET_DRM_OBJECT_TYPE,
  CHECK_RIGHTS_STATUS,
  REMOVE_RIGHTS,
  REMOVE_ALL_RIGHTS,
  OPEN_CONVERT_SESSION,
  OPEN_DECRYPT_SESSION,
  NUM_METHODS,
};

struct DrmManagerMetrics {
    std::string mPluginId;
    std::string mDescription;
    std::set<std::string> mMimeTypes;
    std::array<int64_t, DrmManagerMethodId::NUM_METHODS> mMethodCounts{};
    uid_t mCallingUid;
};

/**
 * This is implementation class for DRM Manager. This class delegates the
 * functionality to corresponding DRM Engine.
 *
 * The DrmManagerService class creates an instance of this class.
 *
 */
class DrmManager : public AHandler, public IDrmEngine::OnInfoListener {
public:
    DrmManager();
    virtual ~DrmManager();

public:
    int addUniqueId(bool isNative);

    void removeUniqueId(int uniqueId);

    void addClient(int uniqueId);

    void removeClient(int uniqueId);

    status_t loadPlugIns();

    status_t loadPlugIns(const String8& plugInDirPath);

    status_t unloadPlugIns();

    status_t setDrmServiceListener(
            int uniqueId, const sp<IDrmServiceListener>& drmServiceListener);

    DrmConstraints* getConstraints(int uniqueId, const String8* path, const int action);

    DrmMetadata* getMetadata(int uniqueId, const String8* path);

    bool canHandle(int uniqueId, const String8& path, const String8& mimeType);

    DrmInfoStatus* processDrmInfo(int uniqueId, const DrmInfo* drmInfo);

    DrmInfo* acquireDrmInfo(int uniqueId, const DrmInfoRequest* drmInfoRequest);

    status_t saveRights(int uniqueId, const DrmRights& drmRights,
            const String8& rightsPath, const String8& contentPath);

    String8 getOriginalMimeType(int uniqueId, const String8& path, int fd);

    int getDrmObjectType(int uniqueId, const String8& path, const String8& mimeType);

    int checkRightsStatus(int uniqueId, const String8& path, int action);

    status_t consumeRights(int uniqueId, sp<DecryptHandle>& decryptHandle, int action,
            bool reserve);

    status_t setPlaybackStatus(
            int uniqueId, sp<DecryptHandle>& decryptHandle, int playbackStatus, int64_t position);

    bool validateAction(
            int uniqueId, const String8& path, int action, const ActionDescription& description);

    status_t removeRights(int uniqueId, const String8& path);

    status_t removeAllRights(int uniqueId);

    int openConvertSession(int uniqueId, const String8& mimeType);

    DrmConvertedStatus* convertData(int uniqueId, int convertId, const DrmBuffer* inputData);

    DrmConvertedStatus* closeConvertSession(int uniqueId, int convertId);

    status_t getAllSupportInfo(int uniqueId, int* length, DrmSupportInfo** drmSupportInfoArray);

    sp<DecryptHandle> openDecryptSession(
            int uniqueId, int fd, off64_t offset, off64_t length, const char* mime);

    sp<DecryptHandle> openDecryptSession(int uniqueId, const char* uri, const char* mime);

    sp<DecryptHandle> openDecryptSession(int uniqueId, const DrmBuffer& buf,
            const String8& mimeType);

    status_t closeDecryptSession(int uniqueId, sp<DecryptHandle>& decryptHandle);

    status_t initializeDecryptUnit(int uniqueId, sp<DecryptHandle>& decryptHandle,
            int decryptUnitId, const DrmBuffer* headerInfo);

    status_t decrypt(int uniqueId, sp<DecryptHandle>& decryptHandle, int decryptUnitId,
            const DrmBuffer* encBuffer, DrmBuffer** decBuffer, DrmBuffer* IV);

    status_t finalizeDecryptUnit(int uniqueId, sp<DecryptHandle>& decryptHandle,
            int decryptUnitId);

    ssize_t pread(int uniqueId, sp<DecryptHandle>& decryptHandle,
            void* buffer, ssize_t numBytes, off64_t offset);

    void onInfo(const DrmInfoEvent& event);

    void initMetricsLooper();

private:
    String8 getSupportedPlugInId(int uniqueId, const String8& path, const String8& mimeType);

    String8 getSupportedPlugInId(const String8& mimeType);

    String8 getSupportedPlugInIdFromPath(int uniqueId, const String8& path);

    bool canHandle(int uniqueId, const String8& path);

    void onMessageReceived(const sp<AMessage> &msg);

    int64_t getMetricsFlushPeriodUs();

    void recordEngineMetrics(const char func[],
            const String8& plugInId, const String8& mimeType = String8(""));

    void flushEngineMetrics();

private:
    enum {
        kMaxNumUniqueIds = 0x1000,
        kWhatFlushMetrics = 'metr',
    };

    bool mUniqueIdArray[kMaxNumUniqueIds];
    static const String8 EMPTY_STRING;
    static const std::map<const char*, size_t> kMethodIdMap;

    int mDecryptSessionId;
    int mConvertId;
    Mutex mLock;
    Mutex mListenerLock;
    Mutex mDecryptLock;
    Mutex mConvertLock;
    Mutex mMetricsLock;
    TPlugInManager<IDrmEngine> mPlugInManager;
    KeyedVector< DrmSupportInfo, String8 > mSupportInfoToPlugInIdMap;
    KeyedVector< int, IDrmEngine*> mConvertSessionMap;
    KeyedVector< int, sp<IDrmServiceListener> > mServiceListeners;
    KeyedVector< int, IDrmEngine*> mDecryptSessionMap;

    std::map<std::pair<uid_t, std::string>, DrmManagerMetrics> mPluginMetrics;
    sp<ALooper> mMetricsLooper;
};

};

#endif /* __DRM_MANAGER_H__ */

