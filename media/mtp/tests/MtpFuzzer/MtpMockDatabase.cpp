/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <string>

#define LOG_TAG "MtpFuzzer"

#include <log/log.h>

#include "MtpDebug.h"
#include "MtpMockDatabase.h"
#include "MtpObjectInfo.h"

namespace android {

MtpMockDatabase::MtpMockDatabase() : mLastObjectHandle(0) {}

MtpMockDatabase::~MtpMockDatabase() {
    for (MtpObjectInfo* i : mObjects) {
        delete i;
    }
    mObjects.clear();
}

void MtpMockDatabase::addObject(MtpObjectInfo* info) {
    assert(hasStorage(info->mStorageID));

    // we take ownership
    mObjects.push_back(info);

    return;
}

MtpObjectHandle MtpMockDatabase::allocateObjectHandle() {
    // this is in sync with our mObjects database
    return mLastObjectHandle++;
}

// Called from SendObjectInfo to reserve a database entry for the incoming file.
MtpObjectHandle MtpMockDatabase::beginSendObject(const char* path, MtpObjectFormat format,
                                                 MtpObjectHandle parent, MtpStorageID storage) {
    if (!hasStorage(storage)) {
        ALOGW("%s: Tried to lookup storageID %u, but doesn't exist\n", __func__, storage);
        return kInvalidObjectHandle;
    }

    ALOGD("MockDatabase %s: path=%s oformat=0x%04x parent_handle=%u "
          "storage_id=%u\n",
          __func__, path, format, parent, storage);

    return mLastObjectHandle;
}

// Called to report success or failure of the SendObject file transfer.
void MtpMockDatabase::endSendObject(MtpObjectHandle handle, bool succeeded) {
    ALOGD("MockDatabase %s: ohandle=%u succeeded=%d\n", __func__, handle, succeeded);
}

// Called to rescan a file, such as after an edit.
void MtpMockDatabase::rescanFile(const char* path, MtpObjectHandle handle, MtpObjectFormat format) {
    ALOGD("MockDatabase %s: path=%s ohandle=%u, oformat=0x%04x\n", __func__, path, handle, format);
}

MtpObjectHandleList* MtpMockDatabase::getObjectList(MtpStorageID storageID, MtpObjectFormat format,
                                                    MtpObjectHandle parent) {
    ALOGD("MockDatabase %s: storage_id=%u oformat=0x%04x ohandle=%u\n", __func__, storageID, format,
          parent);
    return nullptr;
}

int MtpMockDatabase::getNumObjects(MtpStorageID storageID, MtpObjectFormat format,
                                   MtpObjectHandle parent) {
    ALOGD("MockDatabase %s: storage_id=%u oformat=0x%04x ohandle=%u\n", __func__, storageID, format,
          parent);
    // TODO: return MTP_RESPONSE_OK when it stops segfaulting
    return 0;
}

// callee should delete[] the results from these
// results can be NULL
MtpObjectFormatList* MtpMockDatabase::getSupportedPlaybackFormats() {
    ALOGD("MockDatabase %s\n", __func__);
    return nullptr;
}
MtpObjectFormatList* MtpMockDatabase::getSupportedCaptureFormats() {
    ALOGD("MockDatabase %s\n", __func__);
    return nullptr;
}
MtpObjectPropertyList* MtpMockDatabase::getSupportedObjectProperties(MtpObjectFormat format) {
    ALOGD("MockDatabase %s: oformat=0x%04x\n", __func__, format);
    return nullptr;
}
MtpDevicePropertyList* MtpMockDatabase::getSupportedDeviceProperties() {
    ALOGD("MockDatabase %s\n", __func__);
    return nullptr;
}

MtpResponseCode MtpMockDatabase::getObjectPropertyValue(MtpObjectHandle handle,
                                                        MtpObjectProperty property,
                                                        MtpDataPacket& packet) {
    ALOGD("MockDatabase %s: ohandle=%u property=%s\n", __func__, handle,
          MtpDebug::getObjectPropCodeName(property));
    return MTP_RESPONSE_OK;
}

MtpResponseCode MtpMockDatabase::setObjectPropertyValue(MtpObjectHandle handle,
                                                        MtpObjectProperty property,
                                                        MtpDataPacket& packet) {
    ALOGD("MockDatabase %s: ohandle=%u property=%s\n", __func__, handle,
          MtpDebug::getObjectPropCodeName(property));
    return MTP_RESPONSE_OK;
}

MtpResponseCode MtpMockDatabase::getDevicePropertyValue(MtpDeviceProperty property,
                                                        MtpDataPacket& packet) {
    ALOGD("MockDatabase %s: property=%s\n", __func__, MtpDebug::getDevicePropCodeName(property));
    return MTP_RESPONSE_OK;
}

MtpResponseCode MtpMockDatabase::setDevicePropertyValue(MtpDeviceProperty property,
                                                        MtpDataPacket& packet) {
    ALOGD("MockDatabase %s: property=%s\n", __func__, MtpDebug::getDevicePropCodeName(property));
    return MTP_RESPONSE_OK;
}

MtpResponseCode MtpMockDatabase::resetDeviceProperty(MtpDeviceProperty property) {
    ALOGD("MockDatabase %s: property=%s\n", __func__, MtpDebug::getDevicePropCodeName(property));
    return MTP_RESPONSE_OK;
}

MtpResponseCode MtpMockDatabase::getObjectPropertyList(MtpObjectHandle handle, uint32_t format,
                                                       uint32_t property, int groupCode, int depth,
                                                       MtpDataPacket& packet) {
    ALOGD("MockDatabase %s: ohandle=%u format=%s property=%s groupCode=%d "
          "depth=%d\n",
          __func__, handle, MtpDebug::getFormatCodeName(format),
          MtpDebug::getObjectPropCodeName(property), groupCode, depth);
    return MTP_RESPONSE_OK;
}

MtpResponseCode MtpMockDatabase::getObjectInfo(MtpObjectHandle handle, MtpObjectInfo& info) {
    ALOGD("MockDatabase %s: ohandle=%u\n", __func__, handle);

    // used for the root
    if (handle == kInvalidObjectHandle) {
        return MTP_RESPONSE_INVALID_OBJECT_HANDLE;
    } else {
        if (mObjects.size() == 0) {
            return MTP_RESPONSE_INVALID_OBJECT_HANDLE;
        }

        // this is used to let the fuzzer make progress, otherwise
        // it has to brute-force a 32-bit handle
        MtpObjectHandle reducedHandle = handle % mObjects.size();
        MtpObjectInfo* obj = mObjects[reducedHandle];

        // make a copy, but make sure to maintain ownership of string pointers
        info = *obj;

        // fixup the response handle
        info.mHandle = handle;

        if (obj->mName) info.mName = strdup(obj->mName);
        if (obj->mKeywords) info.mKeywords = strdup(obj->mKeywords);

        return MTP_RESPONSE_OK;
    }
}

void* MtpMockDatabase::getThumbnail(MtpObjectHandle handle, size_t& outThumbSize) {
    ALOGD("MockDatabase %s: ohandle=%u\n", __func__, handle);

    size_t allocSize = handle % 0x1000;
    void* data = calloc(allocSize, sizeof(uint8_t));
    if (!data) {
        return nullptr;
    } else {
        ALOGD("MockDatabase %s\n", __func__);
        outThumbSize = allocSize;
        return data;
    }
}

MtpResponseCode MtpMockDatabase::getObjectFilePath(MtpObjectHandle handle,
                                                   MtpStringBuffer& outFilePath,
                                                   int64_t& outFileLength,
                                                   MtpObjectFormat& outFormat) {
    ALOGD("MockDatabase %s: ohandle=%u\n", __func__, handle);

    if (mObjects.size() == 0) {
        return MTP_RESPONSE_INVALID_OBJECT_HANDLE;
    }

    // this is used to let the fuzzer make progress, otherwise
    // it has to brute-force a 32-bit handle
    MtpObjectHandle reducedHandle = handle % mObjects.size();
    MtpObjectInfo* obj = mObjects[reducedHandle];
    MtpStorage* storage = mStorage[obj->mStorageID];

    // walk up the tree to build a full path of the object
    MtpObjectHandle currentHandle = reducedHandle;
    std::string path = "";

    while (currentHandle != MTP_PARENT_ROOT) {
        MtpObjectInfo* next = mObjects[currentHandle];

        // prepend the name
        if (path == "")
            path = std::string(next->mName);
        else
            path = std::string(next->mName) + "/" + path;

        currentHandle = next->mParent;
    }

    outFilePath.set(storage->getPath());
    outFilePath.append("/");
    outFilePath.append(path.c_str());

    outFormat = obj->mFormat;

    ALOGD("MockDatabase %s: get file %s\n", __func__, (const char*)outFilePath);

    struct stat sstat;
    // this should not happen unless our database view of the filesystem is out of
    // sync
    if (stat((const char*)outFilePath, &sstat) < 0) {
        ALOGE("MockDatabase %s: unable to stat %s\n", __func__, (const char*)outFilePath);

        return MTP_RESPONSE_INVALID_OBJECT_HANDLE;
    }

    outFileLength = sstat.st_size;

    return MTP_RESPONSE_OK;
}

int MtpMockDatabase::openFilePath(const char* path, bool transcode) {
    ALOGD("MockDatabase %s: filePath=%s transcode=%d\n", __func__, path, transcode);
    return 0;
}

MtpResponseCode MtpMockDatabase::beginDeleteObject(MtpObjectHandle handle) {
    ALOGD("MockDatabase %s: ohandle=%u\n", __func__, handle);
    return MTP_RESPONSE_OK;
}
void MtpMockDatabase::endDeleteObject(MtpObjectHandle handle, bool succeeded) {
    ALOGD("MockDatabase %s: ohandle=%u succeeded=%d\n", __func__, handle, succeeded);
    return;
}

MtpObjectHandleList* MtpMockDatabase::getObjectReferences(MtpObjectHandle handle) {
    ALOGD("MockDatabase %s: ohandle=%u\n", __func__, handle);
    return nullptr;
}

MtpResponseCode MtpMockDatabase::setObjectReferences(MtpObjectHandle handle,
                                                     MtpObjectHandleList* references) {
    ALOGD("MockDatabase %s: ohandle=%u\n", __func__, handle);
    return MTP_RESPONSE_OK;
}

MtpProperty* MtpMockDatabase::getObjectPropertyDesc(MtpObjectProperty property,
                                                    MtpObjectFormat format) {
    ALOGD("MockDatabase %s: property=%s format=%s\n", __func__,
          MtpDebug::getObjectPropCodeName(property), MtpDebug::getFormatCodeName(format));

    return nullptr;
}

MtpProperty* MtpMockDatabase::getDevicePropertyDesc(MtpDeviceProperty property) {
    ALOGD("MockDatabase %s: property=%s\n", __func__, MtpDebug::getDevicePropCodeName(property));
    return nullptr;
}

MtpResponseCode MtpMockDatabase::beginMoveObject(MtpObjectHandle handle, MtpObjectHandle newParent,
                                                 MtpStorageID newStorage) {
    ALOGD("MockDatabase %s: ohandle=%u newParent=%u newStorage=%u\n", __func__, handle, newParent,
          newStorage);
    return MTP_RESPONSE_OK;
}

void MtpMockDatabase::endMoveObject(MtpObjectHandle oldParent, MtpObjectHandle newParent,
                                    MtpStorageID oldStorage, MtpStorageID newStorage,
                                    MtpObjectHandle handle, bool succeeded) {
    ALOGD("MockDatabase %s: oldParent=%u newParent=%u oldStorage=%u newStorage=%u "
          "ohandle=%u succeeded=%d\n",
          __func__, oldParent, newParent, oldStorage, newStorage, handle, succeeded);
    return;
}

MtpResponseCode MtpMockDatabase::beginCopyObject(MtpObjectHandle handle, MtpObjectHandle newParent,
                                                 MtpStorageID newStorage) {
    ALOGD("MockDatabase %s: ohandle=%u newParent=%u newStorage=%u\n", __func__, handle, newParent,
          newStorage);
    return MTP_RESPONSE_OK;
}

void MtpMockDatabase::endCopyObject(MtpObjectHandle handle, bool succeeded) {
    ALOGD("MockDatabase %s: ohandle=%u succeeded=%d\n", __func__, handle, succeeded);
}

}; // namespace android
