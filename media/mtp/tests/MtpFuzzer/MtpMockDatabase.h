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
#ifndef _MTP_MOCK_DATABASE_H
#define _MTP_MOCK_DATABASE_H

#include <map>

#include "IMtpDatabase.h"
#include "MtpStorage.h"

namespace android {

class MtpMockDatabase : public IMtpDatabase {
    std::map<MtpStorageID, MtpStorage*> mStorage;
    std::vector<MtpObjectInfo*> mObjects;
    uint32_t mLastObjectHandle;

public:
    MtpMockDatabase();
    virtual ~MtpMockDatabase();

    // MtpFuzzer methods
    void addStorage(MtpStorage* storage) {
        // we don't own this
        mStorage[storage->getStorageID()] = storage;
    }

    bool hasStorage(MtpStorageID storage) { return mStorage.find(storage) != mStorage.end(); }

    void addObject(MtpObjectInfo* info);
    MtpObjectHandle allocateObjectHandle();

    // libmtp interface methods
    // Called from SendObjectInfo to reserve a database entry for the incoming
    // file.
    MtpObjectHandle beginSendObject(const char* path, MtpObjectFormat format,
                                    MtpObjectHandle parent, MtpStorageID storage);

    // Called to report success or failure of the SendObject file transfer.
    void endSendObject(MtpObjectHandle handle, bool succeeded);

    // Called to rescan a file, such as after an edit.
    void rescanFile(const char* path, MtpObjectHandle handle, MtpObjectFormat format);

    MtpObjectHandleList* getObjectList(MtpStorageID storageID, MtpObjectFormat format,
                                       MtpObjectHandle parent);

    int getNumObjects(MtpStorageID storageID, MtpObjectFormat format, MtpObjectHandle parent);

    // callee should delete[] the results from these
    // results can be NULL
    MtpObjectFormatList* getSupportedPlaybackFormats();
    MtpObjectFormatList* getSupportedCaptureFormats();
    MtpObjectPropertyList* getSupportedObjectProperties(MtpObjectFormat format);
    MtpDevicePropertyList* getSupportedDeviceProperties();

    MtpResponseCode getObjectPropertyValue(MtpObjectHandle handle, MtpObjectProperty property,
                                           MtpDataPacket& packet);

    MtpResponseCode setObjectPropertyValue(MtpObjectHandle handle, MtpObjectProperty property,
                                           MtpDataPacket& packet);

    MtpResponseCode getDevicePropertyValue(MtpDeviceProperty property, MtpDataPacket& packet);

    MtpResponseCode setDevicePropertyValue(MtpDeviceProperty property, MtpDataPacket& packet);

    MtpResponseCode resetDeviceProperty(MtpDeviceProperty property);

    MtpResponseCode getObjectPropertyList(MtpObjectHandle handle, uint32_t format,
                                          uint32_t property, int groupCode, int depth,
                                          MtpDataPacket& packet);

    MtpResponseCode getObjectInfo(MtpObjectHandle handle, MtpObjectInfo& info);

    void* getThumbnail(MtpObjectHandle handle, size_t& outThumbSize);

    MtpResponseCode getObjectFilePath(MtpObjectHandle handle, MtpStringBuffer& outFilePath,
                                      int64_t& outFileLength, MtpObjectFormat& outFormat);

    int openFilePath(const char* path, bool transcode);

    MtpResponseCode beginDeleteObject(MtpObjectHandle handle);
    void endDeleteObject(MtpObjectHandle handle, bool succeeded);

    MtpObjectHandleList* getObjectReferences(MtpObjectHandle handle);

    MtpResponseCode setObjectReferences(MtpObjectHandle handle, MtpObjectHandleList* references);

    MtpProperty* getObjectPropertyDesc(MtpObjectProperty property, MtpObjectFormat format);

    MtpProperty* getDevicePropertyDesc(MtpDeviceProperty property);

    MtpResponseCode beginMoveObject(MtpObjectHandle handle, MtpObjectHandle newParent,
                                    MtpStorageID newStorage);

    void endMoveObject(MtpObjectHandle oldParent, MtpObjectHandle newParent,
                       MtpStorageID oldStorage, MtpStorageID newStorage, MtpObjectHandle handle,
                       bool succeeded);

    MtpResponseCode beginCopyObject(MtpObjectHandle handle, MtpObjectHandle newParent,
                                    MtpStorageID newStorage);
    void endCopyObject(MtpObjectHandle handle, bool succeeded);
};

}; // namespace android

#endif // _MTP_MOCK_DATABASE_H
