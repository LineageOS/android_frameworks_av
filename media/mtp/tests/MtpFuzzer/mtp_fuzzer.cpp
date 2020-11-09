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

#include <android-base/unique_fd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <string>

#define LOG_TAG "MtpFuzzer"

#include "IMtpHandle.h"
#include "MtpMockDatabase.h"
#include "MtpMockHandle.h"
#include "MtpObjectInfo.h"
#include "MtpServer.h"
#include "MtpStorage.h"
#include "MtpUtils.h"

const char* storage_desc = "Fuzz Storage";
// prefer tmpfs for file operations to avoid wearing out flash
const char* storage_path = "/storage/fuzzer/0";
const char* source_database = "srcdb/";

namespace android {
class MtpMockServer {
public:
    std::unique_ptr<MtpMockHandle> mHandle;
    std::unique_ptr<MtpStorage> mStorage;
    std::unique_ptr<MtpMockDatabase> mDatabase;
    std::unique_ptr<MtpServer> mMtp;
    int mStorageId;

    MtpMockServer(const char* storage_path) : mStorageId(0) {
        bool ptp = false;
        const char* manu = "Google";
        const char* model = "Pixel 3XL";
        const char* version = "1.0";
        const char* serial = "ABDEF1231";

        // This is unused in our harness
        int controlFd = -1;

        mHandle = std::make_unique<MtpMockHandle>();
        mStorage = std::make_unique<MtpStorage>(mStorageId, storage_path, storage_desc, true,
                                                0x200000000L);
        mDatabase = std::make_unique<MtpMockDatabase>();
        mDatabase->addStorage(mStorage.get());

        mMtp = std::make_unique<MtpServer>(mDatabase.get(), controlFd, ptp, manu, model, version,
                                           serial);
        mMtp->addStorage(mStorage.get());

        // clear the old handle first, so we don't leak memory
        delete mMtp->mHandle;
        mMtp->mHandle = mHandle.get();
    }

    void run() { mMtp->run(); }

    int createDatabaseFromSourceDir(const char* fromPath, const char* toPath,
                                    MtpObjectHandle parentHandle) {
        int ret = 0;
        std::string fromPathStr(fromPath);
        std::string toPathStr(toPath);

        DIR* dir = opendir(fromPath);
        if (!dir) {
            ALOGE("opendir %s failed", fromPath);
            return -1;
        }
        if (fromPathStr[fromPathStr.size() - 1] != '/') fromPathStr += '/';
        if (toPathStr[toPathStr.size() - 1] != '/') toPathStr += '/';

        struct dirent* entry;
        while ((entry = readdir(dir))) {
            const char* name = entry->d_name;

            // ignore "." and ".."
            if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0))) {
                continue;
            }

            std::string oldFile = fromPathStr + name;
            std::string newFile = toPathStr + name;

            if (entry->d_type == DT_DIR) {
                ret += makeFolder(newFile.c_str());

                MtpObjectInfo* objectInfo = new MtpObjectInfo(mDatabase->allocateObjectHandle());
                objectInfo->mStorageID = mStorage->getStorageID();
                objectInfo->mParent = parentHandle;
                objectInfo->mFormat = MTP_FORMAT_ASSOCIATION; // folder
                objectInfo->mName = strdup(name);
                objectInfo->mKeywords = strdup("");

                mDatabase->addObject(objectInfo);

                ret += createDatabaseFromSourceDir(oldFile.c_str(), newFile.c_str(),
                                                   objectInfo->mHandle);
            } else {
                ret += copyFile(oldFile.c_str(), newFile.c_str());

                MtpObjectInfo* objectInfo = new MtpObjectInfo(mDatabase->allocateObjectHandle());
                objectInfo->mStorageID = mStorage->getStorageID();
                objectInfo->mParent = parentHandle;
                objectInfo->mFormat = MTP_FORMAT_TEXT;
                objectInfo->mName = strdup(name);
                objectInfo->mKeywords = strdup("");

                mDatabase->addObject(objectInfo);
            }
        }

        closedir(dir);
        return ret;
    }
};
}; // namespace android

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) __attribute__((optnone)) {
    // reset our storage (from MtpUtils.h)
    android::deletePath(storage_path);
    android::makeFolder("/storage/fuzzer");
    android::makeFolder(storage_path);

    std::unique_ptr<android::MtpMockServer> mtp =
            std::make_unique<android::MtpMockServer>(storage_path);

    size_t off = 0;

    // Packetize the input stream
    for (size_t i = 0; i < size; i++) {
        // A longer delimiter could be used, but this worked in practice
        if (data[i] == '@') {
            size_t pktsz = i - off;
            if (pktsz > 0) {
                packet_t pkt = packet_t((unsigned char*)data + off, (unsigned char*)data + i);
                // insert into packet buffer
                mtp->mHandle->add_packet(pkt);
                off = i;
            }
        }
    }

    mtp->createDatabaseFromSourceDir(source_database, storage_path, MTP_PARENT_ROOT);
    mtp->run();

    return 0;
}
