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

#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <filesystem>
#include <fstream>
#include <string>

#define LOG_TAG "MtpFuzzer"

#include "IMtpHandle.h"
#include "MtpMockDatabase.h"
#include "MtpMockHandle.h"
#include "MtpObjectInfo.h"
#include "MtpServer.h"
#include "MtpStorage.h"
#include "MtpUtils.h"

constexpr int32_t kMinFiles = 0;
constexpr int32_t kMaxFiles = 5;
constexpr int32_t kMaxBytes = 128;
constexpr float kMinDataSizeFactor = 0.8;
// prefer tmpfs for file operations to avoid wearing out flash
const char* storage_path = "/storage/fuzzer/0";
const char* source_database = "/data/local/tmp/srcdb/";
const std::string test_path = std::string(source_database) + "TestDir/";
const std::string kPropertyKey = "sys.fuse.transcode_mtp";

namespace android {
class MtpMockServer {
  public:
    MtpMockServer(const uint8_t* data, size_t size) : mFdp(data, size) {
        // This is unused in our harness
        int controlFd = -1;

        mHandle = std::make_unique<MtpMockHandle>();
        mStorage = std::make_unique<MtpStorage>(
                mFdp.ConsumeIntegral<uint32_t>() /* storageId */, storage_path,
                mFdp.ConsumeRandomLengthString(kMaxBytes).c_str() /* descriptor */,
                mFdp.ConsumeBool() /* removable */,
                mFdp.ConsumeIntegral<uint64_t>() /* maxFileSize */);
        mDatabase = std::make_unique<MtpMockDatabase>();
        mDatabase->addStorage(mStorage.get());

        init(data, size);

        mMtp = std::make_unique<MtpServer>(
                mDatabase.get(), controlFd, mFdp.ConsumeBool() /* ptp */,
                mFdp.ConsumeRandomLengthString(kMaxBytes).c_str() /* manu */,
                mFdp.ConsumeRandomLengthString(kMaxBytes).c_str() /* model */,
                mFdp.ConsumeRandomLengthString(kMaxBytes).c_str() /* version */,
                mFdp.ConsumeRandomLengthString(kMaxBytes).c_str() /* serial */);
        mMtp->addStorage(mStorage.get());

        // clear the old handle first, so we don't leak memory
        delete mMtp->mHandle;
        mMtp->mHandle = mHandle.get();
    }

    void process() {
        if (mFdp.ConsumeBool()) {
            createDatabaseFromSourceDir(source_database, storage_path, MTP_PARENT_ROOT);
        }

        while (mFdp.remaining_bytes()) {
            MtpStorage storage(mFdp.ConsumeIntegral<uint32_t>() /* id */,
                               mFdp.ConsumeRandomLengthString(kMaxBytes).c_str() /* filePath */,
                               mFdp.ConsumeRandomLengthString(kMaxBytes).c_str() /* description */,
                               mFdp.ConsumeBool() /* removable */,
                               mFdp.ConsumeIntegral<uint64_t>() /* maxFileSize */);

            auto invokeMtpServerAPI = mFdp.PickValueInArray<const std::function<void()>>({
                    [&]() { mMtp->run(); },
                    [&]() { mMtp->sendObjectAdded(mFdp.ConsumeIntegral<uint32_t>()); },
                    [&]() { mMtp->sendObjectRemoved(mFdp.ConsumeIntegral<uint32_t>()); },
                    [&]() { mMtp->sendObjectInfoChanged(mFdp.ConsumeIntegral<uint32_t>()); },
                    [&]() { mMtp->sendDevicePropertyChanged(mFdp.ConsumeIntegral<uint16_t>()); },
                    [&]() { mMtp->addStorage(&storage); },
                    [&]() { mMtp->removeStorage(&storage); },
            });

            invokeMtpServerAPI();
        }

        std::filesystem::remove_all(source_database);
    }

  private:
    void createFiles(std::string path, size_t fileCount) {
        std::ofstream file;
        for (size_t idx = 0; idx < fileCount; ++idx) {
            file.open(path.append(std::to_string(idx)));
            file.close();
        }
    }

    void addPackets(const uint8_t* data, size_t size) {
        size_t off = 0;
        for (size_t i = 0; i < size; ++i) {
            // A longer delimiter could be used, but this worked in practice
            if (data[i] == '@') {
                size_t pktsz = i - off;
                if (pktsz > 0) {
                    packet_t pkt = packet_t((unsigned char*)data + off, (unsigned char*)data + i);
                    // insert into packet buffer
                    mHandle->add_packet(pkt);
                    off = i;
                }
            }
        }
    }

    void init(const uint8_t* data, size_t size) {
        std::vector<uint8_t> packetData = mFdp.ConsumeBytes<uint8_t>(
                mFdp.ConsumeIntegralInRange<int32_t>(kMinDataSizeFactor * size, size));

        // Packetize the input stream
        addPackets(packetData.data(), packetData.size());

        // Setting the property to true/false to randomly fuzz the PoC depended on it
        base::SetProperty(kPropertyKey, mFdp.ConsumeBool() ? "true" : "false");

        std::filesystem::create_directories(source_database);
        if (mFdp.ConsumeBool()) {
            std::filesystem::create_directories(test_path);
            createFiles(test_path, mFdp.ConsumeIntegralInRange<size_t>(kMinFiles, kMaxFiles));
        }
        createFiles(source_database, mFdp.ConsumeIntegralInRange<size_t>(kMinFiles, kMaxFiles));
    }

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

    FuzzedDataProvider mFdp;
    std::unique_ptr<MtpMockHandle> mHandle;
    std::unique_ptr<MtpStorage> mStorage;
    std::unique_ptr<MtpMockDatabase> mDatabase;
    std::unique_ptr<MtpServer> mMtp;
};
};  // namespace android

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) __attribute__((optnone)) {
    // reset our storage (from MtpUtils.h)
    android::deletePath(storage_path);
    android::makeFolder("/storage/fuzzer");
    android::makeFolder(storage_path);

    std::unique_ptr<android::MtpMockServer> mtp =
            std::make_unique<android::MtpMockServer>(data, size);
    mtp->process();

    std::filesystem::remove_all("/storage/fuzzer");
    return 0;
}
