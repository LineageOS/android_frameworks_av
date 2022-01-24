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
#pragma once

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <set>
#include <string>
#include <vector>

#include "ClearKeyTypes.h"
#include "MemoryFileSystem.h"

namespace clearkeydrm {
class OfflineFile;
class DeviceFiles {
  public:
    typedef enum {
        kLicenseStateUnknown,
        kLicenseStateActive,
        kLicenseStateReleasing,
    } LicenseState;

    DeviceFiles(){};
    virtual ~DeviceFiles(){};

    virtual bool StoreLicense(const std::string& keySetId, LicenseState state,
                              const std::string& keyResponse);

    virtual bool RetrieveLicense(const std::string& key_set_id, LicenseState* state,
                                 std::string* offlineLicense);

    virtual bool LicenseExists(const std::string& keySetId);

    virtual std::vector<std::string> ListLicenses() const;

    virtual bool DeleteLicense(const std::string& keySetId);

    virtual bool DeleteAllLicenses();

  private:
    bool FileExists(const std::string& path) const;
    ssize_t GetFileSize(const std::string& fileName) const;
    bool RemoveFile(const std::string& fileName);

    bool RetrieveHashedFile(
            const std::string& fileName,
            OfflineFile* deSerializedFile);
    bool StoreFileRaw(const std::string& fileName, const std::string& serializedFile);
    bool StoreFileWithHash(const std::string& fileName, const std::string& serializedFile);

    MemoryFileSystem mFileHandle;

    CLEARKEY_DISALLOW_COPY_AND_ASSIGN(DeviceFiles);
};

}  // namespace clearkeydrm
