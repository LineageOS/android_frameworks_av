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

#include <map>
#include <string>

#include "ClearKeyTypes.h"

namespace clearkeydrm {

// Using android file system requires clearkey plugin to update
// its sepolicy. However, we are unable to update sepolicy for
// older vendor partitions. To provide backward compatibility,
// clearkey plugin implements a very simple file system in memory.
// This memory file system does not support directory structure.
class MemoryFileSystem {
  public:
    struct MemoryFile {
        std::string fileName;  // excludes path
        std::string content;
        size_t fileSize;

        std::string getContent() const { return content; }
        size_t getFileSize() const { return fileSize; }
        void setContent(const std::string& file) { content = file; }
        void setFileName(const std::string& name) { fileName = name; }
        void setFileSize(size_t size) {
            content.resize(size);
            fileSize = size;
        }
    };

    MemoryFileSystem(){};
    virtual ~MemoryFileSystem(){};

    bool FileExists(const std::string& fileName) const;
    ssize_t GetFileSize(const std::string& fileName) const;
    std::vector<std::string> ListFiles() const;
    size_t Read(const std::string& pathName, std::string* buffer);
    bool RemoveAllFiles();
    bool RemoveFile(const std::string& fileName);
    size_t Write(const std::string& pathName, const MemoryFile& memoryFile);

  private:
    // License file name is made up of a unique keySetId, therefore,
    // the filename can be used as the key to locate licenses in the
    // memory file system.
    std::map<std::string, MemoryFile> mMemoryFileSystem;

    std::string GetFileName(const std::string& path);

    CLEARKEY_DISALLOW_COPY_AND_ASSIGN(MemoryFileSystem);
};

}  // namespace clearkeydrm
