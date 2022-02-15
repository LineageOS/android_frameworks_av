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
#include <utils/Log.h>
#include <string>
#include <vector>

#include "MemoryFileSystem.h"

namespace clearkeydrm {

std::string MemoryFileSystem::GetFileName(const std::string& path) {
    size_t index = path.find_last_of('/');
    if (index != std::string::npos) {
        return path.substr(index + 1);
    } else {
        return path;
    }
}

bool MemoryFileSystem::FileExists(const std::string& fileName) const {
    auto result = mMemoryFileSystem.find(fileName);
    return result != mMemoryFileSystem.end();
}

ssize_t MemoryFileSystem::GetFileSize(const std::string& fileName) const {
    auto result = mMemoryFileSystem.find(fileName);
    if (result != mMemoryFileSystem.end()) {
        return static_cast<ssize_t>(result->second.getFileSize());
    } else {
        ALOGE("Failed to get size for %s", fileName.c_str());
        return -1;
    }
}

std::vector<std::string> MemoryFileSystem::ListFiles() const {
    std::vector<std::string> list;
    for (const auto& filename : mMemoryFileSystem) {
        list.push_back(filename.first);
    }
    return list;
}

size_t MemoryFileSystem::Read(const std::string& path, std::string* buffer) {
    std::string key = GetFileName(path);
    auto result = mMemoryFileSystem.find(key);
    if (result != mMemoryFileSystem.end()) {
        std::string serializedHashFile = result->second.getContent();
        buffer->assign(serializedHashFile);
        return buffer->size();
    } else {
        ALOGE("Failed to read from %s", path.c_str());
        return -1;
    }
}

size_t MemoryFileSystem::Write(const std::string& path, const MemoryFile& memoryFile) {
    std::string key = GetFileName(path);
    auto result = mMemoryFileSystem.find(key);
    if (result != mMemoryFileSystem.end()) {
        mMemoryFileSystem.erase(key);
    }
    mMemoryFileSystem.insert(std::pair<std::string, MemoryFile>(key, memoryFile));
    return memoryFile.getFileSize();
}

bool MemoryFileSystem::RemoveFile(const std::string& fileName) {
    auto result = mMemoryFileSystem.find(fileName);
    if (result != mMemoryFileSystem.end()) {
        mMemoryFileSystem.erase(result);
        return true;
    } else {
        ALOGE("Cannot find license to remove: %s", fileName.c_str());
        return false;
    }
}

bool MemoryFileSystem::RemoveAllFiles() {
    mMemoryFileSystem.clear();
    return mMemoryFileSystem.empty();
}

}  // namespace clearkeydrm
