// Copyright 2015, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#include <libminijail.h>
#include <scoped_minijail.h>

#include "minijail.h"

namespace android {

int WritePolicyToPipe(const std::string& base_policy_content,
                      const std::vector<std::string>& additional_policy_contents)
{
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        PLOG(ERROR) << "pipe() failed";
        return -1;
    }

    base::unique_fd write_end(pipefd[1]);
    std::string content = base_policy_content;

    for (auto one_content : additional_policy_contents) {
        if (one_content.length() > 0) {
            content += "\n";
            content += one_content;
        }
    }

    if (!base::WriteStringToFd(content, write_end.get())) {
        LOG(ERROR) << "Could not write policy to fd";
        return -1;
    }

    return pipefd[0];
}

void SetUpMinijail(const std::string& base_policy_path,
                   const std::string& additional_policy_path)
{
    SetUpMinijailList(base_policy_path, {additional_policy_path});
}

void SetUpMinijailList(const std::string& base_policy_path,
                   const std::vector<std::string>& additional_policy_paths)
{
    std::string base_policy_content;
    std::vector<std::string> additional_policy_contents;
    if (!base::ReadFileToString(base_policy_path, &base_policy_content,
                                false /* follow_symlinks */)) {
        LOG(FATAL) << "Could not read base policy file '" << base_policy_path << "'";
    }

    for (auto one_policy_path : additional_policy_paths) {
        std::string one_policy_content;
        if (one_policy_path.length() > 0 &&
                !base::ReadFileToString(one_policy_path, &one_policy_content,
                    false /* follow_symlinks */)) {
            // TODO: harder failure (fatal unless ENOENT?)
            LOG(WARNING) << "Could not read additional policy file '" << one_policy_path << "'";
        }
        additional_policy_contents.push_back(one_policy_content);
    }

    base::unique_fd policy_fd(WritePolicyToPipe(base_policy_content, additional_policy_contents));
    if (policy_fd.get() == -1) {
        LOG(FATAL) << "Could not write seccomp policy to fd";
    }

    ScopedMinijail jail{minijail_new()};
    if (!jail) {
        LOG(FATAL) << "Failed to create minijail.";
    }

    minijail_no_new_privs(jail.get());
    minijail_log_seccomp_filter_failures(jail.get());
    minijail_use_seccomp_filter(jail.get());
    // Transfer ownership of |policy_fd|.
    minijail_parse_seccomp_filters_from_fd(jail.get(), policy_fd.release());
    minijail_enter(jail.get());
}
}
