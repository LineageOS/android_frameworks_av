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

#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#include <libminijail.h>
#include <scoped_minijail.h>

#include "minijail.h"

namespace android {

int SetUpMinijail(const std::string& seccomp_policy_path)
{
    // No seccomp policy defined for this architecture.
    if (access(seccomp_policy_path.c_str(), R_OK) == -1) {
        LOG(WARNING) << "No seccomp policy defined for this architecture.";
        return 0;
    }

    int policy_fd = TEMP_FAILURE_RETRY(open(seccomp_policy_path.c_str(), O_RDONLY | O_CLOEXEC));
    if (policy_fd == -1) {
        PLOG(FATAL) << "Failed to open seccomp policy file '" << seccomp_policy_path << "'";
    }

    ScopedMinijail jail{minijail_new()};
    if (!jail) {
        LOG(WARNING) << "Failed to create minijail.";
        return -1;
    }

    minijail_no_new_privs(jail.get());
    minijail_log_seccomp_filter_failures(jail.get());
    minijail_use_seccomp_filter(jail.get());
    // This closes |policy_fd|.
    minijail_parse_seccomp_filters_from_fd(jail.get(), policy_fd);
    minijail_enter(jail.get());
    return 0;
}
}
