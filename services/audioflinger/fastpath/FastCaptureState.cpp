/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "FastCaptureState.h"

namespace android {

// static
const char *FastCaptureState::commandToString(Command command)
{
    const char *str = FastThreadState::commandToString(command);
    if (str != nullptr) {
        return str;
    }
    switch (command) {
    case FastCaptureState::READ:        return "READ";
    case FastCaptureState::WRITE:       return "WRITE";
    case FastCaptureState::READ_WRITE:  return "READ_WRITE";
    }
    LOG_ALWAYS_FATAL("%s: command %d invalid", __func__, (int) command);
}

}  // namespace android
