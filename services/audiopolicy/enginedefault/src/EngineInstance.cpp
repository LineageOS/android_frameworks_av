/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <EngineInterface.h>
#include "Engine.h"

namespace android {
namespace audio_policy {

extern "C" EngineInterface* createEngineInstance()
{
    return new (std::nothrow) Engine();
}

extern "C" void destroyEngineInstance(EngineInterface *engine)
{
    delete static_cast<Engine*>(engine);
}

} // namespace audio_policy
} // namespace android
