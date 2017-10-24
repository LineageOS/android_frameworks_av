/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef AAUDIO_AAUDIO_ENDPOINT_MANAGER_H
#define AAUDIO_AAUDIO_ENDPOINT_MANAGER_H

#include <map>
#include <mutex>
#include <utils/Singleton.h>

#include "binding/AAudioServiceMessage.h"
#include "AAudioServiceEndpoint.h"
#include "AAudioServiceEndpointCapture.h"
#include "AAudioServiceEndpointPlay.h"

namespace aaudio {

class AAudioEndpointManager : public android::Singleton<AAudioEndpointManager>{
public:
    AAudioEndpointManager();
    ~AAudioEndpointManager() = default;

    /**
     * Returns information about the state of the this class.
     *
     * Will attempt to get the object lock, but will proceed
     * even if it cannot.
     *
     * Each line of information ends with a newline.
     *
     * @return a string with useful information
     */
    std::string dump() const;

    /**
     * Find a service endpoint for the given deviceId and direction.
     * If an endpoint does not already exist then try to create one.
     *
     * @param deviceId
     * @param direction
     * @return endpoint or nullptr
     */
    AAudioServiceEndpoint *openEndpoint(android::AAudioService &audioService,
                                        const AAudioStreamConfiguration& configuration,
                                        aaudio_direction_t direction);

    void closeEndpoint(AAudioServiceEndpoint *serviceEndpoint);

private:

    mutable std::mutex mLock;

    std::vector<AAudioServiceEndpointCapture *> mInputs;
    std::vector<AAudioServiceEndpointPlay *> mOutputs;

};

} /* namespace aaudio */

#endif //AAUDIO_AAUDIO_ENDPOINT_MANAGER_H
