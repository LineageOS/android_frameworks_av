/*
**
** Copyright 2023, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#ifndef ANDROID_MEDIA_DEFAULTRESOURCEMODEL_H_
#define ANDROID_MEDIA_DEFAULTRESOURCEMODEL_H_

#include "IResourceModel.h"

namespace android {

class ResourceTracker;

/*
 * Implements the Default Resource Model that handles:
 *   - coexistence of secure codec with another secure/non-secure codecs
 *   - sharing resources among other codecs
 */
class DefaultResourceModel : public IResourceModel {
public:
    DefaultResourceModel(const std::shared_ptr<ResourceTracker>& resourceTracker,
                         bool supportsMultipleSecureCodecs = true,
                         bool supportsSecureWithNonSecureCodec = true);
    virtual ~DefaultResourceModel();

    /*
     * Set the codec co-existence properties
     */
    void config(bool supportsMultipleSecureCodecs, bool supportsSecureWithNonSecureCodec) {
        mSupportsMultipleSecureCodecs = supportsMultipleSecureCodecs;
        mSupportsSecureWithNonSecureCodec = supportsSecureWithNonSecureCodec;
    }

    /*
     * Get a list of all clients that holds the resources requested.
     * This implementation uses the ResourceModel to select the clients.
     *
     * @param[in]  reclaimRequestInfo Information about the Reclaim request
     * @param[out] cliens The list of clients that hold the resources in question.
     *
     * @return true if there aren't any resource conflicts and false otherwise.
     */
    bool getAllClients(const ReclaimRequestInfo& reclaimRequestInfo,
                       std::vector<ClientInfo>& clients) override;

protected:
    bool getCodecClients(const ReclaimRequestInfo& reclaimRequestInfo,
                         std::vector<ClientInfo>& clients);

protected:
    // Keeping these protected to allow extending this implementation
    // by other resource models.
    bool mSupportsMultipleSecureCodecs;
    bool mSupportsSecureWithNonSecureCodec;
    std::shared_ptr<ResourceTracker> mResourceTracker;
};

} // namespace android

#endif  // ANDROID_MEDIA_DEFAULTRESOURCEMODEL_H_
