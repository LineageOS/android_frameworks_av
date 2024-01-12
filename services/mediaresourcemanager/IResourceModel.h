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

#ifndef ANDROID_MEDIA_IRESOURCEMODEL_H_
#define ANDROID_MEDIA_IRESOURCEMODEL_H_

#include <memory>
#include <vector>

#include <aidl/android/media/IResourceManagerClient.h>
#include <aidl/android/media/MediaResourceParcel.h>

namespace android {

struct ClientInfo;
struct ReclaimRequestInfo;

/*
 * Interface that defines Resource Model.
 *
 * This provides an interface that manages the resource model.
 * The primary functionality of the implementation of this resource model is to:
 *  1. Define a resource model for a device (or family of devices)
 *    For example (and not limited to):
 *      - Can a secure codec coexist with another secure or unsecured codec?
 *      - How many codecs can coexist?
 *      - Can one type of codecs (for example avc) coexist with another type of codec
 *        (for example hevc) independently? OR are they sharing the common
 *        resource pool?
 *  2. Provide a list of clients that hold requesting resources.
 */
class IResourceModel {
public:
    IResourceModel() {}

    virtual ~IResourceModel() {}

    /*
     * Get a list of all clients that holds the resources requested.
     * This implementation uses the ResourceModel to select the clients.
     *
     * @param[in]  reclaimRequestInfo Information about the Reclaim request
     * @param[out] clients The list of clients that hold the resources in question.
     *
     * @return true if there aren't any resource conflicts and false otherwise.
     */
    virtual bool getAllClients(const ReclaimRequestInfo& reclaimRequestInfo,
                               std::vector<ClientInfo>& clients) = 0;
};

} // namespace android

#endif  // ANDROID_MEDIA_IRESOURCEMODEL_H_
