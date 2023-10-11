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

#ifndef ANDROID_MEDIA_RESOURCEMANAGERSERVICEUTILS_H_
#define ANDROID_MEDIA_RESOURCEMANAGERSERVICEUTILS_H_

#include <vector>
#include <utils/String8.h>

namespace android {

// templated function to stringify the given vector of items.
template <typename T>
String8 getString(const std::vector<T>& items) {
    String8 itemsStr;
    for (size_t i = 0; i < items.size(); ++i) {
        itemsStr.appendFormat("%s ", toString(items[i]).c_str());
    }
    return itemsStr;
}

// Bunch of utility functions that looks for a specific Resource.

//Check whether a given resource (of type and subtype) is found in given resource parcel.
bool hasResourceType(MediaResource::Type type, MediaResource::SubType subType,
        const MediaResourceParcel& resource);

//Check whether a given resource (of type and subtype) is found in given resource list.
bool hasResourceType(MediaResource::Type type, MediaResource::SubType subType,
        const ResourceList& resources);

//Check whether a given resource (of type and subtype) is found in given resource info list.
bool hasResourceType(MediaResource::Type type, MediaResource::SubType subType,
        const ResourceInfos& infos);

// Return modifiable list of ResourceInfo for a given process (look up by pid)
// from the map of ResourceInfos.
ResourceInfos& getResourceInfosForEdit(int pid, PidResourceInfosMap& map);

// Return modifiable ResourceInfo for a given process (look up by pid)
// from the map of ResourceInfos.
// If the item is not in the map, create one and add it to the map.
ResourceInfo& getResourceInfoForEdit(const ClientInfoParcel& clientInfo,
        const std::shared_ptr<IResourceManagerClient>& client, ResourceInfos& infos);

} // namespace android

#endif //ANDROID_MEDIA_RESOURCEMANAGERSERVICEUTILS_H_
