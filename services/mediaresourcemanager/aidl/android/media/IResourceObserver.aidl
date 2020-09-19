/**
 * Copyright (c) 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.media;

import android.media.MediaObservableEvent;
import android.media.MediaObservableParcel;

/**
 * IResourceObserver interface for receiving observable resource updates
 * from IResourceObserverService.
 *
 * {@hide}
 */
interface IResourceObserver {
    /**
     * Called when an observed resource is granted to a client.
     *
     * @param event the status change that happened to the resource.
     * @param uid uid to which the resource is associated.
     * @param pid pid to which the resource is associated.
     * @param observables the resources whose status has changed.
     */
    oneway void onStatusChanged(MediaObservableEvent event,
        int uid, int pid, in MediaObservableParcel[] observables);
}
