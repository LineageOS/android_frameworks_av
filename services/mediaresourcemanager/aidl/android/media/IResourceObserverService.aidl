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

import android.media.IResourceObserver;
import android.media.MediaObservableFilter;

/**
 * IResourceObserverService interface for registering an IResourceObserver
 * callback to receive status updates about observable media resources.
 *
 * {@hide}
 */
interface IResourceObserverService {

    /**
     * Register an observer on the IResourceObserverService to receive
     * status updates for observable resources.
     *
     * @param observer the observer to register.
     * @param filters an array of filters for resources and events to receive
     *                updates for.
     */
    void registerObserver(
            IResourceObserver observer,
            in MediaObservableFilter[] filters);

    /**
     * Unregister an observer from the IResourceObserverService.
     * The observer will stop receiving the status updates.
     *
     * @param observer the observer to unregister.
     */
    void unregisterObserver(IResourceObserver observer);
}
