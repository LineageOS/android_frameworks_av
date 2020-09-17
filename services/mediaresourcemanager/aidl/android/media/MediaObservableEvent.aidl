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

/**
 * Enums for media observable events.
 *
 * These values are used as bitmasks to indicate the events that the
 * observer is interested in in the MediaObservableFilter objects passed to
 * IResourceObserverService::registerObserver().
 *
 * {@hide}
 */
@Backing(type="long")
enum MediaObservableEvent {
    /**
     * A media resource is granted to a client and becomes busy.
     */
    kBusy = 1,

    /**
     * A media resource is released by a client and becomes idle.
     */
    kIdle = 2,

    /**
     * A bitmask that covers all observable events defined.
     */
    kAll = ~0,
}
