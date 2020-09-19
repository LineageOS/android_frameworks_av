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

import android.media.MediaObservableType;
import android.media.MediaObservableEvent;

/**
 * Description of an observable resource and its associated events that the
 * observer is interested in.
 *
 * {@hide}
 */
parcelable MediaObservableFilter {
    /**
     * Type of the observable media resource.
     */
    MediaObservableType type;

    /**
     * Events that the observer is interested in.
     *
     * This field is a bitwise-OR of the events in MediaObservableEvent. If a
     * particular event's bit is set, it means that updates should be sent for
     * that event. For example, if the observer is only interested in receiving
     * updates when a resource becomes available, it should only set 'kIdle'.
     */
    MediaObservableEvent eventFilter;
}
