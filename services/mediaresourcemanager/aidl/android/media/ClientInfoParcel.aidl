/**
 * Copyright (c) 2023, The Android Open Source Project
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
 * Description of a Client(codec) information.
 *
 * {@hide}
 */
parcelable ClientInfoParcel {
    /**
     * The PID of the client process.
     */
    int pid = -1;

    /**
     * The UID of the client process.
     */
    int uid = -1;

    /**
     * The ID of the client.
     */
    long id = 0;

    /**
     * Name of the resource associated with the client.
     */
    @utf8InCpp String name;

    /*
     * Client importance, which ranges from 0 to int_max.
     * The default importance is high (0)
     * Based on the reclaim policy, this could be used during reclaim.
     */
    int importance = 0;
}
