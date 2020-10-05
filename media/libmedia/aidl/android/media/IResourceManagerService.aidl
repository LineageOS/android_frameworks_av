/**
 * Copyright (c) 2019, The Android Open Source Project
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

import android.media.IResourceManagerClient;
import android.media.MediaResourceParcel;
import android.media.MediaResourcePolicyParcel;

/**
 * ResourceManagerService interface that keeps track of media resource
 * owned by clients, and reclaims resources based on configured policies
 * when necessary.
 *
 * {@hide}
 */
interface IResourceManagerService {
    const @utf8InCpp String kPolicySupportsMultipleSecureCodecs
            = "supports-multiple-secure-codecs";
    const @utf8InCpp String kPolicySupportsSecureWithNonSecureCodec
            = "supports-secure-with-non-secure-codec";

    /**
     * Configure the ResourceManagerService to adopted particular policies when
     * managing the resources.
     *
     * @param policies an array of policies to be adopted.
     */
    void config(in MediaResourcePolicyParcel[] policies);

    /**
     * Add a client to a process with a list of resources.
     *
     * @param pid pid of the client.
     * @param uid uid of the client.
     * @param clientId an identifier that uniquely identifies the client within the pid.
     * @param client interface for the ResourceManagerService to call the client.
     * @param resources an array of resources to be added.
     */
    void addResource(
            int pid,
            int uid,
            long clientId,
            IResourceManagerClient client,
            in MediaResourceParcel[] resources);

    /**
     * Remove the listed resources from a client.
     *
     * @param pid pid from which the list of resources will be removed.
     * @param clientId clientId within the pid from which the list of resources will be removed.
     * @param resources an array of resources to be removed from the client.
     */
    void removeResource(int pid, long clientId, in MediaResourceParcel[] resources);

    /**
     * Remove all resources from a client.
     *
     * @param pid pid from which the client's resources will be removed.
     * @param clientId clientId within the pid that will be removed.
     */
    void removeClient(int pid, long clientId);

    /**
     * Tries to reclaim resource from processes with lower priority than the
     * calling process according to the requested resources.
     *
     * @param callingPid pid of the calling process.
     * @param resources an array of resources to be reclaimed.
     *
     * @return true if the reclaim was successful and false otherwise.
     */
    boolean reclaimResource(int callingPid, in MediaResourceParcel[] resources);

    /**
     * Override the pid of original calling process with the pid of the process
     * who actually use the requested resources.
     *
     * @param originalPid pid of the original calling process.
     * @param newPid pid of the actual process who use the resources.
     *        remove existing override on originalPid if newPid is -1.
     */
    void overridePid(int originalPid, int newPid);

    /**
     * Mark a client for pending removal
     *
     * @param pid pid from which the client's resources will be removed.
     * @param clientId clientId within the pid that will be removed.
     */
    void markClientForPendingRemoval(int pid, long clientId);

    /**
     * Reclaim resources from clients pending removal, if any.
     *
     * @param pid pid from which resources will be reclaimed.
     */
    void reclaimResourcesFromClientsPendingRemoval(int pid);
}
