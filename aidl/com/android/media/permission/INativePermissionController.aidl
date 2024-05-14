/*
 * Copyright (C) 2024 The Android Open Source Project
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

package com.android.media.permission;

import com.android.media.permission.UidPackageState;

/**
 * This interface is used by system_server to communicate permission information
 * downwards towards native services.
 * {@hide}
 */
interface INativePermissionController {
    /**
     * Initialize app-ids and their corresponding packages, to be used for package validation.
     */
    void populatePackagesForUids(in List<UidPackageState> initialPackageStates);
    /**
     * Replace or populate the list of packages associated with a given uid.
     * If the list is empty, the package no longer exists.
     */
    void updatePackagesForUid(in UidPackageState newPackageState);
}
