/*
 * Copyright (C) 2023 The Android Open Source Project
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

package android.media;

/**
 * TODO(b/280077672): This is a temporary copy of the stable
 * android.hardware.audio.core.AudioRoute. Interfaces from the Core API do not
 * support the CPP backend. This copy will be removed either by moving the
 * AudioRoute from core to a.m.a.common or by switching the framework internal
 * interfaces to the NDK backend.
 * {@hide}
 */
parcelable AudioRoute {
    /**
     * The list of IDs of source audio ports ('AudioPort.id').
     * There must be at least one source in a valid route and all IDs must be
     * unique.
     */
    int[] sourcePortIds;
    /** The ID of the sink audio port ('AudioPort.id'). */
    int sinkPortId;
    /** If set, only one source can be active, mixing is not supported. */
    boolean isExclusive;
}
