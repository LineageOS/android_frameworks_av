/*
 * Copyright (C) 2020 The Android Open Source Project
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
 * TranscodingJobStats encapsulated the stats of the a TranscodingJob.
 *
 * {@hide}
 */
parcelable TranscodingJobStats {
    /**
     * System time of when the job is created.
     */
    long jobCreatedTimeUs;

    /**
     * System time of when the job is finished.
     */
    long jobFinishedTimeUs;

    /**
     * Total time spend on transcoding, exclude the time in pause.
     */
    long totalProcessingTimeUs;

    /**
     * Total time spend on handling the job, include the time in pause.
     * The totaltimeUs is actually the same as jobFinishedTimeUs - jobCreatedTimeUs.
     */
    long totalTimeUs;
}
