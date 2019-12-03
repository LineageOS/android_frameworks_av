/*
 * Copyright (C) 2019 The Android Open Source Project
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

namespace android {

extern bool enabled_statsd;

// component specific dumpers
extern bool statsd_audiopolicy(const MediaAnalyticsItem *);
extern bool statsd_audiorecord(const MediaAnalyticsItem *);
extern bool statsd_audiothread(const MediaAnalyticsItem *);
extern bool statsd_audiotrack(const MediaAnalyticsItem *);
extern bool statsd_codec(const MediaAnalyticsItem *);
extern bool statsd_extractor(const MediaAnalyticsItem *);
extern bool statsd_nuplayer(const MediaAnalyticsItem *);
extern bool statsd_recorder(const MediaAnalyticsItem *);

extern bool statsd_mediadrm(const MediaAnalyticsItem *);
extern bool statsd_widevineCDM(const MediaAnalyticsItem *);
extern bool statsd_drmmanager(const MediaAnalyticsItem *);

} // namespace android
