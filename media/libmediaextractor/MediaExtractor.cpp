/*
 * Copyright (C) 2009 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "MediaExtractor"
#include <utils/Log.h>
#include <pwd.h>

#include <media/MediaAnalyticsItem.h>
#include <media/MediaExtractor.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/MetaData.h>

namespace android {

// key for media statistics
static const char *kKeyExtractor = "extractor";

MediaExtractor::MediaExtractor() {
    if (!LOG_NDEBUG) {
        uid_t uid = getuid();
        struct passwd *pw = getpwuid(uid);
        ALOGV("extractor created in uid: %d (%s)", getuid(), pw->pw_name);
    }

    mAnalyticsItem = NULL;
    if (MEDIA_LOG) {
        mAnalyticsItem = new MediaAnalyticsItem(kKeyExtractor);
        (void) mAnalyticsItem->generateSessionID();
    }
}

MediaExtractor::~MediaExtractor() {

    // log the current record, provided it has some information worth recording
    if (MEDIA_LOG) {
        if (mAnalyticsItem != NULL) {
            if (mAnalyticsItem->count() > 0) {
                mAnalyticsItem->setFinalized(true);
                mAnalyticsItem->selfrecord();
            }
        }
    }
    if (mAnalyticsItem != NULL) {
        delete mAnalyticsItem;
        mAnalyticsItem = NULL;
    }
}

sp<MetaData> MediaExtractor::getMetaData() {
    return new MetaData;
}

status_t MediaExtractor::getMetrics(Parcel *reply) {

    if (mAnalyticsItem == NULL || reply == NULL) {
        return UNKNOWN_ERROR;
    }

    populateMetrics();
    mAnalyticsItem->writeToParcel(reply);

    return OK;
}

void MediaExtractor::populateMetrics() {
    ALOGV("MediaExtractor::populateMetrics");
    // normally overridden in subclasses
}

uint32_t MediaExtractor::flags() const {
    return CAN_SEEK_BACKWARD | CAN_SEEK_FORWARD | CAN_PAUSE | CAN_SEEK;
}

}  // namespace android
