/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef ANDROID_IMEDIAANALYTICSSERVICE_H
#define ANDROID_IMEDIAANALYTICSSERVICE_H

#include <utils/String8.h>
#include <binder/IInterface.h>
#include <binder/Parcel.h>

#include <sys/types.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/RefBase.h>
#include <utils/List.h>

#include <binder/IServiceManager.h>

#include <media/MediaAnalyticsItem.h>
// nope...#include <media/MediaAnalytics.h>

namespace android {

class IMediaAnalyticsService: public IInterface
{
public:
    DECLARE_META_INTERFACE(MediaAnalyticsService);

    /**
     * Submits the indicated record to the mediaanalytics service, where
     * it will be merged (if appropriate) with incomplete records that
     * share the same key and sessionID.
     *
     * \param item the item to submit.
     * \return status which is negative if an error is detected (some errors
               may be silent and return 0 - success).
     */
    virtual status_t submit(MediaAnalyticsItem *item) = 0;
};

// ----------------------------------------------------------------------------

class BnMediaAnalyticsService: public BnInterface<IMediaAnalyticsService>
{
public:
    status_t onTransact(uint32_t code,
                        const Parcel& data,
                        Parcel* reply,
                        uint32_t flags = 0) override;

protected:
    // Internal call where release is true if the service is to delete the item.
    virtual status_t submitInternal(
            MediaAnalyticsItem *item, bool release) = 0;
};

}; // namespace android

#endif // ANDROID_IMEDIASTATISTICSSERVICE_H
