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


#ifndef ANDROID_MEDIAANALYTICSSERVICE_H
#define ANDROID_MEDIAANALYTICSSERVICE_H

#include <arpa/inet.h>

#include <utils/threads.h>
#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/String8.h>
#include <utils/List.h>

#include <media/IMediaAnalyticsService.h>


namespace android {

class MediaAnalyticsService : public BnMediaAnalyticsService
{

 public:

    virtual int64_t submit(sp<MediaAnalyticsItem> item, bool forcenew);

    virtual List<sp<MediaAnalyticsItem>>
            *getMediaAnalyticsItemList(bool finished, int64_t ts);
    virtual List<sp<MediaAnalyticsItem>>
            *getMediaAnalyticsItemList(bool finished, int64_t ts, MediaAnalyticsItem::Key key);


    static  void            instantiate();
    virtual status_t        dump(int fd, const Vector<String16>& args);

                            MediaAnalyticsService();
    virtual                 ~MediaAnalyticsService();

 private:
    MediaAnalyticsItem::SessionID_t generateUniqueSessionID();

    // statistics about our analytics
    int64_t mItemsSubmitted;
    int64_t mItemsFinalized;
    int64_t mItemsDiscarded;
    MediaAnalyticsItem::SessionID_t mLastSessionID;

    // partitioned a bit so we don't over serialize
    mutable Mutex           mLock;
    mutable Mutex           mLock_ids;

    // the most we hold in memory
    // up to this many in each queue (open, finalized)
    int32_t mMaxRecords;

    // input validation after arrival from client
    bool contentValid(sp<MediaAnalyticsItem>);
    bool rateLimited(sp<MediaAnalyticsItem>);

    // the ones that are still open
    // (newest at front) since we keep looking for them
    List<sp<MediaAnalyticsItem>> *mOpen;
    // the ones we've finalized
    // (oldest at front) so it prints nicely for dumpsys
    List<sp<MediaAnalyticsItem>> *mFinalized;
    // searching within these queues: queue, key
    sp<MediaAnalyticsItem> findItem(List<sp<MediaAnalyticsItem>> *,
                                     sp<MediaAnalyticsItem>, bool removeit);

    void saveItem(sp<MediaAnalyticsItem>);
    void saveItem(List<sp<MediaAnalyticsItem>>*, sp<MediaAnalyticsItem>, int);
    void deleteItem(List<sp<MediaAnalyticsItem>>*, sp<MediaAnalyticsItem>);

    String8 dumpQueue(List<sp<MediaAnalyticsItem>> *);

};

// ----------------------------------------------------------------------------

}; // namespace android

#endif // ANDROID_MEDIAANALYTICSSERVICE_H
