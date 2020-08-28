/*
 * Copyright (C) 2017 The Android Open Source Project
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

#pragma once

#include <atomic>
#include <deque>
#include <future>
#include <mutex>
#include <unordered_map>

// IMediaMetricsService must include Vector, String16, Errors
#include <android-base/thread_annotations.h>
#include <media/IMediaMetricsService.h>
#include <mediautils/ServiceUtilities.h>
#include <utils/String8.h>

#include "AudioAnalytics.h"

namespace android {

class MediaMetricsService : public BnMediaMetricsService
{
public:
    MediaMetricsService();
    ~MediaMetricsService() override;

    /**
     * Submits the indicated record to the mediaanalytics service.
     *
     * \param item the item to submit.
     * \return status failure, which is negative on binder transaction failure.
     *         As the transaction is one-way, remote failures will not be reported.
     */
    status_t submit(mediametrics::Item *item) override {
        return submitInternal(item, false /* release */);
    }

    status_t submitBuffer(const char *buffer, size_t length) override {
        mediametrics::Item *item = new mediametrics::Item();
        return item->readFromByteString(buffer, length)
                ?: submitInternal(item, true /* release */);
    }

    status_t dump(int fd, const Vector<String16>& args) override;

    static constexpr const char * const kServiceName = "media.metrics";

    /**
     * Rounds time to the nearest second.
     */
    static nsecs_t roundTime(nsecs_t timeNs);

    /**
     * Returns true if we should use uid for package name when uploading to statsd.
     */
    static bool useUidForPackage(const std::string& package, const std::string& installer);

    /**
     * Returns a std::pair of packageName and versionCode for a given uid.
     *
     * The value is sanitized - i.e. if the result is not approved to send,
     * we use the uid as a string and a version code of 0.
     */
    static std::pair<std::string, int64_t> getSanitizedPackageNameAndVersionCode(uid_t uid);

protected:

    // Internal call where release is true if ownership of item is transferred
    // to the service (that is, the service will eventually delete the item).
    status_t submitInternal(mediametrics::Item *item, bool release) override;

private:
    void processExpirations();
    // input validation after arrival from client
    static bool isContentValid(const mediametrics::Item *item, bool isTrusted);
    bool isRateLimited(mediametrics::Item *) const;
    void saveItem(const std::shared_ptr<const mediametrics::Item>& item);

    bool expirations(const std::shared_ptr<const mediametrics::Item>& item) REQUIRES(mLock);

    // support for generating output
    void dumpQueue(String8 &result, int64_t sinceNs, const char* prefix) REQUIRES(mLock);
    void dumpHeaders(String8 &result, int64_t sinceNs, const char* prefix) REQUIRES(mLock);

    // The following variables accessed without mLock

    // limit how many records we'll retain
    // by count (in each queue (open, finalized))
    const size_t mMaxRecords;
    // by time (none older than this)
    const nsecs_t mMaxRecordAgeNs;
    // max to expire per expirations_l() invocation
    const size_t mMaxRecordsExpiredAtOnce;

    std::atomic<int64_t> mItemsSubmitted{}; // accessed outside of lock.

    mediametrics::AudioAnalytics mAudioAnalytics; // mAudioAnalytics is locked internally.

    std::mutex mLock;
    // statistics about our analytics
    int64_t mItemsFinalized GUARDED_BY(mLock) = 0;
    int64_t mItemsDiscarded GUARDED_BY(mLock) = 0;
    int64_t mItemsDiscardedExpire GUARDED_BY(mLock) = 0;
    int64_t mItemsDiscardedCount GUARDED_BY(mLock) = 0;

    // If we have a worker thread to garbage collect
    std::future<void> mExpireFuture GUARDED_BY(mLock);

    // Our item queue, generally (oldest at front)
    // TODO: Make separate class, use segmented queue, write lock only end.
    // Note: Another analytics module might have ownership of an item longer than the log.
    std::deque<std::shared_ptr<const mediametrics::Item>> mItems GUARDED_BY(mLock);
};

} // namespace android
