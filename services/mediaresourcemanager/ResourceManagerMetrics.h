/*
**
** Copyright 2023, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#ifndef ANDROID_MEDIA_RESOURCEMANAGERMETRICS_H_
#define ANDROID_MEDIA_RESOURCEMANAGERMETRICS_H_

#include "ResourceManagerService.h"

namespace android {

using ::aidl::android::media::ClientInfoParcel;
using ::aidl::android::media::ClientConfigParcel;
using ::aidl::android::media::IResourceManagerClient;

struct ProcessInfoInterface;

class UidObserver;

//
// Enumeration for Codec bucket based on:
//   - Encoder or Decoder
//   - hardware implementation or not
//   - Audio/Video/Image codec
//
enum CodecBucket {
    CodecBucketUnspecified = 0,
    HwAudioEncoder = 1,
    HwAudioDecoder = 2,
    HwVideoEncoder = 3,
    HwVideoDecoder = 4,
    HwImageEncoder = 5,
    HwImageDecoder = 6,
    SwAudioEncoder = 7,
    SwAudioDecoder = 8,
    SwVideoEncoder = 9,
    SwVideoDecoder = 10,
    SwImageEncoder = 11,
    SwImageDecoder = 12,
    CodecBucketMaxSize = 13,
};

// Map of client id and client configuration, when it was started last.
typedef std::map<int64_t, ClientConfigParcel> ClientConfigMap;

// Map of pid and the uid.
typedef std::map<int32_t, uid_t> PidUidMap;

// Map of concurrent codes by Codec type bucket.
struct ConcurrentCodecsMap {
    int& operator[](CodecBucket index) {
        return mCodec[index];
    }

    const int& operator[](CodecBucket index) const {
        return mCodec[index];
    }

private:
    int mCodec[CodecBucketMaxSize] = {0};
};

// Current and Peak ConcurrentCodecMap for a process.
struct ConcurrentCodecs {
    ConcurrentCodecsMap mCurrent;
    ConcurrentCodecsMap mPeak;
    // concurrent HW Video codecs.
    int mHWVideoCodecs;
    // concurrent SW Video codecs.
    int mSWVideoCodecs;
    // concurrent Video codecs.
    int mVideoCodecs;
    // concurrent Audio codecs.
    int mAudioCodecs;
    // concurrent Image codecs.
    int mImageCodecs;
};

// Current and Peak pixel count for a process.
struct PixelCount {
    long mCurrent = 0;
    long mPeak = 0;
};

//
//  Resource Manager Metrics is designed to answer some of the questions like:
//    - What apps are causing reclaim and what apps are targeted (reclaimed from) in the process?
//    - which apps use the most codecs and the most codec memory?
//    - What is the % of total successful reclaims?
//
//  Though, it's not in the context of this class, metrics should also answer:
//    - what % of codec errors are due to codec being reclaimed?
//    - What % of successful codec creation(start) requires codec reclaims?
//    - How often codec start fails even after successful reclaim?
//
//  The metrics are collected to analyze and understand the codec resource usage
//  and use that information to help with:
//    - minimize the no of reclaims
//    - reduce the codec start delays by minimizing no of times we try to reclaim
//    - minimize the reclaim errors in codec records
//
//  Success metrics for Resource Manager Service could be defined as:
//   - increase in sucecssful codec creation for the foreground apps
//   - reduce the number of reclaims for codecs
//   - reduce the time to create codec
//
//  We would like to use this data to come up with a better resource management that would:
//   - increase the successful codec creation (for all kind of apps)
//   - decrease the codec errors due to resources
//
// This class that maintains concurrent codec counts based on:
//
//  1. # of concurrent active codecs (initialized, but aren't released yet) of given
//     implementation (by codec name) across the system.
//
//  2. # of concurrent codec usage (started, but not stopped yet), which is
//  measured using codec type bucket (CodecBucket) for:
//   - each process/application.
//   - across the system.
//  Also the peak count of the same for each process/application is maintained.
//
//  3. # of Peak Concurrent Pixels for each process/application.
//  This should help with understanding the (video) memory usage per
//  application.
//

class ResourceManagerMetrics {
public:
    ResourceManagerMetrics(const sp<ProcessInfoInterface>& processInfo);
    ~ResourceManagerMetrics();

    // To be called when a client is created.
    void notifyClientCreated(const ClientInfoParcel& clientInfo);

    // To be called when a client is released.
    void notifyClientReleased(const ClientInfoParcel& clientInfo);

    // To be called when a client is started.
    void notifyClientStarted(const ClientConfigParcel& clientConfig);

    // To be called when a client is stopped.
    void notifyClientStopped(const ClientConfigParcel& clientConfig);

    // To be called when a client's configuration has changed.
    void notifyClientConfigChanged(const ClientConfigParcel& clientConfig);

    // To be called when after a reclaim event.
    void pushReclaimAtom(const ClientInfoParcel& clientInfo,
                         const std::vector<int>& priorities,
                         const std::vector<ClientInfo>& targetClients,
                         bool reclaimed);

    // Add this pid/uid set to monitor for the process termination state.
    void addPid(int pid, uid_t uid = 0);

    // Get the peak concurrent pixel count (associated with the video codecs) for the process.
    long getPeakConcurrentPixelCount(int pid) const;
    // Get the current concurrent pixel count (associated with the video codecs) for the process.
    long getCurrentConcurrentPixelCount(int pid) const;

private:
    ResourceManagerMetrics(const ResourceManagerMetrics&) = delete;
    ResourceManagerMetrics(ResourceManagerMetrics&&) = delete;
    ResourceManagerMetrics& operator=(const ResourceManagerMetrics&) = delete;
    ResourceManagerMetrics& operator=(ResourceManagerMetrics&&) = delete;

    // To increase/decrease the concurrent codec usage for a given CodecBucket.
    void increaseConcurrentCodecs(int32_t pid, CodecBucket codecBucket);
    void decreaseConcurrentCodecs(int32_t pid, CodecBucket codecBucket);

    // To increase/update/decrease the concurrent pixels usage for a process.
    void increasePixelCount(int32_t pid, long pixels);
    void updatePixelCount(int32_t pid, long newPixels, long lastPixels);
    void decreasePixelCount(int32_t pid, long pixels);

    // Issued when the process/application with given pid/uid is terminated.
    void onProcessTerminated(int32_t pid, uid_t uid);

    // To push conccuret codec usage of a process/application.
    void pushConcurrentUsageReport(int32_t pid, uid_t uid);

private:
    std::mutex mLock;

    // Map of client id and the configuration.
    ClientConfigMap mClientConfigMap;

    // Concurrent and Peak Pixel count for each process/application.
    std::map<int32_t, PixelCount> mProcessPixelsMap;

    // Map of resources (name) and number of concurrent instances
    std::map<std::string, int> mConcurrentResourceCountMap;

    // Map of concurrent codes by CodecBucket across the system.
    ConcurrentCodecsMap mConcurrentCodecsMap;
    // Map of concurrent and peak codes by CodecBucket for each process/application.
    std::map<int32_t, ConcurrentCodecs> mProcessConcurrentCodecsMap;

    // Uid Observer to monitor the application termination.
    sp<UidObserver> mUidObserver;
};

} // namespace android

#endif  // ANDROID_MEDIA_RESOURCEMANAGERMETRICS_H_
