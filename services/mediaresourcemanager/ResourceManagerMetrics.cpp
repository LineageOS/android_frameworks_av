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

//#define LOG_NDEBUG 0
#define LOG_TAG "ResourceManagerMetrics"
#include <utils/Log.h>
#include <mediautils/ProcessInfo.h>

#include <stats_media_metrics.h>

#include "UidObserver.h"
#include "ResourceManagerMetrics.h"

#include <cmath>
#include <sstream>

namespace android {

using stats::media_metrics::stats_write;
using stats::media_metrics::MEDIA_CODEC_STARTED;
using stats::media_metrics::MEDIA_CODEC_STOPPED;
// Disabling this for now.
#ifdef ENABLE_MEDIA_CODEC_CONCURRENT_USAGE_REPORTED
using stats::media_metrics::MEDIA_CODEC_CONCURRENT_USAGE_REPORTED;
#endif
using stats::media_metrics::MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED;
using stats::media_metrics::MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED__RECLAIM_STATUS__RECLAIM_SUCCESS;
using stats::media_metrics::\
    MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED__RECLAIM_STATUS__RECLAIM_FAILED_NO_CLIENTS;
using stats::media_metrics::\
    MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED__RECLAIM_STATUS__RECLAIM_FAILED_RECLAIM_RESOURCES;

inline const char* getCodecType(MediaResourceSubType codecType) {
    switch (codecType) {
        case MediaResourceSubType::kAudioCodec:         return "Audio";
        case MediaResourceSubType::kVideoCodec:         return "Video";
        case MediaResourceSubType::kImageCodec:         return "Image";
        case MediaResourceSubType::kUnspecifiedSubType:
        default:
                                                        return "Unspecified";
    }
    return "Unspecified";
}

static CodecBucket getCodecBucket(bool isHardware,
                                  bool isEncoder,
                                  MediaResourceSubType codecType) {
    if (isHardware) {
        switch (codecType) {
            case MediaResourceSubType::kAudioCodec:
                if (isEncoder) return HwAudioEncoder;
                return HwAudioDecoder;
            case MediaResourceSubType::kVideoCodec:
                if (isEncoder) return HwVideoEncoder;
                return HwVideoDecoder;
            case MediaResourceSubType::kImageCodec:
                if (isEncoder) return HwImageEncoder;
                return HwImageDecoder;
            case MediaResourceSubType::kUnspecifiedSubType:
            default:
                return CodecBucketUnspecified;
        }
    } else {
        switch (codecType) {
            case MediaResourceSubType::kAudioCodec:
                if (isEncoder) return SwAudioEncoder;
                return SwAudioDecoder;
            case MediaResourceSubType::kVideoCodec:
                if (isEncoder) return SwVideoEncoder;
                return SwVideoDecoder;
            case MediaResourceSubType::kImageCodec:
                if (isEncoder) return SwImageEncoder;
                return SwImageDecoder;
            case MediaResourceSubType::kUnspecifiedSubType:
            default:
                return CodecBucketUnspecified;
        }
    }

    return CodecBucketUnspecified;
}

static bool getLogMessage(int hwCount, int swCount, std::stringstream& logMsg) {
    bool update = false;
    logMsg.clear();

    if (hwCount > 0) {
        logMsg << " HW: " << hwCount;
        update = true;
    }
    if (swCount > 0) {
        logMsg << " SW: " << swCount;
        update = true;
    }

    if (update) {
        logMsg << " ] ";
    }
    return update;
}

ResourceManagerMetrics::ResourceManagerMetrics(const sp<ProcessInfoInterface>& processInfo) {
    // Create a process termination watcher, with 5seconds of polling frequency.
    mUidObserver = sp<UidObserver>::make(processInfo,
        [this] (int32_t pid, uid_t uid) {
            onProcessTerminated(pid, uid);
        });
    mUidObserver->start();
}

ResourceManagerMetrics::~ResourceManagerMetrics() {
    mUidObserver->stop();
}

void ResourceManagerMetrics::addPid(int pid, uid_t uid) {
    if (uid != 0) {
        std::scoped_lock lock(mLock);
        mUidObserver->add(pid, uid);
    }
}

void ResourceManagerMetrics::notifyClientCreated(const ClientInfoParcel& clientInfo) {
    std::scoped_lock lock(mLock);
    // Update the resource instance count.
    std::map<std::string, int>::iterator found = mConcurrentResourceCountMap.find(clientInfo.name);
    if (found == mConcurrentResourceCountMap.end()) {
        mConcurrentResourceCountMap[clientInfo.name] = 1;
    } else {
        found->second++;
    }
}

void ResourceManagerMetrics::notifyClientReleased(const ClientInfoParcel& clientInfo) {
    bool stopCalled = true;
    ClientConfigParcel clientConfig;
    {
        std::scoped_lock lock(mLock);
        ClientConfigMap::iterator found = mClientConfigMap.find(clientInfo.id);
        if (found != mClientConfigMap.end()) {
            // Release is called without Stop!
            stopCalled = false;
            clientConfig = found->second;
            // Update the timestamp for stopping the codec.
            clientConfig.timeStamp = systemTime(SYSTEM_TIME_MONOTONIC) / 1000LL;
        }
    }
    if (!stopCalled) {
        // call Stop to update the metrics.
        notifyClientStopped(clientConfig);
    }
    {
        std::scoped_lock lock(mLock);
        // Update the resource instance count also.
        std::map<std::string, int>::iterator found =
            mConcurrentResourceCountMap.find(clientInfo.name);
        if (found != mConcurrentResourceCountMap.end()) {
            if (found->second > 0) {
                found->second--;
            }
        }
    }
}

void ResourceManagerMetrics::notifyClientConfigChanged(const ClientConfigParcel& clientConfig) {
    std::scoped_lock lock(mLock);
    ClientConfigMap::iterator entry = mClientConfigMap.find(clientConfig.clientInfo.id);
    if (entry != mClientConfigMap.end() &&
        (clientConfig.codecType == MediaResourceSubType::kVideoCodec ||
        clientConfig.codecType == MediaResourceSubType::kImageCodec)) {
        int pid = clientConfig.clientInfo.pid;
        // Update the pixel count for this process
        updatePixelCount(pid, clientConfig.width * (long)clientConfig.height,
                         entry->second.width * (long)entry->second.height);
        // Update the resolution in the record.
        entry->second.width = clientConfig.width;
        entry->second.height = clientConfig.height;
    }
}

void ResourceManagerMetrics::notifyClientStarted(const ClientConfigParcel& clientConfig) {
    std::scoped_lock lock(mLock);
    int pid = clientConfig.clientInfo.pid;
    // We need to observer this process.
    mUidObserver->add(pid, clientConfig.clientInfo.uid);

    // Update the client config for thic client.
    mClientConfigMap[clientConfig.clientInfo.id] = clientConfig;

    // Update the concurrent codec count for this process.
    CodecBucket codecBucket = getCodecBucket(clientConfig.isHardware,
                                             clientConfig.isEncoder,
                                             clientConfig.codecType);
    increaseConcurrentCodecs(pid, codecBucket);

    if (clientConfig.codecType == MediaResourceSubType::kVideoCodec ||
        clientConfig.codecType == MediaResourceSubType::kImageCodec) {
        // Update the pixel count for this process
        increasePixelCount(pid, clientConfig.width * (long)clientConfig.height);
    }

    // System concurrent codec usage
    int systemConcurrentCodecs = mConcurrentCodecsMap[codecBucket];
    // Process/Application concurrent codec usage for this type of codec
    const ConcurrentCodecs& concurrentCodecs = mProcessConcurrentCodecsMap[pid];
    int appConcurrentCodecs = concurrentCodecs.mCurrent[codecBucket];
    int hwVideoCodecs = concurrentCodecs.mHWVideoCodecs;
    int swVideoCodecs = concurrentCodecs.mSWVideoCodecs;
    int videoCodecs = concurrentCodecs.mVideoCodecs;
    int audioCodecs = concurrentCodecs.mAudioCodecs;
    int imageCodecs = concurrentCodecs.mImageCodecs;
    // Process/Application's current pixel count.
    long pixelCount = 0;
    std::map<int32_t, PixelCount>::iterator it = mProcessPixelsMap.find(pid);
    if (it != mProcessPixelsMap.end()) {
        pixelCount = it->second.mCurrent;
    }

    int result = stats_write(
         MEDIA_CODEC_STARTED,
         clientConfig.clientInfo.uid,
         clientConfig.id,
         clientConfig.clientInfo.name.c_str(),
         static_cast<int32_t>(clientConfig.codecType),
         clientConfig.isEncoder,
         clientConfig.isHardware,
         clientConfig.width, clientConfig.height,
         systemConcurrentCodecs,
         appConcurrentCodecs,
         pixelCount,
         hwVideoCodecs,
         swVideoCodecs,
         videoCodecs,
         audioCodecs,
         imageCodecs);

    ALOGV("%s: Pushed MEDIA_CODEC_STARTED atom: "
          "Process[pid(%d): uid(%d)] "
          "Codec: [%s: %ju] is %s %s %s "
          "Timestamp: %jd "
          "Resolution: %d x %d "
          "ConcurrentCodec[%d]={System: %d App: %d} "
          "AppConcurrentCodecs{Video: %d(HW[%d] SW[%d]) Audio: %d Image: %d} "
          "result: %d",
          __func__,
          pid, clientConfig.clientInfo.uid,
          clientConfig.clientInfo.name.c_str(),
          clientConfig.id,
          clientConfig.isHardware? "hardware" : "software",
          getCodecType(clientConfig.codecType),
          clientConfig.isEncoder? "encoder" : "decoder",
          clientConfig.timeStamp,
          clientConfig.width, clientConfig.height,
          codecBucket, systemConcurrentCodecs, appConcurrentCodecs,
          videoCodecs, hwVideoCodecs, swVideoCodecs, audioCodecs, imageCodecs,
          result);
}

void ResourceManagerMetrics::notifyClientStopped(const ClientConfigParcel& clientConfig) {
    std::scoped_lock lock(mLock);
    int pid = clientConfig.clientInfo.pid;
    // Update the concurrent codec count for this process.
    CodecBucket codecBucket = getCodecBucket(clientConfig.isHardware,
                                             clientConfig.isEncoder,
                                             clientConfig.codecType);
    decreaseConcurrentCodecs(pid, codecBucket);

    if (clientConfig.codecType == MediaResourceSubType::kVideoCodec ||
        clientConfig.codecType == MediaResourceSubType::kImageCodec) {
        // Update the pixel count for this process
        decreasePixelCount(pid, clientConfig.width * (long)clientConfig.height);
    }

    // System concurrent codec usage
    int systemConcurrentCodecs = mConcurrentCodecsMap[codecBucket];
    // Process/Application concurrent codec usage for this type of codec
    int appConcurrentCodecs = 0;
    std::map<int32_t, ConcurrentCodecs>::iterator found = mProcessConcurrentCodecsMap.find(pid);
    if (found != mProcessConcurrentCodecsMap.end()) {
        appConcurrentCodecs = found->second.mCurrent[codecBucket];
    }
    // Process/Application's current pixel count.
    long pixelCount = 0;
    std::map<int32_t, PixelCount>::iterator it = mProcessPixelsMap.find(pid);
    if (it != mProcessPixelsMap.end()) {
        pixelCount = it->second.mCurrent;
    }

    // calculate the usageTime as:
    //  MediaCodecStopped.clientConfig.timeStamp -
    //  MediaCodecStarted.clientConfig.timeStamp
    int64_t usageTime = 0;
    ClientConfigMap::iterator entry = mClientConfigMap.find(clientConfig.clientInfo.id);
    if (entry != mClientConfigMap.end()) {
        usageTime = clientConfig.timeStamp - entry->second.timeStamp;
        // And we can erase this config now.
        mClientConfigMap.erase(entry);
    } else {
        ALOGW("%s: Start Config is missing!", __func__);
    }

     int result = stats_write(
         MEDIA_CODEC_STOPPED,
         clientConfig.clientInfo.uid,
         clientConfig.id,
         clientConfig.clientInfo.name.c_str(),
         static_cast<int32_t>(clientConfig.codecType),
         clientConfig.isEncoder,
         clientConfig.isHardware,
         clientConfig.width, clientConfig.height,
         systemConcurrentCodecs,
         appConcurrentCodecs,
         pixelCount,
         usageTime);
    ALOGV("%s: Pushed MEDIA_CODEC_STOPPED atom: "
          "Process[pid(%d): uid(%d)] "
          "Codec: [%s: %ju] is %s %s %s "
          "Timestamp: %jd Usage time: %jd "
          "Resolution: %d x %d "
          "ConcurrentCodec[%d]={System: %d App: %d} "
          "result: %d",
          __func__,
          pid, clientConfig.clientInfo.uid,
          clientConfig.clientInfo.name.c_str(),
          clientConfig.id,
          clientConfig.isHardware? "hardware" : "software",
          getCodecType(clientConfig.codecType),
          clientConfig.isEncoder? "encoder" : "decoder",
          clientConfig.timeStamp, usageTime,
          clientConfig.width, clientConfig.height,
          codecBucket, systemConcurrentCodecs, appConcurrentCodecs,
          result);
}

void ResourceManagerMetrics::onProcessTerminated(int32_t pid, uid_t uid) {
    std::scoped_lock lock(mLock);
    // post MediaCodecConcurrentUsageReported for this terminated pid.
    pushConcurrentUsageReport(pid, uid);
}

void ResourceManagerMetrics::pushConcurrentUsageReport(int32_t pid, uid_t uid) {
    // Process/Application peak concurrent codec usage
    std::map<int32_t, ConcurrentCodecs>::iterator found = mProcessConcurrentCodecsMap.find(pid);
    if (found == mProcessConcurrentCodecsMap.end()) {
        ALOGI("%s: No MEDIA_CODEC_CONCURRENT_USAGE_REPORTED atom Entry for: "
              "Application[pid(%d): uid(%d)]", __func__, pid, uid);
        return;
    }
    const ConcurrentCodecsMap& codecsMap = found->second.mPeak;
    int peakHwAudioEncoderCount = codecsMap[HwAudioEncoder];
    int peakHwAudioDecoderCount = codecsMap[HwAudioDecoder];
    int peakHwVideoEncoderCount = codecsMap[HwVideoEncoder];
    int peakHwVideoDecoderCount = codecsMap[HwVideoDecoder];
    int peakHwImageEncoderCount = codecsMap[HwImageEncoder];
    int peakHwImageDecoderCount = codecsMap[HwImageDecoder];
    int peakSwAudioEncoderCount = codecsMap[SwAudioEncoder];
    int peakSwAudioDecoderCount = codecsMap[SwAudioDecoder];
    int peakSwVideoEncoderCount = codecsMap[SwVideoEncoder];
    int peakSwVideoDecoderCount = codecsMap[SwVideoDecoder];
    int peakSwImageEncoderCount = codecsMap[SwImageEncoder];
    int peakSwImageDecoderCount = codecsMap[SwImageDecoder];

    long peakPixels = 0;
    std::map<int32_t, PixelCount>::iterator it = mProcessPixelsMap.find(pid);
    if (it == mProcessPixelsMap.end()) {
        ALOGI("%s: No Video Codec Entry for Application[pid(%d): uid(%d)]",
              __func__, pid, uid);
    } else {
        peakPixels = it->second.mPeak;
    }
    std::string peakPixelsLog("Peak Pixels: " + std::to_string(peakPixels));

    std::stringstream peakCodecLog;
    peakCodecLog << "Peak { ";
    std::stringstream logMsg;
    if (getLogMessage(peakHwAudioEncoderCount, peakSwAudioEncoderCount, logMsg)) {
        peakCodecLog << "AudioEnc[" << logMsg.str();
    }
    if (getLogMessage(peakHwAudioDecoderCount, peakSwAudioDecoderCount, logMsg)) {
        peakCodecLog << "AudioDec[" << logMsg.str();
    }
    if (getLogMessage(peakHwVideoEncoderCount, peakSwVideoEncoderCount, logMsg)) {
        peakCodecLog << "VideoEnc[" << logMsg.str();
    }
    if (getLogMessage(peakHwVideoDecoderCount, peakSwVideoDecoderCount, logMsg)) {
        peakCodecLog << "VideoDec[" << logMsg.str();
    }
    if (getLogMessage(peakHwImageEncoderCount, peakSwImageEncoderCount, logMsg)) {
        peakCodecLog << "ImageEnc[" << logMsg.str();
    }
    if (getLogMessage(peakHwImageDecoderCount, peakSwImageDecoderCount, logMsg)) {
        peakCodecLog << "ImageDec[" << logMsg.str();
    }
    peakCodecLog << "}";

#ifdef ENABLE_MEDIA_CODEC_CONCURRENT_USAGE_REPORTED
    int result = stats_write(
        MEDIA_CODEC_CONCURRENT_USAGE_REPORTED,
        uid,
        peakHwVideoDecoderCount,
        peakHwVideoEncoderCount,
        peakSwVideoDecoderCount,
        peakSwVideoEncoderCount,
        peakHwAudioDecoderCount,
        peakHwAudioEncoderCount,
        peakSwAudioDecoderCount,
        peakSwAudioEncoderCount,
        peakHwImageDecoderCount,
        peakHwImageEncoderCount,
        peakSwImageDecoderCount,
        peakSwImageEncoderCount,
        peakPixels);
    ALOGI("%s: Pushed MEDIA_CODEC_CONCURRENT_USAGE_REPORTED atom: "
          "Process[pid(%d): uid(%d)] %s %s result: %d",
          __func__, pid, uid, peakCodecLog.str().c_str(), peakPixelsLog.c_str(), result);
#else
    ALOGI("%s: Concurrent Codec Usage Report for the Process[pid(%d): uid(%d)] is %s %s",
          __func__, pid, uid, peakCodecLog.str().c_str(), peakPixelsLog.c_str());
#endif
}

void ResourceManagerMetrics::pushReclaimAtom(const ClientInfoParcel& clientInfo,
                        const std::vector<int>& priorities,
                        const std::vector<std::shared_ptr<IResourceManagerClient>>& clients,
                        const PidUidVector& idList, bool reclaimed) {
    // Construct the metrics for codec reclaim as a pushed atom.
    // 1. Information about the requester.
    //  - UID and the priority (oom score)
    int32_t callingPid = clientInfo.pid;
    int32_t requesterUid = clientInfo.uid;
    std::string clientName = clientInfo.name;
    int requesterPriority = priorities[0];

    //  2. Information about the codec.
    //  - Name of the codec requested
    //  - Number of concurrent codecs running.
    int32_t noOfConcurrentCodecs = 0;
    std::map<std::string, int>::iterator found = mConcurrentResourceCountMap.find(clientName);
    if (found != mConcurrentResourceCountMap.end()) {
        noOfConcurrentCodecs = found->second;
    }

    // 3. Information about the Reclaim:
    // - Status of reclaim request
    // - How many codecs are reclaimed
    // - For each codecs reclaimed, information of the process that it belonged to:
    //    - UID and the Priority (oom score)
    int32_t reclaimStatus = MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED__RECLAIM_STATUS__RECLAIM_SUCCESS;
    if (!reclaimed) {
      if (clients.size() == 0) {
        // No clients to reclaim from
        reclaimStatus =
            MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED__RECLAIM_STATUS__RECLAIM_FAILED_NO_CLIENTS;
      } else {
        // Couldn't reclaim resources from the clients
        reclaimStatus =
            MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED__RECLAIM_STATUS__RECLAIM_FAILED_RECLAIM_RESOURCES;
      }
    }
    int32_t noOfCodecsReclaimed = clients.size();
    int32_t targetIndex = 1;
    for (PidUidVector::const_reference id : idList) {
        int32_t targetUid = id.second;
        int targetPriority = priorities[targetIndex];
        // Post the pushed atom
        int result = stats_write(
            MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED,
            requesterUid,
            requesterPriority,
            clientName.c_str(),
            noOfConcurrentCodecs,
            reclaimStatus,
            noOfCodecsReclaimed,
            targetIndex,
            targetUid,
            targetPriority);
        ALOGI("%s: Pushed MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED atom: "
              "Requester[pid(%d): uid(%d): priority(%d)] "
              "Codec: [%s] "
              "No of concurrent codecs: %d "
              "Reclaim Status: %d "
              "No of codecs reclaimed: %d "
              "Target[%d][pid(%d): uid(%d): priority(%d)] result: %d",
              __func__, callingPid, requesterUid, requesterPriority,
              clientName.c_str(), noOfConcurrentCodecs,
              reclaimStatus, noOfCodecsReclaimed,
              targetIndex, id.first, targetUid, targetPriority, result);
        targetIndex++;
    }
}

void ResourceManagerMetrics::increaseConcurrentCodecs(int32_t pid,
                                                      CodecBucket codecBucket) {
    // Increase the codec usage across the system.
    mConcurrentCodecsMap[codecBucket]++;

    // Now update the codec usage for this (pid) process.
    std::map<int32_t, ConcurrentCodecs>::iterator found = mProcessConcurrentCodecsMap.find(pid);
    if (found == mProcessConcurrentCodecsMap.end()) {
        ConcurrentCodecs codecs;
        codecs.mCurrent[codecBucket] = 1;
        codecs.mPeak[codecBucket] = 1;
        auto added = mProcessConcurrentCodecsMap.emplace(pid, codecs);
        found = added.first;
    } else {
        found->second.mCurrent[codecBucket]++;
        // Check if it's the peak count for this slot.
        if (found->second.mPeak[codecBucket] < found->second.mCurrent[codecBucket]) {
            found->second.mPeak[codecBucket] = found->second.mCurrent[codecBucket];
        }
    }

    switch (codecBucket) {
        case HwVideoEncoder:
        case HwVideoDecoder:
        case SwVideoEncoder:
        case SwVideoDecoder:
            if (codecBucket == HwVideoEncoder || codecBucket == HwVideoDecoder) {
                found->second.mHWVideoCodecs++;
            } else {
                found->second.mSWVideoCodecs++;
            }
            found->second.mVideoCodecs++;
            break;
        case HwAudioEncoder:
        case HwAudioDecoder:
        case SwAudioEncoder:
        case SwAudioDecoder:
            found->second.mAudioCodecs++;
            break;
        case HwImageEncoder:
        case HwImageDecoder:
        case SwImageEncoder:
        case SwImageDecoder:
            found->second.mImageCodecs++;
            break;
        default:
            break;
    }
}

void ResourceManagerMetrics::decreaseConcurrentCodecs(int32_t pid,
                                                      CodecBucket codecBucket) {
    // Decrease the codec usage across the system.
    if (mConcurrentCodecsMap[codecBucket] > 0) {
        mConcurrentCodecsMap[codecBucket]--;
    }

    // Now update the codec usage for this (pid) process.
    std::map<int32_t, ConcurrentCodecs>::iterator found = mProcessConcurrentCodecsMap.find(pid);
    if (found != mProcessConcurrentCodecsMap.end()) {
        if (found->second.mCurrent[codecBucket] > 0) {
            found->second.mCurrent[codecBucket]--;
        }

        switch (codecBucket) {
            case HwVideoEncoder:
            case HwVideoDecoder:
            case SwVideoEncoder:
            case SwVideoDecoder:
                if (codecBucket == HwVideoEncoder || codecBucket == HwVideoDecoder) {
                    found->second.mHWVideoCodecs--;
                } else {
                    found->second.mSWVideoCodecs--;
                }
                found->second.mVideoCodecs--;
                break;
            case HwAudioEncoder:
            case HwAudioDecoder:
            case SwAudioEncoder:
            case SwAudioDecoder:
                found->second.mAudioCodecs--;
                break;
            case HwImageEncoder:
            case HwImageDecoder:
            case SwImageEncoder:
            case SwImageDecoder:
                found->second.mImageCodecs--;
                break;
            default:
                break;
        }
    }
}

void ResourceManagerMetrics::increasePixelCount(int32_t pid, long pixels) {
    // Now update the current pixel usage for this (pid) process.
    std::map<int32_t, PixelCount>::iterator found = mProcessPixelsMap.find(pid);
    if (found == mProcessPixelsMap.end()) {
        PixelCount pixelCount {pixels, pixels};
        mProcessPixelsMap.emplace(pid, pixelCount);
    } else {
        if (__builtin_add_overflow(found->second.mCurrent, pixels, &found->second.mCurrent)) {
            ALOGI("Pixel Count overflow");
            return;
        }
        // Check if it's the peak count for this slot.
        if (found->second.mPeak < found->second.mCurrent) {
            found->second.mPeak = found->second.mCurrent;
        }
    }
}

void ResourceManagerMetrics::updatePixelCount(int32_t pid, long newPixels, long lastPixels) {
    // Since there is change in resolution, decrease it by last pixels and
    // increase it by new pixels.
    decreasePixelCount(pid, lastPixels);
    increasePixelCount(pid, newPixels);
}

void ResourceManagerMetrics::decreasePixelCount(int32_t pid, long pixels) {
    // Now update the current pixel usage for this (pid) process.
    std::map<int32_t, PixelCount>::iterator found = mProcessPixelsMap.find(pid);
    if (found != mProcessPixelsMap.end()) {
        if (found->second.mCurrent < pixels) {
            found->second.mCurrent = 0;
        } else {
            if (__builtin_sub_overflow(found->second.mCurrent, pixels, &found->second.mCurrent)) {
                ALOGI("Pixel Count overflow");
                return;
            }
        }
    }
}

long ResourceManagerMetrics::getPeakConcurrentPixelCount(int pid) const {
    std::map<int32_t, PixelCount>::const_iterator found = mProcessPixelsMap.find(pid);
    if (found != mProcessPixelsMap.end()) {
        return found->second.mPeak;
    }

    return 0;
}

long ResourceManagerMetrics::getCurrentConcurrentPixelCount(int pid) const {
    std::map<int32_t, PixelCount>::const_iterator found = mProcessPixelsMap.find(pid);
    if (found != mProcessPixelsMap.end()) {
        return found->second.mCurrent;
    }

    return 0;
}

} // namespace android
