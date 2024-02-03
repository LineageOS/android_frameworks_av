/*
 * Copyright 2012, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#include "hidl/HidlSupport.h"
#define LOG_TAG "MediaCodec"
#include <utils/Log.h>

#include <dlfcn.h>
#include <inttypes.h>
#include <future>
#include <random>
#include <set>
#include <string>

#include <C2Buffer.h>

#include "include/SoftwareRenderer.h"

#include <android/api-level.h>
#include <android/binder_manager.h>
#include <android/content/pm/IPackageManagerNative.h>
#include <android/hardware/cas/native/1.0/IDescrambler.h>
#include <android/hardware/media/omx/1.0/IGraphicBufferSource.h>

#include <aidl/android/media/BnResourceManagerClient.h>
#include <aidl/android/media/IResourceManagerService.h>
#include <android/binder_ibinder.h>
#include <android/binder_manager.h>
#include <android/dlext.h>
#include <android-base/stringprintf.h>
#include <binder/IMemory.h>
#include <binder/IServiceManager.h>
#include <binder/MemoryDealer.h>
#include <cutils/properties.h>
#include <gui/BufferQueue.h>
#include <gui/Surface.h>
#include <hidlmemory/FrameworkUtils.h>
#include <mediadrm/ICrypto.h>
#include <media/IOMX.h>
#include <media/MediaCodecBuffer.h>
#include <media/MediaCodecInfo.h>
#include <media/MediaMetricsItem.h>
#include <media/MediaResource.h>
#include <media/NdkMediaErrorPriv.h>
#include <media/NdkMediaFormat.h>
#include <media/NdkMediaFormatPriv.h>
#include <media/formatshaper/FormatShaper.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/AString.h>
#include <media/stagefright/foundation/AUtils.h>
#include <media/stagefright/foundation/avc_utils.h>
#include <media/stagefright/foundation/hexdump.h>
#include <media/stagefright/ACodec.h>
#include <media/stagefright/BatteryChecker.h>
#include <media/stagefright/BufferProducerWrapper.h>
#include <media/stagefright/CCodec.h>
#include <media/stagefright/CryptoAsync.h>
#include <media/stagefright/MediaCodec.h>
#include <media/stagefright/MediaCodecConstants.h>
#include <media/stagefright/MediaCodecList.h>
#include <media/stagefright/MediaCodecConstants.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/OMXClient.h>
#include <media/stagefright/PersistentSurface.h>
#include <media/stagefright/RenderedFrameInfo.h>
#include <media/stagefright/SurfaceUtils.h>
#include <nativeloader/dlext_namespaces.h>
#include <private/android_filesystem_config.h>
#include <server_configurable_flags/get_flags.h>
#include <utils/Singleton.h>

namespace android {

using Status = ::ndk::ScopedAStatus;
using aidl::android::media::BnResourceManagerClient;
using aidl::android::media::IResourceManagerClient;
using aidl::android::media::IResourceManagerService;
using aidl::android::media::ClientInfoParcel;
using server_configurable_flags::GetServerConfigurableFlag;
using FreezeEvent = VideoRenderQualityTracker::FreezeEvent;
using JudderEvent = VideoRenderQualityTracker::JudderEvent;

// key for media statistics
static const char *kCodecKeyName = "codec";
// attrs for media statistics
// NB: these are matched with public Java API constants defined
// in frameworks/base/media/java/android/media/MediaCodec.java
// These must be kept synchronized with the constants there.
static const char *kCodecLogSessionId = "android.media.mediacodec.log-session-id";
static const char *kCodecCodec = "android.media.mediacodec.codec";  /* e.g. OMX.google.aac.decoder */
static const char *kCodecId = "android.media.mediacodec.id";
static const char *kCodecMime = "android.media.mediacodec.mime";    /* e.g. audio/mime */
static const char *kCodecMode = "android.media.mediacodec.mode";    /* audio, video */
static const char *kCodecModeVideo = "video";            /* values returned for kCodecMode */
static const char *kCodecModeAudio = "audio";
static const char *kCodecModeImage = "image";
static const char *kCodecModeUnknown = "unknown";
static const char *kCodecEncoder = "android.media.mediacodec.encoder"; /* 0,1 */
static const char *kCodecHardware = "android.media.mediacodec.hardware"; /* 0,1 */
static const char *kCodecSecure = "android.media.mediacodec.secure";   /* 0, 1 */
static const char *kCodecTunneled = "android.media.mediacodec.tunneled"; /* 0,1 */
static const char *kCodecWidth = "android.media.mediacodec.width";     /* 0..n */
static const char *kCodecHeight = "android.media.mediacodec.height";   /* 0..n */
static const char *kCodecRotation = "android.media.mediacodec.rotation-degrees";  /* 0/90/180/270 */
static const char *kCodecColorFormat = "android.media.mediacodec.color-format";
static const char *kCodecFrameRate = "android.media.mediacodec.frame-rate";
static const char *kCodecCaptureRate = "android.media.mediacodec.capture-rate";
static const char *kCodecOperatingRate = "android.media.mediacodec.operating-rate";
static const char *kCodecPriority = "android.media.mediacodec.priority";

// Min/Max QP before shaping
static const char *kCodecOriginalVideoQPIMin = "android.media.mediacodec.original-video-qp-i-min";
static const char *kCodecOriginalVideoQPIMax = "android.media.mediacodec.original-video-qp-i-max";
static const char *kCodecOriginalVideoQPPMin = "android.media.mediacodec.original-video-qp-p-min";
static const char *kCodecOriginalVideoQPPMax = "android.media.mediacodec.original-video-qp-p-max";
static const char *kCodecOriginalVideoQPBMin = "android.media.mediacodec.original-video-qp-b-min";
static const char *kCodecOriginalVideoQPBMax = "android.media.mediacodec.original-video-qp-b-max";

// Min/Max QP after shaping
static const char *kCodecRequestedVideoQPIMin = "android.media.mediacodec.video-qp-i-min";
static const char *kCodecRequestedVideoQPIMax = "android.media.mediacodec.video-qp-i-max";
static const char *kCodecRequestedVideoQPPMin = "android.media.mediacodec.video-qp-p-min";
static const char *kCodecRequestedVideoQPPMax = "android.media.mediacodec.video-qp-p-max";
static const char *kCodecRequestedVideoQPBMin = "android.media.mediacodec.video-qp-b-min";
static const char *kCodecRequestedVideoQPBMax = "android.media.mediacodec.video-qp-b-max";

// NB: These are not yet exposed as public Java API constants.
static const char *kCodecCrypto = "android.media.mediacodec.crypto";   /* 0,1 */
static const char *kCodecProfile = "android.media.mediacodec.profile";  /* 0..n */
static const char *kCodecLevel = "android.media.mediacodec.level";  /* 0..n */
static const char *kCodecBitrateMode = "android.media.mediacodec.bitrate_mode";  /* CQ/VBR/CBR */
static const char *kCodecBitrate = "android.media.mediacodec.bitrate";  /* 0..n */
static const char *kCodecOriginalBitrate = "android.media.mediacodec.original.bitrate";  /* 0..n */
static const char *kCodecMaxWidth = "android.media.mediacodec.maxwidth";  /* 0..n */
static const char *kCodecMaxHeight = "android.media.mediacodec.maxheight";  /* 0..n */
static const char *kCodecError = "android.media.mediacodec.errcode";
static const char *kCodecLifetimeMs = "android.media.mediacodec.lifetimeMs";   /* 0..n ms*/
static const char *kCodecErrorState = "android.media.mediacodec.errstate";
static const char *kCodecLatencyMax = "android.media.mediacodec.latency.max";   /* in us */
static const char *kCodecLatencyMin = "android.media.mediacodec.latency.min";   /* in us */
static const char *kCodecLatencyAvg = "android.media.mediacodec.latency.avg";   /* in us */
static const char *kCodecLatencyCount = "android.media.mediacodec.latency.n";
static const char *kCodecLatencyHist = "android.media.mediacodec.latency.hist"; /* in us */
static const char *kCodecLatencyUnknown = "android.media.mediacodec.latency.unknown";
static const char *kCodecQueueSecureInputBufferError = "android.media.mediacodec.queueSecureInputBufferError";
static const char *kCodecQueueInputBufferError = "android.media.mediacodec.queueInputBufferError";
static const char *kCodecComponentColorFormat = "android.media.mediacodec.component-color-format";

static const char *kCodecNumLowLatencyModeOn = "android.media.mediacodec.low-latency.on";  /* 0..n */
static const char *kCodecNumLowLatencyModeOff = "android.media.mediacodec.low-latency.off";  /* 0..n */
static const char *kCodecFirstFrameIndexLowLatencyModeOn = "android.media.mediacodec.low-latency.first-frame";  /* 0..n */
static const char *kCodecChannelCount = "android.media.mediacodec.channelCount";
static const char *kCodecSampleRate = "android.media.mediacodec.sampleRate";
static const char *kCodecVideoEncodedBytes = "android.media.mediacodec.vencode.bytes";
static const char *kCodecVideoEncodedFrames = "android.media.mediacodec.vencode.frames";
static const char *kCodecVideoInputBytes = "android.media.mediacodec.video.input.bytes";
static const char *kCodecVideoInputFrames = "android.media.mediacodec.video.input.frames";
static const char *kCodecVideoEncodedDurationUs = "android.media.mediacodec.vencode.durationUs";
// HDR metrics
static const char *kCodecConfigColorStandard = "android.media.mediacodec.config-color-standard";
static const char *kCodecConfigColorRange = "android.media.mediacodec.config-color-range";
static const char *kCodecConfigColorTransfer = "android.media.mediacodec.config-color-transfer";
static const char *kCodecParsedColorStandard = "android.media.mediacodec.parsed-color-standard";
static const char *kCodecParsedColorRange = "android.media.mediacodec.parsed-color-range";
static const char *kCodecParsedColorTransfer = "android.media.mediacodec.parsed-color-transfer";
static const char *kCodecHdrStaticInfo = "android.media.mediacodec.hdr-static-info";
static const char *kCodecHdr10PlusInfo = "android.media.mediacodec.hdr10-plus-info";
static const char *kCodecHdrFormat = "android.media.mediacodec.hdr-format";
// array/sync/async/block modes
static const char *kCodecArrayMode = "android.media.mediacodec.array-mode";
static const char *kCodecOperationMode = "android.media.mediacodec.operation-mode";
static const char *kCodecOutputSurface = "android.media.mediacodec.output-surface";
// max size configured by the app
static const char *kCodecAppMaxInputSize = "android.media.mediacodec.app-max-input-size";
// max size actually used
static const char *kCodecUsedMaxInputSize = "android.media.mediacodec.used-max-input-size";
// max size suggested by the codec
static const char *kCodecCodecMaxInputSize = "android.media.mediacodec.codec-max-input-size";
static const char *kCodecFlushCount = "android.media.mediacodec.flush-count";
static const char *kCodecSetSurfaceCount = "android.media.mediacodec.set-surface-count";
static const char *kCodecResolutionChangeCount = "android.media.mediacodec.resolution-change-count";

// the kCodecRecent* fields appear only in getMetrics() results
static const char *kCodecRecentLatencyMax = "android.media.mediacodec.recent.max";      /* in us */
static const char *kCodecRecentLatencyMin = "android.media.mediacodec.recent.min";      /* in us */
static const char *kCodecRecentLatencyAvg = "android.media.mediacodec.recent.avg";      /* in us */
static const char *kCodecRecentLatencyCount = "android.media.mediacodec.recent.n";
static const char *kCodecRecentLatencyHist = "android.media.mediacodec.recent.hist";    /* in us */

/* -1: shaper disabled
   >=0: number of fields changed */
static const char *kCodecShapingEnhanced = "android.media.mediacodec.shaped";

// Render metrics
static const char *kCodecPlaybackDurationSec = "android.media.mediacodec.playback-duration-sec";
static const char *kCodecFirstRenderTimeUs = "android.media.mediacodec.first-render-time-us";
static const char *kCodecLastRenderTimeUs = "android.media.mediacodec.last-render-time-us";
static const char *kCodecFramesReleased = "android.media.mediacodec.frames-released";
static const char *kCodecFramesRendered = "android.media.mediacodec.frames-rendered";
static const char *kCodecFramesDropped = "android.media.mediacodec.frames-dropped";
static const char *kCodecFramesSkipped = "android.media.mediacodec.frames-skipped";
static const char *kCodecFramerateContent = "android.media.mediacodec.framerate-content";
static const char *kCodecFramerateDesired = "android.media.mediacodec.framerate-desired";
static const char *kCodecFramerateActual = "android.media.mediacodec.framerate-actual";
// Freeze
static const char *kCodecFreezeCount = "android.media.mediacodec.freeze-count";
static const char *kCodecFreezeScore = "android.media.mediacodec.freeze-score";
static const char *kCodecFreezeRate = "android.media.mediacodec.freeze-rate";
static const char *kCodecFreezeDurationMsAvg = "android.media.mediacodec.freeze-duration-ms-avg";
static const char *kCodecFreezeDurationMsMax = "android.media.mediacodec.freeze-duration-ms-max";
static const char *kCodecFreezeDurationMsHistogram =
        "android.media.mediacodec.freeze-duration-ms-histogram";
static const char *kCodecFreezeDurationMsHistogramBuckets =
        "android.media.mediacodec.freeze-duration-ms-histogram-buckets";
static const char *kCodecFreezeDistanceMsAvg = "android.media.mediacodec.freeze-distance-ms-avg";
static const char *kCodecFreezeDistanceMsHistogram =
        "android.media.mediacodec.freeze-distance-ms-histogram";
static const char *kCodecFreezeDistanceMsHistogramBuckets =
        "android.media.mediacodec.freeze-distance-ms-histogram-buckets";
// Judder
static const char *kCodecJudderCount = "android.media.mediacodec.judder-count";
static const char *kCodecJudderScore = "android.media.mediacodec.judder-score";
static const char *kCodecJudderRate = "android.media.mediacodec.judder-rate";
static const char *kCodecJudderScoreAvg = "android.media.mediacodec.judder-score-avg";
static const char *kCodecJudderScoreMax = "android.media.mediacodec.judder-score-max";
static const char *kCodecJudderScoreHistogram = "android.media.mediacodec.judder-score-histogram";
static const char *kCodecJudderScoreHistogramBuckets =
        "android.media.mediacodec.judder-score-histogram-buckets";
// Freeze event
static const char *kCodecFreezeEventCount = "android.media.mediacodec.freeze-event-count";
static const char *kFreezeEventKeyName = "videofreeze";
static const char *kFreezeEventInitialTimeUs = "android.media.mediacodec.freeze.initial-time-us";
static const char *kFreezeEventDurationMs = "android.media.mediacodec.freeze.duration-ms";
static const char *kFreezeEventCount = "android.media.mediacodec.freeze.count";
static const char *kFreezeEventAvgDurationMs = "android.media.mediacodec.freeze.avg-duration-ms";
static const char *kFreezeEventAvgDistanceMs = "android.media.mediacodec.freeze.avg-distance-ms";
static const char *kFreezeEventDetailsDurationMs =
        "android.media.mediacodec.freeze.details-duration-ms";
static const char *kFreezeEventDetailsDistanceMs =
        "android.media.mediacodec.freeze.details-distance-ms";
// Judder event
static const char *kCodecJudderEventCount = "android.media.mediacodec.judder-event-count";
static const char *kJudderEventKeyName = "videojudder";
static const char *kJudderEventInitialTimeUs = "android.media.mediacodec.judder.initial-time-us";
static const char *kJudderEventDurationMs = "android.media.mediacodec.judder.duration-ms";
static const char *kJudderEventCount = "android.media.mediacodec.judder.count";
static const char *kJudderEventAvgScore = "android.media.mediacodec.judder.avg-score";
static const char *kJudderEventAvgDistanceMs = "android.media.mediacodec.judder.avg-distance-ms";
static const char *kJudderEventDetailsActualDurationUs =
        "android.media.mediacodec.judder.details-actual-duration-us";
static const char *kJudderEventDetailsContentDurationUs =
        "android.media.mediacodec.judder.details-content-duration-us";
static const char *kJudderEventDetailsDistanceMs =
        "android.media.mediacodec.judder.details-distance-ms";

// XXX suppress until we get our representation right
static bool kEmitHistogram = false;

typedef WrapperObject<std::vector<AccessUnitInfo>> BufferInfosWrapper;

// Multi access unit helpers
static status_t generateFlagsFromAccessUnitInfo(
        sp<AMessage> &msg, const sp<BufferInfosWrapper> &bufferInfos) {
    msg->setInt64("timeUs", bufferInfos->value[0].mTimestamp);
    msg->setInt32("flags", bufferInfos->value[0].mFlags);
    // will prevent any access-unit info copy.
    if (bufferInfos->value.size() > 1) {
        uint32_t bufferFlags = 0;
        uint32_t flagsInAllAU = BUFFER_FLAG_DECODE_ONLY | BUFFER_FLAG_CODEC_CONFIG;
        uint32_t andFlags = flagsInAllAU;
        int infoIdx = 0;
        bool foundEndOfStream = false;
        for ( ; infoIdx < bufferInfos->value.size() && !foundEndOfStream; ++infoIdx) {
            bufferFlags |= bufferInfos->value[infoIdx].mFlags;
            andFlags &= bufferInfos->value[infoIdx].mFlags;
            if (bufferFlags & BUFFER_FLAG_END_OF_STREAM) {
                foundEndOfStream = true;
            }
        }
        bufferFlags = bufferFlags & (andFlags | (~flagsInAllAU));
        if (infoIdx != bufferInfos->value.size()) {
            ALOGE("Error: incorrect access-units");
            return -EINVAL;
        }
        msg->setInt32("flags", bufferFlags);
        msg->setObject("accessUnitInfo", bufferInfos);
    }
    return OK;
}

static int64_t getId(IResourceManagerClient const * client) {
    return (int64_t) client;
}

static int64_t getId(const std::shared_ptr<IResourceManagerClient> &client) {
    return getId(client.get());
}

static bool isResourceError(status_t err) {
    return (err == NO_MEMORY);
}

static bool areRenderMetricsEnabled() {
    std::string v = GetServerConfigurableFlag("media_native", "render_metrics_enabled", "false");
    return v == "true";
}

static const int kMaxRetry = 2;
static const int kMaxReclaimWaitTimeInUs = 500000;  // 0.5s
static const int kNumBuffersAlign = 16;

static const C2MemoryUsage kDefaultReadWriteUsage{
    C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE};

////////////////////////////////////////////////////////////////////////////////

/*
 * Implementation of IResourceManagerClient interrface that facilitates
 * MediaCodec reclaim for the ResourceManagerService.
 */
struct ResourceManagerClient : public BnResourceManagerClient {
    explicit ResourceManagerClient(MediaCodec* codec, int32_t pid, int32_t uid) :
            mMediaCodec(codec), mPid(pid), mUid(uid) {}

    Status reclaimResource(bool* _aidl_return) override {
        sp<MediaCodec> codec = mMediaCodec.promote();
        if (codec == NULL) {
            // Codec is already gone, so remove the resources as well
            ::ndk::SpAIBinder binder(AServiceManager_waitForService("media.resource_manager"));
            std::shared_ptr<IResourceManagerService> service =
                    IResourceManagerService::fromBinder(binder);
            if (service == nullptr) {
                ALOGE("MediaCodec::ResourceManagerClient unable to find ResourceManagerService");
                *_aidl_return = false;
                return Status::fromStatus(STATUS_INVALID_OPERATION);
            }
            ClientInfoParcel clientInfo{.pid = static_cast<int32_t>(mPid),
                                        .uid = static_cast<int32_t>(mUid),
                                        .id = getId(this)};
            service->removeClient(clientInfo);
            *_aidl_return = true;
            return Status::ok();
        }
        status_t err = codec->reclaim();
        if (err == WOULD_BLOCK) {
            ALOGD("Wait for the client to release codec.");
            usleep(kMaxReclaimWaitTimeInUs);
            ALOGD("Try to reclaim again.");
            err = codec->reclaim(true /* force */);
        }
        if (err != OK) {
            ALOGW("ResourceManagerClient failed to release codec with err %d", err);
        }
        *_aidl_return = (err == OK);
        return Status::ok();
    }

    Status getName(::std::string* _aidl_return) override {
        _aidl_return->clear();
        sp<MediaCodec> codec = mMediaCodec.promote();
        if (codec == NULL) {
            // codec is already gone.
            return Status::ok();
        }

        AString name;
        if (codec->getName(&name) == OK) {
            *_aidl_return = name.c_str();
        }
        return Status::ok();
    }

    virtual ~ResourceManagerClient() {}

private:
    wp<MediaCodec> mMediaCodec;
    int32_t mPid;
    int32_t mUid;

    DISALLOW_EVIL_CONSTRUCTORS(ResourceManagerClient);
};

/*
 * Proxy for ResourceManagerService that communicates with the
 * ResourceManagerService for MediaCodec
 */
struct MediaCodec::ResourceManagerServiceProxy :
    public std::enable_shared_from_this<ResourceManagerServiceProxy> {

    // BinderDiedContext defines the cookie that is passed as DeathRecipient.
    // Since this can maintain more context than a raw pointer, we can
    // validate the scope of ResourceManagerServiceProxy,
    // before deferencing it upon the binder death.
    struct BinderDiedContext {
        std::weak_ptr<ResourceManagerServiceProxy> mRMServiceProxy;
    };

    ResourceManagerServiceProxy(pid_t pid, uid_t uid,
            const std::shared_ptr<IResourceManagerClient> &client);
    ~ResourceManagerServiceProxy();
    status_t init();
    void addResource(const MediaResourceParcel &resource);
    void removeResource(const MediaResourceParcel &resource);
    void removeClient();
    void markClientForPendingRemoval();
    bool reclaimResource(const std::vector<MediaResourceParcel> &resources);
    void notifyClientCreated();
    void notifyClientStarted(ClientConfigParcel& clientConfig);
    void notifyClientStopped(ClientConfigParcel& clientConfig);
    void notifyClientConfigChanged(ClientConfigParcel& clientConfig);

    inline void setCodecName(const char* name) {
        mCodecName = name;
    }

    inline void setImportance(int importance) {
        mImportance = importance;
    }

private:
    // To get the binder interface to ResourceManagerService.
    void getService() {
        std::scoped_lock lock{mLock};
        getService_l();
    }

    std::shared_ptr<IResourceManagerService> getService_l();

    // To add/register all the resources currently added/registered with
    // the ResourceManagerService.
    // This function will be called right after the death of the Resource
    // Manager to make sure that the newly started ResourceManagerService
    // knows about the current resource usage.
    void reRegisterAllResources_l();

    void deinit() {
        std::scoped_lock lock{mLock};
        // Unregistering from DeathRecipient notification.
        if (mService != nullptr) {
            AIBinder_unlinkToDeath(mService->asBinder().get(), mDeathRecipient.get(), mCookie);
            mService = nullptr;
        }
    }

    // For binder death handling
    static void BinderDiedCallback(void* cookie);
    static void BinderUnlinkedCallback(void* cookie);

    void binderDied() {
        std::scoped_lock lock{mLock};
        ALOGE("ResourceManagerService died.");
        mService = nullptr;
        mBinderDied = true;
        // start an async operation that will reconnect with the RM and
        // re-registers all the resources.
        mGetServiceFuture = std::async(std::launch::async, [this] { getService(); });
    }

    /**
     * Get the ClientInfo to communicate with the ResourceManager.
     *
     * ClientInfo includes:
     *   - {pid, uid} of the process
     *   - identifier for the client
     *   - name of the client/codec
     *   - importance associated with the client
     */
    inline ClientInfoParcel getClientInfo() const {
        ClientInfoParcel clientInfo{.pid = static_cast<int32_t>(mPid),
                                    .uid = static_cast<int32_t>(mUid),
                                    .id = getId(mClient),
                                    .name = mCodecName,
                                    .importance = mImportance};
        return std::move(clientInfo);
    }

private:
    std::mutex  mLock;
    bool        mBinderDied = false;
    pid_t       mPid;
    uid_t       mUid;
    int         mImportance = 0;
    std::string mCodecName;
    /**
     * Reconnecting with the ResourceManagerService, after its binder interface dies,
     * is done asynchronously. It will also make sure that, all the resources
     * asssociated with this Proxy (MediaCodec) is added with the new instance
     * of the ResourceManagerService to persist the state of resources.
     * We must store the reference of the furture to guarantee real asynchronous operation.
     */
    std::future<void> mGetServiceFuture;
    // To maintain the list of all the resources currently added/registered with
    // the ResourceManagerService.
    std::set<MediaResourceParcel> mMediaResourceParcel;
    std::shared_ptr<IResourceManagerClient> mClient;
    ::ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;
    std::shared_ptr<IResourceManagerService> mService;
    BinderDiedContext* mCookie;
};

MediaCodec::ResourceManagerServiceProxy::ResourceManagerServiceProxy(
        pid_t pid, uid_t uid, const std::shared_ptr<IResourceManagerClient> &client) :
    mPid(pid), mUid(uid), mClient(client),
    mDeathRecipient(::ndk::ScopedAIBinder_DeathRecipient(
            AIBinder_DeathRecipient_new(BinderDiedCallback))),
    mCookie(nullptr) {
    if (mUid == MediaCodec::kNoUid) {
        mUid = AIBinder_getCallingUid();
    }
    if (mPid == MediaCodec::kNoPid) {
        mPid = AIBinder_getCallingPid();
    }
    // Setting callback notification when DeathRecipient gets deleted.
    AIBinder_DeathRecipient_setOnUnlinked(mDeathRecipient.get(), BinderUnlinkedCallback);
}

MediaCodec::ResourceManagerServiceProxy::~ResourceManagerServiceProxy() {
    deinit();
}

status_t MediaCodec::ResourceManagerServiceProxy::init() {
    std::scoped_lock lock{mLock};

    int callerPid = AIBinder_getCallingPid();
    int callerUid = AIBinder_getCallingUid();

    if (mPid != callerPid || mUid != callerUid) {
        // Media processes don't need special permissions to act on behalf of other processes.
        if (callerUid != AID_MEDIA) {
            char const * permission = "android.permission.MEDIA_RESOURCE_OVERRIDE_PID";
            if (!checkCallingPermission(String16(permission))) {
                ALOGW("%s is required to override the caller's PID for media resource management.",
                        permission);
                return PERMISSION_DENIED;
            }
        }
    }

    mService = getService_l();
    if (mService == nullptr) {
        return DEAD_OBJECT;
    }

    // Kill clients pending removal.
    mService->reclaimResourcesFromClientsPendingRemoval(mPid);
    return OK;
}

std::shared_ptr<IResourceManagerService> MediaCodec::ResourceManagerServiceProxy::getService_l() {
    if (mService != nullptr) {
        return mService;
    }

    // Get binder interface to resource manager.
    ::ndk::SpAIBinder binder(AServiceManager_waitForService("media.resource_manager"));
    mService = IResourceManagerService::fromBinder(binder);
    if (mService == nullptr) {
        ALOGE("Failed to get ResourceManagerService");
        return mService;
    }

    // Create the context that is passed as cookie to the binder death notification.
    // The context gets deleted at BinderUnlinkedCallback.
    mCookie = new BinderDiedContext{.mRMServiceProxy = weak_from_this()};
    // Register for the callbacks by linking to death notification.
    AIBinder_linkToDeath(mService->asBinder().get(), mDeathRecipient.get(), mCookie);

    // If the RM was restarted, re-register all the resources.
    if (mBinderDied) {
        reRegisterAllResources_l();
        mBinderDied = false;
    }
    return mService;
}

void MediaCodec::ResourceManagerServiceProxy::reRegisterAllResources_l() {
    if (mMediaResourceParcel.empty()) {
        ALOGV("No resources to add");
        return;
    }

    if (mService == nullptr) {
        ALOGW("Service isn't available");
        return;
    }

    std::vector<MediaResourceParcel> resources;
    std::copy(mMediaResourceParcel.begin(), mMediaResourceParcel.end(),
              std::back_inserter(resources));
    mService->addResource(getClientInfo(), mClient, resources);
}

void MediaCodec::ResourceManagerServiceProxy::BinderDiedCallback(void* cookie) {
    BinderDiedContext* context = reinterpret_cast<BinderDiedContext*>(cookie);

    // Validate the context and check if the ResourceManagerServiceProxy object is still in scope.
    if (context != nullptr) {
        std::shared_ptr<ResourceManagerServiceProxy> thiz = context->mRMServiceProxy.lock();
        if (thiz != nullptr) {
            thiz->binderDied();
        } else {
            ALOGI("ResourceManagerServiceProxy is out of scope already");
        }
    }
}

void MediaCodec::ResourceManagerServiceProxy::BinderUnlinkedCallback(void* cookie) {
    BinderDiedContext* context = reinterpret_cast<BinderDiedContext*>(cookie);
    // Since we don't need the context anymore, we are deleting it now.
    delete context;
}

void MediaCodec::ResourceManagerServiceProxy::addResource(
        const MediaResourceParcel &resource) {
    std::scoped_lock lock{mLock};
    std::shared_ptr<IResourceManagerService> service = getService_l();
    if (service == nullptr) {
        ALOGW("Service isn't available");
        return;
    }
    std::vector<MediaResourceParcel> resources;
    resources.push_back(resource);
    service->addResource(getClientInfo(), mClient, resources);
    mMediaResourceParcel.emplace(resource);
}

void MediaCodec::ResourceManagerServiceProxy::removeResource(
        const MediaResourceParcel &resource) {
    std::scoped_lock lock{mLock};
    std::shared_ptr<IResourceManagerService> service = getService_l();
    if (service == nullptr) {
        ALOGW("Service isn't available");
        return;
    }
    std::vector<MediaResourceParcel> resources;
    resources.push_back(resource);
    service->removeResource(getClientInfo(), resources);
    mMediaResourceParcel.erase(resource);
}

void MediaCodec::ResourceManagerServiceProxy::removeClient() {
    std::scoped_lock lock{mLock};
    std::shared_ptr<IResourceManagerService> service = getService_l();
    if (service == nullptr) {
        ALOGW("Service isn't available");
        return;
    }
    service->removeClient(getClientInfo());
    mMediaResourceParcel.clear();
}

void MediaCodec::ResourceManagerServiceProxy::markClientForPendingRemoval() {
    std::scoped_lock lock{mLock};
    std::shared_ptr<IResourceManagerService> service = getService_l();
    if (service == nullptr) {
        ALOGW("Service isn't available");
        return;
    }
    service->markClientForPendingRemoval(getClientInfo());
    mMediaResourceParcel.clear();
}

bool MediaCodec::ResourceManagerServiceProxy::reclaimResource(
        const std::vector<MediaResourceParcel> &resources) {
    std::scoped_lock lock{mLock};
    std::shared_ptr<IResourceManagerService> service = getService_l();
    if (service == nullptr) {
        ALOGW("Service isn't available");
        return false;
    }
    bool success;
    Status status = service->reclaimResource(getClientInfo(), resources, &success);
    return status.isOk() && success;
}

void MediaCodec::ResourceManagerServiceProxy::notifyClientCreated() {
    std::scoped_lock lock{mLock};
    std::shared_ptr<IResourceManagerService> service = getService_l();
    if (service == nullptr) {
        ALOGW("Service isn't available");
        return;
    }
    service->notifyClientCreated(getClientInfo());
}

void MediaCodec::ResourceManagerServiceProxy::notifyClientStarted(
        ClientConfigParcel& clientConfig) {
    std::scoped_lock lock{mLock};
    std::shared_ptr<IResourceManagerService> service = getService_l();
    if (service == nullptr) {
        ALOGW("Service isn't available");
        return;
    }
    clientConfig.clientInfo = getClientInfo();
    service->notifyClientStarted(clientConfig);
}

void MediaCodec::ResourceManagerServiceProxy::notifyClientStopped(
        ClientConfigParcel& clientConfig) {
    std::scoped_lock lock{mLock};
    std::shared_ptr<IResourceManagerService> service = getService_l();
    if (service == nullptr) {
        ALOGW("Service isn't available");
        return;
    }
    clientConfig.clientInfo = getClientInfo();
    service->notifyClientStopped(clientConfig);
}

void MediaCodec::ResourceManagerServiceProxy::notifyClientConfigChanged(
        ClientConfigParcel& clientConfig) {
    std::scoped_lock lock{mLock};
    std::shared_ptr<IResourceManagerService> service = getService_l();
    if (service == nullptr) {
        ALOGW("Service isn't available");
        return;
    }
    clientConfig.clientInfo = getClientInfo();
    service->notifyClientConfigChanged(clientConfig);
}

////////////////////////////////////////////////////////////////////////////////

MediaCodec::BufferInfo::BufferInfo() : mOwnedByClient(false) {}

////////////////////////////////////////////////////////////////////////////////

class MediaCodec::ReleaseSurface {
public:
    explicit ReleaseSurface(uint64_t usage) {
        BufferQueue::createBufferQueue(&mProducer, &mConsumer);
        mSurface = new Surface(mProducer, false /* controlledByApp */);
        struct ConsumerListener : public BnConsumerListener {
            ConsumerListener(const sp<IGraphicBufferConsumer> &consumer) {
                mConsumer = consumer;
            }
            void onFrameAvailable(const BufferItem&) override {
                BufferItem buffer;
                // consume buffer
                sp<IGraphicBufferConsumer> consumer = mConsumer.promote();
                if (consumer != nullptr && consumer->acquireBuffer(&buffer, 0) == NO_ERROR) {
                    consumer->releaseBuffer(buffer.mSlot, buffer.mFrameNumber,
                                            EGL_NO_DISPLAY, EGL_NO_SYNC_KHR, buffer.mFence);
                }
            }

            wp<IGraphicBufferConsumer> mConsumer;
            void onBuffersReleased() override {}
            void onSidebandStreamChanged() override {}
        };
        sp<ConsumerListener> listener{new ConsumerListener(mConsumer)};
        mConsumer->consumerConnect(listener, false);
        mConsumer->setConsumerName(String8{"MediaCodec.release"});
        mConsumer->setConsumerUsageBits(usage);
    }

    const sp<Surface> &getSurface() {
        return mSurface;
    }

private:
    sp<IGraphicBufferProducer> mProducer;
    sp<IGraphicBufferConsumer> mConsumer;
    sp<Surface> mSurface;
};

////////////////////////////////////////////////////////////////////////////////

namespace {

enum {
    kWhatFillThisBuffer      = 'fill',
    kWhatDrainThisBuffer     = 'drai',
    kWhatEOS                 = 'eos ',
    kWhatStartCompleted      = 'Scom',
    kWhatStopCompleted       = 'scom',
    kWhatReleaseCompleted    = 'rcom',
    kWhatFlushCompleted      = 'fcom',
    kWhatError               = 'erro',
    kWhatCryptoError         = 'ercp',
    kWhatComponentAllocated  = 'cAll',
    kWhatComponentConfigured = 'cCon',
    kWhatInputSurfaceCreated = 'isfc',
    kWhatInputSurfaceAccepted = 'isfa',
    kWhatSignaledInputEOS    = 'seos',
    kWhatOutputFramesRendered = 'outR',
    kWhatOutputBuffersChanged = 'outC',
    kWhatFirstTunnelFrameReady = 'ftfR',
    kWhatPollForRenderedBuffers = 'plrb',
    kWhatMetricsUpdated      = 'mtru',
};

class CryptoAsyncCallback : public CryptoAsync::CryptoAsyncCallback {
public:

    explicit CryptoAsyncCallback(const sp<AMessage> & notify):mNotify(notify) {
    }

    ~CryptoAsyncCallback() {}

    void onDecryptComplete(const sp<AMessage> &result) override {
        (void)result;
    }

    void onDecryptError(const std::list<sp<AMessage>> &errorMsgs) override {
        // This error may be decrypt/queue error.
        status_t errorCode ;
        for (auto &emsg : errorMsgs) {
             sp<AMessage> notify(mNotify->dup());
             if(emsg->findInt32("err", &errorCode)) {
                 if (isCryptoError(errorCode)) {
                     notify->setInt32("what", kWhatCryptoError);
                 } else {
                     notify->setInt32("what", kWhatError);
                 }
                 notify->extend(emsg);
                 notify->post();
             } else {
                 ALOGW("Buffers with no errorCode are not expected");
             }
        }
    }
private:
    const sp<AMessage> mNotify;
};

class OnBufferReleasedListener : public ::android::BnProducerListener{
private:
    uint32_t mGeneration;
    std::weak_ptr<BufferChannelBase> mBufferChannel;

    void notifyBufferReleased() {
        auto p = mBufferChannel.lock();
        if (p) {
            p->onBufferReleasedFromOutputSurface(mGeneration);
        }
    }

public:
    explicit OnBufferReleasedListener(
            uint32_t generation,
            const std::shared_ptr<BufferChannelBase> &bufferChannel)
            : mGeneration(generation), mBufferChannel(bufferChannel) {}

    virtual ~OnBufferReleasedListener() = default;

    void onBufferReleased() override {
        notifyBufferReleased();
    }

    void onBufferDetached([[maybe_unused]] int slot) override {
        notifyBufferReleased();
    }

    bool needsReleaseNotify() override { return true; }
};

class BufferCallback : public CodecBase::BufferCallback {
public:
    explicit BufferCallback(const sp<AMessage> &notify);
    virtual ~BufferCallback() = default;

    virtual void onInputBufferAvailable(
            size_t index, const sp<MediaCodecBuffer> &buffer) override;
    virtual void onOutputBufferAvailable(
            size_t index, const sp<MediaCodecBuffer> &buffer) override;
private:
    const sp<AMessage> mNotify;
};

BufferCallback::BufferCallback(const sp<AMessage> &notify)
    : mNotify(notify) {}

void BufferCallback::onInputBufferAvailable(
        size_t index, const sp<MediaCodecBuffer> &buffer) {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatFillThisBuffer);
    notify->setSize("index", index);
    notify->setObject("buffer", buffer);
    notify->post();
}

void BufferCallback::onOutputBufferAvailable(
        size_t index, const sp<MediaCodecBuffer> &buffer) {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatDrainThisBuffer);
    notify->setSize("index", index);
    notify->setObject("buffer", buffer);
    notify->post();
}

class CodecCallback : public CodecBase::CodecCallback {
public:
    explicit CodecCallback(const sp<AMessage> &notify);
    virtual ~CodecCallback() = default;

    virtual void onEos(status_t err) override;
    virtual void onStartCompleted() override;
    virtual void onStopCompleted() override;
    virtual void onReleaseCompleted() override;
    virtual void onFlushCompleted() override;
    virtual void onError(status_t err, enum ActionCode actionCode) override;
    virtual void onComponentAllocated(const char *componentName) override;
    virtual void onComponentConfigured(
            const sp<AMessage> &inputFormat, const sp<AMessage> &outputFormat) override;
    virtual void onInputSurfaceCreated(
            const sp<AMessage> &inputFormat,
            const sp<AMessage> &outputFormat,
            const sp<BufferProducerWrapper> &inputSurface) override;
    virtual void onInputSurfaceCreationFailed(status_t err) override;
    virtual void onInputSurfaceAccepted(
            const sp<AMessage> &inputFormat,
            const sp<AMessage> &outputFormat) override;
    virtual void onInputSurfaceDeclined(status_t err) override;
    virtual void onSignaledInputEOS(status_t err) override;
    virtual void onOutputFramesRendered(const std::list<RenderedFrameInfo> &done) override;
    virtual void onOutputBuffersChanged() override;
    virtual void onFirstTunnelFrameReady() override;
    virtual void onMetricsUpdated(const sp<AMessage> &updatedMetrics) override;
private:
    const sp<AMessage> mNotify;
};

CodecCallback::CodecCallback(const sp<AMessage> &notify) : mNotify(notify) {}

void CodecCallback::onEos(status_t err) {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatEOS);
    notify->setInt32("err", err);
    notify->post();
}

void CodecCallback::onStartCompleted() {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatStartCompleted);
    notify->post();
}

void CodecCallback::onStopCompleted() {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatStopCompleted);
    notify->post();
}

void CodecCallback::onReleaseCompleted() {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatReleaseCompleted);
    notify->post();
}

void CodecCallback::onFlushCompleted() {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatFlushCompleted);
    notify->post();
}

void CodecCallback::onError(status_t err, enum ActionCode actionCode) {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatError);
    notify->setInt32("err", err);
    notify->setInt32("actionCode", actionCode);
    notify->post();
}

void CodecCallback::onComponentAllocated(const char *componentName) {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatComponentAllocated);
    notify->setString("componentName", componentName);
    notify->post();
}

void CodecCallback::onComponentConfigured(
        const sp<AMessage> &inputFormat, const sp<AMessage> &outputFormat) {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatComponentConfigured);
    notify->setMessage("input-format", inputFormat);
    notify->setMessage("output-format", outputFormat);
    notify->post();
}

void CodecCallback::onInputSurfaceCreated(
        const sp<AMessage> &inputFormat,
        const sp<AMessage> &outputFormat,
        const sp<BufferProducerWrapper> &inputSurface) {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatInputSurfaceCreated);
    notify->setMessage("input-format", inputFormat);
    notify->setMessage("output-format", outputFormat);
    notify->setObject("input-surface", inputSurface);
    notify->post();
}

void CodecCallback::onInputSurfaceCreationFailed(status_t err) {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatInputSurfaceCreated);
    notify->setInt32("err", err);
    notify->post();
}

void CodecCallback::onInputSurfaceAccepted(
        const sp<AMessage> &inputFormat,
        const sp<AMessage> &outputFormat) {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatInputSurfaceAccepted);
    notify->setMessage("input-format", inputFormat);
    notify->setMessage("output-format", outputFormat);
    notify->post();
}

void CodecCallback::onInputSurfaceDeclined(status_t err) {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatInputSurfaceAccepted);
    notify->setInt32("err", err);
    notify->post();
}

void CodecCallback::onSignaledInputEOS(status_t err) {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatSignaledInputEOS);
    if (err != OK) {
        notify->setInt32("err", err);
    }
    notify->post();
}

void CodecCallback::onOutputFramesRendered(const std::list<RenderedFrameInfo> &done) {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatOutputFramesRendered);
    if (MediaCodec::CreateFramesRenderedMessage(done, notify)) {
        notify->post();
    }
}

void CodecCallback::onOutputBuffersChanged() {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatOutputBuffersChanged);
    notify->post();
}

void CodecCallback::onFirstTunnelFrameReady() {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatFirstTunnelFrameReady);
    notify->post();
}

void CodecCallback::onMetricsUpdated(const sp<AMessage> &updatedMetrics) {
    sp<AMessage> notify(mNotify->dup());
    notify->setInt32("what", kWhatMetricsUpdated);
    notify->setMessage("updated-metrics", updatedMetrics);
    notify->post();
}

static MediaResourceSubType toMediaResourceSubType(bool isHardware, MediaCodec::Domain domain) {
    switch (domain) {
    case MediaCodec::DOMAIN_VIDEO:
        return isHardware? MediaResourceSubType::kHwVideoCodec :
                           MediaResourceSubType::kSwVideoCodec;
    case MediaCodec::DOMAIN_AUDIO:
        return isHardware? MediaResourceSubType::kHwAudioCodec :
                           MediaResourceSubType::kSwAudioCodec;
    case MediaCodec::DOMAIN_IMAGE:
        return isHardware? MediaResourceSubType::kHwImageCodec :
                           MediaResourceSubType::kSwImageCodec;
    default:
        return MediaResourceSubType::kUnspecifiedSubType;
    }
}

static const char * toCodecMode(MediaCodec::Domain domain) {
    switch (domain) {
        case MediaCodec::DOMAIN_VIDEO: return kCodecModeVideo;
        case MediaCodec::DOMAIN_AUDIO: return kCodecModeAudio;
        case MediaCodec::DOMAIN_IMAGE: return kCodecModeImage;
        default:                       return kCodecModeUnknown;
    }
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

// static
sp<MediaCodec> MediaCodec::CreateByType(
        const sp<ALooper> &looper, const AString &mime, bool encoder, status_t *err, pid_t pid,
        uid_t uid) {
    sp<AMessage> format;
    return CreateByType(looper, mime, encoder, err, pid, uid, format);
}

sp<MediaCodec> MediaCodec::CreateByType(
        const sp<ALooper> &looper, const AString &mime, bool encoder, status_t *err, pid_t pid,
        uid_t uid, sp<AMessage> format) {
    Vector<AString> matchingCodecs;

    MediaCodecList::findMatchingCodecs(
            mime.c_str(),
            encoder,
            0,
            format,
            &matchingCodecs);

    if (err != NULL) {
        *err = NAME_NOT_FOUND;
    }
    for (size_t i = 0; i < matchingCodecs.size(); ++i) {
        sp<MediaCodec> codec = new MediaCodec(looper, pid, uid);
        AString componentName = matchingCodecs[i];
        status_t ret = codec->init(componentName);
        if (err != NULL) {
            *err = ret;
        }
        if (ret == OK) {
            return codec;
        }
        ALOGD("Allocating component '%s' failed (%d), try next one.",
                componentName.c_str(), ret);
    }
    return NULL;
}

// static
sp<MediaCodec> MediaCodec::CreateByComponentName(
        const sp<ALooper> &looper, const AString &name, status_t *err, pid_t pid, uid_t uid) {
    sp<MediaCodec> codec = new MediaCodec(looper, pid, uid);

    const status_t ret = codec->init(name);
    if (err != NULL) {
        *err = ret;
    }
    return ret == OK ? codec : NULL; // NULL deallocates codec.
}

// static
sp<PersistentSurface> MediaCodec::CreatePersistentInputSurface() {
    sp<PersistentSurface> pluginSurface = CCodec::CreateInputSurface();
    if (pluginSurface != nullptr) {
        return pluginSurface;
    }

    OMXClient client;
    if (client.connect() != OK) {
        ALOGE("Failed to connect to OMX to create persistent input surface.");
        return NULL;
    }

    sp<IOMX> omx = client.interface();

    sp<IGraphicBufferProducer> bufferProducer;
    sp<hardware::media::omx::V1_0::IGraphicBufferSource> bufferSource;

    status_t err = omx->createInputSurface(&bufferProducer, &bufferSource);

    if (err != OK) {
        ALOGE("Failed to create persistent input surface.");
        return NULL;
    }

    return new PersistentSurface(bufferProducer, bufferSource);
}

// GenerateCodecId generates a 64bit Random ID for each codec that is created.
// The Codec ID is generated as:
//   - A process-unique random high 32bits
//   - An atomic sequence low 32bits
//
static uint64_t GenerateCodecId() {
    static std::atomic_uint64_t sId = [] {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> distrib(0, UINT32_MAX);
        uint32_t randomID = distrib(gen);
        uint64_t id = randomID;
        return id << 32;
    }();
    return sId++;
}

MediaCodec::MediaCodec(
        const sp<ALooper> &looper, pid_t pid, uid_t uid,
        std::function<sp<CodecBase>(const AString &, const char *)> getCodecBase,
        std::function<status_t(const AString &, sp<MediaCodecInfo> *)> getCodecInfo)
    : mState(UNINITIALIZED),
      mReleasedByResourceManager(false),
      mLooper(looper),
      mCodec(NULL),
      mReplyID(0),
      mFlags(0),
      mStickyError(OK),
      mSoftRenderer(NULL),
      mDomain(DOMAIN_UNKNOWN),
      mWidth(0),
      mHeight(0),
      mRotationDegrees(0),
      mDequeueInputTimeoutGeneration(0),
      mDequeueInputReplyID(0),
      mDequeueOutputTimeoutGeneration(0),
      mDequeueOutputReplyID(0),
      mTunneledInputWidth(0),
      mTunneledInputHeight(0),
      mTunneled(false),
      mTunnelPeekState(TunnelPeekState::kLegacyMode),
      mTunnelPeekEnabled(false),
      mHaveInputSurface(false),
      mHavePendingInputBuffers(false),
      mCpuBoostRequested(false),
      mIsSurfaceToDisplay(false),
      mAreRenderMetricsEnabled(areRenderMetricsEnabled()),
      mVideoRenderQualityTracker(
              VideoRenderQualityTracker::Configuration::getFromServerConfigurableFlags(
                      GetServerConfigurableFlag)),
      mLatencyUnknown(0),
      mBytesEncoded(0),
      mEarliestEncodedPtsUs(INT64_MAX),
      mLatestEncodedPtsUs(INT64_MIN),
      mFramesEncoded(0),
      mNumLowLatencyEnables(0),
      mNumLowLatencyDisables(0),
      mIsLowLatencyModeOn(false),
      mIndexOfFirstFrameWhenLowLatencyOn(-1),
      mInputBufferCounter(0),
      mGetCodecBase(getCodecBase),
      mGetCodecInfo(getCodecInfo) {
    mCodecId = GenerateCodecId();
    mResourceManagerProxy = std::make_shared<ResourceManagerServiceProxy>(pid, uid,
            ::ndk::SharedRefBase::make<ResourceManagerClient>(this, pid, uid));
    if (!mGetCodecBase) {
        mGetCodecBase = [](const AString &name, const char *owner) {
            return GetCodecBase(name, owner);
        };
    }
    if (!mGetCodecInfo) {
        mGetCodecInfo = [&log = mErrorLog](const AString &name,
                                           sp<MediaCodecInfo> *info) -> status_t {
            *info = nullptr;
            const sp<IMediaCodecList> mcl = MediaCodecList::getInstance();
            if (!mcl) {
                log.log(LOG_TAG, "Fatal error: failed to initialize MediaCodecList");
                return NO_INIT;  // if called from Java should raise IOException
            }
            AString tmp = name;
            if (tmp.endsWith(".secure")) {
                tmp.erase(tmp.size() - 7, 7);
            }
            for (const AString &codecName : { name, tmp }) {
                ssize_t codecIdx = mcl->findCodecByName(codecName.c_str());
                if (codecIdx < 0) {
                    continue;
                }
                *info = mcl->getCodecInfo(codecIdx);
                return OK;
            }
            log.log(LOG_TAG, base::StringPrintf("Codec with name '%s' is not found on the device.",
                                  name.c_str()));
            return NAME_NOT_FOUND;
        };
    }

    // we want an empty metrics record for any early getMetrics() call
    // this should be the *only* initMediametrics() call that's not on the Looper thread
    initMediametrics();
}

MediaCodec::~MediaCodec() {
    CHECK_EQ(mState, UNINITIALIZED);
    mResourceManagerProxy->removeClient();

    flushMediametrics();

    // clean any saved metrics info we stored as part of configure()
    if (mConfigureMsg != nullptr) {
        mediametrics_handle_t metricsHandle;
        if (mConfigureMsg->findInt64("metrics", &metricsHandle)) {
            mediametrics_delete(metricsHandle);
        }
    }
}

// except for in constructor, called from the looper thread (and therefore mutexed)
void MediaCodec::initMediametrics() {
    if (mMetricsHandle == 0) {
        mMetricsHandle = mediametrics_create(kCodecKeyName);
    }

    mLatencyHist.setup(kLatencyHistBuckets, kLatencyHistWidth, kLatencyHistFloor);

    {
        Mutex::Autolock al(mRecentLock);
        for (int i = 0; i<kRecentLatencyFrames; i++) {
            mRecentSamples[i] = kRecentSampleInvalid;
        }
        mRecentHead = 0;
    }

    {
        Mutex::Autolock al(mLatencyLock);
        mBuffersInFlight.clear();
        mNumLowLatencyEnables = 0;
        mNumLowLatencyDisables = 0;
        mIsLowLatencyModeOn = false;
        mIndexOfFirstFrameWhenLowLatencyOn = -1;
        mInputBufferCounter = 0;
    }

    mLifetimeStartNs = systemTime(SYSTEM_TIME_MONOTONIC);
    resetMetricsFields();
}

void MediaCodec::resetMetricsFields() {
    mHdrInfoFlags = 0;

    mApiUsageMetrics = ApiUsageMetrics();
    mReliabilityContextMetrics = ReliabilityContextMetrics();
}

void MediaCodec::updateMediametrics() {
    if (mMetricsHandle == 0) {
        ALOGV("no metrics handle found");
        return;
    }

    Mutex::Autolock _lock(mMetricsLock);

    mediametrics_setInt32(mMetricsHandle, kCodecArrayMode, mApiUsageMetrics.isArrayMode ? 1 : 0);
    mApiUsageMetrics.operationMode = (mFlags & kFlagIsAsync) ?
            ((mFlags & kFlagUseBlockModel) ? ApiUsageMetrics::kBlockMode
                    : ApiUsageMetrics::kAsynchronousMode)
            : ApiUsageMetrics::kSynchronousMode;
    mediametrics_setInt32(mMetricsHandle, kCodecOperationMode, mApiUsageMetrics.operationMode);
    mediametrics_setInt32(mMetricsHandle, kCodecOutputSurface,
            mApiUsageMetrics.isUsingOutputSurface ? 1 : 0);

    mediametrics_setInt32(mMetricsHandle, kCodecAppMaxInputSize,
            mApiUsageMetrics.inputBufferSize.appMax);
    mediametrics_setInt32(mMetricsHandle, kCodecUsedMaxInputSize,
            mApiUsageMetrics.inputBufferSize.usedMax);
    mediametrics_setInt32(mMetricsHandle, kCodecCodecMaxInputSize,
            mApiUsageMetrics.inputBufferSize.codecMax);

    mediametrics_setInt32(mMetricsHandle, kCodecFlushCount, mReliabilityContextMetrics.flushCount);
    mediametrics_setInt32(mMetricsHandle, kCodecSetSurfaceCount,
            mReliabilityContextMetrics.setOutputSurfaceCount);
    mediametrics_setInt32(mMetricsHandle, kCodecResolutionChangeCount,
            mReliabilityContextMetrics.resolutionChangeCount);

    // Video rendering quality metrics
    {
        const VideoRenderQualityMetrics &m = mVideoRenderQualityTracker.getMetrics();
        if (m.frameReleasedCount > 0) {
            mediametrics_setInt64(mMetricsHandle, kCodecFirstRenderTimeUs, m.firstRenderTimeUs);
            mediametrics_setInt64(mMetricsHandle, kCodecLastRenderTimeUs, m.lastRenderTimeUs);
            mediametrics_setInt64(mMetricsHandle, kCodecFramesReleased, m.frameReleasedCount);
            mediametrics_setInt64(mMetricsHandle, kCodecFramesRendered, m.frameRenderedCount);
            mediametrics_setInt64(mMetricsHandle, kCodecFramesSkipped, m.frameSkippedCount);
            mediametrics_setInt64(mMetricsHandle, kCodecFramesDropped, m.frameDroppedCount);
            mediametrics_setDouble(mMetricsHandle, kCodecFramerateContent, m.contentFrameRate);
            mediametrics_setDouble(mMetricsHandle, kCodecFramerateDesired, m.desiredFrameRate);
            mediametrics_setDouble(mMetricsHandle, kCodecFramerateActual, m.actualFrameRate);
        }
        if (m.freezeDurationMsHistogram.getCount() >= 1) {
            const MediaHistogram<int32_t> &h = m.freezeDurationMsHistogram;
            mediametrics_setInt64(mMetricsHandle, kCodecFreezeScore, m.freezeScore);
            mediametrics_setDouble(mMetricsHandle, kCodecFreezeRate, m.freezeRate);
            mediametrics_setInt64(mMetricsHandle, kCodecFreezeCount, h.getCount());
            mediametrics_setInt32(mMetricsHandle, kCodecFreezeDurationMsAvg, h.getAvg());
            mediametrics_setInt32(mMetricsHandle, kCodecFreezeDurationMsMax, h.getMax());
            mediametrics_setString(mMetricsHandle, kCodecFreezeDurationMsHistogram, h.emit());
            mediametrics_setString(mMetricsHandle, kCodecFreezeDurationMsHistogramBuckets,
                                   h.emitBuckets());
        }
        if (m.freezeDistanceMsHistogram.getCount() >= 1) {
            const MediaHistogram<int32_t> &h = m.freezeDistanceMsHistogram;
            mediametrics_setInt32(mMetricsHandle, kCodecFreezeDistanceMsAvg, h.getAvg());
            mediametrics_setString(mMetricsHandle, kCodecFreezeDistanceMsHistogram, h.emit());
            mediametrics_setString(mMetricsHandle, kCodecFreezeDistanceMsHistogramBuckets,
                                   h.emitBuckets());
        }
        if (m.judderScoreHistogram.getCount() >= 1) {
            const MediaHistogram<int32_t> &h = m.judderScoreHistogram;
            mediametrics_setInt64(mMetricsHandle, kCodecJudderScore, m.judderScore);
            mediametrics_setDouble(mMetricsHandle, kCodecJudderRate, m.judderRate);
            mediametrics_setInt64(mMetricsHandle, kCodecJudderCount, h.getCount());
            mediametrics_setInt32(mMetricsHandle, kCodecJudderScoreAvg, h.getAvg());
            mediametrics_setInt32(mMetricsHandle, kCodecJudderScoreMax, h.getMax());
            mediametrics_setString(mMetricsHandle, kCodecJudderScoreHistogram, h.emit());
            mediametrics_setString(mMetricsHandle, kCodecJudderScoreHistogramBuckets,
                                   h.emitBuckets());
        }
        if (m.freezeEventCount != 0) {
            mediametrics_setInt32(mMetricsHandle, kCodecFreezeEventCount, m.freezeEventCount);
        }
        if (m.judderEventCount != 0) {
            mediametrics_setInt32(mMetricsHandle, kCodecJudderEventCount, m.judderEventCount);
        }
    }

    if (mLatencyHist.getCount() != 0 ) {
        mediametrics_setInt64(mMetricsHandle, kCodecLatencyMax, mLatencyHist.getMax());
        mediametrics_setInt64(mMetricsHandle, kCodecLatencyMin, mLatencyHist.getMin());
        mediametrics_setInt64(mMetricsHandle, kCodecLatencyAvg, mLatencyHist.getAvg());
        mediametrics_setInt64(mMetricsHandle, kCodecLatencyCount, mLatencyHist.getCount());

        if (kEmitHistogram) {
            // and the histogram itself
            std::string hist = mLatencyHist.emit();
            mediametrics_setCString(mMetricsHandle, kCodecLatencyHist, hist.c_str());
        }
    }
    if (mLatencyUnknown > 0) {
        mediametrics_setInt64(mMetricsHandle, kCodecLatencyUnknown, mLatencyUnknown);
    }
    int64_t playbackDurationSec = mPlaybackDurationAccumulator.getDurationInSeconds();
    if (playbackDurationSec > 0) {
        mediametrics_setInt64(mMetricsHandle, kCodecPlaybackDurationSec, playbackDurationSec);
    }
    if (mLifetimeStartNs > 0) {
        nsecs_t lifetime = systemTime(SYSTEM_TIME_MONOTONIC) - mLifetimeStartNs;
        lifetime = lifetime / (1000 * 1000);    // emitted in ms, truncated not rounded
        mediametrics_setInt64(mMetricsHandle, kCodecLifetimeMs, lifetime);
    }

    if (mBytesEncoded) {
        Mutex::Autolock al(mOutputStatsLock);

        mediametrics_setInt64(mMetricsHandle, kCodecVideoEncodedBytes, mBytesEncoded);
        int64_t duration = 0;
        if (mLatestEncodedPtsUs > mEarliestEncodedPtsUs) {
            duration = mLatestEncodedPtsUs - mEarliestEncodedPtsUs;
        }
        mediametrics_setInt64(mMetricsHandle, kCodecVideoEncodedDurationUs, duration);
        mediametrics_setInt64(mMetricsHandle, kCodecVideoEncodedFrames, mFramesEncoded);
        mediametrics_setInt64(mMetricsHandle, kCodecVideoInputFrames, mFramesInput);
        mediametrics_setInt64(mMetricsHandle, kCodecVideoInputBytes, mBytesInput);
    }

    {
        Mutex::Autolock al(mLatencyLock);
        mediametrics_setInt64(mMetricsHandle, kCodecNumLowLatencyModeOn, mNumLowLatencyEnables);
        mediametrics_setInt64(mMetricsHandle, kCodecNumLowLatencyModeOff, mNumLowLatencyDisables);
        mediametrics_setInt64(mMetricsHandle, kCodecFirstFrameIndexLowLatencyModeOn,
                              mIndexOfFirstFrameWhenLowLatencyOn);
    }

#if 0
    // enable for short term, only while debugging
    updateEphemeralMediametrics(mMetricsHandle);
#endif
}

void MediaCodec::updateHdrMetrics(bool isConfig) {
    if ((mDomain != DOMAIN_VIDEO && mDomain != DOMAIN_IMAGE) || mMetricsHandle == 0) {
        return;
    }

    int32_t colorStandard = -1;
    if (mOutputFormat->findInt32(KEY_COLOR_STANDARD, &colorStandard)) {
        mediametrics_setInt32(mMetricsHandle,
                isConfig ? kCodecConfigColorStandard : kCodecParsedColorStandard, colorStandard);
    }
    int32_t colorRange = -1;
    if (mOutputFormat->findInt32(KEY_COLOR_RANGE, &colorRange)) {
        mediametrics_setInt32(mMetricsHandle,
                isConfig ? kCodecConfigColorRange : kCodecParsedColorRange, colorRange);
    }
    int32_t colorTransfer = -1;
    if (mOutputFormat->findInt32(KEY_COLOR_TRANSFER, &colorTransfer)) {
        mediametrics_setInt32(mMetricsHandle,
                isConfig ? kCodecConfigColorTransfer : kCodecParsedColorTransfer, colorTransfer);
    }
    HDRStaticInfo info;
    if (ColorUtils::getHDRStaticInfoFromFormat(mOutputFormat, &info)
            && ColorUtils::isHDRStaticInfoValid(&info)) {
        mHdrInfoFlags |= kFlagHasHdrStaticInfo;
    }
    mediametrics_setInt32(mMetricsHandle, kCodecHdrStaticInfo,
            (mHdrInfoFlags & kFlagHasHdrStaticInfo) ? 1 : 0);
    sp<ABuffer> hdr10PlusInfo;
    if (mOutputFormat->findBuffer("hdr10-plus-info", &hdr10PlusInfo)
            && hdr10PlusInfo != nullptr && hdr10PlusInfo->size() > 0) {
        mHdrInfoFlags |= kFlagHasHdr10PlusInfo;
    }
    mediametrics_setInt32(mMetricsHandle, kCodecHdr10PlusInfo,
            (mHdrInfoFlags & kFlagHasHdr10PlusInfo) ? 1 : 0);

    // hdr format
    sp<AMessage> codedFormat = (mFlags & kFlagIsEncoder) ? mOutputFormat : mInputFormat;

    AString mime;
    int32_t profile = -1;

    if (codedFormat->findString("mime", &mime)
            && codedFormat->findInt32(KEY_PROFILE, &profile)
            && colorTransfer != -1) {
        hdr_format hdrFormat = getHdrFormat(mime, profile, colorTransfer);
        mediametrics_setInt32(mMetricsHandle, kCodecHdrFormat, static_cast<int>(hdrFormat));
    }
}

hdr_format MediaCodec::getHdrFormat(const AString &mime, const int32_t profile,
        const int32_t colorTransfer) {
    return (mFlags & kFlagIsEncoder)
            ? getHdrFormatForEncoder(mime, profile, colorTransfer)
            : getHdrFormatForDecoder(mime, profile, colorTransfer);
}

hdr_format MediaCodec::getHdrFormatForEncoder(const AString &mime, const int32_t profile,
        const int32_t colorTransfer) {
    switch (colorTransfer) {
        case COLOR_TRANSFER_ST2084:
            if (mime.equalsIgnoreCase(MEDIA_MIMETYPE_VIDEO_VP9)) {
                switch (profile) {
                    case VP9Profile2HDR:
                        return HDR_FORMAT_HDR10;
                    case VP9Profile2HDR10Plus:
                        return HDR_FORMAT_HDR10PLUS;
                    default:
                        return HDR_FORMAT_NONE;
                }
            } else if (mime.equalsIgnoreCase(MEDIA_MIMETYPE_VIDEO_AV1)) {
                switch (profile) {
                    case AV1ProfileMain10HDR10:
                        return HDR_FORMAT_HDR10;
                    case AV1ProfileMain10HDR10Plus:
                        return HDR_FORMAT_HDR10PLUS;
                    default:
                        return HDR_FORMAT_NONE;
                }
            } else if (mime.equalsIgnoreCase(MEDIA_MIMETYPE_VIDEO_HEVC)) {
                switch (profile) {
                    case HEVCProfileMain10HDR10:
                        return HDR_FORMAT_HDR10;
                    case HEVCProfileMain10HDR10Plus:
                        return HDR_FORMAT_HDR10PLUS;
                    default:
                        return HDR_FORMAT_NONE;
                }
            } else {
                return HDR_FORMAT_NONE;
            }
        case COLOR_TRANSFER_HLG:
            if (!mime.equalsIgnoreCase(MEDIA_MIMETYPE_VIDEO_DOLBY_VISION)) {
                return HDR_FORMAT_HLG;
            } else {
                // TODO: DOLBY format
                return HDR_FORMAT_NONE;
            }
        default:
            return HDR_FORMAT_NONE;
    }
}

hdr_format MediaCodec::getHdrFormatForDecoder(const AString &mime, const int32_t profile,
        const int32_t colorTransfer) {
    switch (colorTransfer) {
        case COLOR_TRANSFER_ST2084:
            if (!(mHdrInfoFlags & kFlagHasHdrStaticInfo) || !profileSupport10Bits(mime, profile)) {
                return HDR_FORMAT_NONE;
            }
            return mHdrInfoFlags & kFlagHasHdr10PlusInfo ? HDR_FORMAT_HDR10PLUS : HDR_FORMAT_HDR10;
        case COLOR_TRANSFER_HLG:
            if (!mime.equalsIgnoreCase(MEDIA_MIMETYPE_VIDEO_DOLBY_VISION)) {
                return HDR_FORMAT_HLG;
            }
            // TODO: DOLBY format
    }
    return HDR_FORMAT_NONE;
}

bool MediaCodec::profileSupport10Bits(const AString &mime, const int32_t profile) {
    if (mime.equalsIgnoreCase(MEDIA_MIMETYPE_VIDEO_AV1)) {
        return true;
    } else if (mime.equalsIgnoreCase(MEDIA_MIMETYPE_VIDEO_VP9)) {
        switch (profile) {
            case VP9Profile2:
            case VP9Profile3:
            case VP9Profile2HDR:
            case VP9Profile3HDR:
            case VP9Profile2HDR10Plus:
            case VP9Profile3HDR10Plus:
                return true;
        }
    } else if (mime.equalsIgnoreCase(MEDIA_MIMETYPE_VIDEO_HEVC)) {
        switch (profile) {
            case HEVCProfileMain10:
            case HEVCProfileMain10HDR10:
            case HEVCProfileMain10HDR10Plus:
                return true;
        }
    }
    return false;
}


// called to update info being passed back via getMetrics(), which is a
// unique copy for that call, no concurrent access worries.
void MediaCodec::updateEphemeralMediametrics(mediametrics_handle_t item) {
    ALOGD("MediaCodec::updateEphemeralMediametrics()");

    if (item == 0) {
        return;
    }

    // build an empty histogram
    MediaHistogram<int64_t> recentHist;
    recentHist.setup(kLatencyHistBuckets, kLatencyHistWidth, kLatencyHistFloor);

    // stuff it with the samples in the ring buffer
    {
        Mutex::Autolock al(mRecentLock);

        for (int i = 0; i < kRecentLatencyFrames; i++) {
            if (mRecentSamples[i] != kRecentSampleInvalid) {
                recentHist.insert(mRecentSamples[i]);
            }
        }
    }

    // spit the data (if any) into the supplied analytics record
    if (recentHist.getCount() != 0 ) {
        mediametrics_setInt64(item, kCodecRecentLatencyMax, recentHist.getMax());
        mediametrics_setInt64(item, kCodecRecentLatencyMin, recentHist.getMin());
        mediametrics_setInt64(item, kCodecRecentLatencyAvg, recentHist.getAvg());
        mediametrics_setInt64(item, kCodecRecentLatencyCount, recentHist.getCount());

        if (kEmitHistogram) {
            // and the histogram itself
            std::string hist = recentHist.emit();
            mediametrics_setCString(item, kCodecRecentLatencyHist, hist.c_str());
        }
    }
}

static std::string emitVector(std::vector<int32_t> vector) {
    std::ostringstream sstr;
    for (size_t i = 0; i < vector.size(); ++i) {
        if (i != 0) {
            sstr << ',';
        }
        sstr << vector[i];
    }
    return sstr.str();
}

static void reportToMediaMetricsIfValid(const FreezeEvent &e) {
    if (e.valid) {
        mediametrics_handle_t handle = mediametrics_create(kFreezeEventKeyName);
        mediametrics_setInt64(handle, kFreezeEventInitialTimeUs, e.initialTimeUs);
        mediametrics_setInt32(handle, kFreezeEventDurationMs, e.durationMs);
        mediametrics_setInt64(handle, kFreezeEventCount, e.count);
        mediametrics_setInt32(handle, kFreezeEventAvgDurationMs, e.sumDurationMs / e.count);
        mediametrics_setInt32(handle, kFreezeEventAvgDistanceMs, e.sumDistanceMs / e.count);
        mediametrics_setString(handle, kFreezeEventDetailsDurationMs,
                               emitVector(e.details.durationMs));
        mediametrics_setString(handle, kFreezeEventDetailsDistanceMs,
                               emitVector(e.details.distanceMs));
        mediametrics_selfRecord(handle);
        mediametrics_delete(handle);
    }
}

static void reportToMediaMetricsIfValid(const JudderEvent &e) {
    if (e.valid) {
        mediametrics_handle_t handle = mediametrics_create(kJudderEventKeyName);
        mediametrics_setInt64(handle, kJudderEventInitialTimeUs, e.initialTimeUs);
        mediametrics_setInt32(handle, kJudderEventDurationMs, e.durationMs);
        mediametrics_setInt64(handle, kJudderEventCount, e.count);
        mediametrics_setInt32(handle, kJudderEventAvgScore, e.sumScore / e.count);
        mediametrics_setInt32(handle, kJudderEventAvgDistanceMs, e.sumDistanceMs / e.count);
        mediametrics_setString(handle, kJudderEventDetailsActualDurationUs,
                               emitVector(e.details.actualRenderDurationUs));
        mediametrics_setString(handle, kJudderEventDetailsContentDurationUs,
                               emitVector(e.details.contentRenderDurationUs));
        mediametrics_setString(handle, kJudderEventDetailsDistanceMs,
                               emitVector(e.details.distanceMs));
        mediametrics_selfRecord(handle);
        mediametrics_delete(handle);
    }
}

void MediaCodec::flushMediametrics() {
    ALOGV("flushMediametrics");

    // update does its own mutex locking
    updateMediametrics();
    resetMetricsFields();

    // ensure mutex while we do our own work
    Mutex::Autolock _lock(mMetricsLock);
    if (mMetricsHandle != 0) {
        if (mMetricsToUpload && mediametrics_count(mMetricsHandle) > 0) {
            mediametrics_selfRecord(mMetricsHandle);
        }
        mediametrics_delete(mMetricsHandle);
        mMetricsHandle = 0;
    }
    // we no longer have anything pending upload
    mMetricsToUpload = false;

    // Freeze and judder events are reported separately
    reportToMediaMetricsIfValid(mVideoRenderQualityTracker.getAndResetFreezeEvent());
    reportToMediaMetricsIfValid(mVideoRenderQualityTracker.getAndResetJudderEvent());
}

void MediaCodec::updateLowLatency(const sp<AMessage> &msg) {
    int32_t lowLatency = 0;
    if (msg->findInt32("low-latency", &lowLatency)) {
        Mutex::Autolock al(mLatencyLock);
        if (lowLatency > 0) {
            ++mNumLowLatencyEnables;
            // This is just an estimate since low latency mode change happens ONLY at key frame
            mIsLowLatencyModeOn = true;
        } else if (lowLatency == 0) {
            ++mNumLowLatencyDisables;
            // This is just an estimate since low latency mode change happens ONLY at key frame
            mIsLowLatencyModeOn = false;
        }
    }
}

void MediaCodec::updateCodecImportance(const sp<AMessage>& msg) {
    // Update the codec importance.
    int32_t importance = 0;
    if (msg->findInt32(KEY_IMPORTANCE, &importance)) {
        // Ignoring the negative importance.
        if (importance >= 0) {
            // Notify RM about the change in the importance.
            mResourceManagerProxy->setImportance(importance);
            ClientConfigParcel clientConfig;
            initClientConfigParcel(clientConfig);
            mResourceManagerProxy->notifyClientConfigChanged(clientConfig);
        }
    }
}

constexpr const char *MediaCodec::asString(TunnelPeekState state, const char *default_string){
    switch(state) {
        case TunnelPeekState::kLegacyMode:
            return "LegacyMode";
        case TunnelPeekState::kEnabledNoBuffer:
            return "EnabledNoBuffer";
        case TunnelPeekState::kDisabledNoBuffer:
            return "DisabledNoBuffer";
        case TunnelPeekState::kBufferDecoded:
            return "BufferDecoded";
        case TunnelPeekState::kBufferRendered:
            return "BufferRendered";
        case TunnelPeekState::kDisabledQueued:
            return "DisabledQueued";
        case TunnelPeekState::kEnabledQueued:
            return "EnabledQueued";
        default:
            return default_string;
    }
}

void MediaCodec::updateTunnelPeek(const sp<AMessage> &msg) {
    int32_t tunnelPeek = 0;
    if (!msg->findInt32("tunnel-peek", &tunnelPeek)){
        return;
    }

    TunnelPeekState previousState = mTunnelPeekState;
    if(tunnelPeek == 0){
        mTunnelPeekEnabled = false;
        switch (mTunnelPeekState) {
            case TunnelPeekState::kLegacyMode:
                msg->setInt32("android._tunnel-peek-set-legacy", 0);
                [[fallthrough]];
            case TunnelPeekState::kEnabledNoBuffer:
                mTunnelPeekState = TunnelPeekState::kDisabledNoBuffer;
                break;
            case TunnelPeekState::kEnabledQueued:
                mTunnelPeekState = TunnelPeekState::kDisabledQueued;
                break;
            default:
                ALOGV("Ignoring tunnel-peek=%d for %s", tunnelPeek, asString(mTunnelPeekState));
                return;
        }
    } else {
        mTunnelPeekEnabled = true;
        switch (mTunnelPeekState) {
            case TunnelPeekState::kLegacyMode:
                msg->setInt32("android._tunnel-peek-set-legacy", 0);
                [[fallthrough]];
            case TunnelPeekState::kDisabledNoBuffer:
                mTunnelPeekState = TunnelPeekState::kEnabledNoBuffer;
                break;
            case TunnelPeekState::kDisabledQueued:
                mTunnelPeekState = TunnelPeekState::kEnabledQueued;
                break;
            case TunnelPeekState::kBufferDecoded:
                msg->setInt32("android._trigger-tunnel-peek", 1);
                mTunnelPeekState = TunnelPeekState::kBufferRendered;
                break;
            default:
                ALOGV("Ignoring tunnel-peek=%d for %s", tunnelPeek, asString(mTunnelPeekState));
                return;
        }
    }

    ALOGV("TunnelPeekState: %s -> %s", asString(previousState), asString(mTunnelPeekState));
}

void MediaCodec::processRenderedFrames(const sp<AMessage> &msg) {
    int what = 0;
    msg->findInt32("what", &what);
    if (msg->what() != kWhatCodecNotify && what != kWhatOutputFramesRendered) {
        static bool logged = false;
        if (!logged) {
            logged = true;
            ALOGE("processRenderedFrames: expected kWhatOutputFramesRendered (%d)", msg->what());
        }
        return;
    }
    // Rendered frames only matter if they're being sent to the display
    if (mIsSurfaceToDisplay) {
        int64_t renderTimeNs;
        for (size_t index = 0;
            msg->findInt64(AStringPrintf("%zu-system-nano", index).c_str(), &renderTimeNs);
            index++) {
            // Capture metrics for playback duration
            mPlaybackDurationAccumulator.onFrameRendered(renderTimeNs);
            // Capture metrics for quality
            int64_t mediaTimeUs = 0;
            if (!msg->findInt64(AStringPrintf("%zu-media-time-us", index).c_str(), &mediaTimeUs)) {
                ALOGE("processRenderedFrames: no media time found");
                continue;
            }
            // Tunneled frames use INT64_MAX to indicate end-of-stream, so don't report it as a
            // rendered frame.
            if (!mTunneled || mediaTimeUs != INT64_MAX) {
                FreezeEvent freezeEvent;
                JudderEvent judderEvent;
                mVideoRenderQualityTracker.onFrameRendered(mediaTimeUs, renderTimeNs, &freezeEvent,
                                                           &judderEvent);
                reportToMediaMetricsIfValid(freezeEvent);
                reportToMediaMetricsIfValid(judderEvent);
            }
        }
    }
}

// when we send a buffer to the codec;
void MediaCodec::statsBufferSent(int64_t presentationUs, const sp<MediaCodecBuffer> &buffer) {

    // only enqueue if we have a legitimate time
    if (presentationUs <= 0) {
        ALOGV("presentation time: %" PRId64, presentationUs);
        return;
    }

    if (mBatteryChecker != nullptr) {
        mBatteryChecker->onCodecActivity([this] () {
            mResourceManagerProxy->addResource(MediaResource::VideoBatteryResource(mIsHardware));
        });
    }

    if (mDomain == DOMAIN_VIDEO && (mFlags & kFlagIsEncoder)) {
        mBytesInput += buffer->size();
        mFramesInput++;
    }

    // mutex access to mBuffersInFlight and other stats
    Mutex::Autolock al(mLatencyLock);

    // XXX: we *could* make sure that the time is later than the end of queue
    // as part of a consistency check...
    if (!mTunneled) {
        const int64_t nowNs = systemTime(SYSTEM_TIME_MONOTONIC);
        BufferFlightTiming_t startdata = { presentationUs, nowNs };
        mBuffersInFlight.push_back(startdata);
    }

    if (mIsLowLatencyModeOn && mIndexOfFirstFrameWhenLowLatencyOn < 0) {
        mIndexOfFirstFrameWhenLowLatencyOn = mInputBufferCounter;
    }
    ++mInputBufferCounter;
}

// when we get a buffer back from the codec
void MediaCodec::statsBufferReceived(int64_t presentationUs, const sp<MediaCodecBuffer> &buffer) {

    CHECK_NE(mState, UNINITIALIZED);

    if (mDomain == DOMAIN_VIDEO && (mFlags & kFlagIsEncoder)) {
        int32_t flags = 0;
        (void) buffer->meta()->findInt32("flags", &flags);

        // some of these frames, we don't want to count
        // standalone EOS.... has an invalid timestamp
        if ((flags & (BUFFER_FLAG_CODECCONFIG|BUFFER_FLAG_EOS)) == 0) {
            mBytesEncoded += buffer->size();
            mFramesEncoded++;

            Mutex::Autolock al(mOutputStatsLock);
            int64_t timeUs = 0;
            if (buffer->meta()->findInt64("timeUs", &timeUs)) {
                if (timeUs > mLatestEncodedPtsUs) {
                    mLatestEncodedPtsUs = timeUs;
                }
                // can't chain as an else-if or this never triggers
                if (timeUs < mEarliestEncodedPtsUs) {
                    mEarliestEncodedPtsUs = timeUs;
                }
            }
        }
    }

    // mutex access to mBuffersInFlight and other stats
    Mutex::Autolock al(mLatencyLock);

    // how long this buffer took for the round trip through the codec
    // NB: pipelining can/will make these times larger. e.g., if each packet
    // is always 2 msec and we have 3 in flight at any given time, we're going to
    // see "6 msec" as an answer.

    // ignore stuff with no presentation time
    if (presentationUs <= 0) {
        ALOGV("-- returned buffer timestamp %" PRId64 " <= 0, ignore it", presentationUs);
        mLatencyUnknown++;
        return;
    }

    if (mBatteryChecker != nullptr) {
        mBatteryChecker->onCodecActivity([this] () {
            mResourceManagerProxy->addResource(MediaResource::VideoBatteryResource(mIsHardware));
        });
    }

    BufferFlightTiming_t startdata;
    bool valid = false;
    while (mBuffersInFlight.size() > 0) {
        startdata = *mBuffersInFlight.begin();
        ALOGV("-- Looking at startdata. presentation %" PRId64 ", start %" PRId64,
              startdata.presentationUs, startdata.startedNs);
        if (startdata.presentationUs == presentationUs) {
            // a match
            ALOGV("-- match entry for %" PRId64 ", hits our frame of %" PRId64,
                  startdata.presentationUs, presentationUs);
            mBuffersInFlight.pop_front();
            valid = true;
            break;
        } else if (startdata.presentationUs < presentationUs) {
            // we must have missed the match for this, drop it and keep looking
            ALOGV("--  drop entry for %" PRId64 ", before our frame of %" PRId64,
                  startdata.presentationUs, presentationUs);
            mBuffersInFlight.pop_front();
            continue;
        } else {
            // head is after, so we don't have a frame for ourselves
            ALOGV("--  found entry for %" PRId64 ", AFTER our frame of %" PRId64
                  " we have nothing to pair with",
                  startdata.presentationUs, presentationUs);
            mLatencyUnknown++;
            return;
        }
    }
    if (!valid) {
        ALOGV("-- empty queue, so ignore that.");
        mLatencyUnknown++;
        return;
    }

    // now start our calculations
    const int64_t nowNs = systemTime(SYSTEM_TIME_MONOTONIC);
    int64_t latencyUs = (nowNs - startdata.startedNs + 500) / 1000;

    mLatencyHist.insert(latencyUs);

    // push into the recent samples
    {
        Mutex::Autolock al(mRecentLock);

        if (mRecentHead >= kRecentLatencyFrames) {
            mRecentHead = 0;
        }
        mRecentSamples[mRecentHead++] = latencyUs;
    }
}

bool MediaCodec::discardDecodeOnlyOutputBuffer(size_t index) {
    Mutex::Autolock al(mBufferLock);
    BufferInfo *info = &mPortBuffers[kPortIndexOutput][index];
    sp<MediaCodecBuffer> buffer = info->mData;
    int32_t flags;
    CHECK(buffer->meta()->findInt32("flags", &flags));
    if (flags & BUFFER_FLAG_DECODE_ONLY) {
        info->mOwnedByClient = false;
        info->mData.clear();
        mBufferChannel->discardBuffer(buffer);
        return true;
    }
    return false;
}

// static
status_t MediaCodec::PostAndAwaitResponse(
        const sp<AMessage> &msg, sp<AMessage> *response) {
    status_t err = msg->postAndAwaitResponse(response);

    if (err != OK) {
        return err;
    }

    if (!(*response)->findInt32("err", &err)) {
        err = OK;
    }

    return err;
}

void MediaCodec::PostReplyWithError(const sp<AMessage> &msg, int32_t err) {
    sp<AReplyToken> replyID;
    CHECK(msg->senderAwaitsResponse(&replyID));
    PostReplyWithError(replyID, err);
}

void MediaCodec::PostReplyWithError(const sp<AReplyToken> &replyID, int32_t err) {
    int32_t finalErr = err;
    if (mReleasedByResourceManager) {
        // override the err code if MediaCodec has been released by ResourceManager.
        finalErr = DEAD_OBJECT;
    }

    sp<AMessage> response = new AMessage;
    response->setInt32("err", finalErr);
    response->postReply(replyID);
}

static CodecBase *CreateCCodec() {
    return new CCodec;
}

//static
sp<CodecBase> MediaCodec::GetCodecBase(const AString &name, const char *owner) {
    if (owner) {
        if (strcmp(owner, "default") == 0) {
            return new ACodec;
        } else if (strncmp(owner, "codec2", 6) == 0) {
            return CreateCCodec();
        }
    }

    if (name.startsWithIgnoreCase("c2.")) {
        return CreateCCodec();
    } else if (name.startsWithIgnoreCase("omx.")) {
        // at this time only ACodec specifies a mime type.
        return new ACodec;
    } else {
        return NULL;
    }
}

struct CodecListCache {
    CodecListCache()
        : mCodecInfoMap{[] {
              const sp<IMediaCodecList> mcl = MediaCodecList::getInstance();
              size_t count = mcl->countCodecs();
              std::map<std::string, sp<MediaCodecInfo>> codecInfoMap;
              for (size_t i = 0; i < count; ++i) {
                  sp<MediaCodecInfo> info = mcl->getCodecInfo(i);
                  codecInfoMap.emplace(info->getCodecName(), info);
              }
              return codecInfoMap;
          }()} {
    }

    const std::map<std::string, sp<MediaCodecInfo>> mCodecInfoMap;
};

static const CodecListCache &GetCodecListCache() {
    static CodecListCache sCache{};
    return sCache;
}

status_t MediaCodec::init(const AString &name) {
    status_t err = mResourceManagerProxy->init();
    if (err != OK) {
        mErrorLog.log(LOG_TAG, base::StringPrintf(
                "Fatal error: failed to initialize ResourceManager (err=%d)", err));
        mCodec = NULL; // remove the codec
        return err;
    }

    // save init parameters for reset
    mInitName = name;

    // Current video decoders do not return from OMX_FillThisBuffer
    // quickly, violating the OpenMAX specs, until that is remedied
    // we need to invest in an extra looper to free the main event
    // queue.

    mCodecInfo.clear();

    bool secureCodec = false;
    const char *owner = "";
    if (!name.startsWith("android.filter.")) {
        err = mGetCodecInfo(name, &mCodecInfo);
        if (err != OK) {
            mErrorLog.log(LOG_TAG, base::StringPrintf(
                    "Getting codec info with name '%s' failed (err=%d)", name.c_str(), err));
            mCodec = NULL;  // remove the codec.
            return err;
        }
        if (mCodecInfo == nullptr) {
            mErrorLog.log(LOG_TAG, base::StringPrintf(
                    "Getting codec info with name '%s' failed", name.c_str()));
            return NAME_NOT_FOUND;
        }
        secureCodec = name.endsWith(".secure");
        Vector<AString> mediaTypes;
        mCodecInfo->getSupportedMediaTypes(&mediaTypes);
        for (size_t i = 0; i < mediaTypes.size(); ++i) {
            if (mediaTypes[i].startsWith("video/")) {
                mDomain = DOMAIN_VIDEO;
                break;
            } else if (mediaTypes[i].startsWith("audio/")) {
                mDomain = DOMAIN_AUDIO;
                break;
            } else if (mediaTypes[i].startsWith("image/")) {
                mDomain = DOMAIN_IMAGE;
                break;
            }
        }
        owner = mCodecInfo->getOwnerName();
    }

    mCodec = mGetCodecBase(name, owner);
    if (mCodec == NULL) {
        mErrorLog.log(LOG_TAG, base::StringPrintf(
                "Getting codec base with name '%s' (from '%s' HAL) failed", name.c_str(), owner));
        return NAME_NOT_FOUND;
    }

    if (mDomain == DOMAIN_VIDEO) {
        // video codec needs dedicated looper
        if (mCodecLooper == NULL) {
            status_t err = OK;
            mCodecLooper = new ALooper;
            mCodecLooper->setName("CodecLooper");
            err = mCodecLooper->start(false, false, ANDROID_PRIORITY_AUDIO);
            if (OK != err) {
                mErrorLog.log(LOG_TAG, "Fatal error: codec looper failed to start");
                return err;
            }
        }

        mCodecLooper->registerHandler(mCodec);
    } else {
        mLooper->registerHandler(mCodec);
    }

    mLooper->registerHandler(this);

    mCodec->setCallback(
            std::unique_ptr<CodecBase::CodecCallback>(
                    new CodecCallback(new AMessage(kWhatCodecNotify, this))));
    mBufferChannel = mCodec->getBufferChannel();
    mBufferChannel->setCallback(
            std::unique_ptr<CodecBase::BufferCallback>(
                    new BufferCallback(new AMessage(kWhatCodecNotify, this))));
    sp<AMessage> msg = new AMessage(kWhatInit, this);
    if (mCodecInfo) {
        msg->setObject("codecInfo", mCodecInfo);
        // name may be different from mCodecInfo->getCodecName() if we stripped
        // ".secure"
    }
    msg->setString("name", name);

    // initial naming setup covers the period before the first call to ::configure().
    // after that, we manage this through ::configure() and the setup message.
    if (mMetricsHandle != 0) {
        mediametrics_setCString(mMetricsHandle, kCodecCodec, name.c_str());
        mediametrics_setCString(mMetricsHandle, kCodecMode, toCodecMode(mDomain));
    }

    if (mDomain == DOMAIN_VIDEO) {
        mBatteryChecker = new BatteryChecker(new AMessage(kWhatCheckBatteryStats, this));
    }

    // If the ComponentName is not set yet, use the name passed by the user.
    if (mComponentName.empty()) {
        mIsHardware = !MediaCodecList::isSoftwareCodec(name);
        mResourceManagerProxy->setCodecName(name.c_str());
    }

    std::vector<MediaResourceParcel> resources;
    resources.push_back(MediaResource::CodecResource(secureCodec,
                                                     toMediaResourceSubType(mIsHardware, mDomain)));

    for (int i = 0; i <= kMaxRetry; ++i) {
        if (i > 0) {
            // Don't try to reclaim resource for the first time.
            if (!mResourceManagerProxy->reclaimResource(resources)) {
                break;
            }
        }

        sp<AMessage> response;
        err = PostAndAwaitResponse(msg, &response);
        if (!isResourceError(err)) {
            break;
        }
    }

    if (OK == err) {
        // Notify the ResourceManager that, this codec has been created
        // (initialized) successfully.
        mResourceManagerProxy->notifyClientCreated();
    }
    return err;
}

status_t MediaCodec::setCallback(const sp<AMessage> &callback) {
    sp<AMessage> msg = new AMessage(kWhatSetCallback, this);
    msg->setMessage("callback", callback);

    sp<AMessage> response;
    return PostAndAwaitResponse(msg, &response);
}

status_t MediaCodec::setOnFrameRenderedNotification(const sp<AMessage> &notify) {
    sp<AMessage> msg = new AMessage(kWhatSetNotification, this);
    msg->setMessage("on-frame-rendered", notify);
    return msg->post();
}

status_t MediaCodec::setOnFirstTunnelFrameReadyNotification(const sp<AMessage> &notify) {
    sp<AMessage> msg = new AMessage(kWhatSetNotification, this);
    msg->setMessage("first-tunnel-frame-ready", notify);
    return msg->post();
}

/*
 * MediaFormat Shaping forward declarations
 * including the property name we use for control.
 */
static int enableMediaFormatShapingDefault = 1;
static const char enableMediaFormatShapingProperty[] = "debug.stagefright.enableshaping";
static void mapFormat(AString componentName, const sp<AMessage> &format, const char *kind,
                      bool reverse);

mediametrics_handle_t MediaCodec::createMediaMetrics(const sp<AMessage>& format,
                                                     uint32_t flags,
                                                     status_t* err) {
    *err = OK;
    mediametrics_handle_t nextMetricsHandle = mediametrics_create(kCodecKeyName);
    bool isEncoder = (flags & CONFIGURE_FLAG_ENCODE);

    // TODO: validity check log-session-id: it should be a 32-hex-digit.
    format->findString("log-session-id", &mLogSessionId);

    if (nextMetricsHandle != 0) {
        mediametrics_setInt64(nextMetricsHandle, kCodecId, mCodecId);
        int32_t profile = 0;
        if (format->findInt32("profile", &profile)) {
            mediametrics_setInt32(nextMetricsHandle, kCodecProfile, profile);
        }
        int32_t level = 0;
        if (format->findInt32("level", &level)) {
            mediametrics_setInt32(nextMetricsHandle, kCodecLevel, level);
        }
        mediametrics_setInt32(nextMetricsHandle, kCodecEncoder, isEncoder);

        if (!mLogSessionId.empty()) {
            mediametrics_setCString(nextMetricsHandle, kCodecLogSessionId, mLogSessionId.c_str());
        }

        // moved here from ::init()
        mediametrics_setCString(nextMetricsHandle, kCodecCodec, mInitName.c_str());
        mediametrics_setCString(nextMetricsHandle, kCodecMode, toCodecMode(mDomain));
    }

    if (mDomain == DOMAIN_VIDEO || mDomain == DOMAIN_IMAGE) {
        format->findInt32("width", &mWidth);
        format->findInt32("height", &mHeight);
        if (!format->findInt32("rotation-degrees", &mRotationDegrees)) {
            mRotationDegrees = 0;
        }
        if (nextMetricsHandle != 0) {
            mediametrics_setInt32(nextMetricsHandle, kCodecWidth, mWidth);
            mediametrics_setInt32(nextMetricsHandle, kCodecHeight, mHeight);
            mediametrics_setInt32(nextMetricsHandle, kCodecRotation, mRotationDegrees);
            int32_t maxWidth = 0;
            if (format->findInt32("max-width", &maxWidth)) {
                mediametrics_setInt32(nextMetricsHandle, kCodecMaxWidth, maxWidth);
            }
            int32_t maxHeight = 0;
            if (format->findInt32("max-height", &maxHeight)) {
                mediametrics_setInt32(nextMetricsHandle, kCodecMaxHeight, maxHeight);
            }
            int32_t colorFormat = -1;
            if (format->findInt32("color-format", &colorFormat)) {
                mediametrics_setInt32(nextMetricsHandle, kCodecColorFormat, colorFormat);
            }
            int32_t appMaxInputSize = -1;
            if (format->findInt32(KEY_MAX_INPUT_SIZE, &appMaxInputSize)) {
                mApiUsageMetrics.inputBufferSize.appMax = appMaxInputSize;
            }
            if (mDomain == DOMAIN_VIDEO) {
                float frameRate = -1.0;
                if (format->findFloat("frame-rate", &frameRate)) {
                    mediametrics_setDouble(nextMetricsHandle, kCodecFrameRate, frameRate);
                }
                float captureRate = -1.0;
                if (format->findFloat("capture-rate", &captureRate)) {
                    mediametrics_setDouble(nextMetricsHandle, kCodecCaptureRate, captureRate);
                }
                float operatingRate = -1.0;
                if (format->findFloat("operating-rate", &operatingRate)) {
                    mediametrics_setDouble(nextMetricsHandle, kCodecOperatingRate, operatingRate);
                }
                int32_t priority = -1;
                if (format->findInt32("priority", &priority)) {
                    mediametrics_setInt32(nextMetricsHandle, kCodecPriority, priority);
                }
            }
        }

        // Prevent possible integer overflow in downstream code.
        if (mWidth < 0 || mHeight < 0 ||
               (uint64_t)mWidth * mHeight > (uint64_t)INT32_MAX / 4) {
            mErrorLog.log(LOG_TAG, base::StringPrintf(
                    "Invalid size(s), width=%d, height=%d", mWidth, mHeight));
            mediametrics_delete(nextMetricsHandle);
            // Set the error code and return null handle.
            *err = BAD_VALUE;
            return 0;
        }

    } else {
        if (nextMetricsHandle != 0) {
            int32_t channelCount;
            if (format->findInt32(KEY_CHANNEL_COUNT, &channelCount)) {
                mediametrics_setInt32(nextMetricsHandle, kCodecChannelCount, channelCount);
            }
            int32_t sampleRate;
            if (format->findInt32(KEY_SAMPLE_RATE, &sampleRate)) {
                mediametrics_setInt32(nextMetricsHandle, kCodecSampleRate, sampleRate);
            }
        }
    }

    if (isEncoder) {
        int8_t enableShaping = property_get_bool(enableMediaFormatShapingProperty,
                                                 enableMediaFormatShapingDefault);
        if (!enableShaping) {
            ALOGI("format shaping disabled, property '%s'", enableMediaFormatShapingProperty);
            if (nextMetricsHandle != 0) {
                mediametrics_setInt32(nextMetricsHandle, kCodecShapingEnhanced, -1);
            }
        } else {
            (void) shapeMediaFormat(format, flags, nextMetricsHandle);
            // XXX: do we want to do this regardless of shaping enablement?
            mapFormat(mComponentName, format, nullptr, false);
        }
    }

    // push min/max QP to MediaMetrics after shaping
    if (mDomain == DOMAIN_VIDEO && nextMetricsHandle != 0) {
        int32_t qpIMin = -1;
        if (format->findInt32("video-qp-i-min", &qpIMin)) {
            mediametrics_setInt32(nextMetricsHandle, kCodecRequestedVideoQPIMin, qpIMin);
        }
        int32_t qpIMax = -1;
        if (format->findInt32("video-qp-i-max", &qpIMax)) {
            mediametrics_setInt32(nextMetricsHandle, kCodecRequestedVideoQPIMax, qpIMax);
        }
        int32_t qpPMin = -1;
        if (format->findInt32("video-qp-p-min", &qpPMin)) {
            mediametrics_setInt32(nextMetricsHandle, kCodecRequestedVideoQPPMin, qpPMin);
        }
        int32_t qpPMax = -1;
        if (format->findInt32("video-qp-p-max", &qpPMax)) {
            mediametrics_setInt32(nextMetricsHandle, kCodecRequestedVideoQPPMax, qpPMax);
        }
        int32_t qpBMin = -1;
        if (format->findInt32("video-qp-b-min", &qpBMin)) {
            mediametrics_setInt32(nextMetricsHandle, kCodecRequestedVideoQPBMin, qpBMin);
        }
        int32_t qpBMax = -1;
        if (format->findInt32("video-qp-b-max", &qpBMax)) {
            mediametrics_setInt32(nextMetricsHandle, kCodecRequestedVideoQPBMax, qpBMax);
        }
    }

    updateLowLatency(format);

    return nextMetricsHandle;
}

status_t MediaCodec::configure(
        const sp<AMessage> &format,
        const sp<Surface> &nativeWindow,
        const sp<ICrypto> &crypto,
        uint32_t flags) {
    return configure(format, nativeWindow, crypto, NULL, flags);
}

status_t MediaCodec::configure(
        const sp<AMessage> &format,
        const sp<Surface> &surface,
        const sp<ICrypto> &crypto,
        const sp<IDescrambler> &descrambler,
        uint32_t flags) {

    // Update the codec importance.
    updateCodecImportance(format);

    // Create and set up metrics for this codec.
    status_t err = OK;
    mediametrics_handle_t nextMetricsHandle = createMediaMetrics(format, flags, &err);
    if (err != OK) {
        return err;
    }

    sp<AMessage> msg = new AMessage(kWhatConfigure, this);
    msg->setMessage("format", format);
    msg->setInt32("flags", flags);
    msg->setObject("surface", surface);

    if (crypto != NULL || descrambler != NULL) {
        if (crypto != NULL) {
            msg->setPointer("crypto", crypto.get());
        } else {
            msg->setPointer("descrambler", descrambler.get());
        }
        if (nextMetricsHandle != 0) {
            mediametrics_setInt32(nextMetricsHandle, kCodecCrypto, 1);
        }
    } else if (mFlags & kFlagIsSecure) {
        ALOGW("Crypto or descrambler should be given for secure codec");
    }

    if (mConfigureMsg != nullptr) {
        // if re-configuring, we have one of these from before.
        // Recover the space before we discard the old mConfigureMsg
        mediametrics_handle_t metricsHandle;
        if (mConfigureMsg->findInt64("metrics", &metricsHandle)) {
            mediametrics_delete(metricsHandle);
        }
    }
    msg->setInt64("metrics", nextMetricsHandle);

    // save msg for reset
    mConfigureMsg = msg;

    sp<AMessage> callback = mCallback;

    std::vector<MediaResourceParcel> resources;
    resources.push_back(MediaResource::CodecResource(mFlags & kFlagIsSecure,
            toMediaResourceSubType(mIsHardware, mDomain)));
    if (mDomain == DOMAIN_VIDEO || mDomain == DOMAIN_IMAGE) {
        // Don't know the buffer size at this point, but it's fine to use 1 because
        // the reclaimResource call doesn't consider the requester's buffer size for now.
        resources.push_back(MediaResource::GraphicMemoryResource(1));
    }
    for (int i = 0; i <= kMaxRetry; ++i) {
        sp<AMessage> response;
        err = PostAndAwaitResponse(msg, &response);
        if (err != OK && err != INVALID_OPERATION) {
            if (isResourceError(err) && !mResourceManagerProxy->reclaimResource(resources)) {
                break;
            }
            // MediaCodec now set state to UNINITIALIZED upon any fatal error.
            // To maintain backward-compatibility, do a reset() to put codec
            // back into INITIALIZED state.
            // But don't reset if the err is INVALID_OPERATION, which means
            // the configure failure is due to wrong state.

            ALOGE("configure failed with err 0x%08x, resetting...", err);
            status_t err2 = reset();
            if (err2 != OK) {
                ALOGE("retrying configure: failed to reset codec (%08x)", err2);
                break;
            }
            if (callback != nullptr) {
                err2 = setCallback(callback);
                if (err2 != OK) {
                    ALOGE("retrying configure: failed to set callback (%08x)", err2);
                    break;
                }
            }
        }
        if (!isResourceError(err)) {
            break;
        }
    }

    return err;
}

// Media Format Shaping support
//

static android::mediaformatshaper::FormatShaperOps_t *sShaperOps = NULL;
static bool sIsHandheld = true;

static bool connectFormatShaper() {
    static std::once_flag sCheckOnce;

    ALOGV("connectFormatShaper...");

    std::call_once(sCheckOnce, [&](){

        void *libHandle = NULL;
        nsecs_t loading_started = systemTime(SYSTEM_TIME_MONOTONIC);

        // prefer any copy in the mainline module
        //
        android_namespace_t *mediaNs = android_get_exported_namespace("com_android_media");
        AString libraryName = "libmediaformatshaper.so";

        if (mediaNs != NULL) {
            static const android_dlextinfo dlextinfo = {
                .flags = ANDROID_DLEXT_USE_NAMESPACE,
                .library_namespace = mediaNs,
            };

            AString libraryMainline = "/apex/com.android.media/";
#if __LP64__
            libraryMainline.append("lib64/");
#else
            libraryMainline.append("lib/");
#endif
            libraryMainline.append(libraryName);

            libHandle = android_dlopen_ext(libraryMainline.c_str(), RTLD_NOW|RTLD_NODELETE,
                                                 &dlextinfo);

            if (libHandle != NULL) {
                sShaperOps = (android::mediaformatshaper::FormatShaperOps_t*)
                                dlsym(libHandle, "shaper_ops");
            } else {
                ALOGW("connectFormatShaper: unable to load mainline formatshaper %s",
                      libraryMainline.c_str());
            }
        } else {
            ALOGV("connectFormatShaper: couldn't find media namespace.");
        }

        // fall back to the system partition, if present.
        //
        if (sShaperOps == NULL) {

            libHandle = dlopen(libraryName.c_str(), RTLD_NOW|RTLD_NODELETE);

            if (libHandle != NULL) {
                sShaperOps = (android::mediaformatshaper::FormatShaperOps_t*)
                                dlsym(libHandle, "shaper_ops");
            } else {
                ALOGW("connectFormatShaper: unable to load formatshaper %s", libraryName.c_str());
            }
        }

        if (sShaperOps != nullptr
            && sShaperOps->version != android::mediaformatshaper::SHAPER_VERSION_V1) {
            ALOGW("connectFormatShaper: unhandled version ShaperOps: %d, DISABLED",
                  sShaperOps->version);
            sShaperOps = nullptr;
        }

        if (sShaperOps != nullptr) {
            ALOGV("connectFormatShaper: connected to library %s", libraryName.c_str());
        }

        nsecs_t loading_finished = systemTime(SYSTEM_TIME_MONOTONIC);
        ALOGV("connectFormatShaper: loaded libraries: %" PRId64 " us",
              (loading_finished - loading_started)/1000);


        // we also want to know whether this is a handheld device
        // start with assumption that the device is handheld.
        sIsHandheld = true;
        sp<IServiceManager> serviceMgr = defaultServiceManager();
        sp<content::pm::IPackageManagerNative> packageMgr;
        if (serviceMgr.get() != nullptr) {
            sp<IBinder> binder = serviceMgr->waitForService(String16("package_native"));
            packageMgr = interface_cast<content::pm::IPackageManagerNative>(binder);
        }
        // if we didn't get serviceMgr, we'll leave packageMgr as default null
        if (packageMgr != nullptr) {

            // MUST have these
            static const String16 featuresNeeded[] = {
                String16("android.hardware.touchscreen")
            };
            // these must be present to be a handheld
            for (::android::String16 required : featuresNeeded) {
                bool hasFeature = false;
                binder::Status status = packageMgr->hasSystemFeature(required, 0, &hasFeature);
                if (!status.isOk()) {
                    ALOGE("%s: hasSystemFeature failed: %s",
                        __func__, status.exceptionMessage().c_str());
                    continue;
                }
                ALOGV("feature %s says %d", String8(required).c_str(), hasFeature);
                if (!hasFeature) {
                    ALOGV("... which means we are not handheld");
                    sIsHandheld = false;
                    break;
                }
            }

            // MUST NOT have these
            static const String16 featuresDisallowed[] = {
                String16("android.hardware.type.automotive"),
                String16("android.hardware.type.television"),
                String16("android.hardware.type.watch")
            };
            // any of these present -- we aren't a handheld
            for (::android::String16 forbidden : featuresDisallowed) {
                bool hasFeature = false;
                binder::Status status = packageMgr->hasSystemFeature(forbidden, 0, &hasFeature);
                if (!status.isOk()) {
                    ALOGE("%s: hasSystemFeature failed: %s",
                        __func__, status.exceptionMessage().c_str());
                    continue;
                }
                ALOGV("feature %s says %d", String8(forbidden).c_str(), hasFeature);
                if (hasFeature) {
                    ALOGV("... which means we are not handheld");
                    sIsHandheld = false;
                    break;
                }
            }
        }

    });

    return true;
}


#if 0
// a construct to force the above dlopen() to run very early.
// goal: so the dlopen() doesn't happen on critical path of latency sensitive apps
// failure of this means that cold start of those apps is slower by the time to dlopen()
// TODO(b/183454066): tradeoffs between memory of early loading vs latency of late loading
//
static bool forceEarlyLoadingShaper = connectFormatShaper();
#endif

// parse the codec's properties: mapping, whether it meets min quality, etc
// and pass them into the video quality code
//
static void loadCodecProperties(mediaformatshaper::shaperHandle_t shaperHandle,
                                  sp<MediaCodecInfo> codecInfo, AString mediaType) {

    sp<MediaCodecInfo::Capabilities> capabilities =
                    codecInfo->getCapabilitiesFor(mediaType.c_str());
    if (capabilities == nullptr) {
        ALOGI("no capabilities as part of the codec?");
    } else {
        const sp<AMessage> &details = capabilities->getDetails();
        AString mapTarget;
        int count = details->countEntries();
        for(int ix = 0; ix < count; ix++) {
            AMessage::Type entryType;
            const char *mapSrc = details->getEntryNameAt(ix, &entryType);
            // XXX: re-use ix from getEntryAt() to avoid additional findXXX() invocation
            //
            static const char *featurePrefix = "feature-";
            static const int featurePrefixLen = strlen(featurePrefix);
            static const char *tuningPrefix = "tuning-";
            static const int tuningPrefixLen = strlen(tuningPrefix);
            static const char *mappingPrefix = "mapping-";
            static const int mappingPrefixLen = strlen(mappingPrefix);

            if (mapSrc == NULL) {
                continue;
            } else if (!strncmp(mapSrc, featurePrefix, featurePrefixLen)) {
                int32_t intValue;
                if (details->findInt32(mapSrc, &intValue)) {
                    ALOGV("-- feature '%s' -> %d", mapSrc, intValue);
                    (void)(sShaperOps->setFeature)(shaperHandle, &mapSrc[featurePrefixLen],
                                                   intValue);
                }
                continue;
            } else if (!strncmp(mapSrc, tuningPrefix, tuningPrefixLen)) {
                AString value;
                if (details->findString(mapSrc, &value)) {
                    ALOGV("-- tuning '%s' -> '%s'", mapSrc, value.c_str());
                    (void)(sShaperOps->setTuning)(shaperHandle, &mapSrc[tuningPrefixLen],
                                                   value.c_str());
                }
                continue;
            } else if (!strncmp(mapSrc, mappingPrefix, mappingPrefixLen)) {
                AString target;
                if (details->findString(mapSrc, &target)) {
                    ALOGV("-- mapping %s: map %s to %s", mapSrc, &mapSrc[mappingPrefixLen],
                          target.c_str());
                    // key is really "kind-key"
                    // separate that, so setMap() sees the triple  kind, key, value
                    const char *kind = &mapSrc[mappingPrefixLen];
                    const char *sep = strchr(kind, '-');
                    const char *key = sep+1;
                    if (sep != NULL) {
                         std::string xkind = std::string(kind, sep-kind);
                        (void)(sShaperOps->setMap)(shaperHandle, xkind.c_str(),
                                                   key, target.c_str());
                    }
                }
            }
        }
    }

    // we also carry in the codec description whether we are on a handheld device.
    // this info is eventually used by both the Codec and the C2 machinery to inform
    // the underlying codec whether to do any shaping.
    //
    if (sIsHandheld) {
        // set if we are indeed a handheld device (or in future 'any eligible device'
        // missing on devices that aren't eligible for minimum quality enforcement.
        (void)(sShaperOps->setFeature)(shaperHandle, "_vq_eligible.device", 1);
        // strictly speaking, it's a tuning, but those are strings and feature stores int
        (void)(sShaperOps->setFeature)(shaperHandle, "_quality.target", 1 /* S_HANDHELD */);
    }
}

status_t MediaCodec::setupFormatShaper(AString mediaType) {
    ALOGV("setupFormatShaper: initializing shaper data for codec %s mediaType %s",
          mComponentName.c_str(), mediaType.c_str());

    nsecs_t mapping_started = systemTime(SYSTEM_TIME_MONOTONIC);

    // someone might have beaten us to it.
    mediaformatshaper::shaperHandle_t shaperHandle;
    shaperHandle = sShaperOps->findShaper(mComponentName.c_str(), mediaType.c_str());
    if (shaperHandle != nullptr) {
        ALOGV("shaperhandle %p -- no initialization needed", shaperHandle);
        return OK;
    }

    // we get to build & register one
    shaperHandle = sShaperOps->createShaper(mComponentName.c_str(), mediaType.c_str());
    if (shaperHandle == nullptr) {
        ALOGW("unable to create a shaper for cocodec %s mediaType %s",
              mComponentName.c_str(), mediaType.c_str());
        return OK;
    }

    (void) loadCodecProperties(shaperHandle, mCodecInfo, mediaType);

    shaperHandle = sShaperOps->registerShaper(shaperHandle,
                                              mComponentName.c_str(), mediaType.c_str());

    nsecs_t mapping_finished = systemTime(SYSTEM_TIME_MONOTONIC);
    ALOGV("setupFormatShaper: populated shaper node for codec %s: %" PRId64 " us",
          mComponentName.c_str(), (mapping_finished - mapping_started)/1000);

    return OK;
}


// Format Shaping
//      Mapping and Manipulation of encoding parameters
//
//      All of these decisions are pushed into the shaper instead of here within MediaCodec.
//      this includes decisions based on whether the codec implements minimum quality bars
//      itself or needs to be shaped outside of the codec.
//      This keeps all those decisions in one place.
//      It also means that we push some extra decision information (is this a handheld device
//      or one that is otherwise eligible for minimum quality manipulation, which generational
//      quality target is in force, etc).  This allows those values to be cached in the
//      per-codec structures that are done 1 time within a process instead of for each
//      codec instantiation.
//

status_t MediaCodec::shapeMediaFormat(
            const sp<AMessage> &format,
            uint32_t flags,
            mediametrics_handle_t metricsHandle) {
    ALOGV("shapeMediaFormat entry");

    if (!(flags & CONFIGURE_FLAG_ENCODE)) {
        ALOGW("shapeMediaFormat: not encoder");
        return OK;
    }
    if (mCodecInfo == NULL) {
        ALOGW("shapeMediaFormat: no codecinfo");
        return OK;
    }

    AString mediaType;
    if (!format->findString("mime", &mediaType)) {
        ALOGW("shapeMediaFormat: no mediaType information");
        return OK;
    }

    // make sure we have the function entry points for the shaper library
    //

    connectFormatShaper();
    if (sShaperOps == nullptr) {
        ALOGW("shapeMediaFormat: no MediaFormatShaper hooks available");
        return OK;
    }

    // find the shaper information for this codec+mediaType pair
    //
    mediaformatshaper::shaperHandle_t shaperHandle;
    shaperHandle = sShaperOps->findShaper(mComponentName.c_str(), mediaType.c_str());
    if (shaperHandle == nullptr)  {
        setupFormatShaper(mediaType);
        shaperHandle = sShaperOps->findShaper(mComponentName.c_str(), mediaType.c_str());
    }
    if (shaperHandle == nullptr) {
        ALOGW("shapeMediaFormat: no handler for codec %s mediatype %s",
              mComponentName.c_str(), mediaType.c_str());
        return OK;
    }

    // run the shaper
    //

    ALOGV("Shaping input: %s", format->debugString(0).c_str());

    sp<AMessage> updatedFormat = format->dup();
    AMediaFormat *updatedNdkFormat = AMediaFormat_fromMsg(&updatedFormat);

    int result = (*sShaperOps->shapeFormat)(shaperHandle, updatedNdkFormat, flags);
    if (result == 0) {
        AMediaFormat_getFormat(updatedNdkFormat, &updatedFormat);

        sp<AMessage> deltas = updatedFormat->changesFrom(format, false /* deep */);
        size_t changeCount = deltas->countEntries();
        ALOGD("shapeMediaFormat: deltas(%zu): %s", changeCount, deltas->debugString(2).c_str());
        if (metricsHandle != 0) {
            mediametrics_setInt32(metricsHandle, kCodecShapingEnhanced, changeCount);
        }
        if (changeCount > 0) {
            if (metricsHandle != 0) {
                // save some old properties before we fold in the new ones
                int32_t bitrate;
                if (format->findInt32(KEY_BIT_RATE, &bitrate)) {
                    mediametrics_setInt32(metricsHandle, kCodecOriginalBitrate, bitrate);
                }
                int32_t qpIMin = -1;
                if (format->findInt32("original-video-qp-i-min", &qpIMin)) {
                    mediametrics_setInt32(metricsHandle, kCodecOriginalVideoQPIMin, qpIMin);
                }
                int32_t qpIMax = -1;
                if (format->findInt32("original-video-qp-i-max", &qpIMax)) {
                    mediametrics_setInt32(metricsHandle, kCodecOriginalVideoQPIMax, qpIMax);
                }
                int32_t qpPMin = -1;
                if (format->findInt32("original-video-qp-p-min", &qpPMin)) {
                    mediametrics_setInt32(metricsHandle, kCodecOriginalVideoQPPMin, qpPMin);
                }
                int32_t qpPMax = -1;
                if (format->findInt32("original-video-qp-p-max", &qpPMax)) {
                    mediametrics_setInt32(metricsHandle, kCodecOriginalVideoQPPMax, qpPMax);
                }
                 int32_t qpBMin = -1;
                if (format->findInt32("original-video-qp-b-min", &qpBMin)) {
                    mediametrics_setInt32(metricsHandle, kCodecOriginalVideoQPBMin, qpBMin);
                }
                int32_t qpBMax = -1;
                if (format->findInt32("original-video-qp-b-max", &qpBMax)) {
                    mediametrics_setInt32(metricsHandle, kCodecOriginalVideoQPBMax, qpBMax);
                }
            }
            // NB: for any field in both format and deltas, the deltas copy wins
            format->extend(deltas);
        }
    }

    AMediaFormat_delete(updatedNdkFormat);
    return OK;
}

static void mapFormat(AString componentName, const sp<AMessage> &format, const char *kind,
                      bool reverse) {
    AString mediaType;
    if (!format->findString("mime", &mediaType)) {
        ALOGV("mapFormat: no mediaType information");
        return;
    }
    ALOGV("mapFormat: codec %s mediatype %s kind %s reverse %d", componentName.c_str(),
          mediaType.c_str(), kind ? kind : "<all>", reverse);

    // make sure we have the function entry points for the shaper library
    //

#if 0
    // let's play the faster "only do mapping if we've already loaded the library
    connectFormatShaper();
#endif
    if (sShaperOps == nullptr) {
        ALOGV("mapFormat: no MediaFormatShaper hooks available");
        return;
    }

    // find the shaper information for this codec+mediaType pair
    //
    mediaformatshaper::shaperHandle_t shaperHandle;
    shaperHandle = sShaperOps->findShaper(componentName.c_str(), mediaType.c_str());
    if (shaperHandle == nullptr) {
        ALOGV("mapFormat: no shaper handle");
        return;
    }

    const char **mappings;
    if (reverse)
        mappings = sShaperOps->getReverseMappings(shaperHandle, kind);
    else
        mappings = sShaperOps->getMappings(shaperHandle, kind);

    if (mappings == nullptr) {
        ALOGV("no mappings returned");
        return;
    }

    ALOGV("Pre-mapping: %s",  format->debugString(2).c_str());
    // do the mapping
    //
    int entries = format->countEntries();
    for (int i = 0; ; i += 2) {
        if (mappings[i] == nullptr) {
            break;
        }

        size_t ix = format->findEntryByName(mappings[i]);
        if (ix < entries) {
            ALOGV("map '%s' to '%s'", mappings[i], mappings[i+1]);
            status_t status = format->setEntryNameAt(ix, mappings[i+1]);
            if (status != OK) {
                ALOGW("Unable to map from '%s' to '%s': status %d",
                      mappings[i], mappings[i+1], status);
            }
        }
    }
    ALOGV("Post-mapping: %s",  format->debugString(2).c_str());


    // reclaim the mapping memory
    for (int i = 0; ; i += 2) {
        if (mappings[i] == nullptr) {
            break;
        }
        free((void*)mappings[i]);
        free((void*)mappings[i + 1]);
    }
    free(mappings);
    mappings = nullptr;
}

//
// end of Format Shaping hooks within MediaCodec
//

status_t MediaCodec::releaseCrypto()
{
    ALOGV("releaseCrypto");

    sp<AMessage> msg = new AMessage(kWhatDrmReleaseCrypto, this);

    sp<AMessage> response;
    status_t status = msg->postAndAwaitResponse(&response);

    if (status == OK && response != NULL) {
        CHECK(response->findInt32("status", &status));
        ALOGV("releaseCrypto ret: %d ", status);
    }
    else {
        ALOGE("releaseCrypto err: %d", status);
    }

    return status;
}

void MediaCodec::onReleaseCrypto(const sp<AMessage>& msg)
{
    status_t status = INVALID_OPERATION;
    if (mCrypto != NULL) {
        ALOGV("onReleaseCrypto: mCrypto: %p (%d)", mCrypto.get(), mCrypto->getStrongCount());
        mBufferChannel->setCrypto(NULL);
        // TODO change to ALOGV
        ALOGD("onReleaseCrypto: [before clear]  mCrypto: %p (%d)",
                mCrypto.get(), mCrypto->getStrongCount());
        mCrypto.clear();

        status = OK;
    }
    else {
        ALOGW("onReleaseCrypto: No mCrypto. err: %d", status);
    }

    sp<AMessage> response = new AMessage;
    response->setInt32("status", status);

    sp<AReplyToken> replyID;
    CHECK(msg->senderAwaitsResponse(&replyID));
    response->postReply(replyID);
}

status_t MediaCodec::setInputSurface(
        const sp<PersistentSurface> &surface) {
    sp<AMessage> msg = new AMessage(kWhatSetInputSurface, this);
    msg->setObject("input-surface", surface.get());

    sp<AMessage> response;
    return PostAndAwaitResponse(msg, &response);
}

status_t MediaCodec::setSurface(const sp<Surface> &surface) {
    sp<AMessage> msg = new AMessage(kWhatSetSurface, this);
    msg->setObject("surface", surface);

    sp<AMessage> response;
    return PostAndAwaitResponse(msg, &response);
}

status_t MediaCodec::createInputSurface(
        sp<IGraphicBufferProducer>* bufferProducer) {
    sp<AMessage> msg = new AMessage(kWhatCreateInputSurface, this);

    sp<AMessage> response;
    status_t err = PostAndAwaitResponse(msg, &response);
    if (err == NO_ERROR) {
        // unwrap the sp<IGraphicBufferProducer>
        sp<RefBase> obj;
        bool found = response->findObject("input-surface", &obj);
        CHECK(found);
        sp<BufferProducerWrapper> wrapper(
                static_cast<BufferProducerWrapper*>(obj.get()));
        *bufferProducer = wrapper->getBufferProducer();
    } else {
        ALOGW("createInputSurface failed, err=%d", err);
    }
    return err;
}

uint64_t MediaCodec::getGraphicBufferSize() {
    if (mDomain != DOMAIN_VIDEO && mDomain != DOMAIN_IMAGE) {
        return 0;
    }

    uint64_t size = 0;
    size_t portNum = sizeof(mPortBuffers) / sizeof((mPortBuffers)[0]);
    for (size_t i = 0; i < portNum; ++i) {
        // TODO: this is just an estimation, we should get the real buffer size from ACodec.
        size += mPortBuffers[i].size() * mWidth * mHeight * 3 / 2;
    }
    return size;
}

status_t MediaCodec::start() {
    sp<AMessage> msg = new AMessage(kWhatStart, this);

    sp<AMessage> callback;

    status_t err;
    std::vector<MediaResourceParcel> resources;
    resources.push_back(MediaResource::CodecResource(mFlags & kFlagIsSecure,
            toMediaResourceSubType(mIsHardware, mDomain)));
    if (mDomain == DOMAIN_VIDEO || mDomain == DOMAIN_IMAGE) {
        // Don't know the buffer size at this point, but it's fine to use 1 because
        // the reclaimResource call doesn't consider the requester's buffer size for now.
        resources.push_back(MediaResource::GraphicMemoryResource(1));
    }
    for (int i = 0; i <= kMaxRetry; ++i) {
        if (i > 0) {
            // Don't try to reclaim resource for the first time.
            if (!mResourceManagerProxy->reclaimResource(resources)) {
                break;
            }
            // Recover codec from previous error before retry start.
            err = reset();
            if (err != OK) {
                ALOGE("retrying start: failed to reset codec");
                break;
            }
            if (callback != nullptr) {
                err = setCallback(callback);
                if (err != OK) {
                    ALOGE("retrying start: failed to set callback");
                    break;
                }
                ALOGD("succeed to set callback for reclaim");
            }
            sp<AMessage> response;
            err = PostAndAwaitResponse(mConfigureMsg, &response);
            if (err != OK) {
                ALOGE("retrying start: failed to configure codec");
                break;
            }
        }

        // Keep callback message after the first iteration if necessary.
        if (i == 0 && mCallback != nullptr && mFlags & kFlagIsAsync) {
            callback = mCallback;
            ALOGD("keep callback message for reclaim");
        }

        sp<AMessage> response;
        err = PostAndAwaitResponse(msg, &response);
        if (!isResourceError(err)) {
            break;
        }
    }
    return err;
}

status_t MediaCodec::stop() {
    sp<AMessage> msg = new AMessage(kWhatStop, this);

    sp<AMessage> response;
    return PostAndAwaitResponse(msg, &response);
}

bool MediaCodec::hasPendingBuffer(int portIndex) {
    return std::any_of(
            mPortBuffers[portIndex].begin(), mPortBuffers[portIndex].end(),
            [](const BufferInfo &info) { return info.mOwnedByClient; });
}

bool MediaCodec::hasPendingBuffer() {
    return hasPendingBuffer(kPortIndexInput) || hasPendingBuffer(kPortIndexOutput);
}

status_t MediaCodec::reclaim(bool force) {
    ALOGD("MediaCodec::reclaim(%p) %s", this, mInitName.c_str());
    sp<AMessage> msg = new AMessage(kWhatRelease, this);
    msg->setInt32("reclaimed", 1);
    msg->setInt32("force", force ? 1 : 0);

    sp<AMessage> response;
    status_t ret = PostAndAwaitResponse(msg, &response);
    if (ret == -ENOENT) {
        ALOGD("MediaCodec looper is gone, skip reclaim");
        ret = OK;
    }
    return ret;
}

status_t MediaCodec::release() {
    sp<AMessage> msg = new AMessage(kWhatRelease, this);
    sp<AMessage> response;
    return PostAndAwaitResponse(msg, &response);
}

status_t MediaCodec::releaseAsync(const sp<AMessage> &notify) {
    sp<AMessage> msg = new AMessage(kWhatRelease, this);
    msg->setMessage("async", notify);
    sp<AMessage> response;
    return PostAndAwaitResponse(msg, &response);
}

status_t MediaCodec::reset() {
    /* When external-facing MediaCodec object is created,
       it is already initialized.  Thus, reset is essentially
       release() followed by init(), plus clearing the state */

    status_t err = release();

    // unregister handlers
    if (mCodec != NULL) {
        if (mCodecLooper != NULL) {
            mCodecLooper->unregisterHandler(mCodec->id());
        } else {
            mLooper->unregisterHandler(mCodec->id());
        }
        mCodec = NULL;
    }
    mLooper->unregisterHandler(id());

    mFlags = 0;    // clear all flags
    mStickyError = OK;

    // reset state not reset by setState(UNINITIALIZED)
    mDequeueInputReplyID = 0;
    mDequeueOutputReplyID = 0;
    mDequeueInputTimeoutGeneration = 0;
    mDequeueOutputTimeoutGeneration = 0;
    mHaveInputSurface = false;

    if (err == OK) {
        err = init(mInitName);
    }
    return err;
}

status_t MediaCodec::queueInputBuffer(
        size_t index,
        size_t offset,
        size_t size,
        int64_t presentationTimeUs,
        uint32_t flags,
        AString *errorDetailMsg) {
    if (errorDetailMsg != NULL) {
        errorDetailMsg->clear();
    }

    sp<AMessage> msg = new AMessage(kWhatQueueInputBuffer, this);
    msg->setSize("index", index);
    msg->setSize("offset", offset);
    msg->setSize("size", size);
    msg->setInt64("timeUs", presentationTimeUs);
    msg->setInt32("flags", flags);
    msg->setPointer("errorDetailMsg", errorDetailMsg);
    sp<AMessage> response;
    return PostAndAwaitResponse(msg, &response);
}

status_t MediaCodec::queueInputBuffers(
        size_t index,
        size_t offset,
        size_t size,
        const sp<BufferInfosWrapper> &infos,
        AString *errorDetailMsg) {
    sp<AMessage> msg = new AMessage(kWhatQueueInputBuffer, this);
    uint32_t bufferFlags = 0;
    uint32_t flagsinAllAU = BUFFER_FLAG_DECODE_ONLY | BUFFER_FLAG_CODECCONFIG;
    uint32_t andFlags = flagsinAllAU;
    if (infos == nullptr || infos->value.empty()) {
        ALOGE("ERROR: Large Audio frame with no BufferInfo");
        return BAD_VALUE;
    }
    int infoIdx = 0;
    std::vector<AccessUnitInfo> &accessUnitInfo = infos->value;
    int64_t minTimeUs = accessUnitInfo.front().mTimestamp;
    bool foundEndOfStream = false;
    for ( ; infoIdx < accessUnitInfo.size() && !foundEndOfStream; ++infoIdx) {
        bufferFlags |= accessUnitInfo[infoIdx].mFlags;
        andFlags &= accessUnitInfo[infoIdx].mFlags;
        if (bufferFlags & BUFFER_FLAG_END_OF_STREAM) {
            foundEndOfStream = true;
        }
    }
    bufferFlags = bufferFlags & (andFlags | (~flagsinAllAU));
    if (infoIdx != accessUnitInfo.size()) {
        ALOGE("queueInputBuffers has incorrect access-units");
        return -EINVAL;
    }
    msg->setSize("index", index);
    msg->setSize("offset", offset);
    msg->setSize("size", size);
    msg->setInt64("timeUs", minTimeUs);
    // Make this represent flags for the entire buffer
    // decodeOnly Flag is set only when all buffers are decodeOnly
    msg->setInt32("flags", bufferFlags);
    msg->setObject("accessUnitInfo", infos);
    msg->setPointer("errorDetailMsg", errorDetailMsg);
    sp<AMessage> response;
    return PostAndAwaitResponse(msg, &response);
}

status_t MediaCodec::queueSecureInputBuffer(
        size_t index,
        size_t offset,
        const CryptoPlugin::SubSample *subSamples,
        size_t numSubSamples,
        const uint8_t key[16],
        const uint8_t iv[16],
        CryptoPlugin::Mode mode,
        const CryptoPlugin::Pattern &pattern,
        int64_t presentationTimeUs,
        uint32_t flags,
        AString *errorDetailMsg) {
    if (errorDetailMsg != NULL) {
        errorDetailMsg->clear();
    }

    sp<AMessage> msg = new AMessage(kWhatQueueInputBuffer, this);
    msg->setSize("index", index);
    msg->setSize("offset", offset);
    msg->setPointer("subSamples", (void *)subSamples);
    msg->setSize("numSubSamples", numSubSamples);
    msg->setPointer("key", (void *)key);
    msg->setPointer("iv", (void *)iv);
    msg->setInt32("mode", mode);
    msg->setInt32("encryptBlocks", pattern.mEncryptBlocks);
    msg->setInt32("skipBlocks", pattern.mSkipBlocks);
    msg->setInt64("timeUs", presentationTimeUs);
    msg->setInt32("flags", flags);
    msg->setPointer("errorDetailMsg", errorDetailMsg);

    sp<AMessage> response;
    status_t err = PostAndAwaitResponse(msg, &response);

    return err;
}

status_t MediaCodec::queueBuffer(
        size_t index,
        const std::shared_ptr<C2Buffer> &buffer,
        const sp<BufferInfosWrapper> &bufferInfos,
        const sp<AMessage> &tunings,
        AString *errorDetailMsg) {
    if (errorDetailMsg != NULL) {
        errorDetailMsg->clear();
    }
    if (bufferInfos == nullptr || bufferInfos->value.empty()) {
        return BAD_VALUE;
    }
    status_t err = OK;
    sp<AMessage> msg = new AMessage(kWhatQueueInputBuffer, this);
    msg->setSize("index", index);
    sp<WrapperObject<std::shared_ptr<C2Buffer>>> obj{
        new WrapperObject<std::shared_ptr<C2Buffer>>{buffer}};
    msg->setObject("c2buffer", obj);
    if (OK != (err = generateFlagsFromAccessUnitInfo(msg, bufferInfos))) {
        return err;
    }
    if (tunings && tunings->countEntries() > 0) {
        msg->setMessage("tunings", tunings);
    }
    msg->setPointer("errorDetailMsg", errorDetailMsg);
    sp<AMessage> response;
    err = PostAndAwaitResponse(msg, &response);

    return err;
}

status_t MediaCodec::queueEncryptedBuffer(
        size_t index,
        const sp<hardware::HidlMemory> &buffer,
        size_t offset,
        const CryptoPlugin::SubSample *subSamples,
        size_t numSubSamples,
        const uint8_t key[16],
        const uint8_t iv[16],
        CryptoPlugin::Mode mode,
        const CryptoPlugin::Pattern &pattern,
        const sp<BufferInfosWrapper> &bufferInfos,
        const sp<AMessage> &tunings,
        AString *errorDetailMsg) {
    if (errorDetailMsg != NULL) {
        errorDetailMsg->clear();
    }
    if (bufferInfos == nullptr || bufferInfos->value.empty()) {
        return BAD_VALUE;
    }
    status_t err = OK;
    sp<AMessage> msg = new AMessage(kWhatQueueInputBuffer, this);
    msg->setSize("index", index);
    sp<WrapperObject<sp<hardware::HidlMemory>>> memory{
        new WrapperObject<sp<hardware::HidlMemory>>{buffer}};
    msg->setObject("memory", memory);
    msg->setSize("offset", offset);
    msg->setPointer("subSamples", (void *)subSamples);
    msg->setSize("numSubSamples", numSubSamples);
    msg->setPointer("key", (void *)key);
    msg->setPointer("iv", (void *)iv);
    msg->setInt32("mode", mode);
    msg->setInt32("encryptBlocks", pattern.mEncryptBlocks);
    msg->setInt32("skipBlocks", pattern.mSkipBlocks);
    if (OK != (err = generateFlagsFromAccessUnitInfo(msg, bufferInfos))) {
        return err;
    }
    if (tunings && tunings->countEntries() > 0) {
        msg->setMessage("tunings", tunings);
    }
    msg->setPointer("errorDetailMsg", errorDetailMsg);

    sp<AMessage> response;
    err = PostAndAwaitResponse(msg, &response);

    return err;
}

status_t MediaCodec::dequeueInputBuffer(size_t *index, int64_t timeoutUs) {
    sp<AMessage> msg = new AMessage(kWhatDequeueInputBuffer, this);
    msg->setInt64("timeoutUs", timeoutUs);

    sp<AMessage> response;
    status_t err;
    if ((err = PostAndAwaitResponse(msg, &response)) != OK) {
        return err;
    }

    CHECK(response->findSize("index", index));

    return OK;
}

status_t MediaCodec::dequeueOutputBuffer(
        size_t *index,
        size_t *offset,
        size_t *size,
        int64_t *presentationTimeUs,
        uint32_t *flags,
        int64_t timeoutUs) {
    sp<AMessage> msg = new AMessage(kWhatDequeueOutputBuffer, this);
    msg->setInt64("timeoutUs", timeoutUs);

    sp<AMessage> response;
    status_t err;
    if ((err = PostAndAwaitResponse(msg, &response)) != OK) {
        return err;
    }

    CHECK(response->findSize("index", index));
    CHECK(response->findSize("offset", offset));
    CHECK(response->findSize("size", size));
    CHECK(response->findInt64("timeUs", presentationTimeUs));
    CHECK(response->findInt32("flags", (int32_t *)flags));

    return OK;
}

status_t MediaCodec::renderOutputBufferAndRelease(size_t index) {
    sp<AMessage> msg = new AMessage(kWhatReleaseOutputBuffer, this);
    msg->setSize("index", index);
    msg->setInt32("render", true);

    sp<AMessage> response;
    return PostAndAwaitResponse(msg, &response);
}

status_t MediaCodec::renderOutputBufferAndRelease(size_t index, int64_t timestampNs) {
    sp<AMessage> msg = new AMessage(kWhatReleaseOutputBuffer, this);
    msg->setSize("index", index);
    msg->setInt32("render", true);
    msg->setInt64("timestampNs", timestampNs);

    sp<AMessage> response;
    return PostAndAwaitResponse(msg, &response);
}

status_t MediaCodec::releaseOutputBuffer(size_t index) {
    sp<AMessage> msg = new AMessage(kWhatReleaseOutputBuffer, this);
    msg->setSize("index", index);

    sp<AMessage> response;
    return PostAndAwaitResponse(msg, &response);
}

status_t MediaCodec::signalEndOfInputStream() {
    sp<AMessage> msg = new AMessage(kWhatSignalEndOfInputStream, this);

    sp<AMessage> response;
    return PostAndAwaitResponse(msg, &response);
}

status_t MediaCodec::getOutputFormat(sp<AMessage> *format) const {
    sp<AMessage> msg = new AMessage(kWhatGetOutputFormat, this);

    sp<AMessage> response;
    status_t err;
    if ((err = PostAndAwaitResponse(msg, &response)) != OK) {
        return err;
    }

    CHECK(response->findMessage("format", format));

    return OK;
}

status_t MediaCodec::getInputFormat(sp<AMessage> *format) const {
    sp<AMessage> msg = new AMessage(kWhatGetInputFormat, this);

    sp<AMessage> response;
    status_t err;
    if ((err = PostAndAwaitResponse(msg, &response)) != OK) {
        return err;
    }

    CHECK(response->findMessage("format", format));

    return OK;
}

status_t MediaCodec::getName(AString *name) const {
    sp<AMessage> msg = new AMessage(kWhatGetName, this);

    sp<AMessage> response;
    status_t err;
    if ((err = PostAndAwaitResponse(msg, &response)) != OK) {
        return err;
    }

    CHECK(response->findString("name", name));

    return OK;
}

status_t MediaCodec::getCodecInfo(sp<MediaCodecInfo> *codecInfo) const {
    sp<AMessage> msg = new AMessage(kWhatGetCodecInfo, this);

    sp<AMessage> response;
    status_t err;
    if ((err = PostAndAwaitResponse(msg, &response)) != OK) {
        return err;
    }

    sp<RefBase> obj;
    CHECK(response->findObject("codecInfo", &obj));
    *codecInfo = static_cast<MediaCodecInfo *>(obj.get());

    return OK;
}

// this is the user-callable entry point
status_t MediaCodec::getMetrics(mediametrics_handle_t &reply) {

    reply = 0;

    sp<AMessage> msg = new AMessage(kWhatGetMetrics, this);
    sp<AMessage> response;
    status_t err;
    if ((err = PostAndAwaitResponse(msg, &response)) != OK) {
        return err;
    }

    CHECK(response->findInt64("metrics", &reply));

    return OK;
}

// runs on the looper thread (for mutex purposes)
void MediaCodec::onGetMetrics(const sp<AMessage>& msg) {

    mediametrics_handle_t results = 0;

    sp<AReplyToken> replyID;
    CHECK(msg->senderAwaitsResponse(&replyID));

    if (mMetricsHandle != 0) {
        updateMediametrics();
        results = mediametrics_dup(mMetricsHandle);
        updateEphemeralMediametrics(results);
    } else {
        results = mediametrics_dup(mMetricsHandle);
    }

    sp<AMessage> response = new AMessage;
    response->setInt64("metrics", results);
    response->postReply(replyID);
}

status_t MediaCodec::getInputBuffers(Vector<sp<MediaCodecBuffer> > *buffers) const {
    sp<AMessage> msg = new AMessage(kWhatGetBuffers, this);
    msg->setInt32("portIndex", kPortIndexInput);
    msg->setPointer("buffers", buffers);

    sp<AMessage> response;
    return PostAndAwaitResponse(msg, &response);
}

status_t MediaCodec::getOutputBuffers(Vector<sp<MediaCodecBuffer> > *buffers) const {
    sp<AMessage> msg = new AMessage(kWhatGetBuffers, this);
    msg->setInt32("portIndex", kPortIndexOutput);
    msg->setPointer("buffers", buffers);

    sp<AMessage> response;
    return PostAndAwaitResponse(msg, &response);
}

status_t MediaCodec::getOutputBuffer(size_t index, sp<MediaCodecBuffer> *buffer) {
    sp<AMessage> format;
    return getBufferAndFormat(kPortIndexOutput, index, buffer, &format);
}

status_t MediaCodec::getOutputFormat(size_t index, sp<AMessage> *format) {
    sp<MediaCodecBuffer> buffer;
    return getBufferAndFormat(kPortIndexOutput, index, &buffer, format);
}

status_t MediaCodec::getInputBuffer(size_t index, sp<MediaCodecBuffer> *buffer) {
    sp<AMessage> format;
    return getBufferAndFormat(kPortIndexInput, index, buffer, &format);
}

bool MediaCodec::isExecuting() const {
    return mState == STARTED || mState == FLUSHED;
}

status_t MediaCodec::getBufferAndFormat(
        size_t portIndex, size_t index,
        sp<MediaCodecBuffer> *buffer, sp<AMessage> *format) {
    // use mutex instead of a context switch
    if (mReleasedByResourceManager) {
        mErrorLog.log(LOG_TAG, "resource already released");
        return DEAD_OBJECT;
    }

    if (buffer == NULL) {
        mErrorLog.log(LOG_TAG, "null buffer");
        return INVALID_OPERATION;
    }

    if (format == NULL) {
        mErrorLog.log(LOG_TAG, "null format");
        return INVALID_OPERATION;
    }

    buffer->clear();
    format->clear();

    if (!isExecuting()) {
        mErrorLog.log(LOG_TAG, base::StringPrintf(
                "Invalid to call %s; only valid in Executing states",
                apiStateString().c_str()));
        return INVALID_OPERATION;
    }

    // we do not want mPortBuffers to change during this section
    // we also don't want mOwnedByClient to change during this
    Mutex::Autolock al(mBufferLock);

    std::vector<BufferInfo> &buffers = mPortBuffers[portIndex];
    if (index >= buffers.size()) {
        ALOGE("getBufferAndFormat - trying to get buffer with "
              "bad index (index=%zu buffer_size=%zu)", index, buffers.size());
        mErrorLog.log(LOG_TAG, base::StringPrintf("Bad index (index=%zu)", index));
        return INVALID_OPERATION;
    }

    const BufferInfo &info = buffers[index];
    if (!info.mOwnedByClient) {
        ALOGE("getBufferAndFormat - invalid operation "
              "(the index %zu is not owned by client)", index);
        mErrorLog.log(LOG_TAG, base::StringPrintf("index %zu is not owned by client", index));
        return INVALID_OPERATION;
    }

    *buffer = info.mData;
    *format = info.mData->format();

    return OK;
}

status_t MediaCodec::flush() {
    sp<AMessage> msg = new AMessage(kWhatFlush, this);

    sp<AMessage> response;
    return PostAndAwaitResponse(msg, &response);
}

status_t MediaCodec::requestIDRFrame() {
    (new AMessage(kWhatRequestIDRFrame, this))->post();

    return OK;
}

status_t MediaCodec::querySupportedVendorParameters(std::vector<std::string> *names) {
    return mCodec->querySupportedParameters(names);
}

status_t MediaCodec::describeParameter(const std::string &name, CodecParameterDescriptor *desc) {
    return mCodec->describeParameter(name, desc);
}

status_t MediaCodec::subscribeToVendorParameters(const std::vector<std::string> &names) {
    return mCodec->subscribeToParameters(names);
}

status_t MediaCodec::unsubscribeFromVendorParameters(const std::vector<std::string> &names) {
    return mCodec->unsubscribeFromParameters(names);
}

void MediaCodec::requestActivityNotification(const sp<AMessage> &notify) {
    sp<AMessage> msg = new AMessage(kWhatRequestActivityNotification, this);
    msg->setMessage("notify", notify);
    msg->post();
}

void MediaCodec::requestCpuBoostIfNeeded() {
    if (mCpuBoostRequested) {
        return;
    }
    int32_t colorFormat;
    if (mOutputFormat->contains("hdr-static-info")
            && mOutputFormat->findInt32("color-format", &colorFormat)
            // check format for OMX only, for C2 the format is always opaque since the
            // software rendering doesn't go through client
            && ((mSoftRenderer != NULL && colorFormat == OMX_COLOR_FormatYUV420Planar16)
                    || mOwnerName.equalsIgnoreCase("codec2::software"))) {
        int32_t left, top, right, bottom, width, height;
        int64_t totalPixel = 0;
        if (mOutputFormat->findRect("crop", &left, &top, &right, &bottom)) {
            totalPixel = (right - left + 1) * (bottom - top + 1);
        } else if (mOutputFormat->findInt32("width", &width)
                && mOutputFormat->findInt32("height", &height)) {
            totalPixel = width * height;
        }
        if (totalPixel >= 1920 * 1080) {
            mResourceManagerProxy->addResource(MediaResource::CpuBoostResource());
            mCpuBoostRequested = true;
        }
    }
}

BatteryChecker::BatteryChecker(const sp<AMessage> &msg, int64_t timeoutUs)
    : mTimeoutUs(timeoutUs)
    , mLastActivityTimeUs(-1ll)
    , mBatteryStatNotified(false)
    , mBatteryCheckerGeneration(0)
    , mIsExecuting(false)
    , mBatteryCheckerMsg(msg) {}

void BatteryChecker::onCodecActivity(std::function<void()> batteryOnCb) {
    if (!isExecuting()) {
        // ignore if not executing
        return;
    }
    if (!mBatteryStatNotified) {
        batteryOnCb();
        mBatteryStatNotified = true;
        sp<AMessage> msg = mBatteryCheckerMsg->dup();
        msg->setInt32("generation", mBatteryCheckerGeneration);

        // post checker and clear last activity time
        msg->post(mTimeoutUs);
        mLastActivityTimeUs = -1ll;
    } else {
        // update last activity time
        mLastActivityTimeUs = ALooper::GetNowUs();
    }
}

void BatteryChecker::onCheckBatteryTimer(
        const sp<AMessage> &msg, std::function<void()> batteryOffCb) {
    // ignore if this checker already expired because the client resource was removed
    int32_t generation;
    if (!msg->findInt32("generation", &generation)
            || generation != mBatteryCheckerGeneration) {
        return;
    }

    if (mLastActivityTimeUs < 0ll) {
        // timed out inactive, do not repost checker
        batteryOffCb();
        mBatteryStatNotified = false;
    } else {
        // repost checker and clear last activity time
        msg->post(mTimeoutUs + mLastActivityTimeUs - ALooper::GetNowUs());
        mLastActivityTimeUs = -1ll;
    }
}

void BatteryChecker::onClientRemoved() {
    mBatteryStatNotified = false;
    mBatteryCheckerGeneration++;
}

////////////////////////////////////////////////////////////////////////////////

void MediaCodec::cancelPendingDequeueOperations() {
    if (mFlags & kFlagDequeueInputPending) {
        mErrorLog.log(LOG_TAG, "Pending dequeue input buffer request cancelled");
        PostReplyWithError(mDequeueInputReplyID, INVALID_OPERATION);

        ++mDequeueInputTimeoutGeneration;
        mDequeueInputReplyID = 0;
        mFlags &= ~kFlagDequeueInputPending;
    }

    if (mFlags & kFlagDequeueOutputPending) {
        mErrorLog.log(LOG_TAG, "Pending dequeue output buffer request cancelled");
        PostReplyWithError(mDequeueOutputReplyID, INVALID_OPERATION);

        ++mDequeueOutputTimeoutGeneration;
        mDequeueOutputReplyID = 0;
        mFlags &= ~kFlagDequeueOutputPending;
    }
}

bool MediaCodec::handleDequeueInputBuffer(const sp<AReplyToken> &replyID, bool newRequest) {
    if (!isExecuting()) {
        mErrorLog.log(LOG_TAG, base::StringPrintf(
                "Invalid to call %s; only valid in executing state",
                apiStateString().c_str()));
        PostReplyWithError(replyID, INVALID_OPERATION);
    } else if (mFlags & kFlagIsAsync) {
        mErrorLog.log(LOG_TAG, "Invalid to call in async mode");
        PostReplyWithError(replyID, INVALID_OPERATION);
    } else if (newRequest && (mFlags & kFlagDequeueInputPending)) {
        mErrorLog.log(LOG_TAG, "Invalid to call while another dequeue input request is pending");
        PostReplyWithError(replyID, INVALID_OPERATION);
        return true;
    } else if (mFlags & kFlagStickyError) {
        PostReplyWithError(replyID, getStickyError());
        return true;
    }

    ssize_t index = dequeuePortBuffer(kPortIndexInput);

    if (index < 0) {
        CHECK_EQ(index, -EAGAIN);
        return false;
    }

    sp<AMessage> response = new AMessage;
    response->setSize("index", index);
    response->postReply(replyID);

    return true;
}

MediaCodec::DequeueOutputResult MediaCodec::handleDequeueOutputBuffer(
        const sp<AReplyToken> &replyID, bool newRequest) {
    if (!isExecuting()) {
        mErrorLog.log(LOG_TAG, base::StringPrintf(
                "Invalid to call %s; only valid in executing state",
                apiStateString().c_str()));
        PostReplyWithError(replyID, INVALID_OPERATION);
    } else if (mFlags & kFlagIsAsync) {
        mErrorLog.log(LOG_TAG, "Invalid to call in async mode");
        PostReplyWithError(replyID, INVALID_OPERATION);
    } else if (newRequest && (mFlags & kFlagDequeueOutputPending)) {
        mErrorLog.log(LOG_TAG, "Invalid to call while another dequeue output request is pending");
        PostReplyWithError(replyID, INVALID_OPERATION);
    } else if (mFlags & kFlagStickyError) {
        PostReplyWithError(replyID, getStickyError());
    } else if (mFlags & kFlagOutputBuffersChanged) {
        PostReplyWithError(replyID, INFO_OUTPUT_BUFFERS_CHANGED);
        mFlags &= ~kFlagOutputBuffersChanged;
    } else {
        sp<AMessage> response = new AMessage;
        BufferInfo *info = peekNextPortBuffer(kPortIndexOutput);
        if (!info) {
            return DequeueOutputResult::kNoBuffer;
        }

        // In synchronous mode, output format change should be handled
        // at dequeue to put the event at the correct order.

        const sp<MediaCodecBuffer> &buffer = info->mData;
        handleOutputFormatChangeIfNeeded(buffer);
        if (mFlags & kFlagOutputFormatChanged) {
            PostReplyWithError(replyID, INFO_FORMAT_CHANGED);
            mFlags &= ~kFlagOutputFormatChanged;
            return DequeueOutputResult::kRepliedWithError;
        }

        ssize_t index = dequeuePortBuffer(kPortIndexOutput);
        if (discardDecodeOnlyOutputBuffer(index)) {
            return DequeueOutputResult::kDiscardedBuffer;
        }

        response->setSize("index", index);
        response->setSize("offset", buffer->offset());
        response->setSize("size", buffer->size());

        int64_t timeUs;
        CHECK(buffer->meta()->findInt64("timeUs", &timeUs));

        response->setInt64("timeUs", timeUs);

        int32_t flags;
        CHECK(buffer->meta()->findInt32("flags", &flags));

        response->setInt32("flags", flags);

        statsBufferReceived(timeUs, buffer);

        response->postReply(replyID);
        return DequeueOutputResult::kSuccess;
    }

    return DequeueOutputResult::kRepliedWithError;
}


inline void MediaCodec::initClientConfigParcel(ClientConfigParcel& clientConfig) {
    clientConfig.codecType = toMediaResourceSubType(mIsHardware, mDomain);
    clientConfig.isEncoder = mFlags & kFlagIsEncoder;
    clientConfig.width = mWidth;
    clientConfig.height = mHeight;
    clientConfig.timeStamp = systemTime(SYSTEM_TIME_MONOTONIC) / 1000LL;
    clientConfig.id = mCodecId;
}

void MediaCodec::onMessageReceived(const sp<AMessage> &msg) {
    switch (msg->what()) {
        case kWhatCodecNotify:
        {
            int32_t what;
            CHECK(msg->findInt32("what", &what));
            AString codecErrorState;
            switch (what) {
                case kWhatError:
                case kWhatCryptoError:
                {
                    int32_t err, actionCode;
                    CHECK(msg->findInt32("err", &err));
                    CHECK(msg->findInt32("actionCode", &actionCode));

                    ALOGE("Codec reported err %#x/%s, actionCode %d, while in state %d/%s",
                                              err, StrMediaError(err).c_str(), actionCode,
                                              mState, stateString(mState).c_str());
                    if (err == DEAD_OBJECT) {
                        mFlags |= kFlagSawMediaServerDie;
                        mFlags &= ~kFlagIsComponentAllocated;
                    }
                    bool sendErrorResponse = true;
                    std::string origin;
                    if (what == kWhatCryptoError) {
                        origin = "kWhatCryptoError:";
                    } else {
                        origin = "kWhatError:";
                        //TODO: add a new error state
                    }
                    codecErrorState = kCodecErrorState;
                    origin += stateString(mState);
                    if (mCryptoAsync) {
                        //TODO: do some book keeping on the buffers
                        mCryptoAsync->stop();
                    }
                    switch (mState) {
                        case INITIALIZING:
                        {
                            setState(UNINITIALIZED);
                            break;
                        }

                        case CONFIGURING:
                        {
                            if (actionCode == ACTION_CODE_FATAL) {
                                mediametrics_setInt32(mMetricsHandle, kCodecError, err);
                                mediametrics_setCString(mMetricsHandle, kCodecErrorState,
                                                        stateString(mState).c_str());
                                flushMediametrics();
                                initMediametrics();
                            }
                            setState(actionCode == ACTION_CODE_FATAL ?
                                    UNINITIALIZED : INITIALIZED);
                            break;
                        }

                        case STARTING:
                        {
                            if (actionCode == ACTION_CODE_FATAL) {
                                mediametrics_setInt32(mMetricsHandle, kCodecError, err);
                                mediametrics_setCString(mMetricsHandle, kCodecErrorState,
                                                        stateString(mState).c_str());
                                flushMediametrics();
                                initMediametrics();
                            }
                            setState(actionCode == ACTION_CODE_FATAL ?
                                    UNINITIALIZED : CONFIGURED);
                            break;
                        }

                        case RELEASING:
                        {
                            // Ignore the error, assuming we'll still get
                            // the shutdown complete notification. If we
                            // don't, we'll timeout and force release.
                            sendErrorResponse = false;
                            FALLTHROUGH_INTENDED;
                        }
                        case STOPPING:
                        {
                            if (mFlags & kFlagSawMediaServerDie) {
                                if (mState == RELEASING && !mReplyID) {
                                    ALOGD("Releasing asynchronously, so nothing to reply here.");
                                }
                                // MediaServer died, there definitely won't
                                // be a shutdown complete notification after
                                // all.

                                // note that we may be directly going from
                                // STOPPING->UNINITIALIZED, instead of the
                                // usual STOPPING->INITIALIZED state.
                                setState(UNINITIALIZED);
                                if (mState == RELEASING) {
                                    mComponentName.clear();
                                }
                                if (mReplyID) {
                                    postPendingRepliesAndDeferredMessages(origin + ":dead");
                                } else {
                                    ALOGD("no pending replies: %s:dead following %s",
                                          origin.c_str(), mLastReplyOrigin.c_str());
                                }
                                sendErrorResponse = false;
                            } else if (!mReplyID) {
                                sendErrorResponse = false;
                            }
                            break;
                        }

                        case FLUSHING:
                        {
                            if (actionCode == ACTION_CODE_FATAL) {
                                mediametrics_setInt32(mMetricsHandle, kCodecError, err);
                                mediametrics_setCString(mMetricsHandle, kCodecErrorState,
                                                        stateString(mState).c_str());
                                flushMediametrics();
                                initMediametrics();

                                setState(UNINITIALIZED);
                            } else {
                                setState((mFlags & kFlagIsAsync) ? FLUSHED : STARTED);
                            }
                            break;
                        }

                        case FLUSHED:
                        case STARTED:
                        {
                            sendErrorResponse = (mReplyID != nullptr);

                            setStickyError(err);
                            postActivityNotificationIfPossible();

                            cancelPendingDequeueOperations();

                            if (mFlags & kFlagIsAsync) {
                                if (what == kWhatError) {
                                    onError(err, actionCode);
                                } else if (what == kWhatCryptoError) {
                                    onCryptoError(msg);
                                }
                            }
                            switch (actionCode) {
                            case ACTION_CODE_TRANSIENT:
                                break;
                            case ACTION_CODE_RECOVERABLE:
                                setState(INITIALIZED);
                                break;
                            default:
                                mediametrics_setInt32(mMetricsHandle, kCodecError, err);
                                mediametrics_setCString(mMetricsHandle, kCodecErrorState,
                                                        stateString(mState).c_str());
                                flushMediametrics();
                                initMediametrics();
                                setState(UNINITIALIZED);
                                break;
                            }
                            break;
                        }

                        default:
                        {
                            sendErrorResponse = (mReplyID != nullptr);

                            setStickyError(err);
                            postActivityNotificationIfPossible();

                            // actionCode in an uninitialized state is always fatal.
                            if (mState == UNINITIALIZED) {
                                actionCode = ACTION_CODE_FATAL;
                            }
                            if (mFlags & kFlagIsAsync) {
                                if (what == kWhatError) {
                                    onError(err, actionCode);
                                } else if (what == kWhatCryptoError) {
                                    onCryptoError(msg);
                                }
                            }
                            switch (actionCode) {
                            case ACTION_CODE_TRANSIENT:
                                break;
                            case ACTION_CODE_RECOVERABLE:
                                setState(INITIALIZED);
                                break;
                            default:
                                setState(UNINITIALIZED);
                                break;
                            }
                            break;
                        }
                    }

                    if (sendErrorResponse) {
                        // TRICKY: replicate PostReplyWithError logic for
                        //         err code override
                        int32_t finalErr = err;
                        if (mReleasedByResourceManager) {
                            // override the err code if MediaCodec has been
                            // released by ResourceManager.
                            finalErr = DEAD_OBJECT;
                        }
                        postPendingRepliesAndDeferredMessages(origin, finalErr);
                    }
                    break;
                }

                case kWhatComponentAllocated:
                {
                    if (mState == RELEASING || mState == UNINITIALIZED) {
                        // In case a kWhatError or kWhatRelease message came in and replied,
                        // we log a warning and ignore.
                        ALOGW("allocate interrupted by error or release, current state %d/%s",
                              mState, stateString(mState).c_str());
                        break;
                    }
                    CHECK_EQ(mState, INITIALIZING);
                    setState(INITIALIZED);
                    mFlags |= kFlagIsComponentAllocated;

                    CHECK(msg->findString("componentName", &mComponentName));

                    if (mComponentName.c_str()) {
                        mIsHardware = !MediaCodecList::isSoftwareCodec(mComponentName);
                        mediametrics_setCString(mMetricsHandle, kCodecCodec,
                                                mComponentName.c_str());
                        // Update the codec name.
                        mResourceManagerProxy->setCodecName(mComponentName.c_str());
                    }

                    const char *owner = mCodecInfo ? mCodecInfo->getOwnerName() : "";
                    if (mComponentName.startsWith("OMX.google.")
                            && strncmp(owner, "default", 8) == 0) {
                        mFlags |= kFlagUsesSoftwareRenderer;
                    } else {
                        mFlags &= ~kFlagUsesSoftwareRenderer;
                    }
                    mOwnerName = owner;

                    if (mComponentName.endsWith(".secure")) {
                        mFlags |= kFlagIsSecure;
                        mediametrics_setInt32(mMetricsHandle, kCodecSecure, 1);
                    } else {
                        mFlags &= ~kFlagIsSecure;
                        mediametrics_setInt32(mMetricsHandle, kCodecSecure, 0);
                    }

                    mediametrics_setInt32(mMetricsHandle, kCodecHardware,
                                          MediaCodecList::isSoftwareCodec(mComponentName) ? 0 : 1);

                    mResourceManagerProxy->addResource(MediaResource::CodecResource(
                            mFlags & kFlagIsSecure, toMediaResourceSubType(mIsHardware, mDomain)));

                    postPendingRepliesAndDeferredMessages("kWhatComponentAllocated");
                    break;
                }

                case kWhatComponentConfigured:
                {
                    if (mState == RELEASING || mState == UNINITIALIZED || mState == INITIALIZED) {
                        // In case a kWhatError or kWhatRelease message came in and replied,
                        // we log a warning and ignore.
                        ALOGW("configure interrupted by error or release, current state %d/%s",
                              mState, stateString(mState).c_str());
                        break;
                    }
                    CHECK_EQ(mState, CONFIGURING);

                    // reset input surface flag
                    mHaveInputSurface = false;

                    CHECK(msg->findMessage("input-format", &mInputFormat));
                    CHECK(msg->findMessage("output-format", &mOutputFormat));

                    // limit to confirming the opt-in behavior to minimize any behavioral change
                    if (mSurface != nullptr && !mAllowFrameDroppingBySurface) {
                        // signal frame dropping mode in the input format as this may also be
                        // meaningful and confusing for an encoder in a transcoder scenario
                        mInputFormat->setInt32(KEY_ALLOW_FRAME_DROP, mAllowFrameDroppingBySurface);
                    }
                    sp<AMessage> interestingFormat =
                            (mFlags & kFlagIsEncoder) ? mOutputFormat : mInputFormat;
                    ALOGV("[%s] configured as input format: %s, output format: %s",
                            mComponentName.c_str(),
                            mInputFormat->debugString(4).c_str(),
                            mOutputFormat->debugString(4).c_str());
                    int32_t usingSwRenderer;
                    if (mOutputFormat->findInt32("using-sw-renderer", &usingSwRenderer)
                            && usingSwRenderer) {
                        mFlags |= kFlagUsesSoftwareRenderer;
                    }
                    setState(CONFIGURED);
                    postPendingRepliesAndDeferredMessages("kWhatComponentConfigured");

                    // augment our media metrics info, now that we know more things
                    // such as what the codec extracted from any CSD passed in.
                    if (mMetricsHandle != 0) {
                        sp<AMessage> format;
                        if (mConfigureMsg != NULL &&
                            mConfigureMsg->findMessage("format", &format)) {
                                // format includes: mime
                                AString mime;
                                if (format->findString("mime", &mime)) {
                                    mediametrics_setCString(mMetricsHandle, kCodecMime,
                                                            mime.c_str());
                                }
                            }
                        // perhaps video only?
                        int32_t profile = 0;
                        if (interestingFormat->findInt32("profile", &profile)) {
                            mediametrics_setInt32(mMetricsHandle, kCodecProfile, profile);
                        }
                        int32_t level = 0;
                        if (interestingFormat->findInt32("level", &level)) {
                            mediametrics_setInt32(mMetricsHandle, kCodecLevel, level);
                        }
                        sp<AMessage> uncompressedFormat =
                                (mFlags & kFlagIsEncoder) ? mInputFormat : mOutputFormat;
                        int32_t componentColorFormat  = -1;
                        if (uncompressedFormat->findInt32("android._color-format",
                                &componentColorFormat)) {
                            mediametrics_setInt32(mMetricsHandle,
                                    kCodecComponentColorFormat, componentColorFormat);
                        }
                        updateHdrMetrics(true /* isConfig */);
                        int32_t codecMaxInputSize = -1;
                        if (mInputFormat->findInt32(KEY_MAX_INPUT_SIZE, &codecMaxInputSize)) {
                            mApiUsageMetrics.inputBufferSize.codecMax = codecMaxInputSize;
                        }
                        // bitrate and bitrate mode, encoder only
                        if (mFlags & kFlagIsEncoder) {
                            // encoder specific values
                            int32_t bitrate_mode = -1;
                            if (mOutputFormat->findInt32(KEY_BITRATE_MODE, &bitrate_mode)) {
                                    mediametrics_setCString(mMetricsHandle, kCodecBitrateMode,
                                          asString_BitrateMode(bitrate_mode));
                            }
                            int32_t bitrate = -1;
                            if (mOutputFormat->findInt32(KEY_BIT_RATE, &bitrate)) {
                                    mediametrics_setInt32(mMetricsHandle, kCodecBitrate, bitrate);
                            }
                        } else {
                            // decoder specific values
                        }
                    }
                    break;
                }

                case kWhatInputSurfaceCreated:
                {
                    if (mState != CONFIGURED) {
                        // state transitioned unexpectedly; we should have replied already.
                        ALOGD("received kWhatInputSurfaceCreated message in state %s",
                                stateString(mState).c_str());
                        break;
                    }
                    // response to initiateCreateInputSurface()
                    status_t err = NO_ERROR;
                    sp<AMessage> response = new AMessage;
                    if (!msg->findInt32("err", &err)) {
                        sp<RefBase> obj;
                        msg->findObject("input-surface", &obj);
                        CHECK(msg->findMessage("input-format", &mInputFormat));
                        CHECK(msg->findMessage("output-format", &mOutputFormat));
                        ALOGV("[%s] input surface created as input format: %s, output format: %s",
                                mComponentName.c_str(),
                                mInputFormat->debugString(4).c_str(),
                                mOutputFormat->debugString(4).c_str());
                        CHECK(obj != NULL);
                        response->setObject("input-surface", obj);
                        mHaveInputSurface = true;
                    } else {
                        response->setInt32("err", err);
                    }
                    postPendingRepliesAndDeferredMessages("kWhatInputSurfaceCreated", response);
                    break;
                }

                case kWhatInputSurfaceAccepted:
                {
                    if (mState != CONFIGURED) {
                        // state transitioned unexpectedly; we should have replied already.
                        ALOGD("received kWhatInputSurfaceAccepted message in state %s",
                                stateString(mState).c_str());
                        break;
                    }
                    // response to initiateSetInputSurface()
                    status_t err = NO_ERROR;
                    sp<AMessage> response = new AMessage();
                    if (!msg->findInt32("err", &err)) {
                        CHECK(msg->findMessage("input-format", &mInputFormat));
                        CHECK(msg->findMessage("output-format", &mOutputFormat));
                        mHaveInputSurface = true;
                    } else {
                        response->setInt32("err", err);
                    }
                    postPendingRepliesAndDeferredMessages("kWhatInputSurfaceAccepted", response);
                    break;
                }

                case kWhatSignaledInputEOS:
                {
                    if (!isExecuting()) {
                        // state transitioned unexpectedly; we should have replied already.
                        ALOGD("received kWhatSignaledInputEOS message in state %s",
                                stateString(mState).c_str());
                        break;
                    }
                    // response to signalEndOfInputStream()
                    sp<AMessage> response = new AMessage;
                    status_t err;
                    if (msg->findInt32("err", &err)) {
                        response->setInt32("err", err);
                    }
                    postPendingRepliesAndDeferredMessages("kWhatSignaledInputEOS", response);
                    break;
                }

                case kWhatStartCompleted:
                {
                    if (mState == RELEASING || mState == UNINITIALIZED) {
                        // In case a kWhatRelease message came in and replied,
                        // we log a warning and ignore.
                        ALOGW("start interrupted by release, current state %d/%s",
                              mState, stateString(mState).c_str());
                        break;
                    }

                    CHECK_EQ(mState, STARTING);
                    if (mDomain == DOMAIN_VIDEO || mDomain == DOMAIN_IMAGE) {
                        mResourceManagerProxy->addResource(
                                MediaResource::GraphicMemoryResource(getGraphicBufferSize()));
                    }
                    // Notify the RM that the codec is in use (has been started).
                    ClientConfigParcel clientConfig;
                    initClientConfigParcel(clientConfig);
                    mResourceManagerProxy->notifyClientStarted(clientConfig);

                    setState(STARTED);
                    postPendingRepliesAndDeferredMessages("kWhatStartCompleted");

                    // Now that the codec has started, configure, by default, the peek behavior to
                    // be undefined for backwards compatibility with older releases. Later, if an
                    // app explicitly enables or disables peek, the parameter will be turned off and
                    // the legacy undefined behavior is disallowed.
                    // See updateTunnelPeek called in onSetParameters for more details.
                    if (mTunneled && mTunnelPeekState == TunnelPeekState::kLegacyMode) {
                        sp<AMessage> params = new AMessage;
                        params->setInt32("android._tunnel-peek-set-legacy", 1);
                        mCodec->signalSetParameters(params);
                    }
                    break;
                }

                case kWhatOutputBuffersChanged:
                {
                    mFlags |= kFlagOutputBuffersChanged;
                    postActivityNotificationIfPossible();
                    break;
                }

                case kWhatOutputFramesRendered:
                {
                    // ignore these in all states except running
                    if (mState != STARTED) {
                        break;
                    }
                    TunnelPeekState previousState = mTunnelPeekState;
                    if (mTunnelPeekState != TunnelPeekState::kLegacyMode) {
                        mTunnelPeekState = TunnelPeekState::kBufferRendered;
                        ALOGV("TunnelPeekState: %s -> %s",
                                asString(previousState),
                                asString(TunnelPeekState::kBufferRendered));
                    }
                    processRenderedFrames(msg);
                    // check that we have a notification set
                    if (mOnFrameRenderedNotification != NULL) {
                        sp<AMessage> notify = mOnFrameRenderedNotification->dup();
                        notify->setMessage("data", msg);
                        notify->post();
                    }
                    break;
                }

                case kWhatFirstTunnelFrameReady:
                {
                    if (mState != STARTED) {
                        break;
                    }
                    TunnelPeekState previousState = mTunnelPeekState;
                    switch(mTunnelPeekState) {
                        case TunnelPeekState::kDisabledNoBuffer:
                        case TunnelPeekState::kDisabledQueued:
                            mTunnelPeekState = TunnelPeekState::kBufferDecoded;
                            ALOGV("First tunnel frame ready");
                            ALOGV("TunnelPeekState: %s -> %s",
                                  asString(previousState),
                                  asString(mTunnelPeekState));
                            break;
                        case TunnelPeekState::kEnabledNoBuffer:
                        case TunnelPeekState::kEnabledQueued:
                            {
                                sp<AMessage> parameters = new AMessage();
                                parameters->setInt32("android._trigger-tunnel-peek", 1);
                                mCodec->signalSetParameters(parameters);
                            }
                            mTunnelPeekState = TunnelPeekState::kBufferRendered;
                            ALOGV("First tunnel frame ready");
                            ALOGV("TunnelPeekState: %s -> %s",
                                  asString(previousState),
                                  asString(mTunnelPeekState));
                            break;
                        default:
                            ALOGV("Ignoring first tunnel frame ready, TunnelPeekState: %s",
                                  asString(mTunnelPeekState));
                            break;
                    }

                    if (mOnFirstTunnelFrameReadyNotification != nullptr) {
                        sp<AMessage> notify = mOnFirstTunnelFrameReadyNotification->dup();
                        notify->setMessage("data", msg);
                        notify->post();
                    }
                    break;
                }

                case kWhatFillThisBuffer:
                {
                    /* size_t index = */updateBuffers(kPortIndexInput, msg);

                    if (mState == FLUSHING
                            || mState == STOPPING
                            || mState == RELEASING) {
                        returnBuffersToCodecOnPort(kPortIndexInput);
                        break;
                    }

                    if (!mCSD.empty()) {
                        ssize_t index = dequeuePortBuffer(kPortIndexInput);
                        CHECK_GE(index, 0);

                        // If codec specific data had been specified as
                        // part of the format in the call to configure and
                        // if there's more csd left, we submit it here
                        // clients only get access to input buffers once
                        // this data has been exhausted.

                        status_t err = queueCSDInputBuffer(index);

                        if (err != OK) {
                            ALOGE("queueCSDInputBuffer failed w/ error %d",
                                  err);

                            setStickyError(err);
                            postActivityNotificationIfPossible();

                            cancelPendingDequeueOperations();
                        }
                        break;
                    }
                    if (!mLeftover.empty()) {
                        ssize_t index = dequeuePortBuffer(kPortIndexInput);
                        CHECK_GE(index, 0);

                        status_t err = handleLeftover(index);
                        if (err != OK) {
                            setStickyError(err);
                            postActivityNotificationIfPossible();
                            cancelPendingDequeueOperations();
                        }
                        break;
                    }

                    if (mFlags & kFlagIsAsync) {
                        if (!mHaveInputSurface) {
                            if (mState == FLUSHED) {
                                mHavePendingInputBuffers = true;
                            } else {
                                onInputBufferAvailable();
                            }
                        }
                    } else if (mFlags & kFlagDequeueInputPending) {
                        CHECK(handleDequeueInputBuffer(mDequeueInputReplyID));

                        ++mDequeueInputTimeoutGeneration;
                        mFlags &= ~kFlagDequeueInputPending;
                        mDequeueInputReplyID = 0;
                    } else {
                        postActivityNotificationIfPossible();
                    }
                    break;
                }

                case kWhatDrainThisBuffer:
                {
                    if ((mFlags & kFlagUseBlockModel) == 0 && mTunneled) {
                        sp<RefBase> obj;
                        CHECK(msg->findObject("buffer", &obj));
                        sp<MediaCodecBuffer> buffer = static_cast<MediaCodecBuffer *>(obj.get());
                        if (mFlags & kFlagIsAsync) {
                            // In asynchronous mode, output format change is processed immediately.
                            handleOutputFormatChangeIfNeeded(buffer);
                        } else {
                            postActivityNotificationIfPossible();
                        }
                        mBufferChannel->discardBuffer(buffer);
                        break;
                    }

                    /* size_t index = */updateBuffers(kPortIndexOutput, msg);

                    if (mState == FLUSHING
                            || mState == STOPPING
                            || mState == RELEASING) {
                        returnBuffersToCodecOnPort(kPortIndexOutput);
                        break;
                    }

                    if (mFlags & kFlagIsAsync) {
                        sp<RefBase> obj;
                        CHECK(msg->findObject("buffer", &obj));
                        sp<MediaCodecBuffer> buffer = static_cast<MediaCodecBuffer *>(obj.get());

                        // In asynchronous mode, output format change is processed immediately.
                        handleOutputFormatChangeIfNeeded(buffer);
                        onOutputBufferAvailable();
                    } else if (mFlags & kFlagDequeueOutputPending) {
                        DequeueOutputResult dequeueResult =
                            handleDequeueOutputBuffer(mDequeueOutputReplyID);
                        switch (dequeueResult) {
                            case DequeueOutputResult::kNoBuffer:
                                TRESPASS();
                                break;
                            case DequeueOutputResult::kDiscardedBuffer:
                                break;
                            case DequeueOutputResult::kRepliedWithError:
                                [[fallthrough]];
                            case DequeueOutputResult::kSuccess:
                            {
                                ++mDequeueOutputTimeoutGeneration;
                                mFlags &= ~kFlagDequeueOutputPending;
                                mDequeueOutputReplyID = 0;
                                break;
                            }
                            default:
                                TRESPASS();
                        }
                    } else {
                        postActivityNotificationIfPossible();
                    }

                    break;
                }

                case kWhatMetricsUpdated:
                {
                    sp<AMessage> updatedMetrics;
                    CHECK(msg->findMessage("updated-metrics", &updatedMetrics));

                    size_t numEntries = updatedMetrics->countEntries();
                    AMessage::Type type;
                    for (size_t i = 0; i < numEntries; ++i) {
                        const char *name = updatedMetrics->getEntryNameAt(i, &type);
                        AMessage::ItemData itemData = updatedMetrics->getEntryAt(i);
                        switch (type) {
                            case AMessage::kTypeInt32: {
                                int32_t metricValue;
                                itemData.find(&metricValue);
                                mediametrics_setInt32(mMetricsHandle, name, metricValue);
                                break;
                            }
                            case AMessage::kTypeInt64: {
                                int64_t metricValue;
                                itemData.find(&metricValue);
                                mediametrics_setInt64(mMetricsHandle, name, metricValue);
                                break;
                            }
                            case AMessage::kTypeDouble: {
                                double metricValue;
                                itemData.find(&metricValue);
                                mediametrics_setDouble(mMetricsHandle, name, metricValue);
                                break;
                            }
                            case AMessage::kTypeString: {
                                AString metricValue;
                                itemData.find(&metricValue);
                                mediametrics_setCString(mMetricsHandle, name, metricValue.c_str());
                                break;
                            }
                            // ToDo: add support for other types
                            default:
                                ALOGW("Updated metrics type not supported.");
                        }
                    }
                    break;
                }

                case kWhatEOS:
                {
                    // We already notify the client of this by using the
                    // corresponding flag in "onOutputBufferReady".
                    break;
                }

                case kWhatStopCompleted:
                {
                    if (mState != STOPPING) {
                        ALOGW("Received kWhatStopCompleted in state %d/%s",
                              mState, stateString(mState).c_str());
                        break;
                    }

                    if (mIsSurfaceToDisplay) {
                        mVideoRenderQualityTracker.resetForDiscontinuity();
                    }

                    // Notify the RM that the codec has been stopped.
                    ClientConfigParcel clientConfig;
                    initClientConfigParcel(clientConfig);
                    mResourceManagerProxy->notifyClientStopped(clientConfig);

                    setState(INITIALIZED);
                    if (mReplyID) {
                        postPendingRepliesAndDeferredMessages("kWhatStopCompleted");
                    } else {
                        ALOGW("kWhatStopCompleted: presumably an error occurred earlier, "
                              "but the operation completed anyway. (last reply origin=%s)",
                              mLastReplyOrigin.c_str());
                    }
                    break;
                }

                case kWhatReleaseCompleted:
                {
                    if (mState != RELEASING) {
                        ALOGW("Received kWhatReleaseCompleted in state %d/%s",
                              mState, stateString(mState).c_str());
                        break;
                    }
                    setState(UNINITIALIZED);
                    mComponentName.clear();

                    mFlags &= ~kFlagIsComponentAllocated;

                    // off since we're removing all resources including the battery on
                    if (mBatteryChecker != nullptr) {
                        mBatteryChecker->onClientRemoved();
                    }

                    mResourceManagerProxy->removeClient();
                    mReleaseSurface.reset();

                    if (mReplyID != nullptr) {
                        postPendingRepliesAndDeferredMessages("kWhatReleaseCompleted");
                    }
                    if (mAsyncReleaseCompleteNotification != nullptr) {
                        flushMediametrics();
                        mAsyncReleaseCompleteNotification->post();
                        mAsyncReleaseCompleteNotification.clear();
                    }
                    break;
                }

                case kWhatFlushCompleted:
                {
                    if (mState != FLUSHING) {
                        ALOGW("received FlushCompleted message in state %d/%s",
                                mState, stateString(mState).c_str());
                        break;
                    }

                    if (mIsSurfaceToDisplay) {
                        mVideoRenderQualityTracker.resetForDiscontinuity();
                    }

                    if (mFlags & kFlagIsAsync) {
                        setState(FLUSHED);
                    } else {
                        setState(STARTED);
                        mCodec->signalResume();
                    }
                    mReliabilityContextMetrics.flushCount++;

                    postPendingRepliesAndDeferredMessages("kWhatFlushCompleted");
                    break;
                }

                default:
                    TRESPASS();
            }
            break;
        }

        case kWhatInit:
        {
            if (mState != UNINITIALIZED) {
                PostReplyWithError(msg, INVALID_OPERATION);
                break;
            }

            if (mReplyID) {
                mDeferredMessages.push_back(msg);
                break;
            }
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));

            mReplyID = replyID;
            setState(INITIALIZING);

            sp<RefBase> codecInfo;
            (void)msg->findObject("codecInfo", &codecInfo);
            AString name;
            CHECK(msg->findString("name", &name));

            sp<AMessage> format = new AMessage;
            if (codecInfo) {
                format->setObject("codecInfo", codecInfo);
            }
            format->setString("componentName", name);

            mCodec->initiateAllocateComponent(format);
            break;
        }

        case kWhatSetNotification:
        {
            sp<AMessage> notify;
            if (msg->findMessage("on-frame-rendered", &notify)) {
                mOnFrameRenderedNotification = notify;
            }
            if (msg->findMessage("first-tunnel-frame-ready", &notify)) {
                mOnFirstTunnelFrameReadyNotification = notify;
            }
            break;
        }

        case kWhatSetCallback:
        {
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));

            if (mState == UNINITIALIZED
                    || mState == INITIALIZING
                    || isExecuting()) {
                // callback can't be set after codec is executing,
                // or before it's initialized (as the callback
                // will be cleared when it goes to INITIALIZED)
                mErrorLog.log(LOG_TAG, base::StringPrintf(
                        "Invalid to call %s; only valid at Initialized state",
                        apiStateString().c_str()));
                PostReplyWithError(replyID, INVALID_OPERATION);
                break;
            }

            sp<AMessage> callback;
            CHECK(msg->findMessage("callback", &callback));

            mCallback = callback;

            if (mCallback != NULL) {
                ALOGI("MediaCodec will operate in async mode");
                mFlags |= kFlagIsAsync;
            } else {
                mFlags &= ~kFlagIsAsync;
            }

            sp<AMessage> response = new AMessage;
            response->postReply(replyID);
            break;
        }

        case kWhatGetMetrics:
        {
            onGetMetrics(msg);
            break;
        }


        case kWhatConfigure:
        {
            if (mState != INITIALIZED) {
                mErrorLog.log(LOG_TAG, base::StringPrintf(
                        "configure() is valid only at Initialized state; currently %s",
                        apiStateString().c_str()));
                PostReplyWithError(msg, INVALID_OPERATION);
                break;
            }

            if (mReplyID) {
                mDeferredMessages.push_back(msg);
                break;
            }
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));

            sp<RefBase> obj;
            CHECK(msg->findObject("surface", &obj));

            sp<AMessage> format;
            CHECK(msg->findMessage("format", &format));

            // start with a copy of the passed metrics info for use in this run
            mediametrics_handle_t handle;
            CHECK(msg->findInt64("metrics", &handle));
            if (handle != 0) {
                if (mMetricsHandle != 0) {
                    flushMediametrics();
                }
                mMetricsHandle = mediametrics_dup(handle);
                // and set some additional metrics values
                initMediametrics();
            }

            // from this point forward, in this configure/use/release lifecycle, we want to
            // upload our data
            mMetricsToUpload = true;

            int32_t push;
            if (msg->findInt32("push-blank-buffers-on-shutdown", &push) && push != 0) {
                mFlags |= kFlagPushBlankBuffersOnShutdown;
            }

            if (obj != NULL) {
                if (!format->findInt32(KEY_ALLOW_FRAME_DROP, &mAllowFrameDroppingBySurface)) {
                    // allow frame dropping by surface by default
                    mAllowFrameDroppingBySurface = true;
                }

                format->setObject("native-window", obj);
                status_t err = handleSetSurface(static_cast<Surface *>(obj.get()));
                if (err != OK) {
                    PostReplyWithError(replyID, err);
                    break;
                }
                uint32_t generation = mSurfaceGeneration;
                format->setInt32("native-window-generation", generation);
            } else {
                // we are not using surface so this variable is not used, but initialize sensibly anyway
                mAllowFrameDroppingBySurface = false;

                handleSetSurface(NULL);
            }

            mApiUsageMetrics.isUsingOutputSurface = true;

            uint32_t flags;
            CHECK(msg->findInt32("flags", (int32_t *)&flags));
            if (flags & CONFIGURE_FLAG_USE_BLOCK_MODEL ||
                flags & CONFIGURE_FLAG_USE_CRYPTO_ASYNC) {
                if (!(mFlags & kFlagIsAsync)) {
                    mErrorLog.log(
                            LOG_TAG, "Block model is only valid with callback set (async mode)");
                    PostReplyWithError(replyID, INVALID_OPERATION);
                    break;
                }
                if (flags & CONFIGURE_FLAG_USE_BLOCK_MODEL) {
                    mFlags |= kFlagUseBlockModel;
                }
                if (flags & CONFIGURE_FLAG_USE_CRYPTO_ASYNC) {
                    mFlags |= kFlagUseCryptoAsync;
                    if ((mFlags & kFlagUseBlockModel)) {
                        ALOGW("CrytoAsync not yet enabled for block model,\
                                falling back to normal");
                    }
                }
            }
            int32_t largeFrameParamMax = 0, largeFrameParamThreshold = 0;
            if (format->findInt32(KEY_BUFFER_BATCH_MAX_OUTPUT_SIZE, &largeFrameParamMax) ||
                    format->findInt32(KEY_BUFFER_BATCH_THRESHOLD_OUTPUT_SIZE,
                    &largeFrameParamThreshold)) {
                if (largeFrameParamMax > 0 || largeFrameParamThreshold > 0) {
                    if(mComponentName.startsWith("OMX")) {
                        mErrorLog.log(LOG_TAG,
                                "Large Frame params are not supported on OMX codecs."
                                "Currently only supported on C2 audio codec.");
                        PostReplyWithError(replyID, INVALID_OPERATION);
                        break;
                    }
                    AString mime;
                    CHECK(format->findString("mime", &mime));
                    if (!mime.startsWith("audio")) {
                        mErrorLog.log(LOG_TAG,
                                "Large Frame params only works with audio codec");
                        PostReplyWithError(replyID, INVALID_OPERATION);
                        break;
                    }
                    if (!(mFlags & kFlagIsAsync)) {
                            mErrorLog.log(LOG_TAG, "Large Frame audio" \
                                    "config works only with async mode");
                        PostReplyWithError(replyID, INVALID_OPERATION);
                        break;
                    }
                }
            }

            mReplyID = replyID;
            setState(CONFIGURING);

            void *crypto;
            if (!msg->findPointer("crypto", &crypto)) {
                crypto = NULL;
            }

            ALOGV("kWhatConfigure: Old mCrypto: %p (%d)",
                    mCrypto.get(), (mCrypto != NULL ? mCrypto->getStrongCount() : 0));

            mCrypto = static_cast<ICrypto *>(crypto);
            mBufferChannel->setCrypto(mCrypto);

            ALOGV("kWhatConfigure: New mCrypto: %p (%d)",
                    mCrypto.get(), (mCrypto != NULL ? mCrypto->getStrongCount() : 0));

            void *descrambler;
            if (!msg->findPointer("descrambler", &descrambler)) {
                descrambler = NULL;
            }

            mDescrambler = static_cast<IDescrambler *>(descrambler);
            mBufferChannel->setDescrambler(mDescrambler);
            if ((mFlags & kFlagUseCryptoAsync) &&
                mCrypto  && (mDomain == DOMAIN_VIDEO)) {
                // set kFlagUseCryptoAsync but do-not use this for block model
                // this is to propagate the error in onCryptoError()
                // TODO (b/274628160): Enable Use of CONFIG_FLAG_USE_CRYPTO_ASYNC
                //                     with CONFIGURE_FLAG_USE_BLOCK_MODEL)
                if (!(mFlags & kFlagUseBlockModel)) {
                    mCryptoAsync = new CryptoAsync(mBufferChannel);
                    mCryptoAsync->setCallback(
                    std::make_unique<CryptoAsyncCallback>(new AMessage(kWhatCodecNotify, this)));
                    mCryptoLooper = new ALooper();
                    mCryptoLooper->setName("CryptoAsyncLooper");
                    mCryptoLooper->registerHandler(mCryptoAsync);
                    status_t err = mCryptoLooper->start();
                    if (err != OK) {
                        ALOGE("Crypto Looper failed to start");
                        mCryptoAsync = nullptr;
                        mCryptoLooper = nullptr;
                    }
                }
            }

            format->setInt32("flags", flags);
            if (flags & CONFIGURE_FLAG_ENCODE) {
                format->setInt32("encoder", true);
                mFlags |= kFlagIsEncoder;
            }

            extractCSD(format);

            int32_t tunneled;
            if (format->findInt32("feature-tunneled-playback", &tunneled) && tunneled != 0) {
                ALOGI("Configuring TUNNELED video playback.");
                mTunneled = true;
            } else {
                mTunneled = false;
            }
            mediametrics_setInt32(mMetricsHandle, kCodecTunneled, mTunneled ? 1 : 0);

            int32_t background = 0;
            if (format->findInt32("android._background-mode", &background) && background) {
                androidSetThreadPriority(gettid(), ANDROID_PRIORITY_BACKGROUND);
            }

            mCodec->initiateConfigureComponent(format);
            break;
        }

        case kWhatSetSurface:
        {
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));

            status_t err = OK;

            switch (mState) {
                case CONFIGURED:
                case STARTED:
                case FLUSHED:
                {
                    sp<RefBase> obj;
                    (void)msg->findObject("surface", &obj);
                    sp<Surface> surface = static_cast<Surface *>(obj.get());
                    if (mSurface == NULL) {
                        // do not support setting surface if it was not set
                        mErrorLog.log(LOG_TAG,
                                      "Cannot set surface if the codec is not configured with "
                                      "a surface already");
                        err = INVALID_OPERATION;
                    } else if (obj == NULL) {
                        // do not support unsetting surface
                        mErrorLog.log(LOG_TAG, "Unsetting surface is not supported");
                        err = BAD_VALUE;
                    } else {
                        uint32_t generation;
                        err = connectToSurface(surface, &generation);
                        if (err == ALREADY_EXISTS) {
                            // reconnecting to same surface
                            err = OK;
                        } else {
                            if (err == OK) {
                                if (mFlags & kFlagUsesSoftwareRenderer) {
                                    if (mSoftRenderer != NULL
                                            && (mFlags & kFlagPushBlankBuffersOnShutdown)) {
                                        pushBlankBuffersToNativeWindow(mSurface.get());
                                    }
                                    surface->setDequeueTimeout(-1);
                                    mSoftRenderer = new SoftwareRenderer(surface);
                                    // TODO: check if this was successful
                                } else {
                                    err = mCodec->setSurface(surface, generation);
                                }
                            }
                            if (err == OK) {
                                (void)disconnectFromSurface();
                                mSurface = surface;
                                mSurfaceGeneration = generation;
                            }
                            mReliabilityContextMetrics.setOutputSurfaceCount++;
                        }
                    }
                    break;
                }

                default:
                    mErrorLog.log(LOG_TAG, base::StringPrintf(
                            "setSurface() is valid only at Executing states; currently %s",
                            apiStateString().c_str()));
                    err = INVALID_OPERATION;
                    break;
            }

            PostReplyWithError(replyID, err);
            break;
        }

        case kWhatCreateInputSurface:
        case kWhatSetInputSurface:
        {
            // Must be configured, but can't have been started yet.
            if (mState != CONFIGURED) {
                mErrorLog.log(LOG_TAG, base::StringPrintf(
                        "setInputSurface() is valid only at Configured state; currently %s",
                        apiStateString().c_str()));
                PostReplyWithError(msg, INVALID_OPERATION);
                break;
            }

            if (mReplyID) {
                mDeferredMessages.push_back(msg);
                break;
            }
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));

            mReplyID = replyID;
            if (msg->what() == kWhatCreateInputSurface) {
                mCodec->initiateCreateInputSurface();
            } else {
                sp<RefBase> obj;
                CHECK(msg->findObject("input-surface", &obj));

                mCodec->initiateSetInputSurface(
                        static_cast<PersistentSurface *>(obj.get()));
            }
            break;
        }
        case kWhatStart:
        {
            if (mState == FLUSHED) {
                setState(STARTED);
                if (mHavePendingInputBuffers) {
                    onInputBufferAvailable();
                    mHavePendingInputBuffers = false;
                }
                mCodec->signalResume();
                PostReplyWithError(msg, OK);
                break;
            } else if (mState != CONFIGURED) {
                mErrorLog.log(LOG_TAG, base::StringPrintf(
                        "start() is valid only at Configured state; currently %s",
                        apiStateString().c_str()));
                PostReplyWithError(msg, INVALID_OPERATION);
                break;
            }

            if (mReplyID) {
                mDeferredMessages.push_back(msg);
                break;
            }
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));
            TunnelPeekState previousState = mTunnelPeekState;
            if (previousState != TunnelPeekState::kLegacyMode) {
                mTunnelPeekState = mTunnelPeekEnabled ? TunnelPeekState::kEnabledNoBuffer :
                    TunnelPeekState::kDisabledNoBuffer;
                ALOGV("TunnelPeekState: %s -> %s",
                        asString(previousState),
                        asString(mTunnelPeekState));
            }

            mReplyID = replyID;
            setState(STARTING);

            mCodec->initiateStart();
            break;
        }

        case kWhatStop: {
            if (mReplyID) {
                mDeferredMessages.push_back(msg);
                break;
            }
            [[fallthrough]];
        }
        case kWhatRelease:
        {
            State targetState =
                (msg->what() == kWhatStop) ? INITIALIZED : UNINITIALIZED;

            if ((mState == RELEASING && targetState == UNINITIALIZED)
                    || (mState == STOPPING && targetState == INITIALIZED)) {
                mDeferredMessages.push_back(msg);
                break;
            }

            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));
            if (mCryptoAsync) {
                mCryptoAsync->stop();
            }
            sp<AMessage> asyncNotify;
            (void)msg->findMessage("async", &asyncNotify);
            // post asyncNotify if going out of scope.
            struct AsyncNotifyPost {
                AsyncNotifyPost(const sp<AMessage> &asyncNotify) : mAsyncNotify(asyncNotify) {}
                ~AsyncNotifyPost() {
                    if (mAsyncNotify) {
                        mAsyncNotify->post();
                    }
                }
                void clear() { mAsyncNotify.clear(); }
            private:
                sp<AMessage> mAsyncNotify;
            } asyncNotifyPost{asyncNotify};

            // already stopped/released
            if (mState == UNINITIALIZED && mReleasedByResourceManager) {
                sp<AMessage> response = new AMessage;
                response->setInt32("err", OK);
                response->postReply(replyID);
                break;
            }

            int32_t reclaimed = 0;
            msg->findInt32("reclaimed", &reclaimed);
            if (reclaimed) {
                if (!mReleasedByResourceManager) {
                    // notify the async client
                    if (mFlags & kFlagIsAsync) {
                        onError(DEAD_OBJECT, ACTION_CODE_FATAL);
                    }
                    mErrorLog.log(LOG_TAG, "Released by resource manager");
                    mReleasedByResourceManager = true;
                }

                int32_t force = 0;
                msg->findInt32("force", &force);
                if (!force && hasPendingBuffer()) {
                    ALOGW("Can't reclaim codec right now due to pending buffers.");

                    // return WOULD_BLOCK to ask resource manager to retry later.
                    sp<AMessage> response = new AMessage;
                    response->setInt32("err", WOULD_BLOCK);
                    response->postReply(replyID);

                    break;
                }
            }

            bool isReleasingAllocatedComponent =
                    (mFlags & kFlagIsComponentAllocated) && targetState == UNINITIALIZED;
            if (!isReleasingAllocatedComponent // See 1
                    && mState != INITIALIZED
                    && mState != CONFIGURED && !isExecuting()) {
                // 1) Permit release to shut down the component if allocated.
                //
                // 2) We may be in "UNINITIALIZED" state already and
                // also shutdown the encoder/decoder without the
                // client being aware of this if media server died while
                // we were being stopped. The client would assume that
                // after stop() returned, it would be safe to call release()
                // and it should be in this case, no harm to allow a release()
                // if we're already uninitialized.
                sp<AMessage> response = new AMessage;
                // TODO: we shouldn't throw an exception for stop/release. Change this to wait until
                // the previous stop/release completes and then reply with OK.
                status_t err = mState == targetState ? OK : INVALID_OPERATION;
                response->setInt32("err", err);
                // TODO: mErrorLog
                if (err == OK && targetState == UNINITIALIZED) {
                    mComponentName.clear();
                }
                response->postReply(replyID);
                break;
            }

            // If we're flushing, configuring or starting  but
            // received a release request, post the reply for the pending call
            // first, and consider it done. The reply token will be replaced
            // after this, and we'll no longer be able to reply.
            if (mState == FLUSHING || mState == CONFIGURING || mState == STARTING) {
                // mReply is always set if in these states.
                postPendingRepliesAndDeferredMessages(
                        std::string("kWhatRelease:") + stateString(mState));
            }
            // If we're stopping but received a release request, post the reply
            // for the pending call if necessary. Note that the reply may have been
            // already posted due to an error.
            if (mState == STOPPING && mReplyID) {
                postPendingRepliesAndDeferredMessages("kWhatRelease:STOPPING");
            }

            if (mFlags & kFlagSawMediaServerDie) {
                // It's dead, Jim. Don't expect initiateShutdown to yield
                // any useful results now...
                // Any pending reply would have been handled at kWhatError.
                setState(UNINITIALIZED);
                if (targetState == UNINITIALIZED) {
                    mComponentName.clear();
                }
                (new AMessage)->postReply(replyID);
                break;
            }

            // If we already have an error, component may not be able to
            // complete the shutdown properly. If we're stopping, post the
            // reply now with an error to unblock the client, client can
            // release after the failure (instead of ANR).
            if (msg->what() == kWhatStop && (mFlags & kFlagStickyError)) {
                // Any pending reply would have been handled at kWhatError.
                PostReplyWithError(replyID, getStickyError());
                break;
            }

            bool forceSync = false;
            if (asyncNotify != nullptr && mSurface != NULL) {
                if (!mReleaseSurface) {
                    uint64_t usage = 0;
                    if (mSurface->getConsumerUsage(&usage) != OK) {
                        usage = 0;
                    }
                    mReleaseSurface.reset(new ReleaseSurface(usage));
                }
                if (mSurface != mReleaseSurface->getSurface()) {
                    uint32_t generation;
                    status_t err = connectToSurface(mReleaseSurface->getSurface(), &generation);
                    ALOGW_IF(err != OK, "error connecting to release surface: err = %d", err);
                    if (err == OK && !(mFlags & kFlagUsesSoftwareRenderer)) {
                        err = mCodec->setSurface(mReleaseSurface->getSurface(), generation);
                        ALOGW_IF(err != OK, "error setting release surface: err = %d", err);
                    }
                    if (err == OK) {
                        (void)disconnectFromSurface();
                        mSurface = mReleaseSurface->getSurface();
                        mSurfaceGeneration = generation;
                    } else {
                        // We were not able to switch the surface, so force
                        // synchronous release.
                        forceSync = true;
                    }
                }
            }

            if (mReplyID) {
                // State transition replies are handled above, so this reply
                // would not be related to state transition. As we are
                // shutting down the component, just fail the operation.
                postPendingRepliesAndDeferredMessages("kWhatRelease:reply", UNKNOWN_ERROR);
            }
            mReplyID = replyID;
            setState(msg->what() == kWhatStop ? STOPPING : RELEASING);

            mCodec->initiateShutdown(
                    msg->what() == kWhatStop /* keepComponentAllocated */);

            returnBuffersToCodec(reclaimed);

            if (mSoftRenderer != NULL && (mFlags & kFlagPushBlankBuffersOnShutdown)) {
                pushBlankBuffersToNativeWindow(mSurface.get());
            }

            if (asyncNotify != nullptr) {
                if (!forceSync) {
                    mResourceManagerProxy->markClientForPendingRemoval();
                    postPendingRepliesAndDeferredMessages("kWhatRelease:async");
                }
                asyncNotifyPost.clear();
                mAsyncReleaseCompleteNotification = asyncNotify;
            }

            break;
        }

        case kWhatDequeueInputBuffer:
        {
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));

            if (mFlags & kFlagIsAsync) {
                mErrorLog.log(LOG_TAG, "dequeueInputBuffer can't be used in async mode");
                PostReplyWithError(replyID, INVALID_OPERATION);
                break;
            }

            if (mHaveInputSurface) {
                mErrorLog.log(LOG_TAG, "dequeueInputBuffer can't be used with input surface");
                PostReplyWithError(replyID, INVALID_OPERATION);
                break;
            }

            if (handleDequeueInputBuffer(replyID, true /* new request */)) {
                break;
            }

            int64_t timeoutUs;
            CHECK(msg->findInt64("timeoutUs", &timeoutUs));

            if (timeoutUs == 0LL) {
                PostReplyWithError(replyID, -EAGAIN);
                break;
            }

            mFlags |= kFlagDequeueInputPending;
            mDequeueInputReplyID = replyID;

            if (timeoutUs > 0LL) {
                sp<AMessage> timeoutMsg =
                    new AMessage(kWhatDequeueInputTimedOut, this);
                timeoutMsg->setInt32(
                        "generation", ++mDequeueInputTimeoutGeneration);
                timeoutMsg->post(timeoutUs);
            }
            break;
        }

        case kWhatDequeueInputTimedOut:
        {
            int32_t generation;
            CHECK(msg->findInt32("generation", &generation));

            if (generation != mDequeueInputTimeoutGeneration) {
                // Obsolete
                break;
            }

            CHECK(mFlags & kFlagDequeueInputPending);

            PostReplyWithError(mDequeueInputReplyID, -EAGAIN);

            mFlags &= ~kFlagDequeueInputPending;
            mDequeueInputReplyID = 0;
            break;
        }

        case kWhatQueueInputBuffer:
        {
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));

            if (!isExecuting()) {
                mErrorLog.log(LOG_TAG, base::StringPrintf(
                        "queueInputBuffer() is valid only at Executing states; currently %s",
                        apiStateString().c_str()));
                PostReplyWithError(replyID, INVALID_OPERATION);
                break;
            } else if (mFlags & kFlagStickyError) {
                PostReplyWithError(replyID, getStickyError());
                break;
            }

            status_t err = UNKNOWN_ERROR;
            if (!mLeftover.empty()) {
                mLeftover.push_back(msg);
                size_t index;
                msg->findSize("index", &index);
                err = handleLeftover(index);
            } else {
                err = onQueueInputBuffer(msg);
            }

            PostReplyWithError(replyID, err);
            break;
        }

        case kWhatDequeueOutputBuffer:
        {
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));

            if (mFlags & kFlagIsAsync) {
                mErrorLog.log(LOG_TAG, "dequeueOutputBuffer can't be used in async mode");
                PostReplyWithError(replyID, INVALID_OPERATION);
                break;
            }

            DequeueOutputResult dequeueResult =
                handleDequeueOutputBuffer(replyID, true /* new request */);
            switch (dequeueResult) {
                case DequeueOutputResult::kNoBuffer:
                    [[fallthrough]];
                case DequeueOutputResult::kDiscardedBuffer:
                {
                    int64_t timeoutUs;
                    CHECK(msg->findInt64("timeoutUs", &timeoutUs));

                    if (timeoutUs == 0LL) {
                        PostReplyWithError(replyID, -EAGAIN);
                        break;
                    }

                    mFlags |= kFlagDequeueOutputPending;
                    mDequeueOutputReplyID = replyID;

                    if (timeoutUs > 0LL) {
                        sp<AMessage> timeoutMsg =
                            new AMessage(kWhatDequeueOutputTimedOut, this);
                        timeoutMsg->setInt32(
                                "generation", ++mDequeueOutputTimeoutGeneration);
                        timeoutMsg->post(timeoutUs);
                    }
                    break;
                }
                case DequeueOutputResult::kRepliedWithError:
                    [[fallthrough]];
                case DequeueOutputResult::kSuccess:
                    break;
                default:
                    TRESPASS();
            }
            break;
        }

        case kWhatDequeueOutputTimedOut:
        {
            int32_t generation;
            CHECK(msg->findInt32("generation", &generation));

            if (generation != mDequeueOutputTimeoutGeneration) {
                // Obsolete
                break;
            }

            CHECK(mFlags & kFlagDequeueOutputPending);

            PostReplyWithError(mDequeueOutputReplyID, -EAGAIN);

            mFlags &= ~kFlagDequeueOutputPending;
            mDequeueOutputReplyID = 0;
            break;
        }

        case kWhatReleaseOutputBuffer:
        {
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));

            if (!isExecuting()) {
                mErrorLog.log(LOG_TAG, base::StringPrintf(
                        "releaseOutputBuffer() is valid only at Executing states; currently %s",
                        apiStateString().c_str()));
                PostReplyWithError(replyID, INVALID_OPERATION);
                break;
            } else if (mFlags & kFlagStickyError) {
                PostReplyWithError(replyID, getStickyError());
                break;
            }

            status_t err = onReleaseOutputBuffer(msg);

            PostReplyWithError(replyID, err);
            break;
        }

        case kWhatPollForRenderedBuffers:
        {
            if (isExecuting()) {
                mBufferChannel->pollForRenderedBuffers();
            }
            break;
        }

        case kWhatSignalEndOfInputStream:
        {
            if (!isExecuting()) {
                mErrorLog.log(LOG_TAG, base::StringPrintf(
                        "signalEndOfInputStream() is valid only at Executing states; currently %s",
                        apiStateString().c_str()));
                PostReplyWithError(msg, INVALID_OPERATION);
                break;
            } else if (!mHaveInputSurface) {
                mErrorLog.log(
                        LOG_TAG, "signalEndOfInputStream() called without an input surface set");
                PostReplyWithError(msg, INVALID_OPERATION);
                break;
            } else if (mFlags & kFlagStickyError) {
                PostReplyWithError(msg, getStickyError());
                break;
            }

            if (mReplyID) {
                mDeferredMessages.push_back(msg);
                break;
            }
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));

            mReplyID = replyID;
            mCodec->signalEndOfInputStream();
            break;
        }

        case kWhatGetBuffers:
        {
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));
            if (!isExecuting()) {
                mErrorLog.log(LOG_TAG, base::StringPrintf(
                        "getInput/OutputBuffers() is valid only at Executing states; currently %s",
                        apiStateString().c_str()));
                PostReplyWithError(replyID, INVALID_OPERATION);
                break;
            } else if (mFlags & kFlagIsAsync) {
                mErrorLog.log(LOG_TAG, "getInput/OutputBuffers() is not supported with callbacks");
                PostReplyWithError(replyID, INVALID_OPERATION);
                break;
            } else if (mFlags & kFlagStickyError) {
                PostReplyWithError(replyID, getStickyError());
                break;
            }

            int32_t portIndex;
            CHECK(msg->findInt32("portIndex", &portIndex));

            Vector<sp<MediaCodecBuffer> > *dstBuffers;
            CHECK(msg->findPointer("buffers", (void **)&dstBuffers));

            dstBuffers->clear();
            // If we're using input surface (either non-persistent created by
            // createInputSurface(), or persistent set by setInputSurface()),
            // give the client an empty input buffers array.
            if (portIndex != kPortIndexInput || !mHaveInputSurface) {
                if (portIndex == kPortIndexInput) {
                    mBufferChannel->getInputBufferArray(dstBuffers);
                } else {
                    mBufferChannel->getOutputBufferArray(dstBuffers);
                }
            }

            mApiUsageMetrics.isArrayMode = true;

            (new AMessage)->postReply(replyID);
            break;
        }

        case kWhatFlush:
        {
            if (!isExecuting()) {
                mErrorLog.log(LOG_TAG, base::StringPrintf(
                        "flush() is valid only at Executing states; currently %s",
                        apiStateString().c_str()));
                PostReplyWithError(msg, INVALID_OPERATION);
                break;
            } else if (mFlags & kFlagStickyError) {
                PostReplyWithError(msg, getStickyError());
                break;
            }

            if (mReplyID) {
                mDeferredMessages.push_back(msg);
                break;
            }
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));

            mReplyID = replyID;
            // TODO: skip flushing if already FLUSHED
            setState(FLUSHING);
            if (mCryptoAsync) {
                std::list<sp<AMessage>> pendingBuffers;
                mCryptoAsync->stop(&pendingBuffers);
                //TODO: do something with these buffers
            }
            mCodec->signalFlush();
            returnBuffersToCodec();
            TunnelPeekState previousState = mTunnelPeekState;
            if (previousState != TunnelPeekState::kLegacyMode) {
                mTunnelPeekState = mTunnelPeekEnabled ? TunnelPeekState::kEnabledNoBuffer :
                    TunnelPeekState::kDisabledNoBuffer;
                ALOGV("TunnelPeekState: %s -> %s",
                        asString(previousState),
                        asString(mTunnelPeekState));
            }
            break;
        }

        case kWhatGetInputFormat:
        case kWhatGetOutputFormat:
        {
            sp<AMessage> format =
                (msg->what() == kWhatGetOutputFormat ? mOutputFormat : mInputFormat);

            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));

            if (mState != CONFIGURED && mState != STARTING &&
                    mState != STARTED && mState != FLUSHING &&
                    mState != FLUSHED) {
                mErrorLog.log(LOG_TAG, base::StringPrintf(
                        "getInput/OutputFormat() is valid at Executing states "
                        "and Configured state; currently %s",
                        apiStateString().c_str()));
                PostReplyWithError(replyID, INVALID_OPERATION);
                break;
            } else if (format == NULL) {
                mErrorLog.log(LOG_TAG, "Fatal error: format is not initialized");
                PostReplyWithError(replyID, INVALID_OPERATION);
                break;
            } else if (mFlags & kFlagStickyError) {
                PostReplyWithError(replyID, getStickyError());
                break;
            }

            sp<AMessage> response = new AMessage;
            response->setMessage("format", format);
            response->postReply(replyID);
            break;
        }

        case kWhatRequestIDRFrame:
        {
            mCodec->signalRequestIDRFrame();
            break;
        }

        case kWhatRequestActivityNotification:
        {
            CHECK(mActivityNotify == NULL);
            CHECK(msg->findMessage("notify", &mActivityNotify));

            postActivityNotificationIfPossible();
            break;
        }

        case kWhatGetName:
        {
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));

            if (mComponentName.empty()) {
                mErrorLog.log(LOG_TAG, "Fatal error: name is not set");
                PostReplyWithError(replyID, INVALID_OPERATION);
                break;
            }

            sp<AMessage> response = new AMessage;
            response->setString("name", mComponentName.c_str());
            response->postReply(replyID);
            break;
        }

        case kWhatGetCodecInfo:
        {
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));

            sp<AMessage> response = new AMessage;
            response->setObject("codecInfo", mCodecInfo);
            response->postReply(replyID);
            break;
        }

        case kWhatSetParameters:
        {
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));

            sp<AMessage> params;
            CHECK(msg->findMessage("params", &params));

            status_t err = onSetParameters(params);

            PostReplyWithError(replyID, err);
            break;
        }

        case kWhatDrmReleaseCrypto:
        {
            onReleaseCrypto(msg);
            break;
        }

        case kWhatCheckBatteryStats:
        {
            if (mBatteryChecker != nullptr) {
                mBatteryChecker->onCheckBatteryTimer(msg, [this] () {
                    mResourceManagerProxy->removeResource(
                            MediaResource::VideoBatteryResource(mIsHardware));
                });
            }
            break;
        }

        default:
            TRESPASS();
    }
}

void MediaCodec::handleOutputFormatChangeIfNeeded(const sp<MediaCodecBuffer> &buffer) {
    sp<AMessage> format = buffer->format();
    if (mOutputFormat == format) {
        return;
    }
    if (mFlags & kFlagUseBlockModel) {
        sp<AMessage> diff1 = mOutputFormat->changesFrom(format);
        sp<AMessage> diff2 = format->changesFrom(mOutputFormat);
        std::set<std::string> keys;
        size_t numEntries = diff1->countEntries();
        AMessage::Type type;
        for (size_t i = 0; i < numEntries; ++i) {
            keys.emplace(diff1->getEntryNameAt(i, &type));
        }
        numEntries = diff2->countEntries();
        for (size_t i = 0; i < numEntries; ++i) {
            keys.emplace(diff2->getEntryNameAt(i, &type));
        }
        sp<WrapperObject<std::set<std::string>>> changedKeys{
            new WrapperObject<std::set<std::string>>{std::move(keys)}};
        buffer->meta()->setObject("changedKeys", changedKeys);
    }
    mOutputFormat = format;
    mapFormat(mComponentName, format, nullptr, true);
    ALOGV("[%s] output format changed to: %s",
            mComponentName.c_str(), mOutputFormat->debugString(4).c_str());

    if (mSoftRenderer == NULL &&
            mSurface != NULL &&
            (mFlags & kFlagUsesSoftwareRenderer)) {
        AString mime;
        CHECK(mOutputFormat->findString("mime", &mime));

        // TODO: propagate color aspects to software renderer to allow better
        // color conversion to RGB. For now, just mark dataspace for YUV
        // rendering.
        int32_t dataSpace;
        if (mOutputFormat->findInt32("android._dataspace", &dataSpace)) {
            ALOGD("[%s] setting dataspace on output surface to %#x",
                    mComponentName.c_str(), dataSpace);
            int err = native_window_set_buffers_data_space(
                    mSurface.get(), (android_dataspace)dataSpace);
            ALOGW_IF(err != 0, "failed to set dataspace on surface (%d)", err);
        }
        if (mOutputFormat->contains("hdr-static-info")) {
            HDRStaticInfo info;
            if (ColorUtils::getHDRStaticInfoFromFormat(mOutputFormat, &info)) {
                setNativeWindowHdrMetadata(mSurface.get(), &info);
            }
        }

        sp<ABuffer> hdr10PlusInfo;
        if (mOutputFormat->findBuffer("hdr10-plus-info", &hdr10PlusInfo)
                && hdr10PlusInfo != nullptr && hdr10PlusInfo->size() > 0) {
            native_window_set_buffers_hdr10_plus_metadata(mSurface.get(),
                    hdr10PlusInfo->size(), hdr10PlusInfo->data());
        }

        if (mime.startsWithIgnoreCase("video/")) {
            mSurface->setDequeueTimeout(-1);
            mSoftRenderer = new SoftwareRenderer(mSurface, mRotationDegrees);
        }
    }

    requestCpuBoostIfNeeded();

    if (mFlags & kFlagIsEncoder) {
        // Before we announce the format change we should
        // collect codec specific data and amend the output
        // format as necessary.
        int32_t flags = 0;
        (void) buffer->meta()->findInt32("flags", &flags);
        if ((flags & BUFFER_FLAG_CODECCONFIG) && !(mFlags & kFlagIsSecure)
                && !mOwnerName.startsWith("codec2::")) {
            status_t err =
                amendOutputFormatWithCodecSpecificData(buffer);

            if (err != OK) {
                ALOGE("Codec spit out malformed codec "
                      "specific data!");
            }
        }
    }
    if (mFlags & kFlagIsAsync) {
        onOutputFormatChanged();
    } else {
        mFlags |= kFlagOutputFormatChanged;
        postActivityNotificationIfPossible();
    }

    // Update the width and the height.
    int32_t left = 0, top = 0, right = 0, bottom = 0, width = 0, height = 0;
    bool resolutionChanged = false;
    if (mOutputFormat->findRect("crop", &left, &top, &right, &bottom)) {
        mWidth = right - left + 1;
        mHeight = bottom - top + 1;
        resolutionChanged = true;
    } else if (mOutputFormat->findInt32("width", &width) &&
               mOutputFormat->findInt32("height", &height)) {
        mWidth = width;
        mHeight = height;
        resolutionChanged = true;
    }

    // Notify mCrypto and the RM of video resolution changes
    if (resolutionChanged) {
        if (mCrypto != NULL) {
            mCrypto->notifyResolution(mWidth, mHeight);
        }
        ClientConfigParcel clientConfig;
        initClientConfigParcel(clientConfig);
        mResourceManagerProxy->notifyClientConfigChanged(clientConfig);
        mReliabilityContextMetrics.resolutionChangeCount++;
    }

    updateHdrMetrics(false /* isConfig */);
 }

void MediaCodec::extractCSD(const sp<AMessage> &format) {
    mCSD.clear();

    size_t i = 0;
    for (;;) {
        sp<ABuffer> csd;
        if (!format->findBuffer(base::StringPrintf("csd-%zu", i).c_str(), &csd)) {
            break;
        }
        if (csd->size() == 0) {
            ALOGW("csd-%zu size is 0", i);
        }

        mCSD.push_back(csd);
        ++i;
    }

    ALOGV("Found %zu pieces of codec specific data.", mCSD.size());
}

status_t MediaCodec::queueCSDInputBuffer(size_t bufferIndex) {
    CHECK(!mCSD.empty());

    sp<ABuffer> csd = *mCSD.begin();
    mCSD.erase(mCSD.begin());
    std::shared_ptr<C2Buffer> c2Buffer;
    sp<hardware::HidlMemory> memory;

    if (mFlags & kFlagUseBlockModel) {
        if (hasCryptoOrDescrambler()) {
            constexpr size_t kInitialDealerCapacity = 1048576;  // 1MB
            thread_local sp<MemoryDealer> sDealer = new MemoryDealer(
                    kInitialDealerCapacity, "CSD(1MB)");
            sp<IMemory> mem = sDealer->allocate(csd->size());
            if (mem == nullptr) {
                size_t newDealerCapacity = sDealer->getMemoryHeap()->getSize() * 2;
                while (csd->size() * 2 > newDealerCapacity) {
                    newDealerCapacity *= 2;
                }
                sDealer = new MemoryDealer(
                        newDealerCapacity,
                        base::StringPrintf("CSD(%zuMB)", newDealerCapacity / 1048576).c_str());
                mem = sDealer->allocate(csd->size());
            }
            memcpy(mem->unsecurePointer(), csd->data(), csd->size());
            ssize_t heapOffset;
            memory = hardware::fromHeap(mem->getMemory(&heapOffset, nullptr));
        } else {
            std::shared_ptr<C2LinearBlock> block =
                FetchLinearBlock(csd->size(), {std::string{mComponentName.c_str()}});
            C2WriteView view{block->map().get()};
            if (view.error() != C2_OK) {
                mErrorLog.log(LOG_TAG, "Fatal error: failed to allocate and map a block");
                return -EINVAL;
            }
            if (csd->size() > view.capacity()) {
                mErrorLog.log(LOG_TAG, base::StringPrintf(
                        "Fatal error: allocated block is too small "
                        "(csd size %zu; block cap %u)",
                        csd->size(), view.capacity()));
                return -EINVAL;
            }
            memcpy(view.base(), csd->data(), csd->size());
            c2Buffer = C2Buffer::CreateLinearBuffer(block->share(0, csd->size(), C2Fence{}));
        }
    } else {
        const BufferInfo &info = mPortBuffers[kPortIndexInput][bufferIndex];
        const sp<MediaCodecBuffer> &codecInputData = info.mData;

        if (csd->size() > codecInputData->capacity()) {
            mErrorLog.log(LOG_TAG, base::StringPrintf(
                    "CSD is too large to fit in input buffer "
                    "(csd size %zu; buffer cap %zu)",
                    csd->size(), codecInputData->capacity()));
            return -EINVAL;
        }
        if (codecInputData->data() == NULL) {
            ALOGV("Input buffer %zu is not properly allocated", bufferIndex);
            mErrorLog.log(LOG_TAG, base::StringPrintf(
                    "Fatal error: input buffer %zu is not properly allocated", bufferIndex));
            return -EINVAL;
        }

        memcpy(codecInputData->data(), csd->data(), csd->size());
    }

    AString errorDetailMsg;

    sp<AMessage> msg = new AMessage(kWhatQueueInputBuffer, this);
    msg->setSize("index", bufferIndex);
    msg->setSize("offset", 0);
    msg->setSize("size", csd->size());
    msg->setInt64("timeUs", 0LL);
    msg->setInt32("flags", BUFFER_FLAG_CODECCONFIG);
    msg->setPointer("errorDetailMsg", &errorDetailMsg);
    if (c2Buffer) {
        sp<WrapperObject<std::shared_ptr<C2Buffer>>> obj{
            new WrapperObject<std::shared_ptr<C2Buffer>>{c2Buffer}};
        msg->setObject("c2buffer", obj);
    } else if (memory) {
        sp<WrapperObject<sp<hardware::HidlMemory>>> obj{
            new WrapperObject<sp<hardware::HidlMemory>>{memory}};
        msg->setObject("memory", obj);
    }

    return onQueueInputBuffer(msg);
}

void MediaCodec::setState(State newState) {
    if (newState == INITIALIZED || newState == UNINITIALIZED) {
        delete mSoftRenderer;
        mSoftRenderer = NULL;

        if ( mCrypto != NULL ) {
            ALOGV("setState: ~mCrypto: %p (%d)",
                    mCrypto.get(), (mCrypto != NULL ? mCrypto->getStrongCount() : 0));
        }
        mCrypto.clear();
        mDescrambler.clear();
        handleSetSurface(NULL);

        mInputFormat.clear();
        mOutputFormat.clear();
        mFlags &= ~kFlagOutputFormatChanged;
        mFlags &= ~kFlagOutputBuffersChanged;
        mFlags &= ~kFlagStickyError;
        mFlags &= ~kFlagIsEncoder;
        mFlags &= ~kFlagIsAsync;
        mStickyError = OK;

        mActivityNotify.clear();
        mCallback.clear();
        mErrorLog.clear();
    }

    if (newState == UNINITIALIZED) {
        // return any straggling buffers, e.g. if we got here on an error
        returnBuffersToCodec();

        // The component is gone, mediaserver's probably back up already
        // but should definitely be back up should we try to instantiate
        // another component.. and the cycle continues.
        mFlags &= ~kFlagSawMediaServerDie;
    }

    mState = newState;

    if (mBatteryChecker != nullptr) {
        mBatteryChecker->setExecuting(isExecuting());
    }

    cancelPendingDequeueOperations();
}

void MediaCodec::returnBuffersToCodec(bool isReclaim) {
    returnBuffersToCodecOnPort(kPortIndexInput, isReclaim);
    returnBuffersToCodecOnPort(kPortIndexOutput, isReclaim);
}

void MediaCodec::returnBuffersToCodecOnPort(int32_t portIndex, bool isReclaim) {
    CHECK(portIndex == kPortIndexInput || portIndex == kPortIndexOutput);
    Mutex::Autolock al(mBufferLock);

    if (portIndex == kPortIndexInput) {
        mLeftover.clear();
    }
    for (size_t i = 0; i < mPortBuffers[portIndex].size(); ++i) {
        BufferInfo *info = &mPortBuffers[portIndex][i];

        if (info->mData != nullptr) {
            sp<MediaCodecBuffer> buffer = info->mData;
            if (isReclaim && info->mOwnedByClient) {
                ALOGD("port %d buffer %zu still owned by client when codec is reclaimed",
                        portIndex, i);
            } else {
                info->mOwnedByClient = false;
                info->mData.clear();
            }
            mBufferChannel->discardBuffer(buffer);
        }
    }

    mAvailPortBuffers[portIndex].clear();
}

size_t MediaCodec::updateBuffers(
        int32_t portIndex, const sp<AMessage> &msg) {
    CHECK(portIndex == kPortIndexInput || portIndex == kPortIndexOutput);
    size_t index;
    CHECK(msg->findSize("index", &index));
    sp<RefBase> obj;
    CHECK(msg->findObject("buffer", &obj));
    sp<MediaCodecBuffer> buffer = static_cast<MediaCodecBuffer *>(obj.get());

    {
        Mutex::Autolock al(mBufferLock);
        if (mPortBuffers[portIndex].size() <= index) {
            mPortBuffers[portIndex].resize(align(index + 1, kNumBuffersAlign));
        }
        mPortBuffers[portIndex][index].mData = buffer;
    }
    mAvailPortBuffers[portIndex].push_back(index);

    return index;
}

status_t MediaCodec::onQueueInputBuffer(const sp<AMessage> &msg) {
    size_t index;
    size_t offset = 0;
    size_t size = 0;
    int64_t timeUs = 0;
    uint32_t flags = 0;
    CHECK(msg->findSize("index", &index));
    CHECK(msg->findInt64("timeUs", &timeUs));
    CHECK(msg->findInt32("flags", (int32_t *)&flags));
    std::shared_ptr<C2Buffer> c2Buffer;
    sp<hardware::HidlMemory> memory;
    sp<RefBase> obj;
    if (msg->findObject("c2buffer", &obj)) {
        CHECK(obj);
        c2Buffer = static_cast<WrapperObject<std::shared_ptr<C2Buffer>> *>(obj.get())->value;
    } else if (msg->findObject("memory", &obj)) {
        CHECK(obj);
        memory = static_cast<WrapperObject<sp<hardware::HidlMemory>> *>(obj.get())->value;
        CHECK(msg->findSize("offset", &offset));
    } else {
        CHECK(msg->findSize("offset", &offset));
    }
    const CryptoPlugin::SubSample *subSamples;
    size_t numSubSamples = 0;
    const uint8_t *key = NULL;
    const uint8_t *iv = NULL;
    CryptoPlugin::Mode mode = CryptoPlugin::kMode_Unencrypted;

    // We allow the simpler queueInputBuffer API to be used even in
    // secure mode, by fabricating a single unencrypted subSample.
    CryptoPlugin::SubSample ss;
    CryptoPlugin::Pattern pattern;

    if (msg->findSize("size", &size)) {
        if (hasCryptoOrDescrambler()) {
            ss.mNumBytesOfClearData = size;
            ss.mNumBytesOfEncryptedData = 0;

            subSamples = &ss;
            numSubSamples = 1;
            pattern.mEncryptBlocks = 0;
            pattern.mSkipBlocks = 0;
        }
    } else if (!c2Buffer) {
        if (!hasCryptoOrDescrambler()) {
            ALOGE("[%s] queuing secure buffer without mCrypto or mDescrambler!",
                    mComponentName.c_str());
            mErrorLog.log(LOG_TAG, "queuing secure buffer without mCrypto or mDescrambler!");
            return -EINVAL;
        }
        CHECK(msg->findPointer("subSamples", (void **)&subSamples));
        CHECK(msg->findSize("numSubSamples", &numSubSamples));
        CHECK(msg->findPointer("key", (void **)&key));
        CHECK(msg->findPointer("iv", (void **)&iv));
        CHECK(msg->findInt32("encryptBlocks", (int32_t *)&pattern.mEncryptBlocks));
        CHECK(msg->findInt32("skipBlocks", (int32_t *)&pattern.mSkipBlocks));

        int32_t tmp;
        CHECK(msg->findInt32("mode", &tmp));

        mode = (CryptoPlugin::Mode)tmp;

        size = 0;
        for (size_t i = 0; i < numSubSamples; ++i) {
            size += subSamples[i].mNumBytesOfClearData;
            size += subSamples[i].mNumBytesOfEncryptedData;
        }
    }

    if (index >= mPortBuffers[kPortIndexInput].size()) {
        mErrorLog.log(LOG_TAG, base::StringPrintf(
                "index out of range (index=%zu)", mPortBuffers[kPortIndexInput].size()));
        return -ERANGE;
    }

    BufferInfo *info = &mPortBuffers[kPortIndexInput][index];
    sp<MediaCodecBuffer> buffer = info->mData;
    if (buffer == nullptr) {
        mErrorLog.log(LOG_TAG, base::StringPrintf(
                "Fatal error: failed to fetch buffer for index %zu", index));
        return -EACCES;
    }
    if (!info->mOwnedByClient) {
        mErrorLog.log(LOG_TAG, base::StringPrintf(
                "client does not own the buffer #%zu", index));
        return -EACCES;
    }
    auto setInputBufferParams = [this, &msg, &buffer]
        (int64_t timeUs, uint32_t flags = 0) -> status_t {
        status_t err = OK;
        sp<RefBase> obj;
        if (msg->findObject("accessUnitInfo", &obj)) {
                buffer->meta()->setObject("accessUnitInfo", obj);
        }
        buffer->meta()->setInt64("timeUs", timeUs);
        if (flags & BUFFER_FLAG_EOS) {
            buffer->meta()->setInt32("eos", true);
        }

        if (flags & BUFFER_FLAG_CODECCONFIG) {
            buffer->meta()->setInt32("csd", true);
        }
        bool isBufferDecodeOnly = ((flags & BUFFER_FLAG_DECODE_ONLY) != 0);
        if (isBufferDecodeOnly) {
            buffer->meta()->setInt32("decode-only", true);
        }
        if (mTunneled && !isBufferDecodeOnly && !(flags & BUFFER_FLAG_CODECCONFIG)) {
            TunnelPeekState previousState = mTunnelPeekState;
            switch(mTunnelPeekState){
                case TunnelPeekState::kEnabledNoBuffer:
                    buffer->meta()->setInt32("tunnel-first-frame", 1);
                    mTunnelPeekState = TunnelPeekState::kEnabledQueued;
                    ALOGV("TunnelPeekState: %s -> %s",
                        asString(previousState),
                        asString(mTunnelPeekState));
                break;
                case TunnelPeekState::kDisabledNoBuffer:
                    buffer->meta()->setInt32("tunnel-first-frame", 1);
                    mTunnelPeekState = TunnelPeekState::kDisabledQueued;
                    ALOGV("TunnelPeekState: %s -> %s",
                        asString(previousState),
                        asString(mTunnelPeekState));
                break;
            default:
                break;
           }
        }
     return err;
    };
    auto buildCryptoInfoAMessage = [&](const sp<AMessage> & cryptoInfo, int32_t action) {
        size_t key_len = (key != nullptr)? 16 : 0;
        size_t iv_len = (iv != nullptr)? 16 : 0;
        sp<ABuffer> shared_key;
        sp<ABuffer> shared_iv;
        if (key_len > 0) {
            shared_key = ABuffer::CreateAsCopy((void*)key, key_len);
        }
        if (iv_len > 0) {
            shared_iv = ABuffer::CreateAsCopy((void*)iv, iv_len);
        }
        sp<ABuffer> subSamples_buffer =
            new ABuffer(sizeof(CryptoPlugin::SubSample) * numSubSamples);
        CryptoPlugin::SubSample * samples =
           (CryptoPlugin::SubSample *)(subSamples_buffer.get()->data());
        for (int s = 0 ; s < numSubSamples ; s++) {
            samples[s].mNumBytesOfClearData = subSamples[s].mNumBytesOfClearData;
            samples[s].mNumBytesOfEncryptedData = subSamples[s].mNumBytesOfEncryptedData;
        }
        // set decrypt Action
        cryptoInfo->setInt32("action", action);
        cryptoInfo->setObject("buffer", buffer);
        cryptoInfo->setInt32("secure", mFlags & kFlagIsSecure);
        cryptoInfo->setBuffer("key", shared_key);
        cryptoInfo->setBuffer("iv", shared_iv);
        cryptoInfo->setInt32("mode", (int)mode);
        cryptoInfo->setInt32("encryptBlocks", pattern.mEncryptBlocks);
        cryptoInfo->setInt32("skipBlocks", pattern.mSkipBlocks);
        cryptoInfo->setBuffer("subSamples", subSamples_buffer);
        cryptoInfo->setSize("numSubSamples", numSubSamples);
    };
    if (c2Buffer || memory) {
        sp<AMessage> tunings = NULL;
        if (msg->findMessage("tunings", &tunings) && tunings != NULL) {
            onSetParameters(tunings);
        }
        status_t err = OK;
        if (c2Buffer) {
            err = mBufferChannel->attachBuffer(c2Buffer, buffer);
        } else if (memory) {
            AString errorDetailMsg;
            err = mBufferChannel->attachEncryptedBuffer(
                    memory, (mFlags & kFlagIsSecure), key, iv, mode, pattern,
                    offset, subSamples, numSubSamples, buffer, &errorDetailMsg);
            if (err != OK && hasCryptoOrDescrambler()
                    && (mFlags & kFlagUseCryptoAsync)) {
                // create error detail
                AString errorDetailMsg;
                sp<AMessage> cryptoErrorInfo = new AMessage();
                buildCryptoInfoAMessage(cryptoErrorInfo, CryptoAsync::kActionDecrypt);
                cryptoErrorInfo->setInt32("err", err);
                cryptoErrorInfo->setInt32("actionCode", ACTION_CODE_FATAL);
                cryptoErrorInfo->setString("errorDetail", errorDetailMsg);
                onCryptoError(cryptoErrorInfo);
                // we want cryptoError to be in the callback
                // but Codec IllegalStateException to be triggered.
                err = INVALID_OPERATION;
            }
        } else {
            mErrorLog.log(LOG_TAG, "Fatal error: invalid queue request without a buffer");
            err = UNKNOWN_ERROR;
        }
        if (err == OK && !buffer->asC2Buffer()
                && c2Buffer && c2Buffer->data().type() == C2BufferData::LINEAR) {
            C2ConstLinearBlock block{c2Buffer->data().linearBlocks().front()};
            if (block.size() > buffer->size()) {
                C2ConstLinearBlock leftover = block.subBlock(
                        block.offset() + buffer->size(), block.size() - buffer->size());
                sp<WrapperObject<std::shared_ptr<C2Buffer>>> obj{
                    new WrapperObject<std::shared_ptr<C2Buffer>>{
                        C2Buffer::CreateLinearBuffer(leftover)}};
                msg->setObject("c2buffer", obj);
                mLeftover.push_front(msg);
                // Not sending EOS if we have leftovers
                flags &= ~BUFFER_FLAG_EOS;
            }
        }
        offset = buffer->offset();
        size = buffer->size();
        if (err != OK) {
            ALOGE("block model buffer attach failed: err = %s (%d)",
                  StrMediaError(err).c_str(), err);
            return err;
        }
    }

    if (offset + size > buffer->capacity()) {
        mErrorLog.log(LOG_TAG, base::StringPrintf(
                "buffer offset and size goes beyond the capacity: "
                "offset=%zu, size=%zu, cap=%zu",
                offset, size, buffer->capacity()));
        return -EINVAL;
    }
    buffer->setRange(offset, size);
    status_t err = OK;
    err = setInputBufferParams(timeUs, flags);
    if (err != OK) {
        return -EINVAL;
    }

    int32_t usedMaxInputSize = mApiUsageMetrics.inputBufferSize.usedMax;
    mApiUsageMetrics.inputBufferSize.usedMax = size > usedMaxInputSize ? size : usedMaxInputSize;

    if (hasCryptoOrDescrambler() && !c2Buffer && !memory) {
        AString *errorDetailMsg;
        CHECK(msg->findPointer("errorDetailMsg", (void **)&errorDetailMsg));
        // Notify mCrypto of video resolution changes
        if (mTunneled && mCrypto != NULL) {
            int32_t width, height;
            if (mInputFormat->findInt32("width", &width) &&
                mInputFormat->findInt32("height", &height) && width > 0 && height > 0) {
                if (width != mTunneledInputWidth || height != mTunneledInputHeight) {
                    mTunneledInputWidth = width;
                    mTunneledInputHeight = height;
                    mCrypto->notifyResolution(width, height);
                }
            }
        }
        if (mCryptoAsync) {
            // prepare a message and enqueue
            sp<AMessage> cryptoInfo = new AMessage();
            buildCryptoInfoAMessage(cryptoInfo, CryptoAsync::kActionDecrypt);
            mCryptoAsync->decrypt(cryptoInfo);
        } else {
            err = mBufferChannel->queueSecureInputBuffer(
                buffer,
                (mFlags & kFlagIsSecure),
                key,
                iv,
                mode,
                pattern,
                subSamples,
                numSubSamples,
                errorDetailMsg);
        }
        if (err != OK) {
            mediametrics_setInt32(mMetricsHandle, kCodecQueueSecureInputBufferError, err);
            ALOGW("Log queueSecureInputBuffer error: %d", err);
        }
    } else {
        err = mBufferChannel->queueInputBuffer(buffer);
        if (err != OK) {
            mediametrics_setInt32(mMetricsHandle, kCodecQueueInputBufferError, err);
            ALOGW("Log queueInputBuffer error: %d", err);
        }
    }

    if (err == OK) {
        if (mTunneled && (flags & (BUFFER_FLAG_DECODE_ONLY | BUFFER_FLAG_END_OF_STREAM)) == 0) {
            mVideoRenderQualityTracker.onTunnelFrameQueued(timeUs);
        }

        // synchronization boundary for getBufferAndFormat
        Mutex::Autolock al(mBufferLock);
        info->mOwnedByClient = false;
        info->mData.clear();

        statsBufferSent(timeUs, buffer);
    }

    return err;
}

status_t MediaCodec::handleLeftover(size_t index) {
    if (mLeftover.empty()) {
        return OK;
    }
    sp<AMessage> msg = mLeftover.front();
    mLeftover.pop_front();
    msg->setSize("index", index);
    return onQueueInputBuffer(msg);
}

template<typename T>
static size_t CreateFramesRenderedMessageInternal(const std::list<T> &done, sp<AMessage> &msg) {
    size_t index = 0;
    for (typename std::list<T>::const_iterator it = done.cbegin(); it != done.cend(); ++it) {
        if (it->getRenderTimeNs() < 0) {
            continue; // dropped frame from tracking
        }
        msg->setInt64(base::StringPrintf("%zu-media-time-us", index).c_str(), it->getMediaTimeUs());
        msg->setInt64(base::StringPrintf("%zu-system-nano", index).c_str(), it->getRenderTimeNs());
        ++index;
    }
    return index;
}

//static
size_t MediaCodec::CreateFramesRenderedMessage(
        const std::list<RenderedFrameInfo> &done, sp<AMessage> &msg) {
    return CreateFramesRenderedMessageInternal(done, msg);
}

//static
size_t MediaCodec::CreateFramesRenderedMessage(
        const std::list<FrameRenderTracker::Info> &done, sp<AMessage> &msg) {
    return CreateFramesRenderedMessageInternal(done, msg);
}

status_t MediaCodec::onReleaseOutputBuffer(const sp<AMessage> &msg) {
    size_t index;
    CHECK(msg->findSize("index", &index));

    int32_t render;
    if (!msg->findInt32("render", &render)) {
        render = 0;
    }

    if (!isExecuting()) {
        mErrorLog.log(LOG_TAG, base::StringPrintf(
                "releaseOutputBuffer() is valid at Executing states; currently %s",
                apiStateString().c_str()));
        return -EINVAL;
    }

    if (index >= mPortBuffers[kPortIndexOutput].size()) {
        mErrorLog.log(LOG_TAG, base::StringPrintf(
                "index out of range (index=%zu)", mPortBuffers[kPortIndexOutput].size()));
        return -ERANGE;
    }

    BufferInfo *info = &mPortBuffers[kPortIndexOutput][index];

    if (!info->mOwnedByClient) {
        mErrorLog.log(LOG_TAG, base::StringPrintf(
                "client does not own the buffer #%zu", index));
        return -EACCES;
    }
    if (info->mData == nullptr) {
        mErrorLog.log(LOG_TAG, base::StringPrintf(
                "Fatal error: null buffer for index %zu", index));
        return -EACCES;
    }

    // synchronization boundary for getBufferAndFormat
    sp<MediaCodecBuffer> buffer;
    {
        Mutex::Autolock al(mBufferLock);
        info->mOwnedByClient = false;
        buffer = info->mData;
        info->mData.clear();
    }

    if (render && buffer->size() != 0) {
        int64_t mediaTimeUs = INT64_MIN;
        buffer->meta()->findInt64("timeUs", &mediaTimeUs);

        bool noRenderTime = false;
        int64_t renderTimeNs = 0;
        if (!msg->findInt64("timestampNs", &renderTimeNs)) {
            // use media timestamp if client did not request a specific render timestamp
            ALOGV("using buffer PTS of %lld", (long long)mediaTimeUs);
            renderTimeNs = mediaTimeUs * 1000;
            noRenderTime = true;
        }

        if (mSoftRenderer != NULL) {
            std::list<FrameRenderTracker::Info> doneFrames = mSoftRenderer->render(
                    buffer->data(), buffer->size(), mediaTimeUs, renderTimeNs,
                    mPortBuffers[kPortIndexOutput].size(), buffer->format());

            // if we are running, notify rendered frames
            if (!doneFrames.empty() && mState == STARTED && mOnFrameRenderedNotification != NULL) {
                sp<AMessage> notify = mOnFrameRenderedNotification->dup();
                sp<AMessage> data = new AMessage;
                if (CreateFramesRenderedMessage(doneFrames, data)) {
                    notify->setMessage("data", data);
                    notify->post();
                }
            }
        }

        // If rendering to the screen, then schedule a time in the future to poll to see if this
        // frame was ever rendered to seed onFrameRendered callbacks.
        if (mAreRenderMetricsEnabled && mIsSurfaceToDisplay) {
            if (mediaTimeUs != INT64_MIN) {
                noRenderTime ? mVideoRenderQualityTracker.onFrameReleased(mediaTimeUs)
                             : mVideoRenderQualityTracker.onFrameReleased(mediaTimeUs,
                                                                          renderTimeNs);
            }
            // can't initialize this in the constructor because the Looper parent class needs to be
            // initialized first
            if (mMsgPollForRenderedBuffers == nullptr) {
                mMsgPollForRenderedBuffers = new AMessage(kWhatPollForRenderedBuffers, this);
            }
            // Schedule the poll to occur 100ms after the render time - should be safe for
            // determining if the frame was ever rendered. If no render time was specified, the
            // presentation timestamp is used instead, which almost certainly occurs in the past,
            // since it's almost always a zero-based offset from the start of the stream. In these
            // scenarios, we expect the frame to be rendered with no delay.
            int64_t nowUs = ALooper::GetNowUs();
            int64_t renderTimeUs = renderTimeNs / 1000;
            int64_t delayUs = renderTimeUs < nowUs ? 0 : renderTimeUs - nowUs;
            delayUs += 100 * 1000; /* 100ms in microseconds */
            status_t err =
                    mMsgPollForRenderedBuffers->postUnique(/* token= */ mMsgPollForRenderedBuffers,
                                                           delayUs);
            if (err != OK) {
                ALOGE("unexpected failure to post pollForRenderedBuffers: %d", err);
            }
        }
        status_t err = mBufferChannel->renderOutputBuffer(buffer, renderTimeNs);

        if (err == NO_INIT) {
            mErrorLog.log(LOG_TAG, "rendering to non-initialized(obsolete) surface");
            return err;
        }
        if (err != OK) {
            ALOGI("rendring output error %d", err);
        }
    } else {
        if (mIsSurfaceToDisplay && buffer->size() != 0) {
            int64_t mediaTimeUs = INT64_MIN;
            if (buffer->meta()->findInt64("timeUs", &mediaTimeUs)) {
                mVideoRenderQualityTracker.onFrameSkipped(mediaTimeUs);
            }
        }
        mBufferChannel->discardBuffer(buffer);
    }

    return OK;
}

MediaCodec::BufferInfo *MediaCodec::peekNextPortBuffer(int32_t portIndex) {
    CHECK(portIndex == kPortIndexInput || portIndex == kPortIndexOutput);

    std::list<size_t> *availBuffers = &mAvailPortBuffers[portIndex];

    if (availBuffers->empty()) {
        return nullptr;
    }

    return &mPortBuffers[portIndex][*availBuffers->begin()];
}

ssize_t MediaCodec::dequeuePortBuffer(int32_t portIndex) {
    CHECK(portIndex == kPortIndexInput || portIndex == kPortIndexOutput);

    BufferInfo *info = peekNextPortBuffer(portIndex);
    if (!info) {
        return -EAGAIN;
    }

    std::list<size_t> *availBuffers = &mAvailPortBuffers[portIndex];
    size_t index = *availBuffers->begin();
    CHECK_EQ(info, &mPortBuffers[portIndex][index]);
    availBuffers->erase(availBuffers->begin());

    CHECK(!info->mOwnedByClient);
    {
        Mutex::Autolock al(mBufferLock);
        info->mOwnedByClient = true;

        // set image-data
        if (info->mData->format() != NULL) {
            sp<ABuffer> imageData;
            if (info->mData->format()->findBuffer("image-data", &imageData)) {
                info->mData->meta()->setBuffer("image-data", imageData);
            }
            int32_t left, top, right, bottom;
            if (info->mData->format()->findRect("crop", &left, &top, &right, &bottom)) {
                info->mData->meta()->setRect("crop-rect", left, top, right, bottom);
            }
        }
    }

    return index;
}

status_t MediaCodec::connectToSurface(const sp<Surface> &surface, uint32_t *generation) {
    status_t err = OK;
    if (surface != NULL) {
        uint64_t oldId, newId;
        if (mSurface != NULL
                && surface->getUniqueId(&newId) == NO_ERROR
                && mSurface->getUniqueId(&oldId) == NO_ERROR
                && newId == oldId) {
            ALOGI("[%s] connecting to the same surface. Nothing to do.", mComponentName.c_str());
            return ALREADY_EXISTS;
        }

        // in case we don't connect, ensure that we don't signal the surface is
        // connected to the screen
        mIsSurfaceToDisplay = false;

        err = nativeWindowConnect(surface.get(), "connectToSurface");
        if (err == OK) {
            // Require a fresh set of buffers after each connect by using a unique generation
            // number. Rely on the fact that max supported process id by Linux is 2^22.
            // PID is never 0 so we don't have to worry that we use the default generation of 0.
            // TODO: come up with a unique scheme if other producers also set the generation number.
            static uint32_t sSurfaceGeneration = 0;
            *generation = (getpid() << 10) | (++sSurfaceGeneration & ((1 << 10) - 1));
            surface->setGenerationNumber(*generation);
            ALOGI("[%s] setting surface generation to %u", mComponentName.c_str(), *generation);

            // HACK: clear any free buffers. Remove when connect will automatically do this.
            // This is needed as the consumer may be holding onto stale frames that it can reattach
            // to this surface after disconnect/connect, and those free frames would inherit the new
            // generation number. Disconnecting after setting a unique generation prevents this.
            nativeWindowDisconnect(surface.get(), "connectToSurface(reconnect)");
            sp<IProducerListener> listener =
                    new OnBufferReleasedListener(*generation, mBufferChannel);
            err = surfaceConnectWithListener(
                    surface, listener, "connectToSurface(reconnect-with-listener)");
        }

        if (err != OK) {
            *generation = 0;
            ALOGE("nativeWindowConnect/surfaceConnectWithListener returned an error: %s (%d)",
                    strerror(-err), err);
        } else {
            if (!mAllowFrameDroppingBySurface) {
                disableLegacyBufferDropPostQ(surface);
            }
            // keep track whether or not the buffers of the connected surface go to the screen
            int result = 0;
            surface->query(NATIVE_WINDOW_QUEUES_TO_WINDOW_COMPOSER, &result);
            mIsSurfaceToDisplay = result != 0;
        }
    }
    // do not return ALREADY_EXISTS unless surfaces are the same
    return err == ALREADY_EXISTS ? BAD_VALUE : err;
}

status_t MediaCodec::disconnectFromSurface() {
    status_t err = OK;
    if (mSurface != NULL) {
        // Resetting generation is not technically needed, but there is no need to keep it either
        mSurface->setGenerationNumber(0);
        err = nativeWindowDisconnect(mSurface.get(), "disconnectFromSurface");
        if (err != OK) {
            ALOGW("nativeWindowDisconnect returned an error: %s (%d)", strerror(-err), err);
        }
        // assume disconnected even on error
        mSurface.clear();
        mSurfaceGeneration = 0;
        mIsSurfaceToDisplay = false;
    }
    return err;
}

status_t MediaCodec::handleSetSurface(const sp<Surface> &surface) {
    status_t err = OK;
    if (mSurface != NULL) {
        (void)disconnectFromSurface();
    }
    if (surface != NULL) {
        uint32_t generation;
        err = connectToSurface(surface, &generation);
        if (err == OK) {
            mSurface = surface;
            mSurfaceGeneration = generation;
        }
    }
    return err;
}

void MediaCodec::onInputBufferAvailable() {
    int32_t index;
    while ((index = dequeuePortBuffer(kPortIndexInput)) >= 0) {
        sp<AMessage> msg = mCallback->dup();
        msg->setInt32("callbackID", CB_INPUT_AVAILABLE);
        msg->setInt32("index", index);
        msg->post();
    }
}

void MediaCodec::onOutputBufferAvailable() {
    int32_t index;
    while ((index = dequeuePortBuffer(kPortIndexOutput)) >= 0) {
        if (discardDecodeOnlyOutputBuffer(index)) {
            continue;
        }
        sp<AMessage> msg = mCallback->dup();
        const sp<MediaCodecBuffer> &buffer =
            mPortBuffers[kPortIndexOutput][index].mData;
        int32_t outputCallbackID = CB_OUTPUT_AVAILABLE;
        sp<RefBase> accessUnitInfoObj;
        msg->setInt32("index", index);
        msg->setSize("offset", buffer->offset());
        msg->setSize("size", buffer->size());

        int64_t timeUs;
        CHECK(buffer->meta()->findInt64("timeUs", &timeUs));

        msg->setInt64("timeUs", timeUs);

        int32_t flags;
        CHECK(buffer->meta()->findInt32("flags", &flags));

        msg->setInt32("flags", flags);
        buffer->meta()->findObject("accessUnitInfo", &accessUnitInfoObj);
        if (accessUnitInfoObj) {
            outputCallbackID = CB_LARGE_FRAME_OUTPUT_AVAILABLE;
            msg->setObject("accessUnitInfo", accessUnitInfoObj);
             sp<BufferInfosWrapper> auInfo(
                    (decltype(auInfo.get()))accessUnitInfoObj.get());
             auInfo->value.back().mFlags |= flags & BUFFER_FLAG_END_OF_STREAM;
        }
        msg->setInt32("callbackID", outputCallbackID);

        statsBufferReceived(timeUs, buffer);

        msg->post();
    }
}
void MediaCodec::onCryptoError(const sp<AMessage> & msg) {
    if (mCallback != NULL) {
        sp<AMessage> cb_msg = mCallback->dup();
        cb_msg->setInt32("callbackID", CB_CRYPTO_ERROR);
        cb_msg->extend(msg);
        cb_msg->post();
    }
}
void MediaCodec::onError(status_t err, int32_t actionCode, const char *detail) {
    if (mCallback != NULL) {
        sp<AMessage> msg = mCallback->dup();
        msg->setInt32("callbackID", CB_ERROR);
        msg->setInt32("err", err);
        msg->setInt32("actionCode", actionCode);

        if (detail != NULL) {
            msg->setString("detail", detail);
        }

        msg->post();
    }
}

void MediaCodec::onOutputFormatChanged() {
    if (mCallback != NULL) {
        sp<AMessage> msg = mCallback->dup();
        msg->setInt32("callbackID", CB_OUTPUT_FORMAT_CHANGED);
        msg->setMessage("format", mOutputFormat);
        msg->post();
    }
}

void MediaCodec::postActivityNotificationIfPossible() {
    if (mActivityNotify == NULL) {
        return;
    }

    bool isErrorOrOutputChanged =
            (mFlags & (kFlagStickyError
                    | kFlagOutputBuffersChanged
                    | kFlagOutputFormatChanged));

    if (isErrorOrOutputChanged
            || !mAvailPortBuffers[kPortIndexInput].empty()
            || !mAvailPortBuffers[kPortIndexOutput].empty()) {
        mActivityNotify->setInt32("input-buffers",
                mAvailPortBuffers[kPortIndexInput].size());

        if (isErrorOrOutputChanged) {
            // we want consumer to dequeue as many times as it can
            mActivityNotify->setInt32("output-buffers", INT32_MAX);
        } else {
            mActivityNotify->setInt32("output-buffers",
                    mAvailPortBuffers[kPortIndexOutput].size());
        }
        mActivityNotify->post();
        mActivityNotify.clear();
    }
}

status_t MediaCodec::setParameters(const sp<AMessage> &params) {
    sp<AMessage> msg = new AMessage(kWhatSetParameters, this);
    msg->setMessage("params", params);

    sp<AMessage> response;
    return PostAndAwaitResponse(msg, &response);
}

status_t MediaCodec::onSetParameters(const sp<AMessage> &params) {
    if (mState == UNINITIALIZED || mState == INITIALIZING) {
        return NO_INIT;
    }
    updateLowLatency(params);
    updateCodecImportance(params);
    mapFormat(mComponentName, params, nullptr, false);
    updateTunnelPeek(params);
    mCodec->signalSetParameters(params);

    return OK;
}

status_t MediaCodec::amendOutputFormatWithCodecSpecificData(
        const sp<MediaCodecBuffer> &buffer) {
    AString mime;
    CHECK(mOutputFormat->findString("mime", &mime));

    if (!strcasecmp(mime.c_str(), MEDIA_MIMETYPE_VIDEO_AVC)) {
        // Codec specific data should be SPS and PPS in a single buffer,
        // each prefixed by a startcode (0x00 0x00 0x00 0x01).
        // We separate the two and put them into the output format
        // under the keys "csd-0" and "csd-1".

        unsigned csdIndex = 0;

        const uint8_t *data = buffer->data();
        size_t size = buffer->size();

        const uint8_t *nalStart;
        size_t nalSize;
        while (getNextNALUnit(&data, &size, &nalStart, &nalSize, true) == OK) {
            sp<ABuffer> csd = new ABuffer(nalSize + 4);
            memcpy(csd->data(), "\x00\x00\x00\x01", 4);
            memcpy(csd->data() + 4, nalStart, nalSize);

            mOutputFormat->setBuffer(
                    base::StringPrintf("csd-%u", csdIndex).c_str(), csd);

            ++csdIndex;
        }

        if (csdIndex != 2) {
            mErrorLog.log(LOG_TAG, base::StringPrintf(
                    "codec config data contains %u NAL units; expected 2.", csdIndex));
            return ERROR_MALFORMED;
        }
    } else {
        // For everything else we just stash the codec specific data into
        // the output format as a single piece of csd under "csd-0".
        sp<ABuffer> csd = new ABuffer(buffer->size());
        memcpy(csd->data(), buffer->data(), buffer->size());
        csd->setRange(0, buffer->size());
        mOutputFormat->setBuffer("csd-0", csd);
    }

    return OK;
}

void MediaCodec::postPendingRepliesAndDeferredMessages(
        std::string origin, status_t err /* = OK */) {
    sp<AMessage> response{new AMessage};
    if (err != OK) {
        response->setInt32("err", err);
    }
    postPendingRepliesAndDeferredMessages(origin, response);
}

void MediaCodec::postPendingRepliesAndDeferredMessages(
        std::string origin, const sp<AMessage> &response) {
    LOG_ALWAYS_FATAL_IF(
            !mReplyID,
            "postPendingRepliesAndDeferredMessages: mReplyID == null, from %s following %s",
            origin.c_str(),
            mLastReplyOrigin.c_str());
    mLastReplyOrigin = origin;
    response->postReply(mReplyID);
    mReplyID.clear();
    ALOGV_IF(!mDeferredMessages.empty(),
            "posting %zu deferred messages", mDeferredMessages.size());
    for (sp<AMessage> msg : mDeferredMessages) {
        msg->post();
    }
    mDeferredMessages.clear();
}

std::string MediaCodec::apiStateString() {
    const char *rval = NULL;
    char rawbuffer[16]; // room for "%d"

    switch (mState) {
        case UNINITIALIZED:
            rval = (mFlags & kFlagStickyError) ? "at Error state" : "at Released state";
            break;
        case INITIALIZING: rval = "while constructing"; break;
        case INITIALIZED: rval = "at Uninitialized state"; break;
        case CONFIGURING: rval = "during configure()"; break;
        case CONFIGURED: rval = "at Configured state"; break;
        case STARTING: rval = "during start()"; break;
        case STARTED: rval = "at Running state"; break;
        case FLUSHING: rval = "during flush()"; break;
        case FLUSHED: rval = "at Flushed state"; break;
        case STOPPING: rval = "during stop()"; break;
        case RELEASING: rval = "during release()"; break;
        default:
            snprintf(rawbuffer, sizeof(rawbuffer), "at %d", mState);
            rval = rawbuffer;
            break;
    }
    return rval;
}

std::string MediaCodec::stateString(State state) {
    const char *rval = NULL;
    char rawbuffer[16]; // room for "%d"

    switch (state) {
        case UNINITIALIZED: rval = "UNINITIALIZED"; break;
        case INITIALIZING: rval = "INITIALIZING"; break;
        case INITIALIZED: rval = "INITIALIZED"; break;
        case CONFIGURING: rval = "CONFIGURING"; break;
        case CONFIGURED: rval = "CONFIGURED"; break;
        case STARTING: rval = "STARTING"; break;
        case STARTED: rval = "STARTED"; break;
        case FLUSHING: rval = "FLUSHING"; break;
        case FLUSHED: rval = "FLUSHED"; break;
        case STOPPING: rval = "STOPPING"; break;
        case RELEASING: rval = "RELEASING"; break;
        default:
            snprintf(rawbuffer, sizeof(rawbuffer), "%d", state);
            rval = rawbuffer;
            break;
    }
    return rval;
}

// static
status_t MediaCodec::CanFetchLinearBlock(
        const std::vector<std::string> &names, bool *isCompatible) {
    *isCompatible = false;
    if (names.size() == 0) {
        *isCompatible = true;
        return OK;
    }
    const CodecListCache &cache = GetCodecListCache();
    for (const std::string &name : names) {
        auto it = cache.mCodecInfoMap.find(name);
        if (it == cache.mCodecInfoMap.end()) {
            return NAME_NOT_FOUND;
        }
        const char *owner = it->second->getOwnerName();
        if (owner == nullptr || strncmp(owner, "default", 8) == 0) {
            *isCompatible = false;
            return OK;
        } else if (strncmp(owner, "codec2::", 8) != 0) {
            return NAME_NOT_FOUND;
        }
    }
    return CCodec::CanFetchLinearBlock(names, kDefaultReadWriteUsage, isCompatible);
}

// static
std::shared_ptr<C2LinearBlock> MediaCodec::FetchLinearBlock(
        size_t capacity, const std::vector<std::string> &names) {
    return CCodec::FetchLinearBlock(capacity, kDefaultReadWriteUsage, names);
}

// static
status_t MediaCodec::CanFetchGraphicBlock(
        const std::vector<std::string> &names, bool *isCompatible) {
    *isCompatible = false;
    if (names.size() == 0) {
        *isCompatible = true;
        return OK;
    }
    const CodecListCache &cache = GetCodecListCache();
    for (const std::string &name : names) {
        auto it = cache.mCodecInfoMap.find(name);
        if (it == cache.mCodecInfoMap.end()) {
            return NAME_NOT_FOUND;
        }
        const char *owner = it->second->getOwnerName();
        if (owner == nullptr || strncmp(owner, "default", 8) == 0) {
            *isCompatible = false;
            return OK;
        } else if (strncmp(owner, "codec2.", 7) != 0) {
            return NAME_NOT_FOUND;
        }
    }
    return CCodec::CanFetchGraphicBlock(names, isCompatible);
}

// static
std::shared_ptr<C2GraphicBlock> MediaCodec::FetchGraphicBlock(
        int32_t width,
        int32_t height,
        int32_t format,
        uint64_t usage,
        const std::vector<std::string> &names) {
    return CCodec::FetchGraphicBlock(width, height, format, usage, names);
}

}  // namespace android
