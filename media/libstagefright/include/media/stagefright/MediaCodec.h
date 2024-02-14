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

#ifndef MEDIA_CODEC_H_

#define MEDIA_CODEC_H_

#include <list>
#include <memory>
#include <vector>

#include <gui/IGraphicBufferProducer.h>
#include <media/hardware/CryptoAPI.h>
#include <media/MediaCodecInfo.h>
#include <media/MediaMetrics.h>
#include <media/MediaProfiles.h>
#include <media/stagefright/foundation/AHandler.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/CodecErrorLog.h>
#include <media/stagefright/FrameRenderTracker.h>
#include <media/stagefright/MediaHistogram.h>
#include <media/stagefright/PlaybackDurationAccumulator.h>
#include <media/stagefright/VideoRenderQualityTracker.h>
#include <utils/Vector.h>

class C2Buffer;
class C2GraphicBlock;
class C2LinearBlock;

namespace aidl {
namespace android {
namespace media {
class MediaResourceParcel;
class ClientConfigParcel;
} // media
} // android
} // aidl

namespace android {

struct ABuffer;
struct AMessage;
struct AReplyToken;
struct AString;
struct BatteryChecker;
class BufferChannelBase;
struct AccessUnitInfo;
struct CodecBase;
struct CodecCryptoInfo;
struct CodecParameterDescriptor;
class IBatteryStats;
struct ICrypto;
class CryptoAsync;
class MediaCodecBuffer;
class IMemory;
struct PersistentSurface;
class RenderedFrameInfo;
class SoftwareRenderer;
class Surface;
namespace hardware {
namespace cas {
namespace native {
namespace V1_0 {
struct IDescrambler;
}}}}

using hardware::cas::native::V1_0::IDescrambler;
using aidl::android::media::MediaResourceParcel;
using aidl::android::media::ClientConfigParcel;

typedef WrapperObject<std::vector<AccessUnitInfo>> BufferInfosWrapper;
typedef WrapperObject<std::vector<std::unique_ptr<CodecCryptoInfo>>> CryptoInfosWrapper;

struct MediaCodec : public AHandler {
    enum Domain {
        DOMAIN_UNKNOWN = 0,
        DOMAIN_VIDEO = 1,
        DOMAIN_AUDIO = 2,
        DOMAIN_IMAGE = 3
    };

    enum ConfigureFlags {
        CONFIGURE_FLAG_ENCODE           = 1,
        CONFIGURE_FLAG_USE_BLOCK_MODEL  = 2,
        CONFIGURE_FLAG_USE_CRYPTO_ASYNC = 4,
    };

    enum BufferFlags {
        BUFFER_FLAG_SYNCFRAME     = 1,
        BUFFER_FLAG_CODECCONFIG   = 2,
        BUFFER_FLAG_EOS           = 4,
        BUFFER_FLAG_PARTIAL_FRAME = 8,
        BUFFER_FLAG_MUXER_DATA    = 16,
        BUFFER_FLAG_DECODE_ONLY   = 32,
    };

    enum CVODegree {
        CVO_DEGREE_0   = 0,
        CVO_DEGREE_90  = 90,
        CVO_DEGREE_180 = 180,
        CVO_DEGREE_270 = 270,
    };

    enum {
        CB_INPUT_AVAILABLE = 1,
        CB_OUTPUT_AVAILABLE = 2,
        CB_ERROR = 3,
        CB_OUTPUT_FORMAT_CHANGED = 4,
        CB_RESOURCE_RECLAIMED = 5,
        CB_CRYPTO_ERROR = 6,
        CB_LARGE_FRAME_OUTPUT_AVAILABLE = 7,
    };

    static const pid_t kNoPid = -1;
    static const uid_t kNoUid = -1;

    static sp<MediaCodec> CreateByType(
            const sp<ALooper> &looper, const AString &mime, bool encoder, status_t *err = NULL,
            pid_t pid = kNoPid, uid_t uid = kNoUid);

    static sp<MediaCodec> CreateByType(
            const sp<ALooper> &looper, const AString &mime, bool encoder, status_t *err,
            pid_t pid, uid_t uid, sp<AMessage> format);

    static sp<MediaCodec> CreateByComponentName(
            const sp<ALooper> &looper, const AString &name, status_t *err = NULL,
            pid_t pid = kNoPid, uid_t uid = kNoUid);

    static sp<PersistentSurface> CreatePersistentInputSurface();

    status_t configure(
            const sp<AMessage> &format,
            const sp<Surface> &nativeWindow,
            const sp<ICrypto> &crypto,
            uint32_t flags);

    status_t configure(
            const sp<AMessage> &format,
            const sp<Surface> &nativeWindow,
            const sp<ICrypto> &crypto,
            const sp<IDescrambler> &descrambler,
            uint32_t flags);

    status_t releaseCrypto();

    status_t setCallback(const sp<AMessage> &callback);

    status_t setOnFrameRenderedNotification(const sp<AMessage> &notify);

    status_t setOnFirstTunnelFrameReadyNotification(const sp<AMessage> &notify);

    status_t createInputSurface(sp<IGraphicBufferProducer>* bufferProducer);

    status_t setInputSurface(const sp<PersistentSurface> &surface);

    status_t start();

    // Returns to a state in which the component remains allocated but
    // unconfigured.
    status_t stop();

    // Resets the codec to the INITIALIZED state.  Can be called after an error
    // has occured to make the codec usable.
    status_t reset();

    // Client MUST call release before releasing final reference to this
    // object.
    status_t release();

    status_t releaseAsync(const sp<AMessage> &notify);

    status_t flush();

    status_t queueInputBuffer(
            size_t index,
            size_t offset,
            size_t size,
            int64_t presentationTimeUs,
            uint32_t flags,
            AString *errorDetailMsg = NULL);

    status_t queueInputBuffers(
            size_t index,
            size_t offset,
            size_t size,
            const sp<BufferInfosWrapper> &accessUnitInfo,
            AString *errorDetailMsg = NULL);

    status_t queueSecureInputBuffer(
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
            AString *errorDetailMsg = NULL);

    status_t queueSecureInputBuffers(
            size_t index,
            size_t offset,
            size_t size,
            const sp<BufferInfosWrapper> &accessUnitInfo,
            const sp<CryptoInfosWrapper> &cryptoInfos,
            AString *errorDetailMsg = NULL);

    status_t queueBuffer(
            size_t index,
            const std::shared_ptr<C2Buffer> &buffer,
            const sp<BufferInfosWrapper> &bufferInfos,
            const sp<AMessage> &tunings,
            AString *errorDetailMsg = NULL);

    status_t queueEncryptedBuffer(
            size_t index,
            const sp<hardware::HidlMemory> &memory,
            size_t offset,
            size_t size,
            const sp<BufferInfosWrapper> &bufferInfos,
            const sp<CryptoInfosWrapper> &cryptoInfos,
            const sp<AMessage> &tunings,
            AString *errorDetailMsg = NULL);

    std::shared_ptr<C2Buffer> decrypt(
            const std::shared_ptr<C2Buffer> &buffer,
            const CryptoPlugin::SubSample *subSamples,
            size_t numSubSamples,
            const uint8_t key[16],
            const uint8_t iv[16],
            CryptoPlugin::Mode mode,
            const CryptoPlugin::Pattern &pattern);

    status_t dequeueInputBuffer(size_t *index, int64_t timeoutUs = 0ll);

    status_t dequeueOutputBuffer(
            size_t *index,
            size_t *offset,
            size_t *size,
            int64_t *presentationTimeUs,
            uint32_t *flags,
            int64_t timeoutUs = 0ll);

    status_t renderOutputBufferAndRelease(size_t index, int64_t timestampNs);
    status_t renderOutputBufferAndRelease(size_t index);
    status_t releaseOutputBuffer(size_t index);

    status_t signalEndOfInputStream();

    status_t getOutputFormat(sp<AMessage> *format) const;
    status_t getInputFormat(sp<AMessage> *format) const;

    status_t getInputBuffers(Vector<sp<MediaCodecBuffer> > *buffers) const;
    status_t getOutputBuffers(Vector<sp<MediaCodecBuffer> > *buffers) const;

    status_t getOutputBuffer(size_t index, sp<MediaCodecBuffer> *buffer);
    status_t getOutputFormat(size_t index, sp<AMessage> *format);
    status_t getInputBuffer(size_t index, sp<MediaCodecBuffer> *buffer);

    status_t setSurface(const sp<Surface> &nativeWindow);

    status_t requestIDRFrame();

    // Notification will be posted once there "is something to do", i.e.
    // an input/output buffer has become available, a format change is
    // pending, an error is pending.
    void requestActivityNotification(const sp<AMessage> &notify);

    status_t getName(AString *componentName) const;

    status_t getCodecInfo(sp<MediaCodecInfo> *codecInfo) const;

    status_t getMetrics(mediametrics_handle_t &reply);

    status_t setParameters(const sp<AMessage> &params);

    status_t querySupportedVendorParameters(std::vector<std::string> *names);
    status_t describeParameter(const std::string &name, CodecParameterDescriptor *desc);
    status_t subscribeToVendorParameters(const std::vector<std::string> &names);
    status_t unsubscribeFromVendorParameters(const std::vector<std::string> &names);

    // Create a MediaCodec notification message from a list of rendered or dropped render infos
    // by adding rendered frame information to a base notification message. Returns the number
    // of frames that were rendered.
    static size_t CreateFramesRenderedMessage(
            const std::list<RenderedFrameInfo> &done, sp<AMessage> &msg);
    static size_t CreateFramesRenderedMessage(
            const std::list<FrameRenderTracker::Info> &done, sp<AMessage> &msg);

    static status_t CanFetchLinearBlock(
            const std::vector<std::string> &names, bool *isCompatible);

    static std::shared_ptr<C2LinearBlock> FetchLinearBlock(
            size_t capacity, const std::vector<std::string> &names);

    static status_t CanFetchGraphicBlock(
            const std::vector<std::string> &names, bool *isCompatible);

    static std::shared_ptr<C2GraphicBlock> FetchGraphicBlock(
            int32_t width,
            int32_t height,
            int32_t format,
            uint64_t usage,
            const std::vector<std::string> &names);

    template <typename T>
    struct WrapperObject : public RefBase {
        WrapperObject(const T& v) : value(v) {}
        WrapperObject(T&& v) : value(std::move(v)) {}
        T value;
    };

    inline CodecErrorLog &getErrorLog() { return mErrorLog; }

protected:
    virtual ~MediaCodec();
    virtual void onMessageReceived(const sp<AMessage> &msg);

private:
    // used by ResourceManagerClient
    status_t reclaim(bool force = false);
    friend struct ResourceManagerClient;

    // to create the metrics associated with this codec.
    // Any error in this function will be captured by the output argument err.
    mediametrics_handle_t createMediaMetrics(const sp<AMessage>& format,
                                             uint32_t flags,
                                             status_t* err);

private:
    enum State {
        UNINITIALIZED,
        INITIALIZING,
        INITIALIZED,
        CONFIGURING,
        CONFIGURED,
        STARTING,
        STARTED,
        FLUSHING,
        FLUSHED,
        STOPPING,
        RELEASING,
    };
    std::string stateString(State state);
    std::string apiStateString();

    enum {
        kPortIndexInput         = 0,
        kPortIndexOutput        = 1,
    };

    enum {
        kWhatInit                           = 'init',
        kWhatConfigure                      = 'conf',
        kWhatSetSurface                     = 'sSur',
        kWhatCreateInputSurface             = 'cisf',
        kWhatSetInputSurface                = 'sisf',
        kWhatStart                          = 'strt',
        kWhatStop                           = 'stop',
        kWhatRelease                        = 'rele',
        kWhatDequeueInputBuffer             = 'deqI',
        kWhatQueueInputBuffer               = 'queI',
        kWhatDequeueOutputBuffer            = 'deqO',
        kWhatReleaseOutputBuffer            = 'relO',
        kWhatSignalEndOfInputStream         = 'eois',
        kWhatGetBuffers                     = 'getB',
        kWhatFlush                          = 'flus',
        kWhatGetOutputFormat                = 'getO',
        kWhatGetInputFormat                 = 'getI',
        kWhatDequeueInputTimedOut           = 'dITO',
        kWhatDequeueOutputTimedOut          = 'dOTO',
        kWhatCodecNotify                    = 'codc',
        kWhatRequestIDRFrame                = 'ridr',
        kWhatRequestActivityNotification    = 'racN',
        kWhatGetName                        = 'getN',
        kWhatGetCodecInfo                   = 'gCoI',
        kWhatSetParameters                  = 'setP',
        kWhatSetCallback                    = 'setC',
        kWhatSetNotification                = 'setN',
        kWhatDrmReleaseCrypto               = 'rDrm',
        kWhatCheckBatteryStats              = 'chkB',
        kWhatGetMetrics                     = 'getM',
    };

    enum {
        kFlagUsesSoftwareRenderer       = 1,
        kFlagOutputFormatChanged        = 2,
        kFlagOutputBuffersChanged       = 4,
        kFlagStickyError                = 8,
        kFlagDequeueInputPending        = 16,
        kFlagDequeueOutputPending       = 32,
        kFlagIsSecure                   = 64,
        kFlagSawMediaServerDie          = 128,
        kFlagIsEncoder                  = 256,
        // 512 skipped
        kFlagIsAsync                    = 1024,
        kFlagIsComponentAllocated       = 2048,
        kFlagPushBlankBuffersOnShutdown = 4096,
        kFlagUseBlockModel              = 8192,
        kFlagUseCryptoAsync             = 16384,
    };

    struct BufferInfo {
        BufferInfo();

        sp<MediaCodecBuffer> mData;
        bool mOwnedByClient;
    };

    // This type is used to track the tunnel mode video peek state machine:
    //
    // DisabledNoBuffer -> EnabledNoBuffer  when tunnel-peek = true
    // DisabledQueued   -> EnabledQueued    when tunnel-peek = true
    // DisabledNoBuffer -> DisabledQueued   when first frame queued
    // EnabledNoBuffer  -> DisabledNoBuffer when tunnel-peek = false
    // EnabledQueued    -> DisabledQueued   when tunnel-peek = false
    // EnabledNoBuffer  -> EnabledQueued    when first frame queued
    // DisabledNoBuffer -> BufferDecoded    when kWhatFirstTunnelFrameReady
    // DisabledQueued   -> BufferDecoded    when kWhatFirstTunnelFrameReady
    // EnabledNoBuffer  -> BufferDecoded    when kWhatFirstTunnelFrameReady
    // EnabledQueued    -> BufferDecoded    when kWhatFirstTunnelFrameReady
    // BufferDecoded    -> BufferRendered   when kWhatFrameRendered
    // <all states>     -> EnabledNoBuffer  when flush
    // <all states>     -> EnabledNoBuffer  when stop then configure then start
    enum struct TunnelPeekState {
        kLegacyMode,
        kDisabledNoBuffer,
        kEnabledNoBuffer,
        kDisabledQueued,
        kEnabledQueued,
        kBufferDecoded,
        kBufferRendered,
    };

    enum class DequeueOutputResult {
        kNoBuffer,
        kDiscardedBuffer,
        kRepliedWithError,
        kSuccess,
    };

    struct ResourceManagerServiceProxy;

    State mState;
    bool mReleasedByResourceManager;
    sp<ALooper> mLooper;
    sp<ALooper> mCodecLooper;
    sp<CodecBase> mCodec;
    AString mComponentName;
    AString mOwnerName;
    sp<MediaCodecInfo> mCodecInfo;
    sp<AReplyToken> mReplyID;
    std::string mLastReplyOrigin;
    std::vector<sp<AMessage>> mDeferredMessages;
    uint32_t mFlags;
    int64_t mPresentationTimeUs = 0;
    status_t mStickyError;
    sp<Surface> mSurface;
    uint32_t mSurfaceGeneration = 0;
    SoftwareRenderer *mSoftRenderer;

    Mutex mMetricsLock;
    mediametrics_handle_t mMetricsHandle = 0;
    bool mMetricsToUpload = false;
    nsecs_t mLifetimeStartNs = 0;
    void initMediametrics();
    void updateMediametrics();
    void flushMediametrics();
    void resetMetricsFields();
    void updateEphemeralMediametrics(mediametrics_handle_t item);
    void updateLowLatency(const sp<AMessage> &msg);
    void updateCodecImportance(const sp<AMessage>& msg);
    void onGetMetrics(const sp<AMessage>& msg);
    constexpr const char *asString(TunnelPeekState state, const char *default_string="?");
    void updateTunnelPeek(const sp<AMessage> &msg);
    void processRenderedFrames(const sp<AMessage> &msg);

    inline void initClientConfigParcel(ClientConfigParcel& clientConfig);

    sp<AMessage> mOutputFormat;
    sp<AMessage> mInputFormat;
    sp<AMessage> mCallback;
    sp<AMessage> mOnFrameRenderedNotification;
    sp<AMessage> mAsyncReleaseCompleteNotification;
    sp<AMessage> mOnFirstTunnelFrameReadyNotification;

    std::shared_ptr<ResourceManagerServiceProxy> mResourceManagerProxy;

    Domain mDomain;
    AString mLogSessionId;
    int32_t mWidth;
    int32_t mHeight;
    int32_t mRotationDegrees;
    int32_t mAllowFrameDroppingBySurface;

    enum {
        kFlagHasHdrStaticInfo   = 1,
        kFlagHasHdr10PlusInfo   = 2,
    };
    uint32_t mHdrInfoFlags;
    void updateHdrMetrics(bool isConfig);
    hdr_format getHdrFormat(const AString &mime, const int32_t profile,
            const int32_t colorTransfer);
    hdr_format getHdrFormatForEncoder(const AString &mime, const int32_t profile,
            const int32_t colorTransfer);
    hdr_format getHdrFormatForDecoder(const AString &mime, const int32_t profile,
            const int32_t colorTransfer);
    bool profileSupport10Bits(const AString &mime, const int32_t profile);

    struct ApiUsageMetrics {
        bool isArrayMode;
        enum OperationMode {
            kUnknownMode = 0,
            kSynchronousMode = 1,
            kAsynchronousMode = 2,
            kBlockMode = 3,
        };
        OperationMode operationMode;
        bool isUsingOutputSurface;
        struct InputBufferSize {
            int32_t appMax;  // max size configured by the app
            int32_t usedMax;  // max size actually used
            int32_t codecMax;  // max size suggested by the codec
        } inputBufferSize;
    } mApiUsageMetrics;
    struct ReliabilityContextMetrics {
        int32_t flushCount;
        int32_t setOutputSurfaceCount;
        int32_t resolutionChangeCount;
    } mReliabilityContextMetrics;

    // initial create parameters
    AString mInitName;

    // configure parameter
    sp<AMessage> mConfigureMsg;

    // rewrites the format description during configure() for encoding.
    // format and flags as they exist within configure()
    // the (possibly) updated format is returned in place.
    status_t shapeMediaFormat(
            const sp<AMessage> &format,
            uint32_t flags,
            mediametrics_handle_t handle);

    // populate the format shaper library with information for this codec encoding
    // for the indicated media type
    status_t setupFormatShaper(AString mediaType);

    // Used only to synchronize asynchronous getBufferAndFormat
    // across all the other (synchronous) buffer state change
    // operations, such as de/queueIn/OutputBuffer, start and
    // stop/flush/reset/release.
    Mutex mBufferLock;

    std::list<size_t> mAvailPortBuffers[2];
    std::vector<BufferInfo> mPortBuffers[2];

    int32_t mDequeueInputTimeoutGeneration;
    sp<AReplyToken> mDequeueInputReplyID;

    int32_t mDequeueOutputTimeoutGeneration;
    sp<AReplyToken> mDequeueOutputReplyID;

    sp<ICrypto> mCrypto;

    int32_t mTunneledInputWidth;
    int32_t mTunneledInputHeight;
    bool mTunneled;
    TunnelPeekState mTunnelPeekState;
    bool mTunnelPeekEnabled;

    sp<IDescrambler> mDescrambler;

    std::list<sp<ABuffer> > mCSD;

    sp<AMessage> mActivityNotify;

    bool mHaveInputSurface;
    bool mHavePendingInputBuffers;
    bool mCpuBoostRequested;

    std::shared_ptr<BufferChannelBase> mBufferChannel;
    sp<CryptoAsync> mCryptoAsync;
    sp<ALooper> mCryptoLooper;

    bool mIsSurfaceToDisplay;
    bool mAreRenderMetricsEnabled;
    PlaybackDurationAccumulator mPlaybackDurationAccumulator;
    VideoRenderQualityTracker mVideoRenderQualityTracker;

    MediaCodec(
            const sp<ALooper> &looper, pid_t pid, uid_t uid,
            std::function<sp<CodecBase>(const AString &, const char *)> getCodecBase = nullptr,
            std::function<status_t(const AString &, sp<MediaCodecInfo> *)> getCodecInfo = nullptr);

    static sp<CodecBase> GetCodecBase(const AString &name, const char *owner = nullptr);

    static status_t PostAndAwaitResponse(
            const sp<AMessage> &msg, sp<AMessage> *response);

    void PostReplyWithError(const sp<AMessage> &msg, int32_t err);
    void PostReplyWithError(const sp<AReplyToken> &replyID, int32_t err);

    status_t init(const AString &name);

    void setState(State newState);
    void returnBuffersToCodec(bool isReclaim = false);
    void returnBuffersToCodecOnPort(int32_t portIndex, bool isReclaim = false);
    size_t updateBuffers(int32_t portIndex, const sp<AMessage> &msg);
    status_t onQueueInputBuffer(const sp<AMessage> &msg);
    status_t onReleaseOutputBuffer(const sp<AMessage> &msg);
    BufferInfo *peekNextPortBuffer(int32_t portIndex);
    ssize_t dequeuePortBuffer(int32_t portIndex);

    status_t getBufferAndFormat(
            size_t portIndex, size_t index,
            sp<MediaCodecBuffer> *buffer, sp<AMessage> *format);

    bool handleDequeueInputBuffer(const sp<AReplyToken> &replyID, bool newRequest = false);
    DequeueOutputResult handleDequeueOutputBuffer(
            const sp<AReplyToken> &replyID,
            bool newRequest = false);
    void cancelPendingDequeueOperations();

    void extractCSD(const sp<AMessage> &format);
    status_t queueCSDInputBuffer(size_t bufferIndex);

    status_t handleSetSurface(const sp<Surface> &surface);
    status_t connectToSurface(const sp<Surface> &surface, uint32_t *generation);
    status_t disconnectFromSurface();

    bool hasCryptoOrDescrambler() {
        return mCrypto != NULL || mDescrambler != NULL;
    }

    void postActivityNotificationIfPossible();

    void onInputBufferAvailable();
    void onOutputBufferAvailable();
    void onCryptoError(const sp<AMessage> &msg);
    void onError(status_t err, int32_t actionCode, const char *detail = NULL);
    void onOutputFormatChanged();

    status_t onSetParameters(const sp<AMessage> &params);

    status_t amendOutputFormatWithCodecSpecificData(const sp<MediaCodecBuffer> &buffer);
    void handleOutputFormatChangeIfNeeded(const sp<MediaCodecBuffer> &buffer);
    bool isExecuting() const;

    uint64_t getGraphicBufferSize();
    void requestCpuBoostIfNeeded();

    bool hasPendingBuffer(int portIndex);
    bool hasPendingBuffer();

    void postPendingRepliesAndDeferredMessages(std::string origin, status_t err = OK);
    void postPendingRepliesAndDeferredMessages(std::string origin, const sp<AMessage> &response);

    /* called to get the last codec error when the sticky flag is set.
     * if no such codec error is found, returns UNKNOWN_ERROR.
     */
    inline status_t getStickyError() const {
        return mStickyError != 0 ? mStickyError : UNKNOWN_ERROR;
    }

    inline void setStickyError(status_t err) {
        mFlags |= kFlagStickyError;
        mStickyError = err;
    }

    void onReleaseCrypto(const sp<AMessage>& msg);

    // managing time-of-flight aka latency
    typedef struct {
            int64_t presentationUs;
            int64_t startedNs;
    } BufferFlightTiming_t;
    std::deque<BufferFlightTiming_t> mBuffersInFlight;
    Mutex mLatencyLock;
    int64_t mLatencyUnknown;    // buffers for which we couldn't calculate latency

    Mutex mOutputStatsLock;
    int64_t mBytesEncoded = 0;
    int64_t mEarliestEncodedPtsUs = INT64_MAX;
    int64_t mLatestEncodedPtsUs = INT64_MIN;
    int64_t mFramesEncoded = 0;
    int64_t mBytesInput = 0;
    int64_t mFramesInput = 0;

    int64_t mNumLowLatencyEnables;  // how many times low latency mode is enabled
    int64_t mNumLowLatencyDisables;  // how many times low latency mode is disabled
    bool mIsLowLatencyModeOn;  // is low latency mode on currently
    int64_t mIndexOfFirstFrameWhenLowLatencyOn;  // index of the first frame queued
                                                 // when low latency is on
    int64_t mInputBufferCounter;  // number of input buffers queued since last reset/flush

    // A rescheduleable message that periodically polls for rendered buffers
    sp<AMessage> mMsgPollForRenderedBuffers;

    class ReleaseSurface;
    std::unique_ptr<ReleaseSurface> mReleaseSurface;

    std::list<sp<AMessage>> mLeftover;
    status_t handleLeftover(size_t index);

    sp<BatteryChecker> mBatteryChecker;

    void statsBufferSent(int64_t presentationUs, const sp<MediaCodecBuffer> &buffer);
    void statsBufferReceived(int64_t presentationUs, const sp<MediaCodecBuffer> &buffer);
    bool discardDecodeOnlyOutputBuffer(size_t index);

    enum {
        // the default shape of our latency histogram buckets
        // XXX: should these be configurable in some way?
        kLatencyHistBuckets = 20,
        kLatencyHistWidth = 2000,
        kLatencyHistFloor = 2000,

        // how many samples are in the 'recent latency' histogram
        // 300 frames = 5 sec @ 60fps or ~12 sec @ 24fps
        kRecentLatencyFrames = 300,

        // how we initialize mRecentSamples
        kRecentSampleInvalid = -1,
    };

    int64_t mRecentSamples[kRecentLatencyFrames];
    int mRecentHead;
    Mutex mRecentLock;

    MediaHistogram<int64_t> mLatencyHist;

    // An unique ID for the codec - Used by the metrics.
    uint64_t mCodecId = 0;
    bool     mIsHardware = false;

    std::function<sp<CodecBase>(const AString &, const char *)> mGetCodecBase;
    std::function<status_t(const AString &, sp<MediaCodecInfo> *)> mGetCodecInfo;
    friend class MediaTestHelper;

    CodecErrorLog mErrorLog;

    DISALLOW_EVIL_CONSTRUCTORS(MediaCodec);
};

}  // namespace android

#endif  // MEDIA_CODEC_H_
