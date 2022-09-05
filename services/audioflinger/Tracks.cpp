/*
**
** Copyright 2012, The Android Open Source Project
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

#define LOG_TAG "AudioFlinger"
//#define LOG_NDEBUG 0
#define ATRACE_TAG ATRACE_TAG_AUDIO

#include "MmapTracks.h"
#include "PlaybackTracks.h"
#include "RecordTracks.h"

#include "Client.h"
#include "IAfEffect.h"
#include "IAfThread.h"
#include "ResamplerBufferProvider.h"

#include <audio_utils/minifloat.h>
#include <media/AudioValidator.h>
#include <media/RecordBufferConverter.h>
#include <media/nbaio/Pipe.h>
#include <media/nbaio/PipeReader.h>
#include <mediautils/ServiceUtilities.h>
#include <mediautils/SharedMemoryAllocator.h>
#include <private/media/AudioTrackShared.h>
#include <utils/Log.h>
#include <utils/Trace.h>

#include <linux/futex.h>
#include <math.h>
#include <sys/syscall.h>

// ----------------------------------------------------------------------------

// Note: the following macro is used for extremely verbose logging message.  In
// order to run with ALOG_ASSERT turned on, we need to have LOG_NDEBUG set to
// 0; but one side effect of this is to turn all LOGV's as well.  Some messages
// are so verbose that we want to suppress them even when we have ALOG_ASSERT
// turned on.  Do not uncomment the #def below unless you really know what you
// are doing and want to see all of the extremely verbose messages.
//#define VERY_VERY_VERBOSE_LOGGING
#ifdef VERY_VERY_VERBOSE_LOGGING
#define ALOGVV ALOGV
#else
#define ALOGVV(a...) do { } while(0)
#endif

// TODO: Remove when this is put into AidlConversionUtil.h
#define VALUE_OR_RETURN_BINDER_STATUS(x)    \
    ({                                      \
       auto _tmp = (x);                     \
       if (!_tmp.ok()) return ::android::aidl_utils::binderStatusFromStatusT(_tmp.error()); \
       std::move(_tmp.value());             \
     })

namespace android {

using ::android::aidl_utils::binderStatusFromStatusT;
using binder::Status;
using content::AttributionSourceState;
using media::VolumeShaper;
// ----------------------------------------------------------------------------
//      TrackBase
// ----------------------------------------------------------------------------
#undef LOG_TAG
#define LOG_TAG "AF::TrackBase"

static volatile int32_t nextTrackId = 55;

// TrackBase constructor must be called with AudioFlinger::mLock held
TrackBase::TrackBase(
        IAfThreadBase *thread,
            const sp<Client>& client,
            const audio_attributes_t& attr,
            uint32_t sampleRate,
            audio_format_t format,
            audio_channel_mask_t channelMask,
            size_t frameCount,
            void *buffer,
            size_t bufferSize,
            audio_session_t sessionId,
            pid_t creatorPid,
            uid_t clientUid,
            bool isOut,
            const alloc_type alloc,
            track_type type,
            audio_port_handle_t portId,
            std::string metricsId)
    :
        mThread(thread),
        mAllocType(alloc),
        mClient(client),
        mCblk(NULL),
        // mBuffer, mBufferSize
        mState(IDLE),
        mAttr(attr),
        mSampleRate(sampleRate),
        mFormat(format),
        mChannelMask(channelMask),
        mChannelCount(isOut ?
                audio_channel_count_from_out_mask(channelMask) :
                audio_channel_count_from_in_mask(channelMask)),
        mFrameSize(audio_bytes_per_frame(mChannelCount, format)),
        mFrameCount(frameCount),
        mSessionId(sessionId),
        mIsOut(isOut),
        mId(android_atomic_inc(&nextTrackId)),
        mTerminated(false),
        mType(type),
        mThreadIoHandle(thread ? thread->id() : AUDIO_IO_HANDLE_NONE),
        mPortId(portId),
        mIsInvalid(false),
        mTrackMetrics(std::move(metricsId), isOut, clientUid),
        mCreatorPid(creatorPid)
{
    const uid_t callingUid = IPCThreadState::self()->getCallingUid();
    if (!isAudioServerOrMediaServerUid(callingUid) || clientUid == AUDIO_UID_INVALID) {
        ALOGW_IF(clientUid != AUDIO_UID_INVALID && clientUid != callingUid,
                "%s(%d): uid %d tried to pass itself off as %d",
                 __func__, mId, callingUid, clientUid);
        clientUid = callingUid;
    }
    // clientUid contains the uid of the app that is responsible for this track, so we can blame
    // battery usage on it.
    mUid = clientUid;

    // ALOGD("Creating track with %d buffers @ %d bytes", bufferCount, bufferSize);

    size_t minBufferSize = buffer == NULL ? roundup(frameCount) : frameCount;
    // check overflow when computing bufferSize due to multiplication by mFrameSize.
    if (minBufferSize < frameCount  // roundup rounds down for values above UINT_MAX / 2
            || mFrameSize == 0   // format needs to be correct
            || minBufferSize > SIZE_MAX / mFrameSize) {
        android_errorWriteLog(0x534e4554, "34749571");
        return;
    }
    minBufferSize *= mFrameSize;

    if (buffer == nullptr) {
        bufferSize = minBufferSize; // allocated here.
    } else if (minBufferSize > bufferSize) {
        android_errorWriteLog(0x534e4554, "38340117");
        return;
    }

    size_t size = sizeof(audio_track_cblk_t);
    if (buffer == NULL && alloc == ALLOC_CBLK) {
        // check overflow when computing allocation size for streaming tracks.
        if (size > SIZE_MAX - bufferSize) {
            android_errorWriteLog(0x534e4554, "34749571");
            return;
        }
        size += bufferSize;
    }

    if (client != 0) {
        mCblkMemory = client->allocator().allocate(mediautils::NamedAllocRequest{{size},
                std::string("Track ID: ").append(std::to_string(mId))});
        if (mCblkMemory == 0 ||
                (mCblk = static_cast<audio_track_cblk_t *>(mCblkMemory->unsecurePointer())) == NULL) {
            ALOGE("%s(%d): not enough memory for AudioTrack size=%zu", __func__, mId, size);
            ALOGE("%s", client->allocator().dump().c_str());
            mCblkMemory.clear();
            return;
        }
    } else {
        mCblk = (audio_track_cblk_t *) malloc(size);
        if (mCblk == NULL) {
            ALOGE("%s(%d): not enough memory for AudioTrack size=%zu", __func__, mId, size);
            return;
        }
    }

    // construct the shared structure in-place.
    if (mCblk != NULL) {
        new(mCblk) audio_track_cblk_t();
        switch (alloc) {
        case ALLOC_READONLY: {
            const sp<MemoryDealer> roHeap(thread->readOnlyHeap());
            if (roHeap == 0 ||
                    (mBufferMemory = roHeap->allocate(bufferSize)) == 0 ||
                    (mBuffer = mBufferMemory->unsecurePointer()) == NULL) {
                ALOGE("%s(%d): not enough memory for read-only buffer size=%zu",
                        __func__, mId, bufferSize);
                if (roHeap != 0) {
                    roHeap->dump("buffer");
                }
                mCblkMemory.clear();
                mBufferMemory.clear();
                return;
            }
            memset(mBuffer, 0, bufferSize);
            } break;
        case ALLOC_PIPE:
            mBufferMemory = thread->pipeMemory();
            // mBuffer is the virtual address as seen from current process (mediaserver),
            // and should normally be coming from mBufferMemory->unsecurePointer().
            // However in this case the TrackBase does not reference the buffer directly.
            // It should references the buffer via the pipe.
            // Therefore, to detect incorrect usage of the buffer, we set mBuffer to NULL.
            mBuffer = NULL;
            bufferSize = 0;
            break;
        case ALLOC_CBLK:
            // clear all buffers
            if (buffer == NULL) {
                mBuffer = (char*)mCblk + sizeof(audio_track_cblk_t);
                memset(mBuffer, 0, bufferSize);
            } else {
                mBuffer = buffer;
#if 0
                mCblk->mFlags = CBLK_FORCEREADY;    // FIXME hack, need to fix the track ready logic
#endif
            }
            break;
        case ALLOC_LOCAL:
            mBuffer = calloc(1, bufferSize);
            break;
        case ALLOC_NONE:
            mBuffer = buffer;
            break;
        default:
            LOG_ALWAYS_FATAL("%s(%d): invalid allocation type: %d", __func__, mId, (int)alloc);
        }
        mBufferSize = bufferSize;

#ifdef TEE_SINK
        mTee.set(sampleRate, mChannelCount, format, NBAIO_Tee::TEE_FLAG_TRACK);
#endif
        // mState is mirrored for the client to read.
        mState.setMirror(&mCblk->mState);
        // ensure our state matches up until we consolidate the enumeration.
        static_assert(CBLK_STATE_IDLE == IDLE);
        static_assert(CBLK_STATE_PAUSING == PAUSING);
    }
}

// TODO b/182392769: use attribution source util
static AttributionSourceState audioServerAttributionSource(pid_t pid) {
   AttributionSourceState attributionSource{};
   attributionSource.uid = AID_AUDIOSERVER;
   attributionSource.pid = pid;
   attributionSource.token = sp<BBinder>::make();
   return attributionSource;
}

status_t TrackBase::initCheck() const
{
    status_t status;
    if (mType == TYPE_OUTPUT || mType == TYPE_PATCH) {
        status = cblk() != NULL ? NO_ERROR : NO_MEMORY;
    } else {
        status = getCblk() != 0 ? NO_ERROR : NO_MEMORY;
    }
    return status;
}

TrackBase::~TrackBase()
{
    // delete the proxy before deleting the shared memory it refers to, to avoid dangling reference
    mServerProxy.clear();
    releaseCblk();
    mCblkMemory.clear();    // free the shared memory before releasing the heap it belongs to
    if (mClient != 0) {
        // Client destructor must run with AudioFlinger client mutex locked
        audio_utils::lock_guard _l(mClient->afClientCallback()->clientMutex());
        // If the client's reference count drops to zero, the associated destructor
        // must run with AudioFlinger lock held. Thus the explicit clear() rather than
        // relying on the automatic clear() at end of scope.
        mClient.clear();
    }
    if (mAllocType == ALLOC_LOCAL) {
        free(mBuffer);
        mBuffer = nullptr;
    }
    // flush the binder command buffer
    IPCThreadState::self()->flushCommands();
}

// AudioBufferProvider interface
// getNextBuffer() = 0;
// This implementation of releaseBuffer() is used by Track and RecordTrack
void TrackBase::releaseBuffer(AudioBufferProvider::Buffer* buffer)
{
#ifdef TEE_SINK
    mTee.write(buffer->raw, buffer->frameCount);
#endif

    ServerProxy::Buffer buf;
    buf.mFrameCount = buffer->frameCount;
    buf.mRaw = buffer->raw;
    buffer->frameCount = 0;
    buffer->raw = NULL;
    mServerProxy->releaseBuffer(&buf);
}

status_t TrackBase::setSyncEvent(
        const sp<audioflinger::SyncEvent>& event)
{
    mSyncEvents.emplace_back(event);
    return NO_ERROR;
}

PatchTrackBase::PatchTrackBase(const sp<ClientProxy>& proxy,
        IAfThreadBase* thread, const Timeout& timeout)
    : mProxy(proxy)
{
    if (timeout) {
        setPeerTimeout(*timeout);
    } else {
        // Double buffer mixer
        uint64_t mixBufferNs = ((uint64_t)2 * thread->frameCount() * 1000000000) /
                                              thread->sampleRate();
        setPeerTimeout(std::chrono::nanoseconds{mixBufferNs});
    }
}

void PatchTrackBase::setPeerTimeout(std::chrono::nanoseconds timeout) {
    mPeerTimeout.tv_sec = timeout.count() / std::nano::den;
    mPeerTimeout.tv_nsec = timeout.count() % std::nano::den;
}


// ----------------------------------------------------------------------------
//      Playback
// ----------------------------------------------------------------------------
#undef LOG_TAG
#define LOG_TAG "AF::TrackHandle"

class TrackHandle : public android::media::BnAudioTrack {
public:
    explicit TrackHandle(const sp<IAfTrack>& track);
    ~TrackHandle() override;

    binder::Status getCblk(std::optional<media::SharedFileRegion>* _aidl_return) final;
    binder::Status start(int32_t* _aidl_return) final;
    binder::Status stop() final;
    binder::Status flush() final;
    binder::Status pause() final;
    binder::Status attachAuxEffect(int32_t effectId, int32_t* _aidl_return) final;
    binder::Status setParameters(const std::string& keyValuePairs,
                                 int32_t* _aidl_return) final;
    binder::Status selectPresentation(int32_t presentationId, int32_t programId,
                                      int32_t* _aidl_return) final;
    binder::Status getTimestamp(media::AudioTimestampInternal* timestamp,
                                int32_t* _aidl_return) final;
    binder::Status signal() final;
    binder::Status applyVolumeShaper(const media::VolumeShaperConfiguration& configuration,
                                     const media::VolumeShaperOperation& operation,
                                     int32_t* _aidl_return) final;
    binder::Status getVolumeShaperState(
            int32_t id,
            std::optional<media::VolumeShaperState>* _aidl_return) final;
    binder::Status getDualMonoMode(
            media::audio::common::AudioDualMonoMode* _aidl_return) final;
    binder::Status setDualMonoMode(
            media::audio::common::AudioDualMonoMode mode) final;
    binder::Status getAudioDescriptionMixLevel(float* _aidl_return) final;
    binder::Status setAudioDescriptionMixLevel(float leveldB) final;
    binder::Status getPlaybackRateParameters(
            media::audio::common::AudioPlaybackRate* _aidl_return) final;
    binder::Status setPlaybackRateParameters(
            const media::audio::common::AudioPlaybackRate& playbackRate) final;

private:
    const sp<IAfTrack> mTrack;
};

/* static */
sp<media::IAudioTrack> IAfTrack::createIAudioTrackAdapter(const sp<IAfTrack>& track) {
    return sp<TrackHandle>::make(track);
}

TrackHandle::TrackHandle(const sp<IAfTrack>& track)
    : BnAudioTrack(),
      mTrack(track)
{
    setMinSchedulerPolicy(SCHED_NORMAL, ANDROID_PRIORITY_AUDIO);
}

TrackHandle::~TrackHandle() {
    // just stop the track on deletion, associated resources
    // will be freed from the main thread once all pending buffers have
    // been played. Unless it's not in the active track list, in which
    // case we free everything now...
    mTrack->destroy();
}

Status TrackHandle::getCblk(
        std::optional<media::SharedFileRegion>* _aidl_return) {
    *_aidl_return = legacy2aidl_NullableIMemory_SharedFileRegion(mTrack->getCblk()).value();
    return Status::ok();
}

Status TrackHandle::start(int32_t* _aidl_return) {
    *_aidl_return = mTrack->start();
    return Status::ok();
}

Status TrackHandle::stop() {
    mTrack->stop();
    return Status::ok();
}

Status TrackHandle::flush() {
    mTrack->flush();
    return Status::ok();
}

Status TrackHandle::pause() {
    mTrack->pause();
    return Status::ok();
}

Status TrackHandle::attachAuxEffect(int32_t effectId,
                                                  int32_t* _aidl_return) {
    *_aidl_return = mTrack->attachAuxEffect(effectId);
    return Status::ok();
}

Status TrackHandle::setParameters(const std::string& keyValuePairs,
                                                int32_t* _aidl_return) {
    *_aidl_return = mTrack->setParameters(String8(keyValuePairs.c_str()));
    return Status::ok();
}

Status TrackHandle::selectPresentation(int32_t presentationId, int32_t programId,
                                                     int32_t* _aidl_return) {
    *_aidl_return = mTrack->selectPresentation(presentationId, programId);
    return Status::ok();
}

Status TrackHandle::getTimestamp(media::AudioTimestampInternal* timestamp,
                                               int32_t* _aidl_return) {
    AudioTimestamp legacy;
    *_aidl_return = mTrack->getTimestamp(legacy);
    if (*_aidl_return != OK) {
        return Status::ok();
    }

    // restrict position modulo INT_MAX to avoid integer sanitization abort
    legacy.mPosition &= INT_MAX;

    *timestamp = legacy2aidl_AudioTimestamp_AudioTimestampInternal(legacy).value();
    return Status::ok();
}

Status TrackHandle::signal() {
    mTrack->signal();
    return Status::ok();
}

Status TrackHandle::applyVolumeShaper(
        const media::VolumeShaperConfiguration& configuration,
        const media::VolumeShaperOperation& operation,
        int32_t* _aidl_return) {
    sp<VolumeShaper::Configuration> conf = new VolumeShaper::Configuration();
    *_aidl_return = conf->readFromParcelable(configuration);
    if (*_aidl_return != OK) {
        return Status::ok();
    }

    sp<VolumeShaper::Operation> op = new VolumeShaper::Operation();
    *_aidl_return = op->readFromParcelable(operation);
    if (*_aidl_return != OK) {
        return Status::ok();
    }

    *_aidl_return = mTrack->applyVolumeShaper(conf, op);
    return Status::ok();
}

Status TrackHandle::getVolumeShaperState(
        int32_t id,
        std::optional<media::VolumeShaperState>* _aidl_return) {
    sp<VolumeShaper::State> legacy = mTrack->getVolumeShaperState(id);
    if (legacy == nullptr) {
        _aidl_return->reset();
        return Status::ok();
    }
    media::VolumeShaperState aidl;
    legacy->writeToParcelable(&aidl);
    *_aidl_return = aidl;
    return Status::ok();
}

Status TrackHandle::getDualMonoMode(
        media::audio::common::AudioDualMonoMode* _aidl_return)
{
    audio_dual_mono_mode_t mode = AUDIO_DUAL_MONO_MODE_OFF;
    const status_t status = mTrack->getDualMonoMode(&mode)
            ?: AudioValidator::validateDualMonoMode(mode);
    if (status == OK) {
        *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
                legacy2aidl_audio_dual_mono_mode_t_AudioDualMonoMode(mode));
    }
    return binderStatusFromStatusT(status);
}

Status TrackHandle::setDualMonoMode(
        media::audio::common::AudioDualMonoMode mode)
{
    const auto localMonoMode = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioDualMonoMode_audio_dual_mono_mode_t(mode));
    return binderStatusFromStatusT(AudioValidator::validateDualMonoMode(localMonoMode)
            ?: mTrack->setDualMonoMode(localMonoMode));
}

Status TrackHandle::getAudioDescriptionMixLevel(float* _aidl_return)
{
    float leveldB = -std::numeric_limits<float>::infinity();
    const status_t status = mTrack->getAudioDescriptionMixLevel(&leveldB)
            ?: AudioValidator::validateAudioDescriptionMixLevel(leveldB);
    if (status == OK) *_aidl_return = leveldB;
    return binderStatusFromStatusT(status);
}

Status TrackHandle::setAudioDescriptionMixLevel(float leveldB)
{
    return binderStatusFromStatusT(AudioValidator::validateAudioDescriptionMixLevel(leveldB)
             ?: mTrack->setAudioDescriptionMixLevel(leveldB));
}

Status TrackHandle::getPlaybackRateParameters(
        media::audio::common::AudioPlaybackRate* _aidl_return)
{
    audio_playback_rate_t localPlaybackRate{};
    status_t status = mTrack->getPlaybackRateParameters(&localPlaybackRate)
            ?: AudioValidator::validatePlaybackRate(localPlaybackRate);
    if (status == NO_ERROR) {
        *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
                legacy2aidl_audio_playback_rate_t_AudioPlaybackRate(localPlaybackRate));
    }
    return binderStatusFromStatusT(status);
}

Status TrackHandle::setPlaybackRateParameters(
        const media::audio::common::AudioPlaybackRate& playbackRate)
{
    const audio_playback_rate_t localPlaybackRate = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioPlaybackRate_audio_playback_rate_t(playbackRate));
    return binderStatusFromStatusT(AudioValidator::validatePlaybackRate(localPlaybackRate)
            ?: mTrack->setPlaybackRateParameters(localPlaybackRate));
}

// ----------------------------------------------------------------------------
//      AppOp for audio playback
// -------------------------------

// static
sp<OpPlayAudioMonitor> OpPlayAudioMonitor::createIfNeeded(
            IAfThreadBase* thread,
            const AttributionSourceState& attributionSource, const audio_attributes_t& attr, int id,
            audio_stream_type_t streamType)
{
    Vector<String16> packages;
    const uid_t uid = VALUE_OR_FATAL(aidl2legacy_int32_t_uid_t(attributionSource.uid));
    getPackagesForUid(uid, packages);
    if (isServiceUid(uid)) {
        if (packages.isEmpty()) {
            ALOGW("OpPlayAudio: not muting track:%d usage:%d for service UID %d", id, attr.usage,
                  uid);
            return nullptr;
        }
    }
    // stream type has been filtered by audio policy to indicate whether it can be muted
    if (streamType == AUDIO_STREAM_ENFORCED_AUDIBLE) {
        ALOGD("OpPlayAudio: not muting track:%d usage:%d ENFORCED_AUDIBLE", id, attr.usage);
        return nullptr;
    }
    if ((attr.flags & AUDIO_FLAG_BYPASS_INTERRUPTION_POLICY)
            == AUDIO_FLAG_BYPASS_INTERRUPTION_POLICY) {
        ALOGD("OpPlayAudio: not muting track:%d flags %#x have FLAG_BYPASS_INTERRUPTION_POLICY",
            id, attr.flags);
        return nullptr;
    }
    return sp<OpPlayAudioMonitor>::make(thread, attributionSource, attr.usage, id, uid);
}

OpPlayAudioMonitor::OpPlayAudioMonitor(IAfThreadBase* thread,
                                       const AttributionSourceState& attributionSource,
                                       audio_usage_t usage, int id, uid_t uid)
    : mThread(wp<IAfThreadBase>::fromExisting(thread)),
      mHasOpPlayAudio(true),
      mUsage((int32_t)usage),
      mId(id),
      mUid(uid),
      mPackageName(VALUE_OR_FATAL(aidl2legacy_string_view_String16(
                  attributionSource.packageName.value_or("")))) {}

OpPlayAudioMonitor::~OpPlayAudioMonitor()
{
    if (mOpCallback != 0) {
        mAppOpsManager.stopWatchingMode(mOpCallback);
    }
    mOpCallback.clear();
}

void OpPlayAudioMonitor::onFirstRef()
{
    // make sure not to broadcast the initial state since it is not needed and could
    // cause a deadlock since this method can be called with the mThread->mLock held
    checkPlayAudioForUsage(/*doBroadcast=*/false);
    if (mPackageName.size()) {
        mOpCallback = new PlayAudioOpCallback(this);
        mAppOpsManager.startWatchingMode(AppOpsManager::OP_PLAY_AUDIO, mPackageName, mOpCallback);
    } else {
        ALOGW("Skipping OpPlayAudioMonitor due to null package name");
    }
}

bool OpPlayAudioMonitor::hasOpPlayAudio() const {
    return mHasOpPlayAudio.load();
}

// Note this method is never called (and never to be) for audio server / patch record track
// - not called from constructor due to check on UID,
// - not called from PlayAudioOpCallback because the callback is not installed in this case
void OpPlayAudioMonitor::checkPlayAudioForUsage(bool doBroadcast) {
    const bool hasAppOps =
            mPackageName.size() &&
            mAppOpsManager.checkAudioOpNoThrow(AppOpsManager::OP_PLAY_AUDIO, mUsage, mUid,
                                               mPackageName) == AppOpsManager::MODE_ALLOWED;

    bool shouldChange = !hasAppOps;  // check if we need to update.
    if (mHasOpPlayAudio.compare_exchange_strong(shouldChange, hasAppOps)) {
        ALOGI("OpPlayAudio: track:%d package:%s usage:%d %smuted", mId,
              String8(mPackageName).c_str(), mUsage, hasAppOps ? "not " : "");
        if (doBroadcast) {
            auto thread = mThread.promote();
            if (thread != nullptr && thread->type() == IAfThreadBase::OFFLOAD) {
                // Wake up Thread if offloaded, otherwise it may be several seconds for update.
                audio_utils::lock_guard _l(thread->mutex());
                thread->broadcast_l();
            }
        }
    }
}

OpPlayAudioMonitor::PlayAudioOpCallback::PlayAudioOpCallback(
        const wp<OpPlayAudioMonitor>& monitor) : mMonitor(monitor)
{ }

void OpPlayAudioMonitor::PlayAudioOpCallback::opChanged(int32_t op,
            const String16& packageName) {
    if (op != AppOpsManager::OP_PLAY_AUDIO) {
        return;
    }

    ALOGI("%s OP_PLAY_AUDIO callback received for %s", __func__, String8(packageName).c_str());
    sp<OpPlayAudioMonitor> monitor = mMonitor.promote();
    if (monitor != NULL) {
        monitor->checkPlayAudioForUsage(/*doBroadcast=*/true);
    }
}

// static
void OpPlayAudioMonitor::getPackagesForUid(
    uid_t uid, Vector<String16>& packages)
{
    PermissionController permissionController;
    permissionController.getPackagesForUid(uid, packages);
}

// ----------------------------------------------------------------------------
#undef LOG_TAG
#define LOG_TAG "AF::Track"

/* static */
sp<IAfTrack> IAfTrack::create(
        IAfPlaybackThread* thread,
        const sp<Client>& client,
        audio_stream_type_t streamType,
        const audio_attributes_t& attr,
        uint32_t sampleRate,
        audio_format_t format,
        audio_channel_mask_t channelMask,
        size_t frameCount,
        void *buffer,
        size_t bufferSize,
        const sp<IMemory>& sharedBuffer,
        audio_session_t sessionId,
        pid_t creatorPid,
        const AttributionSourceState& attributionSource,
        audio_output_flags_t flags,
        track_type type,
        audio_port_handle_t portId,
        /** default behaviour is to start when there are as many frames
          * ready as possible (aka. Buffer is full). */
        size_t frameCountToBeReady,
        float speed,
        bool isSpatialized,
        bool isBitPerfect) {
    return sp<Track>::make(thread,
            client,
            streamType,
            attr,
            sampleRate,
            format,
            channelMask,
            frameCount,
            buffer,
            bufferSize,
            sharedBuffer,
            sessionId,
            creatorPid,
            attributionSource,
            flags,
            type,
            portId,
            frameCountToBeReady,
            speed,
            isSpatialized,
            isBitPerfect);
}

// Track constructor must be called with AudioFlinger::mLock and ThreadBase::mLock held
Track::Track(
        IAfPlaybackThread* thread,
            const sp<Client>& client,
            audio_stream_type_t streamType,
            const audio_attributes_t& attr,
            uint32_t sampleRate,
            audio_format_t format,
            audio_channel_mask_t channelMask,
            size_t frameCount,
            void *buffer,
            size_t bufferSize,
            const sp<IMemory>& sharedBuffer,
            audio_session_t sessionId,
            pid_t creatorPid,
            const AttributionSourceState& attributionSource,
            audio_output_flags_t flags,
            track_type type,
            audio_port_handle_t portId,
            size_t frameCountToBeReady,
            float speed,
            bool isSpatialized,
            bool isBitPerfect)
    :   TrackBase(thread, client, attr, sampleRate, format, channelMask, frameCount,
                  // TODO: Using unsecurePointer() has some associated security pitfalls
                  //       (see declaration for details).
                  //       Either document why it is safe in this case or address the
                  //       issue (e.g. by copying).
                  (sharedBuffer != 0) ? sharedBuffer->unsecurePointer() : buffer,
                  (sharedBuffer != 0) ? sharedBuffer->size() : bufferSize,
                  sessionId, creatorPid,
                  VALUE_OR_FATAL(aidl2legacy_int32_t_uid_t(attributionSource.uid)), true /*isOut*/,
                  (type == TYPE_PATCH) ? ( buffer == NULL ? ALLOC_LOCAL : ALLOC_NONE) : ALLOC_CBLK,
                  type,
                  portId,
                  std::string(AMEDIAMETRICS_KEY_PREFIX_AUDIO_TRACK) + std::to_string(portId)),
    mFillingStatus(FS_INVALID),
    // mRetryCount initialized later when needed
    mSharedBuffer(sharedBuffer),
    mStreamType(streamType),
    mMainBuffer(thread->sinkBuffer()),
    mAuxBuffer(NULL),
    mAuxEffectId(0), mHasVolumeController(false),
    mFrameMap(16 /* sink-frame-to-track-frame map memory */),
    mVolumeHandler(new media::VolumeHandler(sampleRate)),
    mOpPlayAudioMonitor(OpPlayAudioMonitor::createIfNeeded(thread, attributionSource, attr, id(),
        streamType)),
    // mSinkTimestamp
    mFastIndex(-1),
    mCachedVolume(1.0),
    /* The track might not play immediately after being active, similarly as if its volume was 0.
     * When the track starts playing, its volume will be computed. */
    mFinalVolume(0.f),
    mResumeToStopping(false),
    mFlushHwPending(false),
    mFlags(flags),
    mSpeed(speed),
    mIsSpatialized(isSpatialized),
    mIsBitPerfect(isBitPerfect)
{
    // client == 0 implies sharedBuffer == 0
    ALOG_ASSERT(!(client == 0 && sharedBuffer != 0));

    ALOGV_IF(sharedBuffer != 0, "%s(%d): sharedBuffer: %p, size: %zu",
            __func__, mId, sharedBuffer->unsecurePointer(), sharedBuffer->size());

    /* get package name */
    PermissionController permissionController;
    Vector<String16> packages;
    permissionController.getPackagesForUid(uid(), packages);
    if (!packages.isEmpty()) {
        mPackageName = String8(packages[0]);
    } else {
        mPackageName = "";
    }

    /* init app volume */
    mAppMuted = false;
    mAppVolume = 1.0f;

    if (mCblk == NULL) {
        return;
    }

    uid_t uid = VALUE_OR_FATAL(aidl2legacy_int32_t_uid_t(attributionSource.uid));
    if (!thread->isTrackAllowed_l(channelMask, format, sessionId, uid)) {
        ALOGE("%s(%d): no more tracks available", __func__, mId);
        releaseCblk(); // this makes the track invalid.
        return;
    }

    if (sharedBuffer == 0) {
        mAudioTrackServerProxy = new AudioTrackServerProxy(mCblk, mBuffer, frameCount,
                mFrameSize, !isExternalTrack(), sampleRate);
    } else {
        mAudioTrackServerProxy = new StaticAudioTrackServerProxy(mCblk, mBuffer, frameCount,
                mFrameSize, sampleRate);
    }
    mServerProxy = mAudioTrackServerProxy;
    mServerProxy->setStartThresholdInFrames(frameCountToBeReady); // update the Cblk value

    // only allocate a fast track index if we were able to allocate a normal track name
    if (flags & AUDIO_OUTPUT_FLAG_FAST) {
        // FIXME: Not calling framesReadyIsCalledByMultipleThreads() exposes a potential
        // race with setSyncEvent(). However, if we call it, we cannot properly start
        // static fast tracks (SoundPool) immediately after stopping.
        //mAudioTrackServerProxy->framesReadyIsCalledByMultipleThreads();
        ALOG_ASSERT(thread->fastTrackAvailMask_l() != 0);
        const int i = __builtin_ctz(thread->fastTrackAvailMask_l());
        ALOG_ASSERT(0 < i && i < (int)FastMixerState::sMaxFastTracks);
        // FIXME This is too eager.  We allocate a fast track index before the
        //       fast track becomes active.  Since fast tracks are a scarce resource,
        //       this means we are potentially denying other more important fast tracks from
        //       being created.  It would be better to allocate the index dynamically.
        mFastIndex = i;
        thread->fastTrackAvailMask_l() &= ~(1 << i);
    }

    mServerLatencySupported = checkServerLatencySupported(format, flags);
#ifdef TEE_SINK
    mTee.setId(std::string("_") + std::to_string(mThreadIoHandle)
            + "_" + std::to_string(mId) + "_T");
#endif

    if (thread->supportsHapticPlayback()) {
        // If the track is attached to haptic playback thread, it is potentially to have
        // HapticGenerator effect, which will generate haptic data, on the track. In that case,
        // external vibration is always created for all tracks attached to haptic playback thread.
        mAudioVibrationController = new AudioVibrationController(this);
        std::string packageName = attributionSource.packageName.has_value() ?
            attributionSource.packageName.value() : "";
        mExternalVibration = new os::ExternalVibration(
                mUid, packageName, mAttr, mAudioVibrationController);
    }

    // Once this item is logged by the server, the client can add properties.
    const char * const traits = sharedBuffer == 0 ? "" : "static";
    mTrackMetrics.logConstructor(creatorPid, uid, id(), traits, streamType);
}

Track::~Track()
{
    ALOGV("%s(%d)", __func__, mId);

    // The destructor would clear mSharedBuffer,
    // but it will not push the decremented reference count,
    // leaving the client's IMemory dangling indefinitely.
    // This prevents that leak.
    if (mSharedBuffer != 0) {
        mSharedBuffer.clear();
    }
}

status_t Track::initCheck() const
{
    status_t status = TrackBase::initCheck();
    if (status == NO_ERROR && mCblk == nullptr) {
        status = NO_MEMORY;
    }
    return status;
}

void Track::destroy()
{
    // NOTE: destroyTrack_l() can remove a strong reference to this Track
    // by removing it from mTracks vector, so there is a risk that this Tracks's
    // destructor is called. As the destructor needs to lock mLock,
    // we must acquire a strong reference on this Track before locking mLock
    // here so that the destructor is called only when exiting this function.
    // On the other hand, as long as Track::destroy() is only called by
    // TrackHandle destructor, the TrackHandle still holds a strong ref on
    // this Track with its member mTrack.
    sp<Track> keep(this);
    { // scope for mLock
        bool wasActive = false;
        const sp<IAfThreadBase> thread = mThread.promote();
        if (thread != 0) {
            audio_utils::lock_guard _l(thread->mutex());
            auto* const playbackThread = thread->asIAfPlaybackThread().get();
            wasActive = playbackThread->destroyTrack_l(this);
            forEachTeePatchTrack_l([](const auto& patchTrack) { patchTrack->destroy(); });
        }
        if (isExternalTrack() && !wasActive) {
            AudioSystem::releaseOutput(mPortId);
        }
    }
}

void Track::appendDumpHeader(String8& result) const
{
    result.appendFormat("Type     Id Active Client Session Port Id S  Flags "
                        "  Format Chn mask  SRate "
                        "ST Usg CT "
                        " G db  L dB  R dB  VS dB "
                        "  Server FrmCnt  FrmRdy F Underruns  Flushed BitPerfect"
                        "%s\n",
                        isServerLatencySupported() ? "   Latency" : "");
}

void Track::appendDump(String8& result, bool active) const
{
    char trackType;
    switch (mType) {
    case TYPE_DEFAULT:
    case TYPE_OUTPUT:
        if (isStatic()) {
            trackType = 'S'; // static
        } else {
            trackType = ' '; // normal
        }
        break;
    case TYPE_PATCH:
        trackType = 'P';
        break;
    default:
        trackType = '?';
    }

    if (isFastTrack()) {
        result.appendFormat("F%d %c %6d", mFastIndex, trackType, mId);
    } else {
        result.appendFormat("   %c %6d", trackType, mId);
    }

    char nowInUnderrun;
    switch (mObservedUnderruns.mBitFields.mMostRecent) {
    case UNDERRUN_FULL:
        nowInUnderrun = ' ';
        break;
    case UNDERRUN_PARTIAL:
        nowInUnderrun = '<';
        break;
    case UNDERRUN_EMPTY:
        nowInUnderrun = '*';
        break;
    default:
        nowInUnderrun = '?';
        break;
    }

    char fillingStatus;
    switch (mFillingStatus) {
    case FS_INVALID:
        fillingStatus = 'I';
        break;
    case FS_FILLING:
        fillingStatus = 'f';
        break;
    case FS_FILLED:
        fillingStatus = 'F';
        break;
    case FS_ACTIVE:
        fillingStatus = 'A';
        break;
    default:
        fillingStatus = '?';
        break;
    }

    // clip framesReadySafe to max representation in dump
    const size_t framesReadySafe =
            std::min(mAudioTrackServerProxy->framesReadySafe(), (size_t)99999999);

    // obtain volumes
    const gain_minifloat_packed_t vlr = mAudioTrackServerProxy->getVolumeLR();
    const std::pair<float /* volume */, bool /* active */> vsVolume =
            mVolumeHandler->getLastVolume();

    // Our effective frame count is obtained by ServerProxy::getBufferSizeInFrames()
    // as it may be reduced by the application.
    const size_t bufferSizeInFrames = (size_t)mAudioTrackServerProxy->getBufferSizeInFrames();
    // Check whether the buffer size has been modified by the app.
    const char modifiedBufferChar = bufferSizeInFrames < mFrameCount
            ? 'r' /* buffer reduced */: bufferSizeInFrames > mFrameCount
                    ? 'e' /* error */ : ' ' /* identical */;

    result.appendFormat("%7s %6u %7u %7u %2s 0x%03X "
                        "%08X %08X %6u "
                        "%2u %3x %2x "
                        "%5.2g %5.2g %5.2g %5.2g%c "
                        "%08X %6zu%c %6zu %c %9u%c %7u %10s",
            active ? "yes" : "no",
            (mClient == 0) ? getpid() : mClient->pid(),
            mSessionId,
            mPortId,
            getTrackStateAsCodedString(),
            mCblk->mFlags,

            mFormat,
            mChannelMask,
            sampleRate(),

            mStreamType,
            mAttr.usage,
            mAttr.content_type,

            20.0 * log10(mFinalVolume),
            20.0 * log10(float_from_gain(gain_minifloat_unpack_left(vlr))),
            20.0 * log10(float_from_gain(gain_minifloat_unpack_right(vlr))),
            20.0 * log10(vsVolume.first), // VolumeShaper(s) total volume
            vsVolume.second ? 'A' : ' ',  // if any VolumeShapers active

            mCblk->mServer,
            bufferSizeInFrames,
            modifiedBufferChar,
            framesReadySafe,
            fillingStatus,
            mAudioTrackServerProxy->getUnderrunFrames(),
            nowInUnderrun,
            (unsigned)mAudioTrackServerProxy->framesFlushed() % 10000000,
            isBitPerfect() ? "true" : "false"
            );

    if (isServerLatencySupported()) {
        double latencyMs;
        bool fromTrack;
        if (getTrackLatencyMs(&latencyMs, &fromTrack) == OK) {
            // Show latency in msec, followed by 't' if from track timestamp (the most accurate)
            // or 'k' if estimated from kernel because track frames haven't been presented yet.
            result.appendFormat(" %7.2lf %c", latencyMs, fromTrack ? 't' : 'k');
        } else {
            result.appendFormat("%10s", mCblk->mServer != 0 ? "unavail" : "new");
        }
    }
    result.append("\n");
}

uint32_t Track::sampleRate() const {
    return mAudioTrackServerProxy->getSampleRate();
}

// AudioBufferProvider interface
status_t Track::getNextBuffer(AudioBufferProvider::Buffer* buffer)
{
    ServerProxy::Buffer buf;
    size_t desiredFrames = buffer->frameCount;
    buf.mFrameCount = desiredFrames;
    status_t status = mServerProxy->obtainBuffer(&buf);
    buffer->frameCount = buf.mFrameCount;
    buffer->raw = buf.mRaw;
    if (buf.mFrameCount == 0 && !isStopping() && !isStopped() && !isPaused() && !isOffloaded()) {
        ALOGV("%s(%d): underrun,  framesReady(%zu) < framesDesired(%zd), state: %d",
                __func__, mId, buf.mFrameCount, desiredFrames, (int)mState);
        mAudioTrackServerProxy->tallyUnderrunFrames(desiredFrames);
    } else {
        mAudioTrackServerProxy->tallyUnderrunFrames(0);
    }
    return status;
}

void Track::releaseBuffer(AudioBufferProvider::Buffer* buffer)
{
    interceptBuffer(*buffer);
    TrackBase::releaseBuffer(buffer);
}

// TODO: compensate for time shift between HW modules.
void Track::interceptBuffer(
        const AudioBufferProvider::Buffer& sourceBuffer) {
    auto start = std::chrono::steady_clock::now();
    const size_t frameCount = sourceBuffer.frameCount;
    if (frameCount == 0) {
        return;  // No audio to intercept.
        // Additionally PatchProxyBufferProvider::obtainBuffer (called by PathTrack::getNextBuffer)
        // does not allow 0 frame size request contrary to getNextBuffer
    }
    for (auto& teePatch : mTeePatches) {
        IAfPatchRecord* patchRecord = teePatch.patchRecord.get();
        const size_t framesWritten = patchRecord->writeFrames(
                sourceBuffer.i8, frameCount, mFrameSize);
        const size_t framesLeft = frameCount - framesWritten;
        ALOGW_IF(framesLeft != 0, "%s(%d) PatchRecord %d can not provide big enough "
                 "buffer %zu/%zu, dropping %zu frames", __func__, mId, patchRecord->id(),
                 framesWritten, frameCount, framesLeft);
    }
    auto spent = ceil<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
    using namespace std::chrono_literals;
    // Average is ~20us per track, this should virtually never be logged (Logging takes >200us)
    ALOGD_IF(spent > 500us, "%s: took %lldus to intercept %zu tracks", __func__,
             spent.count(), mTeePatches.size());
}

// ExtendedAudioBufferProvider interface

// framesReady() may return an approximation of the number of frames if called
// from a different thread than the one calling Proxy->obtainBuffer() and
// Proxy->releaseBuffer(). Also note there is no mutual exclusion in the
// AudioTrackServerProxy so be especially careful calling with FastTracks.
size_t Track::framesReady() const {
    if (mSharedBuffer != 0 && (isStopped() || isStopping())) {
        // Static tracks return zero frames immediately upon stopping (for FastTracks).
        // The remainder of the buffer is not drained.
        return 0;
    }
    return mAudioTrackServerProxy->framesReady();
}

int64_t Track::framesReleased() const
{
    return mAudioTrackServerProxy->framesReleased();
}

void Track::onTimestamp(const ExtendedTimestamp &timestamp)
{
    // This call comes from a FastTrack and should be kept lockless.
    // The server side frames are already translated to client frames.
    mAudioTrackServerProxy->setTimestamp(timestamp);

    // We do not set drained here, as FastTrack timestamp may not go to very last frame.

    // Compute latency.
    // TODO: Consider whether the server latency may be passed in by FastMixer
    // as a constant for all active FastTracks.
    const double latencyMs = timestamp.getOutputServerLatencyMs(sampleRate());
    mServerLatencyFromTrack.store(true);
    mServerLatencyMs.store(latencyMs);
}

// Don't call for fast tracks; the framesReady() could result in priority inversion
bool Track::isReady() const {
    if (mFillingStatus != FS_FILLING || isStopped() || isPausing()) {
        return true;
    }

    if (isStopping()) {
        if (framesReady() > 0) {
            mFillingStatus = FS_FILLED;
        }
        return true;
    }

    size_t bufferSizeInFrames = mServerProxy->getBufferSizeInFrames();
    // Note: mServerProxy->getStartThresholdInFrames() is clamped.
    const size_t startThresholdInFrames = mServerProxy->getStartThresholdInFrames();
    const size_t framesToBeReady = std::clamp(  // clamp again to validate client values.
            std::min(startThresholdInFrames, bufferSizeInFrames), size_t(1), mFrameCount);

    if (framesReady() >= framesToBeReady || (mCblk->mFlags & CBLK_FORCEREADY)) {
        ALOGV("%s(%d): consider track ready with %zu/%zu, target was %zu)",
              __func__, mId, framesReady(), bufferSizeInFrames, framesToBeReady);
        mFillingStatus = FS_FILLED;
        android_atomic_and(~CBLK_FORCEREADY, &mCblk->mFlags);
        return true;
    }
    return false;
}

status_t Track::start(AudioSystem::sync_event_t event __unused,
                                                    audio_session_t triggerSession __unused)
{
    status_t status = NO_ERROR;
    ALOGV("%s(%d): calling pid %d session %d",
            __func__, mId, IPCThreadState::self()->getCallingPid(), mSessionId);

    const sp<IAfThreadBase> thread = mThread.promote();
    if (thread != 0) {
        if (isOffloaded()) {
            audio_utils::lock_guard _laf(thread->afThreadCallback()->mutex());
            const bool nonOffloadableGlobalEffectEnabled =
                    thread->afThreadCallback()->isNonOffloadableGlobalEffectEnabled_l();
            audio_utils::lock_guard _lth(thread->mutex());
            sp<IAfEffectChain> ec = thread->getEffectChain_l(mSessionId);
            if (nonOffloadableGlobalEffectEnabled ||
                    (ec != 0 && ec->isNonOffloadableEnabled())) {
                invalidate();
                return PERMISSION_DENIED;
            }
        }
        audio_utils::lock_guard _lth(thread->mutex());
        track_state state = mState;
        // here the track could be either new, or restarted
        // in both cases "unstop" the track

        // initial state-stopping. next state-pausing.
        // What if resume is called ?

        if (state == FLUSHED) {
            // avoid underrun glitches when starting after flush
            reset();
        }

        // clear mPauseHwPending because of pause (and possibly flush) during underrun.
        mPauseHwPending = false;
        if (state == PAUSED || state == PAUSING) {
            if (mResumeToStopping) {
                // happened we need to resume to STOPPING_1
                mState = TrackBase::STOPPING_1;
                ALOGV("%s(%d): PAUSED => STOPPING_1 on thread %d",
                        __func__, mId, (int)mThreadIoHandle);
            } else {
                mState = TrackBase::RESUMING;
                ALOGV("%s(%d): PAUSED => RESUMING on thread %d",
                        __func__,  mId, (int)mThreadIoHandle);
            }
        } else {
            mState = TrackBase::ACTIVE;
            ALOGV("%s(%d): ? => ACTIVE on thread %d",
                    __func__, mId, (int)mThreadIoHandle);
        }

        auto* const playbackThread = thread->asIAfPlaybackThread().get();

        // states to reset position info for pcm tracks
        if (audio_is_linear_pcm(mFormat)
                && (state == IDLE || state == STOPPED || state == FLUSHED)) {
            mFrameMap.reset();

            if (!isFastTrack() && (isDirect() || isOffloaded())) {
                // Start point of track -> sink frame map. If the HAL returns a
                // frame position smaller than the first written frame in
                // updateTrackFrameInfo, the timestamp can be interpolated
                // instead of using a larger value.
                mFrameMap.push(mAudioTrackServerProxy->framesReleased(),
                               playbackThread->framesWritten());
            }
        }
        if (isFastTrack()) {
            // refresh fast track underruns on start because that field is never cleared
            // by the fast mixer; furthermore, the same track can be recycled, i.e. start
            // after stop.
            mObservedUnderruns = playbackThread->getFastTrackUnderruns(mFastIndex);
        }
        status = playbackThread->addTrack_l(this);
        if (status == INVALID_OPERATION || status == PERMISSION_DENIED || status == DEAD_OBJECT) {
            triggerEvents(AudioSystem::SYNC_EVENT_PRESENTATION_COMPLETE);
            //  restore previous state if start was rejected by policy manager
            if (status == PERMISSION_DENIED || status == DEAD_OBJECT) {
                mState = state;
            }
        }

        // Audio timing metrics are computed a few mix cycles after starting.
        {
            mLogStartCountdown = LOG_START_COUNTDOWN;
            mLogStartTimeNs = systemTime();
            mLogStartFrames = mAudioTrackServerProxy->getTimestamp()
                    .mPosition[ExtendedTimestamp::LOCATION_KERNEL];
            mLogLatencyMs = 0.;
        }
        mLogForceVolumeUpdate = true;  // at least one volume logged for metrics when starting.

        if (status == NO_ERROR || status == ALREADY_EXISTS) {
            // for streaming tracks, remove the buffer read stop limit.
            mAudioTrackServerProxy->start();
        }

        // track was already in the active list, not a problem
        if (status == ALREADY_EXISTS) {
            status = NO_ERROR;
        } else {
            // Acknowledge any pending flush(), so that subsequent new data isn't discarded.
            // It is usually unsafe to access the server proxy from a binder thread.
            // But in this case we know the mixer thread (whether normal mixer or fast mixer)
            // isn't looking at this track yet:  we still hold the normal mixer thread lock,
            // and for fast tracks the track is not yet in the fast mixer thread's active set.
            // For static tracks, this is used to acknowledge change in position or loop.
            ServerProxy::Buffer buffer;
            buffer.mFrameCount = 1;
            (void) mAudioTrackServerProxy->obtainBuffer(&buffer, true /*ackFlush*/);
        }
        if (status == NO_ERROR) {
            forEachTeePatchTrack_l([](const auto& patchTrack) { patchTrack->start(); });
        }
    } else {
        status = BAD_VALUE;
    }
    if (status == NO_ERROR) {
        // send format to AudioManager for playback activity monitoring
        const sp<IAudioManager> audioManager =
                thread->afThreadCallback()->getOrCreateAudioManager();
        if (audioManager && mPortId != AUDIO_PORT_HANDLE_NONE) {
            std::unique_ptr<os::PersistableBundle> bundle =
                    std::make_unique<os::PersistableBundle>();
        bundle->putBoolean(String16(kExtraPlayerEventSpatializedKey),
                           isSpatialized());
        bundle->putInt(String16(kExtraPlayerEventSampleRateKey), mSampleRate);
        bundle->putInt(String16(kExtraPlayerEventChannelMaskKey), mChannelMask);
        status_t result = audioManager->portEvent(mPortId,
                                                  PLAYER_UPDATE_FORMAT, bundle);
        if (result != OK) {
            ALOGE("%s: unable to send playback format for port ID %d, status error %d",
                  __func__, mPortId, result);
        }
      }
    }
    return status;
}

void Track::stop()
{
    ALOGV("%s(%d): calling pid %d", __func__, mId, IPCThreadState::self()->getCallingPid());
    const sp<IAfThreadBase> thread = mThread.promote();
    if (thread != 0) {
        audio_utils::lock_guard _l(thread->mutex());
        track_state state = mState;
        if (state == RESUMING || state == ACTIVE || state == PAUSING || state == PAUSED) {
            // If the track is not active (PAUSED and buffers full), flush buffers
            auto* const playbackThread = thread->asIAfPlaybackThread().get();
            if (!playbackThread->isTrackActive(this)) {
                reset();
                mState = STOPPED;
            } else if (isPatchTrack() || (!isFastTrack() && !isOffloaded() && !isDirect())) {
                // for a PatchTrack (whatever fast ot not), do not drain but move directly
                // to STOPPED to avoid closing while active.
                mState = STOPPED;
            } else {
                // For fast tracks prepareTracks_l() will set state to STOPPING_2
                // presentation is complete
                // For an offloaded track this starts a drain and state will
                // move to STOPPING_2 when drain completes and then STOPPED
                mState = STOPPING_1;
                if (isOffloaded()) {
                    mRetryCount = IAfPlaybackThread::kMaxTrackStopRetriesOffload;
                }
            }
            playbackThread->broadcast_l();
            ALOGV("%s(%d): not stopping/stopped => stopping/stopped on thread %d",
                    __func__, mId, (int)mThreadIoHandle);
        }
        forEachTeePatchTrack_l([](const auto& patchTrack) { patchTrack->stop(); });
    }
}

void Track::pause()
{
    ALOGV("%s(%d): calling pid %d", __func__, mId, IPCThreadState::self()->getCallingPid());
    const sp<IAfThreadBase> thread = mThread.promote();
    if (thread != 0) {
        audio_utils::lock_guard _l(thread->mutex());
        auto* const playbackThread = thread->asIAfPlaybackThread().get();
        switch (mState) {
        case STOPPING_1:
        case STOPPING_2:
            if (!isOffloaded()) {
                /* nothing to do if track is not offloaded */
                break;
            }

            // Offloaded track was draining, we need to carry on draining when resumed
            mResumeToStopping = true;
            FALLTHROUGH_INTENDED;
        case ACTIVE:
        case RESUMING:
            mState = PAUSING;
            ALOGV("%s(%d): ACTIVE/RESUMING => PAUSING on thread %d",
                    __func__, mId, (int)mThreadIoHandle);
            if (isOffloadedOrDirect()) {
                mPauseHwPending = true;
            }
            playbackThread->broadcast_l();
            break;

        default:
            break;
        }
        // Pausing the TeePatch to avoid a glitch on underrun, at the cost of buffered audio loss.
        forEachTeePatchTrack_l([](const auto& patchTrack) { patchTrack->pause(); });
    }
}

void Track::flush()
{
    ALOGV("%s(%d)", __func__, mId);
    const sp<IAfThreadBase> thread = mThread.promote();
    if (thread != 0) {
        audio_utils::lock_guard _l(thread->mutex());
        auto* const playbackThread = thread->asIAfPlaybackThread().get();

        // Flush the ring buffer now if the track is not active in the PlaybackThread.
        // Otherwise the flush would not be done until the track is resumed.
        // Requires FastTrack removal be BLOCK_UNTIL_ACKED
        if (!playbackThread->isTrackActive(this)) {
            (void)mServerProxy->flushBufferIfNeeded();
        }

        if (isOffloaded()) {
            // If offloaded we allow flush during any state except terminated
            // and keep the track active to avoid problems if user is seeking
            // rapidly and underlying hardware has a significant delay handling
            // a pause
            if (isTerminated()) {
                return;
            }

            ALOGV("%s(%d): offload flush", __func__, mId);
            reset();

            if (mState == STOPPING_1 || mState == STOPPING_2) {
                ALOGV("%s(%d): flushed in STOPPING_1 or 2 state, change state to ACTIVE",
                        __func__, mId);
                mState = ACTIVE;
            }

            mFlushHwPending = true;
            mResumeToStopping = false;
        } else {
            if (mState != STOPPING_1 && mState != STOPPING_2 && mState != STOPPED &&
                    mState != PAUSED && mState != PAUSING && mState != IDLE && mState != FLUSHED) {
                return;
            }
            // No point remaining in PAUSED state after a flush => go to
            // FLUSHED state
            mState = FLUSHED;
            // do not reset the track if it is still in the process of being stopped or paused.
            // this will be done by prepareTracks_l() when the track is stopped.
            // prepareTracks_l() will see mState == FLUSHED, then
            // remove from active track list, reset(), and trigger presentation complete
            if (isDirect()) {
                mFlushHwPending = true;
            }
            if (!playbackThread->isTrackActive(this)) {
                reset();
            }
        }
        // Prevent flush being lost if the track is flushed and then resumed
        // before mixer thread can run. This is important when offloading
        // because the hardware buffer could hold a large amount of audio
        playbackThread->broadcast_l();
        // Flush the Tee to avoid on resume playing old data and glitching on the transition to
        // new data
        forEachTeePatchTrack_l([](const auto& patchTrack) { patchTrack->flush(); });
    }
}

// must be called with thread lock held
void Track::flushAck()
{
    if (!isOffloaded() && !isDirect()) {
        return;
    }

    // Clear the client ring buffer so that the app can prime the buffer while paused.
    // Otherwise it might not get cleared until playback is resumed and obtainBuffer() is called.
    mServerProxy->flushBufferIfNeeded();

    mFlushHwPending = false;
}

void Track::pauseAck()
{
    mPauseHwPending = false;
}

void Track::reset()
{
    // Do not reset twice to avoid discarding data written just after a flush and before
    // the audioflinger thread detects the track is stopped.
    if (!mResetDone) {
        // Force underrun condition to avoid false underrun callback until first data is
        // written to buffer
        android_atomic_and(~CBLK_FORCEREADY, &mCblk->mFlags);
        mFillingStatus = FS_FILLING;
        mResetDone = true;
        if (mState == FLUSHED) {
            mState = IDLE;
        }
    }
}

status_t Track::setParameters(const String8& keyValuePairs)
{
    const sp<IAfThreadBase> thread = mThread.promote();
    if (thread == 0) {
        ALOGE("%s(%d): thread is dead", __func__, mId);
        return FAILED_TRANSACTION;
    } else if (thread->type() == IAfThreadBase::DIRECT
            || thread->type() == IAfThreadBase::OFFLOAD) {
        return thread->setParameters(keyValuePairs);
    } else {
        return PERMISSION_DENIED;
    }
}

status_t Track::selectPresentation(int presentationId,
        int programId) {
    const sp<IAfThreadBase> thread = mThread.promote();
    if (thread == 0) {
        ALOGE("thread is dead");
        return FAILED_TRANSACTION;
    } else if (thread->type() == IAfThreadBase::DIRECT
            || thread->type() == IAfThreadBase::OFFLOAD) {
        auto directOutputThread = thread->asIAfDirectOutputThread().get();
        return directOutputThread->selectPresentation(presentationId, programId);
    }
    return INVALID_OPERATION;
}

VolumeShaper::Status Track::applyVolumeShaper(
        const sp<VolumeShaper::Configuration>& configuration,
        const sp<VolumeShaper::Operation>& operation)
{
    VolumeShaper::Status status = mVolumeHandler->applyVolumeShaper(configuration, operation);

    if (isOffloadedOrDirect()) {
        // Signal thread to fetch new volume.
        const sp<IAfThreadBase> thread = mThread.promote();
        if (thread != 0) {
            audio_utils::lock_guard _l(thread->mutex());
            thread->broadcast_l();
        }
    }
    return status;
}

sp<VolumeShaper::State> Track::getVolumeShaperState(int id) const
{
    // Note: We don't check if Thread exists.

    // mVolumeHandler is thread safe.
    return mVolumeHandler->getVolumeShaperState(id);
}

void Track::setFinalVolume(float volumeLeft, float volumeRight)
{
    mFinalVolumeLeft = volumeLeft;
    mFinalVolumeRight = volumeRight;
    const float volume = (volumeLeft + volumeRight) * 0.5f;
    if (mFinalVolume != volume) { // Compare to an epsilon if too many meaningless updates
        mFinalVolume = volume;
        setMetadataHasChanged();
        mLogForceVolumeUpdate = true;
    }
    if (mLogForceVolumeUpdate) {
        mLogForceVolumeUpdate = false;
        mTrackMetrics.logVolume(mFinalVolume);
    }
}

void Track::setAppVolume(float volume)
{
    mAppVolume = volume;
}

void Track::setAppMute(bool val)
{
    mAppMuted = val;
}

void Track::copyMetadataTo(MetadataInserter& backInserter) const
{
    // Do not forward metadata for PatchTrack with unspecified stream type
    if (mStreamType == AUDIO_STREAM_PATCH) {
        return;
    }

    playback_track_metadata_v7_t metadata;
    metadata.base = {
            .usage = mAttr.usage,
            .content_type = mAttr.content_type,
            .gain = mFinalVolume,
    };

    // When attributes are undefined, derive default values from stream type.
    // See AudioAttributes.java, usageForStreamType() and Builder.setInternalLegacyStreamType()
    if (mAttr.usage == AUDIO_USAGE_UNKNOWN) {
        switch (mStreamType) {
        case AUDIO_STREAM_VOICE_CALL:
            metadata.base.usage = AUDIO_USAGE_VOICE_COMMUNICATION;
            metadata.base.content_type = AUDIO_CONTENT_TYPE_SPEECH;
            break;
        case AUDIO_STREAM_SYSTEM:
            metadata.base.usage = AUDIO_USAGE_ASSISTANCE_SONIFICATION;
            metadata.base.content_type = AUDIO_CONTENT_TYPE_SONIFICATION;
            break;
        case AUDIO_STREAM_RING:
            metadata.base.usage = AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE;
            metadata.base.content_type = AUDIO_CONTENT_TYPE_SONIFICATION;
            break;
        case AUDIO_STREAM_MUSIC:
            metadata.base.usage = AUDIO_USAGE_MEDIA;
            metadata.base.content_type = AUDIO_CONTENT_TYPE_MUSIC;
            break;
        case AUDIO_STREAM_ALARM:
            metadata.base.usage = AUDIO_USAGE_ALARM;
            metadata.base.content_type = AUDIO_CONTENT_TYPE_SONIFICATION;
            break;
        case AUDIO_STREAM_NOTIFICATION:
            metadata.base.usage = AUDIO_USAGE_NOTIFICATION;
            metadata.base.content_type = AUDIO_CONTENT_TYPE_SONIFICATION;
            break;
        case AUDIO_STREAM_DTMF:
            metadata.base.usage = AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING;
            metadata.base.content_type = AUDIO_CONTENT_TYPE_SONIFICATION;
            break;
        case AUDIO_STREAM_ACCESSIBILITY:
            metadata.base.usage = AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY;
            metadata.base.content_type = AUDIO_CONTENT_TYPE_SPEECH;
            break;
        case AUDIO_STREAM_ASSISTANT:
            metadata.base.usage = AUDIO_USAGE_ASSISTANT;
            metadata.base.content_type = AUDIO_CONTENT_TYPE_SPEECH;
            break;
        case AUDIO_STREAM_REROUTING:
            metadata.base.usage = AUDIO_USAGE_VIRTUAL_SOURCE;
            // unknown content type
            break;
        case AUDIO_STREAM_CALL_ASSISTANT:
            metadata.base.usage = AUDIO_USAGE_CALL_ASSISTANT;
            metadata.base.content_type = AUDIO_CONTENT_TYPE_SPEECH;
            break;
        default:
            break;
        }
    }

    metadata.channel_mask = mChannelMask;
    strncpy(metadata.tags, mAttr.tags, AUDIO_ATTRIBUTES_TAGS_MAX_SIZE);
    *backInserter++ = metadata;
}

void Track::updateTeePatches_l() {
    if (mTeePatchesToUpdate.has_value()) {
        forEachTeePatchTrack_l([](const auto& patchTrack) { patchTrack->destroy(); });
        mTeePatches = mTeePatchesToUpdate.value();
        if (mState == TrackBase::ACTIVE || mState == TrackBase::RESUMING ||
                mState == TrackBase::STOPPING_1) {
            forEachTeePatchTrack_l([](const auto& patchTrack) { patchTrack->start(); });
        }
        mTeePatchesToUpdate.reset();
    }
}

void Track::setTeePatchesToUpdate_l(TeePatches teePatchesToUpdate) {
    ALOGW_IF(mTeePatchesToUpdate.has_value(),
             "%s, existing tee patches to update will be ignored", __func__);
    mTeePatchesToUpdate = std::move(teePatchesToUpdate);
}

// must be called with player thread lock held
void Track::processMuteEvent_l(const sp<
    IAudioManager>& audioManager, mute_state_t muteState)
{
    if (mMuteState == muteState) {
        // mute state did not change, do nothing
        return;
    }

    status_t result = UNKNOWN_ERROR;
    if (audioManager && mPortId != AUDIO_PORT_HANDLE_NONE) {
        if (mMuteEventExtras == nullptr) {
            mMuteEventExtras = std::make_unique<os::PersistableBundle>();
        }
        mMuteEventExtras->putInt(String16(kExtraPlayerEventMuteKey), static_cast<int>(muteState));

        result = audioManager->portEvent(mPortId, PLAYER_UPDATE_MUTED, mMuteEventExtras);
    }

    if (result == OK) {
        ALOGI("%s(%d): processed mute state for port ID %d from %d to %d", __func__, id(), mPortId,
              int(muteState), int(mMuteState));
        mMuteState = muteState;
    } else {
        ALOGW("%s(%d): cannot process mute state for port ID %d, status error %d", __func__, id(),
              mPortId, result);
    }
}

status_t Track::getTimestamp(AudioTimestamp& timestamp)
{
    if (!isOffloaded() && !isDirect()) {
        return INVALID_OPERATION; // normal tracks handled through SSQ
    }
    const sp<IAfThreadBase> thread = mThread.promote();
    if (thread == 0) {
        return INVALID_OPERATION;
    }

    audio_utils::lock_guard _l(thread->mutex());
    auto* const playbackThread = thread->asIAfPlaybackThread().get();
    return playbackThread->getTimestamp_l(timestamp);
}

status_t Track::attachAuxEffect(int EffectId)
{
    const sp<IAfThreadBase> thread = mThread.promote();
    if (thread == nullptr) {
        return DEAD_OBJECT;
    }

    auto dstThread = thread->asIAfPlaybackThread();
    // srcThread is initialized by call to moveAuxEffectToIo()
    sp<IAfPlaybackThread> srcThread;
    const auto& af = mClient->afClientCallback();
    status_t status = af->moveAuxEffectToIo(EffectId, dstThread, &srcThread);

    if (EffectId != 0 && status == NO_ERROR) {
        status = dstThread->attachAuxEffect(this, EffectId);
        if (status == NO_ERROR) {
            AudioSystem::moveEffectsToIo(std::vector<int>(EffectId), dstThread->id());
        }
    }

    if (status != NO_ERROR && srcThread != nullptr) {
        af->moveAuxEffectToIo(EffectId, srcThread, &dstThread);
    }
    return status;
}

void Track::setAuxBuffer(int EffectId, int32_t *buffer)
{
    mAuxEffectId = EffectId;
    mAuxBuffer = buffer;
}

// presentationComplete verified by frames, used by Mixed tracks.
bool Track::presentationComplete(
        int64_t framesWritten, size_t audioHalFrames)
{
    // TODO: improve this based on FrameMap if it exists, to ensure full drain.
    // This assists in proper timestamp computation as well as wakelock management.

    // a track is considered presented when the total number of frames written to audio HAL
    // corresponds to the number of frames written when presentationComplete() is called for the
    // first time (mPresentationCompleteFrames == 0) plus the buffer filling status at that time.
    // For an offloaded track the HAL+h/w delay is variable so a HAL drain() is used
    // to detect when all frames have been played. In this case framesWritten isn't
    // useful because it doesn't always reflect whether there is data in the h/w
    // buffers, particularly if a track has been paused and resumed during draining
    ALOGV("%s(%d): presentationComplete() mPresentationCompleteFrames %lld framesWritten %lld",
            __func__, mId,
            (long long)mPresentationCompleteFrames, (long long)framesWritten);
    if (mPresentationCompleteFrames == 0) {
        mPresentationCompleteFrames = framesWritten + audioHalFrames;
        ALOGV("%s(%d): set:"
                " mPresentationCompleteFrames %lld audioHalFrames %zu",
                __func__, mId,
                (long long)mPresentationCompleteFrames, audioHalFrames);
    }

    bool complete;
    if (isFastTrack()) { // does not go through linear map
        complete = framesWritten >= (int64_t) mPresentationCompleteFrames;
        ALOGV("%s(%d): %s framesWritten:%lld  mPresentationCompleteFrames:%lld",
                __func__, mId, (complete ? "complete" : "waiting"),
                (long long) framesWritten, (long long) mPresentationCompleteFrames);
    } else {  // Normal tracks, OutputTracks, and PatchTracks
        complete = framesWritten >= (int64_t) mPresentationCompleteFrames
                && mAudioTrackServerProxy->isDrained();
    }

    if (complete) {
        notifyPresentationComplete();
        return true;
    }
    return false;
}

// presentationComplete checked by time, used by DirectTracks.
bool Track::presentationComplete(uint32_t latencyMs)
{
    // For Offloaded or Direct tracks.

    // For a direct track, we incorporated time based testing for presentationComplete.

    // For an offloaded track the HAL+h/w delay is variable so a HAL drain() is used
    // to detect when all frames have been played. In this case latencyMs isn't
    // useful because it doesn't always reflect whether there is data in the h/w
    // buffers, particularly if a track has been paused and resumed during draining

    constexpr float MIN_SPEED = 0.125f; // min speed scaling allowed for timely response.
    if (mPresentationCompleteTimeNs == 0) {
        mPresentationCompleteTimeNs = systemTime() + latencyMs * 1e6 / fmax(mSpeed, MIN_SPEED);
        ALOGV("%s(%d): set: latencyMs %u  mPresentationCompleteTimeNs:%lld",
                __func__, mId, latencyMs, (long long) mPresentationCompleteTimeNs);
    }

    bool complete;
    if (isOffloaded()) {
        complete = true;
    } else { // Direct
        complete = systemTime() >= mPresentationCompleteTimeNs;
        ALOGV("%s(%d): %s", __func__, mId, (complete ? "complete" : "waiting"));
    }
    if (complete) {
        notifyPresentationComplete();
        return true;
    }
    return false;
}

void Track::notifyPresentationComplete()
{
    // This only triggers once. TODO: should we enforce this?
    triggerEvents(AudioSystem::SYNC_EVENT_PRESENTATION_COMPLETE);
    mAudioTrackServerProxy->setStreamEndDone();
}

void Track::triggerEvents(AudioSystem::sync_event_t type)
{
    for (auto it = mSyncEvents.begin(); it != mSyncEvents.end();) {
        if ((*it)->type() == type) {
            ALOGV("%s: triggering SyncEvent type %d", __func__, type);
            (*it)->trigger();
            it = mSyncEvents.erase(it);
        } else {
            ++it;
        }
    }
}

// implement VolumeBufferProvider interface

gain_minifloat_packed_t Track::getVolumeLR() const
{
    // called by FastMixer, so not allowed to take any locks, block, or do I/O including logs
    ALOG_ASSERT(isFastTrack() && (mCblk != NULL));
    gain_minifloat_packed_t vlr = mAudioTrackServerProxy->getVolumeLR();
    float vl = float_from_gain(gain_minifloat_unpack_left(vlr));
    float vr = float_from_gain(gain_minifloat_unpack_right(vlr));
    // track volumes come from shared memory, so can't be trusted and must be clamped
    if (vl > GAIN_FLOAT_UNITY) {
        vl = GAIN_FLOAT_UNITY;
    }
    if (vr > GAIN_FLOAT_UNITY) {
        vr = GAIN_FLOAT_UNITY;
    }
    // now apply the cached master volume and stream type volume;
    // this is trusted but lacks any synchronization or barrier so may be stale
    float v = mCachedVolume;
    vl *= v;
    vr *= v;
    // re-combine into packed minifloat
    vlr = gain_minifloat_pack(gain_from_float(vl), gain_from_float(vr));
    // FIXME look at mute, pause, and stop flags
    return vlr;
}

status_t Track::setSyncEvent(
        const sp<audioflinger::SyncEvent>& event)
{
    if (isTerminated() || mState == PAUSED ||
            ((framesReady() == 0) && ((mSharedBuffer != 0) ||
                                      (mState == STOPPED)))) {
        ALOGW("%s(%d): in invalid state %d on session %d %s mode, framesReady %zu",
              __func__, mId,
              (int)mState, mSessionId, (mSharedBuffer != 0) ? "static" : "stream", framesReady());
        event->cancel();
        return INVALID_OPERATION;
    }
    (void) TrackBase::setSyncEvent(event);
    return NO_ERROR;
}

void Track::invalidate()
{
    TrackBase::invalidate();
    signalClientFlag(CBLK_INVALID);
}

void Track::disable()
{
    // TODO(b/142394888): the filling status should also be reset to filling
    signalClientFlag(CBLK_DISABLED);
}

void Track::signalClientFlag(int32_t flag)
{
    // FIXME should use proxy, and needs work
    audio_track_cblk_t* cblk = mCblk;
    android_atomic_or(flag, &cblk->mFlags);
    android_atomic_release_store(0x40000000, &cblk->mFutex);
    // client is not in server, so FUTEX_WAKE is needed instead of FUTEX_WAKE_PRIVATE
    (void) syscall(__NR_futex, &cblk->mFutex, FUTEX_WAKE, INT_MAX);
}

void Track::signal()
{
    const sp<IAfThreadBase> thread = mThread.promote();
    if (thread != 0) {
        auto* const t = thread->asIAfPlaybackThread().get();
        audio_utils::lock_guard _l(t->mutex());
        t->broadcast_l();
    }
}

status_t Track::getDualMonoMode(audio_dual_mono_mode_t* mode) const
{
    status_t status = INVALID_OPERATION;
    if (isOffloadedOrDirect()) {
        const sp<IAfThreadBase> thread = mThread.promote();
        if (thread != nullptr) {
            auto* const t = thread->asIAfPlaybackThread().get();
            audio_utils::lock_guard _l(t->mutex());
            status = t->getOutput_l()->stream->getDualMonoMode(mode);
            ALOGD_IF((status == NO_ERROR) && (mDualMonoMode != *mode),
                    "%s: mode %d inconsistent", __func__, mDualMonoMode);
        }
    }
    return status;
}

status_t Track::setDualMonoMode(audio_dual_mono_mode_t mode)
{
    status_t status = INVALID_OPERATION;
    if (isOffloadedOrDirect()) {
        const sp<IAfThreadBase> thread = mThread.promote();
        if (thread != nullptr) {
            auto* const t = thread->asIAfPlaybackThread().get();
            audio_utils::lock_guard lock(t->mutex());
            status = t->getOutput_l()->stream->setDualMonoMode(mode);
            if (status == NO_ERROR) {
                mDualMonoMode = mode;
            }
        }
    }
    return status;
}

status_t Track::getAudioDescriptionMixLevel(float* leveldB) const
{
    status_t status = INVALID_OPERATION;
    if (isOffloadedOrDirect()) {
        sp<IAfThreadBase> thread = mThread.promote();
        if (thread != nullptr) {
            auto* const t = thread->asIAfPlaybackThread().get();
            audio_utils::lock_guard lock(t->mutex());
            status = t->getOutput_l()->stream->getAudioDescriptionMixLevel(leveldB);
            ALOGD_IF((status == NO_ERROR) && (mAudioDescriptionMixLevel != *leveldB),
                    "%s: level %.3f inconsistent", __func__, mAudioDescriptionMixLevel);
        }
    }
    return status;
}

status_t Track::setAudioDescriptionMixLevel(float leveldB)
{
    status_t status = INVALID_OPERATION;
    if (isOffloadedOrDirect()) {
        const sp<IAfThreadBase> thread = mThread.promote();
        if (thread != nullptr) {
            auto* const t = thread->asIAfPlaybackThread().get();
            audio_utils::lock_guard lock(t->mutex());
            status = t->getOutput_l()->stream->setAudioDescriptionMixLevel(leveldB);
            if (status == NO_ERROR) {
                mAudioDescriptionMixLevel = leveldB;
            }
        }
    }
    return status;
}

status_t Track::getPlaybackRateParameters(
        audio_playback_rate_t* playbackRate) const
{
    status_t status = INVALID_OPERATION;
    if (isOffloadedOrDirect()) {
        const sp<IAfThreadBase> thread = mThread.promote();
        if (thread != nullptr) {
            auto* const t = thread->asIAfPlaybackThread().get();
            audio_utils::lock_guard lock(t->mutex());
            status = t->getOutput_l()->stream->getPlaybackRateParameters(playbackRate);
            ALOGD_IF((status == NO_ERROR) &&
                    !isAudioPlaybackRateEqual(mPlaybackRateParameters, *playbackRate),
                    "%s: playbackRate inconsistent", __func__);
        }
    }
    return status;
}

status_t Track::setPlaybackRateParameters(
        const audio_playback_rate_t& playbackRate)
{
    status_t status = INVALID_OPERATION;
    if (isOffloadedOrDirect()) {
        const sp<IAfThreadBase> thread = mThread.promote();
        if (thread != nullptr) {
            auto* const t = thread->asIAfPlaybackThread().get();
            audio_utils::lock_guard lock(t->mutex());
            status = t->getOutput_l()->stream->setPlaybackRateParameters(playbackRate);
            if (status == NO_ERROR) {
                mPlaybackRateParameters = playbackRate;
            }
        }
    }
    return status;
}

//To be called with thread lock held
bool Track::isResumePending() const {
    if (mState == RESUMING) {
        return true;
    }
    /* Resume is pending if track was stopping before pause was called */
    if (mState == STOPPING_1 &&
        mResumeToStopping) {
        return true;
    }

    return false;
}

//To be called with thread lock held
void Track::resumeAck() {
    if (mState == RESUMING) {
        mState = ACTIVE;
    }

    // Other possibility of  pending resume is stopping_1 state
    // Do not update the state from stopping as this prevents
    // drain being called.
    if (mState == STOPPING_1) {
        mResumeToStopping = false;
    }
}

//To be called with thread lock held
void Track::updateTrackFrameInfo(
        int64_t trackFramesReleased, int64_t sinkFramesWritten,
        uint32_t halSampleRate, const ExtendedTimestamp &timeStamp) {
   // Make the kernel frametime available.
    const FrameTime ft{
            timeStamp.mPosition[ExtendedTimestamp::LOCATION_KERNEL],
            timeStamp.mTimeNs[ExtendedTimestamp::LOCATION_KERNEL]};
    // ALOGD("FrameTime: %lld %lld", (long long)ft.frames, (long long)ft.timeNs);
    mKernelFrameTime.store(ft);
    if (!audio_is_linear_pcm(mFormat)) {
        return;
    }

    //update frame map
    mFrameMap.push(trackFramesReleased, sinkFramesWritten);

    // adjust server times and set drained state.
    //
    // Our timestamps are only updated when the track is on the Thread active list.
    // We need to ensure that tracks are not removed before full drain.
    ExtendedTimestamp local = timeStamp;
    bool drained = true; // default assume drained, if no server info found
    bool checked = false;
    for (int i = ExtendedTimestamp::LOCATION_MAX - 1;
            i >= ExtendedTimestamp::LOCATION_SERVER; --i) {
        // Lookup the track frame corresponding to the sink frame position.
        if (local.mTimeNs[i] > 0) {
            local.mPosition[i] = mFrameMap.findX(local.mPosition[i]);
            // check drain state from the latest stage in the pipeline.
            if (!checked && i <= ExtendedTimestamp::LOCATION_KERNEL) {
                drained = local.mPosition[i] >= mAudioTrackServerProxy->framesReleased();
                checked = true;
            }
        }
    }

    ALOGV("%s: trackFramesReleased:%lld  sinkFramesWritten:%lld  setDrained: %d",
        __func__, (long long)trackFramesReleased, (long long)sinkFramesWritten, drained);
    mAudioTrackServerProxy->setDrained(drained);
    // Set correction for flushed frames that are not accounted for in released.
    local.mFlushed = mAudioTrackServerProxy->framesFlushed();
    mServerProxy->setTimestamp(local);

    // Compute latency info.
    const bool useTrackTimestamp = !drained;
    const double latencyMs = useTrackTimestamp
            ? local.getOutputServerLatencyMs(sampleRate())
            : timeStamp.getOutputServerLatencyMs(halSampleRate);

    mServerLatencyFromTrack.store(useTrackTimestamp);
    mServerLatencyMs.store(latencyMs);

    if (mLogStartCountdown > 0
            && local.mTimeNs[ExtendedTimestamp::LOCATION_KERNEL] > 0
            && local.mPosition[ExtendedTimestamp::LOCATION_KERNEL] > 0)
    {
        if (mLogStartCountdown > 1) {
            --mLogStartCountdown;
        } else if (latencyMs < mLogLatencyMs) { // wait for latency to stabilize (dip)
            mLogStartCountdown = 0;
            // startup is the difference in times for the current timestamp and our start
            double startUpMs =
                    (local.mTimeNs[ExtendedTimestamp::LOCATION_KERNEL] - mLogStartTimeNs) * 1e-6;
            // adjust for frames played.
            startUpMs -= (local.mPosition[ExtendedTimestamp::LOCATION_KERNEL] - mLogStartFrames)
                    * 1e3 / mSampleRate;
            ALOGV("%s: latencyMs:%lf startUpMs:%lf"
                    " localTime:%lld startTime:%lld"
                    " localPosition:%lld startPosition:%lld",
                    __func__, latencyMs, startUpMs,
                    (long long)local.mTimeNs[ExtendedTimestamp::LOCATION_KERNEL],
                    (long long)mLogStartTimeNs,
                    (long long)local.mPosition[ExtendedTimestamp::LOCATION_KERNEL],
                    (long long)mLogStartFrames);
            mTrackMetrics.logLatencyAndStartup(latencyMs, startUpMs);
        }
        mLogLatencyMs = latencyMs;
    }
}

bool Track::AudioVibrationController::setMute(bool muted) {
    const sp<IAfThreadBase> thread = mTrack->mThread.promote();
    if (thread != 0) {
        // Lock for updating mHapticPlaybackEnabled.
        audio_utils::lock_guard _l(thread->mutex());
        auto* const playbackThread = thread->asIAfPlaybackThread().get();
        if ((mTrack->channelMask() & AUDIO_CHANNEL_HAPTIC_ALL) != AUDIO_CHANNEL_NONE
                && playbackThread->hapticChannelCount() > 0) {
            ALOGD("%s, haptic playback was %s for track %d",
                    __func__, muted ? "muted" : "unmuted", mTrack->id());
            mTrack->setHapticPlaybackEnabled(!muted);
            return true;
        }
    }
    return false;
}

binder::Status Track::AudioVibrationController::mute(
        /*out*/ bool *ret) {
    *ret = setMute(true);
    return binder::Status::ok();
}

binder::Status Track::AudioVibrationController::unmute(
        /*out*/ bool *ret) {
    *ret = setMute(false);
    return binder::Status::ok();
}

// ----------------------------------------------------------------------------
#undef LOG_TAG
#define LOG_TAG "AF::OutputTrack"

/* static */
sp<IAfOutputTrack> IAfOutputTrack::create(
        IAfPlaybackThread* playbackThread,
        IAfDuplicatingThread* sourceThread,
        uint32_t sampleRate,
        audio_format_t format,
        audio_channel_mask_t channelMask,
        size_t frameCount,
        const AttributionSourceState& attributionSource) {
    return sp<OutputTrack>::make(
            playbackThread,
            sourceThread,
            sampleRate,
            format,
            channelMask,
            frameCount,
            attributionSource);
}

OutputTrack::OutputTrack(
            IAfPlaybackThread* playbackThread,
            IAfDuplicatingThread* sourceThread,
            uint32_t sampleRate,
            audio_format_t format,
            audio_channel_mask_t channelMask,
            size_t frameCount,
            const AttributionSourceState& attributionSource)
    :   Track(playbackThread, NULL, AUDIO_STREAM_PATCH,
              audio_attributes_t{} /* currently unused for output track */,
              sampleRate, format, channelMask, frameCount,
              nullptr /* buffer */, (size_t)0 /* bufferSize */, nullptr /* sharedBuffer */,
              AUDIO_SESSION_NONE, getpid(), attributionSource, AUDIO_OUTPUT_FLAG_NONE,
              TYPE_OUTPUT),
    mActive(false), mSourceThread(sourceThread)
{

    if (mCblk != NULL) {
        mOutBuffer.frameCount = 0;
        playbackThread->addOutputTrack_l(this);
        ALOGV("%s(): mCblk %p, mBuffer %p, "
                "frameCount %zu, mChannelMask 0x%08x",
                __func__, mCblk, mBuffer,
                frameCount, mChannelMask);
        // since client and server are in the same process,
        // the buffer has the same virtual address on both sides
        mClientProxy = new AudioTrackClientProxy(mCblk, mBuffer, mFrameCount, mFrameSize,
                true /*clientInServer*/);
        mClientProxy->setVolumeLR(GAIN_MINIFLOAT_PACKED_UNITY);
        mClientProxy->setSendLevel(0.0);
        mClientProxy->setSampleRate(sampleRate);
    } else {
        ALOGW("%s(%d): Error creating output track on thread %d",
                __func__, mId, (int)mThreadIoHandle);
    }
}

OutputTrack::~OutputTrack()
{
    clearBufferQueue();
    // superclass destructor will now delete the server proxy and shared memory both refer to
}

status_t OutputTrack::start(AudioSystem::sync_event_t event,
                                                          audio_session_t triggerSession)
{
    status_t status = Track::start(event, triggerSession);
    if (status != NO_ERROR) {
        return status;
    }

    mActive = true;
    mRetryCount = 127;
    return status;
}

void OutputTrack::stop()
{
    Track::stop();
    clearBufferQueue();
    mOutBuffer.frameCount = 0;
    mActive = false;
}

ssize_t OutputTrack::write(void* data, uint32_t frames)
{
    if (!mActive && frames != 0) {
        const sp<IAfThreadBase> thread = mThread.promote();
        if (thread != nullptr && thread->inStandby()) {
            // preload one silent buffer to trigger mixer on start()
            ClientProxy::Buffer buf { .mFrameCount = mClientProxy->getStartThresholdInFrames() };
            status_t status = mClientProxy->obtainBuffer(&buf);
            if (status != NO_ERROR && status != NOT_ENOUGH_DATA && status != WOULD_BLOCK) {
                ALOGE("%s(%d): could not obtain buffer on start", __func__, mId);
                return 0;
            }
            memset(buf.mRaw, 0, buf.mFrameCount * mFrameSize);
            mClientProxy->releaseBuffer(&buf);

            (void) start();

            // wait for HAL stream to start before sending actual audio. Doing this on each
            // OutputTrack makes that playback start on all output streams is synchronized.
            // If another OutputTrack has already started it can underrun but this is OK
            // as only silence has been played so far and the retry count is very high on
            // OutputTrack.
            auto* const pt = thread->asIAfPlaybackThread().get();
            if (!pt->waitForHalStart()) {
                ALOGW("%s(%d): timeout waiting for thread to exit standby", __func__, mId);
                stop();
                return 0;
            }

            // enqueue the first buffer and exit so that other OutputTracks will also start before
            // write() is called again and this buffer actually consumed.
            Buffer firstBuffer;
            firstBuffer.frameCount = frames;
            firstBuffer.raw = data;
            queueBuffer(firstBuffer);
            return frames;
        } else {
            (void) start();
        }
    }

    Buffer *pInBuffer;
    Buffer inBuffer;
    inBuffer.frameCount = frames;
    inBuffer.raw = data;
    uint32_t waitTimeLeftMs = mSourceThread->waitTimeMs();
    while (waitTimeLeftMs) {
        // First write pending buffers, then new data
        if (mBufferQueue.size()) {
            pInBuffer = mBufferQueue.itemAt(0);
        } else {
            pInBuffer = &inBuffer;
        }

        if (pInBuffer->frameCount == 0) {
            break;
        }

        if (mOutBuffer.frameCount == 0) {
            mOutBuffer.frameCount = pInBuffer->frameCount;
            nsecs_t startTime = systemTime();
            status_t status = obtainBuffer(&mOutBuffer, waitTimeLeftMs);
            if (status != NO_ERROR && status != NOT_ENOUGH_DATA) {
                ALOGV("%s(%d): thread %d no more output buffers; status %d",
                        __func__, mId,
                        (int)mThreadIoHandle, status);
                break;
            }
            uint32_t waitTimeMs = (uint32_t)ns2ms(systemTime() - startTime);
            if (waitTimeLeftMs >= waitTimeMs) {
                waitTimeLeftMs -= waitTimeMs;
            } else {
                waitTimeLeftMs = 0;
            }
            if (status == NOT_ENOUGH_DATA) {
                restartIfDisabled();
                continue;
            }
        }

        uint32_t outFrames = pInBuffer->frameCount > mOutBuffer.frameCount ? mOutBuffer.frameCount :
                pInBuffer->frameCount;
        memcpy(mOutBuffer.raw, pInBuffer->raw, outFrames * mFrameSize);
        Proxy::Buffer buf;
        buf.mFrameCount = outFrames;
        buf.mRaw = NULL;
        mClientProxy->releaseBuffer(&buf);
        restartIfDisabled();
        pInBuffer->frameCount -= outFrames;
        pInBuffer->raw = (int8_t *)pInBuffer->raw + outFrames * mFrameSize;
        mOutBuffer.frameCount -= outFrames;
        mOutBuffer.raw = (int8_t *)mOutBuffer.raw + outFrames * mFrameSize;

        if (pInBuffer->frameCount == 0) {
            if (mBufferQueue.size()) {
                mBufferQueue.removeAt(0);
                free(pInBuffer->mBuffer);
                if (pInBuffer != &inBuffer) {
                    delete pInBuffer;
                }
                ALOGV("%s(%d): thread %d released overflow buffer %zu",
                        __func__, mId,
                        (int)mThreadIoHandle, mBufferQueue.size());
            } else {
                break;
            }
        }
    }

    // If we could not write all frames, allocate a buffer and queue it for next time.
    if (inBuffer.frameCount) {
        const sp<IAfThreadBase> thread = mThread.promote();
        if (thread != nullptr && !thread->inStandby()) {
            queueBuffer(inBuffer);
        }
    }

    // Calling write() with a 0 length buffer means that no more data will be written:
    // We rely on stop() to set the appropriate flags to allow the remaining frames to play out.
    if (frames == 0 && mBufferQueue.size() == 0 && mActive) {
        stop();
    }

    return frames - inBuffer.frameCount;  // number of frames consumed.
}

void OutputTrack::queueBuffer(Buffer& inBuffer) {

    if (mBufferQueue.size() < kMaxOverFlowBuffers) {
        Buffer *pInBuffer = new Buffer;
        const size_t bufferSize = inBuffer.frameCount * mFrameSize;
        pInBuffer->mBuffer = malloc(bufferSize);
        LOG_ALWAYS_FATAL_IF(pInBuffer->mBuffer == nullptr,
                "%s: Unable to malloc size %zu", __func__, bufferSize);
        pInBuffer->frameCount = inBuffer.frameCount;
        pInBuffer->raw = pInBuffer->mBuffer;
        memcpy(pInBuffer->raw, inBuffer.raw, inBuffer.frameCount * mFrameSize);
        mBufferQueue.add(pInBuffer);
        ALOGV("%s(%d): thread %d adding overflow buffer %zu", __func__, mId,
                (int)mThreadIoHandle, mBufferQueue.size());
        // audio data is consumed (stored locally); set frameCount to 0.
        inBuffer.frameCount = 0;
    } else {
        ALOGW("%s(%d): thread %d no more overflow buffers",
                __func__, mId, (int)mThreadIoHandle);
        // TODO: return error for this.
    }
}

void OutputTrack::copyMetadataTo(MetadataInserter& backInserter) const
{
    audio_utils::lock_guard lock(trackMetadataMutex());
    backInserter = std::copy(mTrackMetadatas.begin(), mTrackMetadatas.end(), backInserter);
}

void OutputTrack::setMetadatas(const SourceMetadatas& metadatas) {
    {
        audio_utils::lock_guard lock(trackMetadataMutex());
        mTrackMetadatas = metadatas;
    }
    // No need to adjust metadata track volumes as OutputTrack volumes are always 0dBFS.
    setMetadataHasChanged();
}

status_t OutputTrack::obtainBuffer(
        AudioBufferProvider::Buffer* buffer, uint32_t waitTimeMs)
{
    ClientProxy::Buffer buf;
    buf.mFrameCount = buffer->frameCount;
    struct timespec timeout;
    timeout.tv_sec = waitTimeMs / 1000;
    timeout.tv_nsec = (int) (waitTimeMs % 1000) * 1000000;
    status_t status = mClientProxy->obtainBuffer(&buf, &timeout);
    buffer->frameCount = buf.mFrameCount;
    buffer->raw = buf.mRaw;
    return status;
}

void OutputTrack::clearBufferQueue()
{
    size_t size = mBufferQueue.size();

    for (size_t i = 0; i < size; i++) {
        Buffer *pBuffer = mBufferQueue.itemAt(i);
        free(pBuffer->mBuffer);
        delete pBuffer;
    }
    mBufferQueue.clear();
}

void OutputTrack::restartIfDisabled()
{
    int32_t flags = android_atomic_and(~CBLK_DISABLED, &mCblk->mFlags);
    if (mActive && (flags & CBLK_DISABLED)) {
        start();
    }
}

// ----------------------------------------------------------------------------
#undef LOG_TAG
#define LOG_TAG "AF::PatchTrack"

/* static */
sp<IAfPatchTrack> IAfPatchTrack::create(
        IAfPlaybackThread* playbackThread,
        audio_stream_type_t streamType,
        uint32_t sampleRate,
        audio_channel_mask_t channelMask,
        audio_format_t format,
        size_t frameCount,
        void* buffer,
        size_t bufferSize,
        audio_output_flags_t flags,
        const Timeout& timeout,
        size_t frameCountToBeReady /** Default behaviour is to start
                                         *  as soon as possible to have
                                         *  the lowest possible latency
                                         *  even if it might glitch. */)
{
    return sp<PatchTrack>::make(
            playbackThread,
            streamType,
            sampleRate,
            channelMask,
            format,
            frameCount,
            buffer,
            bufferSize,
            flags,
            timeout,
            frameCountToBeReady);
}

PatchTrack::PatchTrack(IAfPlaybackThread* playbackThread,
                                                     audio_stream_type_t streamType,
                                                     uint32_t sampleRate,
                                                     audio_channel_mask_t channelMask,
                                                     audio_format_t format,
                                                     size_t frameCount,
                                                     void *buffer,
                                                     size_t bufferSize,
                                                     audio_output_flags_t flags,
                                                     const Timeout& timeout,
                                                     size_t frameCountToBeReady)
    :   Track(playbackThread, NULL, streamType,
              audio_attributes_t{} /* currently unused for patch track */,
              sampleRate, format, channelMask, frameCount,
              buffer, bufferSize, nullptr /* sharedBuffer */,
              AUDIO_SESSION_NONE, getpid(), audioServerAttributionSource(getpid()), flags,
              TYPE_PATCH, AUDIO_PORT_HANDLE_NONE, frameCountToBeReady),
        PatchTrackBase(mCblk ? new ClientProxy(mCblk, mBuffer, frameCount, mFrameSize, true, true)
                        : nullptr,
                       playbackThread, timeout)
{
    ALOGV("%s(%d): sampleRate %d mPeerTimeout %d.%03d sec",
                                      __func__, mId, sampleRate,
                                      (int)mPeerTimeout.tv_sec,
                                      (int)(mPeerTimeout.tv_nsec / 1000000));
}

PatchTrack::~PatchTrack()
{
    ALOGV("%s(%d)", __func__, mId);
}

size_t PatchTrack::framesReady() const
{
    if (mPeerProxy && mPeerProxy->producesBufferOnDemand()) {
        return std::numeric_limits<size_t>::max();
    } else {
        return Track::framesReady();
    }
}

status_t PatchTrack::start(AudioSystem::sync_event_t event,
                                                         audio_session_t triggerSession)
{
    status_t status = Track::start(event, triggerSession);
    if (status != NO_ERROR) {
        return status;
    }
    android_atomic_and(~CBLK_DISABLED, &mCblk->mFlags);
    return status;
}

// AudioBufferProvider interface
status_t PatchTrack::getNextBuffer(
        AudioBufferProvider::Buffer* buffer)
{
    ALOG_ASSERT(mPeerProxy != 0, "%s(%d): called without peer proxy", __func__, mId);
    Proxy::Buffer buf;
    buf.mFrameCount = buffer->frameCount;
    if (ATRACE_ENABLED()) {
        std::string traceName("PTnReq");
        traceName += std::to_string(id());
        ATRACE_INT(traceName.c_str(), buf.mFrameCount);
    }
    status_t status = mPeerProxy->obtainBuffer(&buf, &mPeerTimeout);
    ALOGV_IF(status != NO_ERROR, "%s(%d): getNextBuffer status %d", __func__, mId, status);
    buffer->frameCount = buf.mFrameCount;
    if (ATRACE_ENABLED()) {
        std::string traceName("PTnObt");
        traceName += std::to_string(id());
        ATRACE_INT(traceName.c_str(), buf.mFrameCount);
    }
    if (buf.mFrameCount == 0) {
        return WOULD_BLOCK;
    }
    status = Track::getNextBuffer(buffer);
    return status;
}

void PatchTrack::releaseBuffer(AudioBufferProvider::Buffer* buffer)
{
    ALOG_ASSERT(mPeerProxy != 0, "%s(%d): called without peer proxy", __func__, mId);
    Proxy::Buffer buf;
    buf.mFrameCount = buffer->frameCount;
    buf.mRaw = buffer->raw;
    mPeerProxy->releaseBuffer(&buf);
    TrackBase::releaseBuffer(buffer); // Note: this is the base class.
}

status_t PatchTrack::obtainBuffer(Proxy::Buffer* buffer,
                                                                const struct timespec *timeOut)
{
    status_t status = NO_ERROR;
    static const int32_t kMaxTries = 5;
    int32_t tryCounter = kMaxTries;
    const size_t originalFrameCount = buffer->mFrameCount;
    do {
        if (status == NOT_ENOUGH_DATA) {
            restartIfDisabled();
            buffer->mFrameCount = originalFrameCount; // cleared on error, must be restored.
        }
        status = mProxy->obtainBuffer(buffer, timeOut);
    } while ((status == NOT_ENOUGH_DATA) && (tryCounter-- > 0));
    return status;
}

void PatchTrack::releaseBuffer(Proxy::Buffer* buffer)
{
    mProxy->releaseBuffer(buffer);
    restartIfDisabled();

    // Check if the PatchTrack has enough data to write once in releaseBuffer().
    // If not, prevent an underrun from occurring by moving the track into FS_FILLING;
    // this logic avoids glitches when suspending A2DP with AudioPlaybackCapture.
    // TODO: perhaps underrun avoidance could be a track property checked in isReady() instead.
    if (mFillingStatus == FS_ACTIVE
            && audio_is_linear_pcm(mFormat)
            && !isOffloadedOrDirect()) {
        if (const sp<IAfThreadBase> thread = mThread.promote();
            thread != 0) {
            auto* const playbackThread = thread->asIAfPlaybackThread().get();
            const size_t frameCount = playbackThread->frameCount() * sampleRate()
                    / playbackThread->sampleRate();
            if (framesReady() < frameCount) {
                ALOGD("%s(%d) Not enough data, wait for buffer to fill", __func__, mId);
                mFillingStatus = FS_FILLING;
            }
        }
    }
}

void PatchTrack::restartIfDisabled()
{
    if (android_atomic_and(~CBLK_DISABLED, &mCblk->mFlags) & CBLK_DISABLED) {
        ALOGW("%s(%d): disabled due to previous underrun, restarting", __func__, mId);
        start();
    }
}

// ----------------------------------------------------------------------------
//      Record
// ----------------------------------------------------------------------------


#undef LOG_TAG
#define LOG_TAG "AF::RecordHandle"

class RecordHandle : public android::media::BnAudioRecord {
public:
    explicit RecordHandle(const sp<IAfRecordTrack>& recordTrack);
    ~RecordHandle() override;
    binder::Status start(int /*AudioSystem::sync_event_t*/ event,
            int /*audio_session_t*/ triggerSession) final;
    binder::Status stop() final;
    binder::Status getActiveMicrophones(
            std::vector<media::MicrophoneInfoFw>* activeMicrophones) final;
    binder::Status setPreferredMicrophoneDirection(
            int /*audio_microphone_direction_t*/ direction) final;
    binder::Status setPreferredMicrophoneFieldDimension(float zoom) final;
    binder::Status shareAudioHistory(
            const std::string& sharedAudioPackageName, int64_t sharedAudioStartMs) final;

private:
    const sp<IAfRecordTrack> mRecordTrack;

    // for use from destructor
    void stop_nonvirtual();
};

/* static */
sp<media::IAudioRecord> IAfRecordTrack::createIAudioRecordAdapter(
        const sp<IAfRecordTrack>& recordTrack) {
    return sp<RecordHandle>::make(recordTrack);
}

RecordHandle::RecordHandle(
        const sp<IAfRecordTrack>& recordTrack)
    : BnAudioRecord(),
    mRecordTrack(recordTrack)
{
    setMinSchedulerPolicy(SCHED_NORMAL, ANDROID_PRIORITY_AUDIO);
}

RecordHandle::~RecordHandle() {
    stop_nonvirtual();
    mRecordTrack->destroy();
}

binder::Status RecordHandle::start(int /*AudioSystem::sync_event_t*/ event,
        int /*audio_session_t*/ triggerSession) {
    ALOGV("%s()", __func__);
    return binderStatusFromStatusT(
        mRecordTrack->start((AudioSystem::sync_event_t)event, (audio_session_t) triggerSession));
}

binder::Status RecordHandle::stop() {
    stop_nonvirtual();
    return binder::Status::ok();
}

void RecordHandle::stop_nonvirtual() {
    ALOGV("%s()", __func__);
    mRecordTrack->stop();
}

binder::Status RecordHandle::getActiveMicrophones(
        std::vector<media::MicrophoneInfoFw>* activeMicrophones) {
    ALOGV("%s()", __func__);
    return binderStatusFromStatusT(mRecordTrack->getActiveMicrophones(activeMicrophones));
}

binder::Status RecordHandle::setPreferredMicrophoneDirection(
        int /*audio_microphone_direction_t*/ direction) {
    ALOGV("%s()", __func__);
    return binderStatusFromStatusT(mRecordTrack->setPreferredMicrophoneDirection(
            static_cast<audio_microphone_direction_t>(direction)));
}

binder::Status RecordHandle::setPreferredMicrophoneFieldDimension(float zoom) {
    ALOGV("%s()", __func__);
    return binderStatusFromStatusT(mRecordTrack->setPreferredMicrophoneFieldDimension(zoom));
}

binder::Status RecordHandle::shareAudioHistory(
        const std::string& sharedAudioPackageName, int64_t sharedAudioStartMs) {
    return binderStatusFromStatusT(
            mRecordTrack->shareAudioHistory(sharedAudioPackageName, sharedAudioStartMs));
}

// ----------------------------------------------------------------------------
#undef LOG_TAG
#define LOG_TAG "AF::RecordTrack"


/* static */
sp<IAfRecordTrack> IAfRecordTrack::create(IAfRecordThread* thread,
        const sp<Client>& client,
        const audio_attributes_t& attr,
        uint32_t sampleRate,
        audio_format_t format,
        audio_channel_mask_t channelMask,
        size_t frameCount,
        void* buffer,
        size_t bufferSize,
        audio_session_t sessionId,
        pid_t creatorPid,
        const AttributionSourceState& attributionSource,
        audio_input_flags_t flags,
        track_type type,
        audio_port_handle_t portId,
        int32_t startFrames)
{
    return sp<RecordTrack>::make(
        thread,
        client,
        attr,
        sampleRate,
        format,
        channelMask,
        frameCount,
        buffer,
        bufferSize,
        sessionId,
        creatorPid,
        attributionSource,
        flags,
        type,
        portId,
        startFrames);
}

// RecordTrack constructor must be called with AudioFlinger::mLock and ThreadBase::mLock held
RecordTrack::RecordTrack(
            IAfRecordThread* thread,
            const sp<Client>& client,
            const audio_attributes_t& attr,
            uint32_t sampleRate,
            audio_format_t format,
            audio_channel_mask_t channelMask,
            size_t frameCount,
            void *buffer,
            size_t bufferSize,
            audio_session_t sessionId,
            pid_t creatorPid,
            const AttributionSourceState& attributionSource,
            audio_input_flags_t flags,
            track_type type,
            audio_port_handle_t portId,
            int32_t startFrames)
    :   TrackBase(thread, client, attr, sampleRate, format,
                  channelMask, frameCount, buffer, bufferSize, sessionId,
                  creatorPid,
                  VALUE_OR_FATAL(aidl2legacy_int32_t_uid_t(attributionSource.uid)),
                  false /*isOut*/,
                  (type == TYPE_DEFAULT) ?
                          ((flags & AUDIO_INPUT_FLAG_FAST) ? ALLOC_PIPE : ALLOC_CBLK) :
                          ((buffer == NULL) ? ALLOC_LOCAL : ALLOC_NONE),
                  type, portId,
                  std::string(AMEDIAMETRICS_KEY_PREFIX_AUDIO_RECORD) + std::to_string(portId)),
        mOverflow(false),
        mResamplerBufferProvider(NULL), // initialize in case of early constructor exit
        mRecordBufferConverter(NULL),
        mFlags(flags),
        mSilenced(false),
        mStartFrames(startFrames)
{
    if (mCblk == NULL) {
        return;
    }

    if (!isDirect()) {
        mRecordBufferConverter = new RecordBufferConverter(
                thread->channelMask(), thread->format(), thread->sampleRate(),
                channelMask, format, sampleRate);
        // Check if the RecordBufferConverter construction was successful.
        // If not, don't continue with construction.
        //
        // NOTE: It would be extremely rare that the record track cannot be created
        // for the current device, but a pending or future device change would make
        // the record track configuration valid.
        if (mRecordBufferConverter->initCheck() != NO_ERROR) {
            ALOGE("%s(%d): RecordTrack unable to create record buffer converter", __func__, mId);
            return;
        }
    }

    mServerProxy = new AudioRecordServerProxy(mCblk, mBuffer, frameCount,
            mFrameSize, !isExternalTrack());

    mResamplerBufferProvider = new ResamplerBufferProvider(this);

    if (flags & AUDIO_INPUT_FLAG_FAST) {
        ALOG_ASSERT(thread->fastTrackAvailable());
        thread->setFastTrackAvailable(false);
    } else {
        // TODO: only Normal Record has timestamps (Fast Record does not).
        mServerLatencySupported = checkServerLatencySupported(mFormat, flags);
    }
#ifdef TEE_SINK
    mTee.setId(std::string("_") + std::to_string(mThreadIoHandle)
            + "_" + std::to_string(mId)
            + "_R");
#endif

    // Once this item is logged by the server, the client can add properties.
    mTrackMetrics.logConstructor(creatorPid, uid(), id());
}

RecordTrack::~RecordTrack()
{
    ALOGV("%s()", __func__);
    delete mRecordBufferConverter;
    delete mResamplerBufferProvider;
}

status_t RecordTrack::initCheck() const
{
    status_t status = TrackBase::initCheck();
    if (status == NO_ERROR && mServerProxy == 0) {
        status = BAD_VALUE;
    }
    return status;
}

// AudioBufferProvider interface
status_t RecordTrack::getNextBuffer(AudioBufferProvider::Buffer* buffer)
{
    ServerProxy::Buffer buf;
    buf.mFrameCount = buffer->frameCount;
    status_t status = mServerProxy->obtainBuffer(&buf);
    buffer->frameCount = buf.mFrameCount;
    buffer->raw = buf.mRaw;
    if (buf.mFrameCount == 0) {
        // FIXME also wake futex so that overrun is noticed more quickly
        (void) android_atomic_or(CBLK_OVERRUN, &mCblk->mFlags);
    }
    return status;
}

status_t RecordTrack::start(AudioSystem::sync_event_t event,
                                                        audio_session_t triggerSession)
{
    const sp<IAfThreadBase> thread = mThread.promote();
    if (thread != 0) {
        auto* const recordThread = thread->asIAfRecordThread().get();
        return recordThread->start(this, event, triggerSession);
    } else {
        ALOGW("%s track %d: thread was destroyed", __func__, portId());
        return DEAD_OBJECT;
    }
}

void RecordTrack::stop()
{
    const sp<IAfThreadBase> thread = mThread.promote();
    if (thread != 0) {
        auto* const recordThread = thread->asIAfRecordThread().get();
        if (recordThread->stop(this) && isExternalTrack()) {
            AudioSystem::stopInput(mPortId);
        }
    }
}

void RecordTrack::destroy()
{
    // see comments at Track::destroy()
    sp<RecordTrack> keep(this);
    {
        track_state priorState = mState;
        const sp<IAfThreadBase> thread = mThread.promote();
        if (thread != 0) {
            audio_utils::lock_guard _l(thread->mutex());
            auto* const recordThread = thread->asIAfRecordThread().get();
            priorState = mState;
            if (!mSharedAudioPackageName.empty()) {
                recordThread->resetAudioHistory_l();
            }
            recordThread->destroyTrack_l(this); // move mState to STOPPED, terminate
        }
        // APM portid/client management done outside of lock.
        // NOTE: if thread doesn't exist, the input descriptor probably doesn't either.
        if (isExternalTrack()) {
            switch (priorState) {
            case ACTIVE:     // invalidated while still active
            case STARTING_2: // invalidated/start-aborted after startInput successfully called
            case PAUSING:    // invalidated while in the middle of stop() pausing (still active)
                AudioSystem::stopInput(mPortId);
                break;

            case STARTING_1: // invalidated/start-aborted and startInput not successful
            case PAUSED:     // OK, not active
            case IDLE:       // OK, not active
                break;

            case STOPPED:    // unexpected (destroyed)
            default:
                LOG_ALWAYS_FATAL("%s(%d): invalid prior state: %d", __func__, mId, priorState);
            }
            AudioSystem::releaseInput(mPortId);
        }
    }
}

void RecordTrack::invalidate()
{
    TrackBase::invalidate();
    // FIXME should use proxy, and needs work
    audio_track_cblk_t* cblk = mCblk;
    android_atomic_or(CBLK_INVALID, &cblk->mFlags);
    android_atomic_release_store(0x40000000, &cblk->mFutex);
    // client is not in server, so FUTEX_WAKE is needed instead of FUTEX_WAKE_PRIVATE
    (void) syscall(__NR_futex, &cblk->mFutex, FUTEX_WAKE, INT_MAX);
}


void RecordTrack::appendDumpHeader(String8& result) const
{
    result.appendFormat("Active     Id Client Session Port Id  S  Flags  "
                        " Format Chn mask  SRate Source  "
                        " Server FrmCnt FrmRdy Sil%s\n",
                        isServerLatencySupported() ? "   Latency" : "");
}

void RecordTrack::appendDump(String8& result, bool active) const
{
    result.appendFormat("%c%5s %6d %6u %7u %7u  %2s 0x%03X "
            "%08X %08X %6u %6X "
            "%08X %6zu %6zu %3c",
            isFastTrack() ? 'F' : ' ',
            active ? "yes" : "no",
            mId,
            (mClient == 0) ? getpid() : mClient->pid(),
            mSessionId,
            mPortId,
            getTrackStateAsCodedString(),
            mCblk->mFlags,

            mFormat,
            mChannelMask,
            mSampleRate,
            mAttr.source,

            mCblk->mServer,
            mFrameCount,
            mServerProxy->framesReadySafe(),
            isSilenced() ? 's' : 'n'
            );
    if (isServerLatencySupported()) {
        double latencyMs;
        bool fromTrack;
        if (getTrackLatencyMs(&latencyMs, &fromTrack) == OK) {
            // Show latency in msec, followed by 't' if from track timestamp (the most accurate)
            // or 'k' if estimated from kernel (usually for debugging).
            result.appendFormat(" %7.2lf %c", latencyMs, fromTrack ? 't' : 'k');
        } else {
            result.appendFormat("%10s", mCblk->mServer != 0 ? "unavail" : "new");
        }
    }
    result.append("\n");
}

// This is invoked by SyncEvent callback.
void RecordTrack::handleSyncStartEvent(
        const sp<audioflinger::SyncEvent>& event)
{
    size_t framesToDrop = 0;
    const sp<IAfThreadBase> threadBase = mThread.promote();
    if (threadBase != 0) {
        // TODO: use actual buffer filling status instead of 2 buffers when info is available
        // from audio HAL
        framesToDrop = threadBase->frameCount() * 2;
    }

    mSynchronizedRecordState.onPlaybackFinished(event, framesToDrop);
}

void RecordTrack::clearSyncStartEvent()
{
    mSynchronizedRecordState.clear();
}

void RecordTrack::updateTrackFrameInfo(
        int64_t trackFramesReleased, int64_t sourceFramesRead,
        uint32_t halSampleRate, const ExtendedTimestamp &timestamp)
{
   // Make the kernel frametime available.
    const FrameTime ft{
            timestamp.mPosition[ExtendedTimestamp::LOCATION_KERNEL],
            timestamp.mTimeNs[ExtendedTimestamp::LOCATION_KERNEL]};
    // ALOGD("FrameTime: %lld %lld", (long long)ft.frames, (long long)ft.timeNs);
    mKernelFrameTime.store(ft);
    if (!audio_is_linear_pcm(mFormat)) {
        // Stream is direct, return provided timestamp with no conversion
        mServerProxy->setTimestamp(timestamp);
        return;
    }

    ExtendedTimestamp local = timestamp;

    // Convert HAL frames to server-side track frames at track sample rate.
    // We use trackFramesReleased and sourceFramesRead as an anchor point.
    for (int i = ExtendedTimestamp::LOCATION_SERVER; i < ExtendedTimestamp::LOCATION_MAX; ++i) {
        if (local.mTimeNs[i] != 0) {
            const int64_t relativeServerFrames = local.mPosition[i] - sourceFramesRead;
            const int64_t relativeTrackFrames = relativeServerFrames
                    * mSampleRate / halSampleRate; // TODO: potential computation overflow
            local.mPosition[i] = relativeTrackFrames + trackFramesReleased;
        }
    }
    mServerProxy->setTimestamp(local);

    // Compute latency info.
    const bool useTrackTimestamp = true; // use track unless debugging.
    const double latencyMs = - (useTrackTimestamp
            ? local.getOutputServerLatencyMs(sampleRate())
            : timestamp.getOutputServerLatencyMs(halSampleRate));

    mServerLatencyFromTrack.store(useTrackTimestamp);
    mServerLatencyMs.store(latencyMs);
}

status_t RecordTrack::getActiveMicrophones(
        std::vector<media::MicrophoneInfoFw>* activeMicrophones) const
{
    const sp<IAfThreadBase> thread = mThread.promote();
    if (thread != 0) {
        auto* const recordThread = thread->asIAfRecordThread().get();
        return recordThread->getActiveMicrophones(activeMicrophones);
    } else {
        return BAD_VALUE;
    }
}

status_t RecordTrack::setPreferredMicrophoneDirection(
        audio_microphone_direction_t direction) {
    const sp<IAfThreadBase> thread = mThread.promote();
    if (thread != 0) {
        auto* const recordThread = thread->asIAfRecordThread().get();
        return recordThread->setPreferredMicrophoneDirection(direction);
    } else {
        return BAD_VALUE;
    }
}

status_t RecordTrack::setPreferredMicrophoneFieldDimension(float zoom) {
    const sp<IAfThreadBase> thread = mThread.promote();
    if (thread != 0) {
        auto* const recordThread = thread->asIAfRecordThread().get();
        return recordThread->setPreferredMicrophoneFieldDimension(zoom);
    } else {
        return BAD_VALUE;
    }
}

status_t RecordTrack::shareAudioHistory(
        const std::string& sharedAudioPackageName, int64_t sharedAudioStartMs) {

    const uid_t callingUid = IPCThreadState::self()->getCallingUid();
    const pid_t callingPid = IPCThreadState::self()->getCallingPid();
    if (callingUid != mUid || callingPid != mCreatorPid) {
        return PERMISSION_DENIED;
    }

    AttributionSourceState attributionSource{};
    attributionSource.uid = VALUE_OR_RETURN_STATUS(legacy2aidl_uid_t_int32_t(callingUid));
    attributionSource.pid = VALUE_OR_RETURN_STATUS(legacy2aidl_uid_t_int32_t(callingPid));
    attributionSource.token = sp<BBinder>::make();
    if (!captureHotwordAllowed(attributionSource)) {
        return PERMISSION_DENIED;
    }

    const sp<IAfThreadBase> thread = mThread.promote();
    if (thread != 0) {
        auto* const recordThread = thread->asIAfRecordThread().get();
        status_t status = recordThread->shareAudioHistory(
                sharedAudioPackageName, mSessionId, sharedAudioStartMs);
        if (status == NO_ERROR) {
            mSharedAudioPackageName = sharedAudioPackageName;
        }
        return status;
    } else {
        return BAD_VALUE;
    }
}

void RecordTrack::copyMetadataTo(MetadataInserter& backInserter) const
{

    // Do not forward PatchRecord metadata with unspecified audio source
    if (mAttr.source == AUDIO_SOURCE_DEFAULT) {
        return;
    }

    // No track is invalid as this is called after prepareTrack_l in the same critical section
    record_track_metadata_v7_t metadata;
    metadata.base = {
            .source = mAttr.source,
            .gain = 1, // capture tracks do not have volumes
    };
    metadata.channel_mask = mChannelMask;
    strncpy(metadata.tags, mAttr.tags, AUDIO_ATTRIBUTES_TAGS_MAX_SIZE);

    *backInserter++ = metadata;
}

// ----------------------------------------------------------------------------
#undef LOG_TAG
#define LOG_TAG "AF::PatchRecord"

/* static */
sp<IAfPatchRecord> IAfPatchRecord::create(
        IAfRecordThread* recordThread,
        uint32_t sampleRate,
        audio_channel_mask_t channelMask,
        audio_format_t format,
        size_t frameCount,
        void *buffer,
        size_t bufferSize,
        audio_input_flags_t flags,
        const Timeout& timeout,
        audio_source_t source)
{
    return sp<PatchRecord>::make(
            recordThread,
            sampleRate,
            channelMask,
            format,
            frameCount,
            buffer,
            bufferSize,
            flags,
            timeout,
            source);
}

PatchRecord::PatchRecord(IAfRecordThread* recordThread,
                                                     uint32_t sampleRate,
                                                     audio_channel_mask_t channelMask,
                                                     audio_format_t format,
                                                     size_t frameCount,
                                                     void *buffer,
                                                     size_t bufferSize,
                                                     audio_input_flags_t flags,
                                                     const Timeout& timeout,
                                                     audio_source_t source)
    :   RecordTrack(recordThread, NULL,
                audio_attributes_t{ .source = source } ,
                sampleRate, format, channelMask, frameCount,
                buffer, bufferSize, AUDIO_SESSION_NONE, getpid(),
                audioServerAttributionSource(getpid()), flags, TYPE_PATCH),
        PatchTrackBase(mCblk ? new ClientProxy(mCblk, mBuffer, frameCount, mFrameSize, false, true)
                        : nullptr,
                       recordThread, timeout)
{
    ALOGV("%s(%d): sampleRate %d mPeerTimeout %d.%03d sec",
                                      __func__, mId, sampleRate,
                                      (int)mPeerTimeout.tv_sec,
                                      (int)(mPeerTimeout.tv_nsec / 1000000));
}

PatchRecord::~PatchRecord()
{
    ALOGV("%s(%d)", __func__, mId);
}

static size_t writeFramesHelper(
        AudioBufferProvider* dest, const void* src, size_t frameCount, size_t frameSize)
{
    AudioBufferProvider::Buffer patchBuffer;
    patchBuffer.frameCount = frameCount;
    auto status = dest->getNextBuffer(&patchBuffer);
    if (status != NO_ERROR) {
       ALOGW("%s PathRecord getNextBuffer failed with error %d: %s",
             __func__, status, strerror(-status));
       return 0;
    }
    ALOG_ASSERT(patchBuffer.frameCount <= frameCount);
    memcpy(patchBuffer.raw, src, patchBuffer.frameCount * frameSize);
    size_t framesWritten = patchBuffer.frameCount;
    dest->releaseBuffer(&patchBuffer);
    return framesWritten;
}

// static
size_t PatchRecord::writeFrames(
        AudioBufferProvider* dest, const void* src, size_t frameCount, size_t frameSize)
{
    size_t framesWritten = writeFramesHelper(dest, src, frameCount, frameSize);
    // On buffer wrap, the buffer frame count will be less than requested,
    // when this happens a second buffer needs to be used to write the leftover audio
    const size_t framesLeft = frameCount - framesWritten;
    if (framesWritten != 0 && framesLeft != 0) {
        framesWritten += writeFramesHelper(dest, (const char*)src + framesWritten * frameSize,
                        framesLeft, frameSize);
    }
    return framesWritten;
}

// AudioBufferProvider interface
status_t PatchRecord::getNextBuffer(
                                                  AudioBufferProvider::Buffer* buffer)
{
    ALOG_ASSERT(mPeerProxy != 0, "%s(%d): called without peer proxy", __func__, mId);
    Proxy::Buffer buf;
    buf.mFrameCount = buffer->frameCount;
    status_t status = mPeerProxy->obtainBuffer(&buf, &mPeerTimeout);
    ALOGV_IF(status != NO_ERROR,
             "%s(%d): mPeerProxy->obtainBuffer status %d", __func__, mId, status);
    buffer->frameCount = buf.mFrameCount;
    if (ATRACE_ENABLED()) {
        std::string traceName("PRnObt");
        traceName += std::to_string(id());
        ATRACE_INT(traceName.c_str(), buf.mFrameCount);
    }
    if (buf.mFrameCount == 0) {
        return WOULD_BLOCK;
    }
    status = RecordTrack::getNextBuffer(buffer);
    return status;
}

void PatchRecord::releaseBuffer(AudioBufferProvider::Buffer* buffer)
{
    ALOG_ASSERT(mPeerProxy != 0, "%s(%d): called without peer proxy", __func__, mId);
    Proxy::Buffer buf;
    buf.mFrameCount = buffer->frameCount;
    buf.mRaw = buffer->raw;
    mPeerProxy->releaseBuffer(&buf);
    TrackBase::releaseBuffer(buffer);
}

status_t PatchRecord::obtainBuffer(Proxy::Buffer* buffer,
                                                               const struct timespec *timeOut)
{
    return mProxy->obtainBuffer(buffer, timeOut);
}

void PatchRecord::releaseBuffer(Proxy::Buffer* buffer)
{
    mProxy->releaseBuffer(buffer);
}

#undef LOG_TAG
#define LOG_TAG "AF::PthrPatchRecord"

static std::unique_ptr<void, decltype(free)*> allocAligned(size_t alignment, size_t size)
{
    void *ptr = nullptr;
    (void)posix_memalign(&ptr, alignment, size);
    return {ptr, free};
}

/* static */
sp<IAfPatchRecord> IAfPatchRecord::createPassThru(
        IAfRecordThread* recordThread,
        uint32_t sampleRate,
        audio_channel_mask_t channelMask,
        audio_format_t format,
        size_t frameCount,
        audio_input_flags_t flags,
        audio_source_t source)
{
    return sp<PassthruPatchRecord>::make(
            recordThread,
            sampleRate,
            channelMask,
            format,
            frameCount,
            flags,
            source);
}

PassthruPatchRecord::PassthruPatchRecord(
        IAfRecordThread* recordThread,
        uint32_t sampleRate,
        audio_channel_mask_t channelMask,
        audio_format_t format,
        size_t frameCount,
        audio_input_flags_t flags,
        audio_source_t source)
        : PatchRecord(recordThread, sampleRate, channelMask, format, frameCount,
                nullptr /*buffer*/, 0 /*bufferSize*/, flags, {} /* timeout */, source),
          mPatchRecordAudioBufferProvider(*this),
          mSinkBuffer(allocAligned(32, mFrameCount * mFrameSize)),
          mStubBuffer(allocAligned(32, mFrameCount * mFrameSize))
{
    memset(mStubBuffer.get(), 0, mFrameCount * mFrameSize);
}

sp<StreamInHalInterface> PassthruPatchRecord::obtainStream(
        sp<IAfThreadBase>* thread)
{
    *thread = mThread.promote();
    if (!*thread) return nullptr;
    auto* const recordThread = (*thread)->asIAfRecordThread().get();
    audio_utils::lock_guard _l(recordThread->mutex());
    return recordThread->getInput() ? recordThread->getInput()->stream : nullptr;
}

// PatchProxyBufferProvider methods are called on DirectOutputThread
status_t PassthruPatchRecord::obtainBuffer(
        Proxy::Buffer* buffer, const struct timespec* timeOut)
{
    if (mUnconsumedFrames) {
        buffer->mFrameCount = std::min(buffer->mFrameCount, mUnconsumedFrames);
        // mUnconsumedFrames is decreased in releaseBuffer to use actual frame consumption figure.
        return PatchRecord::obtainBuffer(buffer, timeOut);
    }

    // Otherwise, execute a read from HAL and write into the buffer.
    nsecs_t startTimeNs = 0;
    if (timeOut && (timeOut->tv_sec != 0 || timeOut->tv_nsec != 0) && timeOut->tv_sec != INT_MAX) {
        // Will need to correct timeOut by elapsed time.
        startTimeNs = systemTime();
    }
    const size_t framesToRead = std::min(buffer->mFrameCount, mFrameCount);
    buffer->mFrameCount = 0;
    buffer->mRaw = nullptr;
    sp<IAfThreadBase> thread;
    sp<StreamInHalInterface> stream = obtainStream(&thread);
    if (!stream) return NO_INIT;  // If there is no stream, RecordThread is not reading.

    status_t result = NO_ERROR;
    size_t bytesRead = 0;
    {
        ATRACE_NAME("read");
        result = stream->read(mSinkBuffer.get(), framesToRead * mFrameSize, &bytesRead);
        if (result != NO_ERROR) goto stream_error;
        if (bytesRead == 0) return NO_ERROR;
    }

    {
        audio_utils::lock_guard lock(readMutex());
        mReadBytes += bytesRead;
        mReadError = NO_ERROR;
    }
    mReadCV.notify_one();
    // writeFrames handles wraparound and should write all the provided frames.
    // If it couldn't, there is something wrong with the client/server buffer of the software patch.
    buffer->mFrameCount = writeFrames(
            &mPatchRecordAudioBufferProvider,
            mSinkBuffer.get(), bytesRead / mFrameSize, mFrameSize);
    ALOGW_IF(buffer->mFrameCount < bytesRead / mFrameSize,
            "Lost %zu frames obtained from HAL", bytesRead / mFrameSize - buffer->mFrameCount);
    mUnconsumedFrames = buffer->mFrameCount;
    struct timespec newTimeOut;
    if (startTimeNs) {
        // Correct the timeout by elapsed time.
        nsecs_t newTimeOutNs = audio_utils_ns_from_timespec(timeOut) - (systemTime() - startTimeNs);
        if (newTimeOutNs < 0) newTimeOutNs = 0;
        newTimeOut.tv_sec = newTimeOutNs / NANOS_PER_SECOND;
        newTimeOut.tv_nsec = newTimeOutNs - newTimeOut.tv_sec * NANOS_PER_SECOND;
        timeOut = &newTimeOut;
    }
    return PatchRecord::obtainBuffer(buffer, timeOut);

stream_error:
    stream->standby();
    {
        audio_utils::lock_guard lock(readMutex());
        mReadError = result;
    }
    mReadCV.notify_one();
    return result;
}

void PassthruPatchRecord::releaseBuffer(Proxy::Buffer* buffer)
{
    if (buffer->mFrameCount <= mUnconsumedFrames) {
        mUnconsumedFrames -= buffer->mFrameCount;
    } else {
        ALOGW("Write side has consumed more frames than we had: %zu > %zu",
                buffer->mFrameCount, mUnconsumedFrames);
        mUnconsumedFrames = 0;
    }
    PatchRecord::releaseBuffer(buffer);
}

// AudioBufferProvider and Source methods are called on RecordThread
// 'read' emulates actual audio data with 0's. This is OK as 'getNextBuffer'
// and 'releaseBuffer' are stubbed out and ignore their input.
// It's not possible to retrieve actual data here w/o blocking 'obtainBuffer'
// until we copy it.
status_t PassthruPatchRecord::read(
        void* buffer, size_t bytes, size_t* read)
{
    bytes = std::min(bytes, mFrameCount * mFrameSize);
    {
        audio_utils::unique_lock lock(readMutex());
        mReadCV.wait(lock, [&]{ return mReadError != NO_ERROR || mReadBytes != 0; });
        if (mReadError != NO_ERROR) {
            mLastReadFrames = 0;
            return mReadError;
        }
        *read = std::min(bytes, mReadBytes);
        mReadBytes -= *read;
    }
    mLastReadFrames = *read / mFrameSize;
    memset(buffer, 0, *read);
    return 0;
}

status_t PassthruPatchRecord::getCapturePosition(
        int64_t* frames, int64_t* time)
{
    sp<IAfThreadBase> thread;
    sp<StreamInHalInterface> stream = obtainStream(&thread);
    return stream ? stream->getCapturePosition(frames, time) : NO_INIT;
}

status_t PassthruPatchRecord::standby()
{
    // RecordThread issues 'standby' command in two major cases:
    // 1. Error on read--this case is handled in 'obtainBuffer'.
    // 2. Track is stopping--as PassthruPatchRecord assumes continuous
    //    output, this can only happen when the software patch
    //    is being torn down. In this case, the RecordThread
    //    will terminate and close the HAL stream.
    return 0;
}

// As the buffer gets filled in obtainBuffer, here we only simulate data consumption.
status_t PassthruPatchRecord::getNextBuffer(
        AudioBufferProvider::Buffer* buffer)
{
    buffer->frameCount = mLastReadFrames;
    buffer->raw = buffer->frameCount != 0 ? mStubBuffer.get() : nullptr;
    return NO_ERROR;
}

void PassthruPatchRecord::releaseBuffer(
        AudioBufferProvider::Buffer* buffer)
{
    buffer->frameCount = 0;
    buffer->raw = nullptr;
}

// ----------------------------------------------------------------------------
#undef LOG_TAG
#define LOG_TAG "AF::MmapTrack"

/* static */
sp<IAfMmapTrack> IAfMmapTrack::create(IAfThreadBase* thread,
          const audio_attributes_t& attr,
          uint32_t sampleRate,
          audio_format_t format,
          audio_channel_mask_t channelMask,
          audio_session_t sessionId,
          bool isOut,
          const android::content::AttributionSourceState& attributionSource,
          pid_t creatorPid,
          audio_port_handle_t portId)
{
    return sp<MmapTrack>::make(
            thread,
            attr,
            sampleRate,
            format,
            channelMask,
            sessionId,
            isOut,
            attributionSource,
            creatorPid,
            portId);
}

MmapTrack::MmapTrack(IAfThreadBase* thread,
        const audio_attributes_t& attr,
        uint32_t sampleRate,
        audio_format_t format,
        audio_channel_mask_t channelMask,
        audio_session_t sessionId,
        bool isOut,
        const AttributionSourceState& attributionSource,
        pid_t creatorPid,
        audio_port_handle_t portId)
    :   TrackBase(thread, NULL, attr, sampleRate, format,
                  channelMask, (size_t)0 /* frameCount */,
                  nullptr /* buffer */, (size_t)0 /* bufferSize */,
                  sessionId, creatorPid,
                  VALUE_OR_FATAL(aidl2legacy_int32_t_uid_t(attributionSource.uid)),
                  isOut,
                  ALLOC_NONE,
                  TYPE_DEFAULT, portId,
                  std::string(AMEDIAMETRICS_KEY_PREFIX_AUDIO_MMAP) + std::to_string(portId)),
        mPid(VALUE_OR_FATAL(aidl2legacy_int32_t_uid_t(attributionSource.pid))),
            mSilenced(false), mSilencedNotified(false)
{
    // Once this item is logged by the server, the client can add properties.
    mTrackMetrics.logConstructor(creatorPid, uid(), id());
}

MmapTrack::~MmapTrack()
{
}

status_t MmapTrack::initCheck() const
{
    return NO_ERROR;
}

status_t MmapTrack::start(AudioSystem::sync_event_t event __unused,
                                                    audio_session_t triggerSession __unused)
{
    return NO_ERROR;
}

void MmapTrack::stop()
{
}

// AudioBufferProvider interface
status_t MmapTrack::getNextBuffer(AudioBufferProvider::Buffer* buffer)
{
    buffer->frameCount = 0;
    buffer->raw = nullptr;
    return INVALID_OPERATION;
}

// ExtendedAudioBufferProvider interface
size_t MmapTrack::framesReady() const {
    return 0;
}

int64_t MmapTrack::framesReleased() const
{
    return 0;
}

void MmapTrack::onTimestamp(const ExtendedTimestamp& timestamp __unused)
{
}

void MmapTrack::processMuteEvent_l(const sp<IAudioManager>& audioManager, mute_state_t muteState)
{
    if (mMuteState == muteState) {
        // mute state did not change, do nothing
        return;
    }

    status_t result = UNKNOWN_ERROR;
    if (audioManager && mPortId != AUDIO_PORT_HANDLE_NONE) {
        if (mMuteEventExtras == nullptr) {
            mMuteEventExtras = std::make_unique<os::PersistableBundle>();
        }
        mMuteEventExtras->putInt(String16(kExtraPlayerEventMuteKey),
                                 static_cast<int>(muteState));

        result = audioManager->portEvent(mPortId,
                                         PLAYER_UPDATE_MUTED,
                                         mMuteEventExtras);
    }

    if (result == OK) {
        mMuteState = muteState;
    } else {
        ALOGW("%s(%d): cannot process mute state for port ID %d, status error %d",
              __func__,
              id(),
              mPortId,
              result);
    }
}

void MmapTrack::appendDumpHeader(String8& result) const
{
    result.appendFormat("Client Session Port Id  Format Chn mask  SRate Flags %s\n",
                        isOut() ? "Usg CT": "Source");
}

void MmapTrack::appendDump(String8& result, bool active __unused) const
{
    result.appendFormat("%6u %7u %7u %08X %08X %6u 0x%03X ",
            mPid,
            mSessionId,
            mPortId,
            mFormat,
            mChannelMask,
            mSampleRate,
            mAttr.flags);
    if (isOut()) {
        result.appendFormat("%3x %2x", mAttr.usage, mAttr.content_type);
    } else {
        result.appendFormat("%6x", mAttr.source);
    }
    result.append("\n");
}

} // namespace android
