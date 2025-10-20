/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <inttypes.h>

#define LOG_TAG "InputSurfaceSource"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#define STRINGIFY_ENUMS // for asString in HardwareAPI.h/VideoAPI.h

#include <codec2/aidl/inputsurface/FrameDropper.h>
#include <codec2/aidl/inputsurface/InputSurfaceSource.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/ColorUtils.h>
#include <media/stagefright/foundation/FileDescriptor.h>

#include <android-base/no_destructor.h>
#include <android-base/properties.h>
#include <media/hardware/HardwareAPI.h>
#include <ui/Fence.h>

#include <inttypes.h>

#include <functional>
#include <map>
#include <memory>
#include <cmath>

// TODO: remove CHECK() since this works in HAL process,
// we don't want to kill the HAL process when there is a irrecoverable runtime
// error.

namespace aidl::android::hardware::media::c2::implementation {

using ::android::AHandlerReflector;
using ::android::ALooper;
using ::android::AMessage;
using ::android::ColorAspects;
using ::android::ColorUtils;
using ::android::Fence;
using ::android::FileDescriptor;
using ::android::List;
using ::android::Mutex;
using ::android::String8;
using ::android::Vector;
using ::android::sp;
using ::android::wp;

using c2::utils::InputSurfaceConnection;

namespace {
// kTimestampFluctuation is an upper bound of timestamp fluctuation from the
// source that InputSurfaceSource allows. The unit of kTimestampFluctuation is
// frames. More specifically, InputSurfaceSource will drop a frame if
//
// expectedNewFrametimestamp - actualNewFrameTimestamp <
//     (0.5 - kTimestampFluctuation) * expectedtimePeriodBetweenFrames
//
// where
// - expectedNewFrameTimestamp is the calculated ideal timestamp of the new
//   incoming frame
// - actualNewFrameTimestamp is the timestamp received from the source
// - expectedTimePeriodBetweenFrames is the ideal difference of the timestamps
//   of two adjacent frames
//
// See InputSurfaceSource::calculateCodecTimestamp_l() for more detail about
// how kTimestampFluctuation is used.
//
// kTimestampFluctuation should be non-negative. A higher value causes a smaller
// chance of dropping frames, but at the same time a higher bound on the
// difference between the source timestamp and the interpreted (snapped)
// timestamp.
//
// The value of 0.05 means that InputSurfaceSource expects the input timestamps
// to fluctuate no more than 5% from the regular time period.
//
// TODO: Justify the choice of this value, or make it configurable.
constexpr double kTimestampFluctuation = 0.05;
}

/**
 * A copiable object managing a buffer in the buffer cache managed by the producer. This object
 * holds a reference to the buffer, and maintains which buffer slot it belongs to (if any), and
 * whether it is still in a buffer slot. It also maintains whether there are any outstanging acquire
 * references to it (by buffers acquired from the slot) mainly so that we can keep a debug
 * count of how many buffers we need to still release back to the producer.
 */
struct InputSurfaceSource::CachedBuffer {
    /**
     * Token that is used to track acquire counts (as opposed to all references to this object).
     */
    struct Acquirable { };

    /**
     * Create using a buffer cached in a slot.
     */
    CachedBuffer(ahwb_id id, AImage *image)
        : mIsCached(true),
          mId(id),
          mImage(image),
          mAcquirable(std::make_shared<Acquirable>()) {}

    /**
     * Returns the id of buffer which is cached in, or 0 if it is no longer cached.
     *
     * This assumes that 0 id is invalid; though, it is just a benign collision used for
     * debugging. This object explicitly manages whether it is still cached.
     */
    ahwb_id getId() const {
        return mIsCached ? mId : 0;
    }

    /**
     * Returns the cached buffer(AImage).
     */
    AImage *getImage() const {
        return mImage;
    }

    /**
     * Checks whether this buffer is still in the buffer cache.
     */
    bool isCached() const {
        return mIsCached;
    }

    /**
     * Checks whether this buffer has an acquired reference.
     */
    bool isAcquired() const {
        return mAcquirable.use_count() > 1;
    }

    /**
     * Gets and returns a shared acquired reference.
     */
    std::shared_ptr<Acquirable> getAcquirable() {
        return mAcquirable;
    }

private:
    friend void InputSurfaceSource::discardBufferAtIter_l(BufferIdMap::iterator&);

    /**
     * This method to be called when the buffer is no longer in the buffer cache.
     * Called from discardBufferAtIter_l.
     */
    void onDroppedFromCache() {
        CHECK_DBG(mIsCached);
        mIsCached = false;
    }

    bool mIsCached;
    ahwb_id mId;
    AImage *mImage;
    std::shared_ptr<Acquirable> mAcquirable;
};

/**
 * A copiable object managing a buffer acquired from the producer. This must always be a cached
 * buffer. This objects also manages its acquire fence and any release fences that may be returned
 * by the encoder for this buffer (this buffer may be queued to the encoder multiple times).
 * If no release fences are added by the encoder, the acquire fence is returned as the release
 * fence for this - as it is assumed that noone waited for the acquire fence. Otherwise, it is
 * assumed that the encoder has waited for the acquire fence (or returned it as the release
 * fence).
 */
struct InputSurfaceSource::AcquiredBuffer {
    AcquiredBuffer(
            const std::shared_ptr<CachedBuffer> &buffer,
            std::function<void(AcquiredBuffer *)> onReleased,
            const sp<Fence> &acquireFence)
        : mBuffer(buffer),
          mAcquirable(buffer->getAcquirable()),
          mAcquireFence(acquireFence),
          mGotReleaseFences(false),
          mOnReleased(onReleased) {
    }

    /**
     * Adds a release fence returned by the encoder to this object. If this is called with an
     * valid file descriptor, it is added to the list of release fences. These are returned to the
     * producer on release() as a merged fence. Regardless of the validity of the file descriptor,
     * we take note that a release fence was attempted to be added and the acquire fence can now be
     * assumed as acquired.
     */
    void addReleaseFenceFd(int fenceFd) {
        // save all release fences - these will be propagated to the producer if this buffer is
        // ever released to it
        if (fenceFd >= 0) {
            mReleaseFenceFds.push_back(fenceFd);
        }
        mGotReleaseFences = true;
    }

    /**
     * Returns the acquire fence file descriptor associated with this object.
     */
    int getAcquireFenceFd() {
        if (mAcquireFence == nullptr || !mAcquireFence->isValid()) {
            return -1;
        }
        return mAcquireFence->dup();
    }

    /**
     * Returns whether the buffer is still in the buffer cache.
     */
    bool isCached() const {
        return mBuffer->isCached();
    }

    /**
     * Returns the acquired buffer.
     */
    AImage *getImage() const {
        return mBuffer->getImage();
    }

    /**
     * Returns the id of buffer which is cached in, or 0 otherwise.
     *
     * This assumes that 0 id is invalid; though, it is just a benign collision used for
     * debugging. This object explicitly manages whether it is still cached.
     */
    ahwb_id getId() const {
        return mBuffer->getId();
    }

    /**
     * Creates and returns a release fence object from the acquire fence and/or any release fences
     * added. If no release fences were added (even if invalid), returns the acquire fence.
     * Otherwise, it returns a merged fence from all the valid release fences added.
     */
    sp<Fence> getReleaseFence() {
        // If did not receive release fences, we assume this buffer was not consumed (it was
        // discarded or dropped). In this case release the acquire fence as the release fence.
        // We do this here to avoid a dup, close and recreation of the Fence object.
        if (!mGotReleaseFences) {
            return mAcquireFence;
        }
        sp<Fence> ret = getReleaseFence(0, mReleaseFenceFds.size());
        // clear fds as fence took ownership of them
        mReleaseFenceFds.clear();
        return ret;
    }

    // this video buffer is no longer referenced by the codec (or kept for later encoding)
    // it is now safe to release to the producer
    ~AcquiredBuffer() {
        //mAcquirable.clear();
        mOnReleased(this);
        // mOnRelease method should call getReleaseFence() that releases all fds but just in case
        ALOGW_IF(!mReleaseFenceFds.empty(), "release fences were not obtained, closing fds");
        for (int fildes : mReleaseFenceFds) {
            ::close(fildes);
            TRESPASS_DBG();
        }
    }

private:
    std::shared_ptr<InputSurfaceSource::CachedBuffer> mBuffer;
    std::shared_ptr<InputSurfaceSource::CachedBuffer::Acquirable> mAcquirable;
    sp<Fence> mAcquireFence;
    Vector<int> mReleaseFenceFds;
    bool mGotReleaseFences;
    std::function<void(AcquiredBuffer *)> mOnReleased;

    /**
     * Creates and returns a release fence from 0 or more release fence file descriptors in from
     * the specified range in the array.
     *
     * @param start start index
     * @param num   number of release fds to merge
     */
    sp<Fence> getReleaseFence(size_t start, size_t num) const {
        if (num == 0) {
            return Fence::NO_FENCE;
        } else if (num == 1) {
            return new Fence(mReleaseFenceFds[start]);
        } else {
            return Fence::merge("GBS::AB",
                                getReleaseFence(start, num >> 1),
                                getReleaseFence(start + (num >> 1), num - (num >> 1)));
        }
    }
};

struct InputSurfaceSource::ImageReaderListener {
private:
    std::map<uint64_t, wp<InputSurfaceSource>> listeners;
    std::mutex mutex;
    uint64_t seqId{0};

    sp<InputSurfaceSource> getSource(void *context) {
        sp<InputSurfaceSource> source;
        uint64_t key = reinterpret_cast<uint64_t>(context);
        std::lock_guard<std::mutex> l(mutex);
        auto it = listeners.find(key);
        if (it != listeners.end()) {
            source = it->second.promote();
            if (!source) {
                listeners.erase(it);
            }
        }
        return source;
    }

public:
    static InputSurfaceSource::ImageReaderListener& GetInstance() {
        static ::android::base::NoDestructor<
              InputSurfaceSource::ImageReaderListener> sImageListener{};
        return *sImageListener;
    }

    void *add(const sp<InputSurfaceSource> &source) {
        wp<InputSurfaceSource> wsource = source;
        std::lock_guard<std::mutex> l(mutex);
        uint64_t key = seqId++;
        listeners[key] = wsource;
        return reinterpret_cast<void *>(key);
    }

    void remove(void *context) {
        std::lock_guard<std::mutex> l(mutex);
        uint64_t key = reinterpret_cast<uint64_t>(context);
        listeners.erase(key);
    }

    void onImageAvailable(void *context) {
        sp<InputSurfaceSource> source = getSource(context);
        if (source) {
            source->onFrameAvailable();
        }
    }

    void onBufferRemoved(void *context, AHardwareBuffer *buf) {
        sp<InputSurfaceSource> source = getSource(context);
        if (source) {
            if (__builtin_available(android __ANDROID_API_T__, *)) {
                uint64_t bid;
                if (AHardwareBuffer_getId(buf, &bid) == ::android::OK) {
                    source->onBufferReleased(bid);
                }
            }
        }
    }
};

InputSurfaceSource::InputSurfaceSource() :
    mInitCheck(C2_NO_INIT),
    mNumAvailableUnacquiredBuffers(0),
    mNumOutstandingAcquires(0),
    mEndOfStream(false),
    mEndOfStreamSent(false),
    mLastDataspace(HAL_DATASPACE_UNKNOWN),
    mExecuting(false),
    mSuspended(false),
    mLastFrameTimestampUs(-1),
    mImageReader(nullptr),
    mImageWindow(nullptr),
    mStopTimeUs(-1),
    mLastActionTimeUs(-1LL),
    mSkipFramesBeforeNs(-1LL),
    mFrameRepeatIntervalUs(-1LL),
    mRepeatLastFrameGeneration(0),
    mOutstandingFrameRepeatCount(0),
    mFrameRepeatBlockedOnCodecBuffer(false),
    mFps(-1.0),
    mCaptureFps(-1.0),
    mBaseCaptureUs(-1LL),
    mBaseFrameUs(-1LL),
    mFrameCount(0),
    mPrevCaptureUs(-1LL),
    mPrevFrameUs(-1LL),
    mInputBufferTimeOffsetUs(0LL) {
    ALOGV("InputSurfaceSource");

    String8 name("InputSurfaceSource");

    memset(&mDefaultColorAspectsPacked, 0, sizeof(mDefaultColorAspectsPacked));
}

void InputSurfaceSource::initImageReaderLocked() {
    constexpr int32_t kInitWidth = 1;
    constexpr int32_t kInitHeight = 1;
    constexpr int32_t kInitFormat = HAL_PIXEL_FORMAT_RGBA_8888;
    constexpr uint64_t kInitUsage = AHARDWAREBUFFER_USAGE_VIDEO_ENCODE;
    constexpr int32_t kInitMaxImages = 1;

    if (mInitCheck != C2_NO_INIT) {
        return;
    }
    media_status_t err = AImageReader_newWithUsage(
            kInitWidth, kInitHeight, kInitFormat, kInitUsage, kInitMaxImages, &mImageReader);
    if (err != AMEDIA_OK) {
        if (err == AMEDIA_ERROR_INVALID_PARAMETER) {
            mInitCheck = C2_BAD_VALUE;
        } else {
            mInitCheck = C2_CORRUPTED;
        }
        ALOGE("Error constructing AImageReader: %d", err);
        return;
    }
    createImageListeners();
    (void)AImageReader_setImageListener(mImageReader, &mImageListener);
    (void)AImageReader_setBufferRemovedListener(mImageReader, &mBufferRemovedListener);

    if (AImageReader_getWindow(mImageReader, &mImageWindow) == AMEDIA_OK) {
        mInitCheck = C2_OK;
    } else {
        ALOGE("Error getting window from AImageReader: %d", err);
        mInitCheck = C2_CORRUPTED;
    }
}

void InputSurfaceSource::setEventCallback(std::shared_ptr<EventCallback> callback) {
    mEventCallback = callback;
}

InputSurfaceSource::~InputSurfaceSource() {
    ALOGV("~InputSurfaceSource");
    {
        // all acquired buffers must be freed with the mutex locked otherwise our debug assertion
        // may trigger
        std::lock_guard<std::mutex> autoLock(mMutex);
        mAvailableBuffers.clear();
        mSubmittedCodecBuffers.clear();
        mLatestBuffer.mBuffer.reset();
    }

    if (mNumOutstandingAcquires != 0) {
        ALOGW("potential buffer leak: acquired=%d", mNumOutstandingAcquires);
        TRESPASS_DBG();
    }

    if (mImageReader != nullptr) {
        AImageReader_delete(mImageReader);
        mImageReader = nullptr;
        mImageWindow = nullptr;
    }
}

void InputSurfaceSource::createImageListeners() {
    void *context = ImageReaderListener::GetInstance().add(
            sp<InputSurfaceSource>::fromExisting(this));
    mImageListener = {
        context,
        [](void *key, AImageReader *imageReader) {
            (void)imageReader;
            ImageReaderListener::GetInstance().onImageAvailable(key); }
    };
    mBufferRemovedListener = {
        context,
        [](void *key, AImageReader *imageReader, AHardwareBuffer *buffer) {
            (void)imageReader;
            ImageReaderListener::GetInstance().onBufferRemoved(key, buffer); }
    };
}

ANativeWindow *InputSurfaceSource::getNativeWindow() {
    std::lock_guard<std::mutex> autoLock(mMutex);
    initImageReaderLocked();
    return mImageWindow;
}

c2_status_t InputSurfaceSource::start() {
    std::lock_guard<std::mutex> autoLock(mMutex);
    if (mInitCheck != C2_OK) {
        ALOGE("start() was called without initialization");
        return C2_CORRUPTED;
    }
    ALOGV("--> start; available=%zu, submittable=%zd",
            mAvailableBuffers.size(), mFreeCodecBuffers.size());
    CHECK(!mExecuting);
    mExecuting = true;
    mLastDataspace = HAL_DATASPACE_UNKNOWN;
    ALOGV("clearing last dataSpace");

    // Start by loading up as many buffers as possible.  We want to do this,
    // rather than just submit the first buffer, to avoid a degenerate case:
    // if all BQ buffers arrive before we start executing, and we only submit
    // one here, the other BQ buffers will just sit until we get notified
    // that the codec buffer has been released.  We'd then acquire and
    // submit a single additional buffer, repeatedly, never using more than
    // one codec buffer simultaneously.  (We could instead try to submit
    // all BQ buffers whenever any codec buffer is freed, but if we get the
    // initial conditions right that will never be useful.)
    while (haveAvailableBuffers_l()) {
        if (!fillCodecBuffer_l()) {
            ALOGV("stop load with available=%zu+%d",
                    mAvailableBuffers.size(), mNumAvailableUnacquiredBuffers);
            break;
        }
    }

    ALOGV("done loading initial frames, available=%zu+%d",
            mAvailableBuffers.size(), mNumAvailableUnacquiredBuffers);

    // If EOS has already been signaled, and there are no more frames to
    // submit, try to send EOS now as well.
    if (mStopTimeUs == -1 && mEndOfStream && !haveAvailableBuffers_l()) {
        submitEndOfInputStream_l();
    }

    if (mFrameRepeatIntervalUs > 0LL && mLooper == NULL) {
        mReflector = new AHandlerReflector<InputSurfaceSource>(this);

        mLooper = new ALooper;
        mLooper->registerHandler(mReflector);
        mLooper->start();

        if (mLatestBuffer.mBuffer != nullptr) {
            queueFrameRepeat_l();
        }
    }

    return C2_OK;
}

c2_status_t InputSurfaceSource::stop() {
    ALOGV("stop");

    std::lock_guard<std::mutex> autoLock(mMutex);

    if (mExecuting) {
        // We are only interested in the transition from executing->idle,
        // not loaded->idle.
        mExecuting = false;
    }
    return C2_OK;
}

c2_status_t InputSurfaceSource::release(){
    sp<ALooper> looper;
    {
        std::lock_guard<std::mutex> autoLock(mMutex);
        looper = mLooper;
        if (mLooper != NULL) {
            mLooper->unregisterHandler(mReflector->id());
            mReflector.clear();

            mLooper.clear();
        }

        ALOGV("--> release; available=%zu+%d eos=%d eosSent=%d acquired=%d",
                mAvailableBuffers.size(), mNumAvailableUnacquiredBuffers,
                mEndOfStream, mEndOfStreamSent, mNumOutstandingAcquires);

        // Codec is no longer executing.  Releasing all buffers to bq.
        mFreeCodecBuffers.clear();
        mSubmittedCodecBuffers.clear();
        mLatestBuffer.mBuffer.reset();
        mComponent.reset();
        mExecuting = false;
    }
    if (looper != NULL) {
        looper->stop();
    }
    if (mEventCallback) {
        mEventCallback->onComponentReleased();
    }
    return C2_OK;
}

c2_status_t InputSurfaceSource::onInputBufferAdded(codec_buffer_id bufferId) {
    std::lock_guard<std::mutex> autoLock(mMutex);

    if (mExecuting) {
        // This should never happen -- buffers can only be allocated when
        // transitioning from "loaded" to "idle".
        ALOGE("addCodecBuffer: buffer added while executing");
        return C2_BAD_STATE;
    }

    ALOGV("addCodecBuffer: bufferId=%u", bufferId);

    mFreeCodecBuffers.push_back(bufferId);
    return C2_OK;
}

c2_status_t InputSurfaceSource::onInputBufferEmptied(codec_buffer_id bufferId, int fenceFd) {
    std::lock_guard<std::mutex> autoLock(mMutex);
    FileDescriptor::Autoclose fence(fenceFd);

    auto it = mSubmittedCodecBuffers.find(bufferId);
    if (it == mSubmittedCodecBuffers.end()) {
        // This should never happen.
        ALOGE("onInputBufferEmptied: buffer not recognized (bufferId=%u)", bufferId);
        return C2_BAD_VALUE;
    }

    std::shared_ptr<AcquiredBuffer> buffer = it->second;

    // Move buffer to available buffers
    mSubmittedCodecBuffers.erase(it);
    mFreeCodecBuffers.push_back(bufferId);

    // header->nFilledLen may not be the original value, so we can't compare
    // that to zero to see of this was the EOS buffer.  Instead we just
    // see if there is a null AcquiredBuffer, which should only ever happen for EOS.
    if (buffer == nullptr) {
        if (!(mEndOfStream && mEndOfStreamSent)) {
            // This can happen when broken code sends us the same buffer twice in a row.
            ALOGE("onInputBufferEmptied: non-EOS null buffer (bufferId=%u)", bufferId);
        } else {
            ALOGV("onInputBufferEmptied: EOS null buffer (bufferId=%u)", bufferId);
        }
        // No GraphicBuffer to deal with, no additional input or output is expected, so just return.
        return C2_BAD_VALUE;
    }

    if (!mExecuting) {
        // this is fine since this could happen when going from Idle to Loaded
        ALOGV("onInputBufferEmptied: no longer executing (bufferId=%u)", bufferId);
        return C2_OK;
    }

    ALOGV("onInputBufferEmptied: bufferId=%d [id=%llu, useCount=%ld] acquired=%d",
            bufferId, (unsigned long long)buffer->getId(), buffer.use_count(),
            mNumOutstandingAcquires);

    buffer->addReleaseFenceFd(fence.release());
    // release codec reference for video buffer just in case remove does not it
    buffer.reset();

    if (haveAvailableBuffers_l()) {
        // Fill this codec buffer.
        CHECK(!mEndOfStreamSent);
        ALOGV("onInputBufferEmptied: buffer freed, feeding codec (available=%zu+%d, eos=%d)",
                mAvailableBuffers.size(), mNumAvailableUnacquiredBuffers, mEndOfStream);
        fillCodecBuffer_l();
    } else if (mEndOfStream && mStopTimeUs == -1) {
        // No frames available, but EOS is pending and no stop time, so use this buffer to
        // send that.
        ALOGV("onInputBufferEmptied: buffer freed, submitting EOS");
        submitEndOfInputStream_l();
    } else if (mFrameRepeatBlockedOnCodecBuffer) {
        bool success = repeatLatestBuffer_l();
        ALOGV("onInputBufferEmptied: completing deferred repeatLatestBuffer_l %s",
                success ? "SUCCESS" : "FAILURE");
        mFrameRepeatBlockedOnCodecBuffer = false;
    }

    // releaseReleasableBuffers_l();
    return C2_OK;
}

void InputSurfaceSource::onDataspaceChanged_l(
        android_dataspace dataspace, android_pixel_format pixelFormat) {
    ALOGD("got buffer with new dataSpace %#x", dataspace);
    mLastDataspace = dataspace;

    if (ColorUtils::convertDataSpaceToV0(dataspace)) {
        mComponent->dispatchDataSpaceChanged(
                mLastDataspace, mDefaultColorAspectsPacked, pixelFormat);
        if (mEventCallback) {
            // This will allow the client to query the changed dataspace.
            mEventCallback->onDataspaceChanged(dataspace, pixelFormat);
        }
    }
}

bool InputSurfaceSource::fillCodecBuffer_l() {
    CHECK(mExecuting && haveAvailableBuffers_l());

    if (mFreeCodecBuffers.empty()) {
        // No buffers available, bail.
        ALOGV("fillCodecBuffer_l: no codec buffers, available=%zu+%d",
                mAvailableBuffers.size(), mNumAvailableUnacquiredBuffers);
        return false;
    }

    VideoBuffer item;
    if (mAvailableBuffers.empty()) {
        ALOGV("fillCodecBuffer_l: acquiring available buffer, available=%zu+%d",
                mAvailableBuffers.size(), mNumAvailableUnacquiredBuffers);
        if (acquireBuffer_l(&item) != C2_OK) {
            ALOGE("fillCodecBuffer_l: failed to acquire available buffer");
            return false;
        }
    } else {
        ALOGV("fillCodecBuffer_l: getting available buffer, available=%zu+%d",
                mAvailableBuffers.size(), mNumAvailableUnacquiredBuffers);
        item = *mAvailableBuffers.begin();
        mAvailableBuffers.erase(mAvailableBuffers.begin());
    }

    int64_t itemTimeUs = item.mTimestampNs / 1000;

    // Process ActionItem in the Queue if there is any. If a buffer's timestamp
    // is smaller than the first action's timestamp, no action need to be performed.
    // If buffer's timestamp is larger or equal than the last action's timestamp,
    // only the last action needs to be performed as all the acitions before the
    // the action are overridden by the last action. For the other cases, traverse
    // the Queue to find the newest action that with timestamp smaller or equal to
    // the buffer's timestamp. For example, an action queue like
    // [pause 1us], [resume 2us], [pause 3us], [resume 4us], [pause 5us].... Upon
    // receiving a buffer with timestamp 3.5us, only the action [pause, 3us] needs
    // to be handled and [pause, 1us], [resume 2us] will be discarded.
    bool done = false;
    bool seeStopAction = false;
    if (!mActionQueue.empty()) {
        // First scan to check if bufferTimestamp is smaller than first action's timestamp.
        ActionItem nextAction = *(mActionQueue.begin());
        if (itemTimeUs < nextAction.mActionTimeUs) {
            ALOGV("No action. buffer timestamp %lld us < action timestamp: %lld us",
                (long long)itemTimeUs, (long long)nextAction.mActionTimeUs);
            // All the actions are ahead. No action need to perform now.
            // Release the buffer if is in suspended state, or process the buffer
            // if not in suspended state.
            done = true;
        }

        if (!done) {
            // Find the newest action that with timestamp smaller than itemTimeUs. Then
            // remove all the actions before and include the newest action.
          std::list<ActionItem>::iterator it = mActionQueue.begin();
            while (it != mActionQueue.end() && it->mActionTimeUs <= itemTimeUs
                    && nextAction.mAction != ActionItem::STOP) {
                nextAction = *it;
                ++it;
            }
            mActionQueue.erase(mActionQueue.begin(), it);

            CHECK(itemTimeUs >= nextAction.mActionTimeUs);
            switch (nextAction.mAction) {
                case ActionItem::PAUSE:
                {
                    mSuspended = true;
                    ALOGV("RUNNING/PAUSE -> PAUSE at buffer %lld us  PAUSE Time: %lld us",
                            (long long)itemTimeUs, (long long)nextAction.mActionTimeUs);
                    break;
                }
                case ActionItem::RESUME:
                {
                    mSuspended = false;
                    ALOGV("PAUSE/RUNNING -> RUNNING at buffer %lld us  RESUME Time: %lld us",
                            (long long)itemTimeUs, (long long)nextAction.mActionTimeUs);
                    break;
                }
                case ActionItem::STOP:
                {
                    ALOGV("RUNNING/PAUSE -> STOP at buffer %lld us  STOP Time: %lld us",
                            (long long)itemTimeUs, (long long)nextAction.mActionTimeUs);
                    // Clear the whole ActionQueue as recording is done
                    mActionQueue.clear();
                    seeStopAction = true;
                    break;
                }
                default:
                    TRESPASS_DBG("Unknown action type");
                    // return true here because we did consume an available buffer, so the
                    // loop in start will eventually terminate even if we hit this.
                    return false;
            }
        }
    }

    if (seeStopAction) {
        // Clear all the buffers before setting mEndOfStream and signal EndOfInputStream.
        releaseAllAvailableBuffers_l();
        mEndOfStream = true;
        submitEndOfInputStream_l();
        return true;
    }

    if (mSuspended) {
        return true;
    }

    c2_status_t err = C2_CORRUPTED;

    // only submit sample if start time is unspecified, or sample
    // is queued after the specified start time
    if (mSkipFramesBeforeNs < 0LL || item.mTimestampNs >= mSkipFramesBeforeNs) {
        // if start time is set, offset time stamp by start time
        if (mSkipFramesBeforeNs > 0) {
            item.mTimestampNs -= mSkipFramesBeforeNs;
        }

        int64_t timeUs = item.mTimestampNs / 1000;
        if (mFrameDropper != NULL && mFrameDropper->shouldDrop(timeUs)) {
            ALOGV("skipping frame (%lld) to meet max framerate", static_cast<long long>(timeUs));
            // set err to OK so that the skipped frame can still be saved as the latest frame
            err = C2_OK;
        } else {
            err = submitBuffer_l(item); // this takes shared ownership of
                                        // the acquired buffer on success
        }
    }

    if (err != C2_OK) {
        ALOGV("submitBuffer_l failed, will release buffer id %llu",
                (unsigned long long)item.mBuffer->getId());
        return true;
    } else {
        // Don't set the last buffer id if we're not repeating,
        // we'll be holding on to the last buffer for nothing.
        if (mFrameRepeatIntervalUs > 0LL) {
            setLatestBuffer_l(item);
        }
        ALOGV("buffer submitted [id=%llu, useCount=%ld] acquired=%d",
                (unsigned long long)item.mBuffer->getId(),
                item.mBuffer.use_count(), mNumOutstandingAcquires);
        mLastFrameTimestampUs = itemTimeUs;
    }

    return true;
}

bool InputSurfaceSource::repeatLatestBuffer_l() {
    CHECK(mExecuting && !haveAvailableBuffers_l());

    if (mLatestBuffer.mBuffer == nullptr || mSuspended) {
        return false;
    }

    if (mFreeCodecBuffers.empty()) {
        // No buffers available, bail.
        ALOGV("repeatLatestBuffer_l: no codec buffers.");
        return false;
    }

    if (!mLatestBuffer.mBuffer->isCached()) {
        ALOGV("repeatLatestBuffer_l: slot was discarded, but repeating our own reference");
    }

    // it is ok to update the timestamp of latest buffer as it is only used for submission
    c2_status_t err = submitBuffer_l(mLatestBuffer);
    if (err != C2_OK) {
        return false;
    }

    /* repeat last frame up to kRepeatLastFrameCount times.
     * in case of static scene, a single repeat might not get rid of encoder
     * ghosting completely, refresh a couple more times to get better quality
     */
    if (--mOutstandingFrameRepeatCount > 0) {
        // set up timestamp for repeat frame
        mLatestBuffer.mTimestampNs += mFrameRepeatIntervalUs * 1000;
        queueFrameRepeat_l();
    }

    return true;
}

void InputSurfaceSource::setLatestBuffer_l(const VideoBuffer &item) {
    mLatestBuffer = item;

    ALOGV("setLatestBuffer_l: [id=%llu, useCount=%ld]",
            (unsigned long long)mLatestBuffer.mBuffer->getId(), mLatestBuffer.mBuffer.use_count());

    mOutstandingFrameRepeatCount = kRepeatLastFrameCount;
    // set up timestamp for repeat frame
    mLatestBuffer.mTimestampNs += mFrameRepeatIntervalUs * 1000;
    queueFrameRepeat_l();
}

void InputSurfaceSource::queueFrameRepeat_l() {
    mFrameRepeatBlockedOnCodecBuffer = false;

    if (mReflector != NULL) {
        sp<AMessage> msg = new AMessage(kWhatRepeatLastFrame, mReflector);
        msg->setInt32("generation", ++mRepeatLastFrameGeneration);
        msg->post(mFrameRepeatIntervalUs);
    }
}

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
bool InputSurfaceSource::calculateCodecTimestamp_l(
        nsecs_t bufferTimeNs, int64_t *codecTimeUs) {
    int64_t timeUs = bufferTimeNs / 1000;
    timeUs += mInputBufferTimeOffsetUs;

    if (mCaptureFps > 0.
            && (mFps > 2 * mCaptureFps
            || mCaptureFps > 2 * mFps)) {
        // Time lapse or slow motion mode
        if (mPrevCaptureUs < 0LL) {
            // first capture
            mPrevCaptureUs = mBaseCaptureUs = timeUs;
            // adjust the first sample timestamp.
            mPrevFrameUs = mBaseFrameUs =
                    std::llround((timeUs * mCaptureFps) / mFps);
            mFrameCount = 0;
        } else if (mSnapTimestamps) {
            double nFrames = (timeUs - mPrevCaptureUs) * mCaptureFps / 1000000;
            if (nFrames < 0.5 - kTimestampFluctuation) {
                // skip this frame as it's too close to previous capture
                ALOGD("skipping frame, timeUs %lld",
                      static_cast<long long>(timeUs));
                return false;
            }
            // snap to nearest capture point
            if (nFrames <= 1.0) {
                nFrames = 1.0;
            }
            mFrameCount += std::llround(nFrames);
            mPrevCaptureUs = mBaseCaptureUs + std::llround(
                    mFrameCount * 1000000 / mCaptureFps);
            mPrevFrameUs = mBaseFrameUs + std::llround(
                    mFrameCount * 1000000 / mFps);
        } else {
            if (timeUs <= mPrevCaptureUs) {
                if (mFrameDropper != NULL && mFrameDropper->disabled()) {
                    // Warn only, client has disabled frame drop logic possibly for image
                    // encoding cases where camera's ZSL mode could send out of order frames.
                    ALOGW("Received frame that's going backward in time");
                } else {
                    // Drop the frame if it's going backward in time. Bad timestamp
                    // could disrupt encoder's rate control completely.
                    ALOGW("Dropping frame that's going backward in time");
                    return false;
                }
            }
            mPrevCaptureUs = timeUs;
            mPrevFrameUs = mBaseFrameUs + std::llround(
                    (timeUs - mBaseCaptureUs) * (mCaptureFps / mFps));
        }

        ALOGV("timeUs %lld, captureUs %lld, frameUs %lld",
                static_cast<long long>(timeUs),
                static_cast<long long>(mPrevCaptureUs),
                static_cast<long long>(mPrevFrameUs));
    } else {
        if (timeUs <= mPrevFrameUs) {
            if (mFrameDropper != NULL && mFrameDropper->disabled()) {
                // Warn only, client has disabled frame drop logic possibly for image
                // encoding cases where camera's ZSL mode could send out of order frames.
                ALOGW("Received frame that's going backward in time");
            } else {
                // Drop the frame if it's going backward in time. Bad timestamp
                // could disrupt encoder's rate control completely.
                ALOGW("Dropping frame that's going backward in time");
                return false;
            }
        }

        mPrevFrameUs = timeUs;
    }

    *codecTimeUs = mPrevFrameUs;
    return true;
}

c2_status_t InputSurfaceSource::submitBuffer_l(const VideoBuffer &item) {
    CHECK(!mFreeCodecBuffers.empty());
    uint32_t codecBufferId = *mFreeCodecBuffers.begin();

    ALOGV("submitBuffer_l [id=%llu, codecbufferId=%d]",
            (unsigned long long)item.mBuffer->getId(), codecBufferId);

    int64_t codecTimeUs;
    if (!calculateCodecTimestamp_l(item.mTimestampNs, &codecTimeUs)) {
        return C2_CORRUPTED;
    }

    std::shared_ptr<AcquiredBuffer> buffer = item.mBuffer;
    int32_t imageFormat = 0;
    AHardwareBuffer *ahwb = nullptr;
    AImage_getFormat(buffer->getImage(), &imageFormat);
    AImage_getHardwareBuffer(buffer->getImage(), &ahwb);

    if ((android_dataspace)item.mDataspace != mLastDataspace) {
        onDataspaceChanged_l(
                item.mDataspace,
                (android_pixel_format)imageFormat);
    }

    c2_status_t err = mComponent->submitBuffer(
            codecBufferId, buffer->getImage(), codecTimeUs, buffer->getAcquireFenceFd());

    if (err != C2_OK) {
        ALOGW("WARNING: emptyGraphicBuffer failed: 0x%x", err);
        return err;
    }

    mFreeCodecBuffers.erase(mFreeCodecBuffers.begin());

    auto res = mSubmittedCodecBuffers.emplace(codecBufferId, buffer);
    if (!res.second) {
        auto it = res.first;
        it->second = buffer;
    }
    ALOGV("emptyImageBuffer succeeded, bufferId=%u@%d bufhandle=%p",
            codecBufferId, res.second, ahwb);
    return C2_OK;
}

void InputSurfaceSource::submitEndOfInputStream_l() {
    CHECK(mEndOfStream);
    if (mEndOfStreamSent) {
        ALOGV("EOS already sent");
        return;
    }

    if (mFreeCodecBuffers.empty()) {
        ALOGV("submitEndOfInputStream_l: no codec buffers available");
        return;
    }
    uint32_t codecBufferId = *mFreeCodecBuffers.begin();

    // We reject any additional incoming graphic buffers. There is no acquired buffer used for EOS
    c2_status_t err = mComponent->submitEos(codecBufferId);
    if (err != C2_OK) {
        ALOGW("emptyDirectBuffer EOS failed: 0x%x", err);
    } else {
        mFreeCodecBuffers.erase(mFreeCodecBuffers.begin());
        auto res = mSubmittedCodecBuffers.emplace(codecBufferId, nullptr);
        if (!res.second) {
            auto it = res.first;
            it->second = nullptr;
        }
        ALOGV("submitEndOfInputStream_l: buffer submitted, bufferId=%u@%d",
                codecBufferId, res.second);
        mEndOfStreamSent = true;

        // no need to hold onto any buffers for frame repeating
        ++mRepeatLastFrameGeneration;
        mLatestBuffer.mBuffer.reset();
    }
}

c2_status_t InputSurfaceSource::acquireBuffer_l(VideoBuffer *ab) {
    //BufferItem bi;
    int fenceFd = -1;
    AImage *image = nullptr;

    media_status_t err = AImageReader_acquireNextImageAsync(mImageReader, &image, &fenceFd);
    if (err == AMEDIA_IMGREADER_NO_BUFFER_AVAILABLE) {
        // shouldn't happen
        ALOGW("acquireBuffer_l: frame was not available");
        return C2_NOT_FOUND;
    } else if (err == AMEDIA_IMGREADER_MAX_IMAGES_ACQUIRED) {
        ALOGW("acquireBuffer_l: already acquired max frames");
        return C2_BLOCKING;
    } else if (err != AMEDIA_OK) {
        ALOGW("acquireBuffer_l: failed with err=%d", err);
        return C2_CORRUPTED;
    }
    CHECK(image != nullptr);

    --mNumAvailableUnacquiredBuffers;

    AHardwareBuffer *ahwbBuffer = nullptr;
    ahwb_id bid = 0;
    (void)AImage_getHardwareBuffer(image, &ahwbBuffer);
    CHECK(ahwbBuffer != nullptr);
    if (__builtin_available(android __ANDROID_API_T__, *)) {
        (void)AHardwareBuffer_getId(ahwbBuffer, &bid);
    } else {
        LOG_ALWAYS_FATAL(
                "AHardwareBuffer_getId must be available for this implementation to work");
    }

    sp<Fence> acqFence(new Fence(fenceFd));


    // Manage our buffer cache.
    std::shared_ptr<CachedBuffer> buffer;

    auto it = mBufferIds.find(bid);

    // replace/initialize the bufferId cache with a new buffer
    ALOGV("acquireBuffer_l: %s buffer id %llu",
            it == mBufferIds.end() ? "setting" : "UPDATING",
            (unsigned long long)bid);
    if (it != mBufferIds.end()) {
        discardBufferAtIter_l(it);
    } else {
        auto res = mBufferIds.emplace(bid, nullptr);
        it = res.first;
    }
    buffer = std::make_shared<CachedBuffer>(bid, image);
    it->second = buffer;

    int64_t imageTimestamp = -1;
    int32_t imageDataspace = 0;
    (void)AImage_getTimestamp(image, &imageTimestamp);
    if (__builtin_available(android __ANDROID_API_U__, *)) {
        (void)AImage_getDataSpace(image, &imageDataspace);
    } else {
        LOG_ALWAYS_FATAL(
                "AHardwareBuffer_getId must be available for this implementation to work");
    }

    std::shared_ptr<AcquiredBuffer> acquiredBuffer =
        std::make_shared<AcquiredBuffer>(
                buffer,
                [this](AcquiredBuffer *buffer){
                    // AcquiredBuffer's destructor should always be called when mMutex is locked.
                    // If we had a reentrant mutex, we could just lock it again to ensure this.
                    if (mMutex.try_lock()) {
                        TRESPASS_DBG();
                        mMutex.unlock();
                    }

                    // we can release buffers immediately if not using adapters
                    // alternately, we could add them to mSlotsToRelease, but we would
                    // somehow need to propagate frame number to that queue
                    if (buffer->isCached()) {
                        --mNumOutstandingAcquires;
                        AImage_deleteAsync(buffer->getImage(), buffer->getReleaseFence()->dup());
                    }
                },
                acqFence);
    VideoBuffer videoBuffer{
        acquiredBuffer, imageTimestamp,
        static_cast<android_dataspace_t>(imageDataspace)};
    *ab = videoBuffer;
    ++mNumOutstandingAcquires;
    return C2_OK;
}

// AImageReader callback calls this interface
void InputSurfaceSource::onFrameAvailable() {
    std::lock_guard<std::mutex> autoLock(mMutex);

    ALOGV("onFrameAvailable: executing=%d available=%zu+%d",
            mExecuting, mAvailableBuffers.size(), mNumAvailableUnacquiredBuffers);
    ++mNumAvailableUnacquiredBuffers;

    // For BufferQueue we cannot acquire a buffer if we cannot immediately feed it to the codec
    // UNLESS we are discarding this buffer (acquiring and immediately releasing it), which makes
    // this an ugly logic.
    // NOTE: We could also rely on our debug counter but that is meant only as a debug counter.
    if (!areWeDiscardingAvailableBuffers_l() && mFreeCodecBuffers.empty()) {
        // we may not be allowed to acquire a possibly encodable buffer, so just note that
        // it is available
        ALOGV("onFrameAvailable: cannot acquire buffer right now, do it later");

        ++mRepeatLastFrameGeneration; // cancel any pending frame repeat
        return;
    }

    VideoBuffer buffer;
    c2_status_t err = acquireBuffer_l(&buffer);
    if (err != C2_OK) {
        ALOGE("onFrameAvailable: acquireBuffer returned err=%d", err);
    } else {
        onBufferAcquired_l(buffer);
    }
}

bool InputSurfaceSource::areWeDiscardingAvailableBuffers_l() {
    return mEndOfStreamSent // already sent EOS to codec
            || mComponent == nullptr // there is no codec connected
            || (mSuspended && mActionQueue.empty()) // we are suspended and not waiting for
                                                    // any further action
            || !mExecuting;
}

void InputSurfaceSource::onBufferAcquired_l(const VideoBuffer &buffer) {
    if (mEndOfStreamSent) {
        // This should only be possible if a new buffer was queued after
        // EOS was signaled, i.e. the app is misbehaving.
        ALOGW("onFrameAvailable: EOS is sent, ignoring frame");
    } else if (mComponent == NULL || (mSuspended && mActionQueue.empty())) {
        // FIXME: if we are suspended but have a resume queued we will stop repeating the last
        // frame. Is that the desired behavior?
        ALOGV("onFrameAvailable: suspended, ignoring frame");
    } else {
        ++mRepeatLastFrameGeneration; // cancel any pending frame repeat
        mAvailableBuffers.push_back(buffer);
        if (mExecuting) {
            fillCodecBuffer_l();
        }
    }
}

// AImageReader callback calls this interface
void InputSurfaceSource::onBufferReleased(InputSurfaceSource::ahwb_id id) {
    std::lock_guard<std::mutex> lock(mMutex);

    if (!discardBufferInId_l(id)) {
        ALOGW("released buffer not cached %llu", (unsigned long long)id);
    }
}

bool InputSurfaceSource::discardBufferInId_l(InputSurfaceSource::ahwb_id id) {
    auto it = mBufferIds.find(id);
    if (it != mBufferIds.end()) {
        return false;
    } else {
        discardBufferAtIter_l(it);
        mBufferIds.erase(it);
        return true;
    }
}

void InputSurfaceSource::discardBufferAtIter_l(BufferIdMap::iterator &it) {
    const std::shared_ptr<CachedBuffer>& buffer = it->second;
    // use -1 if there is no latest buffer, and 0 if it is no longer cached
    ahwb_id latestBufferId =
        mLatestBuffer.mBuffer == nullptr ? -1 : mLatestBuffer.mBuffer->getId();
    ALOGV("releasing acquired buffer: [id=%llu, useCount=%ld], latest: [id=%llu]",
            (unsigned long long)buffer->getId(), buffer.use_count(),
            (unsigned long long)latestBufferId);
    buffer->onDroppedFromCache();

    // If the slot of an acquired buffer is discarded, that buffer will not have to be
    // released to the producer, so account it here. However, it is possible that the
    // acquired buffer has already been discarded so check if it still is.
    if (buffer->isAcquired()) {
        --mNumOutstandingAcquires;
    }

    // clear the buffer reference (not technically needed as caller either replaces or deletes
    // it; done here for safety).
    it->second.reset();
    CHECK_DBG(buffer == nullptr);
}

void InputSurfaceSource::releaseAllAvailableBuffers_l() {
    mAvailableBuffers.clear();
    while (mNumAvailableUnacquiredBuffers > 0) {
        VideoBuffer item;
        if (acquireBuffer_l(&item) != C2_OK) {
            ALOGW("releaseAllAvailableBuffers: failed to acquire available unacquired buffer");
            break;
        }
    }
}

c2_status_t InputSurfaceSource::configure(
        const std::shared_ptr<InputSurfaceConnection>& component,
        int32_t dataSpace,
        int32_t bufferCount,
        uint32_t frameWidth,
        uint32_t frameHeight,
        uint64_t consumerUsage) {
    c2_status_t initCheck = C2_OK;
    {
        std::lock_guard<std::mutex> autoLock(mMutex);
        initImageReaderLocked();
        initCheck = mInitCheck;
    }
    if (initCheck != C2_OK) {
        ALOGE("configure() was called buf ImageReader was not created properly");
        return C2_CORRUPTED;
    }
    if (component == NULL) {
        return C2_BAD_VALUE;
    }
    if (__builtin_available(android 37, *)) {
        media_status_t err = AImageReader_setMaxImages(mImageReader, bufferCount);
        if (err != AMEDIA_OK) {
            ALOGE("media_err(%d): AImageReader_setMaxImagees() to %d maxImages",
                    err, bufferCount);
            return C2_CORRUPTED;
        }
    } else {
        ALOGE("AImageReader_setMaxImages() not available.");
        return C2_OMITTED;
    }

    {
        std::lock_guard<std::mutex> autoLock(mMutex);
        mComponent = component;
        if (__builtin_available(android 37, *)) {
            media_status_t err = AMEDIA_OK;
            err = AImageReader_setDefaultBufferSize(mImageReader, frameWidth, frameHeight);
            if (err != AMEDIA_OK) {
                ALOGE("media_err(%d): AImageReader_setDefaultBufferSize() to (%d, %d)",
                        err, frameWidth, frameHeight);
                return C2_CORRUPTED;
            }
            consumerUsage |= AHARDWAREBUFFER_USAGE_VIDEO_ENCODE;
            AImageReader_setUsage(mImageReader, consumerUsage);

            // Set impl. defined format as default. Depending on the usage flags
            // the device-specific implementation will derive the exact format.
            err = AImageReader_setDefaultAHardwareBufferFormat(
                    mImageReader, HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED);
            if (err != AMEDIA_OK) {
                ALOGE("media_err(%d): failed to set default buffer format to opaque", err);
                return C2_CORRUPTED;
            }

            // Sets the default buffer data space
            ALOGD("setting dataspace: %#x, acquired=%d", dataSpace, mNumOutstandingAcquires);
            AImageReader_setDefaultBufferDataSpace(
                    mImageReader, (android_dataspace)dataSpace);
            mLastDataspace = (android_dataspace)dataSpace;
        } else{
            ALOGE("AImageReader configuration APIs are not available.");
            return C2_OMITTED;
        }

        mExecuting = false;
        mSuspended = false;
        mEndOfStream = false;
        mEndOfStreamSent = false;
        mSkipFramesBeforeNs = -1LL;
        mFrameDropper.reset();
        mFrameRepeatIntervalUs = -1LL;
        mRepeatLastFrameGeneration = 0;
        mOutstandingFrameRepeatCount = 0;
        mLatestBuffer.mBuffer.reset();
        mFrameRepeatBlockedOnCodecBuffer = false;
        mFps = -1.0;
        mCaptureFps = -1.0;
        mBaseCaptureUs = -1LL;
        mBaseFrameUs = -1LL;
        mPrevCaptureUs = -1LL;
        mPrevFrameUs = -1LL;
        mFrameCount = 0;
        mInputBufferTimeOffsetUs = 0;
        mStopTimeUs = -1;
        mActionQueue.clear();
    }

    return C2_OK;
}

c2_status_t InputSurfaceSource::setSuspend(bool suspend, int64_t suspendStartTimeUs) {
    ALOGV("setSuspend=%d at time %lld us", suspend, (long long)suspendStartTimeUs);

    std::lock_guard<std::mutex> autoLock(mMutex);

    if (mStopTimeUs != -1) {
        ALOGE("setSuspend failed as STOP action is pending");
        return C2_CANNOT_DO;
    }

    // Push the action to the queue.
    if (suspendStartTimeUs != -1) {
        // suspendStartTimeUs must be smaller or equal to current systemTime.
        int64_t currentSystemTimeUs = systemTime() / 1000;
        if (suspendStartTimeUs > currentSystemTimeUs) {
            ALOGE("setSuspend failed. %lld is larger than current system time %lld us",
                    (long long)suspendStartTimeUs, (long long)currentSystemTimeUs);
            return C2_BAD_VALUE;
        }
        if (mLastActionTimeUs != -1 && suspendStartTimeUs < mLastActionTimeUs) {
            ALOGE("setSuspend failed. %lld is smaller than last action time %lld us",
                    (long long)suspendStartTimeUs, (long long)mLastActionTimeUs);
            return C2_BAD_VALUE;
        }
        mLastActionTimeUs = suspendStartTimeUs;
        ActionItem action;
        action.mAction = suspend ? ActionItem::PAUSE : ActionItem::RESUME;
        action.mActionTimeUs = suspendStartTimeUs;
        ALOGV("Push %s action into actionQueue", suspend ? "PAUSE" : "RESUME");
        mActionQueue.push_back(action);
    } else {
        if (suspend) {
            mSuspended = true;
            releaseAllAvailableBuffers_l();
            return C2_OK;
        } else {
            mSuspended = false;
            if (mExecuting && !haveAvailableBuffers_l()
                    && mFrameRepeatBlockedOnCodecBuffer) {
                if (repeatLatestBuffer_l()) {
                    ALOGV("suspend/deferred repeatLatestBuffer_l SUCCESS");
                    mFrameRepeatBlockedOnCodecBuffer = false;
                } else {
                    ALOGV("suspend/deferred repeatLatestBuffer_l FAILURE");
                }
            }
        }
    }
    return C2_OK;
}

c2_status_t InputSurfaceSource::setRepeatPreviousFrameDelayUs(int64_t repeatAfterUs) {
    ALOGV("setRepeatPreviousFrameDelayUs: delayUs=%lld", (long long)repeatAfterUs);

    std::lock_guard<std::mutex> autoLock(mMutex);

    if (mExecuting) {
        return C2_BAD_STATE;
    }
    if (repeatAfterUs <= 0LL) {
        return C2_BAD_VALUE;
    }

    mFrameRepeatIntervalUs = repeatAfterUs;
    return C2_OK;
}

c2_status_t InputSurfaceSource::setTimeOffsetUs(int64_t timeOffsetUs) {
    std::lock_guard<std::mutex> autoLock(mMutex);

    // timeOffsetUs must be negative for adjustment.
    if (timeOffsetUs >= 0LL) {
        return C2_BAD_VALUE;
    }

    mInputBufferTimeOffsetUs = timeOffsetUs;
    return C2_OK;
}

c2_status_t InputSurfaceSource::setMaxFps(float maxFps) {
    ALOGV("setMaxFps: maxFps=%lld", (long long)maxFps);

    std::lock_guard<std::mutex> autoLock(mMutex);

    if (mExecuting) {
        return C2_BAD_STATE;
    }

    mFrameDropper = std::make_shared<FrameDropper>();
    mFrameDropper->setMaxFrameRate(maxFps);

    return C2_OK;
}

c2_status_t InputSurfaceSource::setStartTimeUs(int64_t skipFramesBeforeUs) {
    ALOGV("setStartTimeUs: skipFramesBeforeUs=%lld", (long long)skipFramesBeforeUs);

    std::lock_guard<std::mutex> autoLock(mMutex);

    mSkipFramesBeforeNs =
            (skipFramesBeforeUs > 0 && skipFramesBeforeUs <= INT64_MAX / 1000) ?
            (skipFramesBeforeUs * 1000) : -1LL;

    return C2_OK;
}

c2_status_t InputSurfaceSource::setStopTimeUs(int64_t stopTimeUs) {
    ALOGV("setStopTimeUs: %lld us", (long long)stopTimeUs);
    std::lock_guard<std::mutex> autoLock(mMutex);

    if (mStopTimeUs != -1) {
        // Ignore if stop time has already been set
        return C2_OK;
    }

    // stopTimeUs must be smaller or equal to current systemTime.
    int64_t currentSystemTimeUs = systemTime() / 1000;
    if (stopTimeUs > currentSystemTimeUs) {
        ALOGE("setStopTimeUs failed. %lld is larger than current system time %lld us",
            (long long)stopTimeUs, (long long)currentSystemTimeUs);
        return C2_BAD_VALUE;
    }
    if (mLastActionTimeUs != -1 && stopTimeUs < mLastActionTimeUs) {
        ALOGE("setSuspend failed. %lld is smaller than last action time %lld us",
            (long long)stopTimeUs, (long long)mLastActionTimeUs);
        return C2_BAD_VALUE;
    }
    mLastActionTimeUs = stopTimeUs;
    ActionItem action;
    action.mAction = ActionItem::STOP;
    action.mActionTimeUs = stopTimeUs;
    mActionQueue.push_back(action);
    mStopTimeUs = stopTimeUs;
    return C2_OK;
}

c2_status_t InputSurfaceSource::getStopTimeOffsetUs(int64_t *stopTimeOffsetUs) {
    ALOGV("getStopTimeOffsetUs");
    std::lock_guard<std::mutex> autoLock(mMutex);
    if (mStopTimeUs == -1) {
        ALOGW("Fail to return stopTimeOffsetUs as stop time is not set");
        return C2_CANNOT_DO;
    }
    *stopTimeOffsetUs =
        mLastFrameTimestampUs == -1 ? 0 : mStopTimeUs - mLastFrameTimestampUs;
    return C2_OK;
}

c2_status_t InputSurfaceSource::setTimeLapseConfig(double fps, double captureFps) {
    ALOGV("setTimeLapseConfig: fps=%lg, captureFps=%lg",
            fps, captureFps);
    std::lock_guard<std::mutex> autoLock(mMutex);

    if (mExecuting) {
        return C2_BAD_STATE;
    }
    if (!(fps > 0) || !(captureFps > 0)) {
        return C2_BAD_VALUE;
    }

    mFps = fps;
    mCaptureFps = captureFps;
    if (captureFps > fps) {
        mSnapTimestamps = 1 == ::android::base::GetIntProperty(
                "debug.stagefright.snap_timestamps", int64_t(0));
    } else {
        mSnapTimestamps = false;
    }

    return C2_OK;
}

c2_status_t InputSurfaceSource::setColorAspects(int32_t aspectsPacked) {
    std::lock_guard<std::mutex> autoLock(mMutex);
    mDefaultColorAspectsPacked = aspectsPacked;
    ColorAspects colorAspects = ColorUtils::unpackToColorAspects(aspectsPacked);
    ALOGD("requesting color aspects (R:%d(%s), P:%d(%s), M:%d(%s), T:%d(%s))",
            colorAspects.mRange, asString(colorAspects.mRange),
            colorAspects.mPrimaries, asString(colorAspects.mPrimaries),
            colorAspects.mMatrixCoeffs, asString(colorAspects.mMatrixCoeffs),
            colorAspects.mTransfer, asString(colorAspects.mTransfer));

    return C2_OK;
}

c2_status_t InputSurfaceSource::signalEndOfInputStream() {
    std::lock_guard<std::mutex> autoLock(mMutex);
    ALOGV("signalEndOfInputStream: executing=%d available=%zu+%d eos=%d",
            mExecuting, mAvailableBuffers.size(), mNumAvailableUnacquiredBuffers, mEndOfStream);

    if (mEndOfStream) {
        ALOGE("EOS was already signaled");
        return C2_DUPLICATE;
    }

    // Set the end-of-stream flag.  If no frames are pending from the
    // BufferQueue, and a codec buffer is available, and we're executing,
    // and there is no stop timestamp, we initiate the EOS from here.
    // Otherwise, we'll let codecBufferEmptied() (or start) do it.
    //
    // Note: if there are no pending frames and all codec buffers are
    // available, we *must* submit the EOS from here or we'll just
    // stall since no future events are expected.
    mEndOfStream = true;

    if (mStopTimeUs == -1 && mExecuting && !haveAvailableBuffers_l()) {
        submitEndOfInputStream_l();
    }

    return C2_OK;
}

void InputSurfaceSource::onMessageReceived(const sp<AMessage> &msg) {
    switch (msg->what()) {
        case kWhatRepeatLastFrame:
        {
            std::lock_guard<std::mutex> autoLock(mMutex);

            int32_t generation;
            CHECK(msg->findInt32("generation", &generation));

            if (generation != mRepeatLastFrameGeneration) {
                // stale
                break;
            }

            if (!mExecuting || haveAvailableBuffers_l()) {
                break;
            }

            bool success = repeatLatestBuffer_l();
            if (success) {
                ALOGV("repeatLatestBuffer_l SUCCESS");
            } else {
                ALOGV("repeatLatestBuffer_l FAILURE");
                mFrameRepeatBlockedOnCodecBuffer = true;
            }
            break;
        }

        default:
            TRESPASS();
    }
}

}  // namespace aidl::android::hardware::media::c2::implementation
