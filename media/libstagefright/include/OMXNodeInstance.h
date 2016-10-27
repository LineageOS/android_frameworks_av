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

#ifndef OMX_NODE_INSTANCE_H_

#define OMX_NODE_INSTANCE_H_

#include "OMX.h"

#include <utils/RefBase.h>
#include <utils/SortedVector.h>
#include <utils/threads.h>

namespace android {
class IOMXBufferSource;
class IOMXObserver;
struct OMXMaster;
class OMXBuffer;

struct OMXNodeInstance : public BnOMXNode {
    OMXNodeInstance(
            OMX *owner, const sp<IOMXObserver> &observer, const char *name);

    void setHandle(OMX_HANDLETYPE handle);

    OMX_HANDLETYPE handle();
    sp<IOMXObserver> observer();

    status_t freeNode() override;

    status_t sendCommand(OMX_COMMANDTYPE cmd, OMX_S32 param);
    status_t getParameter(OMX_INDEXTYPE index, void *params, size_t size);

    status_t setParameter(
            OMX_INDEXTYPE index, const void *params, size_t size);

    status_t getConfig(OMX_INDEXTYPE index, void *params, size_t size);
    status_t setConfig(OMX_INDEXTYPE index, const void *params, size_t size);

    status_t enableNativeBuffers(OMX_U32 portIndex, OMX_BOOL graphic, OMX_BOOL enable);

    status_t getGraphicBufferUsage(OMX_U32 portIndex, OMX_U32* usage);

    status_t storeMetaDataInBuffers(
            OMX_U32 portIndex, OMX_BOOL enable, MetadataBufferType *type);

    status_t prepareForAdaptivePlayback(
            OMX_U32 portIndex, OMX_BOOL enable,
            OMX_U32 maxFrameWidth, OMX_U32 maxFrameHeight);

    status_t configureVideoTunnelMode(
            OMX_U32 portIndex, OMX_BOOL tunneled,
            OMX_U32 audioHwSync, native_handle_t **sidebandHandle);

    status_t setInputSurface(
            const sp<IOMXBufferSource> &bufferSource);

    status_t allocateSecureBuffer(
            OMX_U32 portIndex, size_t size, OMX::buffer_id *buffer,
            void **buffer_data, sp<NativeHandle> *native_handle);

    status_t useBuffer(
            OMX_U32 portIndex, const OMXBuffer &omxBuf, buffer_id *buffer);

    status_t freeBuffer(
            OMX_U32 portIndex, buffer_id buffer);

    status_t fillBuffer(
            buffer_id buffer, const OMXBuffer &omxBuf, int fenceFd = -1);

    status_t emptyBuffer(
            buffer_id buffer, const OMXBuffer &omxBuf,
            OMX_U32 flags, OMX_TICKS timestamp, int fenceFd = -1);

    status_t getExtensionIndex(
            const char *parameterName, OMX_INDEXTYPE *index);

    status_t setQuirks(OMX_U32 quirks);

    bool isSecure() const {
        return mIsSecure;
    }

    status_t dispatchMessage(const omx_message &msg) override;

    // handles messages and removes them from the list
    void onMessages(std::list<omx_message> &messages);
    void onObserverDied();
    void onEvent(OMX_EVENTTYPE event, OMX_U32 arg1, OMX_U32 arg2);

    static OMX_CALLBACKTYPE kCallbacks;

private:
    struct CallbackDispatcherThread;
    struct CallbackDispatcher;

    Mutex mLock;

    OMX *mOwner;
    OMX_HANDLETYPE mHandle;
    sp<IOMXObserver> mObserver;
    sp<CallbackDispatcher> mDispatcher;
    bool mDying;
    bool mSailed;  // configuration is set (no more meta-mode changes)
    bool mQueriedProhibitedExtensions;
    SortedVector<OMX_INDEXTYPE> mProhibitedExtensions;
    bool mIsSecure;
    uint32_t mQuirks;

    // Lock only covers mOMXBufferSource and mOMXOutputListener.  We can't always
    // use mLock because of rare instances where we'd end up locking it recursively.
    Mutex mOMXBufferSourceLock;
    // Access these through getBufferSource().
    sp<IOMXBufferSource> mOMXBufferSource;

    struct ActiveBuffer {
        OMX_U32 mPortIndex;
        OMX::buffer_id mID;
    };
    Vector<ActiveBuffer> mActiveBuffers;
    // for buffer ptr to buffer id translation
    Mutex mBufferIDLock;
    uint32_t mBufferIDCount;
    KeyedVector<OMX::buffer_id, OMX_BUFFERHEADERTYPE *> mBufferIDToBufferHeader;
    KeyedVector<OMX_BUFFERHEADERTYPE *, OMX::buffer_id> mBufferHeaderToBufferID;

    // metadata and secure buffer type tracking
    MetadataBufferType mMetadataType[2];
    enum SecureBufferType {
        kSecureBufferTypeUnknown,
        kSecureBufferTypeOpaque,
        kSecureBufferTypeNativeHandle,
    };
    SecureBufferType mSecureBufferType[2];

    // Following are OMX parameters managed by us (instead of the component)
    // OMX_IndexParamMaxFrameDurationForBitrateControl
    KeyedVector<int64_t, int64_t> mOriginalTimeUs;
    bool mRestorePtsFailed;
    int64_t mMaxTimestampGapUs;
    int64_t mPrevOriginalTimeUs;
    int64_t mPrevModifiedTimeUs;

    // For debug support
    char *mName;
    int DEBUG;
    size_t mNumPortBuffers[2];  // modified under mLock, read outside for debug
    Mutex mDebugLock;
    // following are modified and read under mDebugLock
    int DEBUG_BUMP;
    SortedVector<OMX_BUFFERHEADERTYPE *> mInputBuffersWithCodec, mOutputBuffersWithCodec;
    size_t mDebugLevelBumpPendingBuffers[2];
    void bumpDebugLevel_l(size_t numInputBuffers, size_t numOutputBuffers);
    void unbumpDebugLevel_l(size_t portIndex);

    ~OMXNodeInstance();

    void addActiveBuffer(OMX_U32 portIndex, OMX::buffer_id id);
    void removeActiveBuffer(OMX_U32 portIndex, OMX::buffer_id id);
    void freeActiveBuffers();

    // For buffer id management
    OMX::buffer_id makeBufferID(OMX_BUFFERHEADERTYPE *bufferHeader);
    OMX_BUFFERHEADERTYPE *findBufferHeader(OMX::buffer_id buffer, OMX_U32 portIndex);
    OMX::buffer_id findBufferID(OMX_BUFFERHEADERTYPE *bufferHeader);
    void invalidateBufferID(OMX::buffer_id buffer);

    bool isProhibitedIndex_l(OMX_INDEXTYPE index);

    status_t useBuffer(
            OMX_U32 portIndex, const sp<IMemory> &params,
            OMX::buffer_id *buffer, OMX_U32 allottedSize);

    status_t useBuffer_l(
            OMX_U32 portIndex, const sp<IMemory> &params,
            OMX::buffer_id *buffer, OMX_U32 allottedSize);

    status_t useGraphicBuffer(
            OMX_U32 portIndex, const sp<GraphicBuffer> &graphicBuffer,
            OMX::buffer_id *buffer);

    status_t useGraphicBufferWithMetadata_l(
            OMX_U32 portIndex, const sp<GraphicBuffer> &graphicBuffer,
            OMX::buffer_id *buffer);

    status_t useGraphicBuffer2_l(
            OMX_U32 portIndex, const sp<GraphicBuffer> &graphicBuffer,
            OMX::buffer_id *buffer);

    status_t emptyBuffer(
            OMX::buffer_id buffer,
            OMX_U32 rangeOffset, OMX_U32 rangeLength,
            OMX_U32 flags, OMX_TICKS timestamp, int fenceFd);

    status_t emptyGraphicBuffer(
            OMX::buffer_id buffer, const sp<GraphicBuffer> &graphicBuffer,
            OMX_U32 flags, OMX_TICKS timestamp, int fenceFd);

    status_t emptyNativeHandleBuffer(
            OMX::buffer_id buffer, const sp<NativeHandle> &nativeHandle,
            OMX_U32 flags, OMX_TICKS timestamp, int fenceFd);

    status_t emptyBuffer_l(
            OMX_BUFFERHEADERTYPE *header,
            OMX_U32 flags, OMX_TICKS timestamp, intptr_t debugAddr, int fenceFd);

    static OMX_ERRORTYPE OnEvent(
            OMX_IN OMX_HANDLETYPE hComponent,
            OMX_IN OMX_PTR pAppData,
            OMX_IN OMX_EVENTTYPE eEvent,
            OMX_IN OMX_U32 nData1,
            OMX_IN OMX_U32 nData2,
            OMX_IN OMX_PTR pEventData);

    static OMX_ERRORTYPE OnEmptyBufferDone(
            OMX_IN OMX_HANDLETYPE hComponent,
            OMX_IN OMX_PTR pAppData,
            OMX_IN OMX_BUFFERHEADERTYPE *pBuffer);

    static OMX_ERRORTYPE OnFillBufferDone(
            OMX_IN OMX_HANDLETYPE hComponent,
            OMX_IN OMX_PTR pAppData,
            OMX_IN OMX_BUFFERHEADERTYPE *pBuffer);

    status_t storeMetaDataInBuffers_l(
            OMX_U32 portIndex, OMX_BOOL enable, MetadataBufferType *type);

    // Stores fence into buffer if it is ANWBuffer type and has enough space.
    // otherwise, waits for the fence to signal.  Takes ownership of |fenceFd|.
    status_t storeFenceInMeta_l(
            OMX_BUFFERHEADERTYPE *header, int fenceFd, OMX_U32 portIndex);

    // Retrieves the fence from buffer if ANWBuffer type and has enough space. Otherwise, returns -1
    int retrieveFenceFromMeta_l(
            OMX_BUFFERHEADERTYPE *header, OMX_U32 portIndex);

    // Updates the graphic buffer handle in the metadata buffer for |buffer| and |header| to
    // |graphicBuffer|'s handle. If |updateCodecBuffer| is true, the update will happen in
    // the actual codec buffer (use this if not using emptyBuffer (with no _l) later to
    // pass the buffer to the codec, as only emptyBuffer copies the backup buffer to the codec
    // buffer.)
    status_t updateGraphicBufferInMeta_l(
            OMX_U32 portIndex, const sp<GraphicBuffer> &graphicBuffer,
            OMX::buffer_id buffer, OMX_BUFFERHEADERTYPE *header);

    status_t updateNativeHandleInMeta_l(
            OMX_U32 portIndex, const sp<NativeHandle> &nativeHandle,
            OMX::buffer_id buffer, OMX_BUFFERHEADERTYPE *header);

    sp<IOMXBufferSource> getBufferSource();
    void setBufferSource(const sp<IOMXBufferSource> &bufferSource);
    // Called when omx_message::FILL_BUFFER_DONE is received. (Currently the
    // buffer source will fix timestamp in the header if needed.)
    void codecBufferFilled(omx_message &msg);

    // Handles |msg|, and may modify it. Returns true iff completely handled it and
    // |msg| does not need to be sent to the event listener.
    bool handleMessage(omx_message &msg);

    bool handleDataSpaceChanged(omx_message &msg);

    status_t setMaxPtsGapUs(const void *params, size_t size);
    int64_t getCodecTimestamp(OMX_TICKS timestamp);

    OMXNodeInstance(const OMXNodeInstance &);
    OMXNodeInstance &operator=(const OMXNodeInstance &);
};

}  // namespace android

#endif  // OMX_NODE_INSTANCE_H_
