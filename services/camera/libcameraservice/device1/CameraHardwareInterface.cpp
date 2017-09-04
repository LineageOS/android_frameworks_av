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
#define LOG_TAG "CameraHardwareInterface"
//#define LOG_NDEBUG 0

#include <inttypes.h>
#include <media/hardware/HardwareAPI.h> // For VideoNativeHandleMetadata
#include "CameraHardwareInterface.h"

namespace android {

using namespace hardware::camera::device::V1_0;
using namespace hardware::camera::common::V1_0;
using hardware::hidl_handle;

CameraHardwareInterface::~CameraHardwareInterface()
{
    ALOGI("Destroying camera %s", mName.string());
    if (mDevice) {
        int rc = mDevice->common.close(&mDevice->common);
        if (rc != OK)
            ALOGE("Could not close camera %s: %d", mName.string(), rc);
    }
    if (mHidlDevice != nullptr) {
        mHidlDevice->close();
        mHidlDevice.clear();
        cleanupCirculatingBuffers();
    }
}

status_t CameraHardwareInterface::initialize(CameraModule *module)
{
    if (mHidlDevice != nullptr) {
        ALOGE("%s: camera hardware interface has been initialized to HIDL path!", __FUNCTION__);
        return INVALID_OPERATION;
    }
    ALOGI("Opening camera %s", mName.string());
    camera_info info;
    status_t res = module->getCameraInfo(atoi(mName.string()), &info);
    if (res != OK) {
        return res;
    }

    int rc = OK;
    if (module->getModuleApiVersion() >= CAMERA_MODULE_API_VERSION_2_3 &&
        info.device_version > CAMERA_DEVICE_API_VERSION_1_0) {
        // Open higher version camera device as HAL1.0 device.
        rc = module->openLegacy(mName.string(),
                                 CAMERA_DEVICE_API_VERSION_1_0,
                                 (hw_device_t **)&mDevice);
    } else {
        rc = module->open(mName.string(), (hw_device_t **)&mDevice);
    }
    if (rc != OK) {
        ALOGE("Could not open camera %s: %d", mName.string(), rc);
        return rc;
    }
    initHalPreviewWindow();
    return rc;
}

status_t CameraHardwareInterface::initialize(sp<CameraProviderManager> manager) {
    if (mDevice) {
        ALOGE("%s: camera hardware interface has been initialized to libhardware path!",
                __FUNCTION__);
        return INVALID_OPERATION;
    }

    ALOGI("Opening camera %s", mName.string());

    status_t ret = manager->openSession(mName.string(), this, &mHidlDevice);
    if (ret != OK) {
        ALOGE("%s: openSession failed! %s (%d)", __FUNCTION__, strerror(-ret), ret);
    }
    return ret;
}

status_t CameraHardwareInterface::setPreviewScalingMode(int scalingMode)
{
    int rc = OK;
    mPreviewScalingMode = scalingMode;
    if (mPreviewWindow != nullptr) {
        rc = native_window_set_scaling_mode(mPreviewWindow.get(),
                scalingMode);
    }
    return rc;
}

status_t CameraHardwareInterface::setPreviewTransform(int transform) {
    int rc = OK;
    mPreviewTransform = transform;
    if (mPreviewWindow != nullptr) {
        rc = native_window_set_buffers_transform(mPreviewWindow.get(),
                mPreviewTransform);
    }
    return rc;
}

/**
 * Implementation of android::hardware::camera::device::V1_0::ICameraDeviceCallback
 */
hardware::Return<void> CameraHardwareInterface::notifyCallback(
        NotifyCallbackMsg msgType, int32_t ext1, int32_t ext2) {
    sNotifyCb((int32_t) msgType, ext1, ext2, (void*) this);
    return hardware::Void();
}

hardware::Return<uint32_t> CameraHardwareInterface::registerMemory(
        const hardware::hidl_handle& descriptor,
        uint32_t bufferSize, uint32_t bufferCount) {
    if (descriptor->numFds != 1) {
        ALOGE("%s: camera memory descriptor has numFds %d (expect 1)",
                __FUNCTION__, descriptor->numFds);
        return 0;
    }
    if (descriptor->data[0] < 0) {
        ALOGE("%s: camera memory descriptor has FD %d (expect >= 0)",
                __FUNCTION__, descriptor->data[0]);
        return 0;
    }

    camera_memory_t* mem = sGetMemory(descriptor->data[0], bufferSize, bufferCount, this);
    sp<CameraHeapMemory> camMem(static_cast<CameraHeapMemory *>(mem->handle));
    int memPoolId = camMem->mHeap->getHeapID();
    if (memPoolId < 0) {
        ALOGE("%s: CameraHeapMemory has FD %d (expect >= 0)", __FUNCTION__, memPoolId);
        return 0;
    }
    mHidlMemPoolMap.insert(std::make_pair(memPoolId, mem));
    return memPoolId;
}

hardware::Return<void> CameraHardwareInterface::unregisterMemory(uint32_t memId) {
    if (mHidlMemPoolMap.count(memId) == 0) {
        ALOGE("%s: memory pool ID %d not found", __FUNCTION__, memId);
        return hardware::Void();
    }
    camera_memory_t* mem = mHidlMemPoolMap.at(memId);
    sPutMemory(mem);
    mHidlMemPoolMap.erase(memId);
    return hardware::Void();
}

hardware::Return<void> CameraHardwareInterface::dataCallback(
        DataCallbackMsg msgType, uint32_t data, uint32_t bufferIndex,
        const hardware::camera::device::V1_0::CameraFrameMetadata& metadata) {
    if (mHidlMemPoolMap.count(data) == 0) {
        ALOGE("%s: memory pool ID %d not found", __FUNCTION__, data);
        return hardware::Void();
    }
    camera_frame_metadata_t md;
    md.number_of_faces = metadata.faces.size();
    md.faces = (camera_face_t*) metadata.faces.data();
    sDataCb((int32_t) msgType, mHidlMemPoolMap.at(data), bufferIndex, &md, this);
    return hardware::Void();
}

hardware::Return<void> CameraHardwareInterface::dataCallbackTimestamp(
        DataCallbackMsg msgType, uint32_t data,
        uint32_t bufferIndex, int64_t timestamp) {
    if (mHidlMemPoolMap.count(data) == 0) {
        ALOGE("%s: memory pool ID %d not found", __FUNCTION__, data);
        return hardware::Void();
    }
    sDataCbTimestamp(timestamp, (int32_t) msgType, mHidlMemPoolMap.at(data), bufferIndex, this);
    return hardware::Void();
}

hardware::Return<void> CameraHardwareInterface::handleCallbackTimestamp(
        DataCallbackMsg msgType, const hidl_handle& frameData, uint32_t data,
        uint32_t bufferIndex, int64_t timestamp) {
    if (mHidlMemPoolMap.count(data) == 0) {
        ALOGE("%s: memory pool ID %d not found", __FUNCTION__, data);
        return hardware::Void();
    }
    sp<CameraHeapMemory> mem(static_cast<CameraHeapMemory *>(mHidlMemPoolMap.at(data)->handle));
    VideoNativeHandleMetadata* md = (VideoNativeHandleMetadata*)
            mem->mBuffers[bufferIndex]->pointer();
    md->pHandle = const_cast<native_handle_t*>(frameData.getNativeHandle());
    sDataCbTimestamp(timestamp, (int32_t) msgType, mHidlMemPoolMap.at(data), bufferIndex, this);
    return hardware::Void();
}

hardware::Return<void> CameraHardwareInterface::handleCallbackTimestampBatch(
        DataCallbackMsg msgType,
        const hardware::hidl_vec<hardware::camera::device::V1_0::HandleTimestampMessage>& messages) {
    std::vector<android::HandleTimestampMessage> msgs;
    msgs.reserve(messages.size());

    for (const auto& hidl_msg : messages) {
        if (mHidlMemPoolMap.count(hidl_msg.data) == 0) {
            ALOGE("%s: memory pool ID %d not found", __FUNCTION__, hidl_msg.data);
            return hardware::Void();
        }
        sp<CameraHeapMemory> mem(
                static_cast<CameraHeapMemory *>(mHidlMemPoolMap.at(hidl_msg.data)->handle));

        if (hidl_msg.bufferIndex >= mem->mNumBufs) {
            ALOGE("%s: invalid buffer index %d, max allowed is %d", __FUNCTION__,
                 hidl_msg.bufferIndex, mem->mNumBufs);
            return hardware::Void();
        }
        VideoNativeHandleMetadata* md = (VideoNativeHandleMetadata*)
                mem->mBuffers[hidl_msg.bufferIndex]->pointer();
        md->pHandle = const_cast<native_handle_t*>(hidl_msg.frameData.getNativeHandle());

        msgs.push_back({hidl_msg.timestamp, mem->mBuffers[hidl_msg.bufferIndex]});
    }

    mDataCbTimestampBatch((int32_t) msgType, msgs, mCbUser);
    return hardware::Void();
}

std::pair<bool, uint64_t> CameraHardwareInterface::getBufferId(
        ANativeWindowBuffer* anb) {
    std::lock_guard<std::mutex> lock(mBufferIdMapLock);

    buffer_handle_t& buf = anb->handle;
    auto it = mBufferIdMap.find(buf);
    if (it == mBufferIdMap.end()) {
        uint64_t bufId = mNextBufferId++;
        mBufferIdMap[buf] = bufId;
        mReversedBufMap[bufId] = anb;
        return std::make_pair(true, bufId);
    } else {
        return std::make_pair(false, it->second);
    }
}

void CameraHardwareInterface::cleanupCirculatingBuffers() {
    std::lock_guard<std::mutex> lock(mBufferIdMapLock);
    mBufferIdMap.clear();
    mReversedBufMap.clear();
}

hardware::Return<void>
CameraHardwareInterface::dequeueBuffer(dequeueBuffer_cb _hidl_cb) {
    ANativeWindow *a = mPreviewWindow.get();
    if (a == nullptr) {
        ALOGE("%s: preview window is null", __FUNCTION__);
        return hardware::Void();
    }
    ANativeWindowBuffer* anb;
    int rc = native_window_dequeue_buffer_and_wait(a, &anb);
    Status s = Status::INTERNAL_ERROR;
    uint64_t bufferId = 0;
    uint32_t stride = 0;
    hidl_handle buf = nullptr;
    if (rc == OK) {
        s = Status::OK;
        auto pair = getBufferId(anb);
        buf = (pair.first) ? anb->handle : nullptr;
        bufferId = pair.second;
        stride = anb->stride;
    }

    _hidl_cb(s, bufferId, buf, stride);
    return hardware::Void();
}

hardware::Return<Status>
CameraHardwareInterface::enqueueBuffer(uint64_t bufferId) {
    ANativeWindow *a = mPreviewWindow.get();
    if (a == nullptr) {
        ALOGE("%s: preview window is null", __FUNCTION__);
        return Status::INTERNAL_ERROR;
    }
    if (mReversedBufMap.count(bufferId) == 0) {
        ALOGE("%s: bufferId %" PRIu64 " not found", __FUNCTION__, bufferId);
        return Status::ILLEGAL_ARGUMENT;
    }
    int rc = a->queueBuffer(a, mReversedBufMap.at(bufferId), -1);
    if (rc == 0) {
        return Status::OK;
    }
    return Status::INTERNAL_ERROR;
}

hardware::Return<Status>
CameraHardwareInterface::cancelBuffer(uint64_t bufferId) {
    ANativeWindow *a = mPreviewWindow.get();
    if (a == nullptr) {
        ALOGE("%s: preview window is null", __FUNCTION__);
        return Status::INTERNAL_ERROR;
    }
    if (mReversedBufMap.count(bufferId) == 0) {
        ALOGE("%s: bufferId %" PRIu64 " not found", __FUNCTION__, bufferId);
        return Status::ILLEGAL_ARGUMENT;
    }
    int rc = a->cancelBuffer(a, mReversedBufMap.at(bufferId), -1);
    if (rc == 0) {
        return Status::OK;
    }
    return Status::INTERNAL_ERROR;
}

hardware::Return<Status>
CameraHardwareInterface::setBufferCount(uint32_t count) {
    ANativeWindow *a = mPreviewWindow.get();
    if (a != nullptr) {
        // Workaround for b/27039775
        // Previously, setting the buffer count would reset the buffer
        // queue's flag that allows for all buffers to be dequeued on the
        // producer side, instead of just the producer's declared max count,
        // if no filled buffers have yet been queued by the producer.  This
        // reset no longer happens, but some HALs depend on this behavior,
        // so it needs to be maintained for HAL backwards compatibility.
        // Simulate the prior behavior by disconnecting/reconnecting to the
        // window and setting the values again.  This has the drawback of
        // actually causing memory reallocation, which may not have happened
        // in the past.
        native_window_api_disconnect(a, NATIVE_WINDOW_API_CAMERA);
        native_window_api_connect(a, NATIVE_WINDOW_API_CAMERA);
        if (mPreviewScalingMode != NOT_SET) {
            native_window_set_scaling_mode(a, mPreviewScalingMode);
        }
        if (mPreviewTransform != NOT_SET) {
            native_window_set_buffers_transform(a, mPreviewTransform);
        }
        if (mPreviewWidth != NOT_SET) {
            native_window_set_buffers_dimensions(a,
                    mPreviewWidth, mPreviewHeight);
            native_window_set_buffers_format(a, mPreviewFormat);
        }
        if (mPreviewUsage != 0) {
            native_window_set_usage(a, mPreviewUsage);
        }
        if (mPreviewSwapInterval != NOT_SET) {
            a->setSwapInterval(a, mPreviewSwapInterval);
        }
        if (mPreviewCrop.left != NOT_SET) {
            native_window_set_crop(a, &(mPreviewCrop));
        }
    }
    int rc = native_window_set_buffer_count(a, count);
    if (rc == OK) {
        cleanupCirculatingBuffers();
        return Status::OK;
    }
    return Status::INTERNAL_ERROR;
}

hardware::Return<Status>
CameraHardwareInterface::setBuffersGeometry(
        uint32_t w, uint32_t h, hardware::graphics::common::V1_0::PixelFormat format) {
    Status s = Status::INTERNAL_ERROR;
    ANativeWindow *a = mPreviewWindow.get();
    if (a == nullptr) {
        ALOGE("%s: preview window is null", __FUNCTION__);
        return s;
    }
    mPreviewWidth = w;
    mPreviewHeight = h;
    mPreviewFormat = (int) format;
    int rc = native_window_set_buffers_dimensions(a, w, h);
    if (rc == OK) {
        rc = native_window_set_buffers_format(a, mPreviewFormat);
    }
    if (rc == OK) {
        cleanupCirculatingBuffers();
        s = Status::OK;
    }
    return s;
}

hardware::Return<Status>
CameraHardwareInterface::setCrop(int32_t left, int32_t top, int32_t right, int32_t bottom) {
    Status s = Status::INTERNAL_ERROR;
    ANativeWindow *a = mPreviewWindow.get();
    if (a == nullptr) {
        ALOGE("%s: preview window is null", __FUNCTION__);
        return s;
    }
    mPreviewCrop.left = left;
    mPreviewCrop.top = top;
    mPreviewCrop.right = right;
    mPreviewCrop.bottom = bottom;
    int rc = native_window_set_crop(a, &mPreviewCrop);
    if (rc == OK) {
        s = Status::OK;
    }
    return s;
}

hardware::Return<Status>
CameraHardwareInterface::setUsage(hardware::graphics::common::V1_0::BufferUsage usage) {
    Status s = Status::INTERNAL_ERROR;
    ANativeWindow *a = mPreviewWindow.get();
    if (a == nullptr) {
        ALOGE("%s: preview window is null", __FUNCTION__);
        return s;
    }
    mPreviewUsage = (int) usage;
    int rc = native_window_set_usage(a, mPreviewUsage);
    if (rc == OK) {
        cleanupCirculatingBuffers();
        s = Status::OK;
    }
    return s;
}

hardware::Return<Status>
CameraHardwareInterface::setSwapInterval(int32_t interval) {
    Status s = Status::INTERNAL_ERROR;
    ANativeWindow *a = mPreviewWindow.get();
    if (a == nullptr) {
        ALOGE("%s: preview window is null", __FUNCTION__);
        return s;
    }
    mPreviewSwapInterval = interval;
    int rc = a->setSwapInterval(a, interval);
    if (rc == OK) {
        s = Status::OK;
    }
    return s;
}

hardware::Return<void>
CameraHardwareInterface::getMinUndequeuedBufferCount(getMinUndequeuedBufferCount_cb _hidl_cb) {
    ANativeWindow *a = mPreviewWindow.get();
    if (a == nullptr) {
        ALOGE("%s: preview window is null", __FUNCTION__);
        return hardware::Void();
    }
    int count = 0;
    int rc = a->query(a, NATIVE_WINDOW_MIN_UNDEQUEUED_BUFFERS, &count);
    Status s = Status::INTERNAL_ERROR;
    if (rc == OK) {
        s = Status::OK;
    }
    _hidl_cb(s, count);
    return hardware::Void();
}

hardware::Return<Status>
CameraHardwareInterface::setTimestamp(int64_t timestamp) {
    Status s = Status::INTERNAL_ERROR;
    ANativeWindow *a = mPreviewWindow.get();
    if (a == nullptr) {
        ALOGE("%s: preview window is null", __FUNCTION__);
        return s;
    }
    int rc = native_window_set_buffers_timestamp(a, timestamp);
    if (rc == OK) {
        s = Status::OK;
    }
    return s;
}

status_t CameraHardwareInterface::setPreviewWindow(const sp<ANativeWindow>& buf)
{
    ALOGV("%s(%s) buf %p", __FUNCTION__, mName.string(), buf.get());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        mPreviewWindow = buf;
        if (buf != nullptr) {
            if (mPreviewScalingMode != NOT_SET) {
                setPreviewScalingMode(mPreviewScalingMode);
            }
            if (mPreviewTransform != NOT_SET) {
                setPreviewTransform(mPreviewTransform);
            }
        }
        return CameraProviderManager::mapToStatusT(
                mHidlDevice->setPreviewWindow(buf.get() ? this : nullptr));
    } else if (mDevice) {
        if (mDevice->ops->set_preview_window) {
            mPreviewWindow = buf;
            if (buf != nullptr) {
                if (mPreviewScalingMode != NOT_SET) {
                    setPreviewScalingMode(mPreviewScalingMode);
                }
                if (mPreviewTransform != NOT_SET) {
                    setPreviewTransform(mPreviewTransform);
                }
            }
            mHalPreviewWindow.user = this;
            ALOGV("%s &mHalPreviewWindow %p mHalPreviewWindow.user %p",__FUNCTION__,
                    &mHalPreviewWindow, mHalPreviewWindow.user);
            return mDevice->ops->set_preview_window(mDevice,
                    buf.get() ? &mHalPreviewWindow.nw : 0);
        }
    }
    return INVALID_OPERATION;
}

void CameraHardwareInterface::setCallbacks(notify_callback notify_cb,
        data_callback data_cb,
        data_callback_timestamp data_cb_timestamp,
        data_callback_timestamp_batch data_cb_timestamp_batch,
        void* user)
{
    mNotifyCb = notify_cb;
    mDataCb = data_cb;
    mDataCbTimestamp = data_cb_timestamp;
    mDataCbTimestampBatch = data_cb_timestamp_batch;
    mCbUser = user;

    ALOGV("%s(%s)", __FUNCTION__, mName.string());

    if (mDevice && mDevice->ops->set_callbacks) {
        mDevice->ops->set_callbacks(mDevice,
                               sNotifyCb,
                               sDataCb,
                               sDataCbTimestamp,
                               sGetMemory,
                               this);
    }
}

void CameraHardwareInterface::enableMsgType(int32_t msgType)
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        mHidlDevice->enableMsgType(msgType);
    } else if (mDevice && mDevice->ops->enable_msg_type) {
        mDevice->ops->enable_msg_type(mDevice, msgType);
    }
}

void CameraHardwareInterface::disableMsgType(int32_t msgType)
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        mHidlDevice->disableMsgType(msgType);
    } else if (mDevice && mDevice->ops->disable_msg_type) {
        mDevice->ops->disable_msg_type(mDevice, msgType);
    }
}

int CameraHardwareInterface::msgTypeEnabled(int32_t msgType)
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        return mHidlDevice->msgTypeEnabled(msgType);
    } else if (mDevice && mDevice->ops->msg_type_enabled) {
        return mDevice->ops->msg_type_enabled(mDevice, msgType);
    }
    return false;
}

status_t CameraHardwareInterface::startPreview()
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        return CameraProviderManager::mapToStatusT(
                mHidlDevice->startPreview());
    } else if (mDevice && mDevice->ops->start_preview) {
        return mDevice->ops->start_preview(mDevice);
    }
    return INVALID_OPERATION;
}

void CameraHardwareInterface::stopPreview()
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        mHidlDevice->stopPreview();
    } else if (mDevice && mDevice->ops->stop_preview) {
        mDevice->ops->stop_preview(mDevice);
    }
}

int CameraHardwareInterface::previewEnabled()
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        return mHidlDevice->previewEnabled();
    } else if (mDevice && mDevice->ops->preview_enabled) {
        return mDevice->ops->preview_enabled(mDevice);
    }
    return false;
}

status_t CameraHardwareInterface::storeMetaDataInBuffers(int enable)
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        return CameraProviderManager::mapToStatusT(
                mHidlDevice->storeMetaDataInBuffers(enable));
    } else if (mDevice && mDevice->ops->store_meta_data_in_buffers) {
        return mDevice->ops->store_meta_data_in_buffers(mDevice, enable);
    }
    return enable ? INVALID_OPERATION: OK;
}

status_t CameraHardwareInterface::startRecording()
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        return CameraProviderManager::mapToStatusT(
                mHidlDevice->startRecording());
    } else if (mDevice && mDevice->ops->start_recording) {
        return mDevice->ops->start_recording(mDevice);
    }
    return INVALID_OPERATION;
}

/**
 * Stop a previously started recording.
 */
void CameraHardwareInterface::stopRecording()
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        mHidlDevice->stopRecording();
    } else if (mDevice && mDevice->ops->stop_recording) {
        mDevice->ops->stop_recording(mDevice);
    }
}

/**
 * Returns true if recording is enabled.
 */
int CameraHardwareInterface::recordingEnabled()
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        return mHidlDevice->recordingEnabled();
    } else if (mDevice && mDevice->ops->recording_enabled) {
        return mDevice->ops->recording_enabled(mDevice);
    }
    return false;
}

void CameraHardwareInterface::releaseRecordingFrame(const sp<IMemory>& mem)
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    ssize_t offset;
    size_t size;
    sp<IMemoryHeap> heap = mem->getMemory(&offset, &size);
    int heapId = heap->getHeapID();
    int bufferIndex = offset / size;
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        if (size == sizeof(VideoNativeHandleMetadata)) {
            VideoNativeHandleMetadata* md = (VideoNativeHandleMetadata*) mem->pointer();
            // Caching the handle here because md->pHandle will be subject to HAL's edit
            native_handle_t* nh = md->pHandle;
            hidl_handle frame = nh;
            mHidlDevice->releaseRecordingFrameHandle(heapId, bufferIndex, frame);
            native_handle_close(nh);
            native_handle_delete(nh);
        } else {
            mHidlDevice->releaseRecordingFrame(heapId, bufferIndex);
        }
    } else if (mDevice && mDevice->ops->release_recording_frame) {
        void *data = ((uint8_t *)heap->base()) + offset;
        return mDevice->ops->release_recording_frame(mDevice, data);
    }
}

void CameraHardwareInterface::releaseRecordingFrameBatch(const std::vector<sp<IMemory>>& frames)
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    size_t n = frames.size();
    std::vector<VideoFrameMessage> msgs;
    msgs.reserve(n);
    for (auto& mem : frames) {
        if (CC_LIKELY(mHidlDevice != nullptr)) {
            ssize_t offset;
            size_t size;
            sp<IMemoryHeap> heap = mem->getMemory(&offset, &size);
            if (size == sizeof(VideoNativeHandleMetadata)) {
                uint32_t heapId = heap->getHeapID();
                uint32_t bufferIndex = offset / size;
                VideoNativeHandleMetadata* md = (VideoNativeHandleMetadata*) mem->pointer();
                // Caching the handle here because md->pHandle will be subject to HAL's edit
                native_handle_t* nh = md->pHandle;
                VideoFrameMessage msg;
                msgs.push_back({nh, heapId, bufferIndex});
            } else {
                ALOGE("%s only supports VideoNativeHandleMetadata mode", __FUNCTION__);
                return;
            }
        } else {
            ALOGE("Non HIDL mode do not support %s", __FUNCTION__);
            return;
        }
    }

    mHidlDevice->releaseRecordingFrameHandleBatch(msgs);

    for (auto& msg : msgs) {
        native_handle_t* nh = const_cast<native_handle_t*>(msg.frameData.getNativeHandle());
        native_handle_close(nh);
        native_handle_delete(nh);
    }
}

status_t CameraHardwareInterface::autoFocus()
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        return CameraProviderManager::mapToStatusT(
                mHidlDevice->autoFocus());
    } else if (mDevice && mDevice->ops->auto_focus) {
        return mDevice->ops->auto_focus(mDevice);
    }
    return INVALID_OPERATION;
}

status_t CameraHardwareInterface::cancelAutoFocus()
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        return CameraProviderManager::mapToStatusT(
                mHidlDevice->cancelAutoFocus());
    } else if (mDevice && mDevice->ops->cancel_auto_focus) {
        return mDevice->ops->cancel_auto_focus(mDevice);
    }
    return INVALID_OPERATION;
}

status_t CameraHardwareInterface::takePicture()
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        return CameraProviderManager::mapToStatusT(
                mHidlDevice->takePicture());
    } else if (mDevice && mDevice->ops->take_picture) {
        return mDevice->ops->take_picture(mDevice);
    }
    return INVALID_OPERATION;
}

status_t CameraHardwareInterface::cancelPicture()
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        return CameraProviderManager::mapToStatusT(
                mHidlDevice->cancelPicture());
    } else if (mDevice && mDevice->ops->cancel_picture) {
        return mDevice->ops->cancel_picture(mDevice);
    }
    return INVALID_OPERATION;
}

status_t CameraHardwareInterface::setParameters(const CameraParameters &params)
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        return CameraProviderManager::mapToStatusT(
                mHidlDevice->setParameters(params.flatten().string()));
    } else if (mDevice && mDevice->ops->set_parameters) {
        return mDevice->ops->set_parameters(mDevice, params.flatten().string());
    }
    return INVALID_OPERATION;
}

CameraParameters CameraHardwareInterface::getParameters() const
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    CameraParameters parms;
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        hardware::hidl_string outParam;
        mHidlDevice->getParameters(
                [&outParam](const auto& outStr) {
                    outParam = outStr;
                });
        String8 tmp(outParam.c_str());
        parms.unflatten(tmp);
    } else if (mDevice && mDevice->ops->get_parameters) {
        char *temp = mDevice->ops->get_parameters(mDevice);
        String8 str_parms(temp);
        if (mDevice->ops->put_parameters)
            mDevice->ops->put_parameters(mDevice, temp);
        else
            free(temp);
        parms.unflatten(str_parms);
    }
    return parms;
}

status_t CameraHardwareInterface::sendCommand(int32_t cmd, int32_t arg1, int32_t arg2)
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        return CameraProviderManager::mapToStatusT(
                mHidlDevice->sendCommand((CommandType) cmd, arg1, arg2));
    } else if (mDevice && mDevice->ops->send_command) {
        return mDevice->ops->send_command(mDevice, cmd, arg1, arg2);
    }
    return INVALID_OPERATION;
}

/**
 * Release the hardware resources owned by this object.  Note that this is
 * *not* done in the destructor.
 */
void CameraHardwareInterface::release() {
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        mHidlDevice->close();
        mHidlDevice.clear();
    } else if (mDevice && mDevice->ops->release) {
        mDevice->ops->release(mDevice);
    }
}

/**
 * Dump state of the camera hardware
 */
status_t CameraHardwareInterface::dump(int fd, const Vector<String16>& /*args*/) const
{
    ALOGV("%s(%s)", __FUNCTION__, mName.string());
    if (CC_LIKELY(mHidlDevice != nullptr)) {
        native_handle_t* handle = native_handle_create(1,0);
        handle->data[0] = fd;
        Status s = mHidlDevice->dumpState(handle);
        native_handle_delete(handle);
        return CameraProviderManager::mapToStatusT(s);
    } else if (mDevice && mDevice->ops->dump) {
        return mDevice->ops->dump(mDevice, fd);
    }
    return OK; // It's fine if the HAL doesn't implement dump()
}

/**
 * Methods for legacy (non-HIDL) path follows
 */
void CameraHardwareInterface::sNotifyCb(int32_t msg_type, int32_t ext1,
                        int32_t ext2, void *user)
{
    ALOGV("%s", __FUNCTION__);
    CameraHardwareInterface *object =
            static_cast<CameraHardwareInterface *>(user);
    object->mNotifyCb(msg_type, ext1, ext2, object->mCbUser);
}

void CameraHardwareInterface::sDataCb(int32_t msg_type,
                      const camera_memory_t *data, unsigned int index,
                      camera_frame_metadata_t *metadata,
                      void *user)
{
    ALOGV("%s", __FUNCTION__);
    CameraHardwareInterface *object =
            static_cast<CameraHardwareInterface *>(user);
    sp<CameraHeapMemory> mem(static_cast<CameraHeapMemory *>(data->handle));
    if (index >= mem->mNumBufs) {
        ALOGE("%s: invalid buffer index %d, max allowed is %d", __FUNCTION__,
             index, mem->mNumBufs);
        return;
    }
    object->mDataCb(msg_type, mem->mBuffers[index], metadata, object->mCbUser);
}

void CameraHardwareInterface::sDataCbTimestamp(nsecs_t timestamp, int32_t msg_type,
                         const camera_memory_t *data, unsigned index,
                         void *user)
{
    ALOGV("%s", __FUNCTION__);
    CameraHardwareInterface *object =
            static_cast<CameraHardwareInterface *>(user);
    // Start refcounting the heap object from here on.  When the clients
    // drop all references, it will be destroyed (as well as the enclosed
    // MemoryHeapBase.
    sp<CameraHeapMemory> mem(static_cast<CameraHeapMemory *>(data->handle));
    if (index >= mem->mNumBufs) {
        ALOGE("%s: invalid buffer index %d, max allowed is %d", __FUNCTION__,
             index, mem->mNumBufs);
        return;
    }
    object->mDataCbTimestamp(timestamp, msg_type, mem->mBuffers[index], object->mCbUser);
}

camera_memory_t* CameraHardwareInterface::sGetMemory(
        int fd, size_t buf_size, uint_t num_bufs,
        void *user __attribute__((unused)))
{
    CameraHeapMemory *mem;
    if (fd < 0) {
        mem = new CameraHeapMemory(buf_size, num_bufs);
    } else {
        mem = new CameraHeapMemory(fd, buf_size, num_bufs);
    }
    mem->incStrong(mem);
    return &mem->handle;
}

void CameraHardwareInterface::sPutMemory(camera_memory_t *data)
{
    if (!data) {
        return;
    }

    CameraHeapMemory *mem = static_cast<CameraHeapMemory *>(data->handle);
    mem->decStrong(mem);
}

ANativeWindow* CameraHardwareInterface::sToAnw(void *user)
{
    CameraHardwareInterface *object =
            reinterpret_cast<CameraHardwareInterface *>(user);
    return object->mPreviewWindow.get();
}
#define anw(n) sToAnw(((struct camera_preview_window *)(n))->user)
#define hwi(n) reinterpret_cast<CameraHardwareInterface *>(\
    ((struct camera_preview_window *)(n))->user)

int CameraHardwareInterface::sDequeueBuffer(struct preview_stream_ops* w,
                            buffer_handle_t** buffer, int *stride)
{
    int rc;
    ANativeWindow *a = anw(w);
    ANativeWindowBuffer* anb;
    rc = native_window_dequeue_buffer_and_wait(a, &anb);
    if (rc == OK) {
        *buffer = &anb->handle;
        *stride = anb->stride;
    }
    return rc;
}

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
    const __typeof__(((type *) 0)->member) *__mptr = (ptr);     \
    (type *) ((char *) __mptr - (char *)(&((type *)0)->member)); })
#endif

int CameraHardwareInterface::sLockBuffer(struct preview_stream_ops* w,
                  buffer_handle_t* /*buffer*/)
{
    ANativeWindow *a = anw(w);
    (void)a;
    return 0;
}

int CameraHardwareInterface::sEnqueueBuffer(struct preview_stream_ops* w,
                  buffer_handle_t* buffer)
{
    ANativeWindow *a = anw(w);
    return a->queueBuffer(a,
              container_of(buffer, ANativeWindowBuffer, handle), -1);
}

int CameraHardwareInterface::sCancelBuffer(struct preview_stream_ops* w,
                  buffer_handle_t* buffer)
{
    ANativeWindow *a = anw(w);
    return a->cancelBuffer(a,
              container_of(buffer, ANativeWindowBuffer, handle), -1);
}

int CameraHardwareInterface::sSetBufferCount(struct preview_stream_ops* w, int count)
{
    ANativeWindow *a = anw(w);

    if (a != nullptr) {
        // Workaround for b/27039775
        // Previously, setting the buffer count would reset the buffer
        // queue's flag that allows for all buffers to be dequeued on the
        // producer side, instead of just the producer's declared max count,
        // if no filled buffers have yet been queued by the producer.  This
        // reset no longer happens, but some HALs depend on this behavior,
        // so it needs to be maintained for HAL backwards compatibility.
        // Simulate the prior behavior by disconnecting/reconnecting to the
        // window and setting the values again.  This has the drawback of
        // actually causing memory reallocation, which may not have happened
        // in the past.
        CameraHardwareInterface *hw = hwi(w);
        native_window_api_disconnect(a, NATIVE_WINDOW_API_CAMERA);
        native_window_api_connect(a, NATIVE_WINDOW_API_CAMERA);
        if (hw->mPreviewScalingMode != NOT_SET) {
            native_window_set_scaling_mode(a, hw->mPreviewScalingMode);
        }
        if (hw->mPreviewTransform != NOT_SET) {
            native_window_set_buffers_transform(a, hw->mPreviewTransform);
        }
        if (hw->mPreviewWidth != NOT_SET) {
            native_window_set_buffers_dimensions(a,
                    hw->mPreviewWidth, hw->mPreviewHeight);
            native_window_set_buffers_format(a, hw->mPreviewFormat);
        }
        if (hw->mPreviewUsage != 0) {
            native_window_set_usage(a, hw->mPreviewUsage);
        }
        if (hw->mPreviewSwapInterval != NOT_SET) {
            a->setSwapInterval(a, hw->mPreviewSwapInterval);
        }
        if (hw->mPreviewCrop.left != NOT_SET) {
            native_window_set_crop(a, &(hw->mPreviewCrop));
        }
    }

    return native_window_set_buffer_count(a, count);
}

int CameraHardwareInterface::sSetBuffersGeometry(struct preview_stream_ops* w,
                  int width, int height, int format)
{
    int rc;
    ANativeWindow *a = anw(w);
    CameraHardwareInterface *hw = hwi(w);
    hw->mPreviewWidth = width;
    hw->mPreviewHeight = height;
    hw->mPreviewFormat = format;
    rc = native_window_set_buffers_dimensions(a, width, height);
    if (rc == OK) {
        rc = native_window_set_buffers_format(a, format);
    }
    return rc;
}

int CameraHardwareInterface::sSetCrop(struct preview_stream_ops *w,
                  int left, int top, int right, int bottom)
{
    ANativeWindow *a = anw(w);
    CameraHardwareInterface *hw = hwi(w);
    hw->mPreviewCrop.left = left;
    hw->mPreviewCrop.top = top;
    hw->mPreviewCrop.right = right;
    hw->mPreviewCrop.bottom = bottom;
    return native_window_set_crop(a, &(hw->mPreviewCrop));
}

int CameraHardwareInterface::sSetTimestamp(struct preview_stream_ops *w,
                           int64_t timestamp) {
    ANativeWindow *a = anw(w);
    return native_window_set_buffers_timestamp(a, timestamp);
}

int CameraHardwareInterface::sSetUsage(struct preview_stream_ops* w, int usage)
{
    ANativeWindow *a = anw(w);
    CameraHardwareInterface *hw = hwi(w);
    hw->mPreviewUsage = usage;
    return native_window_set_usage(a, usage);
}

int CameraHardwareInterface::sSetSwapInterval(struct preview_stream_ops *w, int interval)
{
    ANativeWindow *a = anw(w);
    CameraHardwareInterface *hw = hwi(w);
    hw->mPreviewSwapInterval = interval;
    return a->setSwapInterval(a, interval);
}

int CameraHardwareInterface::sGetMinUndequeuedBufferCount(
                  const struct preview_stream_ops *w,
                  int *count)
{
    ANativeWindow *a = anw(w);
    return a->query(a, NATIVE_WINDOW_MIN_UNDEQUEUED_BUFFERS, count);
}

void CameraHardwareInterface::initHalPreviewWindow()
{
    mHalPreviewWindow.nw.cancel_buffer = sCancelBuffer;
    mHalPreviewWindow.nw.lock_buffer = sLockBuffer;
    mHalPreviewWindow.nw.dequeue_buffer = sDequeueBuffer;
    mHalPreviewWindow.nw.enqueue_buffer = sEnqueueBuffer;
    mHalPreviewWindow.nw.set_buffer_count = sSetBufferCount;
    mHalPreviewWindow.nw.set_buffers_geometry = sSetBuffersGeometry;
    mHalPreviewWindow.nw.set_crop = sSetCrop;
    mHalPreviewWindow.nw.set_timestamp = sSetTimestamp;
    mHalPreviewWindow.nw.set_usage = sSetUsage;
    mHalPreviewWindow.nw.set_swap_interval = sSetSwapInterval;

    mHalPreviewWindow.nw.get_min_undequeued_buffer_count =
            sGetMinUndequeuedBufferCount;
}

}; // namespace android
