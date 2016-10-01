/*
 * Copyright (c) 2009 The Android Open Source Project
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
#define LOG_TAG "IOMX"
#include <utils/Log.h>

#include <sys/mman.h>

#include <binder/IMemory.h>
#include <binder/Parcel.h>
#include <media/IOMX.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/openmax/OMX_IndexExt.h>
#include <utils/NativeHandle.h>

#include <android/IGraphicBufferSource.h>

namespace android {

enum {
    CONNECT = IBinder::FIRST_CALL_TRANSACTION,
    LIST_NODES,
    ALLOCATE_NODE,
    FREE_NODE,
    SEND_COMMAND,
    GET_PARAMETER,
    SET_PARAMETER,
    GET_CONFIG,
    SET_CONFIG,
    GET_STATE,
    ENABLE_NATIVE_BUFFERS,
    USE_BUFFER,
    USE_GRAPHIC_BUFFER,
    CREATE_INPUT_SURFACE,
    CREATE_PERSISTENT_INPUT_SURFACE,
    SET_INPUT_SURFACE,
    STORE_META_DATA_IN_BUFFERS,
    PREPARE_FOR_ADAPTIVE_PLAYBACK,
    ALLOC_SECURE_BUFFER,
    ALLOC_BUFFER_WITH_BACKUP,
    FREE_BUFFER,
    FILL_BUFFER,
    EMPTY_BUFFER,
    EMPTY_GRAPHIC_BUFFER,
    GET_EXTENSION_INDEX,
    OBSERVER_ON_MSG,
    GET_GRAPHIC_BUFFER_USAGE,
    UPDATE_GRAPHIC_BUFFER_IN_META,
    CONFIGURE_VIDEO_TUNNEL_MODE,
    UPDATE_NATIVE_HANDLE_IN_META,
    DISPATCH_MESSAGE,
};

class BpOMX : public BpInterface<IOMX> {
public:
    explicit BpOMX(const sp<IBinder> &impl)
        : BpInterface<IOMX>(impl) {
    }

    virtual bool livesLocally() {
        return false;
    }

    virtual status_t listNodes(List<ComponentInfo> *list) {
        list->clear();

        Parcel data, reply;
        data.writeInterfaceToken(IOMX::getInterfaceDescriptor());
        remote()->transact(LIST_NODES, data, &reply);

        int32_t n = reply.readInt32();
        for (int32_t i = 0; i < n; ++i) {
            list->push_back(ComponentInfo());
            ComponentInfo &info = *--list->end();

            info.mName = reply.readString8();
            int32_t numRoles = reply.readInt32();
            for (int32_t j = 0; j < numRoles; ++j) {
                info.mRoles.push_back(reply.readString8());
            }
        }

        return OK;
    }

    virtual status_t allocateNode(
            const char *name, const sp<IOMXObserver> &observer,
            sp<IBinder> *nodeBinder, sp<IOMXNode> *omxNode) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMX::getInterfaceDescriptor());
        data.writeCString(name);
        data.writeStrongBinder(IInterface::asBinder(observer));
        remote()->transact(ALLOCATE_NODE, data, &reply);

        status_t err = reply.readInt32();
        if (err == OK) {
            *omxNode = IOMXNode::asInterface(reply.readStrongBinder());
            if (nodeBinder != NULL) {
                *nodeBinder = remote();
            }
        } else {
            omxNode->clear();
        }

        return err;
    }

    virtual status_t createPersistentInputSurface(
            sp<IGraphicBufferProducer> *bufferProducer,
            sp<IGraphicBufferConsumer> *bufferConsumer) {
        Parcel data, reply;
        status_t err;
        data.writeInterfaceToken(IOMX::getInterfaceDescriptor());
        err = remote()->transact(CREATE_PERSISTENT_INPUT_SURFACE, data, &reply);
        if (err != OK) {
            ALOGW("binder transaction failed: %d", err);
            return err;
        }

        err = reply.readInt32();
        if (err != OK) {
            return err;
        }

        *bufferProducer = IGraphicBufferProducer::asInterface(
                reply.readStrongBinder());
        *bufferConsumer = IGraphicBufferConsumer::asInterface(
                reply.readStrongBinder());

        return err;
    }
};

class BpOMXNode : public BpInterface<IOMXNode> {
public:
    explicit BpOMXNode(const sp<IBinder> &impl)
        : BpInterface<IOMXNode>(impl) {
    }

    virtual status_t freeNode() {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        remote()->transact(FREE_NODE, data, &reply);

        return reply.readInt32();
    }

    virtual status_t sendCommand(
            OMX_COMMANDTYPE cmd, OMX_S32 param) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(cmd);
        data.writeInt32(param);
        remote()->transact(SEND_COMMAND, data, &reply);

        return reply.readInt32();
    }

    virtual status_t getParameter(
            OMX_INDEXTYPE index,
            void *params, size_t size) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(index);
        data.writeInt64(size);
        data.write(params, size);
        remote()->transact(GET_PARAMETER, data, &reply);

        status_t err = reply.readInt32();
        if (err != OK) {
            return err;
        }

        reply.read(params, size);

        return OK;
    }

    virtual status_t setParameter(
            OMX_INDEXTYPE index,
            const void *params, size_t size) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(index);
        data.writeInt64(size);
        data.write(params, size);
        remote()->transact(SET_PARAMETER, data, &reply);

        return reply.readInt32();
    }

    virtual status_t getConfig(
            OMX_INDEXTYPE index,
            void *params, size_t size) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(index);
        data.writeInt64(size);
        data.write(params, size);
        remote()->transact(GET_CONFIG, data, &reply);

        status_t err = reply.readInt32();
        if (err != OK) {
            return err;
        }

        reply.read(params, size);

        return OK;
    }

    virtual status_t setConfig(
            OMX_INDEXTYPE index,
            const void *params, size_t size) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(index);
        data.writeInt64(size);
        data.write(params, size);
        remote()->transact(SET_CONFIG, data, &reply);

        return reply.readInt32();
    }

    virtual status_t getState(
            OMX_STATETYPE* state) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        remote()->transact(GET_STATE, data, &reply);

        *state = static_cast<OMX_STATETYPE>(reply.readInt32());
        return reply.readInt32();
    }

    virtual status_t enableNativeBuffers(
            OMX_U32 port_index, OMX_BOOL graphic, OMX_BOOL enable) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(port_index);
        data.writeInt32((uint32_t)graphic);
        data.writeInt32((uint32_t)enable);
        remote()->transact(ENABLE_NATIVE_BUFFERS, data, &reply);

        status_t err = reply.readInt32();
        return err;
    }

    virtual status_t getGraphicBufferUsage(
            OMX_U32 port_index, OMX_U32* usage) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(port_index);
        remote()->transact(GET_GRAPHIC_BUFFER_USAGE, data, &reply);

        status_t err = reply.readInt32();
        *usage = reply.readInt32();
        return err;
    }

    virtual status_t useBuffer(
            OMX_U32 port_index, const sp<IMemory> &params,
            buffer_id *buffer, OMX_U32 allottedSize) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(port_index);
        data.writeStrongBinder(IInterface::asBinder(params));
        data.writeInt32(allottedSize);
        remote()->transact(USE_BUFFER, data, &reply);

        status_t err = reply.readInt32();
        if (err != OK) {
            *buffer = 0;

            return err;
        }

        *buffer = (buffer_id)reply.readInt32();

        return err;
    }


    virtual status_t useGraphicBuffer(
            OMX_U32 port_index,
            const sp<GraphicBuffer> &graphicBuffer, buffer_id *buffer) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(port_index);
        data.write(*graphicBuffer);
        remote()->transact(USE_GRAPHIC_BUFFER, data, &reply);

        status_t err = reply.readInt32();
        if (err != OK) {
            *buffer = 0;

            return err;
        }

        *buffer = (buffer_id)reply.readInt32();

        return err;
    }

    virtual status_t updateGraphicBufferInMeta(
            OMX_U32 port_index,
            const sp<GraphicBuffer> &graphicBuffer, buffer_id buffer) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(port_index);
        data.write(*graphicBuffer);
        data.writeInt32((int32_t)buffer);
        remote()->transact(UPDATE_GRAPHIC_BUFFER_IN_META, data, &reply);

        status_t err = reply.readInt32();
        return err;
    }

    virtual status_t updateNativeHandleInMeta(
            OMX_U32 port_index,
            const sp<NativeHandle> &nativeHandle, buffer_id buffer) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(port_index);
        data.writeInt32(nativeHandle != NULL);
        if (nativeHandle != NULL) {
            data.writeNativeHandle(nativeHandle->handle());
        }
        data.writeInt32((int32_t)buffer);
        remote()->transact(UPDATE_NATIVE_HANDLE_IN_META, data, &reply);

        status_t err = reply.readInt32();
        return err;
    }

    virtual status_t createInputSurface(
            OMX_U32 port_index, android_dataspace dataSpace,
            sp<IGraphicBufferProducer> *bufferProducer,
            sp<IGraphicBufferSource> *bufferSource,
            MetadataBufferType *type) {
        Parcel data, reply;
        status_t err;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(port_index);
        data.writeInt32(dataSpace);
        err = remote()->transact(CREATE_INPUT_SURFACE, data, &reply);
        if (err != OK) {
            ALOGW("binder transaction failed: %d", err);
            return err;
        }

        // read type even if createInputSurface failed
        int negotiatedType = reply.readInt32();
        if (type != NULL) {
            *type = (MetadataBufferType)negotiatedType;
        }

        err = reply.readInt32();
        if (err != OK) {
            return err;
        }

        *bufferProducer = IGraphicBufferProducer::asInterface(
                reply.readStrongBinder());
        *bufferSource = IGraphicBufferSource::asInterface(
                reply.readStrongBinder());

        return err;
    }

    virtual status_t setInputSurface(
            OMX_U32 port_index,
            const sp<IGraphicBufferConsumer> &bufferConsumer,
            sp<IGraphicBufferSource> *bufferSource,
            MetadataBufferType *type) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        status_t err;
        data.writeInt32(port_index);
        data.writeStrongBinder(IInterface::asBinder(bufferConsumer));

        err = remote()->transact(SET_INPUT_SURFACE, data, &reply);

        if (err != OK) {
            ALOGW("binder transaction failed: %d", err);
            return err;
        }

        // read type even if setInputSurface failed
        int negotiatedType = reply.readInt32();
        if (type != NULL) {
            *type = (MetadataBufferType)negotiatedType;
        }

        err = reply.readInt32();
        if (err != OK) {
            return err;
        }

        *bufferSource = IGraphicBufferSource::asInterface(
                reply.readStrongBinder());

        return err;
    }

    virtual status_t storeMetaDataInBuffers(
            OMX_U32 port_index, OMX_BOOL enable, MetadataBufferType *type) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(port_index);
        data.writeInt32((int32_t)enable);
        data.writeInt32(type == NULL ? kMetadataBufferTypeANWBuffer : *type);

        remote()->transact(STORE_META_DATA_IN_BUFFERS, data, &reply);

        // read type even storeMetaDataInBuffers failed
        int negotiatedType = reply.readInt32();
        if (type != NULL) {
            *type = (MetadataBufferType)negotiatedType;
        }

        return reply.readInt32();
    }

    virtual status_t prepareForAdaptivePlayback(
            OMX_U32 port_index, OMX_BOOL enable,
            OMX_U32 max_width, OMX_U32 max_height) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(port_index);
        data.writeInt32((int32_t)enable);
        data.writeInt32(max_width);
        data.writeInt32(max_height);
        remote()->transact(PREPARE_FOR_ADAPTIVE_PLAYBACK, data, &reply);

        status_t err = reply.readInt32();
        return err;
    }

    virtual status_t configureVideoTunnelMode(
            OMX_U32 portIndex, OMX_BOOL tunneled,
            OMX_U32 audioHwSync, native_handle_t **sidebandHandle ) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(portIndex);
        data.writeInt32((int32_t)tunneled);
        data.writeInt32(audioHwSync);
        remote()->transact(CONFIGURE_VIDEO_TUNNEL_MODE, data, &reply);

        status_t err = reply.readInt32();
        if (err == OK && sidebandHandle) {
            *sidebandHandle = (native_handle_t *)reply.readNativeHandle();
        }
        return err;
    }


    virtual status_t allocateSecureBuffer(
            OMX_U32 port_index, size_t size,
            buffer_id *buffer, void **buffer_data, sp<NativeHandle> *native_handle) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(port_index);
        data.writeInt64(size);
        remote()->transact(ALLOC_SECURE_BUFFER, data, &reply);

        status_t err = reply.readInt32();
        if (err != OK) {
            *buffer = 0;
            *buffer_data = NULL;
            *native_handle = NULL;
            return err;
        }

        *buffer = (buffer_id)reply.readInt32();
        *buffer_data = (void *)reply.readInt64();
        if (*buffer_data == NULL) {
            *native_handle = NativeHandle::create(
                    reply.readNativeHandle(), true /* ownsHandle */);
        } else {
            *native_handle = NULL;
        }
        return err;
    }

    virtual status_t allocateBufferWithBackup(
            OMX_U32 port_index, const sp<IMemory> &params,
            buffer_id *buffer, OMX_U32 allottedSize) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(port_index);
        data.writeStrongBinder(IInterface::asBinder(params));
        data.writeInt32(allottedSize);
        remote()->transact(ALLOC_BUFFER_WITH_BACKUP, data, &reply);

        status_t err = reply.readInt32();
        if (err != OK) {
            *buffer = 0;

            return err;
        }

        *buffer = (buffer_id)reply.readInt32();

        return err;
    }

    virtual status_t freeBuffer(
            OMX_U32 port_index, buffer_id buffer) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(port_index);
        data.writeInt32((int32_t)buffer);
        remote()->transact(FREE_BUFFER, data, &reply);

        return reply.readInt32();
    }

    virtual status_t fillBuffer(buffer_id buffer, int fenceFd) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32((int32_t)buffer);
        data.writeInt32(fenceFd >= 0);
        if (fenceFd >= 0) {
            data.writeFileDescriptor(fenceFd, true /* takeOwnership */);
        }
        remote()->transact(FILL_BUFFER, data, &reply);

        return reply.readInt32();
    }

    virtual status_t emptyBuffer(
            buffer_id buffer,
            OMX_U32 range_offset, OMX_U32 range_length,
            OMX_U32 flags, OMX_TICKS timestamp, int fenceFd) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32((int32_t)buffer);
        data.writeInt32(range_offset);
        data.writeInt32(range_length);
        data.writeInt32(flags);
        data.writeInt64(timestamp);
        data.writeInt32(fenceFd >= 0);
        if (fenceFd >= 0) {
            data.writeFileDescriptor(fenceFd, true /* takeOwnership */);
        }
        remote()->transact(EMPTY_BUFFER, data, &reply);

        return reply.readInt32();
    }

    virtual status_t emptyGraphicBuffer(
            buffer_id buffer,
            const sp<GraphicBuffer> &graphicBuffer, OMX_U32 flags,
            OMX_TICKS timestamp, OMX_TICKS origTimestamp, int fenceFd) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32((int32_t)buffer);
        data.write(*graphicBuffer);
        data.writeInt32(flags);
        data.writeInt64(timestamp);
        data.writeInt64(origTimestamp);
        data.writeInt32(fenceFd >= 0);
        if (fenceFd >= 0) {
            data.writeFileDescriptor(fenceFd, true /* takeOwnership */);
        }
        remote()->transact(EMPTY_GRAPHIC_BUFFER, data, &reply);

        return reply.readInt32();
    }

    virtual status_t getExtensionIndex(
            const char *parameter_name,
            OMX_INDEXTYPE *index) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeCString(parameter_name);

        remote()->transact(GET_EXTENSION_INDEX, data, &reply);

        status_t err = reply.readInt32();
        if (err == OK) {
            *index = static_cast<OMX_INDEXTYPE>(reply.readInt32());
        } else {
            *index = OMX_IndexComponentStartUnused;
        }

        return err;
    }

    virtual status_t dispatchMessage(const omx_message &msg) {
        Parcel data, reply;
        data.writeInterfaceToken(IOMXNode::getInterfaceDescriptor());
        data.writeInt32(msg.fenceFd >= 0);
        if (msg.fenceFd >= 0) {
            data.writeFileDescriptor(msg.fenceFd, true /* takeOwnership */);
        }
        data.writeInt32(msg.type);
        data.write(&msg.u, sizeof(msg.u));

        remote()->transact(DISPATCH_MESSAGE, data, &reply);

        return reply.readInt32();
    }
};

IMPLEMENT_META_INTERFACE(OMX, "android.hardware.IOMX");
IMPLEMENT_META_INTERFACE(OMXNode, "android.hardware.IOMXNode");

////////////////////////////////////////////////////////////////////////////////

#define CHECK_OMX_INTERFACE(interface, data, reply) \
        do { if (!(data).enforceInterface(interface::getInterfaceDescriptor())) { \
            ALOGW("Call incorrectly routed to " #interface); \
            return PERMISSION_DENIED; \
        } } while (0)

status_t BnOMX::onTransact(
    uint32_t code, const Parcel &data, Parcel *reply, uint32_t flags) {
    switch (code) {
        case LIST_NODES:
        {
            CHECK_OMX_INTERFACE(IOMX, data, reply);

            List<ComponentInfo> list;
            listNodes(&list);

            reply->writeInt32(list.size());
            for (List<ComponentInfo>::iterator it = list.begin();
                 it != list.end(); ++it) {
                ComponentInfo &cur = *it;

                reply->writeString8(cur.mName);
                reply->writeInt32(cur.mRoles.size());
                for (List<String8>::iterator role_it = cur.mRoles.begin();
                     role_it != cur.mRoles.end(); ++role_it) {
                    reply->writeString8(*role_it);
                }
            }

            return NO_ERROR;
        }

        case ALLOCATE_NODE:
        {
            CHECK_OMX_INTERFACE(IOMX, data, reply);

            const char *name = data.readCString();

            sp<IOMXObserver> observer =
                interface_cast<IOMXObserver>(data.readStrongBinder());

            if (name == NULL || observer == NULL) {
                ALOGE("b/26392700");
                reply->writeInt32(INVALID_OPERATION);
                return NO_ERROR;
            }

            sp<IOMXNode> omxNode;

            status_t err = allocateNode(
                    name, observer, NULL /* nodeBinder */, &omxNode);

            reply->writeInt32(err);
            if (err == OK) {
                reply->writeStrongBinder(IInterface::asBinder(omxNode));
            }

            return NO_ERROR;
        }

        case CREATE_PERSISTENT_INPUT_SURFACE:
        {
            CHECK_OMX_INTERFACE(IOMX, data, reply);

            sp<IGraphicBufferProducer> bufferProducer;
            sp<IGraphicBufferConsumer> bufferConsumer;
            status_t err = createPersistentInputSurface(
                    &bufferProducer, &bufferConsumer);

            reply->writeInt32(err);

            if (err == OK) {
                reply->writeStrongBinder(IInterface::asBinder(bufferProducer));
                reply->writeStrongBinder(IInterface::asBinder(bufferConsumer));
            }

            return NO_ERROR;
        }

        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
}

status_t BnOMXNode::onTransact(
    uint32_t code, const Parcel &data, Parcel *reply, uint32_t flags) {
    switch (code) {
        case FREE_NODE:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            reply->writeInt32(freeNode());

            return NO_ERROR;
        }

        case SEND_COMMAND:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            OMX_COMMANDTYPE cmd =
                static_cast<OMX_COMMANDTYPE>(data.readInt32());

            OMX_S32 param = data.readInt32();
            reply->writeInt32(sendCommand(cmd, param));

            return NO_ERROR;
        }

        case GET_PARAMETER:
        case SET_PARAMETER:
        case GET_CONFIG:
        case SET_CONFIG:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            OMX_INDEXTYPE index = static_cast<OMX_INDEXTYPE>(data.readInt32());

            size_t size = data.readInt64();

            status_t err = NOT_ENOUGH_DATA;
            void *params = NULL;
            size_t pageSize = 0;
            size_t allocSize = 0;
            bool isUsageBits = (index == (OMX_INDEXTYPE) OMX_IndexParamConsumerUsageBits);
            if ((isUsageBits && size < 4) || (!isUsageBits && size < 8)) {
                // we expect the structure to contain at least the size and
                // version, 8 bytes total
                ALOGE("b/27207275 (%zu) (%d/%d)", size, int(index), int(code));
                android_errorWriteLog(0x534e4554, "27207275");
            } else {
                err = NO_MEMORY;
                pageSize = (size_t) sysconf(_SC_PAGE_SIZE);
                if (size > SIZE_MAX - (pageSize * 2)) {
                    ALOGE("requested param size too big");
                } else {
                    allocSize = (size + pageSize * 2) & ~(pageSize - 1);
                    params = mmap(NULL, allocSize, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1 /* fd */, 0 /* offset */);
                }
                if (params != MAP_FAILED) {
                    err = data.read(params, size);
                    if (err != OK) {
                        android_errorWriteLog(0x534e4554, "26914474");
                    } else {
                        err = NOT_ENOUGH_DATA;
                        OMX_U32 declaredSize = *(OMX_U32*)params;
                        if (index != (OMX_INDEXTYPE) OMX_IndexParamConsumerUsageBits &&
                                declaredSize > size) {
                            // the buffer says it's bigger than it actually is
                            ALOGE("b/27207275 (%u/%zu)", declaredSize, size);
                            android_errorWriteLog(0x534e4554, "27207275");
                        } else {
                            // mark the last page as inaccessible, to avoid exploitation
                            // of codecs that access past the end of the allocation because
                            // they didn't check the size
                            if (mprotect((char*)params + allocSize - pageSize, pageSize,
                                    PROT_NONE) != 0) {
                                ALOGE("mprotect failed: %s", strerror(errno));
                            } else {
                                switch (code) {
                                    case GET_PARAMETER:
                                        err = getParameter(index, params, size);
                                        break;
                                    case SET_PARAMETER:
                                        err = setParameter(index, params, size);
                                        break;
                                    case GET_CONFIG:
                                        err = getConfig(index, params, size);
                                        break;
                                    case SET_CONFIG:
                                        err = setConfig(index, params, size);
                                        break;
                                    default:
                                        TRESPASS();
                                }
                            }
                        }
                    }
                } else {
                    ALOGE("couldn't map: %s", strerror(errno));
                }
            }

            reply->writeInt32(err);

            if ((code == GET_PARAMETER || code == GET_CONFIG) && err == OK) {
                reply->write(params, size);
            }

            if (params) {
                munmap(params, allocSize);
            }
            params = NULL;

            return NO_ERROR;
        }

        case GET_STATE:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            OMX_STATETYPE state = OMX_StateInvalid;

            status_t err = getState(&state);
            reply->writeInt32(state);
            reply->writeInt32(err);

            return NO_ERROR;
        }

        case ENABLE_NATIVE_BUFFERS:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            OMX_U32 port_index = data.readInt32();
            OMX_BOOL graphic = (OMX_BOOL)data.readInt32();
            OMX_BOOL enable = (OMX_BOOL)data.readInt32();

            status_t err = enableNativeBuffers(port_index, graphic, enable);
            reply->writeInt32(err);

            return NO_ERROR;
        }

        case GET_GRAPHIC_BUFFER_USAGE:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            OMX_U32 port_index = data.readInt32();

            OMX_U32 usage = 0;
            status_t err = getGraphicBufferUsage(port_index, &usage);
            reply->writeInt32(err);
            reply->writeInt32(usage);

            return NO_ERROR;
        }

        case USE_BUFFER:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            OMX_U32 port_index = data.readInt32();
            sp<IMemory> params =
                interface_cast<IMemory>(data.readStrongBinder());
            OMX_U32 allottedSize = data.readInt32();

            if (params == NULL) {
                ALOGE("b/26392700");
                reply->writeInt32(INVALID_OPERATION);
                return NO_ERROR;
            }

            buffer_id buffer;
            status_t err = useBuffer(port_index, params, &buffer, allottedSize);
            reply->writeInt32(err);

            if (err == OK) {
                reply->writeInt32((int32_t)buffer);
            }

            return NO_ERROR;
        }

        case USE_GRAPHIC_BUFFER:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            OMX_U32 port_index = data.readInt32();
            sp<GraphicBuffer> graphicBuffer = new GraphicBuffer();
            data.read(*graphicBuffer);

            buffer_id buffer;
            status_t err = useGraphicBuffer(
                    port_index, graphicBuffer, &buffer);
            reply->writeInt32(err);

            if (err == OK) {
                reply->writeInt32((int32_t)buffer);
            }

            return NO_ERROR;
        }

        case UPDATE_GRAPHIC_BUFFER_IN_META:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            OMX_U32 port_index = data.readInt32();
            sp<GraphicBuffer> graphicBuffer = new GraphicBuffer();
            data.read(*graphicBuffer);
            buffer_id buffer = (buffer_id)data.readInt32();

            status_t err = updateGraphicBufferInMeta(
                    port_index, graphicBuffer, buffer);
            reply->writeInt32(err);

            return NO_ERROR;
        }

        case UPDATE_NATIVE_HANDLE_IN_META:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            OMX_U32 port_index = data.readInt32();
            native_handle *handle = NULL;
            if (data.readInt32()) {
                handle = data.readNativeHandle();
            }
            buffer_id buffer = (buffer_id)data.readInt32();

            status_t err = updateNativeHandleInMeta(
                    port_index, NativeHandle::create(handle, true /* ownshandle */), buffer);
            reply->writeInt32(err);

            return NO_ERROR;
        }

        case CREATE_INPUT_SURFACE:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            OMX_U32 port_index = data.readInt32();
            android_dataspace dataSpace = (android_dataspace)data.readInt32();

            sp<IGraphicBufferProducer> bufferProducer;
            sp<IGraphicBufferSource> bufferSource;
            MetadataBufferType type = kMetadataBufferTypeInvalid;
            status_t err = createInputSurface(
                    port_index, dataSpace, &bufferProducer, &bufferSource, &type);

            if ((err != OK) && (type == kMetadataBufferTypeInvalid)) {
                android_errorWriteLog(0x534e4554, "26324358");
            }

            reply->writeInt32(type);
            reply->writeInt32(err);

            if (err == OK) {
                reply->writeStrongBinder(IInterface::asBinder(bufferProducer));
                reply->writeStrongBinder(IInterface::asBinder(bufferSource));
            }

            return NO_ERROR;
        }

        case SET_INPUT_SURFACE:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            OMX_U32 port_index = data.readInt32();

            sp<IGraphicBufferConsumer> bufferConsumer =
                    interface_cast<IGraphicBufferConsumer>(data.readStrongBinder());

            sp<IGraphicBufferSource> bufferSource;
            MetadataBufferType type = kMetadataBufferTypeInvalid;

            status_t err = INVALID_OPERATION;
            if (bufferConsumer == NULL) {
                ALOGE("b/26392700");
            } else {
                err = setInputSurface(port_index, bufferConsumer, &bufferSource, &type);

                if ((err != OK) && (type == kMetadataBufferTypeInvalid)) {
                   android_errorWriteLog(0x534e4554, "26324358");
                }
            }

            reply->writeInt32(type);
            reply->writeInt32(err);
            if (err == OK) {
                reply->writeStrongBinder(IInterface::asBinder(bufferSource));
            }
            return NO_ERROR;
        }

        case STORE_META_DATA_IN_BUFFERS:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            OMX_U32 port_index = data.readInt32();
            OMX_BOOL enable = (OMX_BOOL)data.readInt32();

            MetadataBufferType type = (MetadataBufferType)data.readInt32();
            status_t err = storeMetaDataInBuffers(port_index, enable, &type);

            reply->writeInt32(type);
            reply->writeInt32(err);

            return NO_ERROR;
        }

        case PREPARE_FOR_ADAPTIVE_PLAYBACK:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            OMX_U32 port_index = data.readInt32();
            OMX_BOOL enable = (OMX_BOOL)data.readInt32();
            OMX_U32 max_width = data.readInt32();
            OMX_U32 max_height = data.readInt32();

            status_t err = prepareForAdaptivePlayback(
                    port_index, enable, max_width, max_height);
            reply->writeInt32(err);

            return NO_ERROR;
        }

        case CONFIGURE_VIDEO_TUNNEL_MODE:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            OMX_U32 port_index = data.readInt32();
            OMX_BOOL tunneled = (OMX_BOOL)data.readInt32();
            OMX_U32 audio_hw_sync = data.readInt32();

            native_handle_t *sideband_handle = NULL;
            status_t err = configureVideoTunnelMode(
                    port_index, tunneled, audio_hw_sync, &sideband_handle);
            reply->writeInt32(err);
            if(err == OK){
                reply->writeNativeHandle(sideband_handle);
            }

            return NO_ERROR;
        }

        case ALLOC_SECURE_BUFFER:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            OMX_U32 port_index = data.readInt32();
            if (!isSecure() || port_index != 0 /* kPortIndexInput */) {
                ALOGE("b/24310423");
                reply->writeInt32(INVALID_OPERATION);
                return NO_ERROR;
            }

            size_t size = data.readInt64();

            buffer_id buffer;
            void *buffer_data = NULL;
            sp<NativeHandle> native_handle;
            status_t err = allocateSecureBuffer(
                    port_index, size, &buffer, &buffer_data, &native_handle);
            reply->writeInt32(err);

            if (err == OK) {
                reply->writeInt32((int32_t)buffer);
                reply->writeInt64((uintptr_t)buffer_data);
                if (buffer_data == NULL) {
                    reply->writeNativeHandle(native_handle == NULL ? NULL : native_handle->handle());
                }
            }

            return NO_ERROR;
        }

        case ALLOC_BUFFER_WITH_BACKUP:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            OMX_U32 port_index = data.readInt32();
            sp<IMemory> params =
                interface_cast<IMemory>(data.readStrongBinder());
            OMX_U32 allottedSize = data.readInt32();

            if (params == NULL) {
                ALOGE("b/26392700");
                reply->writeInt32(INVALID_OPERATION);
                return NO_ERROR;
            }

            buffer_id buffer;
            status_t err = allocateBufferWithBackup(
                    port_index, params, &buffer, allottedSize);

            reply->writeInt32(err);

            if (err == OK) {
                reply->writeInt32((int32_t)buffer);
            }

            return NO_ERROR;
        }

        case FREE_BUFFER:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            OMX_U32 port_index = data.readInt32();
            buffer_id buffer = (buffer_id)data.readInt32();
            reply->writeInt32(freeBuffer(port_index, buffer));

            return NO_ERROR;
        }

        case FILL_BUFFER:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            buffer_id buffer = (buffer_id)data.readInt32();
            bool haveFence = data.readInt32();
            int fenceFd = haveFence ? ::dup(data.readFileDescriptor()) : -1;
            reply->writeInt32(fillBuffer(buffer, fenceFd));

            return NO_ERROR;
        }

        case EMPTY_BUFFER:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            buffer_id buffer = (buffer_id)data.readInt32();
            OMX_U32 range_offset = data.readInt32();
            OMX_U32 range_length = data.readInt32();
            OMX_U32 flags = data.readInt32();
            OMX_TICKS timestamp = data.readInt64();
            bool haveFence = data.readInt32();
            int fenceFd = haveFence ? ::dup(data.readFileDescriptor()) : -1;
            reply->writeInt32(emptyBuffer(
                    buffer, range_offset, range_length, flags, timestamp, fenceFd));

            return NO_ERROR;
        }

        case EMPTY_GRAPHIC_BUFFER:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            buffer_id buffer = (buffer_id)data.readInt32();
            sp<GraphicBuffer> graphicBuffer = new GraphicBuffer();
            data.read(*graphicBuffer);
            OMX_U32 flags = data.readInt32();
            OMX_TICKS timestamp = data.readInt64();
            OMX_TICKS origTimestamp = data.readInt64();
            bool haveFence = data.readInt32();
            int fenceFd = haveFence ? ::dup(data.readFileDescriptor()) : -1;
            reply->writeInt32(emptyGraphicBuffer(
                    buffer, graphicBuffer, flags,
                    timestamp, origTimestamp, fenceFd));

            return NO_ERROR;
        }

        case GET_EXTENSION_INDEX:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);

            const char *parameter_name = data.readCString();

            if (parameter_name == NULL) {
                ALOGE("b/26392700");
                reply->writeInt32(INVALID_OPERATION);
                return NO_ERROR;
            }

            OMX_INDEXTYPE index;
            status_t err = getExtensionIndex(parameter_name, &index);

            reply->writeInt32(err);

            if (err == OK) {
                reply->writeInt32(index);
            }

            return OK;
        }

        case DISPATCH_MESSAGE:
        {
            CHECK_OMX_INTERFACE(IOMXNode, data, reply);
            omx_message msg;
            int haveFence = data.readInt32();
            msg.fenceFd = haveFence ? ::dup(data.readFileDescriptor()) : -1;
            msg.type = (typeof(msg.type))data.readInt32();
            status_t err = data.read(&msg.u, sizeof(msg.u));

            if (err == OK) {
                err = dispatchMessage(msg);
            }
            reply->writeInt32(err);

            return NO_ERROR;
        }

        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
}

////////////////////////////////////////////////////////////////////////////////

class BpOMXObserver : public BpInterface<IOMXObserver> {
public:
    explicit BpOMXObserver(const sp<IBinder> &impl)
        : BpInterface<IOMXObserver>(impl) {
    }

    virtual void onMessages(const std::list<omx_message> &messages) {
        Parcel data, reply;
        std::list<omx_message>::const_iterator it = messages.cbegin();
        if (messages.empty()) {
            return;
        }
        data.writeInterfaceToken(IOMXObserver::getInterfaceDescriptor());
        while (it != messages.cend()) {
            const omx_message &msg = *it++;
            data.writeInt32(msg.fenceFd >= 0);
            if (msg.fenceFd >= 0) {
                data.writeFileDescriptor(msg.fenceFd, true /* takeOwnership */);
            }
            data.writeInt32(msg.type);
            data.write(&msg.u, sizeof(msg.u));
            ALOGV("onMessage writing message %d, size %zu", msg.type, sizeof(msg));
        }
        data.writeInt32(-1); // mark end
        remote()->transact(OBSERVER_ON_MSG, data, &reply, IBinder::FLAG_ONEWAY);
    }
};

IMPLEMENT_META_INTERFACE(OMXObserver, "android.hardware.IOMXObserver");

status_t BnOMXObserver::onTransact(
    uint32_t code, const Parcel &data, Parcel *reply, uint32_t flags) {
    switch (code) {
        case OBSERVER_ON_MSG:
        {
            CHECK_OMX_INTERFACE(IOMXObserver, data, reply);
            std::list<omx_message> messages;
            status_t err = FAILED_TRANSACTION; // must receive at least one message
            do {
                int haveFence = data.readInt32();
                if (haveFence < 0) { // we use -1 to mark end of messages
                    break;
                }
                omx_message msg;
                msg.fenceFd = haveFence ? ::dup(data.readFileDescriptor()) : -1;
                msg.type = (typeof(msg.type))data.readInt32();
                err = data.read(&msg.u, sizeof(msg.u));
                ALOGV("onTransact reading message %d, size %zu", msg.type, sizeof(msg));
                messages.push_back(msg);
            } while (err == OK);

            if (err == OK) {
                onMessages(messages);
            }

            return err;
        }

        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
}

}  // namespace android
