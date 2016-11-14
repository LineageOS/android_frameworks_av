/*
 * Copyright (C) 2014 The Android Open Source Project
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

#ifndef CODEC_BASE_H_

#define CODEC_BASE_H_

#include <memory>

#include <stdint.h>

#define STRINGIFY_ENUMS

#include <media/IOMX.h>
#include <media/MediaCodecInfo.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/foundation/AHandler.h>
#include <media/stagefright/foundation/ColorUtils.h>
#include <media/hardware/HardwareAPI.h>

#include <utils/NativeHandle.h>

#include <system/graphics.h>

namespace android {

class BufferProducerWrapper;
class MediaCodecBuffer;
struct PersistentSurface;
struct RenderedFrameInfo;
class Surface;

struct CodecBase : public AHandler, /* static */ ColorUtils {
    struct PortDescription;

    /**
     * This interface defines events firing from CodecBase back to MediaCodec.
     * All methods must not block.
     */
    class Callback {
    public:
        virtual ~Callback() = default;

        /**
         * Request MediaCodec to fill the specified input buffer.
         *
         * @param bufferId  ID of the buffer, assigned by underlying component.
         * @param buffer    a buffer to be filled.
         * @param reply     a message to post once MediaCodec has filled the
         *                  buffer.
         */
        virtual void fillThisBuffer(
                IOMX::buffer_id bufferId,
                const sp<MediaCodecBuffer> &buffer,
                const sp<AMessage> &reply) = 0;
        /**
         * Request MediaCodec to drain the specified output buffer.
         *
         * @param bufferId  ID of the buffer, assigned by underlying component.
         * @param buffer    a buffer to be filled.
         * @param flags     flags associated with this buffer (e.g. EOS).
         * @param reply     a message to post once MediaCodec has filled the
         *                  buffer.
         */
        virtual void drainThisBuffer(
                IOMX::buffer_id bufferId,
                const sp<MediaCodecBuffer> &buffer,
                int32_t flags,
                const sp<AMessage> &reply) = 0;
        /**
         * Notify MediaCodec for seeing an output EOS.
         *
         * @param err the underlying cause of the EOS. If the value is neither
         *            OK nor ERROR_END_OF_STREAM, the EOS is declared
         *            prematurely for that error.
         */
        virtual void onEos(status_t err) = 0;
        /**
         * Notify MediaCodec that stop operation is complete.
         */
        virtual void onStopCompleted() = 0;
        /**
         * Notify MediaCodec that release operation is complete.
         */
        virtual void onReleaseCompleted() = 0;
        /**
         * Notify MediaCodec that flush operation is complete.
         */
        virtual void onFlushCompleted() = 0;
        /**
         * Notify MediaCodec that an error is occurred.
         *
         * @param err         an error code for the occurred error.
         * @param actionCode  an action code for severity of the error.
         */
        virtual void onError(status_t err, enum ActionCode actionCode) = 0;
        /**
         * Notify MediaCodec that the underlying component is allocated.
         *
         * @param componentName the unique name of the component specified in
         *                      MediaCodecList.
         */
        virtual void onComponentAllocated(const char *componentName) = 0;
        /**
         * Notify MediaCodec that the underlying component is configured.
         *
         * @param inputFormat   an input format at configure time.
         * @param outputFormat  an output format at configure time.
         */
        virtual void onComponentConfigured(
                const sp<AMessage> &inputFormat, const sp<AMessage> &outputFormat) = 0;
        /**
         * Notify MediaCodec that the input surface is created.
         *
         * @param inputFormat   an input format at surface creation. Formats
         *                      could change from the previous state as a result
         *                      of creating a surface.
         * @param outputFormat  an output format at surface creation.
         * @param inputSurface  the created surface.
         */
        virtual void onInputSurfaceCreated(
                const sp<AMessage> &inputFormat,
                const sp<AMessage> &outputFormat,
                const sp<BufferProducerWrapper> &inputSurface) = 0;
        /**
         * Notify MediaCodec that the input surface creation is failed.
         *
         * @param err an error code of the cause.
         */
        virtual void onInputSurfaceCreationFailed(status_t err) = 0;
        /**
         * Notify MediaCodec that the component accepted the provided input
         * surface.
         *
         * @param inputFormat   an input format at surface assignment. Formats
         *                      could change from the previous state as a result
         *                      of assigning a surface.
         * @param outputFormat  an output format at surface assignment.
         */
        virtual void onInputSurfaceAccepted(
                const sp<AMessage> &inputFormat,
                const sp<AMessage> &outputFormat) = 0;
        /**
         * Notify MediaCodec that the component declined the provided input
         * surface.
         *
         * @param err an error code of the cause.
         */
        virtual void onInputSurfaceDeclined(status_t err) = 0;
        /**
         * Noitfy MediaCodec that the requested input EOS is sent to the input
         * surface.
         *
         * @param err an error code returned from the surface. If there is no
         *            input surface, the value is INVALID_OPERATION.
         */
        virtual void onSignaledInputEOS(status_t err) = 0;
        /**
         * Notify MediaCodec with the allocated buffers.
         *
         * @param portIndex zero for input port, one for output port.
         * @param portDesc  a PortDescription object containing allocated
         *                  buffers.
         */
        virtual void onBuffersAllocated(int32_t portIndex, const sp<PortDescription> &portDesc) = 0;
        /**
         * Notify MediaCodec that output frames are rendered with information on
         * those frames.
         *
         * @param done  a list of rendered frames.
         */
        virtual void onOutputFramesRendered(const std::list<RenderedFrameInfo> &done) = 0;
    };

    enum {
        kMaxCodecBufferSize = 8192 * 4096 * 4, // 8K RGBA
    };

    void setCallback(std::shared_ptr<Callback> &&callback);

    virtual void initiateAllocateComponent(const sp<AMessage> &msg) = 0;
    virtual void initiateConfigureComponent(const sp<AMessage> &msg) = 0;
    virtual void initiateCreateInputSurface() = 0;
    virtual void initiateSetInputSurface(
            const sp<PersistentSurface> &surface) = 0;
    virtual void initiateStart() = 0;
    virtual void initiateShutdown(bool keepComponentAllocated = false) = 0;

    // require an explicit message handler
    virtual void onMessageReceived(const sp<AMessage> &msg) = 0;

    virtual status_t queryCapabilities(
            const AString &name, const AString &mime, bool isEncoder,
            sp<MediaCodecInfo::Capabilities> *caps /* nonnull */) { return INVALID_OPERATION; }

    virtual status_t setSurface(const sp<Surface> &surface) { return INVALID_OPERATION; }

    virtual void signalFlush() = 0;
    virtual void signalResume() = 0;

    virtual void signalRequestIDRFrame() = 0;
    virtual void signalSetParameters(const sp<AMessage> &msg) = 0;
    virtual void signalEndOfInputStream() = 0;

    struct PortDescription : public RefBase {
        virtual size_t countBuffers() = 0;
        virtual IOMX::buffer_id bufferIDAt(size_t index) const = 0;
        virtual sp<MediaCodecBuffer> bufferAt(size_t index) const = 0;

    protected:
        PortDescription();
        virtual ~PortDescription();

    private:
        DISALLOW_EVIL_CONSTRUCTORS(PortDescription);
    };

    /*
     * Codec-related defines
     */

protected:
    CodecBase();
    virtual ~CodecBase();

    std::shared_ptr<Callback> mCallback;

private:
    DISALLOW_EVIL_CONSTRUCTORS(CodecBase);
};

}  // namespace android

#endif  // CODEC_BASE_H_

