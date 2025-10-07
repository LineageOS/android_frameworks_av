/*
 * Copyright (C) 2025 The Android Open Source Project
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

#pragma once

#include <memory>
#include <vector>

#include <C2Component.h>

#include <apex/ApexCodecs.h>
#include <apex/ApexCodecsParam.h>

/**
 * A buffer object is a container for data that is processed by a component.
 * It can hold a linear buffer, a graphic buffer, or be empty. It also carries
 * buffer metadata like flags, timestamp, and frame index. Additionally, it can
 * carry configuration updates.
 */
struct ApexCodec_Buffer {
public:
    ApexCodec_Buffer();
    ~ApexCodec_Buffer();

    /**
     * Clears the buffer object to an empty state.
     *
     * Resets the buffer to its initial state, same as after construction.
     * This does not free the underlying linear or graphic buffers if they are not
     * owned by this object. It will free owned config updates.
     */
    void clear();

    /**
     * Gets the type of the buffer.
     *
     * \return The type of the buffer, e.g., APEXCODEC_BUFFER_TYPE_LINEAR,
     *         APEXCODEC_BUFFER_TYPE_GRAPHIC, or APEXCODEC_BUFFER_TYPE_EMPTY.
     */
    ApexCodec_BufferType getType() const;

    /**
     * Sets the buffer's metadata.
     *
     * \param flags The flags associated with the buffer.
     * \param frameIndex The frame index for the buffer.
     * \param timestampUs The timestamp for the buffer in microseconds.
     */
    void setBufferInfo(ApexCodec_BufferFlags flags, uint64_t frameIndex, uint64_t timestampUs);

    /**
     * Sets a linear buffer to this buffer object.
     *
     * The buffer must be empty before calling this method.
     *
     * \param linearBuffer A pointer to the linear buffer. May be null to indicate
     *                     an empty linear buffer, which can be used to communicate
     *                     only flags and/or config updates.
     * \return APEXCODEC_STATUS_OK on success, or APEXCODEC_STATUS_BAD_STATE if the
     *         buffer is not empty.
     */
    ApexCodec_Status setLinearBuffer(const ApexCodec_LinearBuffer *linearBuffer);

    /**
     * Sets a graphic buffer to this buffer object.
     *
     * The buffer must be empty before calling this method.
     *
     * \param graphicBuffer A pointer to the AHardwareBuffer. May be null to
     *                      indicate an empty graphic buffer, which can be used to
     *                      communicate only flags and/or config updates.
     * \return APEXCODEC_STATUS_OK on success, or APEXCODEC_STATUS_BAD_STATE if the
     *         buffer is not empty.
     */
    ApexCodec_Status setGraphicBuffer(AHardwareBuffer *graphicBuffer);

    /**
     * Sets configuration updates to this buffer object.
     *
     * These updates are sent to the component for a specific input frame. This
     * should not be called for output buffers. This method can only be called
     * once until the buffer is cleared. The buffer does not take ownership of
     * the memory pointed to by |configUpdates|.
     *
     * \param configUpdates A pointer to the linear buffer containing config
     *                      updates.
     * \return APEXCODEC_STATUS_OK on success, or APEXCODEC_STATUS_BAD_STATE if
     *         config updates are already set.
     */
    ApexCodec_Status setConfigUpdates(const ApexCodec_LinearBuffer *configUpdates);

    /**
     * Retrieves the buffer's metadata.
     *
     * \param[out] outFlags Pointer to store the buffer flags.
     * \param[out] outFrameIndex Pointer to store the frame index.
     * \param[out] outTimestampUs Pointer to store the timestamp in microseconds.
     * \return APEXCODEC_STATUS_OK on success, or APEXCODEC_STATUS_BAD_STATE if
     *         buffer info was not set.
     */
    ApexCodec_Status getBufferInfo(
            ApexCodec_BufferFlags *outFlags,
            uint64_t *outFrameIndex,
            uint64_t *outTimestampUs) const;

    /**
     * Retrieves the linear buffer.
     *
     * \param[out] outLinearBuffer Pointer to store the linear buffer information.
     * \return APEXCODEC_STATUS_OK on success, or APEXCODEC_STATUS_BAD_STATE if the
     *         buffer is not a linear buffer.
     */
    ApexCodec_Status getLinearBuffer(ApexCodec_LinearBuffer *outLinearBuffer) const;

    /**
     * Retrieves the graphic buffer.
     *
     * \param[out] outGraphicBuffer Pointer to store the AHardwareBuffer pointer.
     * \return APEXCODEC_STATUS_OK on success, or APEXCODEC_STATUS_BAD_STATE if the
     *         buffer is not a graphic buffer.
     */
    ApexCodec_Status getGraphicBuffer(AHardwareBuffer **outGraphicBuffer) const;

    /**
     * Retrieves the configuration updates from the buffer.
     *
     * \param[out] outConfigUpdates Pointer to store the config updates.
     * \param[out] outOwnedByClient Pointer to a boolean that is set to true if the
     *                              client owns the config updates memory, or false
     *                              if the buffer object owns it.
     * \return APEXCODEC_STATUS_OK on success, or APEXCODEC_STATUS_NOT_FOUND if the
     *         buffer does not contain config updates.
     */
    ApexCodec_Status getConfigUpdates(
            ApexCodec_LinearBuffer *outConfigUpdates,
            bool *outOwnedByClient) const;

    /**
     * Sets configuration updates that are owned by this buffer object.
     *
     * The buffer takes ownership of the provided vector.
     *
     * \param configUpdates An rvalue reference to a vector containing the config
     *                      updates.
     */
    void setOwnedConfigUpdates(std::vector<uint8_t> &&configUpdates);

private:
    struct BufferInfo {
        ApexCodec_BufferFlags flags;
        uint64_t frameIndex;
        uint64_t timestampUs;
    };

    ApexCodec_BufferType mType;
    std::optional<BufferInfo> mBufferInfo;
    ApexCodec_LinearBuffer mLinearBuffer;
    AHardwareBuffer *mGraphicBuffer;
    std::optional<ApexCodec_LinearBuffer> mConfigUpdates;
    std::optional<std::vector<uint8_t>> mOwnedConfigUpdates;
};

namespace android::apexcodecs {

class ApexConfigurableIntf {
public:
    virtual ~ApexConfigurableIntf() = default;

    virtual ApexCodec_Status config(
            const std::vector<C2Param *> &params,
            std::vector<std::unique_ptr<C2SettingResult>> *results) const = 0;

    virtual ApexCodec_Status query(
            const std::vector<C2Param::Index> &heapParamIndices,
            std::vector<std::unique_ptr<C2Param>>* const heapParams) const = 0;

    virtual ApexCodec_Status querySupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>> * const params) const = 0;

    virtual ApexCodec_Status querySupportedValues(
            std::vector<C2FieldSupportedValuesQuery> &fields) const = 0;
};

class ApexComponentIntf {
public:
    virtual ~ApexComponentIntf() = default;
    virtual ApexCodec_Status start() = 0;
    virtual ApexCodec_Status flush() = 0;
    virtual ApexCodec_Status reset() = 0;
    virtual std::unique_ptr<ApexConfigurableIntf> getConfigurable() = 0;
    virtual ApexCodec_Status process(
            const ApexCodec_Buffer *input,
            ApexCodec_Buffer *output,
            size_t *consumed,
            size_t *produced) = 0;
};

class ApexComponentStoreIntf {
public:
    virtual ~ApexComponentStoreIntf() = default;
    virtual std::vector<std::shared_ptr<const C2Component::Traits>> listComponents() const = 0;
    virtual std::unique_ptr<ApexComponentIntf> createComponent(const char *name) = 0;
    virtual std::shared_ptr<C2ParamReflector> getParamReflector() const = 0;
};

}  // namespace android

__BEGIN_DECLS

void *GetApexComponentStore();

__END_DECLS
