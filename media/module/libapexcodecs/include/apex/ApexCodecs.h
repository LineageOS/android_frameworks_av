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

#pragma once

#include <sys/cdefs.h>
#include <errno.h>
#include <stdint.h>

#include <android/api-level.h>
#include <android/hardware_buffer.h>
#include <android/versioning.h>
#include <apex/ApexCodecsParam.h>

__BEGIN_DECLS

/**
 * An API to access and operate codecs implemented within an APEX module,
 * used only by the OS when using the codecs within a client process
 * (instead of via a HAL).
 *
 * NOTE: Many of the constants and types mirror the ones in the Codec 2.0 API.
 */

/**
 * Error code for ApexCodec APIs.
 *
 * Introduced in API 36.
 */
typedef enum ApexCodec_Status : int32_t {
    APEXCODEC_STATUS_OK        = 0,

    /* bad input */
    APEXCODEC_STATUS_BAD_VALUE = EINVAL,
    APEXCODEC_STATUS_BAD_INDEX = ENXIO,
    APEXCODEC_STATUS_CANNOT_DO = ENOTSUP,

    /* bad sequencing of events */
    APEXCODEC_STATUS_DUPLICATE = EEXIST,
    APEXCODEC_STATUS_NOT_FOUND = ENOENT,
    APEXCODEC_STATUS_BAD_STATE = EPERM,
    APEXCODEC_STATUS_BLOCKING  = EWOULDBLOCK,
    APEXCODEC_STATUS_CANCELED  = EINTR,

    /* bad environment */
    APEXCODEC_STATUS_NO_MEMORY = ENOMEM,
    APEXCODEC_STATUS_REFUSED   = EACCES,

    APEXCODEC_STATUS_TIMED_OUT = ETIMEDOUT,

    /* bad versioning */
    APEXCODEC_STATUS_OMITTED   = ENOSYS,

    /* unknown fatal */
    APEXCODEC_STATUS_CORRUPTED = EFAULT,
    APEXCODEC_STATUS_NO_INIT   = ENODEV,
} ApexCodec_Status;

/**
 * Enum that represents the kind of component
 *
 * Introduced in API 36.
 */
typedef enum ApexCodec_Kind : uint32_t {
    /**
     * The component is of a kind that is not listed below.
     */
    APEXCODEC_KIND_OTHER = 0x0,
    /**
     * The component is a decoder, which decodes coded bitstream
     * into raw buffers.
     *
     * Introduced in API 36.
     */
    APEXCODEC_KIND_DECODER = 0x1,
    /**
     * The component is an encoder, which encodes raw buffers
     * into coded bitstream.
     *
     * Introduced in API 36.
     */
    APEXCODEC_KIND_ENCODER = 0x2,
} ApexCodec_Kind;

typedef enum ApexCodec_Domain : uint32_t {
    /**
     * A component domain that is not listed below.
     *
     * Introduced in API 36.
     */
    APEXCODEC_DOMAIN_OTHER = 0x0,
    /**
     * A component domain that operates on video.
     *
     * Introduced in API 36.
     */
    APEXCODEC_DOMAIN_VIDEO = 0x1,
    /**
     * A component domain that operates on audio.
     *
     * Introduced in API 36.
     */
    APEXCODEC_DOMAIN_AUDIO = 0x2,
    /**
     * A component domain that operates on image.
     *
     * Introduced in API 36.
     */
    APEXCODEC_DOMAIN_IMAGE = 0x3,
} ApexCodec_Domain;

/**
 * Handle for component traits such as name, media type, kind (decoder/encoder),
 * domain (audio/video/image), etc.
 *
 * Introduced in API 36.
 */
typedef struct ApexCodec_ComponentTraits {
    /**
     * The name of the component in ASCII encoding.
     */
    const char *_Nonnull name;
    /**
     * The supported media type of the component in ASCII encoding.
     */
    const char *_Nonnull mediaType;
    /**
     * The kind of the component.
     */
    ApexCodec_Kind kind;
    /**
     * The domain on which the component operates.
     */
    ApexCodec_Domain domain;
} ApexCodec_ComponentTraits;

/**
 * An opaque struct that represents a component store.
 *
 * Introduced in API 36.
 */
typedef struct ApexCodec_ComponentStore ApexCodec_ComponentStore;

/**
 * Get the component store object. This function never fails.
 *
 * \return component store object.
 */
ApexCodec_ComponentStore *_Nullable ApexCodec_GetComponentStore()
        __INTRODUCED_IN(36);

/**
 * Get the traits object of a component at given index. ApexCodecs_Traits_*
 * functions are used to extract information from the traits object.
 *
 * Returns nullptr if index is out of bounds. The returned object is owned by
 * ApexCodec_ComponentStore object and the client should not delete it.
 *
 * The client can iterate through the traits objects by calling this function
 * with an index incrementing from 0 until it gets a nullptr.
 *
 * \param index index of the traits object to query
 * \return traits object at the index, or nullptr if the index is out of bounds.
 */
ApexCodec_ComponentTraits *_Nullable ApexCodec_Traits_get(
        ApexCodec_ComponentStore *_Nonnull store, size_t index) __INTRODUCED_IN(36);

/**
 * An opaque struct that represents a codec.
 */
typedef struct ApexCodec_Component ApexCodec_Component;

/**
 * Create a component by the name.
 *
 * \param store the component store
 * \param name the name of the component in ASCII encoding
 * \param outComponent out-param to be filled with the component; must not be null
 * \return  APEXCODEC_STATUS_OK         if successful
 * \return  APEXCODEC_STATUS_NOT_FOUND  if the name is not found
 * \return  APEXCODEC_STATUS_CORRUPTED  if an unexpected error occurs
 */
ApexCodec_Status ApexCodec_Component_create(
        ApexCodec_ComponentStore *_Nonnull store,
        const char *_Nonnull name,
        ApexCodec_Component *_Nullable *_Nonnull outComponent) __INTRODUCED_IN(36);

/**
 * Destroy the component by the handle. It is invalid to call component methods on the handle
 * after calling this method. It is no-op to call this method with |comp| == nullptr.
 *
 * \param comp the handle for the component
 */
void ApexCodec_Component_destroy(ApexCodec_Component *_Nullable comp) __INTRODUCED_IN(36);

/**
 * Start the component. The component is ready to process buffers after this call.
 *
 * \param comp the handle for the component
 * \return  APEXCODEC_STATUS_OK         if successful
 * \return  APEXCODEC_STATUS_BAD_STATE  if the component is already started or released
 * \return  APEXCODEC_STATUS_CORRUPTED  if an unexpected error occurs
 */
ApexCodec_Status ApexCodec_Component_start(
        ApexCodec_Component *_Nonnull comp) __INTRODUCED_IN(36);

/**
 * Flush the component's internal states. This operation preserves the existing configurations.
 *
 * \param comp the handle for the component
 * \return  APEXCODEC_STATUS_OK         if successful
 * \return  APEXCODEC_STATUS_BAD_STATE  if the component is not started
 * \return  APEXCODEC_STATUS_CORRUPTED  if an unexpected error occurs
 */
ApexCodec_Status ApexCodec_Component_flush(
        ApexCodec_Component *_Nonnull comp) __INTRODUCED_IN(36);

/**
 * Resets the component to the initial state, right after creation. Note that the configuration
 * will also revert to the initial state, so if there are configurations required those should be
 * set again to use the component.
 *
 * \param comp the handle for the component
 * \return  APEXCODEC_STATUS_OK         if successful
 * \return  APEXCODEC_STATUS_CORRUPTED  if an unexpected error occurs
 */
ApexCodec_Status ApexCodec_Component_reset(
        ApexCodec_Component *_Nonnull comp) __INTRODUCED_IN(36);

/**
 * An opaque struct that represents a configurable part of the component.
 *
 * Introduced in API 36.
 */
typedef struct ApexCodec_Configurable ApexCodec_Configurable;

/**
 * Return the configurable object for the given ApexCodec_Component.
 * The returned object has the same lifecycle as |comp|.
 *
 * \param comp the handle for the component
 * \return the configurable object handle
 */
ApexCodec_Configurable *_Nonnull ApexCodec_Component_getConfigurable(
        ApexCodec_Component *_Nonnull comp) __INTRODUCED_IN(36);

/**
 * Enum that represents the flags for ApexCodec_Buffer.
 *
 * Introduced in API 36.
 */
typedef enum ApexCodec_BufferFlags : uint32_t {
    APEXCODEC_FLAG_DROP_FRAME    = (1 << 0),
    APEXCODEC_FLAG_END_OF_STREAM = (1 << 1),
    APEXCODEC_FLAG_DISCARD_FRAME = (1 << 2),
    APEXCODEC_FLAG_INCOMPLETE    = (1 << 3),
    APEXCODEC_FLAG_CORRECTED     = (1 << 4),
    APEXCODEC_FLAG_CORRUPT       = (1 << 5),
    APEXCODEC_FLAG_CODEC_CONFIG  = (1u << 31),
} ApexCodec_BufferFlags;

/**
 * Enum that represents the type of buffer.
 *
 * Introduced in API 36.
 */
typedef enum ApexCodec_BufferType : uint32_t {
    APEXCODEC_BUFFER_TYPE_EMPTY,
    APEXCODEC_BUFFER_TYPE_LINEAR,
    APEXCODEC_BUFFER_TYPE_LINEAR_CHUNKS,
    APEXCODEC_BUFFER_TYPE_GRAPHIC,
    APEXCODEC_BUFFER_TYPE_GRAPHIC_CHUNKS,
} ApexCodec_BufferType;

/**
 * Struct that represents the memory for ApexCodec_Buffer.
 *
 * All memory regions have the simple 1D representation.
 *
 * Introduced in API 36.
 */
typedef struct ApexCodec_LinearBuffer {
    /**
     * A pointer to the start of the buffer. This is not aligned.
     */
    uint8_t *_Nullable data;
    /**
     * Size of the buffer. The memory region between |data| (inclusive) and
     * |data + size| (exclusive) is assumed to be valid for read/write.
     */
    size_t size;
} ApexCodec_LinearBuffer;

/**
 * Opaque struct that represents a buffer for ApexCodec_Component.
 *
 * The buffer object is used to pass data between the client and the component.
 * The buffer object is created by ApexCodec_Buffer_create and destroyed by
 * ApexCodec_Buffer_destroy. The main usage is to pass the buffer to
 * ApexCodec_Component_process.
 *
 * The buffer object is empty by default. The client can set the buffer to be
 * either linear or graphic by calling ApexCodec_Buffer_setLinearBuffer or
 * ApexCodec_Buffer_setGraphicBuffer.
 *
 * The buffer object can be reused after it is cleared by
 * ApexCodec_Buffer_clear. The client should set the buffer again before using
 * it.
 *
 * Introduced in API 36.
 */
typedef struct ApexCodec_Buffer ApexCodec_Buffer;

/**
 * Create an empty buffer object, with no underlying memory or buffer info set.
 * ApexCodec_Buffer_getType will return APEXCODEC_BUFFER_TYPE_EMPTY, and other getters
 * will throw APEXCODEC_STATUS_BAD_STATE.
 *
 * \return the buffer object handle
 */
ApexCodec_Buffer *_Nonnull ApexCodec_Buffer_create() __INTRODUCED_IN(36);

/**
 * Destroy the buffer object. No-op if |buffer| is nullptr. Note that ApexCodec_Buffer does not own
 * objects that are set from the client including linear buffer, graphic buffer, and config updates.
 * The client therefore is responsible for freeing them if needed.
 *
 * The exception is the config updates that are owned by the buffer object, which will be
 * freed when the buffer object is destroyed.
 *
 * \param buffer the buffer object
 */
void ApexCodec_Buffer_destroy(ApexCodec_Buffer *_Nullable buffer) __INTRODUCED_IN(36);

/**
 * Clear the buffer object to be the empty state; i.e. the same as the buffer object created by
 * ApexCodec_Buffer_create.
 *
 * Similarly to ApexCodec_Buffer_destroy, The client is responsible for freeing objects set to the
 * buffer if needed.
 *
 * \param buffer the buffer object
 */
void ApexCodec_Buffer_clear(ApexCodec_Buffer *_Nonnull buffer) __INTRODUCED_IN(36);

/**
 * Set the buffer info to the buffer object.
 *
 * For input buffers the buffer info is required; otherwise
 * ApexCodec_Component_process will return APEXCODEC_STATUS_BAD_VALUE.
 * For output buffers the buffer info is optional.
 *
 * When called multiple times, the last set values will be used.
 *
 * \param buffer            the buffer object
 * \param flags             the flags associated with the buffer
 * \param frameIndex        the frame index for the buffer
 * \param timestampUs       the timestamp for the buffer in microseconds
 */
void ApexCodec_Buffer_setBufferInfo(
        ApexCodec_Buffer *_Nonnull buffer,
        ApexCodec_BufferFlags flags,
        uint64_t frameIndex,
        uint64_t timestampUs) __INTRODUCED_IN(36);


/**
 * Set the linear buffer for the empty buffer object. It is an error to call this function if the
 * buffer is not empty. For example, calling this function twice or after calling
 * ApexCodec_Buffer_setGraphicBuffer will result in APEXCODEC_STATUS_BAD_STATE, unless the buffer
 * is cleared first.
 *
 * If successful ApexCodec_Buffer_getType will return APEXCODEC_BUFFER_TYPE_LINEAR.
 *
 * \param buffer the buffer object
 * \param linearBuffer  the linear buffer to be set; may be null to indicate an empty linear buffer.
 *                      an empty linear buffer is used to communicate flags and/or config updates
 *                      only to the component.
 * \return  APEXCODEC_STATUS_OK         if successful
 * \return  APEXCODEC_STATUS_BAD_STATE  if |buffer| is not empty
 */
ApexCodec_Status ApexCodec_Buffer_setLinearBuffer(
        ApexCodec_Buffer *_Nonnull buffer,
        const ApexCodec_LinearBuffer *_Nullable linearBuffer) __INTRODUCED_IN(36);

/**
 * Set the graphic buffer for the empty buffer object. It is an error to call this function if the
 * buffer is not empty. For example, calling this function twice or after calling
 * ApexCodec_Buffer_setLinearBuffer will result in APEXCODEC_STATUS_BAD_STATE, unless the buffer
 * is cleared first.
 *
 * If successful ApexCodec_Buffer_getType will return APEXCODEC_BUFFER_TYPE_GRAPHIC.
 *
 * \param buffer        the buffer object
 * \param graphicBuffer the graphic buffer to be set; may be null to indicate
 *                      an empty graphic buffer.
 *                      an empty graphic buffer is used to communicate flags and/or config updates
 *                      only to the component.
 * \return  APEXCODEC_STATUS_OK         if successful
 * \return  APEXCODEC_STATUS_BAD_STATE  if |buffer| is not empty
 */
ApexCodec_Status ApexCodec_Buffer_setGraphicBuffer(
        ApexCodec_Buffer *_Nonnull buffer,
        AHardwareBuffer *_Nullable graphicBuffer) __INTRODUCED_IN(36);

/**
 * Set the config updates for the buffer object.
 *
 * For input buffers these are sent to the component at the specific input frame.
 * For output buffers client should not set this; otherwise ApexCodec_Component_process will return
 * APEXCODEC_STATUS_BAD_VALUE.
 *
 * This function cannot be called multiple times on the same buffer object until the buffer object
 * is cleared. This is to prevent the client from accidentally overwriting the config updates
 * before the client could free the existing config updates if needed.
 *
 * \param buffer            the buffer object
 * \param configUpdates     the config updates to be set
 * \return  APEXCODEC_STATUS_OK         if successful
 * \return  APEXCODEC_STATUS_BAD_STATE  if config updates are already set
 */
ApexCodec_Status ApexCodec_Buffer_setConfigUpdates(
        ApexCodec_Buffer *_Nonnull buffer,
        const ApexCodec_LinearBuffer *_Nonnull configUpdates) __INTRODUCED_IN(36);

/**
 * Get the type of the buffer object.
 *
 * \param buffer the buffer object
 * \return the type of the buffer object
 */
ApexCodec_BufferType ApexCodec_Buffer_getType(
        ApexCodec_Buffer *_Nonnull buffer) __INTRODUCED_IN(36);

/**
 * Extract the buffer info from the buffer object.
 *
 * \param buffer            the buffer object
 * \param outFlags          the flags associated with the buffer
 * \param outFrameIndex     the frame index for the buffer
 *                          for output buffers it is the same as the associated
 *                          input buffer's frame index.
 * \param outTimestampUs    the timestamp for the buffer in microseconds
 * \return  APEXCODEC_STATUS_OK         if successful
 * \return  APEXCODEC_STATUS_BAD_STATE  if buffer info was never set
 */
ApexCodec_Status ApexCodec_Buffer_getBufferInfo(
        ApexCodec_Buffer *_Nonnull buffer,
        ApexCodec_BufferFlags *_Nonnull outFlags,
        uint64_t *_Nonnull outFrameIndex,
        uint64_t *_Nonnull outTimestampUs) __INTRODUCED_IN(36);

/**
 * Extract the linear buffer from the buffer object.
 *
 * \param buffer            the buffer object
 * \param outLinearBuffer   the linear buffer to be set
 * \return  APEXCODEC_STATUS_OK         if successful
 * \return  APEXCODEC_STATUS_BAD_STATE  if |buffer| does not contain a linear buffer
 */
ApexCodec_Status ApexCodec_Buffer_getLinearBuffer(
        ApexCodec_Buffer *_Nonnull buffer,
        ApexCodec_LinearBuffer *_Nonnull outLinearBuffer) __INTRODUCED_IN(36);

/**
 * Extract the graphic buffer from the buffer object.
 *
 * \param buffer            the buffer object
 * \param outGraphicBuffer  the graphic buffer to be set
 * \return  APEXCODEC_STATUS_OK         if successful
 * \return  APEXCODEC_STATUS_BAD_STATE  if |buffer| does not contain a graphic buffer
 */
ApexCodec_Status ApexCodec_Buffer_getGraphicBuffer(
        ApexCodec_Buffer *_Nonnull buffer,
        AHardwareBuffer *_Nullable *_Nonnull outGraphicBuffer) __INTRODUCED_IN(36);

/**
 * Extract the config updates from the buffer object.
 * For output buffers these are config updates as a result of processing the buffer.
 *
 * \param buffer            the buffer object
 * \param outConfigUpdates  the config updates to be set.
 *                          if the config update was set by the client via
 *                          ApexCodec_Buffer_setConfigUpdates, the config updates are the same as
 *                          what was set before. |outOwnedByClient| will be set to true.
 *                          if the config update was set by the component, |outOwnedByClient| will
 *                          be set to false.
 * \param outOwnedByClient  if true, the client owns the config updates and is responsible
 *                          for freeing it.
 *                          if false, the config updates are owned by the buffer object
 *                          and the client should not free it; it will be freed when the buffer
 *                          object is cleared or destroyed.
 * \return  APEXCODEC_STATUS_OK         if successful
 * \return  APEXCODEC_STATUS_NOT_FOUND  if |buffer| does not contain config updates
 */
ApexCodec_Status ApexCodec_Buffer_getConfigUpdates(
        ApexCodec_Buffer *_Nonnull buffer,
        ApexCodec_LinearBuffer *_Nonnull outConfigUpdates,
        bool *_Nonnull outOwnedByClient) __INTRODUCED_IN(36);

/**
 * An opaque struct that represents the supported values of a parameter.
 *
 * Introduced in API 36.
 */
typedef struct ApexCodec_SupportedValues ApexCodec_SupportedValues;

/**
 * Extract information from ApexCodec_SupportedValues object.
 *
 * \param supportedValues   the supported values object
 * \param outType           pointer to be filled with the type of the supported values
 * \param outNumberType     pointer to be filled with the numeric type of the supported values
 * \param outValues         pointer to be filled with the array of the actual supported values.
 *                          if type == APEXCODEC_SUPPORTED_VALUES_EMPTY: nullptr
 *                          if type == APEXCODEC_SUPPORTED_VALUES_RANGE: {min, max, step, num, den}
 *                          if type == APEXCODEC_SUPPORTED_VALUES_VALUES/_FLAGS:
 *                              the array of supported values/flags
 *                          the array is owned by the |supportedValues| object and the client
 *                          should not free it.
 * \param outNumValues      pointer to be filled with the number of values.
 *                          if type == APEXCODEC_SUPPORTED_VALUES_EMPTY: 0
 *                          if type == APEXCODEC_SUPPORTED_VALUES_RANGE: 5
 *                          if type == APEXCODEC_SUPPORTED_VALUES_VALUES/_FLAGS: varies
 * \return  APEXCODEC_STATUS_OK         if successful
 * \return  APEXCODEC_STATUS_BAD_VALUE  if the parameters are bad
 * \return  APEXCODEC_STATUS_CORRUPTED  if an unexpected error occurs
 */
ApexCodec_Status ApexCodec_SupportedValues_getTypeAndValues(
        ApexCodec_SupportedValues *_Nonnull supportedValues,
        ApexCodec_SupportedValuesType *_Nonnull outType,
        ApexCodec_SupportedValuesNumberType *_Nonnull outNumberType,
        ApexCodec_Value *_Nullable *_Nonnull outValues,
        uint32_t *_Nonnull outNumValues) __INTRODUCED_IN(36);

/**
 * Destroy the supported values object. No-op if |values| is nullptr.
 *
 * \param values the supported values object
 */
void ApexCodec_SupportedValues_destroy(
        ApexCodec_SupportedValues *_Nullable values) __INTRODUCED_IN(36);

/**
 * Struct that represents the result of ApexCodec_Configurable_config.
 *
 * Introduced in API 36.
 */
typedef struct ApexCodec_SettingResults ApexCodec_SettingResults;

/**
 * Extract the result of ApexCodec_Configurable_config.
 * The client can iterate through the results with index starting from 0 until this function returns
 * APEXCODEC_STATUS_NOT_FOUND.
 *
 * \param result        the result object
 * \param index         the index of the result to extract, starts from 0.
 * \param outFailure    pointer to be filled with the failure code
 * \param outField      pointer to be filled with the field that failed.
 *                      |field->value| is owned by the |result| object and the client should not
 *                      free it.
 * \param outConflicts      pointer to be filled with the array of conflicts.
 *                          nullptr if |numConflicts| is 0.
 *                          the array and its content is owned by the |result| object and the client
 *                          should not free it.
 * \param outNumConflicts   pointer to be filled with the number of conflicts
 *                          may be 0 if there are no conflicts
 * \return  APEXCODEC_STATUS_OK         if successful
 * \return  APEXCODEC_STATUS_NOT_FOUND  if index is out of range
 * \return  APEXCODEC_STATUS_BAD_VALUE  if the parameters are bad
 */
ApexCodec_Status ApexCodec_SettingResults_getResultAtIndex(
        ApexCodec_SettingResults *_Nonnull results,
        size_t index,
        ApexCodec_SettingResultFailure *_Nonnull outFailure,
        ApexCodec_ParamFieldValues *_Nonnull outField,
        ApexCodec_ParamFieldValues *_Nullable *_Nonnull outConflicts,
        size_t *_Nonnull outNumConflicts) __INTRODUCED_IN(36);

/**
 * Destroy the setting result object. No-op if |results| is nullptr.
 *
 * \param result the setting result object
 */
void ApexCodec_SettingResults_destroy(
        ApexCodec_SettingResults *_Nullable results) __INTRODUCED_IN(36);

/**
 * Process one frame from |input|, and produce one frame to |output| if possible.
 *
 * When successfully filled, |outProduced| has the size adjusted to the produced
 * output size, in case of linear buffers. |input->configUpdates| is applied with the input
 * buffer; |output->configUpdates| contains config updates as a result of processing the frame.
 *
 * \param comp          the component to process the buffers
 * \param input         the input buffer; when nullptr, the component should fill |output|
 *                      if there are any pending output buffers.
 * \param output        the output buffer, should not be nullptr.
 * \param outConsumed   the number of consumed bytes from the input buffer
 *                      set to 0 if no input buffer has been consumed, including |input| is nullptr.
 *                      for graphic buffers, any non-zero value means that
 *                      the input buffer is consumed.
 * \param outProduced   the number of bytes produced on the output buffer
 *                      set to 0 if no output buffer has been produced.
 *                      for graphic buffers, any non-zero value means that
 *                      the output buffer is filled.
 * \return APEXCODEC_STATUS_OK         if successful
 * \return APEXCODEC_STATUS_NO_MEMORY  if the output buffer is not suitable to hold the output frame
 *                                     the client should retry with a new output buffer;
 *                                     configUpdates should have the information to update
 *                                     the buffer size.
 * \return APEXCODEC_STATUS_BAD_VALUE  if the parameters are bad
 * \return APEXCODEC_STATUS_BAD_STATE  if the component is not in the right state
 *                                     to process the frame
 * \return APEXCODEC_STATUS_CORRUPTED  if unexpected error has occurred
 */
ApexCodec_Status ApexCodec_Component_process(
        ApexCodec_Component *_Nonnull comp,
        const ApexCodec_Buffer *_Nullable input,
        ApexCodec_Buffer *_Nonnull output,
        size_t *_Nonnull outConsumed,
        size_t *_Nonnull outProduced) __INTRODUCED_IN(36);

/**
 * Configure the component with the given config.
 *
 * Configurations are Codec 2.0 configs in binary blobs,
 * concatenated if there are multiple configs.
 *
 * frameworks/av/media/codec2/core/include/C2Param.h contains more details about the configuration
 * blob layout.
 *
 * The component may correct the configured parameters to the closest supported values, and could
 * fail in case there are no values that the component can auto-correct to. |result| contains the
 * information about the failures. See ApexCodec_SettingResultFailure and ApexCodec_SettingResults
 * for more details.
 *
 * \param comp          the handle for the component
 * \param inoutConfig   the config blob; after the call, the config blob is updated to the actual
 *                      config by the component.
 * \param outResult     the result of the configuration.
 *                      the client should call ApexCodec_SettingResult_getResultAtIndex()
 *                      to extract the result. The result object is owned by the client and should
 *                      be released with ApexCodec_SettingResult_destroy().
 *                      |result| may be nullptr if empty.
 * \return APEXCODEC_STATUS_OK         if successful
 * \return APEXCODEC_STATUS_BAD_VALUE  if the config is invalid
 * \return APEXCODEC_STATUS_BAD_STATE  if the component is not in the right state to be configured
 * \return APEXCODEC_STATUS_CORRUPTED  if unexpected error has occurred
 */
ApexCodec_Status ApexCodec_Configurable_config(
        ApexCodec_Configurable *_Nonnull comp,
        ApexCodec_LinearBuffer *_Nonnull inoutConfig,
        ApexCodec_SettingResults *_Nullable *_Nonnull outResults) __INTRODUCED_IN(36);

/**
 * Query the component for the given indices.
 *
 * Parameter indices are defined in frameworks/av/media/codec2/core/include/C2Config.h.
 *
 * \param comp          the handle for the component
 * \param indices       the array of indices to query
 * \param numIndices    the size of the indices array
 * \param inoutConfig   the output buffer for the config blob, allocated by the client.
 *                      it can be null to query the required size.
 * \param outWrittenOrRequired      the number of bytes written to |config|.
 *                                  if the |config->size| was insufficient, it is set to the
 *                                  required size.
 *
 * \return APEXCODEC_STATUS_OK          if successful
 * \return APEXCODEC_STATUS_NO_MEMORY   if |config.size| is too small; |config.size| is updated
 *                                      to the requested buffer size.
 * \return APEXCODEC_STATUS_BAD_VALUE   if the parameters are bad. e.g. |indices| or
 *                                      |written| is nullptr.
 */
ApexCodec_Status ApexCodec_Configurable_query(
        ApexCodec_Configurable *_Nonnull comp,
        uint32_t indices[_Nonnull],
        size_t numIndices,
        ApexCodec_LinearBuffer *_Nullable inoutConfig,
        size_t *_Nonnull outWrittenOrRequired) __INTRODUCED_IN(36);

/**
 * Struct that represents a parameter descriptor.
 *
 * Introduced in API 36.
 */
typedef struct ApexCodec_ParamDescriptors ApexCodec_ParamDescriptors;

/**
 * Get the parameter indices of the param descriptors.
 *
 * \param descriptors   the param descriptors object
 * \param outIndices    the pointer to be filled with the array of the indices;
 *                      the array is owned by |descriptors| and should not be freed by the client.
 * \param outNumIndices the size of the indices array
 * \return APEXCODEC_STATUS_OK          if successful
 * \return APEXCODEC_STATUS_BAD_VALUE   if parameters are bad. e.g. |descriptors|, |indices| or
 *                                  |numIndices| is nullptr.
 */
ApexCodec_Status ApexCodec_ParamDescriptors_getIndices(
        ApexCodec_ParamDescriptors *_Nonnull descriptors,
        uint32_t *_Nullable *_Nonnull outIndices,
        size_t *_Nonnull outNumIndices) __INTRODUCED_IN(36);

/**
 * Get the descriptor of the param.
 *
 * \param descriptors   the param descriptors object
 * \param index         the index of the param
 * \param outAttr       the attribute of the param
 * \param outName       the pointer to be filled with the name of the param
 *                      the string is owned by |descriptors| and should not be freed by the client.
 *                      the encoding is ASCII.
 * \param outDependencies the pointer to be filled with an array of the parameter indices
 *                        that the parameter with |index| depends on.
 *                        may be null if empty.
 *                        the array is owned by |descriptors| and should not be freed by the client.
 * \param outNumDependencies the number of dependencies
 * \return APEXCODEC_STATUS_OK          if successful
 * \return APEXCODEC_STATUS_BAD_VALUE   if parameters are bad. e.g. |descriptors|, |attr|, |name|,
 *                                  |dependencies| or |numDependencies| is nullptr.
 * \return APEXCODEC_STATUS_BAD_INDEX   if the index is not included in the param descriptors.
 */
ApexCodec_Status ApexCodec_ParamDescriptors_getDescriptor(
        ApexCodec_ParamDescriptors *_Nonnull descriptors,
        uint32_t index,
        ApexCodec_ParamAttribute *_Nonnull outAttr,
        const char *_Nullable *_Nonnull outName,
        uint32_t *_Nullable *_Nonnull outDependencies,
        size_t *_Nonnull outNumDependencies) __INTRODUCED_IN(36);

/**
 * Destroy the param descriptors object. No-op if |descriptors| is nullptr.
 *
 * \param descriptors the param descriptors object
 */
void ApexCodec_ParamDescriptors_destroy(
        ApexCodec_ParamDescriptors *_Nullable descriptors) __INTRODUCED_IN(36);

/**
 * Query the component for the supported parameters.
 *
 * \param comp              the handle for the component
 * \param outDescriptors    the pointer to be filled with the param descriptors object
 *                          the object should be released with ApexCodec_ParamDescriptors_destroy().
 * \return APEXCODEC_STATUS_OK          if successful
 * \return APEXCODEC_STATUS_BAD_VALUE   if parameters are bad. e.g. |descriptors| is nullptr.
 */
ApexCodec_Status ApexCodec_Configurable_querySupportedParams(
        ApexCodec_Configurable *_Nonnull comp,
        ApexCodec_ParamDescriptors *_Nullable *_Nonnull outDescriptors) __INTRODUCED_IN(36);

/**
 * Struct that represents the query for the supported values of a parameter.
 *
 * The offset of the field can be found in the layout of the parameter blob.
 *
 * Introduced in API 36.
 */
typedef struct ApexCodec_SupportedValuesQuery {
    /* in-params */

    /** index of the param */
    uint32_t index;
    /** offset to the param field */
    size_t offset;
    /** query type */
    ApexCodec_SupportedValuesQueryType type;

    /* out-params */

    /** status of the query */
    ApexCodec_Status status;

    /** supported values. must be released with ApexCodec_SupportedValues_destroy(). */
    ApexCodec_SupportedValues *_Nullable values;
} ApexCodec_SupportedValuesQuery;

/**
 * Query the component for the supported values of the given indices.
 *
 * \param comp the handle for the component
 * \param inoutQueries the array of queries
 * \param numQueries the size of the queries array
 * \return  APEXCODEC_STATUS_OK         if successful
 * \return  APEXCODEC_STATUS_CORRUPTED  if unexpected error has occurred
 */
ApexCodec_Status ApexCodec_Configurable_querySupportedValues(
        ApexCodec_Configurable *_Nonnull comp,
        ApexCodec_SupportedValuesQuery *_Nonnull inoutQueries,
        size_t numQueries) __INTRODUCED_IN(36);

__END_DECLS