#ifndef MEDIA_LIBAUDIOUSECASEVALIDATION_INCLUDE_MEDIA_USECASEVALIDATOR_H_
#define MEDIA_LIBAUDIOUSECASEVALIDATION_INCLUDE_MEDIA_USECASEVALIDATOR_H_

#pragma once

#include <error/Result.h>
#include <system/audio.h>
#include <android/content/AttributionSourceState.h>

#include <limits>
#include <memory>

namespace android {
namespace media {

/**
 * Main entry-point for this library.
 */
class UsecaseValidator {
 public:
    virtual ~UsecaseValidator() = default;

    /**
     * A callback called by the module when the audio attributes for
     * an active portId changes.
     */
    class AttributesChangedCallback {
     public:
        virtual ~AttributesChangedCallback() = default;
        virtual void onAttributesChanged(audio_port_handle_t portId,
                                         const audio_attributes_t& attributes) = 0;
    };

    /**
     * Register a new mixer/stream.
     * Called when the stream is opened at the HAL  and communicates
     * immutable stream attributes like flags, sampling rate, format.
     */
    virtual status_t registerStream(audio_io_handle_t streamId,
                                    const audio_config_base_t& audioConfig,
                                    const audio_output_flags_t outputFlags) = 0;

    /**
     * Unregister a stream/mixer.
     * Called when the stream is closed.
     */
    virtual status_t unregisterStream(audio_io_handle_t streamId) = 0;

    /**
     * Indicates that some playback activity started on the stream.
     * Called each time an audio track starts or resumes.
     */
    virtual error::Result<audio_attributes_t> startClient(audio_io_handle_t streamId,
            audio_port_handle_t portId,
            const content::AttributionSourceState& attributionSource,
            const audio_attributes_t& attributes,
            const AttributesChangedCallback *callback) = 0;

    /**
     * Indicates that some playback activity stopped on the stream.
     * Called each time an audio track stops or pauses.
     */
    virtual status_t stopClient(audio_io_handle_t streamId, audio_port_handle_t portId) = 0;

    /**
     * Called to verify and update audio attributes for a track that is connected
     * to the specified stream.
     */
    virtual error::Result<audio_attributes_t> verifyAudioAttributes(audio_io_handle_t streamId,
            const content::AttributionSourceState& attributionSource,
            const audio_attributes_t& attributes) = 0;
};

/**
 * Creates an instance featuring a default implementation of the UsecaseValidator interface.
 */
std::unique_ptr<UsecaseValidator> createUsecaseValidator();

}  // namespace media
}  // namespace android

#endif  // MEDIA_LIBAUDIOUSECASEVALIDATION_INCLUDE_MEDIA_USECASEVALIDATOR_H_
