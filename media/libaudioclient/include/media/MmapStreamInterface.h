/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef ANDROID_AUDIO_MMAP_STREAM_INTERFACE_H
#define ANDROID_AUDIO_MMAP_STREAM_INTERFACE_H

#include <android/media/OpenMmapRequest.h>
#include <android/media/OpenMmapResponse.h>
#include <android/media/IMmapStream.h>
#include <android/media/audio/common/AudioPlaybackRate.h>
#include <audio_utils/TimerQueue.h>
#include <media/AidlConversion.h>
#include <media/AudioClient.h>
#include <media/AudioContainers.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

#include <time.h>

namespace android {

class MmapStreamCallback;

class MmapStreamInterface : public virtual RefBase
{
  public:

    MmapStreamInterface(const audio_config_base_t& config,
            const sp<media::IMmapStream>& stream,
            const sp<media::IMmapStreamCallback>& callback);

    /**
     * Open a playback or capture stream in MMAP mode at the audio HAL.
     *
     * \note This method is implemented by AudioFlinger
     *
     * \param[in] isOutput true for playback or false for capture stream.
     * \param[in] attr audio attributes defining the main use case for this stream
     * \param[in,out] config audio parameters (sampling rate, format ...) for the stream.
     *                       Requested parameters as input,
     *                       Actual parameters as output
     * \param[in] client a AudioClient struct describing the first client using this stream.
     * \param[in,out] deviceIds audio devices the stream should preferably be routed to/from.
     *                          Leave empty if there are no preferred devices.
     *                          Requested as input,
     *                          Actual as output
     * \param[in,out] sessionId audio sessionId for the stream
     *                       Requested as input, may be AUDIO_SESSION_ALLOCATE
     *                       Actual as output
     * \param[in] callback the MmapStreamCallback interface used by AudioFlinger to notify
     *                     condition changes affecting the stream operation
     * \param[in] offloadInfo additional information for offload playback
     * \param[out] interface the MmapStreamInterface controlling the created stream
     * \param[out] same unique handle as the one used for the first client stream started.
     * \return OK if the stream was successfully created.
     *         NO_INIT if AudioFlinger is not properly initialized
     *         BAD_VALUE if the stream cannot be opened because of invalid arguments
     *         INVALID_OPERATION if the stream cannot be opened because of platform limitations
     */
    static status_t openMmapStream(bool isOutput,
                                   const audio_attributes_t& attr,
                                   audio_config_base_t* config,
                                   const AudioClient& client,
                                   DeviceIdVector* deviceIds,
                                   audio_session_t* sessionId,
                                   const sp<MmapStreamCallback>& callback,
                                   const audio_offload_info_t* offloadInfo,
                                   sp<MmapStreamInterface>& interface,
                                   audio_port_handle_t* handle);

    static status_t buildRequest(bool isOutput,
                                 const audio_attributes_t& attr,
                                 const audio_config_base_t& config,
                                 const AudioClient& client,
                                 const DeviceIdVector& deviceIds,
                                 audio_session_t sessionId,
                                 const sp<MmapStreamCallback>& callback,
                                 const audio_offload_info_t* offloadInfo,
                                 media::OpenMmapRequest* request);

    static status_t parseResponse(const media::OpenMmapResponse& response,
                                  bool isOutput,
                                  audio_config_base_t* config,
                                  DeviceIdVector* deviceIds,
                                  audio_session_t* sessionId,
                                  audio_port_handle_t* handle);

    static status_t parseRequest(const media::OpenMmapRequest& request,
                                 bool* isOutput,
                                 audio_attributes_t* attr,
                                 audio_config_base_t* config,
                                 AudioClient* client,
                                 DeviceIdVector* deviceIds,
                                 audio_session_t* sessionId,
                                 sp<media::IMmapStreamCallback>* callback,
                                 audio_offload_info_t* offloadInfo);

    static status_t buildResponse(bool isOutput,
                                  const audio_config_base_t& config,
                                  const DeviceIdVector& deviceIds,
                                  audio_session_t sessionId,
                                  const sp<media::IMmapStream>& interface,
                                  audio_port_handle_t portId,
                                  media::OpenMmapResponse* response);

    /**
     * Retrieve information on the mmap buffer used for audio samples transfer.
     * Must be called before any other method after opening the stream or entering standby.
     *
     * \param[in] min_size_frames minimum buffer size requested. The actual buffer
     *        size returned in struct audio_mmap_buffer_info can be larger.
     * \param[out] info address at which the mmap buffer information should be returned.
     *         The mmap_buffer_info.shared_memory_fd must be closed by the caller.
     *
     * \return OK if the buffer was allocated.
     *         NO_INIT in case of initialization error
     *         BAD_VALUE if the requested buffer size is too large
     *         INVALID_OPERATION if called out of sequence (e.g. buffer already allocated)
     */
    virtual status_t createMmapBuffer(int32_t minSizeFrames,
                                      struct audio_mmap_buffer_info* info);

    /**
     * Read current read/write position in the mmap buffer with associated time stamp.
     *
     * \param[out] position address at which the mmap read/write position should be returned.
     *
     * \return OK if the position is successfully returned.
     *         NO_INIT in case of initialization error
     *         NOT_ENOUGH_DATA if the position cannot be retrieved
     *         INVALID_OPERATION if called before createMmapBuffer()
     */
    virtual status_t getMmapPosition(struct audio_mmap_position* position);

    /**
     * Get a recent count of the number of audio frames presented/received to/from an
     * external observer.
     *
     * \param[out] position count of presented audio frames
     * \param[out] timeNanos associated clock time
     *
     * \return OK if the external position is set correctly.
     *         NO_INIT in case of initialization error
     *         INVALID_OPERATION if the interface is not implemented
     */
    virtual status_t getObservablePosition(uint64_t* position, int64_t* timeNanos);

    /**
     * Create a track for the client.
     *
     * \param[in] client a AudioClient struct describing the client.
     * \param[in] attr audio attributes provided by the client.
     * \param[out] portId allocated port id for the track. Used for start() and stop()
     * \param[out] ioHandle IO handle of the thread.
     * \return OK in case of success.
     */
    virtual status_t createTrack(const AudioClient& client,
                                 const audio_attributes_t& attr,
                                 audio_port_handle_t* portId,
                                 audio_io_handle_t* ioHandle);

    /**
     * Start a track operating in mmap mode.
     * createMmapBuffer() must be called before calling start()
     *
     * \param[in] portId unique port id allocated by createTrack().
     * \return OK in case of success.
     *         NO_INIT in case of initialization error
     *         INVALID_OPERATION if called out of sequence
     */
    virtual status_t startTrack(audio_port_handle_t portId);

    /**
     * Stop a track operating in mmap mode.
     * Must be called after start()
     *
     * \param[in] portId unique port id allocated by createTrack().
     * \return OK in case of success.
     *         NO_INIT in case of initialization error
     *         INVALID_OPERATION if called out of sequence
     */
    virtual status_t stopTrack(audio_port_handle_t portId);

    /**
     * Release a track from the mmap stream.
     *
     * \param[in] portId unique port id allocated by createTrack().
     * \return OK in case of success.
     */
    virtual status_t releaseTrack(audio_port_handle_t portId);

    /**
     * Put a stream operating in mmap mode into standby.
     * Must be called after createMmapBuffer(). Cannot be called if any client is active.
     * It is recommended to place a mmap stream into standby as often as possible when no client is
     * active to save power.
     *
     * \return OK in case of success.
     *         NO_INIT in case of initialization error
     *         INVALID_OPERATION if called out of sequence
     */
    virtual status_t standby();

    /**
     * Report when data being written to a playback buffer. Currently, this is used by mmap
     * playback thread for sound dose computation.
     *
     * \param[in] buffer a pointer to the audio data
     * \param[in] frameCount the number of frames written by the CPU
     * \return OK in case of success.
     *         NO_INIT in case of initialization error
     *         INVALID_OPERATION in case of wrong thread type
     */
    virtual status_t reportData(const void* buffer, size_t frameCount);

    /**
     * Notify the stream is currently draining.
     */
    virtual status_t drain(int64_t wakeUpNanos, bool allowSoftWakeUp,
                           android::audio_utils::TimerQueue::handle_t* handle);

    /**
     * Notify the stream is active.
     */
    virtual status_t activate(android::audio_utils::TimerQueue::handle_t handle);

    virtual status_t setPlaybackParameters(
            const android::media::audio::common::AudioPlaybackRate& rate);

    virtual status_t getPlaybackParameters(
            android::media::audio::common::AudioPlaybackRate* rate);

  protected:
    const audio_config_base_t mConfig;
    const sp<media::IMmapStream> mStream;
    const sp<media::IMmapStreamCallback> mCallback;  // for callback lifetime management.
};

} // namespace android

#endif // ANDROID_AUDIO_MMAP_STREAM_INTERFACE_H
