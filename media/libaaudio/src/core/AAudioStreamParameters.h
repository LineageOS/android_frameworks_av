/*
 * Copyright 2017 The Android Open Source Project
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

#ifndef AAUDIO_STREAM_PARAMETERS_H
#define AAUDIO_STREAM_PARAMETERS_H

// go/keep-sorted start
#include <aaudio/AAudio.h>
#include <media/AudioContainers.h>
#include <utility/AAudioUtilities.h>
// go/keep-sorted end

#include <stdint.h>

namespace aaudio {

class AAudioStreamParameters {
public:
    AAudioStreamParameters() = default;
    virtual ~AAudioStreamParameters() = default;

    android::DeviceIdVector getDeviceIds() const {
        return mDeviceIds;
    }

    void setDeviceIds(const android::DeviceIdVector& deviceIds) {
        mDeviceIds = deviceIds;
    }

    int32_t getSampleRate() const {
        return mSampleRate;
    }

    void setSampleRate(int32_t sampleRate) {
        mSampleRate = sampleRate;
    }

    int32_t getSamplesPerFrame() const {
        return mSamplesPerFrame;
    }

    audio_format_t getFormat() const {
        return mAudioFormat;
    }

    void setFormat(audio_format_t audioFormat) {
        mAudioFormat = audioFormat;
    }

    aaudio_sharing_mode_t getSharingMode() const {
        return mSharingMode;
    }

    void setSharingMode(aaudio_sharing_mode_t sharingMode) {
        mSharingMode = sharingMode;
    }

    int32_t getBufferCapacity() const {
        return mBufferCapacity;
    }

    void setBufferCapacity(int32_t frames) {
        mBufferCapacity = frames;
    }

    aaudio_direction_t getDirection() const {
        return mDirection;
    }

    void setDirection(aaudio_direction_t direction) {
        mDirection = direction;
    }

    aaudio_usage_t getUsage() const {
        return mUsage;
    }

    void setUsage(aaudio_usage_t usage) {
        mUsage = usage;
    }

    aaudio_content_type_t getContentType() const {
        return mContentType;
    }

    void setContentType(aaudio_content_type_t contentType) {
        mContentType = contentType;
    }

    void setTags(const std::set<std::string>& tags) {
        mTags = tags;
    }

    const std::set<std::string>& getTags() const {
        return mTags;
    }

    std::string getTagsAsString() const;

    aaudio_spatialization_behavior_t getSpatializationBehavior() const {
        return mSpatializationBehavior;
    }

    void setSpatializationBehavior(aaudio_spatialization_behavior_t spatializationBehavior) {
        mSpatializationBehavior = spatializationBehavior;
    }

    bool isContentSpatialized() const {
        return mIsContentSpatialized;
    }

    void setIsContentSpatialized(bool isSpatialized) {
        mIsContentSpatialized = isSpatialized;
    }

    aaudio_input_preset_t getInputPreset() const {
        return mInputPreset;
    }

    void setInputPreset(aaudio_input_preset_t inputPreset) {
        mInputPreset = inputPreset;
    }

    aaudio_allowed_capture_policy_t getAllowedCapturePolicy() const {
        return mAllowedCapturePolicy;
    }

    void setAllowedCapturePolicy(aaudio_allowed_capture_policy_t policy) {
        mAllowedCapturePolicy = policy;
    }

    aaudio_session_id_t getSessionId() const {
        return mSessionId;
    }

    void setSessionId(aaudio_session_id_t sessionId) {
        mSessionId = sessionId;
    }

    bool isPrivacySensitive() const {
        return mIsPrivacySensitive;
    }

    void setPrivacySensitive(bool privacySensitive) {
        mIsPrivacySensitive = privacySensitive;
    }

    const std::optional<std::string> getOpPackageName() const {
        return mOpPackageName;
    }

    // TODO b/182392769: reexamine if Identity can be used
    void setOpPackageName(const std::optional<std::string>& opPackageName) {
        mOpPackageName = opPackageName;
    }

    const std::optional<std::string> getAttributionTag() const {
        return mAttributionTag;
    }

    void setAttributionTag(const std::optional<std::string>& attributionTag) {
        mAttributionTag = attributionTag;
    }

    aaudio_channel_mask_t getChannelMask() const {
        return mChannelMask;
    }

    void setChannelMask(aaudio_channel_mask_t channelMask) {
        mChannelMask = channelMask;
        mSamplesPerFrame = AAudioConvert_channelMaskToCount(channelMask);
    }

    int32_t getHardwareSamplesPerFrame() const {
        return mHardwareSamplesPerFrame;
    }

    void setHardwareSamplesPerFrame(int32_t hardwareSamplesPerFrame) {
        mHardwareSamplesPerFrame = hardwareSamplesPerFrame;
    }

    int32_t getHardwareSampleRate() const {
        return mHardwareSampleRate;
    }

    void setHardwareSampleRate(int32_t hardwareSampleRate) {
        mHardwareSampleRate = hardwareSampleRate;
    }

    audio_format_t getHardwareFormat() const {
        return mHardwareAudioFormat;
    }

    void setHardwareFormat(audio_format_t hardwareAudioFormat) {
        mHardwareAudioFormat = hardwareAudioFormat;
    }

    /**
     * @return bytes per frame of getFormat()
     */
    int32_t calculateBytesPerFrame() const {
        return getSamplesPerFrame() * audio_bytes_per_sample(getFormat());
    }

    aaudio_performance_mode_t getPerformanceMode() const {
        return mPerformanceMode;
    }

    void setPerformanceMode(aaudio_performance_mode_t performanceMode) {
        mPerformanceMode = performanceMode;
    }

    audio_port_handle_t getPortHandle() const { return mPortHandle; }
    audio_io_handle_t getIoHandle() const { return mIoHandle; }
    void setPortHandle(audio_port_handle_t portHandle) { mPortHandle = portHandle; }
    void setIoHandle(audio_io_handle_t ioHandle) { mIoHandle = ioHandle; }

    /**
     * Copy variables defined in other AAudioStreamParameters instance to this one.
     * @param other
     */
    void copyFrom(const AAudioStreamParameters &other);

    virtual aaudio_result_t validate() const;

    void dump() const;

protected:
    std::set<std::string>           mTags;

    audio_port_handle_t mPortHandle = AUDIO_PORT_HANDLE_NONE;
    audio_io_handle_t mIoHandle = AUDIO_IO_HANDLE_NONE;

private:
    aaudio_result_t validateChannelMask() const;

    int32_t                         mSamplesPerFrame      = AAUDIO_UNSPECIFIED;
    int32_t                         mSampleRate           = AAUDIO_UNSPECIFIED;
    android::DeviceIdVector         mDeviceIds;
    aaudio_sharing_mode_t           mSharingMode          = AAUDIO_SHARING_MODE_SHARED;
    audio_format_t                  mAudioFormat          = AUDIO_FORMAT_DEFAULT;
    aaudio_direction_t              mDirection            = AAUDIO_DIRECTION_OUTPUT;
    aaudio_usage_t                  mUsage                = AAUDIO_UNSPECIFIED;
    aaudio_content_type_t           mContentType          = AAUDIO_UNSPECIFIED;
    aaudio_spatialization_behavior_t mSpatializationBehavior
                                                          = AAUDIO_UNSPECIFIED;
    bool                            mIsContentSpatialized = false;
    aaudio_input_preset_t           mInputPreset          = AAUDIO_UNSPECIFIED;
    int32_t                         mBufferCapacity       = AAUDIO_UNSPECIFIED;
    aaudio_allowed_capture_policy_t mAllowedCapturePolicy = AAUDIO_UNSPECIFIED;
    aaudio_session_id_t             mSessionId            = AAUDIO_SESSION_ID_NONE;
    bool                            mIsPrivacySensitive   = false;
    std::optional<std::string>      mOpPackageName        = {};
    std::optional<std::string>      mAttributionTag       = {};
    aaudio_channel_mask_t           mChannelMask          = AAUDIO_UNSPECIFIED;
    int                             mHardwareSamplesPerFrame
                                                          = AAUDIO_UNSPECIFIED;
    int                             mHardwareSampleRate   = AAUDIO_UNSPECIFIED;
    audio_format_t                  mHardwareAudioFormat  = AUDIO_FORMAT_DEFAULT;
    aaudio_performance_mode_t       mPerformanceMode      = AAUDIO_PERFORMANCE_MODE_NONE;
};

} /* namespace aaudio */

#endif //AAUDIO_STREAM_PARAMETERS_H
