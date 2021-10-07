/**
 * Copyright (c) 2020, The Android Open Source Project
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

package android.media;

import android.media.TranscodingVideoCodecType;

/**
 * TranscodingVideoTrackFormat contains the video track format of a video.
 *
 * TODO(hkuang): Switch to PersistableBundle when b/156428735 is fixed or after we remove
 * aidl_interface
 *
 * Note that TranscodingVideoTrackFormat is used in TranscodingRequestParcel for the  client to
 * specify the desired transcoded video format, and is also used in TranscodingSessionParcel for the
 * service to notify client of the final video format for transcoding.
 * When used as input in TranscodingRequestParcel, the client only needs to specify the config that
 * they want to change, e.g. codec or resolution, and all the missing configs will be extracted
 * from the source video and applied to the destination video.
 * When used as output in TranscodingSessionParcel, all the configs will be populated to indicate
 * the final encoder configs used for transcoding.
 *
 * {@hide}
 */
parcelable TranscodingVideoTrackFormat {
    /**
     * Video Codec type.
     */
    TranscodingVideoCodecType codecType; // TranscodingVideoCodecType::kUnspecified;

    /**
     * Width of the video in pixels. -1 means unavailable.
     */
    int width = -1;

    /**
     * Height of the video in pixels. -1 means unavailable.
     */
    int height = -1;

    /**
     * Bitrate in bits per second. -1 means unavailable.
     */
    int bitrateBps = -1;

    /**
     * Codec profile. This must be the same constant as used in MediaCodecInfo.CodecProfileLevel.
     * -1 means unavailable.
     */
    int profile = -1;

    /**
     * Codec level. This must be the same constant as used in MediaCodecInfo.CodecProfileLevel.
     * -1 means unavailable.
     */
    int level = -1;

    /**
     * Decoder operating rate. This is used to work around the fact that vendor does not boost the
     * hardware to maximum speed in transcoding usage case. This operating rate will be applied
     * to decoder inside MediaTranscoder. -1 means unavailable.
     */
    int decoderOperatingRate = -1;

    /**
     * Encoder operating rate. This is used to work around the fact that vendor does not boost the
     * hardware to maximum speed in transcoding usage case. This operating rate will be applied
     * to encoder inside MediaTranscoder. -1 means unavailable.
     */
    int encoderOperatingRate = -1;
}
