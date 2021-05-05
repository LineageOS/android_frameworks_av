/*
 *
 * Copyright 2010, The Android Open Source Project.
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

#ifndef ANDROID_MEDIAPROFILES_H
#define ANDROID_MEDIAPROFILES_H

#include <utils/threads.h>
#include <media/mediarecorder.h>

#include <vector>

namespace android {

enum camcorder_quality {
    CAMCORDER_QUALITY_LIST_START = 0,
    CAMCORDER_QUALITY_LOW  = 0,
    CAMCORDER_QUALITY_HIGH = 1,
    CAMCORDER_QUALITY_QCIF = 2,
    CAMCORDER_QUALITY_CIF = 3,
    CAMCORDER_QUALITY_480P = 4,
    CAMCORDER_QUALITY_720P = 5,
    CAMCORDER_QUALITY_1080P = 6,
    CAMCORDER_QUALITY_QVGA = 7,
    CAMCORDER_QUALITY_2160P = 8,
    CAMCORDER_QUALITY_VGA = 9,
    CAMCORDER_QUALITY_4KDCI = 10,
    CAMCORDER_QUALITY_QHD = 11,
    CAMCORDER_QUALITY_2K = 12,
    CAMCORDER_QUALITY_8KUHD = 13,
    CAMCORDER_QUALITY_LIST_END = 13,

    CAMCORDER_QUALITY_TIME_LAPSE_LIST_START = 1000,
    CAMCORDER_QUALITY_TIME_LAPSE_LOW  = 1000,
    CAMCORDER_QUALITY_TIME_LAPSE_HIGH = 1001,
    CAMCORDER_QUALITY_TIME_LAPSE_QCIF = 1002,
    CAMCORDER_QUALITY_TIME_LAPSE_CIF = 1003,
    CAMCORDER_QUALITY_TIME_LAPSE_480P = 1004,
    CAMCORDER_QUALITY_TIME_LAPSE_720P = 1005,
    CAMCORDER_QUALITY_TIME_LAPSE_1080P = 1006,
    CAMCORDER_QUALITY_TIME_LAPSE_QVGA = 1007,
    CAMCORDER_QUALITY_TIME_LAPSE_2160P = 1008,
    CAMCORDER_QUALITY_TIME_LAPSE_VGA = 1009,
    CAMCORDER_QUALITY_TIME_LAPSE_4KDCI = 1010,
    CAMCORDER_QUALITY_TIME_LAPSE_QHD = 1011,
    CAMCORDER_QUALITY_TIME_LAPSE_2K = 1012,
    CAMCORDER_QUALITY_TIME_LAPSE_8KUHD = 1013,
    CAMCORDER_QUALITY_TIME_LAPSE_LIST_END = 1013,

    CAMCORDER_QUALITY_HIGH_SPEED_LIST_START = 2000,
    CAMCORDER_QUALITY_HIGH_SPEED_LOW  = 2000,
    CAMCORDER_QUALITY_HIGH_SPEED_HIGH = 2001,
    CAMCORDER_QUALITY_HIGH_SPEED_480P = 2002,
    CAMCORDER_QUALITY_HIGH_SPEED_720P = 2003,
    CAMCORDER_QUALITY_HIGH_SPEED_1080P = 2004,
    CAMCORDER_QUALITY_HIGH_SPEED_2160P = 2005,
    CAMCORDER_QUALITY_HIGH_SPEED_CIF = 2006,
    CAMCORDER_QUALITY_HIGH_SPEED_VGA = 2007,
    CAMCORDER_QUALITY_HIGH_SPEED_4KDCI = 2008,
    CAMCORDER_QUALITY_HIGH_SPEED_LIST_END = 2008,
};

enum video_decoder {
    VIDEO_DECODER_WMV,
};

enum audio_decoder {
    AUDIO_DECODER_WMA,
};


class MediaProfiles
{
public:

    /**
     * Returns the singleton instance for subsequence queries or NULL if error.
     *
     * If property media.settings.xml is set, getInstance() will attempt to read
     * from file path in media.settings.xml. Otherwise, getInstance() will
     * search through the list of preset XML file paths.
     *
     * If the search is unsuccessful, the default instance will be created
     * instead.
     *
     * TODO: After validation is added, getInstance() should handle validation
     * failure properly.
     */
    static MediaProfiles* getInstance();

    /**
     * Configuration for a video encoder.
     */
    struct VideoCodec {
    public:
        /**
         * Constructs a video encoder configuration.
         *
         * @param codec codec type
         * @param bitrate bitrate in bps
         * @param frameWidth frame width in pixels
         * @param frameHeight frame height in pixels
         * @param frameRate frame rate in fps
         * @param profile codec profile (for MediaCodec) or -1 for none
         */
        VideoCodec(video_encoder codec, int bitrate, int frameWidth, int frameHeight, int frameRate,
                   int profile = -1)
            : mCodec(codec),
              mBitRate(bitrate),
              mFrameWidth(frameWidth),
              mFrameHeight(frameHeight),
              mFrameRate(frameRate),
              mProfile(profile) {
        }

        VideoCodec(const VideoCodec&) = default;

        ~VideoCodec() {}

        /** Returns the codec type. */
        video_encoder getCodec() const {
            return mCodec;
        }

        /** Returns the bitrate in bps. */
        int getBitrate() const {
            return mBitRate;
        }

        /** Returns the frame width in pixels. */
        int getFrameWidth() const {
            return mFrameWidth;
        }

        /** Returns the frame height in pixels. */
        int getFrameHeight() const {
            return mFrameHeight;
        }

        /** Returns the frame rate in fps. */
        int getFrameRate() const {
            return mFrameRate;
        }

        /** Returns the codec profile (or -1 for no profile). */
        int getProfile() const {
            return mProfile;
        }

    private:
        video_encoder mCodec;
        int mBitRate;
        int mFrameWidth;
        int mFrameHeight;
        int mFrameRate;
        int mProfile;
        friend class MediaProfiles;
    };

    /**
     * Configuration for an audio encoder.
     */
    struct AudioCodec {
    public:
        /**
         * Constructs an audio encoder configuration.
         *
         * @param codec codec type
         * @param bitrate bitrate in bps
         * @param sampleRate sample rate in Hz
         * @param channels number of channels
         * @param profile codec profile (for MediaCodec) or -1 for none
         */
        AudioCodec(audio_encoder codec, int bitrate, int sampleRate, int channels, int profile = -1)
            : mCodec(codec),
              mBitRate(bitrate),
              mSampleRate(sampleRate),
              mChannels(channels),
              mProfile(profile) {
        }

        AudioCodec(const AudioCodec&) = default;

        ~AudioCodec() {}

        /** Returns the codec type. */
        audio_encoder getCodec() const {
            return mCodec;
        }

        /** Returns the bitrate in bps. */
        int getBitrate() const {
            return mBitRate;
        }

        /** Returns the sample rate in Hz. */
        int getSampleRate() const {
            return mSampleRate;
        }

        /** Returns the number of channels. */
        int getChannels() const {
            return mChannels;
        }

        /** Returns the codec profile (or -1 for no profile). */
        int getProfile() const {
            return mProfile;
        }

    private:
        audio_encoder mCodec;
        int mBitRate;
        int mSampleRate;
        int mChannels;
        int mProfile;
        friend class MediaProfiles;
    };

    /**
     * Configuration for a camcorder profile/encoder profiles object.
     */
    struct CamcorderProfile {
        /**
         *  Returns on ordered list of the video codec configurations in
         *  decreasing preference. The returned object is only valid
         *  during the lifetime of this object.
         */
        std::vector<const VideoCodec *> getVideoCodecs() const;

        /**
         *  Returns on ordered list of the audio codec configurations in
         *  decreasing preference. The returned object is only valid
         *  during the lifetime of this object.
         */
        std::vector<const AudioCodec *> getAudioCodecs() const;

        /** Returns the default duration in seconds. */
        int getDuration() const {
            return mDuration;
        }

        /** Returns the preferred file format. */
        int getFileFormat() const {
            return mFileFormat;
        }

        CamcorderProfile(const CamcorderProfile& copy) = default;

        ~CamcorderProfile() = default;

    private:
        /**
         * Constructs an empty object with no audio/video profiles.
         */
        CamcorderProfile()
            : mCameraId(0),
              mFileFormat(OUTPUT_FORMAT_THREE_GPP),
              mQuality(CAMCORDER_QUALITY_HIGH),
              mDuration(0) {}

        int mCameraId;
        output_format mFileFormat;
        camcorder_quality mQuality;
        int mDuration;
        std::vector<VideoCodec> mVideoCodecs;
        std::vector<AudioCodec> mAudioCodecs;
        friend class MediaProfiles;
    };

    /**
     * Returns the CamcorderProfile object for the given camera at
     * the given quality level, or null if it does not exist.
     */
    const CamcorderProfile *getCamcorderProfile(
            int cameraId, camcorder_quality quality) const;

    /**
     * Returns the value for the given param name for the given camera at
     * the given quality level, or -1 if error.
     *
     * Supported param name are:
     * duration - the recording duration.
     * file.format - output file format. see mediarecorder.h for details
     * vid.codec - video encoder. see mediarecorder.h for details.
     * aud.codec - audio encoder. see mediarecorder.h for details.
     * vid.width - video frame width
     * vid.height - video frame height
     * vid.fps - video frame rate
     * vid.bps - video bit rate
     * aud.bps - audio bit rate
     * aud.hz - audio sample rate
     * aud.ch - number of audio channels
     */
    int getCamcorderProfileParamByName(const char *name, int cameraId,
                                       camcorder_quality quality) const;

    /**
     * Returns true if a profile for the given camera at the given quality exists,
     * or false if not.
     */
    bool hasCamcorderProfile(int cameraId, camcorder_quality quality) const;

    /**
     * Returns the output file formats supported.
     */
    Vector<output_format> getOutputFileFormats() const;

    /**
     * Returns the video encoders supported.
     */
    Vector<video_encoder> getVideoEncoders() const;

    /**
     * Returns the value for the given param name for the given video encoder
     * returned from getVideoEncoderByIndex or -1 if error.
     *
     * Supported param name are:
     * enc.vid.width.min - min video frame width
     * enc.vid.width.max - max video frame width
     * enc.vid.height.min - min video frame height
     * enc.vid.height.max - max video frame height
     * enc.vid.bps.min - min bit rate in bits per second
     * enc.vid.bps.max - max bit rate in bits per second
     * enc.vid.fps.min - min frame rate in frames per second
     * enc.vid.fps.max - max frame rate in frames per second
     */
    int getVideoEncoderParamByName(const char *name, video_encoder codec) const;

    /**
     * Returns the audio encoders supported.
     */
    Vector<audio_encoder> getAudioEncoders() const;

    /**
     * Returns the value for the given param name for the given audio encoder
     * returned from getAudioEncoderByIndex or -1 if error.
     *
     * Supported param name are:
     * enc.aud.ch.min - min number of channels
     * enc.aud.ch.max - max number of channels
     * enc.aud.bps.min - min bit rate in bits per second
     * enc.aud.bps.max - max bit rate in bits per second
     * enc.aud.hz.min - min sample rate in samples per second
     * enc.aud.hz.max - max sample rate in samples per second
     */
    int getAudioEncoderParamByName(const char *name, audio_encoder codec) const;

    /**
      * Returns the video decoders supported.
      */
    Vector<video_decoder> getVideoDecoders() const;

     /**
      * Returns the audio decoders supported.
      */
    Vector<audio_decoder> getAudioDecoders() const;

    /**
     * Returns the number of image encoding quality levels supported.
     */
    Vector<int> getImageEncodingQualityLevels(int cameraId) const;

    /**
     * Returns the start time offset (in ms) for the given camera Id.
     * If the given camera Id does not exist, -1 will be returned.
     */
    int getStartTimeOffsetMs(int cameraId) const;

private:
    enum {
        // Camcorder profiles (high/low) and timelapse profiles (high/low)
        kNumRequiredProfiles = 4,
    };

    MediaProfiles& operator=(const MediaProfiles&);  // Don't call me
    MediaProfiles(const MediaProfiles&);             // Don't call me
    MediaProfiles() {}                               // Dummy default constructor
    ~MediaProfiles();                                // Don't delete me

    struct VideoEncoderCap {
        // Ugly constructor
        VideoEncoderCap(video_encoder codec,
                        int minBitRate, int maxBitRate,
                        int minFrameWidth, int maxFrameWidth,
                        int minFrameHeight, int maxFrameHeight,
                        int minFrameRate, int maxFrameRate)
            : mCodec(codec),
              mMinBitRate(minBitRate), mMaxBitRate(maxBitRate),
              mMinFrameWidth(minFrameWidth), mMaxFrameWidth(maxFrameWidth),
              mMinFrameHeight(minFrameHeight), mMaxFrameHeight(maxFrameHeight),
              mMinFrameRate(minFrameRate), mMaxFrameRate(maxFrameRate) {}

         ~VideoEncoderCap() {}

        video_encoder mCodec;
        int mMinBitRate, mMaxBitRate;
        int mMinFrameWidth, mMaxFrameWidth;
        int mMinFrameHeight, mMaxFrameHeight;
        int mMinFrameRate, mMaxFrameRate;
    };

    struct AudioEncoderCap {
        // Ugly constructor
        AudioEncoderCap(audio_encoder codec,
                        int minBitRate, int maxBitRate,
                        int minSampleRate, int maxSampleRate,
                        int minChannels, int maxChannels)
            : mCodec(codec),
              mMinBitRate(minBitRate), mMaxBitRate(maxBitRate),
              mMinSampleRate(minSampleRate), mMaxSampleRate(maxSampleRate),
              mMinChannels(minChannels), mMaxChannels(maxChannels) {}

        ~AudioEncoderCap() {}

        audio_encoder mCodec;
        int mMinBitRate, mMaxBitRate;
        int mMinSampleRate, mMaxSampleRate;
        int mMinChannels, mMaxChannels;
    };

    struct VideoDecoderCap {
        VideoDecoderCap(video_decoder codec): mCodec(codec) {}
        ~VideoDecoderCap() {}

        video_decoder mCodec;
    };

    struct AudioDecoderCap {
        AudioDecoderCap(audio_decoder codec): mCodec(codec) {}
        ~AudioDecoderCap() {}

        audio_decoder mCodec;
    };

    struct NameToTagMap {
        const char* name;
        int tag;
    };

    struct ImageEncodingQualityLevels {
        int mCameraId;
        Vector<int> mLevels;
    };

    int getCamcorderProfileIndex(int cameraId, camcorder_quality quality) const;
    void initRequiredProfileRefs(const Vector<int>& cameraIds);
    int getRequiredProfileRefIndex(int cameraId);

    // Debug
    static void logVideoCodec(const VideoCodec& codec);
    static void logAudioCodec(const AudioCodec& codec);
    static void logVideoEncoderCap(const VideoEncoderCap& cap);
    static void logAudioEncoderCap(const AudioEncoderCap& cap);
    static void logVideoDecoderCap(const VideoDecoderCap& cap);
    static void logAudioDecoderCap(const AudioDecoderCap& cap);

    // Returns true if xmlFile exists.
    // TODO: Add runtime validation.
    static bool checkXmlFile(const char* xmlFile);

    // If the xml configuration file does exist, use the settings
    // from the xml
    static MediaProfiles* createInstanceFromXmlFile(const char *xml);
    static output_format createEncoderOutputFileFormat(const char **atts, size_t natts);
    static void createVideoCodec(const char **atts, size_t natts, MediaProfiles *profiles);
    static void createAudioCodec(const char **atts, size_t natts, MediaProfiles *profiles);
    static AudioDecoderCap* createAudioDecoderCap(const char **atts, size_t natts);
    static VideoDecoderCap* createVideoDecoderCap(const char **atts, size_t natts);
    static VideoEncoderCap* createVideoEncoderCap(const char **atts, size_t natts);
    static AudioEncoderCap* createAudioEncoderCap(const char **atts, size_t natts);

    static CamcorderProfile* createCamcorderProfile(
                int cameraId, const char **atts, size_t natts, Vector<int>& cameraIds);

    static int getCameraId(const char **atts, size_t natts);

    void addStartTimeOffset(int cameraId, const char **atts, size_t natts);

    ImageEncodingQualityLevels* findImageEncodingQualityLevels(int cameraId) const;
    void addImageEncodingQualityLevel(int cameraId, const char** atts, size_t natts);

    // Customized element tag handler for parsing the xml configuration file.
    static void startElementHandler(void *userData, const char *name, const char **atts);

    // If the xml configuration file does not exist, use hard-coded values
    static MediaProfiles* createDefaultInstance();

    static CamcorderProfile *createDefaultCamcorderQcifProfile(camcorder_quality quality);
    static CamcorderProfile *createDefaultCamcorderCifProfile(camcorder_quality quality);
    static void createDefaultCamcorderLowProfiles(
            MediaProfiles::CamcorderProfile **lowProfile,
            MediaProfiles::CamcorderProfile **lowSpecificProfile);
    static void createDefaultCamcorderHighProfiles(
            MediaProfiles::CamcorderProfile **highProfile,
            MediaProfiles::CamcorderProfile **highSpecificProfile);

    static CamcorderProfile *createDefaultCamcorderTimeLapseQcifProfile(camcorder_quality quality);
    static CamcorderProfile *createDefaultCamcorderTimeLapse480pProfile(camcorder_quality quality);
    static void createDefaultCamcorderTimeLapseLowProfiles(
            MediaProfiles::CamcorderProfile **lowTimeLapseProfile,
            MediaProfiles::CamcorderProfile **lowSpecificTimeLapseProfile);
    static void createDefaultCamcorderTimeLapseHighProfiles(
            MediaProfiles::CamcorderProfile **highTimeLapseProfile,
            MediaProfiles::CamcorderProfile **highSpecificTimeLapseProfile);

    static void createDefaultCamcorderProfiles(MediaProfiles *profiles);
    static void createDefaultVideoEncoders(MediaProfiles *profiles);
    static void createDefaultAudioEncoders(MediaProfiles *profiles);
    static void createDefaultVideoDecoders(MediaProfiles *profiles);
    static void createDefaultAudioDecoders(MediaProfiles *profiles);
    static void createDefaultEncoderOutputFileFormats(MediaProfiles *profiles);
    static void createDefaultImageEncodingQualityLevels(MediaProfiles *profiles);
    static void createDefaultImageDecodingMaxMemory(MediaProfiles *profiles);

    static VideoEncoderCap* createDefaultH263VideoEncoderCap();
    static VideoEncoderCap* createDefaultM4vVideoEncoderCap();
    static AudioEncoderCap* createDefaultAmrNBEncoderCap();

    static int findTagForName(const NameToTagMap *map, size_t nMappings, const char *name);

    /**
     * Check on existing profiles with the following criteria:
     * 1. Low quality profile must have the lowest video
     *    resolution product (width x height)
     * 2. High quality profile must have the highest video
     *    resolution product (width x height)
     *
     * and add required low/high quality camcorder/timelapse
     * profiles if they are not found. This allows to remove
     * duplicate profile definitions in the media_profiles.xml
     * file.
     */
    void checkAndAddRequiredProfilesIfNecessary();


    // Mappings from name (for instance, codec name) to enum value
    static const NameToTagMap sVideoEncoderNameMap[];
    static const NameToTagMap sAudioEncoderNameMap[];
    static const NameToTagMap sFileFormatMap[];
    static const NameToTagMap sVideoDecoderNameMap[];
    static const NameToTagMap sAudioDecoderNameMap[];
    static const NameToTagMap sCamcorderQualityNameMap[];

    static bool sIsInitialized;
    static MediaProfiles *sInstance;
    static Mutex sLock;
    int mCurrentCameraId;

    Vector<CamcorderProfile*> mCamcorderProfiles;
    Vector<AudioEncoderCap*>  mAudioEncoders;
    Vector<VideoEncoderCap*>  mVideoEncoders;
    Vector<AudioDecoderCap*>  mAudioDecoders;
    Vector<VideoDecoderCap*>  mVideoDecoders;
    Vector<output_format>     mEncoderOutputFileFormats;
    Vector<ImageEncodingQualityLevels *>  mImageEncodingQualityLevels;
    KeyedVector<int, int> mStartTimeOffsets;

    typedef struct {
        bool mHasRefProfile;      // Refers to an existing profile
        int  mRefProfileIndex;    // Reference profile index
        int  mResolutionProduct;  // width x height
    } RequiredProfileRefInfo;     // Required low and high profiles

    typedef struct {
        RequiredProfileRefInfo mRefs[kNumRequiredProfiles];
        int mCameraId;
    } RequiredProfiles;

    RequiredProfiles *mRequiredProfileRefs;
    Vector<int>              mCameraIds;
};

}; // namespace android

#endif // ANDROID_MEDIAPROFILES_H
