/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef ANDROID_SERVERS_CAMERA_CAMERA3_HEIC_COMPOSITE_STREAM_H
#define ANDROID_SERVERS_CAMERA_CAMERA3_HEIC_COMPOSITE_STREAM_H

#include <algorithm>
#include <android/data_space.h>
#include <memory>
#include <queue>

#include <gui/CpuConsumer.h>

#include <media/hardware/VideoAPI.h>
#include <media/MediaCodecBuffer.h>
#include <media/stagefright/foundation/ALooper.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/MediaCodec.h>
#include <media/stagefright/MediaMuxer.h>
#include <ultrahdr/ultrahdrcommon.h>
#include <ultrahdr/gainmapmetadata.h>

#include "CompositeStream.h"

namespace android {
namespace camera3 {

class HeicCompositeStream : public CompositeStream, public Thread,
        public CpuConsumer::FrameAvailableListener {
public:
    HeicCompositeStream(sp<CameraDeviceBase> device,
            wp<hardware::camera2::ICameraDeviceCallbacks> cb);
    ~HeicCompositeStream() override;

    static bool isHeicCompositeStream(const sp<Surface>& surface, bool isCompositeHeicDisabled,
                                      bool isCompositeHeicUltraHDRDisabled);
    static bool isHeicCompositeStreamInfo(const OutputStreamInfo& streamInfo,
                                          bool isCompositeHeicDisabled,
                                          bool isCompositeHeicUltraHDRDisabled);
    static bool isHeicCompositeStreamOutput(const OutputConfiguration& output,
                                      bool isCompositeHeicDisabled,
                                      bool isCompositeHeicUltraHDRDisabled);

    status_t createInternalStreams(const std::vector<SurfaceHolder>& consumers,
                                   bool hasDeferredConsumer, uint32_t width, uint32_t height,
                                   int format, camera_stream_rotation_t rotation, int* id,
                                   const std::string& physicalCameraId,
                                   const std::unordered_set<int32_t>& sensorPixelModesUsed,
                                   std::vector<int>* surfaceIds, int streamSetId, bool isShared,
                                   int32_t colorSpace, int64_t dynamicProfile,
                                   int64_t streamUseCase, bool useReadoutTimestamp,
                                   int dataspace) override;

    status_t setConsumerSurfaces(int streamId, const std::vector<SurfaceHolder>& consumers,
                                 std::vector<int>* surfaceIds /*out*/) override;

    status_t updateStream(int streamId, const std::vector<SurfaceHolder>& newSurfaces,
            KeyedVector<sp<Surface>, size_t> * outputMap, int64_t* lastFrameNumber) override;

    status_t deleteInternalStreams() override;

    status_t configureStream(bool outputConnected = true) override;

    status_t insertGbp(SurfaceMap* /*out*/outSurfaceMap, Vector<int32_t>* /*out*/outputStreamIds,
            int32_t* /*out*/currentStreamId) override;

    status_t insertCompositeStreamIds(std::vector<int32_t>* compositeStreamIds /*out*/) override;

    void onShutter(const CaptureResultExtras& resultExtras, nsecs_t timestamp) override;

    int getStreamId() override { return mMainImageStreamId; }

    // Use onShutter to keep track of frame number <-> timestamp mapping.
    void onBufferReleased(const BufferInfo& bufferInfo) override;
    void onBufferRequestForFrameNumber(uint64_t frameNumber, int streamId,
            const CameraMetadata& settings) override;

    // CpuConsumer listener implementation
    void onFrameAvailable(const BufferItem& item) override;

    // Return stream information about the internal camera streams
    static status_t getCompositeStreamInfo(const OutputStreamInfo &streamInfo,
            const CameraMetadata& ch, std::vector<OutputStreamInfo>* compositeOutput /*out*/);

    // Get composite stream stats
    void getStreamStats(hardware::CameraStreamStats*) override {};

    static bool isSizeSupportedByHeifEncoder(int32_t width, int32_t height,
            bool* useHeic, bool* useGrid, int64_t* stall, AString* hevcName = nullptr,
            bool allowSWCodec = false);
    static bool isInMemoryTempFileSupported();

    // HDR Gainmap subsampling
    static constexpr size_t kGainmapScale = 4;

protected:

    bool threadLoop() override;
    bool onStreamBufferError(const CaptureResultExtras& resultExtras) override;
    void onResultError(const CaptureResultExtras& resultExtras) override;
    void onRequestError(const CaptureResultExtras& resultExtras) override;

private:
    //
    // HEIC/HEVC Codec related structures, utility functions, and callbacks
    //
    struct CodecOutputBufferInfo {
        int32_t index;
        int32_t offset;
        int32_t size;
        int64_t timeUs;
        uint32_t flags;
    };

    struct CodecInputBufferInfo {
        int32_t index;
        int64_t timeUs;
        size_t tileIndex;
    };

    class CodecCallbackHandler : public AHandler {
    public:
        explicit CodecCallbackHandler(wp<HeicCompositeStream> parent, bool isGainmap = false) :
            mParent(parent), mIsGainmap(isGainmap) {}
        virtual void onMessageReceived(const sp<AMessage> &msg);
    private:
        wp<HeicCompositeStream> mParent;
        bool mIsGainmap;
    };

    enum {
        kWhatCallbackNotify,
    };

    bool              mUseHeic;
    sp<MediaCodec>    mCodec;
    sp<MediaCodec>    mGainmapCodec;
    sp<ALooper>       mCodecLooper, mCallbackLooper, mGainmapCallbackLooper;
    sp<CodecCallbackHandler> mCodecCallbackHandler, mGainmapCodecCallbackHandler;
    sp<AMessage>      mAsyncNotify, mGainmapAsyncNotify;
    sp<AMessage>      mFormat, mGainmapFormat;
    size_t            mNumOutputTiles, mNumGainmapOutputTiles;

    int32_t           mOutputWidth, mOutputHeight, mGainmapOutputWidth, mGainmapOutputHeight;
    size_t            mMaxHeicBufferSize;
    int32_t           mGridWidth, mGridHeight, mGainmapGridWidth, mGainmapGridHeight;
    size_t            mGridRows, mGridCols, mGainmapGridRows, mGainmapGridCols;
    bool              mUseGrid, mGainmapUseGrid; // Whether to use framework YUV frame tiling.

    static constexpr int64_t kNoFrameDropMaxPtsGap = -1000000;
    static constexpr int32_t kNoGridOpRate = 30;
    static constexpr int32_t kGridOpRate = 120;

    void onHeicOutputFrameAvailable(const CodecOutputBufferInfo& bufferInfo, bool isGainmap);
    void onHeicInputFrameAvailable(int32_t index, bool isGainmap);// Only called for YUV input mode.
    void onHeicFormatChanged(sp<AMessage>& newFormat, bool isGainmap);
    void onHeicGainmapFormatChanged(sp<AMessage>& newFormat);
    void onHeicCodecError();

    status_t initializeCodec(uint32_t width, uint32_t height,
            const sp<CameraDeviceBase>& cameraDevice);
    void deinitCodec();
    status_t initializeGainmapCodec();
    void deinitGainmapCodec();

    //
    // Composite stream related structures, utility functions and callbacks.
    //
    struct InputFrame {
        int32_t                   orientation;
        int32_t                   quality;

        CpuConsumer::LockedBuffer          appSegmentBuffer;
        std::vector<CodecOutputBufferInfo> codecOutputBuffers, gainmapCodecOutputBuffers;
        std::unique_ptr<CameraMetadata>    result;

        // Fields that are only applicable to HEVC tiling.
        CpuConsumer::LockedBuffer          yuvBuffer;
        std::vector<CodecInputBufferInfo>  codecInputBuffers, gainmapCodecInputBuffers;

        bool                      error;     // Main input image buffer error
        bool                      outputUpdated; // Output surface switched during processing
        sp<Surface>               currentSurface; // Output surface for this capture request
        bool                      exifError; // Exif/APP_SEGMENT buffer error
        int64_t                   timestamp;
        int32_t                   requestId;

        sp<AMessage>              format, gainmapFormat;
        sp<MediaMuxer>            muxer;
        int                       fenceFd;
        int                       fileFd;
        ssize_t                   trackIndex, gainmapTrackIndex;
        ANativeWindowBuffer       *anb;

        bool                      appSegmentWritten;
        size_t                    pendingOutputTiles, gainmapPendingOutputTiles;
        size_t                    codecInputCounter, gainmapCodecInputCounter;

        std::unique_ptr<CpuConsumer::LockedBuffer> baseImage, gainmapImage;
        std::unique_ptr<ultrahdr::uhdr_raw_image_ext> baseBuffer, gainmap;
        std::unique_ptr<uint8_t[]> gainmapChroma;
        std::vector<uint8_t> isoGainmapMetadata;

        InputFrame()
            : orientation(0),
              quality(kDefaultJpegQuality),
              error(false),
              outputUpdated(false),
              exifError(false),
              timestamp(-1),
              requestId(-1),
              fenceFd(-1),
              fileFd(-1),
              trackIndex(-1),
              gainmapTrackIndex(-1),
              anb(nullptr),
              appSegmentWritten(false),
              pendingOutputTiles(0),
              gainmapPendingOutputTiles(0),
              codecInputCounter(0),
              gainmapCodecInputCounter(0) {}
    };

    void compilePendingInputLocked();
    // Find first complete and valid frame with smallest frame number
    bool getNextReadyInputLocked(int64_t *frameNumber /*out*/);
    // Find next failing frame number with smallest frame number and return respective frame number
    int64_t getNextFailingInputLocked();

    status_t processInputFrame(int64_t frameNumber, InputFrame &inputFrame);
    status_t processCodecInputFrame(InputFrame &inputFrame);
    status_t processCodecGainmapInputFrame(InputFrame &inputFrame);
    status_t startMuxerForInputFrame(int64_t frameNumber, InputFrame &inputFrame);
    status_t processAppSegment(int64_t frameNumber, InputFrame &inputFrame);
    status_t processOneCodecOutputFrame(int64_t frameNumber, InputFrame &inputFrame);
    status_t processOneCodecGainmapOutputFrame(int64_t frameNumber, InputFrame &inputFrame);
    status_t processCompletedInputFrame(int64_t frameNumber, InputFrame &inputFrame);

    void releaseInputFrameLocked(int64_t frameNumber, InputFrame *inputFrame /*out*/);
    void releaseInputFramesLocked();

    size_t findAppSegmentsSize(const uint8_t* appSegmentBuffer, size_t maxSize,
            size_t* app1SegmentSize);
    status_t copyOneYuvTile(sp<MediaCodecBuffer>& codecBuffer,
            const CpuConsumer::LockedBuffer& yuvBuffer,
            size_t top, size_t left, size_t width, size_t height);
    void initCopyRowFunction(int32_t width);
    static size_t calcAppSegmentMaxSize(const CameraMetadata& info);
    void updateCodecQualityLocked(int32_t quality);

    static constexpr nsecs_t kWaitDuration = 10000000; // 10 ms
    static constexpr int32_t kDefaultJpegQuality = 99;
    static constexpr auto kJpegDataSpace = HAL_DATASPACE_V0_JFIF;
    static constexpr android_dataspace kAppSegmentDataSpace =
            static_cast<android_dataspace>(HAL_DATASPACE_JPEG_APP_SEGMENTS);
    static constexpr android_dataspace kHeifDataSpace =
            static_cast<android_dataspace>(HAL_DATASPACE_HEIF);
    android_dataspace mInternalDataSpace = kHeifDataSpace;
    // Use the limit of pipeline depth in the API sepc as maximum number of acquired
    // app segment buffers.
    static constexpr uint32_t kMaxAcquiredAppSegment = 8;

    int               mAppSegmentStreamId, mAppSegmentSurfaceId;
    sp<CpuConsumer>   mAppSegmentConsumer;
    sp<Surface>       mAppSegmentSurface;
    size_t            mAppSegmentMaxSize;
    std::queue<int64_t> mAppSegmentFrameNumbers;
    CameraMetadata    mStaticInfo;

    int               mMainImageStreamId, mMainImageSurfaceId;
    sp<Surface>       mMainImageSurface;
    sp<CpuConsumer>   mMainImageConsumer; // Only applicable for HEVC codec.
    bool              mYuvBufferAcquired; // Only applicable to HEVC codec
    std::queue<int64_t> mMainImageFrameNumbers;

    static constexpr int32_t    kMaxOutputSurfaceProducerCount = 1;
    sp<Surface>                 mOutputSurface;
    sp<StreamSurfaceListener>   mStreamSurfaceListener;
    int32_t                     mDequeuedOutputBufferCnt;

    // Map from frame number to JPEG setting of orientation+quality
    struct HeicSettings {
        int32_t orientation;
        int32_t quality;
        int64_t timestamp;
        int32_t requestId;
        bool shutterNotified;

        HeicSettings() : orientation(0), quality(95), timestamp(0),
                requestId(-1), shutterNotified(false) {}
        HeicSettings(int32_t _orientation, int32_t _quality) :
                orientation(_orientation),
                quality(_quality), timestamp(0),
                requestId(-1), shutterNotified(false) {}

    };
    std::map<int64_t, HeicSettings> mSettingsByFrameNumber;

    // Keep all incoming APP segment Blob buffer pending further processing.
    std::vector<int64_t> mInputAppSegmentBuffers;

    // Keep all incoming HEIC blob buffer pending further processing.
    std::vector<CodecOutputBufferInfo> mCodecOutputBuffers, mGainmapCodecOutputBuffers;
    std::queue<int64_t> mCodecOutputBufferFrameNumbers, mCodecGainmapOutputBufferFrameNumbers;
    size_t mCodecOutputCounter, mCodecGainmapOutputCounter;
    int32_t mQuality;

    // Keep all incoming Yuv buffer pending tiling and encoding (for HEVC YUV tiling only)
    std::vector<int64_t> mInputYuvBuffers;
    // Keep all codec input buffers ready to be filled out (for HEVC YUV tiling only)
    std::vector<int32_t> mCodecInputBuffers, mGainmapCodecInputBuffers;

    // Artificial strictly incremental YUV grid timestamp to make encoder happy.
    int64_t mGridTimestampUs;

    // Indexed by frame number. In most common use case, entries are accessed in order.
    std::map<int64_t, InputFrame> mPendingInputFrames;

    // Function pointer of libyuv row copy.
    void (*mFnCopyRow)(const uint8_t* src, uint8_t* dst, int width);

    // A set of APP_SEGMENT error frame numbers
    std::set<int64_t> mExifErrorFrameNumbers;
    void flagAnExifErrorFrameNumber(int64_t frameNumber);

    // The status id for tracking the active/idle status of this composite stream
    int mStatusId;
    void markTrackerIdle();

    //APP_SEGMENT stream supported
    bool mAppSegmentSupported = false;

    bool mHDRGainmapEnabled = false;

    // UltraHDR tonemap color and format aspects
    static constexpr uhdr_img_fmt_t kUltraHdrInputFmt = UHDR_IMG_FMT_24bppYCbCrP010;
    static constexpr uhdr_color_gamut kUltraHdrInputGamut = UHDR_CG_BT_2100;
    static constexpr uhdr_color_transfer kUltraHdrInputTransfer = UHDR_CT_HLG;
    static constexpr uhdr_color_range kUltraHdrInputRange = UHDR_CR_FULL_RANGE;

    static constexpr uhdr_img_fmt_t kUltraHdrOutputFmt = UHDR_IMG_FMT_12bppYCbCr420;
    static constexpr uhdr_color_gamut kUltraHdrOutputGamut = UHDR_CG_DISPLAY_P3;
    static constexpr uhdr_color_transfer kUltraHdrOutputTransfer = UHDR_CT_SRGB;
    static constexpr uhdr_color_range kUltraHdrOutputRange = UHDR_CR_FULL_RANGE;

    static constexpr auto kUltraHDRDataSpace =
        aidl::android::hardware::graphics::common::Dataspace::HEIF_ULTRAHDR;

    // MediaMuxer/Codec color and format aspects for base image and gainmap metadata
    static constexpr int32_t kCodecColorFormat = COLOR_FormatYUV420Flexible;
    static constexpr ColorAspects::Primaries kCodecColorPrimaries =
        ColorAspects::Primaries::PrimariesEG432;
    static constexpr ColorAspects::MatrixCoeffs kCodecColorMatrix =
        ColorAspects::MatrixCoeffs::MatrixUnspecified;
    static constexpr ColorAspects::Transfer kCodecColorTransfer =
        ColorAspects::Transfer::TransferSRGB;
    static constexpr ColorAspects::Range kCodecColorRange =
        ColorAspects::Range::RangeFull;

    // MediaMuxer/Codec color and format aspects for gainmap as per ISO 23008-12:2024
    static constexpr int32_t kCodecGainmapColorFormat = COLOR_FormatYUV420Flexible;
    static constexpr ColorAspects::Primaries kCodecGainmapColorPrimaries =
        ColorAspects::Primaries::PrimariesUnspecified;
    static constexpr ColorAspects::MatrixCoeffs kCodecGainmapColorMatrix =
        ColorAspects::MatrixCoeffs::MatrixUnspecified;
    static constexpr ColorAspects::Transfer kCodecGainmapColorTransfer =
        ColorAspects::Transfer::TransferUnspecified;
    static constexpr ColorAspects::Range kCodecGainmapColorRange =
        ColorAspects::Range::RangeFull;


    status_t generateBaseImageAndGainmap(InputFrame &inputFrame);
};

}; // namespace camera3
}; // namespace android

#endif //ANDROID_SERVERS_CAMERA_CAMERA3_HEIC_COMPOSITE_STREAM_H
