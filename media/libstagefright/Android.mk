LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)


LOCAL_SRC_FILES:=                         \
        ACodec.cpp                        \
        ACodecBufferChannel.cpp           \
        AACExtractor.cpp                  \
        AACWriter.cpp                     \
        AMRExtractor.cpp                  \
        AMRWriter.cpp                     \
        AudioPlayer.cpp                   \
        AudioSource.cpp                   \
        BufferImpl.cpp                    \
        CallbackDataSource.cpp            \
        CameraSource.cpp                  \
        CameraSourceTimeLapse.cpp         \
        DataConverter.cpp                 \
        DataSource.cpp                    \
        DataURISource.cpp                 \
        ESDS.cpp                          \
        FileSource.cpp                    \
        FLACExtractor.cpp                 \
        FrameRenderTracker.cpp            \
        HTTPBase.cpp                      \
        HevcUtils.cpp                     \
        JPEGSource.cpp                    \
        MP3Extractor.cpp                  \
        MPEG2TSWriter.cpp                 \
        MPEG4Extractor.cpp                \
        MPEG4Writer.cpp                   \
        MediaAdapter.cpp                  \
        MediaClock.cpp                    \
        MediaCodec.cpp                    \
        MediaCodecList.cpp                \
        MediaCodecListOverrides.cpp       \
        MediaCodecSource.cpp              \
        MediaExtractor.cpp                \
        MediaSync.cpp                     \
        MidiExtractor.cpp                 \
        http/MediaHTTP.cpp                \
        MediaMuxer.cpp                    \
        MediaSource.cpp                   \
        NuCachedSource2.cpp               \
        NuMediaExtractor.cpp              \
        OMXClient.cpp                     \
        OggExtractor.cpp                  \
        SampleIterator.cpp                \
        SampleTable.cpp                   \
        SimpleDecodingSource.cpp          \
        SkipCutBuffer.cpp                 \
        StagefrightMediaScanner.cpp       \
        StagefrightMetadataRetriever.cpp  \
        SurfaceMediaSource.cpp            \
        SurfaceUtils.cpp                  \
        ThrottledSource.cpp               \
        Utils.cpp                         \
        VBRISeeker.cpp                    \
        VideoFrameScheduler.cpp           \
        WAVExtractor.cpp                  \
        XINGSeeker.cpp                    \
        avc_utils.cpp                     \

LOCAL_C_INCLUDES:= \
        $(TOP)/frameworks/av/include/media/ \
        $(TOP)/frameworks/av/include/media/stagefright/timedtext \
        $(TOP)/frameworks/native/include/media/hardware \
        $(TOP)/frameworks/native/include/media/openmax \
        $(TOP)/external/flac/include \
        $(TOP)/external/tremolo \
        $(TOP)/external/libvpx/libwebm \
        $(TOP)/external/icu/icu4c/source/common \
        $(TOP)/external/icu/icu4c/source/i18n \
        $(TOP)/system/netd/include \
        $(call include-path-for, audio-utils)

LOCAL_SHARED_LIBRARIES := \
        libaudioutils \
        libbinder \
        libcamera_client \
        libcrypto \
        libcutils \
        libdl \
        libdrmframework \
        libexpat \
        libgui \
        liblog \
        libmedia \
        libaudioclient \
        libmediametrics \
        libmediautils \
        libnetd_client \
        libsonivox \
        libstagefright_omx \
        libui \
        libutils \
        libvorbisidec \
        libmediadrm \
        libnativewindow \

LOCAL_STATIC_LIBRARIES := \
        libstagefright_color_conversion \
        libyuv_static \
        libstagefright_aacenc \
        libstagefright_matroska \
        libstagefright_mediafilter \
        libstagefright_webm \
        libstagefright_timedtext \
        libvpx \
        libwebm \
        libstagefright_mpeg2ts \
        libstagefright_id3 \
        libFLAC \

LOCAL_SHARED_LIBRARIES += \
        libmedia_helper \
        libstagefright_foundation \
        libdl \
        libRScpp \
        libhidlbase \
        libhidlmemory \
        android.hidl.allocator@1.0 \
        android.hidl.memory@1.0 \
        android.hardware.media.omx@1.0 \
        libstagefright_xmlparser@1.0 \

LOCAL_EXPORT_SHARED_LIBRARY_HEADERS := libmedia

ifeq ($(TARGET_HAS_LEGACY_CAMERA_HAL1),true)
LOCAL_CFLAGS += -DCAMCORDER_GRALLOC_SOURCE
endif

LOCAL_CFLAGS += -Wno-multichar -Werror -Wno-error=deprecated-declarations -Wall

# enable experiments only in userdebug and eng builds
ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DENABLE_STAGEFRIGHT_EXPERIMENTS
endif

LOCAL_SANITIZE := unsigned-integer-overflow signed-integer-overflow cfi
LOCAL_SANITIZE_DIAG := cfi

LOCAL_MODULE:= libstagefright

LOCAL_MODULE_TAGS := optional

include $(BUILD_SHARED_LIBRARY)

include $(call all-makefiles-under,$(LOCAL_PATH))
