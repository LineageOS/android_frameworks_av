LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_AIDL_INCLUDES := \
    frameworks/av/media/libmedia/aidl

LOCAL_SRC_FILES:= \
    aidl/android/IGraphicBufferSource.aidl \
    aidl/android/IOMXBufferSource.aidl

LOCAL_SRC_FILES += \
    IDataSource.cpp \
    IHDCP.cpp \
    BufferingSettings.cpp \
    mediaplayer.cpp \
    IMediaCodecList.cpp \
    IMediaCodecService.cpp \
    IMediaHTTPConnection.cpp \
    IMediaHTTPService.cpp \
    IMediaExtractor.cpp           \
    IMediaExtractorService.cpp \
    IMediaPlayerService.cpp \
    IMediaPlayerClient.cpp \
    IMediaRecorderClient.cpp \
    IMediaPlayer.cpp \
    IMediaRecorder.cpp \
    IMediaSource.cpp \
    IRemoteDisplay.cpp \
    IRemoteDisplayClient.cpp \
    IResourceManagerClient.cpp \
    IResourceManagerService.cpp \
    IStreamSource.cpp \
    MediaCodecBuffer.cpp \
    MediaCodecInfo.cpp \
    MediaDefs.cpp \
    MediaUtils.cpp \
    Metadata.cpp \
    mediarecorder.cpp \
    IMediaMetadataRetriever.cpp \
    mediametadataretriever.cpp \
    MidiDeviceInfo.cpp \
    MidiIoWrapper.cpp \
    JetPlayer.cpp \
    IOMX.cpp \
    MediaScanner.cpp \
    MediaScannerClient.cpp \
    CharacterEncodingDetector.cpp \
    IMediaDeathNotifier.cpp \
    MediaProfiles.cpp \
    MediaResource.cpp \
    MediaResourcePolicy.cpp \
    OMXBuffer.cpp \
    Visualizer.cpp \
    StringArray.cpp \
    omx/1.0/WGraphicBufferSource.cpp \
    omx/1.0/WOmx.cpp \
    omx/1.0/WOmxBufferSource.cpp \
    omx/1.0/WOmxNode.cpp \
    omx/1.0/WOmxObserver.cpp \

LOCAL_SHARED_LIBRARIES := \
        libui liblog libcutils libutils libbinder libsonivox libicuuc libicui18n libexpat \
        libcamera_client libstagefright_foundation \
        libgui libdl libaudioutils libaudioclient \
        libmedia_helper libmediadrm \
        libmediametrics \
        libbase \
        libhidlbase \
        libhidltransport \
        libhwbinder \
        libhidlmemory \
        android.hidl.base@1.0 \
        android.hidl.memory@1.0 \
        android.hidl.token@1.0-utils \
        android.hardware.graphics.common@1.0 \
        android.hardware.graphics.bufferqueue@1.0 \
        android.hardware.media@1.0 \
        android.hardware.media.omx@1.0 \

LOCAL_EXPORT_SHARED_LIBRARY_HEADERS := \
        libbinder \
        libsonivox \
        libmediadrm \
        android.hidl.token@1.0-utils \
        android.hardware.media.omx@1.0 \
        android.hidl.memory@1.0 \

LOCAL_HEADER_LIBRARIES := libmedia_headers

# for memory heap analysis
LOCAL_STATIC_LIBRARIES := libc_malloc_debug_backtrace libc_logging

LOCAL_WHOLE_STATIC_LIBRARIES := libavmediaextentions

LOCAL_MODULE:= libmedia

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk

LOCAL_C_INCLUDES := \
    $(TOP)/system/libhidl/base/include \
    $(TOP)/frameworks/native/include/media/openmax \
    $(TOP)/frameworks/av/include/media/ \
    $(TOP)/frameworks/av/media/libmedia/aidl \
    $(TOP)/frameworks/av/media/libavextensions \
    $(TOP)/frameworks/av/include \
    $(TOP)/frameworks/native/include \
    $(call include-path-for, audio-utils)

LOCAL_EXPORT_C_INCLUDE_DIRS := \
    frameworks/av/include/media \
    frameworks/av/media/libmedia/aidl \

LOCAL_CFLAGS += -Werror -Wno-error=deprecated-declarations -Wall
LOCAL_SANITIZE := unsigned-integer-overflow signed-integer-overflow cfi
LOCAL_SANITIZE_DIAG := cfi

include $(BUILD_SHARED_LIBRARY)
