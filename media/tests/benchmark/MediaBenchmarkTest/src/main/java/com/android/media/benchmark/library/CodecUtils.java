package com.android.media.benchmark.library;

import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.media.MediaFormat;
import android.os.Build;

import java.util.ArrayList;
import java.util.List;

public class CodecUtils {
    private CodecUtils() {}
    /**
     * Queries the MediaCodecList and returns codec names of supported codecs.
     *
     * @param mimeType  Mime type of input
     * @param isEncoder Specifies encoder or decoder
     * @return ArrayList of codec names
     */
    public static List<String> selectCodecs(String mimeType, boolean isEncoder) {
        MediaCodecList codecList = new MediaCodecList(MediaCodecList.REGULAR_CODECS);
        MediaCodecInfo[] codecInfos = codecList.getCodecInfos();
        ArrayList<String> supportedCodecs = new ArrayList<>();
        for (MediaCodecInfo codecInfo : codecInfos) {
            if (isEncoder != codecInfo.isEncoder()) {
                continue;
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && codecInfo.isAlias()) {
                continue;
            }
            String[] types = codecInfo.getSupportedTypes();
            for (String type : types) {
                if (type.equalsIgnoreCase(mimeType)) {
                    supportedCodecs.add(codecInfo.getName());
                }
            }
        }
        return supportedCodecs;
    }
    /**
     * Returns a decoder that supports the given MediaFormat along with the "features".
     *
     * @param format  MediaFormat that the codec should support
     * @param isSoftware Specifies if this is a software / hardware decoder
     * @param isEncoder Specifies if the request is for encoders or not.
     * @param features is the feature that should be supported.
     * @return name of the codec.
     */
    public static String getMediaCodec(MediaFormat format, boolean isSoftware,
                                  String[] features, boolean isEncoder) {
        MediaCodecList mcl = new MediaCodecList(MediaCodecList.ALL_CODECS);
        MediaCodecInfo[] codecInfos = mcl.getCodecInfos();
        String mime = format.getString(MediaFormat.KEY_MIME);
        for (MediaCodecInfo codecInfo : codecInfos) {
            if (codecInfo.isEncoder() != isEncoder) continue;
            if (isSoftware != codecInfo.isSoftwareOnly()) continue;
            String[] types = codecInfo.getSupportedTypes();
            for (String type : types) {
                if (type.equalsIgnoreCase(mime)) {
                    boolean isOk = true;
                    MediaCodecInfo.CodecCapabilities codecCapabilities =
                        codecInfo.getCapabilitiesForType(type);
                    if (!codecCapabilities.isFormatSupported(format)) {
                        isOk = false;
                    }
                    if (features != null) {
                        for (String feature : features) {
                            if (!codecCapabilities.isFeatureSupported(feature)) {
                                isOk = false;
                                break;
                            }
                        }
                    }
                    if (isOk) {
                        return codecInfo.getName();
                    }
                }
            }
        }
        return null;
    }

    /**
     * Returns a codec that matches the given mime and software/hardware type, without checking
     * specific capabilities or format support.
     *
     * @param mime Mime type of the codec.
     * @param isSoftware Specifies if this is a software / hardware decoder/encoder.
     * @param isEncoder Specifies if the request is for encoders or not.
     * @return name of the codec.
     */
    public static String getMediaCodec(String mime, boolean isSoftware, boolean isEncoder) {
        MediaCodecList mcl = new MediaCodecList(MediaCodecList.ALL_CODECS);
        MediaCodecInfo[] codecInfos = mcl.getCodecInfos();
        for (MediaCodecInfo codecInfo : codecInfos) {
            if (codecInfo.isEncoder() != isEncoder) continue;
            if (isSoftware != codecInfo.isSoftwareOnly()) continue;
            String[] types = codecInfo.getSupportedTypes();
            for (String type : types) {
                if (type.equalsIgnoreCase(mime)) {
                    return codecInfo.getName();
                }
            }
        }
        return null;
    }

    /**
     * Returns compression ratio for a given mediaType.
     * @param mediaType mime type for which compression ratio is to be returned.
     */
    public static float getCompressionRatio(String mediaType) {
        return switch (mediaType) {
            case MediaFormat.MIMETYPE_AUDIO_FLAC -> 0.7f;
            case MediaFormat.MIMETYPE_AUDIO_G711_MLAW,
                MediaFormat.MIMETYPE_AUDIO_G711_ALAW,
                MediaFormat.MIMETYPE_AUDIO_MSGSM -> 0.5f;
            case MediaFormat.MIMETYPE_AUDIO_RAW -> 1.0f;
            default -> 0.1f;
        };
    }
}
