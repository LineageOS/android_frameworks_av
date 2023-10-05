package com.android.media.benchmark.library;

import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.media.MediaFormat;
import android.os.Build;
import java.util.ArrayList;

public class CodecUtils {
    private CodecUtils() {}
    /**
     * Queries the MediaCodecList and returns codec names of supported codecs.
     *
     * @param mimeType  Mime type of input
     * @param isEncoder Specifies encoder or decoder
     * @return ArrayList of codec names
     */
    public static ArrayList<String> selectCodecs(String mimeType, boolean isEncoder) {
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
}
