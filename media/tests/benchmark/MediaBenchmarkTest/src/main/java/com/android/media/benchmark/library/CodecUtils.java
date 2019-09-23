package com.android.media.benchmark.library;

import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
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
}
