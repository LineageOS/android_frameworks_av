package android.media;

/*
 * {@hide}
 */
parcelable AudioSessionInfo {
    /** Interpreted as audio_session_t */
    int session;
    /** Interpreted as audio_stream_type_t */
    int stream;
    /** Interpreted as audio_output_flags_t */
    int flags;
    /** Interpreted as audio_channel_mask_t */
    int channelMask;
    /** Interpreted as uid_t */
    int uid;
}
