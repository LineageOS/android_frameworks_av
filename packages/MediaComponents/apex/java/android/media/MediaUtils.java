package android.media;

import android.view.KeyEvent;

/**
 * @hide
 */
public class MediaUtils {

    /**
     * Adjusting the volume due to a hardware key press.
     * (Copied version of hidden AudioManager.FLAG_FROM_KEY)
     */
    public static final int AUDIO_MANAGER_FLAG_FROM_KEY = 1 << 12;

    // Keep sync with KeyEvent#isMediaKey().
    public static boolean isMediaKey(int keyCode) {
        switch (keyCode) {
            case KeyEvent.KEYCODE_MEDIA_PLAY:
            case KeyEvent.KEYCODE_MEDIA_PAUSE:
            case KeyEvent.KEYCODE_MEDIA_PLAY_PAUSE:
            case KeyEvent.KEYCODE_MUTE:
            case KeyEvent.KEYCODE_HEADSETHOOK:
            case KeyEvent.KEYCODE_MEDIA_STOP:
            case KeyEvent.KEYCODE_MEDIA_NEXT:
            case KeyEvent.KEYCODE_MEDIA_PREVIOUS:
            case KeyEvent.KEYCODE_MEDIA_REWIND:
            case KeyEvent.KEYCODE_MEDIA_RECORD:
            case KeyEvent.KEYCODE_MEDIA_FAST_FORWARD:
                return true;
        }
        return false;
    }
}
