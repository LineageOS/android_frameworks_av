# PlaybackPower test app

PlaybackPower is a simple media playback test app that uses Media3 ExoPlayer.

Pass the media to play via intent, optionally specifying string extras to
configure DRM playbacks. For example:

```sh
adb shell am start -W -n \
  com.android.test.playbackpower/com.android.test.playbackpower.PlaybackPowerActivity \
  -a com.android.test.playbackpower.VIEW \
  -d https://storage.googleapis.com/wvmedia/cbcs/h264/tears/tears_aes_cbcs.mpd \
  --es drm_scheme widevine \
  --es drm_license_uri \
    https://proxy.uat.widevine.com/proxy?video_id=2015_tears&provider=widevine_test
```
