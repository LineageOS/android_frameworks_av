# to run the loopback test from the command line
{cd to top of the repo}
mmma frameworks/av/media/libaaudio/examples/
adb root
adb remount -R
adb push $OUT/data/nativetest/aaudio_loopback/aaudio_loopback /data/aaudio_loopback
adb shell /data/aaudio_loopback -?
