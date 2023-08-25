# to run write_sine examples from the command line
{cd to top of the repo}
mmma frameworks/av/media/libaaudio/examples/
adb root
adb remount -R
adb push $OUT/data/nativetest/write_sine/write_sine /data/write_sine
adb shell /data/write_sine -?

adb push $OUT/data/nativetest/write_sine_callback/write_sine_callback /data/write_sine_callback
adb shell /data/write_sine_callback -?
