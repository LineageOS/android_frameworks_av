#!/bin/bash
#
# Run tests in this directory.
#

if [ -z "$ANDROID_BUILD_TOP" ]; then
    echo "Android build environment not set"
    exit -1
fi

# ensure we have mm
. $ANDROID_BUILD_TOP/build/envsetup.sh

mm -j

echo "waiting for device"

adb root && adb wait-for-device remount

# location of test files
testdir="/data/local/tmp/lvmTest"

#flags="-bE -tE -eqE -csE"
flags="-csE -tE -eqE"


echo "========================================"
echo "testing lvm"
adb shell mkdir $testdir
adb push $ANDROID_BUILD_TOP/cts/tests/tests/media/res/raw/sinesweepraw.raw $testdir
adb push $OUT/testcases/lvmtest/arm64/lvmtest $testdir

# run multichannel effects at different channel counts, saving only the stereo channel pair.
adb shell $testdir/lvmtest -i:$testdir/sinesweepraw.raw -o:$testdir/sinesweep_1.raw\
                          -ch:1 -fs:44100 $flags
adb shell $testdir/lvmtest -i:$testdir/sinesweepraw.raw -o:$testdir/sinesweep_2.raw\
                           -ch:2 -fs:44100 $flags
adb shell $testdir/lvmtest -i:$testdir/sinesweepraw.raw -o:$testdir/sinesweep_4.raw\
                           -ch:4 -fs:44100 $flags
adb shell $testdir/lvmtest -i:$testdir/sinesweepraw.raw -o:$testdir/sinesweep_6.raw\
                           -ch:6 -fs:44100 $flags
adb shell $testdir/lvmtest -i:$testdir/sinesweepraw.raw -o:$testdir/sinesweep_8.raw\
                           -ch:8 -fs:44100 $flags

# two channel files should be identical to higher channel computation (first 2 channels).
adb shell cmp $testdir/sinesweep_2.raw $testdir/sinesweep_2.raw
adb shell cmp $testdir/sinesweep_2.raw $testdir/sinesweep_4.raw
adb shell cmp $testdir/sinesweep_2.raw $testdir/sinesweep_6.raw
adb shell cmp $testdir/sinesweep_2.raw $testdir/sinesweep_8.raw
