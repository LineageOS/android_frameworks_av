#!/bin/bash
#
# reverb test
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
testdir="/data/local/tmp/revTest"

echo "========================================"
echo "testing reverb"
adb shell mkdir -p $testdir
adb push $ANDROID_BUILD_TOP/cts/tests/tests/media/res/raw/sinesweepraw.raw $testdir

E_VAL=1
cmds="adb push $OUT/testcases/reverb_test/arm/reverb_test $testdir"

fs_arr=(
    8000
    16000
    22050
    32000
    44100
    48000
    88200
    96000
    176400
    192000
)

# run reverb at different configs, saving only the stereo channel
# pair.
error_count=0
for cmd in "${cmds[@]}"
do
    $cmd
    for preset_val in {0..6}
    do
        for fs in ${fs_arr[*]}
        do
            for chMask in {1..22}
            do
                adb shell LD_LIBRARY_PATH=/system/vendor/lib/soundfx $testdir/reverb_test \
                    --input $testdir/sinesweepraw.raw \
                    --output $testdir/sinesweep_$((chMask))_$((fs)).raw \
                    --chMask $chMask --fs $fs --preset $preset_val

                shell_ret=$?
                if [ $shell_ret -ne 0 ]; then
                    echo "error: $shell_ret"
                    ((++error_count))
                fi

                # two channel files should be identical to higher channel
                # computation (first 2 channels).
                if [[ "$chMask" -gt 1 ]]
                then
                    adb shell cmp $testdir/sinesweep_1_$((fs)).raw \
                        $testdir/sinesweep_$((chMask))_$((fs)).raw
                fi
                # cmp returns EXIT_FAILURE on mismatch.
                shell_ret=$?
                if [ $shell_ret -ne 0 ]; then
                    echo "error: $shell_ret"
                    ((++error_count))
                fi
            done
        done
    done
done

adb shell rm -r $testdir
echo "$error_count errors"
exit $error_count
