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
testdir="/data/local/tmp/AudioPreProcessingTest"

echo "========================================"
echo "testing PreProcessing modules"
adb shell mkdir -p $testdir
adb push $ANDROID_BUILD_TOP/frameworks/av/media/libeffects/res/raw/sinesweepraw.raw $testdir
adb push $OUT/testcases/snr/arm64/snr $testdir

E_VAL=1
if [ -z "$1" ]
then
    cmds=("adb push $OUT/testcases/AudioPreProcessingTest/arm64/AudioPreProcessingTest $testdir"
          "adb push $OUT/testcases/AudioPreProcessingTest/arm/AudioPreProcessingTest $testdir"
)
elif [ "$1" == "32" ]
then
    cmds="adb push $OUT/testcases/AudioPreProcessingTest/arm/AudioPreProcessingTest $testdir"
elif [ "$1" == "64" ]
then
    cmds="adb push $OUT/testcases/AudioPreProcessingTest/arm64/AudioPreProcessingTest $testdir"
else
    echo ""
    echo "Invalid \"val\""
    echo "Usage:"
    echo "      "$0" [val]"
    echo "      where, val can be either 32 or 64."
    echo ""
    echo "      If val is not specified then both 32 bit and 64 bit binaries"
    echo "      are tested."
    exit $E_VAL
fi

flags_arr=(
    "--agc --mono"
    "--ns --mono"
    "--agc2 --mono"
    "--aec --mono"
)

fs_arr=(
    8000
    11025
    12000
    16000
    22050
    24000
    32000
    44100
    48000
)

# run multichannel effects at different configs, saving only the mono channel
error_count=0
test_count=0
for cmd in "${cmds[@]}"
do
    $cmd
    for flags in "${flags_arr[@]}"
    do
        for fs in ${fs_arr[*]}
        do
            for chMask in {0..7}
            do
                adb shell $testdir/AudioPreProcessingTest $flags \
                    --i $testdir/sinesweepraw.raw --far $testdir/sinesweepraw.raw \
                    --output $testdir/sinesweep_$((chMask))_$((fs)).raw --ch_mask $chMask \
                    --fs $fs --fch 1

                shell_ret=$?
                if [ $shell_ret -ne 0 ]; then
                    echo "error shell_ret here is zero: $shell_ret"
                    ((++error_count))
                fi


                # single channel files should be identical to higher channel
                # computation (first channel).
                if  [[ "$chMask" -gt 1 ]]
                then
                    adb shell cmp $testdir/sinesweep_1_$((fs)).raw \
                        $testdir/sinesweep_$((chMask))_$((fs)).raw
                fi

                # cmp return EXIT_FAILURE on mismatch.
                shell_ret=$?
                if [ $shell_ret -ne 0 ]; then
                    echo "error: $shell_ret"
                    ((++error_count))
                fi
                ((++test_count))
            done
        done
    done
done

adb shell rm -r $testdir
echo "$test_count tests performed"
echo "$error_count errors"
exit $error_count
