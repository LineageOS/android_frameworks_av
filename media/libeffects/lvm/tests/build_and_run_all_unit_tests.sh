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

echo "========================================"
echo "testing lvm"
adb shell mkdir -p $testdir
adb push $ANDROID_BUILD_TOP/cts/tests/tests/media/res/raw/sinesweepraw.raw $testdir
adb push $OUT/testcases/lvmtest/arm64/lvmtest $testdir
adb push $OUT/testcases/snr/arm64/snr $testdir

flags_arr=(
    "-csE"
    "-eqE"
    "-tE"
    "-csE -tE -eqE"
    "-bE -M"
    "-csE -tE"
    "-csE -eqE" "-tE -eqE"
    "-csE -tE -bE -M -eqE"
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
    88200
    96000
    176400
    192000
)

# run multichannel effects at different configs, saving only the stereo channel
# pair.
for flags in "${flags_arr[@]}"
do
    for fs in ${fs_arr[*]}
    do
        for ch in {1..8}
        do
            adb shell $testdir/lvmtest -i:$testdir/sinesweepraw.raw \
                -o:$testdir/sinesweep_$((ch))_$((fs)).raw -ch:$ch -fs:$fs $flags

            # two channel files should be identical to higher channel
            # computation (first 2 channels).
            # Do not compare cases where -bE is in flags (due to mono computation)
            if [[ $flags != *"-bE"* ]] && [ "$ch" -gt 2 ]
            then
                adb shell cmp $testdir/sinesweep_2_$((fs)).raw \
                    $testdir/sinesweep_$((ch))_$((fs)).raw
            elif [[ $flags == *"-bE"* ]] && [ "$ch" -gt 2 ]
            then
                adb shell $testdir/snr $testdir/sinesweep_2_$((fs)).raw \
                    $testdir/sinesweep_$((ch))_$((fs)).raw -thr:90.308998
            fi

        done
    done
done

adb shell rm -r $testdir
