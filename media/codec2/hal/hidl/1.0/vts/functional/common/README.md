# Codec2 VTS Hal @ 1.0 tests #

## master :
Functionality of master is to enumerate all the Codec2 components available in C2 media service.

usage: `atest VtsHalMediaC2V1_0TargetMasterTest`

## component :
Functionality of component test is to validate common functionality across all the Codec2 components available in C2 media service. For a standard C2 component, these tests are expected to pass.

usage: `atest VtsHalMediaC2V1_0TargetComponentTest`

## audio :
Functionality of audio test is to validate audio specific functionality of Codec2 components. The resource files for this test are taken from `frameworks/av/media/codec2/hidl/1.0/vts/functional/res`. The path to these files on the device can be specified with `-P`. (If the device path is omitted, `/data/local/tmp/media/` is the default value.)

usage: `atest VtsHalMediaC2V1_0TargetAudioDecTest`

usage: `atest VtsHalMediaC2V1_0TargetAudioEncTest`

## video :
Functionality of video test is to validate video specific functionality of Codec2 components. The resource files for this test are taken from `frameworks/av/media/codec2/hidl/1.0/vts/functional/res`. The path to these files on the device can be specified with `-P`. (If the device path is omitted, `/data/local/tmp/media/` is the default value.)

usage: `atest VtsHalMediaC2V1_0TargetVideoDecTest`
usage: `atest VtsHalMediaC2V1_0TargetVideoEncTest`
