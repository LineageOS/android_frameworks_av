## Codec2 Hal @ 1.0 tests ##
---
#### master :
Functionality of master is to enumerate all the Codec2 components available in C2 media service.

usage: MtsHidlC2V1\_0TargetMasterTest -I software

#### component :
Functionality of component is to test common functionality across all the Codec2 components available in C2 media service. For a standard C2 component, these tests are expected to pass.

usage: MtsHidlC2V1\_0TargetComponentTest -I software -C <comp name>

#### audio :
Functionality of audio test is to validate audio specific functionality Codec2 components. The resource files for this test are taken from hardware/interfaces/media/res. The path to these files on the device is required to be given for bitstream tests.

usage: MtsHidlC2V1\_0TargetAudioDecTest -I software -C <comp name> -P /sdcard/media

#### video :
Functionality of video test is to validate video specific functionality Codec2 components. The resource files for this test are taken from hardware/interfaces/media/res. The path to these files on the device is required to be given for bitstream tests.

usage: MtsHidlC2V1\_0TargetVideoDecTest -I software -C <comp name> -P /sdcard/media

