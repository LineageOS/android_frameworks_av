# Fuzzers for libcamera_client

## Plugin Design Considerations
The fuzzer plugins for libcamera_client are designed based on the understanding of the
source code and try to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzers.

libcamera_client supports the following parameters:
1. Command (parameter name: `cmd`)
2. Video Buffer Mode (parameter name: `videoBufferMode`)
3. Preview Callback Flag (parameter name: `previewCallbackFlag`)
4. Facing (parameter name: `facing`)
5. Orientation (parameter name: `orientation`)
6. Format (parameter name: `format`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `cmd` | 0.`CAMERA_CMD_START_SMOOTH_ZOOM` 1.`CAMERA_CMD_STOP_SMOOTH_ZOOM` 3.`CAMERA_CMD_SET_DISPLAY_ORIENTATION` 4.`CAMERA_CMD_ENABLE_SHUTTER_SOUND` 5.`CAMERA_CMD_PLAY_RECORDING_SOUND` 6.`CAMERA_CMD_START_FACE_DETECTION` 7.`CAMERA_CMD_STOP_FACE_DETECTION` 8.`CAMERA_CMD_ENABLE_FOCUS_MOVE_MSG` 9.`CAMERA_CMD_PING` 10.`CAMERA_CMD_SET_VIDEO_BUFFER_COUNT` 11.`CAMERA_CMD_SET_VIDEO_FORMAT`| Value obtained from FuzzedDataProvider|
| `videoBufferMode` |0. `ICamera::VIDEO_BUFFER_MODE_DATA_CALLBACK_YUV` 1.`ICamera::VIDEO_BUFFER_MODE_DATA_CALLBACK_METADATA` 2.`ICamera::VIDEO_BUFFER_MODE_BUFFER_QUEUE`| Value obtained from FuzzedDataProvider|
| `previewCallbackFlag` | 0. `CAMERA_FRAME_CALLBACK_FLAG_ENABLE_MASK` 1.`CAMERA_FRAME_CALLBACK_FLAG_ONE_SHOT_MASK` 2.`CAMERA_FRAME_CALLBACK_FLAG_COPY_OUT_MASK` 3.`CAMERA_FRAME_CALLBACK_FLAG_NOOP` 4.`CAMERA_FRAME_CALLBACK_FLAG_CAMCORDER` 5.`CAMERA_FRAME_CALLBACK_FLAG_CAMERA` 6.`CAMERA_FRAME_CALLBACK_FLAG_BARCODE_SCANNER`| Value obtained from FuzzedDataProvider|
| `facing` | 0.`android::hardware::CAMERA_FACING_BACK` 1.`android::hardware::CAMERA_FACING_FRONT`| Value obtained from FuzzedDataProvider|
| `orientation` | 0.`0` 1.`90` 2.`180`3.`270`| Value obtained from FuzzedDataProvider|
| `format` | 0.`CameraParameters::PIXEL_FORMAT_YUV422SP` 1.`CameraParameters::PIXEL_FORMAT_YUV420SP` 2.`CameraParameters::PIXEL_FORMAT_YUV422I` 3.`CameraParameters::PIXEL_FORMAT_YUV420P` 4.`CameraParameters::PIXEL_FORMAT_RGB565` 5.`CameraParameters::PIXEL_FORMAT_RGBA8888` 6.`CameraParameters::PIXEL_FORMAT_JPEG` 7.`CameraParameters::PIXEL_FORMAT_BAYER_RGGB` 8.`CameraParameters::PIXEL_FORMAT_ANDROID_OPAQUE`| Value obtained from FuzzedDataProvider|

This also ensures that the plugins are always deterministic for any given input.

##### Maximize utilization of input data
The plugins feed the entire input data to the module.
This ensures that the plugins tolerate any kind of input (empty, huge,
malformed, etc) and dont `exit()` on any input and thereby increasing the
chance of identifying vulnerabilities.

## Build

This describes steps to build camera_fuzzer, camera2CaptureRequest_fuzzer, camera2ConcurrentCamera_fuzzer, camera2SubmitInfo_fuzzer, camera2SessionConfiguration_fuzzer, camera2OutputConfiguration_fuzzer, vendorTagDescriptor_fuzzer, cameraParameters_fuzzer, cameraSessionStats_fuzzer and captureResult_fuzzer binaries

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) camera_fuzzer
  $ mm -j$(nproc) camera_c2CaptureRequest_fuzzer
  $ mm -j$(nproc) camera_c2ConcurrentCamera_fuzzer
  $ mm -j$(nproc) camera_c2SubmitInfo_fuzzer
  $ mm -j$(nproc) camera_c2SessionConfiguration_fuzzer
  $ mm -j$(nproc) camera_c2OutputConfiguration_fuzzer
  $ mm -j$(nproc) camera_vendorTagDescriptor_fuzzer
  $ mm -j$(nproc) camera_Parameters_fuzzer
  $ mm -j$(nproc) camera_SessionStats_fuzzer
  $ mm -j$(nproc) camera_captureResult_fuzzer
```
#### Steps to run
To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/${TARGET_ARCH}/camera_fuzzer/camera_fuzzer
  $ adb shell /data/fuzz/${TARGET_ARCH}/camera_c2CaptureRequest_fuzzer/camera_c2CaptureRequest_fuzzer
  $ adb shell /data/fuzz/${TARGET_ARCH}/camera_c2ConcurrentCamera_fuzzer/camera_c2ConcurrentCamera_fuzzer
  $ adb shell /data/fuzz/${TARGET_ARCH}/camera_c2SubmitInfo_fuzzer/camera_c2SubmitInfo_fuzzer
  $ adb shell /data/fuzz/${TARGET_ARCH}/camera_c2SessionConfiguration_fuzzer/camera_c2SessionConfiguration_fuzzer
  $ adb shell /data/fuzz/${TARGET_ARCH}/camera_c2OutputConfiguration_fuzzer/camera_c2OutputConfiguration_fuzzer
  $ adb shell /data/fuzz/${TARGET_ARCH}/camera_vendorTagDescriptor_fuzzer/camera_vendorTagDescriptor_fuzzer
  $ adb shell /data/fuzz/${TARGET_ARCH}/camera_Parameters_fuzzer/camera_Parameters_fuzzer
  $ adb shell /data/fuzz/${TARGET_ARCH}/camera_SessionStats_fuzzer/camera_SessionStats_fuzzer
  $ adb shell /data/fuzz/${TARGET_ARCH}/camera_captureResult_fuzzer/camera_captureResult_fuzzer
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
