# B-Frames Encoding App

This is a sample android application for encoding AVC/HEVC streams with B-Frames enabled. It uses MediaRecorder APIs to record B-frames enabled video from camera2 input and MediaCodec APIs to encode reference test vector using input surface.

This page describes how to get started with the Encoder App and how to run the tests for it.


# Getting Started

This app uses the Gradle build system as well as Soong Build System.

To build this project using Gradle build, use the "gradlew build" command or use "Import Project" in Android Studio.

To build the app using Soong Build System, run the following command:
```
mmm frameworks/av/media/tests/SampleVideoEncoder/
```

The apk is generated at the following location:
```
out\target\product\sargo\testcases\SampleVideoEncoder\arm64\SampleVideoEncoder.apk
```

Command to install the apk:
```
adb install SampleVideoEncoder.apk
```

Command to launch the app:
```
adb shell am start -n "com.android.media.samplevideoencoder/com.android.media.samplevideoencoder.MainActivity"
```

After installing the app, a TextureView showing camera preview is dispalyed on one third of the screen. It also features checkboxes to select either avc/hevc and hw/sw codecs. It also has an option to select either MediaRecorder APIs or MediaCodec, along with the 'Start' button to start/stop recording.

# Running Tests

The app also contains a test, which will test the MediaCodec APIs for encoding avc/hevc streams with B-frames enabled. This does not require us to use application UI.

## Running the tests using atest
Note that atest command will install the SampleVideoEncoder app on the device.

Command to run the tests:
```
atest SampleVideoEncoder
```

# Ouput

The muxed ouptput video is saved in the app data at:
```
/storage/emulated/0/Android/data/com.android.media.samplevideoencoder/files/
```

The total number of I-frames, P-frames and B-frames after encoding has been done using MediaCodec APIs are displayed on the screen.
The results of the tests can be obtained from the logcats of the test.
