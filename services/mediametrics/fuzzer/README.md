# Fuzzer for libmediametricsservice

## Plugin Design Considerations
The fuzzer plugin for libmediametricsservice is designed based on the
understanding of the service and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

Media Metrics Service contains the following modules:
1. Media Metrics Item Manipulation (module name: `Item`)
2. Media Metrics Time Machine Storage (module name: `TimeMachineStorage`)
3. Media Metrics Transaction Log (module name: `TransactionLog`)
4. Media Metrics Analytics Action (module name: `AnalyticsAction`)
5. Media Metrics Audio Analytics (module name: `AudioAnalytics`)
6. Media Metrics Timed Action (module name: `TimedAction`)

| Module| Valid Input Values| Configured Value|
|------------- |-------------| ----- |
| `Item` | Key: `std::string`. Values: `INT32_MIN` to `INT32_MAX`, `INT64_MIN` to `INT64_MAX`, `std::string`, `double`, `pair<INT32_MIN to INT32_MAX, INT32_MIN to INT32_MAX>` | Value obtained from FuzzedDataProvider |
| `TimeMachineStorage`   | Key: `std::string`. Values: `INT32_MIN` to `INT32_MAX`, `INT64_MIN` to `INT64_MAX`, `std::string`, `double`, `pair<INT32_MIN to INT32_MAX, INT32_MIN to INT32_MAX>` | Value obtained from FuzzedDataProvider |
| `TranscationLog`   | `mediametrics::Item` | `mediametrics::Item` created by obtaining values from FuzzedDataProvider|
| `AnalyticsAction`   | URL: `std::string` ending with .event, Value: `std::string`, action: A function | URL and Values obtained from FuzzedDataProvider, a placeholder function was passed as action|
| `AudioAnalytics`   | `mediametrics::Item` | `mediametrics::Item` created by obtaining values from FuzzedDataProvider|
| `TimedAction`   | time: `std::chrono::seconds`, function: `std::function` | `std::chrono::seconds` : value obtained from FuzzedDataProvider, `std::function`: a placeholder function was used. |

This also ensures that the plugin is always deterministic for any given input.

## Build

This describes steps to build mediametrics_service_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) mediametrics_service_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mediametrics_service_fuzzer/mediametrics_service_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
