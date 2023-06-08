# Fuzzer for libstagefright_timedtext

libstagefright_timedtext supports the following parameters:
1. Flags (parameter name: `flags`)
2. TimeMs (parameter name: `timeMs`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `flags`   | 1. `TextDescriptions::OUT_OF_BAND_TEXT_SRT` 2.  `TextDescriptions::GLOBAL_DESCRIPTIONS` 3. `TextDescriptions::IN_BAND_TEXT_3GPP` 4. `TextDescriptions::LOCAL_DESCRIPTIONS` | Value chosen from valid values by obtaining index from FuzzedDataProvider|
| `timeMs`   | `INT_MIN` to `INT_MAX` | Value obtained from FuzzedDataProvider|


#### Steps to run

1. Build the fuzzer
```
  $ mm -j$(nproc) timedtext_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/timedtext_fuzzer/timedtext_fuzzer
```
