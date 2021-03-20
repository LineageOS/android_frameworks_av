# Preprocessing effects

## Limitations
- Preprocessing effects currently work on 10ms worth of data and do not support
  arbitrary frame counts. This limiation comes from the underlying effects in
  webrtc modules
- There is currently no api to communicate this requirement
