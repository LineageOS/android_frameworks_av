mediatranscodingservice_simulated_tests:
	Tests media transcoding service with simulated transcoder.

mediatranscodingservice_real_tests:
	Tests media transcoding service with real transcoder. Uses the same test assets
	as the MediaTranscoder unit tests. Before running the test, please make sure
	to push the test assets to /sdcard:
	adb push $TOP/frameworks/av/media/libmediatranscoding/tests/assets /data/local/tmp/TranscodingTestAssets
