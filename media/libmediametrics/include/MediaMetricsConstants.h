/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_MEDIA_MEDIAMETRICSCONSTANTS_H
#define ANDROID_MEDIA_MEDIAMETRICSCONSTANTS_H

/*
 * MediaMetrics Keys and Properties.
 *
 * C/C++ friendly constants that ensure
 * 1) Compilation error on misspelling
 * 2) Consistent behavior and documentation.
 */

#define AMEDIAMETRICS_INITIAL_MAX_VOLUME (0.f)
#define AMEDIAMETRICS_INITIAL_MIN_VOLUME (1.f)

/*
 * Taxonomy of audio keys
 *
 * To build longer keys, we use compiler string concatenation of
 * adjacent string literals.  This is done in the translation phase
 * of compilation to make a single string token.
 */

// Key Prefixes are used for MediaMetrics Item Keys and ends with a ".".
// They must be appended with another value to make a key.
#define AMEDIAMETRICS_KEY_PREFIX_AUDIO "audio."

// Device related key prefix.
#define AMEDIAMETRICS_KEY_PREFIX_AUDIO_DEVICE  AMEDIAMETRICS_KEY_PREFIX_AUDIO "device."

// The AudioMmap key appends the "trackId" to the prefix.
// This is the AudioFlinger equivalent of the AAudio Stream.
// TODO: unify with AMEDIAMETRICS_KEY_PREFIX_AUDIO_STREAM
#define AMEDIAMETRICS_KEY_PREFIX_AUDIO_MMAP  AMEDIAMETRICS_KEY_PREFIX_AUDIO "mmap."

// The AudioRecord key appends the "trackId" to the prefix.
#define AMEDIAMETRICS_KEY_PREFIX_AUDIO_RECORD AMEDIAMETRICS_KEY_PREFIX_AUDIO "record."

// The Audio Sensor key appends the sensor handle integer.
#define AMEDIAMETRICS_KEY_PREFIX_AUDIO_SENSOR AMEDIAMETRICS_KEY_PREFIX_AUDIO "sensor."

// The Audio Spatializer key appends the spatializerId (currently 0)
#define AMEDIAMETRICS_KEY_PREFIX_AUDIO_SPATIALIZER AMEDIAMETRICS_KEY_PREFIX_AUDIO "spatializer."

// The Audio Spatializer device key appends the device type.
#define AMEDIAMETRICS_KEY_PREFIX_AUDIO_SPATIALIZER_DEVICE \
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_SPATIALIZER "device."

// The AudioStream key appends the "streamId" to the prefix.
#define AMEDIAMETRICS_KEY_PREFIX_AUDIO_STREAM  AMEDIAMETRICS_KEY_PREFIX_AUDIO "stream."

// The AudioThread key appends the "threadId" to the prefix.
#define AMEDIAMETRICS_KEY_PREFIX_AUDIO_THREAD AMEDIAMETRICS_KEY_PREFIX_AUDIO "thread."

// The AudioTrack key appends the "trackId" to the prefix.
#define AMEDIAMETRICS_KEY_PREFIX_AUDIO_TRACK  AMEDIAMETRICS_KEY_PREFIX_AUDIO "track."

// Keys are strings used for MediaMetrics Item Keys
#define AMEDIAMETRICS_KEY_AUDIO_FLINGER       AMEDIAMETRICS_KEY_PREFIX_AUDIO "flinger"
#define AMEDIAMETRICS_KEY_AUDIO_POLICY        AMEDIAMETRICS_KEY_PREFIX_AUDIO "policy"

// Error keys
#define AMEDIAMETRICS_KEY_AUDIO_TRACK_ERROR   AMEDIAMETRICS_KEY_PREFIX_AUDIO_TRACK "error"
#define AMEDIAMETRICS_KEY_AUDIO_RECORD_ERROR  AMEDIAMETRICS_KEY_PREFIX_AUDIO_RECORD "error"

/*
 * MediaMetrics Properties are unified space for consistency and readability.
 */

// Property prefixes may be applied before a property name to indicate a specific
// category to which it is associated.
#define AMEDIAMETRICS_PROP_PREFIX_EFFECTIVE "effective."
#define AMEDIAMETRICS_PROP_PREFIX_HAL       "hal."
#define AMEDIAMETRICS_PROP_PREFIX_HAPTIC    "haptic."
#define AMEDIAMETRICS_PROP_PREFIX_LAST      "last."
#define AMEDIAMETRICS_PROP_PREFIX_SERVER    "server."

// Properties within mediametrics are string constants denoted by
// a macro name beginning with AMEDIAMETRICS_PROP_*
//
// For a property name like "auxEffectId" we write this as a single upper case word
// at the end of the macro name, such as AMEDIAMETRICS_PROP_AUXEFFECTID.
//
// Underscores after the AMEDIAMETRICS_PROP_* prefix indicate
// a "dot" in the property name. For example AMEDIAMETRICS_PROP_VOLUME_LEFT
// corresponds to "volume.left".
//
// The property names are camel case, typically a lowercase letter [a-z]
// followed by one or more characters in the range [a-zA-Z0-9_.].
// Special symbols such as !@#$%^&*()[]{}<>,:;'"\/?|+-=~ are reserved.
//
// Properties within this header should include special suffixes like '#'
// directly in the string for brevity.  Code outside of this header should
// use the macro constant for the special symbols for searchability.

// Any property that ends with a # will have duplicate values listed instead
// of suppressed in the Time Machine.
#define AMEDIAMETRICS_PROP_SUFFIX_CHAR_DUPLICATES_ALLOWED '#'

#define AMEDIAMETRICS_PROP_ADDRESS        "address"        // string, for example MAC address
#define AMEDIAMETRICS_PROP_ALLOWUID       "_allowUid"      // int32_t, allow client uid to post
#define AMEDIAMETRICS_PROP_AUDIOMODE      "audioMode"      // string (audio.flinger)
#define AMEDIAMETRICS_PROP_AUXEFFECTID    "auxEffectId"    // int32 (AudioTrack)
#define AMEDIAMETRICS_PROP_BUFFERSIZEFRAMES "bufferSizeFrames" // int32
#define AMEDIAMETRICS_PROP_BUFFERCAPACITYFRAMES "bufferCapacityFrames" // int32
#define AMEDIAMETRICS_PROP_BURSTFRAMES    "burstFrames"    // int32
#define AMEDIAMETRICS_PROP_CALLERNAME     "callerName"     // string, eg. "aaudio"
#define AMEDIAMETRICS_PROP_CHANNELCOUNT   "channelCount"   // int32
#define AMEDIAMETRICS_PROP_CHANNELMASK    "channelMask"    // int32
#define AMEDIAMETRICS_PROP_CHANNELMASKS   "channelMasks"   // string with channelMask values
                                                           // separated by |.
#define AMEDIAMETRICS_PROP_CONTENTTYPE    "contentType"    // string attributes (AudioTrack)
#define AMEDIAMETRICS_PROP_CUMULATIVETIMENS "cumulativeTimeNs" // int64_t playback/record time
                                                           // since start
// DEVICE values are averaged since starting on device
#define AMEDIAMETRICS_PROP_DEVICELATENCYMS "deviceLatencyMs" // double - avg latency time
#define AMEDIAMETRICS_PROP_DEVICESTARTUPMS "deviceStartupMs" // double - avg startup time
#define AMEDIAMETRICS_PROP_DEVICETIMENS   "deviceTimeNs"   // int64_t playback/record time
#define AMEDIAMETRICS_PROP_DEVICEVOLUME   "deviceVolume"   // double - average device volume

#define AMEDIAMETRICS_PROP_DEVICEMAXVOLUMEDURATIONNS "deviceMaxVolumeDurationNs" // int64_t
#define AMEDIAMETRICS_PROP_DEVICEMAXVOLUME "deviceMaxVolume" // double - maximum device volume
#define AMEDIAMETRICS_PROP_DEVICEMINVOLUMEDURATIONNS "deviceMinVolumeDurationNs" // int64_t
#define AMEDIAMETRICS_PROP_DEVICEMINVOLUME "deviceMinVolume" // double - minimum device volume

#define AMEDIAMETRICS_PROP_DIRECTION      "direction"      // string AAudio input or output
#define AMEDIAMETRICS_PROP_DURATIONNS     "durationNs"     // int64 duration time span
#define AMEDIAMETRICS_PROP_ENABLED        "enabled"        // string true/false.
#define AMEDIAMETRICS_PROP_ENCODING       "encoding"       // string value of format

#define AMEDIAMETRICS_PROP_EVENT          "event#"         // string value (often func name)
#define AMEDIAMETRICS_PROP_EXECUTIONTIMENS "executionTimeNs"  // time to execute the event

// TODO: fix inconsistency in flags: AudioRecord / AudioTrack int32,  AudioThread string
#define AMEDIAMETRICS_PROP_FLAGS          "flags"

#define AMEDIAMETRICS_PROP_FRAMECOUNT     "frameCount"     // int32
#define AMEDIAMETRICS_PROP_HASHEADTRACKER  "hasHeadTracker" // string true/false
#define AMEDIAMETRICS_PROP_HEADTRACKERENABLED "headTrackerEnabled" // string true/false
#define AMEDIAMETRICS_PROP_HEADTRACKINGMODES "headTrackingModes" // string |, like modes.
#define AMEDIAMETRICS_PROP_INPUTDEVICES   "inputDevices"   // string value
#define AMEDIAMETRICS_PROP_INTERNALTRACKID "internalTrackId" // int32
#define AMEDIAMETRICS_PROP_INTERVALCOUNT  "intervalCount"  // int32
#define AMEDIAMETRICS_PROP_LATENCYMS      "latencyMs"      // double value
#define AMEDIAMETRICS_PROP_LEVELS         "levels"          // string | with levels
#define AMEDIAMETRICS_PROP_LOGSESSIONID   "logSessionId"   // hex string, "" none
#define AMEDIAMETRICS_PROP_METHODCODE     "methodCode"     // int64_t an int indicating method
#define AMEDIAMETRICS_PROP_METHODNAME     "methodName"     // string method name
#define AMEDIAMETRICS_PROP_MODE           "mode"           // string
#define AMEDIAMETRICS_PROP_MODES          "modes"          // string | with modes
#define AMEDIAMETRICS_PROP_NAME           "name"           // string value
#define AMEDIAMETRICS_PROP_ORIGINALFLAGS  "originalFlags"  // int32
#define AMEDIAMETRICS_PROP_OUTPUTDEVICES  "outputDevices"  // string value
#define AMEDIAMETRICS_PROP_PERFORMANCEMODE "performanceMode"    // string value, "none", lowLatency"
#define AMEDIAMETRICS_PROP_PLAYBACK_PITCH "playback.pitch" // double value (AudioTrack)
#define AMEDIAMETRICS_PROP_PLAYBACK_SPEED "playback.speed" // double value (AudioTrack)
#define AMEDIAMETRICS_PROP_PLAYERIID      "playerIId"      // int32 (-1 invalid/unset IID)
#define AMEDIAMETRICS_PROP_ROUTEDDEVICEID "routedDeviceId" // int32
#define AMEDIAMETRICS_PROP_SAMPLERATE     "sampleRate"     // int32
#define AMEDIAMETRICS_PROP_SELECTEDDEVICEID "selectedDeviceId" // int32
#define AMEDIAMETRICS_PROP_SELECTEDMICDIRECTION "selectedMicDirection" // int32
#define AMEDIAMETRICS_PROP_SELECTEDMICFIELDDIRECTION "selectedMicFieldDimension" // double
#define AMEDIAMETRICS_PROP_SESSIONID      "sessionId"      // int32
#define AMEDIAMETRICS_PROP_SHARINGMODE    "sharingMode"    // string value, "exclusive", shared"
#define AMEDIAMETRICS_PROP_SOURCE         "source"         // string (AudioAttributes)
#define AMEDIAMETRICS_PROP_STARTTHRESHOLDFRAMES "startThresholdFrames" // int32 (AudioTrack)
#define AMEDIAMETRICS_PROP_STARTUPMS      "startupMs"      // double value
// State is "ACTIVE" or "STOPPED" for AudioRecord
#define AMEDIAMETRICS_PROP_STATE          "state"          // string
#define AMEDIAMETRICS_PROP_STATUS         "status#"        // int32 status_t
                                                           // AAudio uses their own status codes
// Supplemental information to the status code.
#define AMEDIAMETRICS_PROP_STATUSSUBCODE  "statusSubCode"  // int32, specific code
                                                           // used in conjunction with status.
#define AMEDIAMETRICS_PROP_STATUSMESSAGE  "statusMessage"  // string, supplemental info.
                                                           // Arbitrary information treated as
                                                           // informational, may be logcat msg,
                                                           // or an exception with stack trace.
                                                           // Treated as "debug" information.

#define AMEDIAMETRICS_PROP_STREAMTYPE     "streamType"     // string (AudioTrack)
#define AMEDIAMETRICS_PROP_THREADID       "threadId"       // int32 value io handle
#define AMEDIAMETRICS_PROP_THROTTLEMS     "throttleMs"     // double
#define AMEDIAMETRICS_PROP_TRACKID        "trackId"        // int32 port id of track/record
#define AMEDIAMETRICS_PROP_TRAITS         "traits"         // string
#define AMEDIAMETRICS_PROP_TYPE           "type"           // string (thread type)
#define AMEDIAMETRICS_PROP_UNDERRUN       "underrun"       // int32
#define AMEDIAMETRICS_PROP_UNDERRUNFRAMES "underrunFrames" // int64_t from Thread
#define AMEDIAMETRICS_PROP_USAGE          "usage"          // string attributes (ATrack)
#define AMEDIAMETRICS_PROP_VOICEVOLUME    "voiceVolume"    // double (audio.flinger)
#define AMEDIAMETRICS_PROP_VOLUME_LEFT    "volume.left"    // double (AudioTrack)
#define AMEDIAMETRICS_PROP_VOLUME_RIGHT   "volume.right"   // double (AudioTrack)
#define AMEDIAMETRICS_PROP_WHERE          "where"          // string value
// EncodingClient is the encoding format requested by the client
#define AMEDIAMETRICS_PROP_ENCODINGCLIENT "encodingClient" // string
// PerformanceModeActual is the actual selected performance mode, could be "none', "lowLatency" or
// "powerSaving"
#define AMEDIAMETRICS_PROP_PERFORMANCEMODEACTUAL "performanceModeActual" // string
#define AMEDIAMETRICS_PROP_FRAMESTRANSFERRED "framesTransferred" // int64_t, transferred frames
// string value, "exclusive", "shared". the actual selected sharing mode by the server
#define AMEDIAMETRICS_PROP_SHARINGMODEACTUAL "sharingModeActual"

// Timing values: millisecond values are suffixed with MS and the type is double
// nanosecond values are suffixed with NS and the type is int64.

// Values are strings accepted for a given property.

// An event is a general description, which often is a function name.
#define AMEDIAMETRICS_PROP_EVENT_VALUE_BEGINAUDIOINTERVALGROUP "beginAudioIntervalGroup"
#define AMEDIAMETRICS_PROP_EVENT_VALUE_CLOSE      "close"
#define AMEDIAMETRICS_PROP_EVENT_VALUE_CREATE     "create"
#define AMEDIAMETRICS_PROP_EVENT_VALUE_CREATEAUDIOPATCH "createAudioPatch"
#define AMEDIAMETRICS_PROP_EVENT_VALUE_CTOR       "ctor"
#define AMEDIAMETRICS_PROP_EVENT_VALUE_DISCONNECT "disconnect"
#define AMEDIAMETRICS_PROP_EVENT_VALUE_DTOR       "dtor"
#define AMEDIAMETRICS_PROP_EVENT_VALUE_ENDAAUDIOSTREAM "endAAudioStream" // AAudioStream
#define AMEDIAMETRICS_PROP_EVENT_VALUE_ENDAUDIOINTERVALGROUP "endAudioIntervalGroup"
#define AMEDIAMETRICS_PROP_EVENT_VALUE_FLUSH      "flush"  // AudioTrack
#define AMEDIAMETRICS_PROP_EVENT_VALUE_INVALIDATE "invalidate" // server track, record
#define AMEDIAMETRICS_PROP_EVENT_VALUE_OPEN       "open"
#define AMEDIAMETRICS_PROP_EVENT_VALUE_PAUSE      "pause"  // AudioTrack
#define AMEDIAMETRICS_PROP_EVENT_VALUE_READPARAMETERS "readParameters" // Thread
#define AMEDIAMETRICS_PROP_EVENT_VALUE_RELEASE    "release"
#define AMEDIAMETRICS_PROP_EVENT_VALUE_RESTORE    "restore"
#define AMEDIAMETRICS_PROP_EVENT_VALUE_SETMODE    "setMode" // AudioFlinger
#define AMEDIAMETRICS_PROP_EVENT_VALUE_SETBUFFERSIZE    "setBufferSize" // AudioTrack
#define AMEDIAMETRICS_PROP_EVENT_VALUE_SETLOGSESSIONID  "setLogSessionId" // AudioTrack, Record
#define AMEDIAMETRICS_PROP_EVENT_VALUE_SETPLAYBACKPARAM "setPlaybackParam" // AudioTrack
#define AMEDIAMETRICS_PROP_EVENT_VALUE_SETPLAYERIID "setPlayerIId" // AudioTrack
#define AMEDIAMETRICS_PROP_EVENT_VALUE_SETSTARTTHRESHOLD "setStartThreshold" // AudioTrack
#define AMEDIAMETRICS_PROP_EVENT_VALUE_SETVOICEVOLUME   "setVoiceVolume" // AudioFlinger
#define AMEDIAMETRICS_PROP_EVENT_VALUE_SETVOLUME  "setVolume"  // AudioTrack
#define AMEDIAMETRICS_PROP_EVENT_VALUE_START      "start"  // AudioTrack, AudioRecord
#define AMEDIAMETRICS_PROP_EVENT_VALUE_STOP       "stop"   // AudioTrack, AudioRecord
#define AMEDIAMETRICS_PROP_EVENT_VALUE_TIMEOUT    "timeout"  // AudioFlinger, AudioPolicy
#define AMEDIAMETRICS_PROP_EVENT_VALUE_UNDERRUN   "underrun" // from Thread

// Possible values for AMEDIAMETRICS_PROP_CALLERNAME
// Check within the framework for these strings as this header file may not be explicitly
// included to avoid unnecessary cross-project dependencies.
#define AMEDIAMETRICS_PROP_CALLERNAME_VALUE_AAUDIO        "aaudio"         // Native AAudio
#define AMEDIAMETRICS_PROP_CALLERNAME_VALUE_JAVA          "java"           // Java API layer
#define AMEDIAMETRICS_PROP_CALLERNAME_VALUE_MEDIA         "media"          // libmedia
#define AMEDIAMETRICS_PROP_CALLERNAME_VALUE_OPENSLES      "opensles"       // Open SLES
#define AMEDIAMETRICS_PROP_CALLERNAME_VALUE_RTP           "rtp"            // RTP communication
#define AMEDIAMETRICS_PROP_CALLERNAME_VALUE_SOUNDPOOL     "soundpool"      // SoundPool
#define AMEDIAMETRICS_PROP_CALLERNAME_VALUE_TONEGENERATOR "tonegenerator"  // dial tones
#define AMEDIAMETRICS_PROP_CALLERNAME_VALUE_UNKNOWN       "unknown"        // callerName not set

// Many properties are available for the sensor.
// The mode is how the sensor is being currently used.
#define AMEDIAMETRICS_PROP_MODE_VALUE_HEAD          "head"        // used for head tracking
#define AMEDIAMETRICS_PROP_MODE_VALUE_SCREEN        "screen"      // used for screen

// MediaMetrics errors are expected to cover the following sources:
// https://docs.oracle.com/javase/7/docs/api/java/lang/RuntimeException.html
// https://docs.oracle.com/javase/7/docs/api/java/lang/Exception.html
// https://cs.android.com/android/platform/superproject/+/master:frameworks/native/libs/binder/include/binder/Status.h;drc=88e25c0861499ee3ab885814dddc097ab234cb7b;l=57
// https://cs.android.com/android/platform/superproject/+/master:frameworks/base/media/java/android/media/AudioSystem.java;drc=3ac246c43294d7f7012bdcb0ccb7bae1aa695bd4;l=785
// https://cs.android.com/android/platform/superproject/+/master:frameworks/av/media/libaaudio/include/aaudio/AAudio.h;drc=cfd3a6fa3aaaf712a890dc02452b38ef401083b8;l=120
// https://abseil.io/docs/cpp/guides/status-codes

// Status errors:
// An empty status string or "ok" is interpreted as no error.
#define AMEDIAMETRICS_PROP_STATUS_VALUE_OK                "ok"

// Error category: argument
//   IllegalArgumentException
//   NullPointerException
//   BAD_VALUE
//   absl::INVALID_ARGUMENT
//   absl::OUT_OF_RANGE
//   Out of range, out of bounds.
#define AMEDIAMETRICS_PROP_STATUS_VALUE_ARGUMENT          "argument"

// Error category: io
//   IOException
//   android.os.DeadObjectException, android.os.RemoteException
//   DEAD_OBJECT
//   FAILED_TRANSACTION
//   IO_ERROR
//   file or ioctl failure
//   Service, rpc, binder, or socket failure.
//   Hardware or device failure.
#define AMEDIAMETRICS_PROP_STATUS_VALUE_IO                "io"

// Error category: outOfMemory
//   OutOfMemoryException
//   NO_MEMORY
//   absl::RESOURCE_EXHAUSTED
#define AMEDIAMETRICS_PROP_STATUS_VALUE_MEMORY            "memory"

// Error category: security
//   SecurityException
//   PERMISSION_DENIED
//   absl::PERMISSION_DENIED
//   absl::UNAUTHENTICATED
#define AMEDIAMETRICS_PROP_STATUS_VALUE_SECURITY          "security"

// Error category: state
//   IllegalStateException
//   UnsupportedOperationException
//   INVALID_OPERATION
//   NO_INIT
//   absl::NOT_FOUND
//   absl::ALREADY_EXISTS
//   absl::FAILED_PRECONDITION
//   absl::UNAVAILABLE
//   absl::UNIMPLEMENTED
//   Functionality not implemented (argument may or may not be correct).
//   Call unexpected or out of order.
#define AMEDIAMETRICS_PROP_STATUS_VALUE_STATE             "state"

// Error category: timeout
//   TimeoutException
//   WOULD_BLOCK
//   absl::DEADLINE_EXCEEDED
//   absl::ABORTED
#define AMEDIAMETRICS_PROP_STATUS_VALUE_TIMEOUT           "timeout"

// Error category: unknown
//   Exception (Java specified not listed above, or custom app/service)
//   UNKNOWN_ERROR
//   absl::INTERNAL
//   absl::DATA_LOSS
//   Catch-all bucket for errors not listed above.
#define AMEDIAMETRICS_PROP_STATUS_VALUE_UNKNOWN           "unknown"

#endif // ANDROID_MEDIA_MEDIAMETRICSCONSTANTS_H
