/*
 * Copyright (C) 2018 The Android Open Source Project
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

#pragma once

#include <system/audio.h>

namespace android {
/**
 * @brief AudioProductStrategies hard coded array of strategies to fill new engine API contract.
 */
const engineConfig::ProductStrategies gOrderedStrategies = {
    {"STRATEGY_PHONE",
     {
         {"phone", AUDIO_STREAM_VOICE_CALL,
          {{AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_VOICE_COMMUNICATION, AUDIO_SOURCE_DEFAULT, 0,
            ""}},
         },
         {"sco", AUDIO_STREAM_BLUETOOTH_SCO,
          {{AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN, AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_SCO,
            ""}},
         }
     },
    },
    {"STRATEGY_SONIFICATION",
     {
         {"ring", AUDIO_STREAM_RING,
          {{AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
            AUDIO_SOURCE_DEFAULT, 0, ""}}
         },
         {"alarm", AUDIO_STREAM_ALARM,
          {{AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_ALARM, AUDIO_SOURCE_DEFAULT, 0, ""}},
         }
     },
    },
    {"STRATEGY_ENFORCED_AUDIBLE",
     {
         {"", AUDIO_STREAM_ENFORCED_AUDIBLE,
          {{AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN, AUDIO_SOURCE_DEFAULT,
            AUDIO_FLAG_AUDIBILITY_ENFORCED, ""}}
         }
     },
    },
    {"STRATEGY_ACCESSIBILITY",
     {
         {"", AUDIO_STREAM_ACCESSIBILITY,
          {{AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
            AUDIO_SOURCE_DEFAULT, 0, ""}}
         }
     },
    },
    {"STRATEGY_SONIFICATION_RESPECTFUL",
     {
         {"", AUDIO_STREAM_NOTIFICATION,
          {
              {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_NOTIFICATION, AUDIO_SOURCE_DEFAULT, 0, ""},
              {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_NOTIFICATION_COMMUNICATION_REQUEST,
               AUDIO_SOURCE_DEFAULT, 0, ""},
              {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_NOTIFICATION_COMMUNICATION_INSTANT,
               AUDIO_SOURCE_DEFAULT, 0, ""},
              {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_NOTIFICATION_COMMUNICATION_DELAYED,
               AUDIO_SOURCE_DEFAULT, 0, ""},
              {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_NOTIFICATION_EVENT,
               AUDIO_SOURCE_DEFAULT, 0, ""}
          }
         }
     },
    },
    {"STRATEGY_MEDIA",
     {
         {"music", AUDIO_STREAM_MUSIC,
          {
              {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_MEDIA, AUDIO_SOURCE_DEFAULT, 0, ""},
              {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_GAME, AUDIO_SOURCE_DEFAULT, 0, ""},
              {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_ASSISTANT, AUDIO_SOURCE_DEFAULT, 0, ""},
              {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
               AUDIO_SOURCE_DEFAULT, 0, ""},
              {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN, AUDIO_SOURCE_DEFAULT, 0, ""}
          },
         },
         {"system", AUDIO_STREAM_SYSTEM,
          {{AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_ASSISTANCE_SONIFICATION,
            AUDIO_SOURCE_DEFAULT, 0, ""}}
         }
     },
    },
    {"STRATEGY_DTMF",
     {
         {"", AUDIO_STREAM_DTMF,
          {
              {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
               AUDIO_SOURCE_DEFAULT, 0, ""}
          }
         }
     },
    },
    {"STRATEGY_TRANSMITTED_THROUGH_SPEAKER",
     {
         {"", AUDIO_STREAM_TTS,
          {{AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN, AUDIO_SOURCE_DEFAULT,
            AUDIO_FLAG_BEACON, ""}}
         }
     },
    },
    {"STRATEGY_REROUTING",
     {
         {"", AUDIO_STREAM_REROUTING,
          {{AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN, AUDIO_SOURCE_DEFAULT, 0, ""}}
         }
     },
    },
    {"STRATEGY_PATCH",
     {
         {"", AUDIO_STREAM_PATCH,
          {{AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN, AUDIO_SOURCE_DEFAULT, 0, ""}}
         }
     },
    }
};

const engineConfig::VolumeGroups gVolumeGroups = {
    {"voice_call", "AUDIO_STREAM_VOICE_CALL", 1, 10,
     {
         {"DEVICE_CATEGORY_HEADSET", { {0, -4200}, {33, -2800}, {66, -1400}, {100, 0} } },
         {"DEVICE_CATEGORY_SPEAKER", { {0, -2400}, {33, -1600}, {66, -800}, {100, 0} } },
         {"DEVICE_CATEGORY_EARPIECE", { {0, -2700}, {33, -1800}, {66, -900}, {100, 0} } },
         {"DEVICE_CATEGORY_EXT_MEDIA", { {1, -5800}, {20, -4000}, {60, -1700}, {100, 0} } },
         {"DEVICE_CATEGORY_HEARING_AID", { {1, -12700}, {20, -8000}, {60, -4000}, {100, 0} } },
     },
    },
    {"system", "AUDIO_STREAM_SYSTEM", 0, 100,
     {
         {"DEVICE_CATEGORY_HEADSET", { {1, -3000}, {33, -2600}, {66, -2200}, {100, -1800} } },
         {"DEVICE_CATEGORY_SPEAKER", { {1, -5100}, {57, -2800}, {71, -2500}, {85, -2300}, {100, -2100} } },
         {"DEVICE_CATEGORY_EARPIECE", { {1, -2400}, {33, -1800}, {66, -1200}, {100, -600} } },
         {"DEVICE_CATEGORY_EXT_MEDIA", { {1, -5800}, {20, -4000}, {60, -2100}, {100, -1000} } }, // DEFAULT_DEVICE_CATEGORY_EXT_MEDIA_VOLUME_CURVE
         {"DEVICE_CATEGORY_HEARING_AID", { {1, -12700}, {20, -8000}, {60, -4000}, {100, 0} } }, // DEFAULT_HEARING_AID_VOLUME_CURVE
     },
    },
    {"ring", "AUDIO_STREAM_RING", 0, 100,
     {
         {"DEVICE_CATEGORY_HEADSET", { {1, -4950}, {33, -3350}, {66, -1700}, {100, 0} } }, // DEFAULT_DEVICE_CATEGORY_HEADSET_VOLUME_CURVE
         {"DEVICE_CATEGORY_SPEAKER", { {1, -5800}, {20, -4000}, {60, -1700}, {100, 0} } },
         {"DEVICE_CATEGORY_EARPIECE", { {1, -4950}, {33, -3350}, {66, -1700}, {100, 0} } }, // DEFAULT_DEVICE_CATEGORY_EARPIECE_VOLUME_CURVE
         {"DEVICE_CATEGORY_EXT_MEDIA", { {1, -5800}, {20, -4000}, {60, -2100}, {100, -1000} } }, // DEFAULT_DEVICE_CATEGORY_EXT_MEDIA_VOLUME_CURVE
         {"DEVICE_CATEGORY_HEARING_AID", { {1, -12700}, {20, -8000}, {60, -4000}, {100, 0} } }, // DEFAULT_HEARING_AID_VOLUME_CURVE
     },
    },
    {"music", "AUDIO_STREAM_MUSIC", 0, 40,
     {
         {"DEVICE_CATEGORY_HEADSET", { {1, -5800}, {20, -4000}, {60, -1700}, {100, 0} } }, // DEFAULT_MEDIA_VOLUME_CURVE
         {"DEVICE_CATEGORY_SPEAKER", { {1, -5800}, {20, -4000}, {60, -1700}, {100, 0} } }, // DEFAULT_DEVICE_CATEGORY_SPEAKER_VOLUME_CURVE
         {"DEVICE_CATEGORY_EARPIECE", { {1, -5800}, {20, -4000}, {60, -1700}, {100, 0} } }, // DEFAULT_MEDIA_VOLUME_CURVE
         {"DEVICE_CATEGORY_EXT_MEDIA", { {1, -5800}, {20, -4000}, {60, -1700}, {100, 0} } }, // DEFAULT_MEDIA_VOLUME_CURVE
         {"DEVICE_CATEGORY_HEARING_AID", { {1, -12700}, {20, -8000}, {60, -4000}, {100, 0} } }, // DEFAULT_HEARING_AID_VOLUME_CURVE
     },
    },
    {"alarm", "AUDIO_STREAM_ALARM", 0, 100,
     {
         {"DEVICE_CATEGORY_HEADSET", { {0, -4950}, {33, -3350}, {66, -1700}, {100, 0} } }, // DEFAULT_NON_MUTABLE_HEADSET_VOLUME_CURVE
         {"DEVICE_CATEGORY_SPEAKER", { {0, -5800}, {20, -4000}, {60, -1700}, {100, 0} } }, // DEFAULT_NON_MUTABLE_SPEAKER_VOLUME_CURVE
         {"DEVICE_CATEGORY_EARPIECE", { {0, -4950}, {33, -3350}, {66, -1700}, {100, 0} } }, // DEFAULT_NON_MUTABLE_EARPIECE_VOLUME_CURVE
         {"DEVICE_CATEGORY_EXT_MEDIA", { {0, -5800}, {20, -4000}, {60, -2100}, {100, -1000} } }, // DEFAULT_NON_MUTABLE_EXT_VOLUME_CURVE
         {"DEVICE_CATEGORY_HEARING_AID", { {0, -12700}, {20, -8000}, {60, -4000}, {100, 0} } }, // DEFAULT_NON_MUTABLE_HEARING_AID_VOLUME_CURVE
     },
    },
    {"notification", "AUDIO_STREAM_NOTIFICATION", 0, 100,
     {
         {"DEVICE_CATEGORY_HEADSET", { {1, -4950}, {33, -3350}, {66, -1700}, {100, 0} } }, // DEFAULT_DEVICE_CATEGORY_HEADSET_VOLUME_CURVE
         {"DEVICE_CATEGORY_SPEAKER", { {1, -4680}, {42, -2070}, {85, -540}, {100, 0} } }, // DEFAULT_DEVICE_CATEGORY_SPEAKER_SYSTEM_VOLUME_CURVE
         {"DEVICE_CATEGORY_EARPIECE", { {1, -4950}, {33, -3350}, {66, -1700}, {100, 0} } }, // DEFAULT_DEVICE_CATEGORY_EARPIECE_VOLUME_CURVE
         {"DEVICE_CATEGORY_EXT_MEDIA", { {1, -5800}, {20, -4000}, {60, -2100}, {100, -1000} } }, // DEFAULT_DEVICE_CATEGORY_EXT_MEDIA_VOLUME_CURVE
         {"DEVICE_CATEGORY_HEARING_AID", { {1, -4950}, {33, -3350}, {66, -1700}, {100, 0} } }, // DEFAULT_DEVICE_CATEGORY_HEADSET_VOLUME_CURVE
     },
    },
    {"bluetooth_sco", "AUDIO_STREAM_BLUETOOTH_SCO", 1, 10,
     {
         {"DEVICE_CATEGORY_HEADSET", { {0, -4200}, {33, -2800}, {66, -1400}, {100, 0} } },
         {"DEVICE_CATEGORY_SPEAKER", { {0, -2400}, {33, -1600}, {66, -800}, {100, 0} } },
         {"DEVICE_CATEGORY_EARPIECE", { {0, -4200}, {33, -2800}, {66, -1400}, {100, 0} } },
         {"DEVICE_CATEGORY_EXT_MEDIA", { {1, -5800}, {20, -4000}, {60, -1700}, {100, 0} } }, // DEFAULT_MEDIA_VOLUME_CURVE
         {"DEVICE_CATEGORY_HEARING_AID", { {1, -12700}, {20, -8000}, {60, -4000}, {100, 0} } }, // DEFAULT_HEARING_AID_VOLUME_CURVE
     },
    },
    {"enforced_audible", "AUDIO_STREAM_ENFORCED_AUDIBLE", 0, 100,
     {
         {"DEVICE_CATEGORY_HEADSET", { {1, -3000}, {33, -2600}, {66, -2200}, {100, -1800} } },
         {"DEVICE_CATEGORY_SPEAKER", { {1, -3400}, {71, -2400}, {100, -2000} } },
         {"DEVICE_CATEGORY_EARPIECE", { {1, -2400}, {33, -1800}, {66, -1200}, {100, -600} } }, // DEFAULT_SYSTEM_VOLUME_CURVE
         {"DEVICE_CATEGORY_EXT_MEDIA", { {1, -5800}, {20, -4000}, {60, -2100}, {100, -1000} } }, // DEFAULT_DEVICE_CATEGORY_EXT_MEDIA_VOLUME_CURVE
         {"DEVICE_CATEGORY_HEARING_AID", { {1, -12700}, {20, -8000}, {60, -4000}, {100, 0} } }, // DEFAULT_HEARING_AID_VOLUME_CURVE
     },
    },
    {"dtmf", "AUDIO_STREAM_DTMF", 0, 100,
     {
         {"DEVICE_CATEGORY_HEADSET", { {1, -3000}, {33, -2600}, {66, -2200}, {100, -1800} } },
         {"DEVICE_CATEGORY_SPEAKER", { {1, -4000}, {71, -2400}, {100, -1400} } }, // DEFAULT_SYSTEM_VOLUME_CURVE
         {"DEVICE_CATEGORY_EARPIECE", { {1, -2400}, {33, -1800}, {66, -1200}, {100, -600} } }, // DEFAULT_SYSTEM_VOLUME_CURVE
         {"DEVICE_CATEGORY_EXT_MEDIA", { {1, -5800}, {20, -4000}, {60, -2100}, {100, -1000} } }, // DEFAULT_DEVICE_CATEGORY_EXT_MEDIA_VOLUME_CURVE
         {"DEVICE_CATEGORY_HEARING_AID", { {1, -12700}, {20, -8000}, {60, -4000}, {100, 0} } }, // DEFAULT_HEARING_AID_VOLUME_CURVE
     },
    },
    {"tts", "AUDIO_STREAM_TTS", 0, 16,
     {
         {"DEVICE_CATEGORY_HEADSET", { {0, -9600}, {100, -9600} } }, // SILENT_VOLUME_CURVE
         {"DEVICE_CATEGORY_SPEAKER", { {0, -0}, {100, 0} } }, // FULL_SCALE_VOLUME_CURVE
         {"DEVICE_CATEGORY_EARPIECE", { {0, -9600}, {100, -9600} } }, // SILENT_VOLUME_CURVE
         {"DEVICE_CATEGORY_EXT_MEDIA", { {0, -9600}, {100, -9600} } }, // SILENT_VOLUME_CURVE
         {"DEVICE_CATEGORY_HEARING_AID", { {0, -9600}, {100, -9600} } }, // SILENT_VOLUME_CURVE
     },
    },
    {"accessibility", "AUDIO_STREAM_ACCESSIBILITY", 1, 40,
     {
         {"DEVICE_CATEGORY_HEADSET", { {0, -5800}, {20, -4000}, {60, -1700}, {100, 0} } }, // DEFAULT_NON_MUTABLE_VOLUME_CURVE
         {"DEVICE_CATEGORY_SPEAKER", { {0, -5800}, {20, -4000}, {60, -1700}, {100, 0} } }, // DEFAULT_NON_MUTABLE_SPEAKER_VOLUME_CURVE
         {"DEVICE_CATEGORY_EARPIECE", { {0, -5800}, {20, -4000}, {60, -1700}, {100, 0} } }, // DEFAULT_NON_MUTABLE_VOLUME_CURVE
         {"DEVICE_CATEGORY_EXT_MEDIA", { {0, -5800}, {20, -4000}, {60, -1700}, {100, 0} } }, // DEFAULT_NON_MUTABLE_VOLUME_CURVE
         {"DEVICE_CATEGORY_HEARING_AID", { {0, -12700}, {20, -8000}, {60, -4000}, {100, 0} } }, // DEFAULT_NON_MUTABLE_HEARING_AID_VOLUME_CURVE
     },
    },
    {"rerouting", "AUDIO_STREAM_REROUTING", 0, 1,
     {
         {"DEVICE_CATEGORY_HEADSET", { {0, -0}, {100, 0} } }, // FULL_SCALE_VOLUME_CURVE
         {"DEVICE_CATEGORY_SPEAKER", { {0, -0}, {100, 0} } }, // FULL_SCALE_VOLUME_CURVE
         {"DEVICE_CATEGORY_EARPIECE", { {0, -0}, {100, 0} } }, // FULL_SCALE_VOLUME_CURVE
         {"DEVICE_CATEGORY_EXT_MEDIA", { {0, -0}, {100, 0} } }, // FULL_SCALE_VOLUME_CURVE
         {"DEVICE_CATEGORY_HEARING_AID", { {0, -0}, {100, 0} } }, // FULL_SCALE_VOLUME_CURVE
     },
    },
    {"patch", "AUDIO_STREAM_PATCH", 0, 1,
     {
         {"DEVICE_CATEGORY_HEADSET", { {0, -0}, {100, 0} } }, // FULL_SCALE_VOLUME_CURVE
         {"DEVICE_CATEGORY_SPEAKER", { {0, -0}, {100, 0} } }, // FULL_SCALE_VOLUME_CURVE
         {"DEVICE_CATEGORY_EARPIECE", { {0, -0}, {100, 0} } }, // FULL_SCALE_VOLUME_CURVE
         {"DEVICE_CATEGORY_EXT_MEDIA", { {0, -0}, {100, 0} } }, // FULL_SCALE_VOLUME_CURVE
         {"DEVICE_CATEGORY_HEARING_AID", { {0, -0}, {100, 0} } }, // FULL_SCALE_VOLUME_CURVE
     },
    },
};

const engineConfig::Config gDefaultEngineConfig = {
    1.0,
    gOrderedStrategies,
    {},
    {},
    gVolumeGroups
};
} // namespace android
