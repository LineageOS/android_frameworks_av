/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include "MediaDrmStatsdHelper.h"
#include <tuple>
#include <map>
#include <unordered_map>

namespace {

struct UUID {
    uint64_t msb, lsb; // NOLINT(misc-non-private-member-variables-in-classes)
    bool operator < (const UUID& that) const {
        return std::tie(msb, lsb) < std::tie(that.msb, that.lsb);
    }
};

// KEEP IN SYNC WITH frameworks/proto_logging/stats/enums/media/drm/enums.proto
std::map<UUID, int32_t> const kUuidSchemeEnumMap {
    {{.msb = 0x6DD8B3C345F44A68, .lsb = 0xBF3A64168D01A4A6}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__ABV_MODRM             }, // ABV_MODRM
    {{.msb = 0xF239E769EFA34850, .lsb = 0x9C16A903C6932EFB}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__ADOBE_PRIMETIME       }, // ADOBE_PRIMETIME
    {{.msb = 0x616C746963617374, .lsb = 0x2D50726F74656374}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__ALTICAST              }, // ALTICAST
    {{.msb = 0x94CE86FB07FF4F43, .lsb = 0xADB893D2FA968CA2}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__APPLE_FAIRPLAY        }, // APPLE_FAIRPLAY
    {{.msb = 0x279FE473512C48FE, .lsb = 0xADE8D176FEE6B40F}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__ARRIS_TITANIUM        }, // ARRIS_TITANIUM
    {{.msb = 0x3D5E6D359B9A41E8, .lsb = 0xB843DD3C6E72C42C}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__CHINADRM              }, // CHINADRM
    {{.msb = 0x3EA8778F77424BF9, .lsb = 0xB18BE834B2ACBD47}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__CLEAR_KEY_AES_128     }, // CLEAR_KEY_AES_128
    {{.msb = 0xBE58615B19C44684, .lsb = 0x88B3C8C57E99E957}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__CLEAR_KEY_SAMPLE_AES  }, // CLEAR_KEY_SAMPLE_AES
    {{.msb = 0xE2719D58A985B3C9, .lsb = 0x781AB030AF78D30E}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__CLEAR_KEY_DASH_IF     }, // CLEAR_KEY_DASH_IF
    {{.msb = 0x644FE7B5260F4FAD, .lsb = 0x949A0762FFB054B4}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__CMLA_OMA              }, // CMLA_OMA
    {{.msb = 0x37C332587B994C7E, .lsb = 0xB15D19AF74482154}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__COMMSCOPE_TITANIUM    }, // COMMSCOPE_TITANIUM
    {{.msb = 0x45D481CB8FE049C0, .lsb = 0xADA9AB2D2455B2F2}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__CORECRYPT             }, // CORECRYPT
    {{.msb = 0xDCF4E3E362F15818, .lsb = 0x7BA60A6FE33FF3DD}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__DIGICAP_SMARTXESS     }, // DIGICAP_SMARTXESS
    {{.msb = 0x35BF197B530E42D7, .lsb = 0x8B651B4BF415070F}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__DIVX                  }, // DIVX
    {{.msb = 0x80A6BE7E14484C37, .lsb = 0x9E70D5AEBE04C8D2}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__IRDETO                }, // IRDETO
    {{.msb = 0x5E629AF538DA4063, .lsb = 0x897797FFBD9902D4}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__MARLIN                }, // MARLIN
    {{.msb = 0x9A04F07998404286, .lsb = 0xAB92E65BE0885F95}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__MICROSOFT_PLAYREADY   }, // MICROSOFT_PLAYREADY
    {{.msb = 0x6A99532D869F5922, .lsb = 0x9A91113AB7B1E2F3}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__MOBITV                }, // MOBITV
    {{.msb = 0xADB41C242DBF4A6D, .lsb = 0x958B4457C0D27B95}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__NAGRA_MEDIAACCESS     }, // NAGRA_MEDIAACCESS
    {{.msb = 0x1F83E1E86EE94F0D, .lsb = 0xBA2F5EC4E3ED1A66}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__SECUREMEDIA           }, // SECUREMEDIA
    {{.msb = 0x992C46E6C4374899, .lsb = 0xB6A050FA91AD0E39}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__SECUREMEDIA_STEELKNOT }, // SECUREMEDIA_STEELKNOT
    {{.msb = 0xA68129D3575B4F1A, .lsb = 0x9CBA3223846CF7C3}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__SYNAMEDIA_VIDEOGUARD  }, // SYNAMEDIA_VIDEOGUARD
    {{.msb = 0xAA11967FCC014A4A, .lsb = 0x8E99C5D3DDDFEA2D}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__UNITEND_UDRM          }, // UNITEND_UDRM
    {{.msb = 0x9A27DD82FDE24725, .lsb = 0x8CBC4234AA06EC09}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__VERIMATRIX_VCAS       }, // VERIMATRIX_VCAS
    {{.msb = 0xB4413586C58CFFB0, .lsb = 0x94A5D4896C1AF6C3}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__VIACCESS_ORCA         }, // VIACCESS_ORCA
    {{.msb = 0x793B79569F944946, .lsb = 0xA94223E7EF7E44B4}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__VISIONCRYPT           }, // VISIONCRYPT
    {{.msb = 0x1077EFECC0B24D02, .lsb = 0xACE33C1E52E2FB4B}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__W3C_COMMON            }, // W3C_COMMON
    {{.msb = 0xEDEF8BA979D64ACE, .lsb = 0xA3C827DCD51D21ED}, android::stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__WIDEVINE              }, // WIDEVINE
};

// KEEP IN SYNC WITH frameworks/av/drm/libmediadrm/include/mediadrm/IDrm.h
// KEEP IN SYNC WITH frameworks/proto_logging/stats/enums/media/drm/enums.proto
std::unordered_map<std::string, int32_t> const kDrmApiEnumMap {
    {"initCheck"                  , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_INIT_CHECK                      },
    {"isCryptoSchemeSupported"    , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_IS_CRYPTO_SCHEME_SUPPORTED      },
    {"createPlugin"               , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_CREATE_PLUGIN                   },
    {"destroyPlugin"              , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_DESTROY_PLUGIN                  },
    {"openSession"                , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_OPEN_SESSION                    },
    {"closeSession"               , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_CLOSE_SESSION                   },
    {"getKeyRequest"              , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GET_KEY_REQUEST                 },
    {"provideKeyResponse"         , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_PROVIDE_KEY_RESPONSE            },
    {"removeKeys"                 , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_REMOVE_KEYS                     },
    {"restoreKeys"                , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_RESTORE_KEYS                    },
    {"queryKeyStatus"             , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_QUERY_KEY_STATUS                },
    {"getProvisionRequest"        , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GET_PROVISION_REQUEST           },
    {"provideProvisionResponse"   , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_PROVIDE_PROVISION_RESPONSE      },
    {"getSecureStops"             , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GET_SECURE_STOPS                },
    {"getSecureStopIds"           , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GET_SECURE_STOP_IDS             },
    {"getSecureStop"              , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GET_SECURE_STOP                 },
    {"releaseSecureStops"         , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_RELEASE_SECURE_STOPS            },
    {"removeSecureStop"           , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_REMOVE_SECURE_STOP              },
    {"removeAllSecureStops"       , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_REMOVE_ALL_SECURE_STOPS         },
    {"getHdcpLevels"              , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GET_HDCP_LEVELS                 },
    {"getNumberOfSessions"        , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GET_NUMBER_OF_SESSIONS          },
    {"getSecurityLevel"           , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GET_SECURITY_LEVEL              },
    {"getOfflineLicenseKeySetIds" , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GET_OFFLINE_LICENSE_KEY_SET_IDS },
    {"removeOfflineLicense"       , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_REMOVE_OFFLINE_LICENSE          },
    {"getOfflineLicenseState"     , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GET_OFFLINE_LICENSE_STATE       },
    {"getPropertyString"          , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GET_PROPERTY_STRING             },
    {"getPropertyByteArray"       , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GET_PROPERTY_BYTE_ARRAY         },
    {"setPropertyString"          , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_SET_PROPERTY_STRING             },
    {"setPropertyByteArray"       , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_SET_PROPERTY_BYTE_ARRAY         },
    {"getMetrics"                 , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GET_METRICS                     },
    {"setCipherAlgorithm"         , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_SET_CIPHER_ALGORITHM            },
    {"setMacAlgorithm"            , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_SET_MAC_ALGORITHM               },
    {"encrypt"                    , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GENERIC_ENCRYPT                 },
    {"decrypt"                    , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GENERIC_DECRYPT                 },
    {"sign"                       , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GENERIC_SIGN                    },
    {"verify"                     , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GENERIC_VERIFY                  },
    {"signRSA"                    , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_SIGN_RSA                        },
    {"setListener"                , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_SET_LISTENER                    },
    {"requiresSecureDecoder"      , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_REQUIRES_SECURE_DECODER         },
    {"requiresSecureDecoderLevel" , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_REQUIRES_SECURE_DECODER_LEVEL   },
    {"setPlaybackId"              , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_SET_PLAYBACK_ID                 },
    {"getLogMessages"             , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GET_LOG_MESSAGES                },
    {"getSupportedSchemes"        , android::stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_GET_SUPPORTED_SCHEMES           },
};

} // anonymous namespace

namespace android {

int32_t MediaDrmStatsdHelper::findDrmScheme(const int64_t msb, const int64_t lsb) {
    auto it = kUuidSchemeEnumMap.find({.msb = static_cast<uint64_t>(msb), .lsb = static_cast<uint64_t>(lsb)});
    if (it == kUuidSchemeEnumMap.end()) return stats::media_metrics::MEDIA_DRM_SESSION_OPENED__SCHEME__DRM_SCHEME_OTHER;
    return it->second;
}

int32_t MediaDrmStatsdHelper::findDrmApi(const std::string& api) {
    auto it = kDrmApiEnumMap.find(api);
    if (it == kDrmApiEnumMap.end()) return stats::media_metrics::MEDIA_DRM_ERRORED__API__DRM_API_UNKNOWN;
    return it->second;
}

} // namespace android