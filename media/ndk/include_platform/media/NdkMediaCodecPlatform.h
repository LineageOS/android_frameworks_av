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

#ifndef _NDK_MEDIA_CODEC_PLATFORM_H
#define _NDK_MEDIA_CODEC_PLATFORM_H

#include <stdint.h>
#include <sys/cdefs.h>

#include <media/NdkMediaCodec.h>

__BEGIN_DECLS

/**
 * Special uid and pid values used with AMediaCodec_createCodecByNameForClient,
 * AMediaCodec_createDecoderByTypeForClient and AMediaCodec_createEncoderByTypeForClient.
 *
 * Introduced in API 31.
 */
enum {
    /**
     * Uid value to indicate using calling uid.
     */
    AMEDIACODEC_CALLING_UID = -1,
    /**
     * Pid value to indicate using calling pid.
     */
    AMEDIACODEC_CALLING_PID = -1,
};

/**
 * Create codec by name on behalf of a client.
 *
 * The usage is similar to AMediaCodec_createCodecByName(), except that the codec instance
 * will be attributed to the client of {uid, pid}, instead of the caller.
 *
 * Only certain privileged users are allowed to specify {uid, pid} that's different from the
 * caller's. Without the privilege, this API will behave the same as
 * AMediaCodec_createCodecByName().
 *
 * Available since API level 31.
 */
AMediaCodec* AMediaCodec_createCodecByNameForClient(const char *name,
                                                    pid_t pid,
                                                    uid_t uid) __INTRODUCED_IN(31);

/**
 * Create codec by mime type on behalf of a client.
 *
 * The usage is similar to AMediaCodec_createDecoderByType(), except that the codec instance
 * will be attributed to the client of {uid, pid}, instead of the caller.
 *
 * Only certain privileged users are allowed to specify {uid, pid} that's different from the
 * caller's. Without the privilege, this API will behave the same as
 * AMediaCodec_createDecoderByType().
 *
 * Available since API level 31.
 */
AMediaCodec* AMediaCodec_createDecoderByTypeForClient(const char *mime_type,
                                                      pid_t pid,
                                                      uid_t uid) __INTRODUCED_IN(31);

/**
 * Create encoder by name on behalf of a client.
 *
 * The usage is similar to AMediaCodec_createEncoderByType(), except that the codec instance
 * will be attributed to the client of {uid, pid}, instead of the caller.
 *
 * Only certain privileged users are allowed to specify {uid, pid} that's different from the
 * caller's. Without the privilege, this API will behave the same as
 * AMediaCodec_createEncoderByType().
 *
 * Available since API level 31.
 */
AMediaCodec* AMediaCodec_createEncoderByTypeForClient(const char *mime_type,
                                                      pid_t pid,
                                                      uid_t uid) __INTRODUCED_IN(31);

__END_DECLS

#endif //_NDK_MEDIA_CODEC_PLATFORM_H

/** @} */
