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

#include <media/NdkMediaError.h>
#include <media/stagefright/MediaErrors.h>
#include <utils/Errors.h>
#include <utils/Log.h>

using namespace android;

media_status_t translate_error(status_t err) {

    if (err == OK) {
        return AMEDIA_OK;
    } else if (err == ERROR_END_OF_STREAM) {
        return AMEDIA_ERROR_END_OF_STREAM;
    } else if (err == ERROR_IO) {
        return AMEDIA_ERROR_IO;
    }

    ALOGE("sf error code: %d", err);
    return AMEDIA_ERROR_UNKNOWN;
}

status_t reverse_translate_error(media_status_t err) {

    if (err == AMEDIA_OK) {
        return OK;
    } else if (err == AMEDIA_ERROR_END_OF_STREAM) {
        return ERROR_END_OF_STREAM;
    } else if (err == AMEDIA_ERROR_IO) {
        return ERROR_IO;
    } else if (err == AMEDIA_ERROR_WOULD_BLOCK) {
        return WOULD_BLOCK;
    }

    ALOGE("ndk error code: %d", err);
    return UNKNOWN_ERROR;
}
