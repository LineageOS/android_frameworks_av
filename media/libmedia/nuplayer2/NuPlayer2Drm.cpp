/*
 * Copyright 2017 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "NuPlayer2Drm"

#include "NuPlayer2Drm.h"

#include <media/NdkWrapper.h>
#include <utils/Log.h>


namespace android {

Vector<DrmUUID> NuPlayer2Drm::parsePSSH(const void *pssh, size_t psshsize)
{
    Vector<DrmUUID> drmSchemes, empty;
    const int DATALEN_SIZE = 4;

    // the format of the buffer is 1 or more of:
    //    {
    //        16 byte uuid
    //        4 byte data length N
    //        N bytes of data
    //    }
    // Determine the number of entries in the source data.
    // Since we got the data from stagefright, we trust it is valid and properly formatted.

    const uint8_t *data = (const uint8_t*)pssh;
    size_t len = psshsize;
    size_t numentries = 0;
    while (len > 0) {
        if (len < DrmUUID::UUID_SIZE) {
            ALOGE("ParsePSSH: invalid PSSH data");
            return empty;
        }

        const uint8_t *uuidPtr = data;

        // skip uuid
        data += DrmUUID::UUID_SIZE;
        len -= DrmUUID::UUID_SIZE;

        // get data length
        if (len < DATALEN_SIZE) {
            ALOGE("ParsePSSH: invalid PSSH data");
            return empty;
        }

        uint32_t datalen = *((uint32_t*)data);
        data += DATALEN_SIZE;
        len -= DATALEN_SIZE;

        if (len < datalen) {
            ALOGE("ParsePSSH: invalid PSSH data");
            return empty;
        }

        // skip the data
        data += datalen;
        len -= datalen;

        DrmUUID _uuid(uuidPtr);
        drmSchemes.add(_uuid);

        ALOGV("ParsePSSH[%zu]: %s: %s", numentries,
                _uuid.toHexString().string(),
                DrmUUID::arrayToHex(data, datalen).string()
             );

        numentries++;
    }

    return drmSchemes;
}

Vector<DrmUUID> NuPlayer2Drm::getSupportedDrmSchemes(const void *pssh, size_t psshsize)
{
    Vector<DrmUUID> psshDRMs = parsePSSH(pssh, psshsize);

    Vector<DrmUUID> supportedDRMs;
    for (size_t i = 0; i < psshDRMs.size(); i++) {
        DrmUUID uuid = psshDRMs[i];
        if (AMediaDrmWrapper::isCryptoSchemeSupported(uuid.ptr(), NULL)) {
            supportedDRMs.add(uuid);
        }
    }

    ALOGV("getSupportedDrmSchemes: psshDRMs: %zu supportedDRMs: %zu",
            psshDRMs.size(), supportedDRMs.size());

    return supportedDRMs;
}

// Parcel has only private copy constructor so passing it in rather than returning
void NuPlayer2Drm::retrieveDrmInfo(const void *pssh, size_t psshsize, Parcel *parcel)
{
    // 1) PSSH bytes
    parcel->writeUint32(psshsize);
    parcel->writeByteArray(psshsize, (const uint8_t*)pssh);

    ALOGV("retrieveDrmInfo: MEDIA2_DRM_INFO  PSSH: size: %zu %s", psshsize,
            DrmUUID::arrayToHex((uint8_t*)pssh, psshsize).string());

    // 2) supportedDRMs
    Vector<DrmUUID> supportedDRMs = getSupportedDrmSchemes(pssh, psshsize);
    parcel->writeUint32(supportedDRMs.size());
    for (size_t i = 0; i < supportedDRMs.size(); i++) {
        DrmUUID uuid = supportedDRMs[i];
        parcel->writeByteArray(DrmUUID::UUID_SIZE, uuid.ptr());

        ALOGV("retrieveDrmInfo: MEDIA2_DRM_INFO  supportedScheme[%zu] %s", i,
                uuid.toHexString().string());
    }
}

}   // namespace android
