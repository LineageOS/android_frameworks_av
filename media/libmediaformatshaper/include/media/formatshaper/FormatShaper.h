/*
 * Copyright 2021, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * structure defining the function pointers that system-side folks
 * use to invoke operations within the MediaFormat shaping library
 *
 * This is the include file the outside world uses.
 */

#ifndef LIBMEDIAFORMATSHAPER_FORMATSHAPER_H_
#define LIBMEDIAFORMATSHAPER_FORMATSHAPER_H_

namespace android {
namespace mediaformatshaper {

/*
 * An opaque handle clients use to refer to codec+mediatype being shaped.
 */
typedef void (*shaperHandle_t);

/*
 * shapeFormat applies any re-shaping on the passed AMediaFormat.
 * The updated format is returned in-place.
 */
typedef int (*shapeFormat_t)(shaperHandle_t shaperHandle,
                             AMediaFormat* inFormat, int flags);

/*
 * getMapping returns any mappings from standard keys to codec-specific keys.
 * The return is a vector of const char* which are set up in pairs
 * of "from", and "to".
 * This array is always finished with a pair of nulls (to indicate a null from
 * and a null to)
 */

typedef const char **(*getMappings_t)(shaperHandle_t shaperHandle, const char *kind);

/*
 * Returns a handle to the shaperHandle for the specified codec and mediatype.
 * If none exists, it returns null.
 */
typedef shaperHandle_t (*findShaper_t)(const char *codecName, const char *mediaType);

/*
 * Creates and returns an empty shaperHandle that the client can populate using the
 * setFeature() and setMap() operations.
 */
typedef shaperHandle_t (*createShaper_t)(const char *codecName, const char *mediaType);

/*
 * Registers the indicated shaperHandle for the indicated codec and mediatype.
 * This call returns the shaperHandle that is to be used for further shaper operations.
 * The returned value may be different than the one passed as an argument if another
 * shaperinfo was registered while the passed one was being configured.
 */
typedef shaperHandle_t (*registerShaper_t)(shaperHandle_t shaper, const char *codecName,
                                         const char *mediaType);

/*
 * establishes a mapping between the standard key "from" and the codec-specific key "to"
 * in the "kind" namespace. This mapping is specific to the indicated codecName when
 * encoding for the indicated mediaType.
 */
typedef int (*setMap_t)(shaperHandle_t shaper, const char *kind, const char *from, const char *to);

/*
 * establishes that codec "codecName" encoding for "mediaType" supports the indicated
 * feature at the indicated value
 */
typedef int (*setFeature_t)(shaperHandle_t shaper, const char *feature, int value);

/*
 * establishes that codec "codecName" encoding for "mediaType" supports the indicated
 * tuning at the indicated value
 */
typedef int (*setTuning_t)(shaperHandle_t shaper, const char *feature, const char * value);

/*
 * The expectation is that the client will implement a flow similar to the following when
 * setting up an encoding.
 *
 * if ((shaper=formatShaperops->findShaper(codecName, mediaType)) == NULL) {
 *     for (all codec features) {
 *         get feature name, feature value
 *         formatShaperops->setFeature(shaper,, featurename, featurevalue)
 *     }
 *     for (all codec mappings) {
 *         get mapping 'kind', mapping 'from', mapping 'to'
 *         formatShaperops->setMap(shaper, kind, from, to)
 *     }
 * }
 *
 */

typedef struct FormatShaperOps {
    const uint32_t version;

    /*
     * find, create, setup, and register the shaper info
     */
    findShaper_t findShaper;
    createShaper_t createShaper;
    setMap_t setMap;
    setFeature_t setFeature;
    registerShaper_t registerShaper;

    /*
     * use the shaper info
     */
    shapeFormat_t shapeFormat;
    getMappings_t getMappings;
    getMappings_t getReverseMappings;

    setTuning_t setTuning;

    // additions happen at the end of the structure
} FormatShaperOps_t;

// versioninf information
const uint32_t SHAPER_VERSION_UNKNOWN = 0;
const uint32_t SHAPER_VERSION_V1 = 1;

}  // namespace mediaformatshaper
}  // namespace android

#endif  // LIBMEDIAFORMATSHAPER_FORMATSHAPER_H_
