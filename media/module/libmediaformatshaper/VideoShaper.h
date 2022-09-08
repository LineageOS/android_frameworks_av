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

#ifndef LIBMEDIAFORMATSHAPER_VIDEOSHAPER_H_
#define LIBMEDIAFORMATSHAPER_VIDEOSHAPER_H_

namespace android {
namespace mediaformatshaper {

/*
 * runs through video-specific shaping operations for the codec/format combination.
 * updates inFormat in place.
 */
int videoShaper(CodecProperties *codec,  AMediaFormat* inFormat, int flags);

}  // namespace mediaformatshaper
}  // namespace android

#endif  // LIBMEDIAFORMATSHAPER_VIDEOSHAPER_H_
