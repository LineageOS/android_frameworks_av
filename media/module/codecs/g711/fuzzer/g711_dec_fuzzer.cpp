/******************************************************************************
 *
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "g711Dec.h"

class Codec {
 public:
  Codec() = default;
  ~Codec() = default;
  void decodeFrames(const uint8_t *data, size_t size);
};

void Codec::decodeFrames(const uint8_t *data, size_t size) {
  size_t outputBufferSize = sizeof(int16_t) * size;
  int16_t *out = new int16_t[outputBufferSize];
  if (!out) {
    return;
  }
#ifdef ALAW
  DecodeALaw(out, data, size);
#else
  DecodeMLaw(out, data, size);
#endif
  delete[] out;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }
  Codec *codec = new Codec();
  if (!codec) {
    return 0;
  }
  codec->decodeFrames(data, size);
  delete codec;
  return 0;
}
