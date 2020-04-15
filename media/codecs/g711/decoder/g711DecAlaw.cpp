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

#include <stddef.h>
#include <stdint.h>

void DecodeALaw(int16_t *out, const uint8_t *in, size_t inSize) {
  if (out != nullptr && in != nullptr) {
    while (inSize > 0) {
      inSize--;
      int32_t x = *in++;

      int32_t ix = x ^ 0x55;
      ix &= 0x7f;

      int32_t iexp = ix >> 4;
      int32_t mant = ix & 0x0f;

      if (iexp > 0) {
        mant += 16;
      }

      mant = (mant << 4) + 8;

      if (iexp > 1) {
        mant = mant << (iexp - 1);
      }

      *out++ = (x > 127) ? mant : -mant;
    }
  }
}
