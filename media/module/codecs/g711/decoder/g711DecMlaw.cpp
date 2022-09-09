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

void DecodeMLaw(int16_t *out, const uint8_t *in, size_t inSize) {
  if (out != nullptr && in != nullptr) {
    while (inSize > 0) {
      inSize--;
      int32_t x = *in++;

      int32_t mantissa = ~x;
      int32_t exponent = (mantissa >> 4) & 7;
      int32_t segment = exponent + 1;
      mantissa &= 0x0f;

      int32_t step = 4 << segment;

      int32_t abs = (0x80l << exponent) + step * mantissa + step / 2 - 4 * 33;

      *out++ = (x < 0x80) ? -abs : abs;
    }
  }
}
