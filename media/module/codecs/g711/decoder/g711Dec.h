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

#ifndef G711_DEC_H_
#define G711_DEC_H_

/**
 * @file g711Dec.h
 * @brief g711 Decoder API: DecodeALaw and DecodeMLaw
 */

/** Decodes input bytes of size inSize according to ALAW
 *
 * @param [in] out <tt>int16_t*</tt>: output buffer to be filled with decoded bytes.
 * @param [in] in <tt>const uint8_t*</tt>: input buffer containing bytes to be decoded.
 * @param [in] inSize <tt>size_t</tt>: size of the input buffer.
 */
void DecodeALaw(int16_t *out, const uint8_t *in, size_t inSize);

/** Decodes input bytes of size inSize according to MLAW
 *
 * @param [in] out <tt>int16_t*</tt>: output buffer to be filled with decoded bytes.
 * @param [in] in <tt>const uint8_t*</tt>: input buffer containing bytes to be decoded.
 * @param [in] inSize <tt>size_t</tt>: size of the input buffer.
 */
void DecodeMLaw(int16_t *out, const uint8_t *in, size_t inSize);

#endif  // G711_DECODER_H_
