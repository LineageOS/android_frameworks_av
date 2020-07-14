/*
 * Copyright (C) 2014 The Android Open Source Project
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

#ifndef ANDROID_AUDIO_MIXER_OPS_H
#define ANDROID_AUDIO_MIXER_OPS_H

namespace android {

// Hack to make static_assert work in a constexpr
// https://en.cppreference.com/w/cpp/language/if
template <int N>
inline constexpr bool dependent_false = false;

/* MixMul is a multiplication operator to scale an audio input signal
 * by a volume gain, with the formula:
 *
 * O(utput) = I(nput) * V(olume)
 *
 * The output, input, and volume may have different types.
 * There are 27 variants, of which 14 are actually defined in an
 * explicitly templated class.
 *
 * The following type variables and the underlying meaning:
 *
 * Output type       TO: int32_t (Q4.27) or int16_t (Q.15) or float [-1,1]
 * Input signal type TI: int32_t (Q4.27) or int16_t (Q.15) or float [-1,1]
 * Volume type       TV: int32_t (U4.28) or int16_t (U4.12) or float [-1,1]
 *
 * For high precision audio, only the <TO, TI, TV> = <float, float, float>
 * needs to be accelerated. This is perhaps the easiest form to do quickly as well.
 *
 * A generic version is NOT defined to catch any mistake of using it.
 */

template <typename TO, typename TI, typename TV>
TO MixMul(TI value, TV volume);

template <>
inline int32_t MixMul<int32_t, int16_t, int16_t>(int16_t value, int16_t volume) {
    return value * volume;
}

template <>
inline int32_t MixMul<int32_t, int32_t, int16_t>(int32_t value, int16_t volume) {
    return (value >> 12) * volume;
}

template <>
inline int32_t MixMul<int32_t, int16_t, int32_t>(int16_t value, int32_t volume) {
    return value * (volume >> 16);
}

template <>
inline int32_t MixMul<int32_t, int32_t, int32_t>(int32_t value, int32_t volume) {
    return (value >> 12) * (volume >> 16);
}

template <>
inline float MixMul<float, float, int16_t>(float value, int16_t volume) {
    static const float norm = 1. / (1 << 12);
    return value * volume * norm;
}

template <>
inline float MixMul<float, float, int32_t>(float value, int32_t volume) {
    static const float norm = 1. / (1 << 28);
    return value * volume * norm;
}

template <>
inline int16_t MixMul<int16_t, float, int16_t>(float value, int16_t volume) {
    return clamp16_from_float(MixMul<float, float, int16_t>(value, volume));
}

template <>
inline int16_t MixMul<int16_t, float, int32_t>(float value, int32_t volume) {
    return clamp16_from_float(MixMul<float, float, int32_t>(value, volume));
}

template <>
inline float MixMul<float, int16_t, int16_t>(int16_t value, int16_t volume) {
    static const float norm = 1. / (1 << (15 + 12));
    return static_cast<float>(value) * static_cast<float>(volume) * norm;
}

template <>
inline float MixMul<float, int16_t, int32_t>(int16_t value, int32_t volume) {
    static const float norm = 1. / (1ULL << (15 + 28));
    return static_cast<float>(value) * static_cast<float>(volume) * norm;
}

template <>
inline int16_t MixMul<int16_t, int16_t, int16_t>(int16_t value, int16_t volume) {
    return clamp16(MixMul<int32_t, int16_t, int16_t>(value, volume) >> 12);
}

template <>
inline int16_t MixMul<int16_t, int32_t, int16_t>(int32_t value, int16_t volume) {
    return clamp16(MixMul<int32_t, int32_t, int16_t>(value, volume) >> 12);
}

template <>
inline int16_t MixMul<int16_t, int16_t, int32_t>(int16_t value, int32_t volume) {
    return clamp16(MixMul<int32_t, int16_t, int32_t>(value, volume) >> 12);
}

template <>
inline int16_t MixMul<int16_t, int32_t, int32_t>(int32_t value, int32_t volume) {
    return clamp16(MixMul<int32_t, int32_t, int32_t>(value, volume) >> 12);
}

/* Required for floating point volume.  Some are needed for compilation but
 * are not needed in execution and should be removed from the final build by
 * an optimizing compiler.
 */
template <>
inline float MixMul<float, float, float>(float value, float volume) {
    return value * volume;
}

template <>
inline float MixMul<float, int16_t, float>(int16_t value, float volume) {
    static const float float_from_q_15 = 1. / (1 << 15);
    return value * volume * float_from_q_15;
}

template <>
inline int32_t MixMul<int32_t, int32_t, float>(int32_t value, float volume) {
    LOG_ALWAYS_FATAL("MixMul<int32_t, int32_t, float> Runtime Should not be here");
    return value * volume;
}

template <>
inline int32_t MixMul<int32_t, int16_t, float>(int16_t value, float volume) {
    LOG_ALWAYS_FATAL("MixMul<int32_t, int16_t, float> Runtime Should not be here");
    static const float u4_12_from_float = (1 << 12);
    return value * volume * u4_12_from_float;
}

template <>
inline int16_t MixMul<int16_t, int16_t, float>(int16_t value, float volume) {
    LOG_ALWAYS_FATAL("MixMul<int16_t, int16_t, float> Runtime Should not be here");
    return clamp16_from_float(MixMul<float, int16_t, float>(value, volume));
}

template <>
inline int16_t MixMul<int16_t, float, float>(float value, float volume) {
    return clamp16_from_float(value * volume);
}

/*
 * MixAccum is used to add into an accumulator register of a possibly different
 * type. The TO and TI types are the same as MixMul.
 */

template <typename TO, typename TI>
inline void MixAccum(TO *auxaccum, TI value) {
    if (!std::is_same_v<TO, TI>) {
        LOG_ALWAYS_FATAL("MixAccum type not properly specialized: %zu %zu\n",
                sizeof(TO), sizeof(TI));
    }
    *auxaccum += value;
}

template<>
inline void MixAccum<float, int16_t>(float *auxaccum, int16_t value) {
    static constexpr float norm = 1. / (1 << 15);
    *auxaccum += norm * value;
}

template<>
inline void MixAccum<float, int32_t>(float *auxaccum, int32_t value) {
    static constexpr float norm = 1. / (1 << 27);
    *auxaccum += norm * value;
}

template<>
inline void MixAccum<int32_t, int16_t>(int32_t *auxaccum, int16_t value) {
    *auxaccum += value << 12;
}

template<>
inline void MixAccum<int32_t, float>(int32_t *auxaccum, float value) {
    *auxaccum += clampq4_27_from_float(value);
}

/* MixMulAux is just like MixMul except it combines with
 * an accumulator operation MixAccum.
 */

template <typename TO, typename TI, typename TV, typename TA>
inline TO MixMulAux(TI value, TV volume, TA *auxaccum) {
    MixAccum<TA, TI>(auxaccum, value);
    return MixMul<TO, TI, TV>(value, volume);
}

/* MIXTYPE is used to determine how the samples in the input frame
 * are mixed with volume gain into the output frame.
 * See the volumeRampMulti functions below for more details.
 */
enum {
    MIXTYPE_MULTI,
    MIXTYPE_MONOEXPAND,
    MIXTYPE_MULTI_SAVEONLY,
    MIXTYPE_MULTI_MONOVOL,
    MIXTYPE_MULTI_SAVEONLY_MONOVOL,
    MIXTYPE_MULTI_STEREOVOL,
    MIXTYPE_MULTI_SAVEONLY_STEREOVOL,
    MIXTYPE_STEREOEXPAND,
};

/*
 * TODO: We should work on non-interleaved streams - the
 * complexity of working on interleaved streams is now getting
 * too high, and likely limits compiler optimization.
 */
template <int MIXTYPE, int NCHAN,
        typename TO, typename TI, typename TV,
        typename F>
void stereoVolumeHelper(TO*& out, const TI*& in, const TV *vol, F f) {
    static_assert(NCHAN > 0 && NCHAN <= 8);
    static_assert(MIXTYPE == MIXTYPE_MULTI_STEREOVOL
            || MIXTYPE == MIXTYPE_MULTI_SAVEONLY_STEREOVOL
            || MIXTYPE == MIXTYPE_STEREOEXPAND
            || MIXTYPE == MIXTYPE_MONOEXPAND);
    auto proc = [](auto& a, const auto& b) {
        if constexpr (MIXTYPE == MIXTYPE_MULTI_STEREOVOL
                || MIXTYPE == MIXTYPE_STEREOEXPAND
                || MIXTYPE == MIXTYPE_MONOEXPAND) {
            a += b;
        } else {
            a = b;
        }
    };
    auto inp = [&in]() -> const TI& {
        if constexpr (MIXTYPE == MIXTYPE_STEREOEXPAND
                || MIXTYPE == MIXTYPE_MONOEXPAND) {
            return *in;
        } else {
            return *in++;
        }
    };

    // HALs should only expose the canonical channel masks.
    proc(*out++, f(inp(), vol[0])); // front left
    if constexpr (NCHAN == 1) return;
    proc(*out++, f(inp(), vol[1])); // front right
    if constexpr (NCHAN == 2)  return;
    if constexpr (NCHAN == 4) {
        proc(*out++, f(inp(), vol[0])); // back left
        proc(*out++, f(inp(), vol[1])); // back right
        return;
    }

    // TODO: Precompute center volume if not ramping.
    std::decay_t<TV> center;
    if constexpr (std::is_floating_point_v<TV>) {
        center = (vol[0] + vol[1]) * 0.5;       // do not use divide
    } else {
        center = (vol[0] >> 1) + (vol[1] >> 1); // rounds to 0.
    }
    proc(*out++, f(inp(), center)); // center (or 2.1 LFE)
    if constexpr (NCHAN == 3) return;
    if constexpr (NCHAN == 5) {
        proc(*out++, f(inp(), vol[0]));  // back left
        proc(*out++, f(inp(), vol[1]));  // back right
        return;
    }

    proc(*out++, f(inp(), center)); // lfe
    proc(*out++, f(inp(), vol[0])); // back left
    proc(*out++, f(inp(), vol[1])); // back right
    if constexpr (NCHAN == 6) return;
    if constexpr (NCHAN == 7) {
        proc(*out++, f(inp(), center)); // back center
        return;
    }
    // NCHAN == 8
    proc(*out++, f(inp(), vol[0])); // side left
    proc(*out++, f(inp(), vol[1])); // side right
}

/*
 * The volumeRampMulti and volumeRamp functions take a MIXTYPE
 * which indicates the per-frame mixing and accumulation strategy.
 *
 * MIXTYPE_MULTI:
 *   NCHAN represents number of input and output channels.
 *   TO: int32_t (Q4.27) or float
 *   TI: int32_t (Q4.27) or int16_t (Q0.15) or float
 *   TA: int32_t (Q4.27) or float
 *   TV: int32_t (U4.28) or int16_t (U4.12) or float
 *   vol: represents a volume array.
 *
 *   This accumulates into the out pointer.
 *
 * MIXTYPE_MONOEXPAND:
 *   Single input channel. NCHAN represents number of output channels.
 *   TO: int32_t (Q4.27) or float
 *   TI: int32_t (Q4.27) or int16_t (Q0.15) or float
 *   TA: int32_t (Q4.27) or float
 *   TV/TAV: int32_t (U4.28) or int16_t (U4.12) or float
 *   Input channel count is 1.
 *   vol: represents volume array.
 *   This uses stereo balanced volume vol[0] and vol[1].
 *   Before R, this was a full volume array but was called only for channels <= 2.
 *
 *   This accumulates into the out pointer.
 *
 * MIXTYPE_MULTI_SAVEONLY:
 *   NCHAN represents number of input and output channels.
 *   TO: int16_t (Q.15) or float
 *   TI: int32_t (Q4.27) or int16_t (Q0.15) or float
 *   TA: int32_t (Q4.27) or float
 *   TV/TAV: int32_t (U4.28) or int16_t (U4.12) or float
 *   vol: represents a volume array.
 *
 *   MIXTYPE_MULTI_SAVEONLY does not accumulate into the out pointer.
 *
 * MIXTYPE_MULTI_MONOVOL:
 *   Same as MIXTYPE_MULTI, but uses only volume[0].
 *
 * MIXTYPE_MULTI_SAVEONLY_MONOVOL:
 *   Same as MIXTYPE_MULTI_SAVEONLY, but uses only volume[0].
 *
 * MIXTYPE_MULTI_STEREOVOL:
 *   Same as MIXTYPE_MULTI, but uses only volume[0] and volume[1].
 *
 * MIXTYPE_MULTI_SAVEONLY_STEREOVOL:
 *   Same as MIXTYPE_MULTI_SAVEONLY, but uses only volume[0] and volume[1].
 *
 * MIXTYPE_STEREOEXPAND:
 *   Stereo input channel. NCHAN represents number of output channels.
 *   Expand size 2 array "in" and "vol" to multi-channel output. Note
 *   that the 2 array is assumed to have replicated L+R.
 *
 */

template <int MIXTYPE, int NCHAN,
        typename TO, typename TI, typename TV, typename TA, typename TAV>
inline void volumeRampMulti(TO* out, size_t frameCount,
        const TI* in, TA* aux, TV *vol, const TV *volinc, TAV *vola, TAV volainc)
{
#ifdef ALOGVV
    ALOGVV("volumeRampMulti, MIXTYPE:%d\n", MIXTYPE);
#endif
    if (aux != NULL) {
        do {
            TA auxaccum = 0;
            if constexpr (MIXTYPE == MIXTYPE_MULTI) {
                static_assert(NCHAN <= 2);
                for (int i = 0; i < NCHAN; ++i) {
                    *out++ += MixMulAux<TO, TI, TV, TA>(*in++, vol[i], &auxaccum);
                    vol[i] += volinc[i];
                }
            } else if constexpr (MIXTYPE == MIXTYPE_MULTI_SAVEONLY) {
                static_assert(NCHAN <= 2);
                for (int i = 0; i < NCHAN; ++i) {
                    *out++ = MixMulAux<TO, TI, TV, TA>(*in++, vol[i], &auxaccum);
                    vol[i] += volinc[i];
                }
            } else if constexpr (MIXTYPE == MIXTYPE_MULTI_MONOVOL) {
                for (int i = 0; i < NCHAN; ++i) {
                    *out++ += MixMulAux<TO, TI, TV, TA>(*in++, vol[0], &auxaccum);
                }
                vol[0] += volinc[0];
            } else if constexpr (MIXTYPE == MIXTYPE_MULTI_SAVEONLY_MONOVOL) {
                for (int i = 0; i < NCHAN; ++i) {
                    *out++ = MixMulAux<TO, TI, TV, TA>(*in++, vol[0], &auxaccum);
                }
                vol[0] += volinc[0];
            } else if constexpr (MIXTYPE == MIXTYPE_MULTI_STEREOVOL
                    || MIXTYPE == MIXTYPE_MULTI_SAVEONLY_STEREOVOL
                    || MIXTYPE == MIXTYPE_MONOEXPAND
                    || MIXTYPE == MIXTYPE_STEREOEXPAND) {
                stereoVolumeHelper<MIXTYPE, NCHAN>(
                        out, in, vol, [&auxaccum] (auto &a, const auto &b) {
                    return MixMulAux<TO, TI, TV, TA>(a, b, &auxaccum);
                });
                if constexpr (MIXTYPE == MIXTYPE_MONOEXPAND) in += 1;
                if constexpr (MIXTYPE == MIXTYPE_STEREOEXPAND) in += 2;
                vol[0] += volinc[0];
                vol[1] += volinc[1];
            } else /* constexpr */ {
                static_assert(dependent_false<MIXTYPE>, "invalid mixtype");
            }
            auxaccum /= NCHAN;
            *aux++ += MixMul<TA, TA, TAV>(auxaccum, *vola);
            vola[0] += volainc;
        } while (--frameCount);
    } else {
        do {
            if constexpr (MIXTYPE == MIXTYPE_MULTI) {
                static_assert(NCHAN <= 2);
                for (int i = 0; i < NCHAN; ++i) {
                    *out++ += MixMul<TO, TI, TV>(*in++, vol[i]);
                    vol[i] += volinc[i];
                }
            } else if constexpr (MIXTYPE == MIXTYPE_MULTI_SAVEONLY) {
                static_assert(NCHAN <= 2);
                for (int i = 0; i < NCHAN; ++i) {
                    *out++ = MixMul<TO, TI, TV>(*in++, vol[i]);
                    vol[i] += volinc[i];
                }
            } else if constexpr (MIXTYPE == MIXTYPE_MULTI_MONOVOL) {
                for (int i = 0; i < NCHAN; ++i) {
                    *out++ += MixMul<TO, TI, TV>(*in++, vol[0]);
                }
                vol[0] += volinc[0];
            } else if constexpr (MIXTYPE == MIXTYPE_MULTI_SAVEONLY_MONOVOL) {
                for (int i = 0; i < NCHAN; ++i) {
                    *out++ = MixMul<TO, TI, TV>(*in++, vol[0]);
                }
                vol[0] += volinc[0];
            } else if constexpr (MIXTYPE == MIXTYPE_MULTI_STEREOVOL
                    || MIXTYPE == MIXTYPE_MULTI_SAVEONLY_STEREOVOL
                    || MIXTYPE == MIXTYPE_MONOEXPAND
                    || MIXTYPE == MIXTYPE_STEREOEXPAND) {
                stereoVolumeHelper<MIXTYPE, NCHAN>(out, in, vol, [] (auto &a, const auto &b) {
                    return MixMul<TO, TI, TV>(a, b);
                });
                if constexpr (MIXTYPE == MIXTYPE_MONOEXPAND) in += 1;
                if constexpr (MIXTYPE == MIXTYPE_STEREOEXPAND) in += 2;
                vol[0] += volinc[0];
                vol[1] += volinc[1];
            } else /* constexpr */ {
                static_assert(dependent_false<MIXTYPE>, "invalid mixtype");
            }
        } while (--frameCount);
    }
}

template <int MIXTYPE, int NCHAN,
        typename TO, typename TI, typename TV, typename TA, typename TAV>
inline void volumeMulti(TO* out, size_t frameCount,
        const TI* in, TA* aux, const TV *vol, TAV vola)
{
#ifdef ALOGVV
    ALOGVV("volumeMulti MIXTYPE:%d\n", MIXTYPE);
#endif
    if (aux != NULL) {
        do {
            TA auxaccum = 0;
            if constexpr (MIXTYPE == MIXTYPE_MULTI) {
                static_assert(NCHAN <= 2);
                for (int i = 0; i < NCHAN; ++i) {
                    *out++ += MixMulAux<TO, TI, TV, TA>(*in++, vol[i], &auxaccum);
                }
            } else if constexpr (MIXTYPE == MIXTYPE_MULTI_SAVEONLY) {
                static_assert(NCHAN <= 2);
                for (int i = 0; i < NCHAN; ++i) {
                    *out++ = MixMulAux<TO, TI, TV, TA>(*in++, vol[i], &auxaccum);
                }
            } else if constexpr (MIXTYPE == MIXTYPE_MULTI_MONOVOL) {
                for (int i = 0; i < NCHAN; ++i) {
                    *out++ += MixMulAux<TO, TI, TV, TA>(*in++, vol[0], &auxaccum);
                }
            } else if constexpr (MIXTYPE == MIXTYPE_MULTI_SAVEONLY_MONOVOL) {
                for (int i = 0; i < NCHAN; ++i) {
                    *out++ = MixMulAux<TO, TI, TV, TA>(*in++, vol[0], &auxaccum);
                }
            } else if constexpr (MIXTYPE == MIXTYPE_MULTI_STEREOVOL
                    || MIXTYPE == MIXTYPE_MULTI_SAVEONLY_STEREOVOL
                    || MIXTYPE == MIXTYPE_MONOEXPAND
                    || MIXTYPE == MIXTYPE_STEREOEXPAND) {
                stereoVolumeHelper<MIXTYPE, NCHAN>(
                        out, in, vol, [&auxaccum] (auto &a, const auto &b) {
                    return MixMulAux<TO, TI, TV, TA>(a, b, &auxaccum);
                });
                if constexpr (MIXTYPE == MIXTYPE_MONOEXPAND) in += 1;
                if constexpr (MIXTYPE == MIXTYPE_STEREOEXPAND) in += 2;
            } else /* constexpr */ {
                static_assert(dependent_false<MIXTYPE>, "invalid mixtype");
            }
            auxaccum /= NCHAN;
            *aux++ += MixMul<TA, TA, TAV>(auxaccum, vola);
        } while (--frameCount);
    } else {
        do {
            // ALOGD("Mixtype:%d NCHAN:%d", MIXTYPE, NCHAN);
            if constexpr (MIXTYPE == MIXTYPE_MULTI) {
                static_assert(NCHAN <= 2);
                for (int i = 0; i < NCHAN; ++i) {
                    *out++ += MixMul<TO, TI, TV>(*in++, vol[i]);
                }
            } else if constexpr (MIXTYPE == MIXTYPE_MULTI_SAVEONLY) {
                static_assert(NCHAN <= 2);
                for (int i = 0; i < NCHAN; ++i) {
                    *out++ = MixMul<TO, TI, TV>(*in++, vol[i]);
                }
            } else if constexpr (MIXTYPE == MIXTYPE_MULTI_MONOVOL) {
                for (int i = 0; i < NCHAN; ++i) {
                    *out++ += MixMul<TO, TI, TV>(*in++, vol[0]);
                }
            } else if constexpr (MIXTYPE == MIXTYPE_MULTI_SAVEONLY_MONOVOL) {
                for (int i = 0; i < NCHAN; ++i) {
                    *out++ = MixMul<TO, TI, TV>(*in++, vol[0]);
                }
            } else if constexpr (MIXTYPE == MIXTYPE_MULTI_STEREOVOL
                    || MIXTYPE == MIXTYPE_MULTI_SAVEONLY_STEREOVOL
                    || MIXTYPE == MIXTYPE_MONOEXPAND
                    || MIXTYPE == MIXTYPE_STEREOEXPAND) {
                stereoVolumeHelper<MIXTYPE, NCHAN>(out, in, vol, [] (auto &a, const auto &b) {
                    return MixMul<TO, TI, TV>(a, b);
                });
                if constexpr (MIXTYPE == MIXTYPE_MONOEXPAND) in += 1;
                if constexpr (MIXTYPE == MIXTYPE_STEREOEXPAND) in += 2;
            } else /* constexpr */ {
                static_assert(dependent_false<MIXTYPE>, "invalid mixtype");
            }
        } while (--frameCount);
    }
}

};

#endif /* ANDROID_AUDIO_MIXER_OPS_H */
