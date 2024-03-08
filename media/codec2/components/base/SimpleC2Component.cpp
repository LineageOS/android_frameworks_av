/*
 * Copyright (C) 2017 The Android Open Source Project
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
#define LOG_TAG "SimpleC2Component"
#include <log/log.h>

#include <android/hardware_buffer.h>
#include <cutils/properties.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/AUtils.h>

#include <inttypes.h>
#include <libyuv.h>

#include <C2Config.h>
#include <C2Debug.h>
#include <C2PlatformSupport.h>
#include <Codec2BufferUtils.h>
#include <Codec2CommonUtils.h>
#include <SimpleC2Component.h>

namespace android {

// libyuv version required for I410ToAB30Matrix and I210ToAB30Matrix.
#if LIBYUV_VERSION >= 1780
#include <algorithm>
#define HAVE_LIBYUV_I410_I210_TO_AB30 1
#else
#define HAVE_LIBYUV_I410_I210_TO_AB30 0
#endif

constexpr uint8_t kNeutralUVBitDepth8 = 128;
constexpr uint16_t kNeutralUVBitDepth10 = 512;

void convertYUV420Planar8ToYV12(uint8_t *dstY, uint8_t *dstU, uint8_t *dstV, const uint8_t *srcY,
                                const uint8_t *srcU, const uint8_t *srcV, size_t srcYStride,
                                size_t srcUStride, size_t srcVStride, size_t dstYStride,
                                size_t dstUStride, size_t dstVStride, uint32_t width,
                                uint32_t height, bool isMonochrome) {
    for (size_t i = 0; i < height; ++i) {
        memcpy(dstY, srcY, width);
        srcY += srcYStride;
        dstY += dstYStride;
    }

    if (isMonochrome) {
        // Fill with neutral U/V values.
        for (size_t i = 0; i < (height + 1) / 2; ++i) {
            memset(dstV, kNeutralUVBitDepth8, (width + 1) / 2);
            memset(dstU, kNeutralUVBitDepth8, (width + 1) / 2);
            dstV += dstVStride;
            dstU += dstUStride;
        }
        return;
    }

    for (size_t i = 0; i < (height + 1) / 2; ++i) {
        memcpy(dstV, srcV, (width + 1) / 2);
        srcV += srcVStride;
        dstV += dstVStride;
    }

    for (size_t i = 0; i < (height + 1) / 2; ++i) {
        memcpy(dstU, srcU, (width + 1) / 2);
        srcU += srcUStride;
        dstU += dstUStride;
    }
}

void convertYUV420Planar16ToY410(uint32_t *dst, const uint16_t *srcY, const uint16_t *srcU,
                                 const uint16_t *srcV, size_t srcYStride, size_t srcUStride,
                                 size_t srcVStride, size_t dstStride, size_t width, size_t height) {
    // Converting two lines at a time, slightly faster
    for (size_t y = 0; y < height; y += 2) {
        uint32_t *dstTop = (uint32_t *)dst;
        uint32_t *dstBot = (uint32_t *)(dst + dstStride);
        uint16_t *ySrcTop = (uint16_t *)srcY;
        uint16_t *ySrcBot = (uint16_t *)(srcY + srcYStride);
        uint16_t *uSrc = (uint16_t *)srcU;
        uint16_t *vSrc = (uint16_t *)srcV;

        uint32_t u01, v01, y01, y23, y45, y67, uv0, uv1;
        size_t x = 0;
        for (; x < width - 3; x += 4) {
            u01 = *((uint32_t *)uSrc);
            uSrc += 2;
            v01 = *((uint32_t *)vSrc);
            vSrc += 2;

            y01 = *((uint32_t *)ySrcTop);
            ySrcTop += 2;
            y23 = *((uint32_t *)ySrcTop);
            ySrcTop += 2;
            y45 = *((uint32_t *)ySrcBot);
            ySrcBot += 2;
            y67 = *((uint32_t *)ySrcBot);
            ySrcBot += 2;

            uv0 = (u01 & 0x3FF) | ((v01 & 0x3FF) << 20);
            uv1 = (u01 >> 16) | ((v01 >> 16) << 20);

            *dstTop++ = 3 << 30 | ((y01 & 0x3FF) << 10) | uv0;
            *dstTop++ = 3 << 30 | ((y01 >> 16) << 10) | uv0;
            *dstTop++ = 3 << 30 | ((y23 & 0x3FF) << 10) | uv1;
            *dstTop++ = 3 << 30 | ((y23 >> 16) << 10) | uv1;

            *dstBot++ = 3 << 30 | ((y45 & 0x3FF) << 10) | uv0;
            *dstBot++ = 3 << 30 | ((y45 >> 16) << 10) | uv0;
            *dstBot++ = 3 << 30 | ((y67 & 0x3FF) << 10) | uv1;
            *dstBot++ = 3 << 30 | ((y67 >> 16) << 10) | uv1;
        }

        // There should be at most 2 more pixels to process. Note that we don't
        // need to consider odd case as the buffer is always aligned to even.
        if (x < width) {
            u01 = *uSrc;
            v01 = *vSrc;
            y01 = *((uint32_t *)ySrcTop);
            y45 = *((uint32_t *)ySrcBot);
            uv0 = (u01 & 0x3FF) | ((v01 & 0x3FF) << 20);
            *dstTop++ = ((y01 & 0x3FF) << 10) | uv0;
            *dstTop++ = ((y01 >> 16) << 10) | uv0;
            *dstBot++ = ((y45 & 0x3FF) << 10) | uv0;
            *dstBot++ = ((y45 >> 16) << 10) | uv0;
        }

        srcY += srcYStride * 2;
        srcU += srcUStride;
        srcV += srcVStride;
        dst += dstStride * 2;
    }
}

namespace {

static C2ColorAspectsStruct FillMissingColorAspects(
        std::shared_ptr<const C2ColorAspectsStruct> aspects,
        int32_t width, int32_t height) {
    C2ColorAspectsStruct _aspects;
    if (aspects) {
        _aspects = *aspects;
    }

    // use matrix for conversion
    if (_aspects.matrix == C2Color::MATRIX_UNSPECIFIED) {
        // if not specified, deduce matrix from primaries
        if (_aspects.primaries == C2Color::PRIMARIES_UNSPECIFIED) {
            // if those are also not specified, deduce primaries first from transfer, then from
            // width and height
            if (_aspects.transfer == C2Color::TRANSFER_ST2084
                    || _aspects.transfer == C2Color::TRANSFER_HLG) {
                _aspects.primaries = C2Color::PRIMARIES_BT2020;
            } else if (width >= 3840 || height >= 3840 || width * (int64_t)height >= 3840 * 1634) {
                // TODO: stagefright defaults to BT.2020 for UHD, but perhaps we should default to
                // BT.709 for non-HDR 10-bit UHD content
                // (see media/libstagefright/foundation/ColorUtils.cpp)
                _aspects.primaries = C2Color::PRIMARIES_BT2020;
            } else if ((width <= 720 && height <= 576)
                    || (height <= 720 && width <= 576)) {
                // note: it does not actually matter whether to use 525 or 625 here as the
                // conversion is the same
                _aspects.primaries = C2Color::PRIMARIES_BT601_625;
            } else {
                _aspects.primaries = C2Color::PRIMARIES_BT709;
            }
        }

        switch (_aspects.primaries) {
        case C2Color::PRIMARIES_BT601_525:
        case C2Color::PRIMARIES_BT601_625:
            _aspects.matrix = C2Color::MATRIX_BT601;
            break;

        case C2Color::PRIMARIES_BT709:
            _aspects.matrix = C2Color::MATRIX_BT709;
            break;

        case C2Color::PRIMARIES_BT2020:
        default:
            _aspects.matrix = C2Color::MATRIX_BT2020;
        }
    }

    return _aspects;
}

// matrix conversion coefficients
// (see media/libstagefright/colorconverter/ColorConverter.cpp for more details)
struct Coeffs {
    int32_t _y, _r_v, _g_u, _g_v, _b_u, _c16;
};

static const struct Coeffs GetCoeffsForAspects(const C2ColorAspectsStruct &aspects) {
    bool isFullRange = aspects.range == C2Color::RANGE_FULL;

    switch (aspects.matrix) {
    case C2Color::MATRIX_BT601:
        /**
         * BT.601:  K_R = 0.299;  K_B = 0.114
         */
        if (isFullRange) {
            return Coeffs { 1024, 1436, 352, 731, 1815, 0 };
        } else {
            return Coeffs { 1196, 1639, 402, 835, 2072, 64 };
        }
        break;

    case C2Color::MATRIX_BT709:
        /**
         * BT.709:  K_R = 0.2126;  K_B = 0.0722
         */
        if (isFullRange) {
            return Coeffs { 1024, 1613, 192, 479, 1900, 0 };
        } else {
            return Coeffs { 1196, 1841, 219, 547, 2169, 64 };
        }
        break;

    case C2Color::MATRIX_BT2020:
    default:
        /**
         * BT.2020:  K_R = 0.2627;  K_B = 0.0593
         */
        if (isFullRange) {
            return Coeffs { 1024, 1510, 169, 585, 1927, 0 };
        } else {
            return Coeffs { 1196, 1724, 192, 668, 2200, 64 };
        }
    }
}

}

#define CLIP3(min, v, max) (((v) < (min)) ? (min) : (((max) > (v)) ? (v) : (max)))
void convertYUV420Planar16ToRGBA1010102(
        uint32_t *dst, const uint16_t *srcY, const uint16_t *srcU,
        const uint16_t *srcV, size_t srcYStride, size_t srcUStride,
        size_t srcVStride, size_t dstStride, size_t width,
        size_t height,
        std::shared_ptr<const C2ColorAspectsStruct> aspects) {

    C2ColorAspectsStruct _aspects = FillMissingColorAspects(aspects, width, height);

    struct Coeffs coeffs = GetCoeffsForAspects(_aspects);

    int32_t _y = coeffs._y;
    int32_t _b_u = coeffs._b_u;
    int32_t _neg_g_u = -coeffs._g_u;
    int32_t _neg_g_v = -coeffs._g_v;
    int32_t _r_v = coeffs._r_v;
    int32_t _c16 = coeffs._c16;

    // Converting two lines at a time, slightly faster
    for (size_t y = 0; y < height; y += 2) {
        uint32_t *dstTop = (uint32_t *)dst;
        uint32_t *dstBot = (uint32_t *)(dst + dstStride);
        uint16_t *ySrcTop = (uint16_t *)srcY;
        uint16_t *ySrcBot = (uint16_t *)(srcY + srcYStride);
        uint16_t *uSrc = (uint16_t *)srcU;
        uint16_t *vSrc = (uint16_t *)srcV;

        for (size_t x = 0; x < width; x += 2) {
            int32_t u, v, y00, y01, y10, y11;
            u = *uSrc - 512;
            uSrc += 1;
            v = *vSrc - 512;
            vSrc += 1;

            y00 = *ySrcTop - _c16;
            ySrcTop += 1;
            y01 = *ySrcTop - _c16;
            ySrcTop += 1;
            y10 = *ySrcBot - _c16;
            ySrcBot += 1;
            y11 = *ySrcBot - _c16;
            ySrcBot += 1;

            int32_t u_b = u * _b_u;
            int32_t u_g = u * _neg_g_u;
            int32_t v_g = v * _neg_g_v;
            int32_t v_r = v * _r_v;

            int32_t yMult, b, g, r;
            yMult = y00 * _y + 512;
            b = (yMult + u_b) / 1024;
            g = (yMult + v_g + u_g) / 1024;
            r = (yMult + v_r) / 1024;
            b = CLIP3(0, b, 1023);
            g = CLIP3(0, g, 1023);
            r = CLIP3(0, r, 1023);
            *dstTop++ = 3 << 30 | (b << 20) | (g << 10) | r;

            yMult = y01 * _y + 512;
            b = (yMult + u_b) / 1024;
            g = (yMult + v_g + u_g) / 1024;
            r = (yMult + v_r) / 1024;
            b = CLIP3(0, b, 1023);
            g = CLIP3(0, g, 1023);
            r = CLIP3(0, r, 1023);
            *dstTop++ = 3 << 30 | (b << 20) | (g << 10) | r;

            yMult = y10 * _y + 512;
            b = (yMult + u_b) / 1024;
            g = (yMult + v_g + u_g) / 1024;
            r = (yMult + v_r) / 1024;
            b = CLIP3(0, b, 1023);
            g = CLIP3(0, g, 1023);
            r = CLIP3(0, r, 1023);
            *dstBot++ = 3 << 30 | (b << 20) | (g << 10) | r;

            yMult = y11 * _y + 512;
            b = (yMult + u_b) / 1024;
            g = (yMult + v_g + u_g) / 1024;
            r = (yMult + v_r) / 1024;
            b = CLIP3(0, b, 1023);
            g = CLIP3(0, g, 1023);
            r = CLIP3(0, r, 1023);
            *dstBot++ = 3 << 30 | (b << 20) | (g << 10) | r;
        }

        srcY += srcYStride * 2;
        srcU += srcUStride;
        srcV += srcVStride;
        dst += dstStride * 2;
    }
}

void convertYUV420Planar16ToY410OrRGBA1010102(
        uint32_t *dst, const uint16_t *srcY,
        const uint16_t *srcU, const uint16_t *srcV,
        size_t srcYStride, size_t srcUStride,
        size_t srcVStride, size_t dstStride, size_t width, size_t height,
        std::shared_ptr<const C2ColorAspectsStruct> aspects) {
    if (isAtLeastT()) {
        convertYUV420Planar16ToRGBA1010102(dst, srcY, srcU, srcV, srcYStride, srcUStride,
                                           srcVStride, dstStride, width, height, aspects);
    } else {
        convertYUV420Planar16ToY410(dst, srcY, srcU, srcV, srcYStride, srcUStride, srcVStride,
                                    dstStride, width, height);
    }
}

void convertYUV420Planar16ToYV12(uint8_t *dstY, uint8_t *dstU, uint8_t *dstV, const uint16_t *srcY,
                                 const uint16_t *srcU, const uint16_t *srcV, size_t srcYStride,
                                 size_t srcUStride, size_t srcVStride, size_t dstYStride,
                                 size_t dstUVStride, size_t width, size_t height,
                                 bool isMonochrome) {
    for (size_t y = 0; y < height; ++y) {
        for (size_t x = 0; x < width; ++x) {
            dstY[x] = (uint8_t)(srcY[x] >> 2);
        }
        srcY += srcYStride;
        dstY += dstYStride;
    }

    if (isMonochrome) {
        // Fill with neutral U/V values.
        for (size_t y = 0; y < (height + 1) / 2; ++y) {
            memset(dstV, kNeutralUVBitDepth8, (width + 1) / 2);
            memset(dstU, kNeutralUVBitDepth8, (width + 1) / 2);
            dstV += dstUVStride;
            dstU += dstUVStride;
        }
        return;
    }

    for (size_t y = 0; y < (height + 1) / 2; ++y) {
        for (size_t x = 0; x < (width + 1) / 2; ++x) {
            dstU[x] = (uint8_t)(srcU[x] >> 2);
            dstV[x] = (uint8_t)(srcV[x] >> 2);
        }
        srcU += srcUStride;
        srcV += srcVStride;
        dstU += dstUVStride;
        dstV += dstUVStride;
    }
}

void convertYUV420Planar16ToP010(uint16_t *dstY, uint16_t *dstUV, const uint16_t *srcY,
                                 const uint16_t *srcU, const uint16_t *srcV, size_t srcYStride,
                                 size_t srcUStride, size_t srcVStride, size_t dstYStride,
                                 size_t dstUVStride, size_t width, size_t height,
                                 bool isMonochrome) {
    for (size_t y = 0; y < height; ++y) {
        for (size_t x = 0; x < width; ++x) {
            dstY[x] = srcY[x] << 6;
        }
        srcY += srcYStride;
        dstY += dstYStride;
    }

    if (isMonochrome) {
        // Fill with neutral U/V values.
        for (size_t y = 0; y < (height + 1) / 2; ++y) {
            for (size_t x = 0; x < (width + 1) / 2; ++x) {
                dstUV[2 * x] = kNeutralUVBitDepth10 << 6;
                dstUV[2 * x + 1] = kNeutralUVBitDepth10 << 6;
            }
            dstUV += dstUVStride;
        }
        return;
    }

    for (size_t y = 0; y < (height + 1) / 2; ++y) {
        for (size_t x = 0; x < (width + 1) / 2; ++x) {
            dstUV[2 * x] = srcU[x] << 6;
            dstUV[2 * x + 1] = srcV[x] << 6;
        }
        srcU += srcUStride;
        srcV += srcVStride;
        dstUV += dstUVStride;
    }
}

void convertP010ToYUV420Planar16(uint16_t *dstY, uint16_t *dstU, uint16_t *dstV,
                                 const uint16_t *srcY, const uint16_t *srcUV,
                                 size_t srcYStride, size_t srcUVStride, size_t dstYStride,
                                 size_t dstUStride, size_t dstVStride, size_t width,
                                 size_t height, bool isMonochrome) {
    for (size_t y = 0; y < height; ++y) {
        for (size_t x = 0; x < width; ++x) {
            dstY[x] = srcY[x] >> 6;
        }
        srcY += srcYStride;
        dstY += dstYStride;
    }

    if (isMonochrome) {
        // Fill with neutral U/V values.
        for (size_t y = 0; y < (height + 1) / 2; ++y) {
            for (size_t x = 0; x < (width + 1) / 2; ++x) {
                dstU[x] = kNeutralUVBitDepth10;
                dstV[x] = kNeutralUVBitDepth10;
            }
            dstU += dstUStride;
            dstV += dstVStride;
        }
        return;
    }

    for (size_t y = 0; y < (height + 1) / 2; ++y) {
        for (size_t x = 0; x < (width + 1) / 2; ++x) {
            dstU[x] = srcUV[2 * x] >> 6;
            dstV[x] = srcUV[2 * x + 1] >> 6;
        }
        dstU += dstUStride;
        dstV += dstVStride;
        srcUV += srcUVStride;
    }
}

static const int16_t bt709Matrix_10bit[2][3][3] = {
    { { 218, 732, 74 }, { -117, -395, 512 }, { 512, -465, -47 } }, /* RANGE_FULL */
    { { 186, 627, 63 }, { -103, -345, 448 }, { 448, -407, -41 } }, /* RANGE_LIMITED */
};

static const int16_t bt2020Matrix_10bit[2][3][3] = {
    { { 269, 694, 61 }, { -143, -369, 512 }, { 512, -471, -41 } }, /* RANGE_FULL */
    { { 230, 594, 52 }, { -125, -323, 448 }, { 448, -412, -36 } }, /* RANGE_LIMITED */
};

void convertRGBA1010102ToYUV420Planar16(uint16_t* dstY, uint16_t* dstU, uint16_t* dstV,
                                        const uint32_t* srcRGBA, size_t srcRGBStride, size_t width,
                                        size_t height, C2Color::matrix_t colorMatrix,
                                        C2Color::range_t colorRange) {
    uint16_t r, g, b;
    int32_t i32Y, i32U, i32V;
    uint16_t zeroLvl =  colorRange == C2Color::RANGE_FULL ? 0 : 64;
    uint16_t maxLvlLuma =  colorRange == C2Color::RANGE_FULL ? 1023 : 940;
    uint16_t maxLvlChroma =  colorRange == C2Color::RANGE_FULL ? 1023 : 960;
    // set default range as limited
    if (colorRange != C2Color::RANGE_FULL) {
        colorRange = C2Color::RANGE_LIMITED;
    }
    const int16_t(*weights)[3] = (colorMatrix == C2Color::MATRIX_BT709)
                                         ? bt709Matrix_10bit[colorRange - 1]
                                         : bt2020Matrix_10bit[colorRange - 1];

    for (size_t y = 0; y < height; ++y) {
        for (size_t x = 0; x < width; ++x) {
            b = (srcRGBA[x]  >> 20) & 0x3FF;
            g = (srcRGBA[x]  >> 10) & 0x3FF;
            r = srcRGBA[x] & 0x3FF;

            i32Y = ((r * weights[0][0] + g * weights[0][1] + b * weights[0][2] + 512) >> 10) +
                   zeroLvl;
            dstY[x] = CLIP3(zeroLvl, i32Y, maxLvlLuma);
            if (y % 2 == 0 && x % 2 == 0) {
                i32U = ((r * weights[1][0] + g * weights[1][1] + b * weights[1][2] + 512) >> 10) +
                       512;
                i32V = ((r * weights[2][0] + g * weights[2][1] + b * weights[2][2] + 512) >> 10) +
                       512;
                dstU[x >> 1] = CLIP3(zeroLvl, i32U, maxLvlChroma);
                dstV[x >> 1] = CLIP3(zeroLvl, i32V, maxLvlChroma);
            }
        }
        srcRGBA += srcRGBStride;
        dstY += width;
        if (y % 2 == 0) {
            dstU += width / 2;
            dstV += width / 2;
        }
    }
}

void convertPlanar16ToY410OrRGBA1010102(uint8_t* dst, const uint16_t* srcY, const uint16_t* srcU,
                                        const uint16_t* srcV, size_t srcYStride, size_t srcUStride,
                                        size_t srcVStride, size_t dstStride, size_t width,
                                        size_t height,
                                        std::shared_ptr<const C2ColorAspectsStruct> aspects,
                                        CONV_FORMAT_T format) {
    bool processed = false;
#if HAVE_LIBYUV_I410_I210_TO_AB30
    if (format == CONV_FORMAT_I444) {
        libyuv::I410ToAB30Matrix(srcY, srcYStride, srcU, srcUStride, srcV, srcVStride, dst,
                                 dstStride, &libyuv::kYuvV2020Constants, width, height);
        processed = true;
    } else if (format == CONV_FORMAT_I422) {
        libyuv::I210ToAB30Matrix(srcY, srcYStride, srcU, srcUStride, srcV, srcVStride, dst,
                                 dstStride, &libyuv::kYuvV2020Constants, width, height);
        processed = true;
    }
#endif  // HAVE_LIBYUV_I410_I210_TO_AB30
    if (!processed) {
        convertYUV420Planar16ToY410OrRGBA1010102(
                (uint32_t*)dst, srcY, srcU, srcV, srcYStride, srcUStride, srcVStride,
                dstStride / sizeof(uint32_t), width, height,
                std::static_pointer_cast<const C2ColorAspectsStruct>(aspects));
    }
}

void convertPlanar16ToP010(uint16_t* dstY, uint16_t* dstUV, const uint16_t* srcY,
                           const uint16_t* srcU, const uint16_t* srcV, size_t srcYStride,
                           size_t srcUStride, size_t srcVStride, size_t dstYStride,
                           size_t dstUStride, size_t dstVStride, size_t width, size_t height,
                           bool isMonochrome, CONV_FORMAT_T format, uint16_t* tmpFrameBuffer,
                           size_t tmpFrameBufferSize) {
#if LIBYUV_VERSION >= 1779
    if ((format == CONV_FORMAT_I444) || (format == CONV_FORMAT_I422)) {
        // TODO(https://crbug.com/libyuv/952): replace this block with libyuv::I410ToP010
        // and libyuv::I210ToP010 when they are available. Note it may be safe to alias dstY
        // in I010ToP010, but the libyuv API doesn't make any guarantees.
        const size_t tmpSize = dstYStride * height + dstUStride * align(height, 2);
        CHECK(tmpSize <= tmpFrameBufferSize);

        uint16_t* const tmpY = tmpFrameBuffer;
        uint16_t* const tmpU = tmpY + dstYStride * height;
        uint16_t* const tmpV = tmpU + dstUStride * align(height, 2) / 2;
        if (format == CONV_FORMAT_I444) {
            libyuv::I410ToI010(srcY, srcYStride, srcU, srcUStride, srcV, srcVStride, tmpY,
                               dstYStride, tmpU, dstUStride, tmpV, dstUStride, width, height);
        } else {
            libyuv::I210ToI010(srcY, srcYStride, srcU, srcUStride, srcV, srcVStride, tmpY,
                               dstYStride, tmpU, dstUStride, tmpV, dstUStride, width, height);
        }
        libyuv::I010ToP010(tmpY, dstYStride, tmpU, dstUStride, tmpV, dstVStride, dstY, dstYStride,
                           dstUV, dstUStride, width, height);
    } else {
        convertYUV420Planar16ToP010(dstY, dstUV, srcY, srcU, srcV, srcYStride, srcUStride,
                                    srcVStride, dstYStride, dstUStride, width, height,
                                    isMonochrome);
    }
#else   // LIBYUV_VERSION < 1779
    convertYUV420Planar16ToP010(dstY, dstUV, srcY, srcU, srcV, srcYStride, srcUStride, srcVStride,
                                dstYStride, dstUStride, width, height, isMonochrome);
#endif  // LIBYUV_VERSION >= 1779
}

void convertPlanar16ToYV12(uint8_t* dstY, uint8_t* dstU, uint8_t* dstV, const uint16_t* srcY,
                           const uint16_t* srcU, const uint16_t* srcV, size_t srcYStride,
                           size_t srcUStride, size_t srcVStride, size_t dstYStride,
                           size_t dstUStride, size_t dstVStride, size_t width, size_t height,
                           bool isMonochrome, CONV_FORMAT_T format, uint16_t* tmpFrameBuffer,
                           size_t tmpFrameBufferSize) {
#if LIBYUV_VERSION >= 1779
    if (format == CONV_FORMAT_I444) {
        // TODO(https://crbug.com/libyuv/950): replace this block with libyuv::I410ToI420
        // when it's available.
        const size_t tmpSize = dstYStride * height + dstUStride * align(height, 2);
        CHECK(tmpSize <= tmpFrameBufferSize);

        uint16_t* const tmpY = tmpFrameBuffer;
        uint16_t* const tmpU = tmpY + dstYStride * height;
        uint16_t* const tmpV = tmpU + dstUStride * align(height, 2) / 2;
        libyuv::I410ToI010(srcY, srcYStride, srcU, srcUStride, srcV, srcVStride, tmpY, dstYStride,
                           tmpU, dstUStride, tmpV, dstVStride, width, height);
        libyuv::I010ToI420(tmpY, dstYStride, tmpU, dstUStride, tmpV, dstUStride, dstY, dstYStride,
                           dstU, dstUStride, dstV, dstVStride, width, height);
    } else if (format == CONV_FORMAT_I422) {
        libyuv::I210ToI420(srcY, srcYStride, srcU, srcUStride, srcV, srcVStride, dstY, dstYStride,
                           dstU, dstUStride, dstV, dstVStride, width, height);
    } else {
        convertYUV420Planar16ToYV12(dstY, dstU, dstV, srcY, srcU, srcV, srcYStride, srcUStride,
                                    srcVStride, dstYStride, dstUStride, width, height,
                                    isMonochrome);
    }
#else   // LIBYUV_VERSION < 1779
    convertYUV420Planar16ToYV12(dstY, dstU, dstV, srcY, srcU, srcV, srcYStride, srcUStride,
                                srcVStride, dstYStride, dstUStride, width, height, isMonochrome);
#endif  // LIBYUV_VERSION >= 1779
}

void convertPlanar8ToYV12(uint8_t* dstY, uint8_t* dstU, uint8_t* dstV, const uint8_t* srcY,
                          const uint8_t* srcU, const uint8_t* srcV, size_t srcYStride,
                          size_t srcUStride, size_t srcVStride, size_t dstYStride,
                          size_t dstUStride, size_t dstVStride, uint32_t width, uint32_t height,
                          bool isMonochrome, CONV_FORMAT_T format) {
    if (format == CONV_FORMAT_I444) {
        libyuv::I444ToI420(srcY, srcYStride, srcU, srcUStride, srcV, srcVStride, dstY, dstYStride,
                           dstU, dstUStride, dstV, dstVStride, width, height);
    } else if (format == CONV_FORMAT_I422) {
        libyuv::I422ToI420(srcY, srcYStride, srcU, srcUStride, srcV, srcVStride, dstY, dstYStride,
                           dstU, dstUStride, dstV, dstVStride, width, height);
    } else {
        convertYUV420Planar8ToYV12(dstY, dstU, dstV, srcY, srcU, srcV, srcYStride, srcUStride,
                                   srcVStride, dstYStride, dstUStride, dstVStride, width, height,
                                   isMonochrome);
    }
}
std::unique_ptr<C2Work> SimpleC2Component::WorkQueue::pop_front() {
    std::unique_ptr<C2Work> work = std::move(mQueue.front().work);
    mQueue.pop_front();
    return work;
}

void SimpleC2Component::WorkQueue::push_back(std::unique_ptr<C2Work> work) {
    mQueue.push_back({ std::move(work), NO_DRAIN });
}

bool SimpleC2Component::WorkQueue::empty() const {
    return mQueue.empty();
}

void SimpleC2Component::WorkQueue::clear() {
    mQueue.clear();
}

uint32_t SimpleC2Component::WorkQueue::drainMode() const {
    return mQueue.front().drainMode;
}

void SimpleC2Component::WorkQueue::markDrain(uint32_t drainMode) {
    mQueue.push_back({ nullptr, drainMode });
}

////////////////////////////////////////////////////////////////////////////////

SimpleC2Component::WorkHandler::WorkHandler() : mRunning(false) {}

void SimpleC2Component::WorkHandler::setComponent(
        const std::shared_ptr<SimpleC2Component> &thiz) {
    mThiz = thiz;
}

static void Reply(const sp<AMessage> &msg, int32_t *err = nullptr) {
    sp<AReplyToken> replyId;
    CHECK(msg->senderAwaitsResponse(&replyId));
    sp<AMessage> reply = new AMessage;
    if (err) {
        reply->setInt32("err", *err);
    }
    reply->postReply(replyId);
}

void SimpleC2Component::WorkHandler::onMessageReceived(const sp<AMessage> &msg) {
    std::shared_ptr<SimpleC2Component> thiz = mThiz.lock();
    if (!thiz) {
        ALOGD("component not yet set; msg = %s", msg->debugString().c_str());
        sp<AReplyToken> replyId;
        if (msg->senderAwaitsResponse(&replyId)) {
            sp<AMessage> reply = new AMessage;
            reply->setInt32("err", C2_CORRUPTED);
            reply->postReply(replyId);
        }
        return;
    }

    switch (msg->what()) {
        case kWhatProcess: {
            if (mRunning) {
                if (thiz->processQueue()) {
                    (new AMessage(kWhatProcess, this))->post();
                }
            } else {
                ALOGV("Ignore process message as we're not running");
            }
            break;
        }
        case kWhatInit: {
            int32_t err = thiz->onInit();
            Reply(msg, &err);
            [[fallthrough]];
        }
        case kWhatStart: {
            mRunning = true;
            break;
        }
        case kWhatStop: {
            int32_t err = thiz->onStop();
            thiz->mOutputBlockPool.reset();
            Reply(msg, &err);
            break;
        }
        case kWhatReset: {
            thiz->onReset();
            thiz->mOutputBlockPool.reset();
            mRunning = false;
            Reply(msg);
            break;
        }
        case kWhatRelease: {
            thiz->onRelease();
            thiz->mOutputBlockPool.reset();
            mRunning = false;
            Reply(msg);
            break;
        }
        default: {
            ALOGD("Unrecognized msg: %d", msg->what());
            break;
        }
    }
}

class SimpleC2Component::BlockingBlockPool : public C2BlockPool {
public:
    BlockingBlockPool(const std::shared_ptr<C2BlockPool>& base): mBase{base} {}

    virtual local_id_t getLocalId() const override {
        return mBase->getLocalId();
    }

    virtual C2Allocator::id_t getAllocatorId() const override {
        return mBase->getAllocatorId();
    }

    virtual c2_status_t fetchLinearBlock(
            uint32_t capacity,
            C2MemoryUsage usage,
            std::shared_ptr<C2LinearBlock>* block) {
        c2_status_t status;
        do {
            status = mBase->fetchLinearBlock(capacity, usage, block);
        } while (status == C2_BLOCKING);
        return status;
    }

    virtual c2_status_t fetchCircularBlock(
            uint32_t capacity,
            C2MemoryUsage usage,
            std::shared_ptr<C2CircularBlock>* block) {
        c2_status_t status;
        do {
            status = mBase->fetchCircularBlock(capacity, usage, block);
        } while (status == C2_BLOCKING);
        return status;
    }

    virtual c2_status_t fetchGraphicBlock(
            uint32_t width, uint32_t height, uint32_t format,
            C2MemoryUsage usage,
            std::shared_ptr<C2GraphicBlock>* block) {
        c2_status_t status;
        do {
            status = mBase->fetchGraphicBlock(width, height, format, usage,
                                              block);
        } while (status == C2_BLOCKING);
        return status;
    }

private:
    std::shared_ptr<C2BlockPool> mBase;
};

////////////////////////////////////////////////////////////////////////////////

namespace {

struct DummyReadView : public C2ReadView {
    DummyReadView() : C2ReadView(C2_NO_INIT) {}
};

}  // namespace

SimpleC2Component::SimpleC2Component(
        const std::shared_ptr<C2ComponentInterface> &intf)
    : mDummyReadView(DummyReadView()),
      mIntf(intf),
      mLooper(new ALooper),
      mHandler(new WorkHandler) {
    mLooper->setName(intf->getName().c_str());
    (void)mLooper->registerHandler(mHandler);
    mLooper->start(false, false, ANDROID_PRIORITY_VIDEO);
}

SimpleC2Component::~SimpleC2Component() {
    mLooper->unregisterHandler(mHandler->id());
    (void)mLooper->stop();
}

c2_status_t SimpleC2Component::setListener_vb(
        const std::shared_ptr<C2Component::Listener> &listener, c2_blocking_t mayBlock) {
    mHandler->setComponent(shared_from_this());

    Mutexed<ExecState>::Locked state(mExecState);
    if (state->mState == RUNNING) {
        if (listener) {
            return C2_BAD_STATE;
        } else if (!mayBlock) {
            return C2_BLOCKING;
        }
    }
    state->mListener = listener;
    // TODO: wait for listener change to have taken place before returning
    // (e.g. if there is an ongoing listener callback)
    return C2_OK;
}

c2_status_t SimpleC2Component::queue_nb(std::list<std::unique_ptr<C2Work>> * const items) {
    {
        Mutexed<ExecState>::Locked state(mExecState);
        if (state->mState != RUNNING) {
            return C2_BAD_STATE;
        }
    }
    bool queueWasEmpty = false;
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        queueWasEmpty = queue->empty();
        while (!items->empty()) {
            queue->push_back(std::move(items->front()));
            items->pop_front();
        }
    }
    if (queueWasEmpty) {
        (new AMessage(WorkHandler::kWhatProcess, mHandler))->post();
    }
    return C2_OK;
}

c2_status_t SimpleC2Component::announce_nb(const std::vector<C2WorkOutline> &items) {
    (void)items;
    return C2_OMITTED;
}

c2_status_t SimpleC2Component::flush_sm(
        flush_mode_t flushMode, std::list<std::unique_ptr<C2Work>>* const flushedWork) {
    (void)flushMode;
    {
        Mutexed<ExecState>::Locked state(mExecState);
        if (state->mState != RUNNING) {
            return C2_BAD_STATE;
        }
    }
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        queue->incGeneration();
        // TODO: queue->splicedBy(flushedWork, flushedWork->end());
        while (!queue->empty()) {
            std::unique_ptr<C2Work> work = queue->pop_front();
            if (work) {
                flushedWork->push_back(std::move(work));
            }
        }
        while (!queue->pending().empty()) {
            flushedWork->push_back(std::move(queue->pending().begin()->second));
            queue->pending().erase(queue->pending().begin());
        }
    }

    return C2_OK;
}

c2_status_t SimpleC2Component::drain_nb(drain_mode_t drainMode) {
    if (drainMode == DRAIN_CHAIN) {
        return C2_OMITTED;
    }
    {
        Mutexed<ExecState>::Locked state(mExecState);
        if (state->mState != RUNNING) {
            return C2_BAD_STATE;
        }
    }
    bool queueWasEmpty = false;
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        queueWasEmpty = queue->empty();
        queue->markDrain(drainMode);
    }
    if (queueWasEmpty) {
        (new AMessage(WorkHandler::kWhatProcess, mHandler))->post();
    }

    return C2_OK;
}

c2_status_t SimpleC2Component::start() {
    Mutexed<ExecState>::Locked state(mExecState);
    if (state->mState == RUNNING) {
        return C2_BAD_STATE;
    }
    bool needsInit = (state->mState == UNINITIALIZED);
    state.unlock();
    if (needsInit) {
        sp<AMessage> reply;
        (new AMessage(WorkHandler::kWhatInit, mHandler))->postAndAwaitResponse(&reply);
        int32_t err;
        CHECK(reply->findInt32("err", &err));
        if (err != C2_OK) {
            return (c2_status_t)err;
        }
    } else {
        (new AMessage(WorkHandler::kWhatStart, mHandler))->post();
    }
    state.lock();
    state->mState = RUNNING;
    return C2_OK;
}

c2_status_t SimpleC2Component::stop() {
    ALOGV("stop");
    {
        Mutexed<ExecState>::Locked state(mExecState);
        if (state->mState != RUNNING) {
            return C2_BAD_STATE;
        }
        state->mState = STOPPED;
    }
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        queue->clear();
        queue->pending().clear();
    }
    sp<AMessage> reply;
    (new AMessage(WorkHandler::kWhatStop, mHandler))->postAndAwaitResponse(&reply);
    int32_t err;
    CHECK(reply->findInt32("err", &err));
    if (err != C2_OK) {
        return (c2_status_t)err;
    }
    return C2_OK;
}

c2_status_t SimpleC2Component::reset() {
    ALOGV("reset");
    {
        Mutexed<ExecState>::Locked state(mExecState);
        state->mState = UNINITIALIZED;
    }
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        queue->clear();
        queue->pending().clear();
    }
    sp<AMessage> reply;
    (new AMessage(WorkHandler::kWhatReset, mHandler))->postAndAwaitResponse(&reply);
    return C2_OK;
}

c2_status_t SimpleC2Component::release() {
    ALOGV("release");
    sp<AMessage> reply;
    (new AMessage(WorkHandler::kWhatRelease, mHandler))->postAndAwaitResponse(&reply);
    return C2_OK;
}

std::shared_ptr<C2ComponentInterface> SimpleC2Component::intf() {
    return mIntf;
}

namespace {

std::list<std::unique_ptr<C2Work>> vec(std::unique_ptr<C2Work> &work) {
    std::list<std::unique_ptr<C2Work>> ret;
    ret.push_back(std::move(work));
    return ret;
}

}  // namespace

void SimpleC2Component::finish(
        uint64_t frameIndex, std::function<void(const std::unique_ptr<C2Work> &)> fillWork) {
    std::unique_ptr<C2Work> work;
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        if (queue->pending().count(frameIndex) == 0) {
            ALOGW("unknown frame index: %" PRIu64, frameIndex);
            return;
        }
        work = std::move(queue->pending().at(frameIndex));
        queue->pending().erase(frameIndex);
    }
    if (work) {
        fillWork(work);
        std::shared_ptr<C2Component::Listener> listener = mExecState.lock()->mListener;
        listener->onWorkDone_nb(shared_from_this(), vec(work));
        ALOGV("returning pending work");
    }
}

void SimpleC2Component::cloneAndSend(
        uint64_t frameIndex,
        const std::unique_ptr<C2Work> &currentWork,
        std::function<void(const std::unique_ptr<C2Work> &)> fillWork) {
    std::unique_ptr<C2Work> work(new C2Work);
    if (currentWork->input.ordinal.frameIndex == frameIndex) {
        work->input.flags = currentWork->input.flags;
        work->input.ordinal = currentWork->input.ordinal;
    } else {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        if (queue->pending().count(frameIndex) == 0) {
            ALOGW("unknown frame index: %" PRIu64, frameIndex);
            return;
        }
        work->input.flags = queue->pending().at(frameIndex)->input.flags;
        work->input.ordinal = queue->pending().at(frameIndex)->input.ordinal;
    }
    work->worklets.emplace_back(new C2Worklet);
    if (work) {
        fillWork(work);
        std::shared_ptr<C2Component::Listener> listener = mExecState.lock()->mListener;
        listener->onWorkDone_nb(shared_from_this(), vec(work));
        ALOGV("cloned and sending work");
    }
}

bool SimpleC2Component::processQueue() {
    std::unique_ptr<C2Work> work;
    uint64_t generation;
    int32_t drainMode;
    bool isFlushPending = false;
    bool hasQueuedWork = false;
    {
        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
        if (queue->empty()) {
            return false;
        }

        generation = queue->generation();
        drainMode = queue->drainMode();
        isFlushPending = queue->popPendingFlush();
        work = queue->pop_front();
        hasQueuedWork = !queue->empty();
    }
    if (isFlushPending) {
        ALOGV("processing pending flush");
        c2_status_t err = onFlush_sm();
        if (err != C2_OK) {
            ALOGD("flush err: %d", err);
            // TODO: error
        }
    }

    if (!mOutputBlockPool) {
        c2_status_t err = [this] {
            // TODO: don't use query_vb
            C2StreamBufferTypeSetting::output outputFormat(0u);
            std::vector<std::unique_ptr<C2Param>> params;
            c2_status_t err = intf()->query_vb(
                    { &outputFormat },
                    { C2PortBlockPoolsTuning::output::PARAM_TYPE },
                    C2_DONT_BLOCK,
                    &params);
            if (err != C2_OK && err != C2_BAD_INDEX) {
                ALOGD("query err = %d", err);
                return err;
            }
            C2BlockPool::local_id_t poolId =
                outputFormat.value == C2BufferData::GRAPHIC
                        ? C2BlockPool::BASIC_GRAPHIC
                        : C2BlockPool::BASIC_LINEAR;
            if (params.size()) {
                C2PortBlockPoolsTuning::output *outputPools =
                    C2PortBlockPoolsTuning::output::From(params[0].get());
                if (outputPools && outputPools->flexCount() >= 1) {
                    poolId = outputPools->m.values[0];
                }
            }

            std::shared_ptr<C2BlockPool> blockPool;
            err = GetCodec2BlockPool(poolId, shared_from_this(), &blockPool);
            ALOGD("Using output block pool with poolID %llu => got %llu - %d",
                    (unsigned long long)poolId,
                    (unsigned long long)(
                            blockPool ? blockPool->getLocalId() : 111000111),
                    err);
            if (err == C2_OK) {
                mOutputBlockPool = std::make_shared<BlockingBlockPool>(blockPool);
            }
            return err;
        }();
        if (err != C2_OK) {
            Mutexed<ExecState>::Locked state(mExecState);
            std::shared_ptr<C2Component::Listener> listener = state->mListener;
            state.unlock();
            listener->onError_nb(shared_from_this(), err);
            return hasQueuedWork;
        }
    }

    if (!work) {
        c2_status_t err = drain(drainMode, mOutputBlockPool);
        if (err != C2_OK) {
            Mutexed<ExecState>::Locked state(mExecState);
            std::shared_ptr<C2Component::Listener> listener = state->mListener;
            state.unlock();
            listener->onError_nb(shared_from_this(), err);
        }
        return hasQueuedWork;
    }

    {
        std::vector<C2Param *> updates;
        for (const std::unique_ptr<C2Param> &param: work->input.configUpdate) {
            if (param) {
                updates.emplace_back(param.get());
            }
        }
        if (!updates.empty()) {
            std::vector<std::unique_ptr<C2SettingResult>> failures;
            c2_status_t err = intf()->config_vb(updates, C2_MAY_BLOCK, &failures);
            ALOGD("applied %zu configUpdates => %s (%d)", updates.size(), asString(err), err);
        }
    }

    ALOGV("start processing frame #%" PRIu64, work->input.ordinal.frameIndex.peeku());
    // If input buffer list is not empty, it means we have some input to process on.
    // However, input could be a null buffer. In such case, clear the buffer list
    // before making call to process().
    if (!work->input.buffers.empty() && !work->input.buffers[0]) {
        ALOGD("Encountered null input buffer. Clearing the input buffer");
        work->input.buffers.clear();
    }
    process(work, mOutputBlockPool);
    ALOGV("processed frame #%" PRIu64, work->input.ordinal.frameIndex.peeku());
    Mutexed<WorkQueue>::Locked queue(mWorkQueue);
    if (queue->generation() != generation) {
        ALOGD("work form old generation: was %" PRIu64 " now %" PRIu64,
                queue->generation(), generation);
        work->result = C2_NOT_FOUND;
        queue.unlock();

        Mutexed<ExecState>::Locked state(mExecState);
        std::shared_ptr<C2Component::Listener> listener = state->mListener;
        state.unlock();
        listener->onWorkDone_nb(shared_from_this(), vec(work));
        return hasQueuedWork;
    }
    if (work->workletsProcessed != 0u) {
        queue.unlock();
        Mutexed<ExecState>::Locked state(mExecState);
        ALOGV("returning this work");
        std::shared_ptr<C2Component::Listener> listener = state->mListener;
        state.unlock();
        listener->onWorkDone_nb(shared_from_this(), vec(work));
    } else {
        ALOGV("queue pending work");
        work->input.buffers.clear();
        std::unique_ptr<C2Work> unexpected;

        uint64_t frameIndex = work->input.ordinal.frameIndex.peeku();
        if (queue->pending().count(frameIndex) != 0) {
            unexpected = std::move(queue->pending().at(frameIndex));
            queue->pending().erase(frameIndex);
        }
        (void)queue->pending().insert({ frameIndex, std::move(work) });

        queue.unlock();
        if (unexpected) {
            ALOGD("unexpected pending work");
            unexpected->result = C2_CORRUPTED;
            Mutexed<ExecState>::Locked state(mExecState);
            std::shared_ptr<C2Component::Listener> listener = state->mListener;
            state.unlock();
            listener->onWorkDone_nb(shared_from_this(), vec(unexpected));
        }
    }
    return hasQueuedWork;
}

int SimpleC2Component::getHalPixelFormatForBitDepth10(bool allowRGBA1010102) {
    // Save supported hal pixel formats for bit depth of 10, the first time this is called
    if (!mBitDepth10HalPixelFormats.size()) {
        std::vector<int> halPixelFormats;
        halPixelFormats.push_back(HAL_PIXEL_FORMAT_YCBCR_P010);

        // since allowRGBA1010102 can chance in each call, but mBitDepth10HalPixelFormats
        // is populated only once, allowRGBA1010102 is not considered at this stage.
        halPixelFormats.push_back(HAL_PIXEL_FORMAT_RGBA_1010102);

        for (int halPixelFormat : halPixelFormats) {
            if (isHalPixelFormatSupported((AHardwareBuffer_Format)halPixelFormat)) {
                mBitDepth10HalPixelFormats.push_back(halPixelFormat);
            }
        }
        // Add YV12 in the end as a fall-back option
        mBitDepth10HalPixelFormats.push_back(HAL_PIXEL_FORMAT_YV12);
    }
    // From Android T onwards, HAL_PIXEL_FORMAT_RGBA_1010102 corresponds to true
    // RGBA 1010102 format unlike earlier versions where it was used to represent
    // YUVA 1010102 data
    if (!isAtLeastT()) {
        // When RGBA1010102 is not allowed and if the first supported hal pixel is format is
        // HAL_PIXEL_FORMAT_RGBA_1010102, then return HAL_PIXEL_FORMAT_YV12
        if (!allowRGBA1010102 && mBitDepth10HalPixelFormats[0] == HAL_PIXEL_FORMAT_RGBA_1010102) {
            return HAL_PIXEL_FORMAT_YV12;
        }
    }
    // Return the first entry from supported formats
    return mBitDepth10HalPixelFormats[0];
}
std::shared_ptr<C2Buffer> SimpleC2Component::createLinearBuffer(
        const std::shared_ptr<C2LinearBlock> &block, size_t offset, size_t size) {
    return C2Buffer::CreateLinearBuffer(block->share(offset, size, ::C2Fence()));
}

std::shared_ptr<C2Buffer> SimpleC2Component::createGraphicBuffer(
        const std::shared_ptr<C2GraphicBlock> &block, const C2Rect &crop) {
    return C2Buffer::CreateGraphicBuffer(block->share(crop, ::C2Fence()));
}

} // namespace android
