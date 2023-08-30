/*
 * Copyright (C) 2009 The Android Open Source Project
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
#define LOG_TAG "ColorConverter"
#include <android-base/macros.h>
#include <utils/Log.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/ALooper.h>
#include <media/stagefright/foundation/ColorUtils.h>
#include <media/stagefright/ColorConverter.h>
#include <media/stagefright/MediaCodecConstants.h>
#include <media/stagefright/MediaErrors.h>

#include "libyuv/convert_from.h"
#include "libyuv/convert_argb.h"
#include "libyuv/planar_functions.h"
#include "libyuv/video_common.h"
#include <functional>
#include <sys/time.h>

#define PERF_PROFILING 0

#if defined(__aarch64__) || defined(__ARM_NEON__)
#define USE_NEON_Y410 1
#else
#define USE_NEON_Y410 0
#endif

#if USE_NEON_Y410
#include <arm_neon.h>
#endif

namespace android {
typedef const struct libyuv::YuvConstants LibyuvConstants;

struct LibyuvConstPair {
    const LibyuvConstants *yuv;
    const LibyuvConstants *yvu;
};

// Function to resolve YUV Matrices defined in libyuv
static LibyuvConstPair getLibYUVMatrix(
        const ColorConverter::ColorSpace &colorSpace, bool is10Bit) {
    LibyuvConstPair matrix = {nullptr, nullptr};
    const bool isFullRange = (colorSpace.mRange == ColorUtils::kColorRangeFull);
    if (colorSpace.isI601()) {
        matrix.yuv = &libyuv::kYuvI601Constants;
        matrix.yvu = &libyuv::kYvuI601Constants;
    } else if (colorSpace.isJ601()) {
        matrix.yuv = &libyuv::kYuvJPEGConstants;
        matrix.yvu = &libyuv::kYvuJPEGConstants;
    } else if (colorSpace.isH709()) {
        matrix.yuv = &libyuv::kYuvH709Constants;
        matrix.yvu = &libyuv::kYvuH709Constants;
    } else if (colorSpace.isF709()) {
        matrix.yuv = &libyuv::kYuvF709Constants;
        matrix.yvu = &libyuv::kYvuF709Constants;
    } else if (colorSpace.isBt2020()) {
        matrix.yuv = &libyuv::kYuv2020Constants;
        matrix.yvu = &libyuv::kYvu2020Constants;
    } else if (colorSpace.isBtV2020()) {
        matrix.yuv = &libyuv::kYuvV2020Constants;
        matrix.yvu = &libyuv::kYvuV2020Constants;
    } else {
        // unspecified
        if (isFullRange) {
            matrix.yuv = is10Bit ? &libyuv::kYuvV2020Constants : &libyuv::kYuvJPEGConstants;
            matrix.yvu = is10Bit ? &libyuv::kYvuV2020Constants : &libyuv::kYvuJPEGConstants;
        } else {
            matrix.yuv = is10Bit ? &libyuv::kYuv2020Constants : &libyuv::kYuvI601Constants;
            matrix.yvu = is10Bit ? &libyuv::kYvu2020Constants : &libyuv::kYvuI601Constants;
        }
    }
    return matrix;
}

static bool isRGB(OMX_COLOR_FORMATTYPE colorFormat) {
    return colorFormat == OMX_COLOR_Format16bitRGB565
            || colorFormat == OMX_COLOR_Format32BitRGBA8888
            || colorFormat == OMX_COLOR_Format32bitBGRA8888
            || colorFormat == COLOR_Format32bitABGR2101010;
}

// check for limited Range
bool ColorConverter::ColorSpace::isLimitedRange() const {
    return mRange == ColorUtils::kColorRangeLimited;
}

// BT.2020 limited range YUV to RGB
bool ColorConverter::ColorSpace::isBt2020() const {
    return (mStandard == ColorUtils::kColorStandardBT2020
            && mRange == ColorUtils::kColorRangeLimited);
}

// BT.2020 full range YUV to RGB
bool ColorConverter::ColorSpace::isBtV2020() const {
    return (mStandard == ColorUtils::kColorStandardBT2020
            && mRange == ColorUtils::kColorRangeFull);
}

// BT.709 full range YUV to RGB
bool ColorConverter::ColorSpace::isF709() const {
    return (mStandard == ColorUtils::kColorStandardBT709
            && mRange == ColorUtils::kColorRangeFull);
}

// BT.709 limited range YUV to RGB
bool ColorConverter::ColorSpace::isH709() const {
    return (mStandard == ColorUtils::kColorStandardBT709)
            && (mRange == ColorUtils::kColorRangeLimited);
}

// BT.601 limited range YUV to RGB
// the matrix coefficients are the same for both 601.625 and 601.525 standards
bool ColorConverter::ColorSpace::isI601() const {
    return ((mStandard == ColorUtils::kColorStandardBT601_625)
            || (mStandard == ColorUtils::kColorStandardBT601_525))
            && (mRange == ColorUtils::kColorRangeLimited);
}

// BT.601 full range YUV to RGB
bool ColorConverter::ColorSpace::isJ601() const {
    return ((mStandard == ColorUtils::kColorStandardBT601_625)
            || (mStandard == ColorUtils::kColorStandardBT601_525))
            && (mRange == ColorUtils::kColorRangeFull);
}

// Utility functions for MediaImage2
static MediaImage2 CreateYUV420PlanarMediaImage2(
        uint32_t width, uint32_t height, uint32_t stride,
        uint32_t vstride, uint32_t bitDepth) {
    const uint32_t componentBytes = (bitDepth + 7) / 8;
    return MediaImage2 {
        .mType = MediaImage2::MEDIA_IMAGE_TYPE_YUV,
        .mNumPlanes = 3,
        .mWidth = width,
        .mHeight = height,
        .mBitDepth = bitDepth,
        .mBitDepthAllocated = componentBytes * 8,
        .mPlane = {
            {
                .mOffset = 0,
                .mColInc = static_cast<int32_t>(componentBytes),
                .mRowInc = static_cast<int32_t>(stride),
                .mHorizSubsampling = 1,
                .mVertSubsampling = 1,
            },
            {
                .mOffset = stride * vstride,
                .mColInc = static_cast<int32_t>(componentBytes),
                .mRowInc = static_cast<int32_t>(stride / 2),
                .mHorizSubsampling = 2,
                .mVertSubsampling = 2,
            },
            {
                .mOffset = stride * vstride * 5 / 4,
                .mColInc = static_cast<int32_t>(componentBytes),
                .mRowInc = static_cast<int32_t>(stride / 2),
                .mHorizSubsampling = 2,
                .mVertSubsampling = 2,
            }
        },
    };
}

static MediaImage2 CreateYUV420SemiPlanarMediaImage2(
        uint32_t width, uint32_t height, uint32_t stride,
        uint32_t vstride, uint32_t bitDepth, bool uv = true /*nv12 or not*/) {
    const uint32_t componentBytes = (bitDepth + 7) / 8;
    return MediaImage2 {
        .mType = MediaImage2::MEDIA_IMAGE_TYPE_YUV,
        .mNumPlanes = 3,
        .mWidth = width,
        .mHeight = height,
        .mBitDepth = bitDepth,
        .mBitDepthAllocated = componentBytes * 8,
        .mPlane = {
            {
                .mOffset = 0,
                .mColInc = static_cast<int32_t>(componentBytes),
                .mRowInc = static_cast<int32_t>(stride),
                .mHorizSubsampling = 1,
                .mVertSubsampling = 1,
            },
            {
                .mOffset = stride * vstride + (uv ? 0 : componentBytes),
                .mColInc = static_cast<int32_t>(2 * componentBytes),
                .mRowInc = static_cast<int32_t>(stride),
                .mHorizSubsampling = 2,
                .mVertSubsampling = 2,
            },
            {
                .mOffset = stride * vstride + (uv ? componentBytes : 0),
                .mColInc = static_cast<int32_t>(2 * componentBytes),
                .mRowInc = static_cast<int32_t>(stride),
                .mHorizSubsampling = 2,
                .mVertSubsampling = 2,
            }
        },
    };
}

ColorConverter::Image::Image(const MediaImage2& img)
    :mImage(img),
    mLayout(ImageLayoutUnknown),
    mSampling(ImageSamplingUnknown) {
    const MediaImage2::PlaneInfo &yPlane =
            img.mPlane[MediaImage2::PlaneIndex::Y];
    const MediaImage2::PlaneInfo &uPlane =
            img.mPlane[MediaImage2::PlaneIndex::U];
    const MediaImage2::PlaneInfo &vPlane =
            img.mPlane[MediaImage2::PlaneIndex::V];

    if (mImage.mNumPlanes != 3) {
        ALOGE("Conversion error: MediaImage2 mNumPlanes != 3");
        mLayout = ImageLayoutUnknown;
        mSampling = ImageSamplingUnknown;
        mBitDepth = ImageBitDepthInvalid;
        return;
    }

    if (mImage.mBitDepth == 8
            && yPlane.mColInc == 1
            && uPlane.mColInc == 1
            && vPlane.mColInc == 1
            && yPlane.mVertSubsampling == 1
            && uPlane.mVertSubsampling == 2
            && vPlane.mVertSubsampling == 2) {
        mLayout = ImageLayout420Planar;
        mSampling = ImageSamplingYUV420;
    } else if (mImage.mBitDepth == 8
            && yPlane.mColInc == 1
            && uPlane.mColInc == 2
            && vPlane.mColInc == 2
            && yPlane.mVertSubsampling == 1
            && uPlane.mVertSubsampling == 2
            && vPlane.mVertSubsampling == 2
            && ((vPlane.mOffset == uPlane.mOffset + 1) ||
            (uPlane.mOffset == vPlane.mOffset + 1))) {
        mLayout = ImageLayout420SemiPlanar;
        mSampling = ImageSamplingYUV420;
    }

    mBitDepth = ImageBitDepthInvalid;
    switch (img.mBitDepth) {
        case 8:
            mBitDepth = ImageBitDepth8;
            break;

        case 10:
        case 12:
        case 16:
        default:
            // TODO: Implement 10b, 12b and 16b using MediaImage2
            mBitDepth = ImageBitDepthInvalid;
    }

}

status_t ColorConverter::Image::getYUVPlaneOffsetAndStride(
        const BitmapParams &src,
        uint32_t *y_offset,
        uint32_t *u_offset,
        uint32_t *v_offset,
        size_t *y_stride,
        size_t *u_stride,
        size_t *v_stride) const {

    if (y_offset == nullptr || u_offset == nullptr || v_offset == nullptr
            || y_stride == nullptr || u_stride == nullptr || v_stride == nullptr) {
        return ERROR_UNSUPPORTED;
    }

    if (mImage.mNumPlanes != 3) {
        return ERROR_UNSUPPORTED;
    }

    const MediaImage2::PlaneInfo &yPlane = mImage.mPlane[MediaImage2::PlaneIndex::Y];
    *y_offset = yPlane.mOffset
            + src.mCropTop * yPlane.mRowInc
            + src.mCropLeft * yPlane.mColInc;

    const MediaImage2::PlaneInfo &uPlane = mImage.mPlane[MediaImage2::PlaneIndex::U];
    *u_offset = uPlane.mOffset
            + (src.mCropTop / uPlane.mVertSubsampling) * uPlane.mRowInc
            + (src.mCropLeft / uPlane.mHorizSubsampling) * uPlane.mColInc;

    const MediaImage2::PlaneInfo &vPlane = mImage.mPlane[MediaImage2::PlaneIndex::V];
    *v_offset = vPlane.mOffset
            + (src.mCropTop / vPlane.mVertSubsampling) * vPlane.mRowInc
            + (src.mCropLeft / vPlane.mHorizSubsampling) * vPlane.mColInc;

    *y_stride = yPlane.mRowInc;
    *u_stride = uPlane.mRowInc;
    *v_stride = vPlane.mRowInc;

    return OK;
}

bool ColorConverter::Image::isNV21() const {
    if (getLayout() == ImageLayout420SemiPlanar) {
        const MediaImage2::PlaneInfo &uPlane = mImage.mPlane[MediaImage2::PlaneIndex::U];
        const MediaImage2::PlaneInfo &vPlane = mImage.mPlane[MediaImage2::PlaneIndex::V];

        int componentBytes = (mImage.mBitDepthAllocated) / 8;

        return (((vPlane.mOffset + componentBytes) == uPlane.mOffset));
    }
    return false;
}

/**
 * This class approximates the standard YUV to RGB conversions by factoring the matrix
 * coefficients to 1/256th-s (as dividing by 256 is easy to do with right shift). The chosen value
 * of 256 is somewhat arbitrary and was not dependent on the bit-depth, but it does limit the
 * precision of the matrix coefficients (KR & KB).
 *
 * The maximum color error after clipping from using 256 is a distance of:
 *   0.4 (8-bit) / 1.4 (10-bit) for greens in BT.601
 *   0.5 (8-bit) / 1.9 (10-bit) for cyans in BT.709, and
 *   0.3 (8-bit) / 1.3 (10-bit) for violets in BT.2020 (it is 0.4 for 10-bit BT.2020 limited)
 *
 * Note for reference: libyuv is using a divisor of 64 instead of 256 to ensure no overflow in
 * 16-bit math. The maximum color error for libyuv is 3.5 / 14.
 *
 * The clamping is done using a lookup vector where negative indices are mapped to 0
 * and indices > 255 are mapped to 255. (For 10-bit these are clamped to 0 to 1023)
 *
 * The matrices are assumed to be of the following format (note the sign on the 2nd row):
 *
 * [ R ]     [ _y     0    _r_v ]   [ Y -  C16 ]
 * [ G ]  =  [ _y  -_g_u  -_g_v ] * [ U - C128 ]
 * [ B ]     [ _y   _b_u     0  ]   [ V - C128 ]
 *
 * C16 is 1 << (bitdepth - 4) for limited range, and 0 for full range
 * C128 is 1 << (bitdepth - 1)
 * C255 is (1 << bitdepth) - 1
 *
 * The min and max values from these equations determine the clip range needed for clamping:
 *
 * min = - (_y * C16 + max((_g_u + _g_v) * (C255-C128), max(_r_v, _b_u) * C128)) / 256
 * max = (_y * (C255 - C16) + max((_g_u + _g_v) * C128, max(_r_v, _b_u) * (C255-C128)) + 128) / 256
 */

struct ColorConverter::Coeffs {
    int32_t _y;
    int32_t _r_v;
    int32_t _g_u;
    int32_t _g_v;
    int32_t _b_u;
    int32_t _c16;  // 16 for limited range matrix, 0 for full rance
};

/*

Color conversion rules are dictated by ISO (e.g. ISO:IEC 23008:2)

Limited range means Y is in [16, 235], U and V are in [16, 224] corresponding to [-0.5 to 0.5].

Full range means Y is in [0, 255], U and V are in [0.5, 255.5] corresponding to [-0.5 to .5].

RGB is always in full range ([0, 255])

The color primaries determine the KR and KB values:


For full range (assuming 8-bits) ISO defines:

(   Y   )   (  KR      1-KR-KB       KB  )
(       )   (                            )   (R)
(       )   (-KR/2   -(1-KR-KB)/2        )   ( )
(U - 128) = (-----   ------------    0.5 ) * (G)
(       )   ((1-KB)     (1-KB)           )   ( )
(       )   (                            )   (B)
(       )   (        -(1-KR-KB)/2  -KB/2 )
(V - 128)   ( 0.5    ------------  ----- )
            (           (1-KR)     (1-KR))

(the math is rounded, 128 is (1 << (bitdepth - 1)) )

From this

(R)      ( 1       0        2*(1-KR)   )   (   Y   )
( )      (                             )   (       )
( )      (    2*KB*(KB-1)  2*KR*(KR-1) )   (       )
(G)  =   ( 1  -----------  ----------- ) * (U - 128)
( )      (      1-KR-KB      1-KR-KB   )   (       )
( )      (                             )   (       )
(B)      ( 1   2*(1-KB)         0      )   (V - 128)

For limited range, this becomes

(R)      ( 1       0        2*(1-KR)   )   (255/219  0  0)   (Y -  16)
( )      (                             )   (             )   (       )
( )      (    2*KB*(KB-1)  2*KR*(KR-1) )   (             )   (       )
(G)  =   ( 1  -----------  ----------- ) * (0  255/224  0) * (U - 128)
( )      (      1-KR-KB      1-KR-KB   )   (             )   (       )
( )      (                             )   (             )   (       )
(B)      ( 1   2*(1-KB)         0      )   (0  0  255/224)   (V - 128)

( For non-8-bit, 16 is (1 << (bitdepth - 4)), 128 is (1 << (bitdepth - 1)),
  255 is ((1 << bitdepth) - 1), 219 is (219 << (bitdepth - 8)) and
  224 is (224 << (bitdepth - 8)), so the matrix coefficients slightly change. )

*/

namespace {

/**
 * BT.601:  K_R = 0.299;  K_B = 0.114
 *
 * clip range 8-bit: [-277, 535], 10-bit: [-1111, 2155]
 */
const struct ColorConverter::Coeffs BT601_FULL      = { 256, 359,  88, 183, 454, 0 };
const struct ColorConverter::Coeffs BT601_LIMITED   = { 298, 409, 100, 208, 516, 16 };
const struct ColorConverter::Coeffs BT601_LTD_10BIT = { 299, 410, 101, 209, 518, 16 };

/**
 * BT.709:  K_R = 0.2126; K_B = 0.0722
 *
 * clip range 8-bit: [-289, 547], 10-bit: [-1159, 2202]
 */
const struct ColorConverter::Coeffs BT709_FULL      = { 256, 403,  48, 120, 475, 0 };
const struct ColorConverter::Coeffs BT709_LIMITED   = { 298, 459,  55, 136, 541, 16 };
const struct ColorConverter::Coeffs BT709_LTD_10BIT = { 299, 460,  55, 137, 542, 16 };

/**
 * BT.2020:  K_R = 0.2627; K_B = 0.0593
 *
 * clip range 8-bit: [-294, 552], 10-bit: [-1175, 2218]
 *
 * This is the largest clip range.
 */
const struct ColorConverter::Coeffs BT2020_FULL      = { 256, 377,  42, 146, 482, 0 };
const struct ColorConverter::Coeffs BT2020_LIMITED   = { 298, 430,  48, 167, 548, 16 };
const struct ColorConverter::Coeffs BT2020_LTD_10BIT = { 299, 431,  48, 167, 550, 16 };

constexpr int CLIP_RANGE_MIN_8BIT = -294;
constexpr int CLIP_RANGE_MAX_8BIT = 552;

constexpr int CLIP_RANGE_MIN_10BIT = -1175;
constexpr int CLIP_RANGE_MAX_10BIT = 2218;

}

ColorConverter::ColorConverter(
        OMX_COLOR_FORMATTYPE from, OMX_COLOR_FORMATTYPE to)
    : mSrcFormat(from),
      mDstFormat(to),
      mSrcColorSpace({0, 0, 0}),
      mClip(NULL),
      mClip10Bit(NULL) {
}

ColorConverter::~ColorConverter() {
    delete[] mClip;
    mClip = NULL;
    delete[] mClip10Bit;
    mClip10Bit = NULL;
}

// Set MediaImage2 Flexible formats
void ColorConverter::setSrcMediaImage2(MediaImage2 img) {
    mSrcImage = Image(img);
 }

bool ColorConverter::isValidForMediaImage2() const {

    if (!mSrcImage
            || mSrcImage->getMediaImage2().mType != MediaImage2::MEDIA_IMAGE_TYPE_YUV) {
        // TODO: support Yonly or RGB etc?
        return false;
    }
    // try to identify the src format

    BitDepth_t srcBitDepth = mSrcImage->getBitDepth();

    //TODO: support 12b and 16b ?
    if (srcBitDepth == ImageBitDepthInvalid) {
        return false;
    }

    return ((srcBitDepth == ImageBitDepth8  &&
            (mDstFormat == OMX_COLOR_Format16bitRGB565
            || mDstFormat == OMX_COLOR_Format32BitRGBA8888
            || mDstFormat == OMX_COLOR_Format32bitBGRA8888))

            || (srcBitDepth == ImageBitDepth10
            && (mDstFormat == COLOR_Format32bitABGR2101010)));
}

bool ColorConverter::isValid() const {
    switch ((int32_t)mSrcFormat) {
        case COLOR_FormatYUV420Flexible:
            return isValidForMediaImage2();
            break;

        case OMX_COLOR_FormatYUV420Planar16:
            if (mDstFormat == OMX_COLOR_FormatYUV444Y410) {
                return true;
            }
            FALLTHROUGH_INTENDED;
        case OMX_COLOR_FormatYUV420Planar:
            return mDstFormat == OMX_COLOR_Format16bitRGB565
                    || mDstFormat == OMX_COLOR_Format32BitRGBA8888
                    || mDstFormat == OMX_COLOR_Format32bitBGRA8888;

        case OMX_COLOR_FormatCbYCrY:
            return mDstFormat == OMX_COLOR_Format16bitRGB565;

        case OMX_COLOR_FormatYUV420SemiPlanar:
        case OMX_QCOM_COLOR_FormatYVU420SemiPlanar:
        case OMX_TI_COLOR_FormatYUV420PackedSemiPlanar:
            if (mSrcImage) {
                return isValidForMediaImage2();
            }
            return mDstFormat == OMX_COLOR_Format16bitRGB565
                    || mDstFormat == OMX_COLOR_Format32BitRGBA8888
                    || mDstFormat == OMX_COLOR_Format32bitBGRA8888;

        case COLOR_FormatYUVP010:
            return mDstFormat == COLOR_Format32bitABGR2101010;

        default:
            //TODO: Should this be enabled for MediaImage2?
            return false;
    }
}

bool ColorConverter::isDstRGB() const {
    return isRGB(mDstFormat);
}

void ColorConverter::setSrcColorSpace(
        uint32_t standard, uint32_t range, uint32_t transfer) {
    if (isRGB(mSrcFormat)) {
        ALOGW("Can't set color space on RGB source");
        return;
    }
    mSrcColorSpace.mStandard = standard;
    mSrcColorSpace.mRange = range;
    mSrcColorSpace.mTransfer = transfer;
}

/*
 * If stride is non-zero, client's stride will be used. For planar
 * or semi-planar YUV formats, stride must be even numbers.
 * If stride is zero, it will be calculated based on width and bpp
 * of the format, assuming no padding on the right edge.
 */
ColorConverter::BitmapParams::BitmapParams(
        void *bits,
        size_t width, size_t height, size_t stride,
        size_t cropLeft, size_t cropTop,
        size_t cropRight, size_t cropBottom,
        OMX_COLOR_FORMATTYPE colorFromat)
    : mBits(bits),
      mColorFormat(colorFromat),
      mWidth(width),
      mHeight(height),
      mCropLeft(cropLeft),
      mCropTop(cropTop),
      mCropRight(cropRight),
      mCropBottom(cropBottom) {
    switch((int32_t)mColorFormat) {
    case OMX_COLOR_Format16bitRGB565:
    case OMX_COLOR_FormatYUV420Planar16:
    case COLOR_FormatYUVP010:
    case OMX_COLOR_FormatCbYCrY:
        mBpp = 2;
        mStride = 2 * mWidth;
        break;

    case OMX_COLOR_Format32bitBGRA8888:
    case OMX_COLOR_Format32BitRGBA8888:
    case COLOR_Format32bitABGR2101010:
    case OMX_COLOR_FormatYUV444Y410:
        mBpp = 4;
        mStride = 4 * mWidth;
        break;

    case OMX_COLOR_FormatYUV420Planar:
    case OMX_QCOM_COLOR_FormatYVU420SemiPlanar:
    case OMX_COLOR_FormatYUV420SemiPlanar:
    case OMX_TI_COLOR_FormatYUV420PackedSemiPlanar:
        mBpp = 1;
        mStride = mWidth;
        break;

    case COLOR_FormatYUV420Flexible:
        // MediaImage2 should be used.
        mBpp = 1;
        mStride = mWidth;

        break;

    default:
        ALOGE("Unsupported color format %d", mColorFormat);
        mBpp = 1;
        mStride = mWidth;
        break;
    }
    // use client's stride if it's specified.
    if (stride != 0) {
        mStride = stride;
    }
}

size_t ColorConverter::BitmapParams::cropWidth() const {
    return mCropRight - mCropLeft + 1;
}

size_t ColorConverter::BitmapParams::cropHeight() const {
    return mCropBottom - mCropTop + 1;
}

bool ColorConverter::BitmapParams::isValid() const {
    if (!((mStride & 1) == 0  // stride must be even
        && mStride >= mBpp * cropWidth())) {
            return false;
    }
    return true;
}

status_t ColorConverter::convert(
        const void *srcBits,
        size_t srcWidth, size_t srcHeight, size_t srcStride,
        size_t srcCropLeft, size_t srcCropTop,
        size_t srcCropRight, size_t srcCropBottom,
        void *dstBits,
        size_t dstWidth, size_t dstHeight, size_t dstStride,
        size_t dstCropLeft, size_t dstCropTop,
        size_t dstCropRight, size_t dstCropBottom) {
    BitmapParams src(
            const_cast<void *>(srcBits),
            srcWidth, srcHeight, srcStride,
            srcCropLeft, srcCropTop, srcCropRight, srcCropBottom,
            mSrcFormat);

    BitmapParams dst(
            dstBits,
            dstWidth, dstHeight, dstStride,
            dstCropLeft, dstCropTop, dstCropRight, dstCropBottom, mDstFormat);

    if (!(src.isValid()
            && dst.isValid()
            && (src.mCropLeft & 1) == 0
            && src.cropWidth() == dst.cropWidth()
            && src.cropHeight() == dst.cropHeight())) {
        return ERROR_UNSUPPORTED;
    }
#if PERF_PROFILING
    int64_t startTimeUs = ALooper::GetNowUs();
#endif
    status_t err;
    switch ((int32_t)mSrcFormat) {
        case COLOR_FormatYUV420Flexible:
            err = convertYUVMediaImage(src, dst);
            break;

        case OMX_COLOR_FormatYUV420Planar:
            if (!mSrcImage) {
                mSrcImage = Image(CreateYUV420PlanarMediaImage2(
                        srcWidth, srcHeight, srcStride, srcHeight, 8 /*bitDepth*/));
            }
            err = convertYUVMediaImage(src, dst);

            break;

        case OMX_COLOR_FormatYUV420Planar16:
            err = convertYUV420Planar16(src, dst);
            break;

        case COLOR_FormatYUVP010:
            err = convertYUVP010(src, dst);

            break;

        case OMX_COLOR_FormatCbYCrY:
            err = convertCbYCrY(src, dst);
            break;

        case OMX_QCOM_COLOR_FormatYVU420SemiPlanar:
            if (!mSrcImage) {
                mSrcImage = Image(CreateYUV420SemiPlanarMediaImage2(
                    srcWidth, srcHeight, srcStride, srcHeight, 8 /*bitDepth*/, false));
            }
            err = convertYUVMediaImage(src, dst);

            break;

        case OMX_COLOR_FormatYUV420SemiPlanar:
        case OMX_TI_COLOR_FormatYUV420PackedSemiPlanar:
            if (!mSrcImage) {
                mSrcImage = Image(CreateYUV420SemiPlanarMediaImage2(
                    srcWidth, srcHeight, srcStride, srcHeight, 8 /*bitDepth*/));
            }
            err = convertYUVMediaImage(src, dst);

            break;

        default:

            CHECK(!"Should not be here. Unknown color conversion.");
            break;
    }

#if PERF_PROFILING
    int64_t endTimeUs = ALooper::GetNowUs();
    ALOGD("%s image took %lld us", asString_ColorFormat(mSrcFormat,"Unknown"),
            (long long) (endTimeUs - startTimeUs));
#endif

    return err;
}

const struct ColorConverter::Coeffs *ColorConverter::getMatrix() const {
    const bool isFullRange = mSrcColorSpace.mRange == ColorUtils::kColorRangeFull;
    const bool is10Bit = (mSrcFormat == COLOR_FormatYUVP010
            || mSrcFormat == OMX_COLOR_FormatYUV420Planar16);

    ColorAspects::Primaries primaries;
    ColorAspects::MatrixCoeffs matrix;
    if (ColorUtils::unwrapColorAspectsFromColorStandard(
            mSrcColorSpace.mStandard, &primaries, &matrix) != OK) {
        matrix = ColorAspects::MatrixUnspecified;
    }

    switch (matrix) {
    case ColorAspects::MatrixBT601_6:
    case ColorAspects::MatrixBT470_6M:   // use 601 matrix as that is the closest for now
    case ColorAspects::MatrixSMPTE240M:  // use 601 matrix as that is the closest for now
        return (isFullRange ? &BT601_FULL :
                is10Bit ? &BT601_LTD_10BIT : &BT601_LIMITED);

    case ColorAspects::MatrixBT709_5:
        return (isFullRange ? &BT709_FULL :
                is10Bit ? &BT709_LTD_10BIT : &BT709_LIMITED);

    case ColorAspects::MatrixBT2020:
    case ColorAspects::MatrixBT2020Constant: // use 2020 matrix as that is the closest for now
        return (isFullRange ? &BT2020_FULL :
                is10Bit ? &BT2020_LTD_10BIT : &BT2020_LIMITED);

    default:
        // use BT.2020 for 10-bit and 601 for 8-bit by default
        if (is10Bit) {
            return isFullRange ? &BT2020_FULL : &BT2020_LTD_10BIT;
        } else {
            return isFullRange ? &BT601_FULL : &BT601_LIMITED;
        }
    }
}

// Interleaved YUV 422 CbYCrY to RGB565
status_t ColorConverter::convertCbYCrY(
        const BitmapParams &src, const BitmapParams &dst) {
    // XXX Untested

    const struct Coeffs *matrix = getMatrix();
    if (!matrix) {
        return ERROR_UNSUPPORTED;
    }

    signed _b_u = matrix->_b_u;
    signed _neg_g_u = -matrix->_g_u;
    signed _neg_g_v = -matrix->_g_v;
    signed _r_v = matrix->_r_v;
    signed _y = matrix->_y;
    signed _c16 = matrix->_c16;

    uint8_t *kAdjustedClip = initClip();

    uint16_t *dst_ptr = (uint16_t *)dst.mBits
        + dst.mCropTop * dst.mWidth + dst.mCropLeft;

    const uint8_t *src_ptr = (const uint8_t *)src.mBits
        + (src.mCropTop * src.mWidth + src.mCropLeft) * 2;

    for (size_t y = 0; y < src.cropHeight(); ++y) {
        for (size_t x = 0; x < src.cropWidth() - 1; x += 2) {
            signed y1 = (signed)src_ptr[2 * x + 1] - _c16;
            signed y2 = (signed)src_ptr[2 * x + 3] - _c16;
            signed u = (signed)src_ptr[2 * x] - 128;
            signed v = (signed)src_ptr[2 * x + 2] - 128;

            signed u_b = u * _b_u;
            signed u_g = u * _neg_g_u;
            signed v_g = v * _neg_g_v;
            signed v_r = v * _r_v;

            signed tmp1 = y1 * _y + 128;
            signed b1 = (tmp1 + u_b) / 256;
            signed g1 = (tmp1 + v_g + u_g) / 256;
            signed r1 = (tmp1 + v_r) / 256;

            signed tmp2 = y2 * _y + 128;
            signed b2 = (tmp2 + u_b) / 256;
            signed g2 = (tmp2 + v_g + u_g) / 256;
            signed r2 = (tmp2 + v_r) / 256;

            uint32_t rgb1 =
                ((kAdjustedClip[r1] >> 3) << 11)
                | ((kAdjustedClip[g1] >> 2) << 5)
                | (kAdjustedClip[b1] >> 3);

            uint32_t rgb2 =
                ((kAdjustedClip[r2] >> 3) << 11)
                | ((kAdjustedClip[g2] >> 2) << 5)
                | (kAdjustedClip[b2] >> 3);

            if (x + 1 < src.cropWidth()) {
                *(uint32_t *)(&dst_ptr[x]) = (rgb2 << 16) | rgb1;
            } else {
                dst_ptr[x] = rgb1;
            }
        }

        src_ptr += src.mWidth * 2;
        dst_ptr += dst.mWidth;
    }

    return OK;
}

status_t ColorConverter::getSrcYUVPlaneOffsetAndStride(
        const BitmapParams &src,
        uint32_t *y_offset, uint32_t *u_offset, uint32_t *v_offset,
        size_t *y_stride, size_t *u_stride, size_t *v_stride) const {
    if (y_offset == nullptr || u_offset == nullptr || v_offset == nullptr
            || y_stride == nullptr || u_stride == nullptr || v_stride == nullptr) {
        ALOGE("nullptrs given for yuv source offset / stride");
        return ERROR_MALFORMED;
    }

    if (mSrcImage) {
        // if we have MediaImage2; get the info from MediaImage2
        return mSrcImage->getYUVPlaneOffsetAndStride(src, y_offset, u_offset, v_offset,
                y_stride, u_stride, v_stride);
    }
    return ERROR_UNSUPPORTED;
}
/*
    libyuv supports the following color spaces:

    I601:  BT.601 limited range
    J601:  BT.601 full range (jpeg)
    H709:  BT.709 limited range
    F709:  BT.709 Full range
    2020:  BT.2020 limited range
    V2020: BT.2020 Full range

*/

status_t ColorConverter::convertYUV420PlanarUseLibYUV(
        const BitmapParams &src, const BitmapParams &dst) {
    LibyuvConstPair yuvConstants =
            getLibYUVMatrix(mSrcColorSpace, false);

    uint32_t y_offset = 0, u_offset = 0, v_offset = 0;
    size_t src_stride_y =0, src_stride_u = 0, src_stride_v = 0;
    if (getSrcYUVPlaneOffsetAndStride(src, &y_offset, &u_offset, &v_offset,
                          &src_stride_y, &src_stride_u, &src_stride_v) != OK) {
        return ERROR_UNSUPPORTED;
    }

    uint8_t *dst_ptr = (uint8_t *)dst.mBits
        + dst.mCropTop * dst.mStride + dst.mCropLeft * dst.mBpp;

    const uint8_t *src_y = (const uint8_t *)src.mBits + y_offset;

    const uint8_t *src_u = (const uint8_t *)src.mBits + u_offset;

    const uint8_t *src_v = (const uint8_t *)src.mBits + v_offset;

    switch (mDstFormat) {
    case OMX_COLOR_Format16bitRGB565:
    {
        libyuv::I420ToRGB565Matrix(src_y,
                src_stride_y,
                src_u,
                src_stride_u,
                src_v,
                src_stride_v,
                dst_ptr,
                dst.mStride,
                yuvConstants.yuv,
                src.cropWidth(),
                src.cropHeight());

        break;
    }

    case OMX_COLOR_Format32bitBGRA8888:
    {
        libyuv::I420ToARGBMatrix(src_y,
                src_stride_y,
                src_u,
                src_stride_u,
                src_v,
                src_stride_v,
                (uint8_t*)dst_ptr,
                dst.mStride,
                yuvConstants.yuv,
                src.cropWidth(),
                src.cropHeight());
        break;
    }

    case OMX_COLOR_Format32BitRGBA8888:
    {
        libyuv::I420ToARGBMatrix(src_y,
                src_stride_y,
                src_v,
                src_stride_v,
                src_u,
                src_stride_u,
                (uint8_t*)dst_ptr,
                dst.mStride,
                yuvConstants.yvu,
                src.cropWidth(),
                src.cropHeight());
        break;
    }

    default:
        return ERROR_UNSUPPORTED;
    }

    return OK;
}

status_t ColorConverter::convertYUV420SemiPlanarUseLibYUV(
        const BitmapParams &src, const BitmapParams &dst) {
    LibyuvConstPair yuvConstants =
            getLibYUVMatrix(mSrcColorSpace, false);

    uint32_t y_offset = 0, u_offset = 0, v_offset = 0;
    size_t src_stride_y =0, src_stride_u = 0, src_stride_v = 0;
    if (getSrcYUVPlaneOffsetAndStride(src, &y_offset, &u_offset, &v_offset,
                          &src_stride_y, &src_stride_u, &src_stride_v) != OK) {
        return ERROR_UNSUPPORTED;
    }
    (void)v_offset;
    uint8_t *dst_ptr = (uint8_t *)dst.mBits
        + dst.mCropTop * dst.mStride + dst.mCropLeft * dst.mBpp;

    const uint8_t *src_y = (const uint8_t *)src.mBits + y_offset;

    const uint8_t *src_u = (const uint8_t *)src.mBits + u_offset;

    const uint8_t *src_v = (const uint8_t *)src.mBits + v_offset;

    bool isNV21 = (u_offset == (v_offset + 1)) ? true : false;

    // libyuv function signature for semiplanar formats;
    std::function<int(const uint8_t*, int,
            const uint8_t*, int, uint8_t *, int,
            LibyuvConstants *, int, int)> libyuvFunc;

    switch (mDstFormat) {
    case OMX_COLOR_Format16bitRGB565:
    {
        // Note: We don't seem to have similar function for NV21
        libyuv::NV12ToRGB565Matrix(src_y,
                src_stride_y,
                src_u,
                src_stride_u,
                (uint8_t*)dst_ptr,
                dst.mStride,
                yuvConstants.yuv,
                src.cropWidth(),
                src.cropHeight());
        break;
    }
    case OMX_COLOR_Format32bitBGRA8888:
    {
        if (src_stride_u != src_stride_v) {
            return ERROR_UNSUPPORTED;
        }

        libyuvFunc = isNV21 ? libyuv:: NV21ToARGBMatrix : libyuv:: NV12ToARGBMatrix;

        libyuvFunc(src_y,
                src_stride_y,
                isNV21 ? src_v: src_u,
                // src_stride_v should be equal to src_stride_u
                // but this is done like this for readability
                isNV21 ? src_stride_v : src_stride_u,
                (uint8_t*)dst_ptr,
                dst.mStride,
                yuvConstants.yuv,
                src.cropWidth(),
                src.cropHeight());
        break;
    }

    case OMX_COLOR_Format32BitRGBA8888:
    {

        if (src_stride_u != src_stride_v) {
            return ERROR_UNSUPPORTED;
        }

        libyuvFunc = isNV21 ? libyuv::NV12ToARGBMatrix : libyuv::NV21ToARGBMatrix;

        libyuvFunc(src_y,
                src_stride_y,
                isNV21 ? src_v : src_u,
                // src_stride_v should be equal to src_stride_u
                isNV21 ? src_stride_v : src_stride_u,
                (uint8_t*)dst_ptr,
                dst.mStride,
                yuvConstants.yvu,
                src.cropWidth(),
                src.cropHeight());
        break;
    }

    default:
        return ERROR_UNSUPPORTED;
   }

   return OK;
}

std::function<void (void *, void *, void *, size_t,
        signed *, signed *, signed *, signed *)>
getReadFromChromaHorizSubsampled2Image8b(std::optional<MediaImage2> image,
        OMX_COLOR_FORMATTYPE srcFormat) {
    // this function is for reading src only
    // when both chromas are horizontally subsampled by 2
    // this returns 2 luma for one chroma.
    if (image) {
        uint32_t uColInc =
                image->mPlane[MediaImage2::PlaneIndex::U].mColInc;
        uint32_t vColInc =
                image->mPlane[MediaImage2::PlaneIndex::V].mColInc;
        uint32_t uHorizSubsampling =
                image->mPlane[MediaImage2::PlaneIndex::U].mHorizSubsampling;
         uint32_t vHorizSubsampling =
                image->mPlane[MediaImage2::PlaneIndex::V].mHorizSubsampling;

        if (!(uHorizSubsampling == 2 && vHorizSubsampling == 2)) {
            return nullptr;
        }

        if (image->mBitDepthAllocated == 8) {

            return [uColInc, vColInc, uHorizSubsampling, vHorizSubsampling]
                    (void *src_y, void *src_u, void *src_v, size_t x,
                    signed *y1, signed *y2, signed *u, signed *v) {
                *y1 = ((uint8_t *)src_y)[x];
                *y2 = ((uint8_t *)src_y)[x + 1];
                *u  = ((uint8_t *)src_u)[(x / uHorizSubsampling) * uColInc] - 128;
                *v  = ((uint8_t *)src_v)[(x / vHorizSubsampling) * vColInc] - 128;
            };
        }
    }
    if (srcFormat == OMX_COLOR_FormatYUV420Planar16) {
        // OMX_COLOR_FormatYUV420Planar16
        return [](void *src_y, void *src_u, void *src_v, size_t x,
                signed *y1, signed *y2, signed *u, signed *v) {
            *y1 = (uint8_t)(((uint16_t*)src_y)[x] >> 2);
            *y2 = (uint8_t)(((uint16_t*)src_y)[x + 1] >> 2);
            *u = (uint8_t)(((uint16_t*)src_u)[x / 2] >> 2) - 128;
            *v = (uint8_t)(((uint16_t*)src_v)[x / 2] >> 2) - 128;
        };
    }
    return nullptr;
}

std::function<void (void *, void *, void *, size_t,
        signed *, signed *, signed *)>
getReadFromImage(std::optional<MediaImage2> image, OMX_COLOR_FORMATTYPE &srcFormat) {
    (void)srcFormat;
    if (image) {
        uint32_t uColInc =
                image->mPlane[MediaImage2::PlaneIndex::U].mColInc;
        uint32_t vColInc =
                image->mPlane[MediaImage2::PlaneIndex::V].mColInc;
        uint32_t uHorizSubsampling =
                image->mPlane[MediaImage2::PlaneIndex::U].mHorizSubsampling;
         uint32_t vHorizSubsampling =
                image->mPlane[MediaImage2::PlaneIndex::V].mHorizSubsampling;

        if (image->mBitDepthAllocated == 8) {

            return [uColInc, vColInc, uHorizSubsampling, vHorizSubsampling]
                    (void *src_y, void *src_u, void *src_v, size_t x,
                    signed *y1, signed *u, signed *v) {
                *y1 = ((uint8_t *)src_y)[x];
                *u  = ((uint8_t *)src_u)[(x / uHorizSubsampling) * uColInc] - 128;
                *v  = ((uint8_t *)src_v)[(x / vHorizSubsampling) * vColInc] - 128;
            };
        }
    }
    return nullptr;
}

// TRICKY: this method only supports RGBA_1010102 output for 10-bit sources, and all other outputs
// for 8-bit sources as the type of kAdjustedClip is hardcoded based on output, not input.
std::function<void (void *, bool, signed, signed, signed, signed, signed, signed)>
getWriteToDst(OMX_COLOR_FORMATTYPE dstFormat, void *kAdjustedClip) {
    switch ((int)dstFormat) {
    case OMX_COLOR_Format16bitRGB565:
    {
        return [kAdjustedClip](void *dst_ptr, bool uncropped,
                               signed r1, signed g1, signed b1,
                               signed r2, signed g2, signed b2) {
            uint32_t rgb1 =
                ((((uint8_t *)kAdjustedClip)[r1] >> 3) << 11)
                | ((((uint8_t *)kAdjustedClip)[g1] >> 2) << 5)
                | (((uint8_t *)kAdjustedClip)[b1] >> 3);

            if (uncropped) {
                uint32_t rgb2 =
                    ((((uint8_t *)kAdjustedClip)[r2] >> 3) << 11)
                    | ((((uint8_t *)kAdjustedClip)[g2] >> 2) << 5)
                    | (((uint8_t *)kAdjustedClip)[b2] >> 3);

                *(uint32_t *)dst_ptr = (rgb2 << 16) | rgb1;
            } else {
                *(uint16_t *)dst_ptr = rgb1;
            }
        };
    }
    case OMX_COLOR_Format32BitRGBA8888:
    {
        return [kAdjustedClip](void *dst_ptr, bool uncropped,
                               signed r1, signed g1, signed b1,
                               signed r2, signed g2, signed b2) {
            ((uint32_t *)dst_ptr)[0] =
                    (((uint8_t *)kAdjustedClip)[r1])
                    | (((uint8_t *)kAdjustedClip)[g1] << 8)
                    | (((uint8_t *)kAdjustedClip)[b1] << 16)
                    | (0xFF << 24);

            if (uncropped) {
                ((uint32_t *)dst_ptr)[1] =
                        (((uint8_t *)kAdjustedClip)[r2])
                        | (((uint8_t *)kAdjustedClip)[g2] << 8)
                        | (((uint8_t *)kAdjustedClip)[b2] << 16)
                        | (0xFF << 24);
            }
        };
    }
    case OMX_COLOR_Format32bitBGRA8888:
    {
        return [kAdjustedClip](void *dst_ptr, bool uncropped,
                               signed r1, signed g1, signed b1,
                               signed r2, signed g2, signed b2) {
            ((uint32_t *)dst_ptr)[0] =
                    (((uint8_t *)kAdjustedClip)[b1])
                    | (((uint8_t *)kAdjustedClip)[g1] << 8)
                    | (((uint8_t *)kAdjustedClip)[r1] << 16)
                    | (0xFF << 24);

            if (uncropped) {
                ((uint32_t *)dst_ptr)[1] =
                        (((uint8_t *)kAdjustedClip)[b2])
                        | (((uint8_t *)kAdjustedClip)[g2] << 8)
                        | (((uint8_t *)kAdjustedClip)[r2] << 16)
                        | (0xFF << 24);
            }
        };
    }
    case COLOR_Format32bitABGR2101010:
    {
        return [kAdjustedClip](void *dst_ptr, bool uncropped,
                               signed r1, signed g1, signed b1,
                               signed r2, signed g2, signed b2) {
            ((uint32_t *)dst_ptr)[0] =
                    (((uint16_t *)kAdjustedClip)[r1])
                    | (((uint16_t *)kAdjustedClip)[g1] << 10)
                    | (((uint16_t *)kAdjustedClip)[b1] << 20)
                    | (3 << 30);

            if (uncropped) {
                ((uint32_t *)dst_ptr)[1] =
                        (((uint16_t *)kAdjustedClip)[r2])
                        | (((uint16_t *)kAdjustedClip)[g2] << 10)
                        | (((uint16_t *)kAdjustedClip)[b2] << 20)
                        | (3 << 30);
            }
        };
    }

    default:
        TRESPASS();
    }
    return nullptr;
}

status_t ColorConverter::convertYUVMediaImage(
        const BitmapParams &src, const BitmapParams &dst) {
    // first see if we can do this as a 420Planar or 420SemiPlanar 8b

    if(!mSrcImage ||
            mSrcImage->getMediaImage2().mType != MediaImage2::MEDIA_IMAGE_TYPE_YUV
            || mSrcImage->getMediaImage2().mNumPlanes != 3) {
        ALOGE("Cannot convert without MediaImage2 or MediaImage is not Valid YUV");
        return ERROR_UNSUPPORTED;
    }
    if (mSrcImage->getBitDepth() == ImageBitDepth8
            && mSrcImage->getSampling() == ImageSamplingYUV420) {
        Layout_t layout = mSrcImage->getLayout();
        switch (layout) {
            case Layout_t::ImageLayout420Planar:
            {
                return convertYUV420PlanarUseLibYUV(src, dst);
                break;
            }

            case Layout_t::ImageLayout420SemiPlanar:
            {
                // Note: libyuv doesn't support NV21 -> RGB565
                if (!(mSrcImage->isNV21() && mDstFormat == OMX_COLOR_Format16bitRGB565)) {
                    status_t ret = convertYUV420SemiPlanarUseLibYUV(src, dst);
                    // This function may fail if some specific conditions are not
                    // met for semiPlanar formats like strideU != strideV.
                    // if failed, this will fail before attempting conversion, so
                    // no additional memcpy will be involved here.
                    // Upon failure, this will fall into pixel based processing below.
                    if (ret == OK) {
                        return ret;
                    }
                }
                break;
            }
            default:
                // we will handle this case below.
                break;
        }
    }
    const struct Coeffs *matrix = getMatrix();
    if (!matrix) {
        return ERROR_UNSUPPORTED;
    }

    signed _b_u = matrix->_b_u;
    signed _neg_g_u = -matrix->_g_u;
    signed _neg_g_v = -matrix->_g_v;
    signed _r_v = matrix->_r_v;
    signed _y = matrix->_y;
    signed _c16 = matrix->_c16;

    uint8_t *dst_ptr = (uint8_t *)dst.mBits
            + dst.mCropTop * dst.mStride + dst.mCropLeft * dst.mBpp;


    uint32_t y_offset = 0, u_offset = 0, v_offset = 0;
    size_t src_stride_y =0, src_stride_u = 0, src_stride_v = 0;
    if (getSrcYUVPlaneOffsetAndStride(src, &y_offset, &u_offset, &v_offset,
            &src_stride_y, &src_stride_u, &src_stride_v) != OK) {
        return ERROR_UNSUPPORTED;
    }
    uint32_t uVertSubsampling =
            mSrcImage->getMediaImage2().mPlane[MediaImage2::PlaneIndex::U].mVertSubsampling;
    uint32_t vVertSubsampling =
            mSrcImage->getMediaImage2().mPlane[MediaImage2::PlaneIndex::V].mVertSubsampling;

    //TODO: optimize for chroma sampling, reading and writing multiple pixels
    //      within the same loop

    void *kAdjustedClip = nullptr;
    if (mSrcImage->getBitDepth() != ImageBitDepth8) {
        ALOGE("BitDepth != 8 for MediaImage2");
        return ERROR_UNSUPPORTED;
    }
    kAdjustedClip = initClip();

    auto writeToDst = getWriteToDst(mDstFormat, (void *)kAdjustedClip);
    uint8_t *src_y = (uint8_t *)src.mBits + y_offset;
    uint8_t *src_u = (uint8_t *)src.mBits + u_offset;
    uint8_t *src_v = (uint8_t *)src.mBits + v_offset;

    switch (mSrcImage->getSampling()) {

        case ImageSamplingYUV420:
        {
            // get read function that can read
            // chroma sampling 2 with image
            auto readFromSrcImage = getReadFromChromaHorizSubsampled2Image8b(
                    mSrcImage->getMediaImage2(), mSrcFormat);
            if (readFromSrcImage == nullptr) {
                ALOGE("Cannot get a read function for this MediaImage2");
                return ERROR_UNSUPPORTED;
            }
            for (size_t y = 0; y < src.cropHeight(); ++y) {
                for (size_t x = 0; x < src.cropWidth(); x += 2) {
                    signed y1, y2, u, v;
                    readFromSrcImage(src_y, src_u, src_v, x, &y1, &y2, &u, &v);

                    signed u_b = u * _b_u;
                    signed u_g = u * _neg_g_u;
                    signed v_g = v * _neg_g_v;
                    signed v_r = v * _r_v;

                    y1 = y1 - _c16;
                    signed tmp1 = y1 * _y + 128;
                    signed b1 = (tmp1 + u_b) / 256;
                    signed g1 = (tmp1 + v_g + u_g) / 256;
                    signed r1 = (tmp1 + v_r) / 256;

                    y2 = y2 - _c16;
                    signed tmp2 = y2 * _y + 128;
                    signed b2 = (tmp2 + u_b) / 256;
                    signed g2 = (tmp2 + v_g + u_g) / 256;
                    signed r2 = (tmp2 + v_r) / 256;

                    bool uncropped = x + 1 < src.cropWidth();
                    writeToDst(dst_ptr + x * dst.mBpp, uncropped, r1, g1, b1, r2, g2, b2);
                }
                src_y += src_stride_y;
                src_u += (((y + 1) % uVertSubsampling) == 0) ? src_stride_u : 0;
                src_v += (((y + 1) % vVertSubsampling) == 0) ? src_stride_v : 0;

                dst_ptr += dst.mStride;
            }
            break;
        }

        default:
        {
            // Interleaved or any other formats.
            auto readFromSrcImage = getReadFromImage(mSrcImage->getMediaImage2(), mSrcFormat);
            if (readFromSrcImage == nullptr) {
                ALOGE("Cannot get a read function for this MediaImage2");
                return ERROR_UNSUPPORTED;
            }
            for (size_t y = 0; y < src.cropHeight(); ++y) {
                for (size_t x = 0; x < src.cropWidth(); x += 1) {
                    signed y1, y2, u, v;
                    readFromSrcImage(src_y, src_u, src_v, x, &y1, &u, &v);

                    signed u_b = u * _b_u;
                    signed u_g = u * _neg_g_u;
                    signed v_g = v * _neg_g_v;
                    signed v_r = v * _r_v;

                    y1 = y1 - _c16;
                    signed tmp1 = y1 * _y + 128;
                    signed b1 = (tmp1 + u_b) / 256;
                    signed g1 = (tmp1 + v_g + u_g) / 256;
                    signed r1 = (tmp1 + v_r) / 256;

                    writeToDst(dst_ptr + x * dst.mBpp, false, r1, g1, b1, 0, 0, 0);
                }
                src_y += src_stride_y;
                src_u += (((y + 1) % uVertSubsampling) == 0) ? src_stride_u : 0;
                src_v += (((y + 1) % vVertSubsampling) == 0) ? src_stride_v : 0;

                dst_ptr += dst.mStride;
            }
        }
    }
    return OK;
}

status_t ColorConverter::convertYUV420Planar16(
        const BitmapParams &src, const BitmapParams &dst) {
    if (mDstFormat == OMX_COLOR_FormatYUV444Y410) {
        return convertYUV420Planar16ToY410(src, dst);
    }

    const struct Coeffs *matrix = getMatrix();
    if (!matrix) {
        return ERROR_UNSUPPORTED;
    }

    signed _b_u = matrix->_b_u;
    signed _neg_g_u = -matrix->_g_u;
    signed _neg_g_v = -matrix->_g_v;
    signed _r_v = matrix->_r_v;
    signed _y = matrix->_y;
    signed _c16 = matrix->_c16;

    uint8_t *kAdjustedClip = initClip();

    auto readFromSrc = getReadFromChromaHorizSubsampled2Image8b(std::nullopt, mSrcFormat);
    auto writeToDst = getWriteToDst(mDstFormat, (void *)kAdjustedClip);

    uint8_t *dst_ptr = (uint8_t *)dst.mBits
            + dst.mCropTop * dst.mStride + dst.mCropLeft * dst.mBpp;

    uint8_t *src_y = (uint8_t *)src.mBits
            + src.mCropTop * src.mStride + src.mCropLeft * src.mBpp;

    uint8_t *src_u = (uint8_t *)src.mBits + src.mStride * src.mHeight
            + (src.mCropTop / 2) * (src.mStride / 2) + src.mCropLeft / 2 * src.mBpp;

    uint8_t *src_v = src_u + (src.mStride / 2) * (src.mHeight / 2);

    for (size_t y = 0; y < src.cropHeight(); ++y) {
        for (size_t x = 0; x < src.cropWidth(); x += 2) {
            signed y1, y2, u, v;
            readFromSrc(src_y, src_u, src_v, x, &y1, &y2, &u, &v);

            signed u_b = u * _b_u;
            signed u_g = u * _neg_g_u;
            signed v_g = v * _neg_g_v;
            signed v_r = v * _r_v;

            signed tmp1 = (y1 - _c16) * _y + 128;
            signed b1 = (tmp1 + u_b) / 256;
            signed g1 = (tmp1 + v_g + u_g) / 256;
            signed r1 = (tmp1 + v_r) / 256;

            signed tmp2 = (y2 - _c16) * _y + 128;
            signed b2 = (tmp2 + u_b) / 256;
            signed g2 = (tmp2 + v_g + u_g) / 256;
            signed r2 = (tmp2 + v_r) / 256;

            bool uncropped = x + 1 < src.cropWidth();
            writeToDst(dst_ptr + x * dst.mBpp, uncropped, r1, g1, b1, r2, g2, b2);
        }

        src_y += src.mStride;

        if (y & 1) {
            src_u += src.mStride / 2;
            src_v += src.mStride / 2;
        }

        dst_ptr += dst.mStride;
    }
    return OK;
}

status_t ColorConverter::convertYUVP010(
        const BitmapParams &src, const BitmapParams &dst) {
    if (mDstFormat == COLOR_Format32bitABGR2101010) {
        return convertYUVP010ToRGBA1010102(src, dst);
    }

    return ERROR_UNSUPPORTED;
}

status_t ColorConverter::convertYUVP010ToRGBA1010102(
        const BitmapParams &src, const BitmapParams &dst) {
    const struct Coeffs *matrix = getMatrix();
    if (!matrix) {
        return ERROR_UNSUPPORTED;
    }

    signed _b_u = matrix->_b_u;
    signed _neg_g_u = -matrix->_g_u;
    signed _neg_g_v = -matrix->_g_v;
    signed _r_v = matrix->_r_v;
    signed _y = matrix->_y;
    signed _c64 = matrix->_c16 * 4;

    uint16_t *kAdjustedClip10bit = initClip10Bit();

//    auto readFromSrc = getReadFromSrc(mSrcFormat);
    auto writeToDst = getWriteToDst(mDstFormat, (void *)kAdjustedClip10bit);

    uint8_t *dst_ptr = (uint8_t *)dst.mBits
            + dst.mCropTop * dst.mStride + dst.mCropLeft * dst.mBpp;

    uint16_t *src_y = (uint16_t *)((uint8_t *)src.mBits
            + src.mCropTop * src.mStride + src.mCropLeft * src.mBpp);

    uint16_t *src_uv = (uint16_t *)((uint8_t *)src.mBits
            + src.mStride * src.mHeight
            + (src.mCropTop / 2) * src.mStride + src.mCropLeft * src.mBpp);

    for (size_t y = 0; y < src.cropHeight(); ++y) {
        for (size_t x = 0; x < src.cropWidth(); x += 2) {
            signed y1, y2, u, v;
            y1 = (src_y[x] >> 6) - _c64;
            y2 = (src_y[x + 1] >> 6) - _c64;
            u = int(src_uv[x] >> 6) - 512;
            v = int(src_uv[x + 1] >> 6) - 512;

            signed u_b = u * _b_u;
            signed u_g = u * _neg_g_u;
            signed v_g = v * _neg_g_v;
            signed v_r = v * _r_v;

            signed tmp1 = y1 * _y + 128;
            signed b1 = (tmp1 + u_b) / 256;
            signed g1 = (tmp1 + v_g + u_g) / 256;
            signed r1 = (tmp1 + v_r) / 256;

            signed tmp2 = y2 * _y + 128;
            signed b2 = (tmp2 + u_b) / 256;
            signed g2 = (tmp2 + v_g + u_g) / 256;
            signed r2 = (tmp2 + v_r) / 256;

            bool uncropped = x + 1 < src.cropWidth();

            writeToDst(dst_ptr + x * dst.mBpp, uncropped, r1, g1, b1, r2, g2, b2);
        }

        src_y += src.mStride / 2;

        if (y & 1) {
            src_uv += src.mStride / 2;
        }

        dst_ptr += dst.mStride;
    }

    return OK;
}


#if !USE_NEON_Y410

status_t ColorConverter::convertYUV420Planar16ToY410(
        const BitmapParams &src, const BitmapParams &dst) {
    uint8_t *dst_ptr = (uint8_t *)dst.mBits
        + dst.mCropTop * dst.mStride + dst.mCropLeft * dst.mBpp;

    const uint8_t *src_y =
        (const uint8_t *)src.mBits + src.mCropTop * src.mStride + src.mCropLeft * src.mBpp;

    const uint8_t *src_u =
        (const uint8_t *)src.mBits + src.mStride * src.mHeight
        + (src.mCropTop / 2) * (src.mStride / 2) + (src.mCropLeft / 2) * src.mBpp;

    const uint8_t *src_v =
        src_u + (src.mStride / 2) * (src.mHeight / 2);

    // Converting two lines at a time, slightly faster
    for (size_t y = 0; y < src.cropHeight(); y += 2) {
        uint32_t *dst_top = (uint32_t *) dst_ptr;
        uint32_t *dst_bot = (uint32_t *) (dst_ptr + dst.mStride);
        uint16_t *ptr_ytop = (uint16_t*) src_y;
        uint16_t *ptr_ybot = (uint16_t*) (src_y + src.mStride);
        uint16_t *ptr_u = (uint16_t*) src_u;
        uint16_t *ptr_v = (uint16_t*) src_v;

        uint32_t u01, v01, y01, y23, y45, y67, uv0, uv1;
        size_t x = 0;
        for (; x < src.cropWidth() - 3; x += 4) {
            u01 = *((uint32_t*)ptr_u); ptr_u += 2;
            v01 = *((uint32_t*)ptr_v); ptr_v += 2;

            y01 = *((uint32_t*)ptr_ytop); ptr_ytop += 2;
            y23 = *((uint32_t*)ptr_ytop); ptr_ytop += 2;
            y45 = *((uint32_t*)ptr_ybot); ptr_ybot += 2;
            y67 = *((uint32_t*)ptr_ybot); ptr_ybot += 2;

            uv0 = (u01 & 0x3FF) | ((v01 & 0x3FF) << 20);
            uv1 = (u01 >> 16) | ((v01 >> 16) << 20);

            *dst_top++ = ((y01 & 0x3FF) << 10) | uv0;
            *dst_top++ = ((y01 >> 16) << 10) | uv0;
            *dst_top++ = ((y23 & 0x3FF) << 10) | uv1;
            *dst_top++ = ((y23 >> 16) << 10) | uv1;

            *dst_bot++ = ((y45 & 0x3FF) << 10) | uv0;
            *dst_bot++ = ((y45 >> 16) << 10) | uv0;
            *dst_bot++ = ((y67 & 0x3FF) << 10) | uv1;
            *dst_bot++ = ((y67 >> 16) << 10) | uv1;
        }

        // There should be at most 2 more pixels to process. Note that we don't
        // need to consider odd case as the buffer is always aligned to even.
        if (x < src.cropWidth()) {
            u01 = *ptr_u;
            v01 = *ptr_v;
            y01 = *((uint32_t*)ptr_ytop);
            y45 = *((uint32_t*)ptr_ybot);
            uv0 = (u01 & 0x3FF) | ((v01 & 0x3FF) << 20);
            *dst_top++ = ((y01 & 0x3FF) << 10) | uv0;
            *dst_top++ = ((y01 >> 16) << 10) | uv0;
            *dst_bot++ = ((y45 & 0x3FF) << 10) | uv0;
            *dst_bot++ = ((y45 >> 16) << 10) | uv0;
        }

        src_y += src.mStride * 2;
        src_u += src.mStride / 2;
        src_v += src.mStride / 2;
        dst_ptr += dst.mStride * 2;
    }

    return OK;
}

#else

status_t ColorConverter::convertYUV420Planar16ToY410(
        const BitmapParams &src, const BitmapParams &dst) {
    uint8_t *out = (uint8_t *)dst.mBits
        + dst.mCropTop * dst.mStride + dst.mCropLeft * dst.mBpp;

    const uint8_t *src_y =
        (const uint8_t *)src.mBits + src.mCropTop * src.mStride + src.mCropLeft * src.mBpp;

    const uint8_t *src_u =
        (const uint8_t *)src.mBits + src.mStride * src.mHeight
        + (src.mCropTop / 2) * (src.mStride / 2) + (src.mCropLeft / 2) * src.mBpp;

    const uint8_t *src_v =
        src_u + (src.mStride / 2) * (src.mHeight / 2);

    for (size_t y = 0; y < src.cropHeight(); y++) {
        uint16_t *ptr_y = (uint16_t*) src_y;
        uint16_t *ptr_u = (uint16_t*) src_u;
        uint16_t *ptr_v = (uint16_t*) src_v;
        uint32_t *ptr_out = (uint32_t *) out;

        // Process 16-pixel at a time.
        uint32_t *ptr_limit = ptr_out + (src.cropWidth() & ~15);
        while (ptr_out < ptr_limit) {
            uint16x4_t u0123 = vld1_u16(ptr_u); ptr_u += 4;
            uint16x4_t u4567 = vld1_u16(ptr_u); ptr_u += 4;
            uint16x4_t v0123 = vld1_u16(ptr_v); ptr_v += 4;
            uint16x4_t v4567 = vld1_u16(ptr_v); ptr_v += 4;
            uint16x4_t y0123 = vld1_u16(ptr_y); ptr_y += 4;
            uint16x4_t y4567 = vld1_u16(ptr_y); ptr_y += 4;
            uint16x4_t y89ab = vld1_u16(ptr_y); ptr_y += 4;
            uint16x4_t ycdef = vld1_u16(ptr_y); ptr_y += 4;

            uint32x2_t uvtempl;
            uint32x4_t uvtempq;

            uvtempq = vaddw_u16(vshll_n_u16(v0123, 20), u0123);

            uvtempl = vget_low_u32(uvtempq);
            uint32x4_t uv0011 = vreinterpretq_u32_u64(
                    vaddw_u32(vshll_n_u32(uvtempl, 32), uvtempl));

            uvtempl = vget_high_u32(uvtempq);
            uint32x4_t uv2233 = vreinterpretq_u32_u64(
                    vaddw_u32(vshll_n_u32(uvtempl, 32), uvtempl));

            uvtempq = vaddw_u16(vshll_n_u16(v4567, 20), u4567);

            uvtempl = vget_low_u32(uvtempq);
            uint32x4_t uv4455 = vreinterpretq_u32_u64(
                    vaddw_u32(vshll_n_u32(uvtempl, 32), uvtempl));

            uvtempl = vget_high_u32(uvtempq);
            uint32x4_t uv6677 = vreinterpretq_u32_u64(
                    vaddw_u32(vshll_n_u32(uvtempl, 32), uvtempl));

            uint32x4_t dsttemp;

            dsttemp = vorrq_u32(uv0011, vshll_n_u16(y0123, 10));
            vst1q_u32(ptr_out, dsttemp); ptr_out += 4;

            dsttemp = vorrq_u32(uv2233, vshll_n_u16(y4567, 10));
            vst1q_u32(ptr_out, dsttemp); ptr_out += 4;

            dsttemp = vorrq_u32(uv4455, vshll_n_u16(y89ab, 10));
            vst1q_u32(ptr_out, dsttemp); ptr_out += 4;

            dsttemp = vorrq_u32(uv6677, vshll_n_u16(ycdef, 10));
            vst1q_u32(ptr_out, dsttemp); ptr_out += 4;
        }

        src_y += src.mStride;
        if (y & 1) {
            src_u += src.mStride / 2;
            src_v += src.mStride / 2;
        }
        out += dst.mStride;
    }

    // Process the left-overs out-of-loop, 2-pixel at a time. Note that we don't
    // need to consider odd case as the buffer is always aligned to even.
    if (src.cropWidth() & 15) {
        size_t xstart = (src.cropWidth() & ~15);

        uint8_t *out = (uint8_t *)dst.mBits + dst.mCropTop * dst.mStride
                + (dst.mCropLeft + xstart) * dst.mBpp;

        const uint8_t *src_y = (const uint8_t *)src.mBits + src.mCropTop * src.mStride
                + (src.mCropLeft + xstart) * src.mBpp;

        const uint8_t *src_u = (const uint8_t *)src.mBits + src.mStride * src.mHeight
            + (src.mCropTop / 2) * (src.mStride / 2)
            + ((src.mCropLeft + xstart) / 2) * src.mBpp;

        const uint8_t *src_v = src_u + (src.mStride / 2) * (src.mHeight / 2);

        for (size_t y = 0; y < src.cropHeight(); y++) {
            uint16_t *ptr_y = (uint16_t*) src_y;
            uint16_t *ptr_u = (uint16_t*) src_u;
            uint16_t *ptr_v = (uint16_t*) src_v;
            uint32_t *ptr_out = (uint32_t *) out;
            for (size_t x = xstart; x < src.cropWidth(); x += 2) {
                uint16_t u = *ptr_u++;
                uint16_t v = *ptr_v++;
                uint32_t y01 = *((uint32_t*)ptr_y); ptr_y += 2;
                uint32_t uv = u | (((uint32_t)v) << 20);
                *ptr_out++ = ((y01 & 0x3FF) << 10) | uv;
                *ptr_out++ = ((y01 >> 16) << 10) | uv;
            }
            src_y += src.mStride;
            if (y & 1) {
                src_u += src.mStride / 2;
                src_v += src.mStride / 2;
            }
            out += dst.mStride;
        }
    }

    return OK;
}

#endif // USE_NEON_Y410

uint8_t *ColorConverter::initClip() {
    if (mClip == NULL) {
        mClip = new uint8_t[CLIP_RANGE_MAX_8BIT - CLIP_RANGE_MIN_8BIT + 1];

        for (signed i = CLIP_RANGE_MIN_8BIT; i <= CLIP_RANGE_MAX_8BIT; ++i) {
            mClip[i - CLIP_RANGE_MIN_8BIT] = (i < 0) ? 0 : (i > 255) ? 255 : (uint8_t)i;
        }
    }

    return &mClip[-CLIP_RANGE_MIN_8BIT];
}

uint16_t *ColorConverter::initClip10Bit() {
    if (mClip10Bit == NULL) {
        mClip10Bit = new uint16_t[CLIP_RANGE_MAX_10BIT - CLIP_RANGE_MIN_10BIT + 1];

        for (signed i = CLIP_RANGE_MIN_10BIT; i <= CLIP_RANGE_MAX_10BIT; ++i) {
            mClip10Bit[i - CLIP_RANGE_MIN_10BIT] = (i < 0) ? 0 : (i > 1023) ? 1023 : (uint16_t)i;
        }
    }

    return &mClip10Bit[-CLIP_RANGE_MIN_10BIT];
}

}  // namespace android
