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

#ifndef COLOR_CONVERTER_H_

#define COLOR_CONVERTER_H_

#include <sys/types.h>

#include <stdint.h>
#include <utils/Errors.h>

#include <optional>

#include <OMX_Video.h>
#include <media/hardware/VideoAPI.h>

namespace android {

struct ColorConverter {
    ColorConverter(OMX_COLOR_FORMATTYPE from, OMX_COLOR_FORMATTYPE to);
    ~ColorConverter();

    bool isValid() const;

    bool isDstRGB() const;

    void setSrcMediaImage2(MediaImage2 img);

    void setSrcColorSpace(uint32_t standard, uint32_t range, uint32_t transfer);

    status_t convert(
            const void *srcBits,
            size_t srcWidth, size_t srcHeight, size_t srcStride,
            size_t srcCropLeft, size_t srcCropTop,
            size_t srcCropRight, size_t srcCropBottom,
            void *dstBits,
            size_t dstWidth, size_t dstHeight, size_t dstStride,
            size_t dstCropLeft, size_t dstCropTop,
            size_t dstCropRight, size_t dstCropBottom);

    struct Coeffs; // matrix coefficients

    struct ColorSpace {
        uint32_t mStandard;
        uint32_t mRange;
        uint32_t mTransfer;

        bool isLimitedRange() const;
        // libyuv helper methods
        //   BT.2020 limited Range
        bool isBt2020() const;
        // BT.2020 full range
        bool isBtV2020() const;
        // 709 limited range
        bool isH709() const;
        // 709 full range
        bool isF709() const;
        // 601 limited range
        bool isI601() const;
        // 601 full range
        // also called "JPEG" in libyuv
        bool isJ601() const;
    };

private:

    typedef enum : uint8_t {
        ImageLayoutUnknown = 0x0,
        ImageLayout420SemiPlanar = 0x1,
        ImageLayout420Planar = 0x2
    } Layout_t;

    typedef enum : uint8_t {
        ImageSamplingUnknown = 0x0,
        ImageSamplingYUV420 = 0x1,
    } Sampling_t;

    //this is the actual usable bit
    typedef enum : uint8_t {
        ImageBitDepthInvalid = 0x0,
        ImageBitDepth8 = 0x1,
        ImageBitDepth10 = 0x2,
        ImageBitDepth12 = 0x3,
        ImageBitDepth16 = 0x4
    } BitDepth_t;

    struct BitmapParams;


    class Image {
    public:
        Image(const MediaImage2& img);
        virtual ~Image() {}

        const MediaImage2 getMediaImage2() const {
            return mImage;
        }

        Layout_t getLayout() const {
            return mLayout;
        }
        Sampling_t getSampling() const {
            return mSampling;
        }
        BitDepth_t getBitDepth() const {
            return mBitDepth;
        }

        // Returns the plane offset for this image
        // after accounting for the src Crop offsets
        status_t getYUVPlaneOffsetAndStride(
                const BitmapParams &src,
                uint32_t *y_offset,
                uint32_t *u_offset,
                uint32_t *v_offset,
                size_t *y_stride,
                size_t *u_stride,
                size_t *v_stride
                ) const;

        bool isNV21() const;

    private:
        MediaImage2 mImage;
        Layout_t mLayout;
        Sampling_t mSampling;
        BitDepth_t mBitDepth;
    };

    struct BitmapParams {
        BitmapParams(
                void *bits,
                size_t width, size_t height, size_t stride,
                size_t cropLeft, size_t cropTop,
                size_t cropRight, size_t cropBottom,
                OMX_COLOR_FORMATTYPE colorFromat);

        size_t cropWidth() const;
        size_t cropHeight() const;

        bool isValid() const;

        void *mBits;
        OMX_COLOR_FORMATTYPE mColorFormat;
        size_t mWidth, mHeight;
        size_t mCropLeft, mCropTop, mCropRight, mCropBottom;
        size_t mBpp, mStride;
    };

    OMX_COLOR_FORMATTYPE mSrcFormat, mDstFormat;
    std::optional<Image> mSrcImage;
    ColorSpace mSrcColorSpace;
    uint8_t *mClip;
    uint16_t *mClip10Bit;

    uint8_t *initClip();
    uint16_t *initClip10Bit();

    // resolve YUVFormat from YUV420Flexible
    bool isValidForMediaImage2() const;

    // get plane offsets from Formats
    status_t getSrcYUVPlaneOffsetAndStride(
            const BitmapParams &src,
            uint32_t *y_offset,
            uint32_t *u_offset,
            uint32_t *v_offset,
            size_t *y_stride,
            size_t *u_stride,
            size_t *v_stride) const;

    status_t convertYUVMediaImage(
        const BitmapParams &src, const BitmapParams &dst);

    // returns the YUV2RGB matrix coefficients according to the color aspects and bit depth
    const struct Coeffs *getMatrix() const;

    status_t convertCbYCrY(
            const BitmapParams &src, const BitmapParams &dst);

    // status_t convertYUV420Planar(
    //        const BitmapParams &src, const BitmapParams &dst);

    status_t convertYUV420PlanarUseLibYUV(
            const BitmapParams &src, const BitmapParams &dst);

    status_t convertYUV420SemiPlanarUseLibYUV(
            const BitmapParams &src, const BitmapParams &dst);

    status_t convertYUV420Planar16(
            const BitmapParams &src, const BitmapParams &dst);

    status_t convertYUV420Planar16ToY410(
            const BitmapParams &src, const BitmapParams &dst);

    status_t convertYUV420Planar16ToRGB(
            const BitmapParams &src, const BitmapParams &dst);

    status_t convertYUVP010(
                const BitmapParams &src, const BitmapParams &dst);

    status_t convertYUVP010ToRGBA1010102(
                const BitmapParams &src, const BitmapParams &dst);

    ColorConverter(const ColorConverter &);

    ColorConverter &operator=(const ColorConverter &);
};

}  // namespace android

#endif  // COLOR_CONVERTER_H_
