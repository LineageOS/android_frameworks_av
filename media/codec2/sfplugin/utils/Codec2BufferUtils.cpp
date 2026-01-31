/*
 * Copyright 2018, The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "Codec2BufferUtils"
#define ATRACE_TAG  ATRACE_TAG_VIDEO
#include <utils/Log.h>
#include <utils/Trace.h>

#include <libyuv.h>

#include <list>
#include <mutex>

#include <android/hardware_buffer.h>
#include <media/hardware/HardwareAPI.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/AUtils.h>
#include <media/stagefright/MediaCodecConstants.h>

#include <C2Debug.h>

#include "Codec2BufferUtils.h"

namespace android {

namespace {

/**
 * A flippable, optimizable memcpy. Constructs such as (from ? src : dst)
 * do not work as the results are always const.
 */
template<bool ToA, size_t S>
struct MemCopier {
    template<typename A, typename B>
    inline static void copy(A *a, const B *b, size_t size) {
        __builtin_memcpy(a, b, size);
    }
};

template<size_t S>
struct MemCopier<false, S> {
    template<typename A, typename B>
    inline static void copy(const A *a, B *b, size_t size) {
        MemCopier<true, S>::copy(b, a, size);
    }
};

/**
 * Copies between a MediaImage and a graphic view.
 *
 * \param ToMediaImage whether to copy to (or from) the MediaImage
 * \param view graphic view (could be ConstGraphicView or GraphicView depending on direction)
 * \param img MediaImage data
 * \param imgBase base of MediaImage (could be const uint8_t* or uint8_t* depending on direction)
 */
template<bool ToMediaImage, typename View, typename ImagePixel>
static status_t _ImageCopy(View &view, const MediaImage2 *img, ImagePixel *imgBase) {
    // TODO: more efficient copying --- e.g. copy interleaved planes together, etc.
    const C2PlanarLayout &layout = view.layout();
    const size_t bpp = divUp(img->mBitDepthAllocated, 8u);

    for (uint32_t i = 0; i < layout.numPlanes; ++i) {
        typename std::conditional<ToMediaImage, uint8_t, const uint8_t>::type *imgRow =
            imgBase + img->mPlane[i].mOffset;
        typename std::conditional<ToMediaImage, const uint8_t, uint8_t>::type *viewRow =
            viewRow = view.data()[i];
        const C2PlaneInfo &plane = layout.planes[i];
        if (plane.colSampling != img->mPlane[i].mHorizSubsampling
                || plane.rowSampling != img->mPlane[i].mVertSubsampling
                || plane.allocatedDepth != img->mBitDepthAllocated
                || plane.allocatedDepth < plane.bitDepth
                // MediaImage only supports MSB values
                || plane.rightShift != plane.allocatedDepth - plane.bitDepth
                || (bpp > 1 && plane.endianness != plane.NATIVE)) {
            return BAD_VALUE;
        }

        uint32_t planeW = img->mWidth / plane.colSampling;
        uint32_t planeH = img->mHeight / plane.rowSampling;

        bool canCopyByRow = (plane.colInc == bpp) && (img->mPlane[i].mColInc == bpp);
        bool canCopyByPlane = canCopyByRow && (plane.rowInc == img->mPlane[i].mRowInc);
        if (canCopyByPlane) {
            MemCopier<ToMediaImage, 0>::copy(imgRow, viewRow, plane.rowInc * planeH);
        } else if (canCopyByRow) {
            for (uint32_t row = 0; row < planeH; ++row) {
                MemCopier<ToMediaImage, 0>::copy(
                        imgRow, viewRow, std::min(plane.rowInc, img->mPlane[i].mRowInc));
                imgRow += img->mPlane[i].mRowInc;
                viewRow += plane.rowInc;
            }
        } else {
            for (uint32_t row = 0; row < planeH; ++row) {
                decltype(imgRow) imgPtr = imgRow;
                decltype(viewRow) viewPtr = viewRow;
                for (uint32_t col = 0; col < planeW; ++col) {
                    MemCopier<ToMediaImage, 0>::copy(imgPtr, viewPtr, bpp);
                    imgPtr += img->mPlane[i].mColInc;
                    viewPtr += plane.colInc;
                }
                imgRow += img->mPlane[i].mRowInc;
                viewRow += plane.rowInc;
            }
        }
    }
    return OK;
}

}  // namespace

status_t ImageCopy(uint8_t *imgBase, const MediaImage2 *img, const C2GraphicView &view) {
    if (img == nullptr
        || imgBase == nullptr
        || view.crop().width != img->mWidth
        || view.crop().height != img->mHeight) {
        return BAD_VALUE;
    }
    const uint8_t* src_y = view.data()[0];
    const uint8_t* src_u = view.data()[1];
    const uint8_t* src_v = view.data()[2];
    int32_t src_stride_y = view.layout().planes[0].rowInc;
    int32_t src_stride_u = view.layout().planes[1].rowInc;
    int32_t src_stride_v = view.layout().planes[2].rowInc;
    uint8_t* dst_y = imgBase + img->mPlane[0].mOffset;
    uint8_t* dst_u = imgBase + img->mPlane[1].mOffset;
    uint8_t* dst_v = imgBase + img->mPlane[2].mOffset;
    int32_t dst_stride_y = img->mPlane[0].mRowInc;
    int32_t dst_stride_u = img->mPlane[1].mRowInc;
    int32_t dst_stride_v = img->mPlane[2].mRowInc;
    int width = view.crop().width;
    int height = view.crop().height;

    if (IsNV12(view)) {
        if (IsNV12(img)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: NV12->NV12");
            libyuv::CopyPlane(src_y, src_stride_y, dst_y, dst_stride_y, width, height);
            libyuv::CopyPlane(src_u, src_stride_u, dst_u, dst_stride_u, width, height / 2);
            return OK;
        } else if (IsNV21(img)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: NV12->NV21");
            if (!libyuv::NV21ToNV12(src_y, src_stride_y, src_u, src_stride_u,
                                    dst_y, dst_stride_y, dst_v, dst_stride_v, width, height)) {
                return OK;
            }
        } else if (IsI420(img)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: NV12->I420");
            if (!libyuv::NV12ToI420(src_y, src_stride_y, src_u, src_stride_u, dst_y, dst_stride_y,
                                    dst_u, dst_stride_u, dst_v, dst_stride_v, width, height)) {
                return OK;
            }
        }
    } else if (IsNV21(view)) {
        if (IsNV12(img)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: NV21->NV12");
            if (!libyuv::NV21ToNV12(src_y, src_stride_y, src_v, src_stride_v,
                                    dst_y, dst_stride_y, dst_u, dst_stride_u, width, height)) {
                return OK;
            }
        } else if (IsNV21(img)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: NV21->NV21");
            libyuv::CopyPlane(src_y, src_stride_y, dst_y, dst_stride_y, width, height);
            libyuv::CopyPlane(src_v, src_stride_v, dst_v, dst_stride_v, width, height / 2);
            return OK;
        } else if (IsI420(img)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: NV21->I420");
            if (!libyuv::NV21ToI420(src_y, src_stride_y, src_v, src_stride_v, dst_y, dst_stride_y,
                                    dst_u, dst_stride_u, dst_v, dst_stride_v, width, height)) {
                return OK;
            }
        }
    } else if (IsI420(view)) {
        if (IsNV12(img)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: I420->NV12");
            if (!libyuv::I420ToNV12(src_y, src_stride_y, src_u, src_stride_u, src_v, src_stride_v,
                                    dst_y, dst_stride_y, dst_u, dst_stride_u, width, height)) {
                return OK;
            }
        } else if (IsNV21(img)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: I420->NV21");
            if (!libyuv::I420ToNV21(src_y, src_stride_y, src_u, src_stride_u, src_v, src_stride_v,
                                    dst_y, dst_stride_y, dst_v, dst_stride_v, width, height)) {
                return OK;
            }
        } else if (IsI420(img)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: I420->I420");
            libyuv::CopyPlane(src_y, src_stride_y, dst_y, dst_stride_y, width, height);
            libyuv::CopyPlane(src_u, src_stride_u, dst_u, dst_stride_u, width / 2, height / 2);
            libyuv::CopyPlane(src_v, src_stride_v, dst_v, dst_stride_v, width / 2, height / 2);
            return OK;
        }
    }
    ScopedTrace trace(ATRACE_TAG, "ImageCopy: generic");
    return _ImageCopy<true>(view, img, imgBase);
}

status_t ImageCopy(C2GraphicView &view, const uint8_t *imgBase, const MediaImage2 *img) {
    if (img == nullptr
        || imgBase == nullptr
        || view.crop().width != img->mWidth
        || view.crop().height != img->mHeight) {
        return BAD_VALUE;
    }
    const uint8_t* src_y = imgBase + img->mPlane[0].mOffset;
    const uint8_t* src_u = imgBase + img->mPlane[1].mOffset;
    const uint8_t* src_v = imgBase + img->mPlane[2].mOffset;
    int32_t src_stride_y = img->mPlane[0].mRowInc;
    int32_t src_stride_u = img->mPlane[1].mRowInc;
    int32_t src_stride_v = img->mPlane[2].mRowInc;
    uint8_t* dst_y = view.data()[0];
    uint8_t* dst_u = view.data()[1];
    uint8_t* dst_v = view.data()[2];
    int32_t dst_stride_y = view.layout().planes[0].rowInc;
    int32_t dst_stride_u = view.layout().planes[1].rowInc;
    int32_t dst_stride_v = view.layout().planes[2].rowInc;
    int width = view.crop().width;
    int height = view.crop().height;
    if (IsNV12(img)) {
        if (IsNV12(view)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: NV12->NV12");
            libyuv::CopyPlane(src_y, src_stride_y, dst_y, dst_stride_y, width, height);
            libyuv::CopyPlane(src_u, src_stride_u, dst_u, dst_stride_u, width, height / 2);
            return OK;
        } else if (IsNV21(view)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: NV12->NV21");
            if (!libyuv::NV21ToNV12(src_y, src_stride_y, src_u, src_stride_u,
                                    dst_y, dst_stride_y, dst_v, dst_stride_v, width, height)) {
                return OK;
            }
        } else if (IsI420(view)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: NV12->I420");
            if (!libyuv::NV12ToI420(src_y, src_stride_y, src_u, src_stride_u, dst_y, dst_stride_y,
                                    dst_u, dst_stride_u, dst_v, dst_stride_v, width, height)) {
                return OK;
            }
        }
    } else if (IsNV21(img)) {
        if (IsNV12(view)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: NV21->NV12");
            if (!libyuv::NV21ToNV12(src_y, src_stride_y, src_v, src_stride_v,
                                    dst_y, dst_stride_y, dst_u, dst_stride_u, width, height)) {
                return OK;
            }
        } else if (IsNV21(view)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: NV21->NV21");
            libyuv::CopyPlane(src_y, src_stride_y, dst_y, dst_stride_y, width, height);
            libyuv::CopyPlane(src_v, src_stride_v, dst_v, dst_stride_v, width, height / 2);
            return OK;
        } else if (IsI420(view)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: NV21->I420");
            if (!libyuv::NV21ToI420(src_y, src_stride_y, src_v, src_stride_v, dst_y, dst_stride_y,
                                    dst_u, dst_stride_u, dst_v, dst_stride_v, width, height)) {
                return OK;
            }
        }
    } else if (IsI420(img)) {
        if (IsNV12(view)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: I420->NV12");
            if (!libyuv::I420ToNV12(src_y, src_stride_y, src_u, src_stride_u, src_v, src_stride_v,
                                    dst_y, dst_stride_y, dst_u, dst_stride_u, width, height)) {
                return OK;
            }
        } else if (IsNV21(view)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: I420->NV21");
            if (!libyuv::I420ToNV21(src_y, src_stride_y, src_u, src_stride_u, src_v, src_stride_v,
                                    dst_y, dst_stride_y, dst_v, dst_stride_v, width, height)) {
                return OK;
            }
        } else if (IsI420(view)) {
            ScopedTrace trace(ATRACE_TAG, "ImageCopy: I420->I420");
            libyuv::CopyPlane(src_y, src_stride_y, dst_y, dst_stride_y, width, height);
            libyuv::CopyPlane(src_u, src_stride_u, dst_u, dst_stride_u, width / 2, height / 2);
            libyuv::CopyPlane(src_v, src_stride_v, dst_v, dst_stride_v, width / 2, height / 2);
            return OK;
        }
    }
    ScopedTrace trace(ATRACE_TAG, "ImageCopy: generic");
    return _ImageCopy<false>(view, img, imgBase);
}

bool IsYUV420(const C2GraphicView &view) {
    const C2PlanarLayout &layout = view.layout();
    return (layout.numPlanes == 3
            && layout.type == C2PlanarLayout::TYPE_YUV
            && layout.planes[layout.PLANE_Y].channel == C2PlaneInfo::CHANNEL_Y
            && layout.planes[layout.PLANE_Y].allocatedDepth == 8
            && layout.planes[layout.PLANE_Y].bitDepth == 8
            && layout.planes[layout.PLANE_Y].rightShift == 0
            && layout.planes[layout.PLANE_Y].colSampling == 1
            && layout.planes[layout.PLANE_Y].rowSampling == 1
            && layout.planes[layout.PLANE_U].channel == C2PlaneInfo::CHANNEL_CB
            && layout.planes[layout.PLANE_U].allocatedDepth == 8
            && layout.planes[layout.PLANE_U].bitDepth == 8
            && layout.planes[layout.PLANE_U].rightShift == 0
            && layout.planes[layout.PLANE_U].colSampling == 2
            && layout.planes[layout.PLANE_U].rowSampling == 2
            && layout.planes[layout.PLANE_V].channel == C2PlaneInfo::CHANNEL_CR
            && layout.planes[layout.PLANE_V].allocatedDepth == 8
            && layout.planes[layout.PLANE_V].bitDepth == 8
            && layout.planes[layout.PLANE_V].rightShift == 0
            && layout.planes[layout.PLANE_V].colSampling == 2
            && layout.planes[layout.PLANE_V].rowSampling == 2);
}

bool IsYUV420_10bit(const C2GraphicView &view) {
    const C2PlanarLayout &layout = view.layout();
    return (layout.numPlanes == 3
            && layout.type == C2PlanarLayout::TYPE_YUV
            && layout.planes[layout.PLANE_Y].channel == C2PlaneInfo::CHANNEL_Y
            && layout.planes[layout.PLANE_Y].allocatedDepth == 16
            && layout.planes[layout.PLANE_Y].bitDepth == 10
            && layout.planes[layout.PLANE_Y].colSampling == 1
            && layout.planes[layout.PLANE_Y].rowSampling == 1
            && layout.planes[layout.PLANE_U].channel == C2PlaneInfo::CHANNEL_CB
            && layout.planes[layout.PLANE_U].allocatedDepth == 16
            && layout.planes[layout.PLANE_U].bitDepth == 10
            && layout.planes[layout.PLANE_U].colSampling == 2
            && layout.planes[layout.PLANE_U].rowSampling == 2
            && layout.planes[layout.PLANE_V].channel == C2PlaneInfo::CHANNEL_CR
            && layout.planes[layout.PLANE_V].allocatedDepth == 16
            && layout.planes[layout.PLANE_V].bitDepth == 10
            && layout.planes[layout.PLANE_V].colSampling == 2
            && layout.planes[layout.PLANE_V].rowSampling == 2);
}

bool IsYUV422_10bit(const C2GraphicView &view) {
    const C2PlanarLayout &layout = view.layout();
    return (layout.numPlanes == 3
            && layout.type == C2PlanarLayout::TYPE_YUV
            && layout.planes[layout.PLANE_Y].channel == C2PlaneInfo::CHANNEL_Y
            && layout.planes[layout.PLANE_Y].allocatedDepth == 16
            && layout.planes[layout.PLANE_Y].bitDepth == 10
            && layout.planes[layout.PLANE_Y].colSampling == 1
            && layout.planes[layout.PLANE_Y].rowSampling == 1
            && layout.planes[layout.PLANE_U].channel == C2PlaneInfo::CHANNEL_CB
            && layout.planes[layout.PLANE_U].allocatedDepth == 16
            && layout.planes[layout.PLANE_U].bitDepth == 10
            && layout.planes[layout.PLANE_U].colSampling == 2
            && layout.planes[layout.PLANE_U].rowSampling == 1
            && layout.planes[layout.PLANE_V].channel == C2PlaneInfo::CHANNEL_CR
            && layout.planes[layout.PLANE_V].allocatedDepth == 16
            && layout.planes[layout.PLANE_V].bitDepth == 10
            && layout.planes[layout.PLANE_V].colSampling == 2
            && layout.planes[layout.PLANE_V].rowSampling == 1);
}


bool IsNV12(const C2GraphicView &view) {
    if (!IsYUV420(view)) {
        return false;
    }
    const C2PlanarLayout &layout = view.layout();
    return (layout.rootPlanes == 2
            && layout.planes[layout.PLANE_U].colInc == 2
            && layout.planes[layout.PLANE_U].rootIx == layout.PLANE_U
            && layout.planes[layout.PLANE_U].offset == 0
            && layout.planes[layout.PLANE_V].colInc == 2
            && layout.planes[layout.PLANE_V].rootIx == layout.PLANE_U
            && layout.planes[layout.PLANE_V].offset == 1);
}

bool IsP010(const C2GraphicView &view) {
    if (!IsYUV420_10bit(view)) {
        return false;
    }
    const C2PlanarLayout &layout = view.layout();
    return (layout.rootPlanes == 2
            && layout.planes[layout.PLANE_U].colInc == 4
            && layout.planes[layout.PLANE_U].rootIx == layout.PLANE_U
            && layout.planes[layout.PLANE_U].offset == 0
            && layout.planes[layout.PLANE_V].colInc == 4
            && layout.planes[layout.PLANE_V].rootIx == layout.PLANE_U
            && layout.planes[layout.PLANE_V].offset == 2
            && layout.planes[layout.PLANE_Y].rightShift == 6
            && layout.planes[layout.PLANE_U].rightShift == 6
            && layout.planes[layout.PLANE_V].rightShift == 6);
}

bool IsP210(const C2GraphicView &view) {
    if (!IsYUV422_10bit(view)) {
        return false;
    }
    const C2PlanarLayout &layout = view.layout();
    return (layout.rootPlanes == 2
            && layout.planes[layout.PLANE_U].colInc == 4
            && layout.planes[layout.PLANE_U].rootIx == layout.PLANE_U
            && layout.planes[layout.PLANE_U].offset == 0
            && layout.planes[layout.PLANE_V].colInc == 4
            && layout.planes[layout.PLANE_V].rootIx == layout.PLANE_U
            && layout.planes[layout.PLANE_V].offset == 2
            && layout.planes[layout.PLANE_Y].rightShift == 6
            && layout.planes[layout.PLANE_U].rightShift == 6
            && layout.planes[layout.PLANE_V].rightShift == 6);
}

bool IsNV21(const C2GraphicView &view) {
    if (!IsYUV420(view)) {
        return false;
    }
    const C2PlanarLayout &layout = view.layout();
    return (layout.rootPlanes == 2
            && layout.planes[layout.PLANE_U].colInc == 2
            && layout.planes[layout.PLANE_U].rootIx == layout.PLANE_V
            && layout.planes[layout.PLANE_U].offset == 1
            && layout.planes[layout.PLANE_V].colInc == 2
            && layout.planes[layout.PLANE_V].rootIx == layout.PLANE_V
            && layout.planes[layout.PLANE_V].offset == 0);
}

bool IsI420(const C2GraphicView &view) {
    if (!IsYUV420(view)) {
        return false;
    }
    const C2PlanarLayout &layout = view.layout();
    return (layout.rootPlanes == 3
            && layout.planes[layout.PLANE_U].colInc == 1
            && layout.planes[layout.PLANE_U].rootIx == layout.PLANE_U
            && layout.planes[layout.PLANE_U].offset == 0
            && layout.planes[layout.PLANE_V].colInc == 1
            && layout.planes[layout.PLANE_V].rootIx == layout.PLANE_V
            && layout.planes[layout.PLANE_V].offset == 0);
}

bool IsYUV420(const MediaImage2 *img) {
    return (img->mType == MediaImage2::MEDIA_IMAGE_TYPE_YUV
            && img->mNumPlanes == 3
            && img->mBitDepth == 8
            && img->mBitDepthAllocated == 8
            && img->mPlane[0].mHorizSubsampling == 1
            && img->mPlane[0].mVertSubsampling == 1
            && img->mPlane[1].mHorizSubsampling == 2
            && img->mPlane[1].mVertSubsampling == 2
            && img->mPlane[2].mHorizSubsampling == 2
            && img->mPlane[2].mVertSubsampling == 2);
}

bool IsNV12(const MediaImage2 *img) {
    if (!IsYUV420(img)) {
        return false;
    }
    return (img->mPlane[1].mColInc == 2
            && img->mPlane[2].mColInc == 2
            && (img->mPlane[2].mOffset == img->mPlane[1].mOffset + 1));
}

bool IsNV21(const MediaImage2 *img) {
    if (!IsYUV420(img)) {
        return false;
    }
    return (img->mPlane[1].mColInc == 2
            && img->mPlane[2].mColInc == 2
            && (img->mPlane[1].mOffset == img->mPlane[2].mOffset + 1));
}

bool IsI420(const MediaImage2 *img) {
    if (!IsYUV420(img)) {
        return false;
    }
    return (img->mPlane[1].mColInc == 1
            && img->mPlane[2].mColInc == 1
            && img->mPlane[2].mOffset > img->mPlane[1].mOffset);
}

FlexLayout GetYuv420FlexibleLayout() {
    static FlexLayout sLayout = []{
        AHardwareBuffer_Desc desc = {
            16,  // width
            16,  // height
            1,   // layers
            AHARDWAREBUFFER_FORMAT_Y8Cb8Cr8_420,
            AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN | AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN,
            0,   // stride
            0,   // rfu0
            0,   // rfu1
        };
        AHardwareBuffer *buffer = nullptr;
        int ret = AHardwareBuffer_allocate(&desc, &buffer);
        if (ret != 0) {
            return FLEX_LAYOUT_UNKNOWN;
        }
        class AutoCloser {
        public:
            AutoCloser(AHardwareBuffer *buffer) : mBuffer(buffer), mLocked(false) {}
            ~AutoCloser() {
                if (mLocked) {
                    AHardwareBuffer_unlock(mBuffer, nullptr);
                }
                AHardwareBuffer_release(mBuffer);
            }

            void setLocked() { mLocked = true; }

        private:
            AHardwareBuffer *mBuffer;
            bool mLocked;
        } autoCloser(buffer);
        AHardwareBuffer_Planes planes;
        ret = AHardwareBuffer_lockPlanes(
                buffer,
                AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN | AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN,
                -1,       // fence
                nullptr,  // rect
                &planes);
        if (ret != 0) {
            AHardwareBuffer_release(buffer);
            return FLEX_LAYOUT_UNKNOWN;
        }
        autoCloser.setLocked();
        if (planes.planeCount != 3) {
            return FLEX_LAYOUT_UNKNOWN;
        }
        if (planes.planes[0].pixelStride != 1) {
            return FLEX_LAYOUT_UNKNOWN;
        }
        if (planes.planes[1].pixelStride == 1 && planes.planes[2].pixelStride == 1) {
            return FLEX_LAYOUT_PLANAR;
        }
        if (planes.planes[1].pixelStride == 2 && planes.planes[2].pixelStride == 2) {
            ssize_t uvDist =
                static_cast<uint8_t *>(planes.planes[2].data) -
                static_cast<uint8_t *>(planes.planes[1].data);
            if (uvDist == 1) {
                return FLEX_LAYOUT_SEMIPLANAR_UV;
            } else if (uvDist == -1) {
                return FLEX_LAYOUT_SEMIPLANAR_VU;
            }
            return FLEX_LAYOUT_UNKNOWN;
        }
        return FLEX_LAYOUT_UNKNOWN;
    }();
    return sLayout;
}

MediaImage2 CreateYUV420PlanarMediaImage2(
        uint32_t width, uint32_t height, uint32_t stride, uint32_t vstride) {
    return MediaImage2 {
        .mType = MediaImage2::MEDIA_IMAGE_TYPE_YUV,
        .mNumPlanes = 3,
        .mWidth = width,
        .mHeight = height,
        .mBitDepth = 8,
        .mBitDepthAllocated = 8,
        .mPlane = {
            {
                .mOffset = 0,
                .mColInc = 1,
                .mRowInc = (int32_t)stride,
                .mHorizSubsampling = 1,
                .mVertSubsampling = 1,
            },
            {
                .mOffset = stride * vstride,
                .mColInc = 1,
                .mRowInc = (int32_t)stride / 2,
                .mHorizSubsampling = 2,
                .mVertSubsampling = 2,
            },
            {
                .mOffset = stride * vstride * 5 / 4,
                .mColInc = 1,
                .mRowInc = (int32_t)stride / 2,
                .mHorizSubsampling = 2,
                .mVertSubsampling = 2,
            }
        },
    };
}

MediaImage2 CreateYUV420SemiPlanarMediaImage2(
        uint32_t width, uint32_t height, uint32_t stride, uint32_t vstride) {
    return MediaImage2 {
        .mType = MediaImage2::MEDIA_IMAGE_TYPE_YUV,
        .mNumPlanes = 3,
        .mWidth = width,
        .mHeight = height,
        .mBitDepth = 8,
        .mBitDepthAllocated = 8,
        .mPlane = {
            {
                .mOffset = 0,
                .mColInc = 1,
                .mRowInc = (int32_t)stride,
                .mHorizSubsampling = 1,
                .mVertSubsampling = 1,
            },
            {
                .mOffset = stride * vstride,
                .mColInc = 2,
                .mRowInc = (int32_t)stride,
                .mHorizSubsampling = 2,
                .mVertSubsampling = 2,
            },
            {
                .mOffset = stride * vstride + 1,
                .mColInc = 2,
                .mRowInc = (int32_t)stride,
                .mHorizSubsampling = 2,
                .mVertSubsampling = 2,
            }
        },
    };
}

// Matrix coefficient to convert RGB to Planar YUV data.
// Each sub-array represents the 3X3 coeff used with R, G and B
static const int16_t bt601Matrix[2][3][3] = {
    { { 77, 150, 29 }, { -43, -85, 128 }, { 128, -107, -21 } }, /* RANGE_FULL */
    { { 66, 129, 25 }, { -38, -74, 112 }, { 112, -94, -18 } },  /* RANGE_LIMITED */
};

static const int16_t bt709Matrix[2][3][3] = {
    // TRICKY: 18 is adjusted to 19 so that sum of row 1 is 256
    { { 54, 183, 19 }, { -29, -99, 128 }, { 128, -116, -12 } }, /* RANGE_FULL */
    // TRICKY: -87 is adjusted to -86 so that sum of row 2 is 0
    { { 47, 157, 16 }, { -26, -86, 112 }, { 112, -102, -10 } }, /* RANGE_LIMITED */
};

status_t ConvertRGBToPlanarYUV(
        uint8_t *dstY, size_t dstStride, size_t dstVStride, size_t bufferSize,
        const C2GraphicView &src, C2Color::matrix_t colorMatrix, C2Color::range_t colorRange) {
    CHECK(dstY != nullptr);

    if (dstStride * dstVStride * 3 / 2 > bufferSize) {
        ALOGD("conversion buffer is too small for converting from RGB to YUV");
        return NO_MEMORY;
    }

    uint8_t *dstU = dstY + dstStride * dstVStride;
    uint8_t *dstV = dstU + (dstStride >> 1) * (dstVStride >> 1);

    const C2PlanarLayout &layout = src.layout();
    const uint8_t *pRed   = src.data()[C2PlanarLayout::PLANE_R];
    const uint8_t *pGreen = src.data()[C2PlanarLayout::PLANE_G];
    const uint8_t *pBlue  = src.data()[C2PlanarLayout::PLANE_B];

    // set default range as limited
    if (colorRange != C2Color::RANGE_FULL && colorRange != C2Color::RANGE_LIMITED) {
        colorRange = C2Color::RANGE_LIMITED;
    }
    const int16_t (*weights)[3] =
        (colorMatrix == C2Color::MATRIX_BT709) ?
            bt709Matrix[colorRange - 1] : bt601Matrix[colorRange - 1];
    uint8_t zeroLvl =  colorRange == C2Color::RANGE_FULL ? 0 : 16;
    uint8_t maxLvlLuma =  colorRange == C2Color::RANGE_FULL ? 255 : 235;
    uint8_t maxLvlChroma =  colorRange == C2Color::RANGE_FULL ? 255 : 240;

#define CLIP3(min,v,max) (((v) < (min)) ? (min) : (((max) > (v)) ? (v) : (max)))
    for (size_t y = 0; y < src.crop().height; ++y) {
        for (size_t x = 0; x < src.crop().width; ++x) {
            uint8_t r = *pRed;
            uint8_t g = *pGreen;
            uint8_t b = *pBlue;

            unsigned luma = ((r * weights[0][0] + g * weights[0][1] + b * weights[0][2]) >> 8) +
                             zeroLvl;

            dstY[x] = CLIP3(zeroLvl, luma, maxLvlLuma);

            if ((x & 1) == 0 && (y & 1) == 0) {
                unsigned U = ((r * weights[1][0] + g * weights[1][1] + b * weights[1][2]) >> 8) +
                              128;

                unsigned V = ((r * weights[2][0] + g * weights[2][1] + b * weights[2][2]) >> 8) +
                              128;

                dstU[x >> 1] = CLIP3(zeroLvl, U, maxLvlChroma);
                dstV[x >> 1] = CLIP3(zeroLvl, V, maxLvlChroma);
            }
            pRed   += layout.planes[C2PlanarLayout::PLANE_R].colInc;
            pGreen += layout.planes[C2PlanarLayout::PLANE_G].colInc;
            pBlue  += layout.planes[C2PlanarLayout::PLANE_B].colInc;
        }

        if ((y & 1) == 0) {
            dstU += dstStride >> 1;
            dstV += dstStride >> 1;
        }

        pRed   -= layout.planes[C2PlanarLayout::PLANE_R].colInc * src.width();
        pGreen -= layout.planes[C2PlanarLayout::PLANE_G].colInc * src.width();
        pBlue  -= layout.planes[C2PlanarLayout::PLANE_B].colInc * src.width();
        pRed   += layout.planes[C2PlanarLayout::PLANE_R].rowInc;
        pGreen += layout.planes[C2PlanarLayout::PLANE_G].rowInc;
        pBlue  += layout.planes[C2PlanarLayout::PLANE_B].rowInc;

        dstY += dstStride;
    }
    return OK;
}

namespace {

/**
 * A block of raw allocated memory.
 */
struct MemoryBlockPoolBlock {
    MemoryBlockPoolBlock(size_t size)
        : mData(new uint8_t[size]), mSize(mData ? size : 0) { }

    ~MemoryBlockPoolBlock() {
        delete[] mData;
    }

    const uint8_t *data() const {
        return mData;
    }

    size_t size() const {
        return mSize;
    }

    C2_DO_NOT_COPY(MemoryBlockPoolBlock);

private:
    uint8_t *mData;
    size_t mSize;
};

/**
 * A simple raw memory block pool implementation.
 */
struct MemoryBlockPoolImpl {
    void release(std::list<MemoryBlockPoolBlock>::const_iterator block) {
        std::lock_guard<std::mutex> lock(mMutex);
        // return block to free blocks if it is the current size; otherwise, discard
        if (block->size() == mCurrentSize) {
            mFreeBlocks.splice(mFreeBlocks.begin(), mBlocksInUse, block);
        } else {
            mBlocksInUse.erase(block);
        }
    }

    std::list<MemoryBlockPoolBlock>::const_iterator fetch(size_t size) {
        std::lock_guard<std::mutex> lock(mMutex);
        mFreeBlocks.remove_if([size](const MemoryBlockPoolBlock &block) -> bool {
            return block.size() != size;
        });
        mCurrentSize = size;
        if (mFreeBlocks.empty()) {
            mBlocksInUse.emplace_front(size);
        } else {
            mBlocksInUse.splice(mBlocksInUse.begin(), mFreeBlocks, mFreeBlocks.begin());
        }
        return mBlocksInUse.begin();
    }

    MemoryBlockPoolImpl() = default;

    C2_DO_NOT_COPY(MemoryBlockPoolImpl);

private:
    std::mutex mMutex;
    std::list<MemoryBlockPoolBlock> mFreeBlocks;
    std::list<MemoryBlockPoolBlock> mBlocksInUse;
    size_t mCurrentSize;
};

} // namespace

struct MemoryBlockPool::Impl : MemoryBlockPoolImpl {
};

struct MemoryBlock::Impl {
    Impl(std::list<MemoryBlockPoolBlock>::const_iterator block,
         std::shared_ptr<MemoryBlockPoolImpl> pool)
        : mBlock(block), mPool(pool) {
    }

    ~Impl() {
        mPool->release(mBlock);
    }

    const uint8_t *data() const {
        return mBlock->data();
    }

    size_t size() const {
        return mBlock->size();
    }

private:
    std::list<MemoryBlockPoolBlock>::const_iterator mBlock;
    std::shared_ptr<MemoryBlockPoolImpl> mPool;
};

MemoryBlock MemoryBlockPool::fetch(size_t size) {
    std::list<MemoryBlockPoolBlock>::const_iterator poolBlock = mImpl->fetch(size);
    return MemoryBlock(std::make_shared<MemoryBlock::Impl>(
            poolBlock, std::static_pointer_cast<MemoryBlockPoolImpl>(mImpl)));
}

MemoryBlockPool::MemoryBlockPool()
    : mImpl(std::make_shared<MemoryBlockPool::Impl>()) {
}

MemoryBlock::MemoryBlock(std::shared_ptr<MemoryBlock::Impl> impl)
    : mImpl(impl) {
}

MemoryBlock::MemoryBlock() = default;

MemoryBlock::~MemoryBlock() = default;

const uint8_t* MemoryBlock::data() const {
    return mImpl ? mImpl->data() : nullptr;
}

size_t MemoryBlock::size() const {
    return mImpl ? mImpl->size() : 0;
}

MemoryBlock MemoryBlock::Allocate(size_t size) {
    return MemoryBlockPool().fetch(size);
}

GraphicView2MediaImageConverter::GraphicView2MediaImageConverter(
        const C2GraphicView &view, const sp<AMessage> &format, bool copy)
    : mInitCheck(NO_INIT),
        mView(view),
        mWidth(view.width()),
        mHeight(view.height()),
        mAllocatedDepth(0),
        mBackBufferSize(0),
        mMediaImage(new ABuffer(sizeof(MediaImage2))) {
    ATRACE_CALL();
    if (!format->findInt32(KEY_COLOR_FORMAT, &mClientColorFormat)) {
        mClientColorFormat = COLOR_FormatYUV420Flexible;
    }
    if (!format->findInt32("android._color-format", &mComponentColorFormat)) {
        mComponentColorFormat = COLOR_FormatYUV420Flexible;
    }
    if (view.error() != C2_OK) {
        ALOGD("Converter: view.error() = %d", view.error());
        mInitCheck = BAD_VALUE;
        return;
    }
    MediaImage2 *mediaImage = (MediaImage2 *)mMediaImage->base();
    const C2PlanarLayout &layout = view.layout();
    if (layout.numPlanes == 0) {
        ALOGD("Converter: 0 planes");
        mInitCheck = BAD_VALUE;
        return;
    }
    memset(mediaImage, 0, sizeof(*mediaImage));
    mAllocatedDepth = layout.planes[0].allocatedDepth;
    uint32_t bitDepth = layout.planes[0].bitDepth;

    // align width and height to support subsampling cleanly
    uint32_t stride = align(view.crop().width, 2) * divUp(layout.planes[0].allocatedDepth, 8u);
    uint32_t vStride = align(view.crop().height, 2);

    bool tryWrapping = !copy;

    switch (layout.type) {
        case C2PlanarLayout::TYPE_YUV: {
            mediaImage->mType = MediaImage2::MEDIA_IMAGE_TYPE_YUV;
            if (layout.numPlanes != 3) {
                ALOGD("Converter: %d planes for YUV layout", layout.numPlanes);
                mInitCheck = BAD_VALUE;
                return;
            }
            std::optional<int> clientBitDepth = {};
            switch (mClientColorFormat) {
                case COLOR_FormatYUVP010:
                case COLOR_FormatYUVP210:
                    clientBitDepth = 10;
                    break;
                case COLOR_FormatYUV411PackedPlanar:
                case COLOR_FormatYUV411Planar:
                case COLOR_FormatYUV420Flexible:
                case COLOR_FormatYUV420PackedPlanar:
                case COLOR_FormatYUV420PackedSemiPlanar:
                case COLOR_FormatYUV420Planar:
                case COLOR_FormatYUV420SemiPlanar:
                case COLOR_FormatYUV422Flexible:
                case COLOR_FormatYUV422PackedPlanar:
                case COLOR_FormatYUV422PackedSemiPlanar:
                case COLOR_FormatYUV422Planar:
                case COLOR_FormatYUV422SemiPlanar:
                case COLOR_FormatYUV444Flexible:
                case COLOR_FormatYUV444Interleaved:
                    clientBitDepth = 8;
                    break;
                default:
                    // no-op; used with optional
                    break;

            }
            // conversion fails if client bit-depth and the component bit-depth differs
            if ((clientBitDepth) && (bitDepth != clientBitDepth.value())) {
                ALOGD("Bit depth of client: %d and component: %d differs",
                    *clientBitDepth, bitDepth);
                mInitCheck = BAD_VALUE;
                return;
            }
            C2PlaneInfo yPlane = layout.planes[C2PlanarLayout::PLANE_Y];
            C2PlaneInfo uPlane = layout.planes[C2PlanarLayout::PLANE_U];
            C2PlaneInfo vPlane = layout.planes[C2PlanarLayout::PLANE_V];
            if (yPlane.channel != C2PlaneInfo::CHANNEL_Y
                    || uPlane.channel != C2PlaneInfo::CHANNEL_CB
                    || vPlane.channel != C2PlaneInfo::CHANNEL_CR) {
                ALOGD("Converter: not YUV layout");
                mInitCheck = BAD_VALUE;
                return;
            }
            bool yuv420888 = yPlane.rowSampling == 1 && yPlane.colSampling == 1
                    && uPlane.rowSampling == 2 && uPlane.colSampling == 2
                    && vPlane.rowSampling == 2 && vPlane.colSampling == 2;
            if (yuv420888) {
                for (uint32_t i = 0; i < 3; ++i) {
                    const C2PlaneInfo &plane = layout.planes[i];
                    if (plane.allocatedDepth != 8 || plane.bitDepth != 8) {
                        yuv420888 = false;
                        break;
                    }
                }
                yuv420888 = yuv420888 && yPlane.colInc == 1 && uPlane.rowInc == vPlane.rowInc;
            }
            int32_t copyFormat = mClientColorFormat;
            if (yuv420888 && mClientColorFormat == COLOR_FormatYUV420Flexible) {
                if (uPlane.colInc == 2 && vPlane.colInc == 2
                        && yPlane.rowInc == uPlane.rowInc) {
                    copyFormat = COLOR_FormatYUV420PackedSemiPlanar;
                } else if (uPlane.colInc == 1 && vPlane.colInc == 1
                        && yPlane.rowInc == uPlane.rowInc * 2) {
                    copyFormat = COLOR_FormatYUV420PackedPlanar;
                }
            }
            ALOGV("client_fmt=0x%x y:{colInc=%d rowInc=%d} u:{colInc=%d rowInc=%d} "
                    "v:{colInc=%d rowInc=%d}",
                    mClientColorFormat,
                    yPlane.colInc, yPlane.rowInc,
                    uPlane.colInc, uPlane.rowInc,
                    vPlane.colInc, vPlane.rowInc);
            switch (copyFormat) {
                case COLOR_FormatYUV420Flexible:
                case COLOR_FormatYUV420Planar:
                case COLOR_FormatYUV420PackedPlanar:
                    mediaImage->mPlane[mediaImage->Y].mOffset = 0;
                    mediaImage->mPlane[mediaImage->Y].mColInc = 1;
                    mediaImage->mPlane[mediaImage->Y].mRowInc = stride;
                    mediaImage->mPlane[mediaImage->Y].mHorizSubsampling = 1;
                    mediaImage->mPlane[mediaImage->Y].mVertSubsampling = 1;

                    mediaImage->mPlane[mediaImage->U].mOffset = stride * vStride;
                    mediaImage->mPlane[mediaImage->U].mColInc = 1;
                    mediaImage->mPlane[mediaImage->U].mRowInc = stride / 2;
                    mediaImage->mPlane[mediaImage->U].mHorizSubsampling = 2;
                    mediaImage->mPlane[mediaImage->U].mVertSubsampling = 2;

                    mediaImage->mPlane[mediaImage->V].mOffset = stride * vStride * 5 / 4;
                    mediaImage->mPlane[mediaImage->V].mColInc = 1;
                    mediaImage->mPlane[mediaImage->V].mRowInc = stride / 2;
                    mediaImage->mPlane[mediaImage->V].mHorizSubsampling = 2;
                    mediaImage->mPlane[mediaImage->V].mVertSubsampling = 2;

                    if (tryWrapping && mClientColorFormat != COLOR_FormatYUV420Flexible) {
                        tryWrapping = yuv420888 && uPlane.colInc == 1 && vPlane.colInc == 1
                                && yPlane.rowInc == uPlane.rowInc * 2
                                && view.data()[0] < view.data()[1]
                                && view.data()[1] < view.data()[2];
                    }
                    break;

                case COLOR_FormatYUV420SemiPlanar:
                case COLOR_FormatYUV420PackedSemiPlanar:
                    mediaImage->mPlane[mediaImage->Y].mOffset = 0;
                    mediaImage->mPlane[mediaImage->Y].mColInc = 1;
                    mediaImage->mPlane[mediaImage->Y].mRowInc = stride;
                    mediaImage->mPlane[mediaImage->Y].mHorizSubsampling = 1;
                    mediaImage->mPlane[mediaImage->Y].mVertSubsampling = 1;

                    mediaImage->mPlane[mediaImage->U].mOffset = stride * vStride;
                    mediaImage->mPlane[mediaImage->U].mColInc = 2;
                    mediaImage->mPlane[mediaImage->U].mRowInc = stride;
                    mediaImage->mPlane[mediaImage->U].mHorizSubsampling = 2;
                    mediaImage->mPlane[mediaImage->U].mVertSubsampling = 2;

                    mediaImage->mPlane[mediaImage->V].mOffset = stride * vStride + 1;
                    mediaImage->mPlane[mediaImage->V].mColInc = 2;
                    mediaImage->mPlane[mediaImage->V].mRowInc = stride;
                    mediaImage->mPlane[mediaImage->V].mHorizSubsampling = 2;
                    mediaImage->mPlane[mediaImage->V].mVertSubsampling = 2;

                    if (tryWrapping && mClientColorFormat != COLOR_FormatYUV420Flexible) {
                        tryWrapping = yuv420888 && uPlane.colInc == 2 && vPlane.colInc == 2
                                && yPlane.rowInc == uPlane.rowInc
                                && view.data()[0] < view.data()[1]
                                && view.data()[1] < view.data()[2];
                    }
                    break;

                case COLOR_FormatYUVP010:
                    // stride is in bytes
                    mediaImage->mPlane[mediaImage->Y].mOffset = 0;
                    mediaImage->mPlane[mediaImage->Y].mColInc = 2;
                    mediaImage->mPlane[mediaImage->Y].mRowInc = stride;
                    mediaImage->mPlane[mediaImage->Y].mHorizSubsampling = 1;
                    mediaImage->mPlane[mediaImage->Y].mVertSubsampling = 1;

                    mediaImage->mPlane[mediaImage->U].mOffset = stride * vStride;
                    mediaImage->mPlane[mediaImage->U].mColInc = 4;
                    mediaImage->mPlane[mediaImage->U].mRowInc = stride;
                    mediaImage->mPlane[mediaImage->U].mHorizSubsampling = 2;
                    mediaImage->mPlane[mediaImage->U].mVertSubsampling = 2;

                    mediaImage->mPlane[mediaImage->V].mOffset = stride * vStride + 2;
                    mediaImage->mPlane[mediaImage->V].mColInc = 4;
                    mediaImage->mPlane[mediaImage->V].mRowInc = stride;
                    mediaImage->mPlane[mediaImage->V].mHorizSubsampling = 2;
                    mediaImage->mPlane[mediaImage->V].mVertSubsampling = 2;
                    if (tryWrapping) {
                        tryWrapping = yPlane.allocatedDepth == 16
                                && uPlane.allocatedDepth == 16
                                && vPlane.allocatedDepth == 16
                                && yPlane.bitDepth == 10
                                && uPlane.bitDepth == 10
                                && vPlane.bitDepth == 10
                                && yPlane.rightShift == 6
                                && uPlane.rightShift == 6
                                && vPlane.rightShift == 6
                                && yPlane.rowSampling == 1 && yPlane.colSampling == 1
                                && uPlane.rowSampling == 2 && uPlane.colSampling == 2
                                && vPlane.rowSampling == 2 && vPlane.colSampling == 2
                                && yPlane.colInc == 2
                                && uPlane.colInc == 4
                                && vPlane.colInc == 4
                                && yPlane.rowInc == uPlane.rowInc
                                && yPlane.rowInc == vPlane.rowInc;
                    }
                    break;
                case COLOR_FormatYUVP210:
                    // stride is in bytes
                    // Luma (Y) plane: 16-bit samples, full resolution
                    mediaImage->mPlane[mediaImage->Y].mOffset = 0;
                    // 2 bytes per 16-bit Y sample
                    mediaImage->mPlane[mediaImage->Y].mColInc = 2;
                    mediaImage->mPlane[mediaImage->Y].mRowInc = stride;
                    // no horizontal subsampling
                    mediaImage->mPlane[mediaImage->Y].mHorizSubsampling = 1;
                    // no vertical subsampling
                    mediaImage->mPlane[mediaImage->Y].mVertSubsampling = 1;

                    // Chroma (UV) plane: interleaved U,V;
                    //   4:2:2 => horizontal subsampling=2, vertical subsampling=1
                    // Plane starts immediately after Y plane
                    mediaImage->mPlane[mediaImage->U].mOffset = stride * vStride;
                    // U is every 2 luma samples (2x16-bit => 4 bytes step)
                    mediaImage->mPlane[mediaImage->U].mColInc = 4;
                    mediaImage->mPlane[mediaImage->U].mRowInc = stride;
                    mediaImage->mPlane[mediaImage->U].mHorizSubsampling = 2;
                    mediaImage->mPlane[mediaImage->U].mVertSubsampling = 1;

                    // V within the interleaved UV: offset by +2 bytes from U for each pair
                    mediaImage->mPlane[mediaImage->V].mOffset = stride * vStride + 2;
                    mediaImage->mPlane[mediaImage->V].mColInc = 4;         // same as U
                    mediaImage->mPlane[mediaImage->V].mRowInc = stride;
                    mediaImage->mPlane[mediaImage->V].mHorizSubsampling = 2;
                    mediaImage->mPlane[mediaImage->V].mVertSubsampling = 1;

                    if (tryWrapping) {
                        // Typical 10-bit-in-16-bit packing (lower 10 bits used),
                        // rightShift=6 to align to MSB if needed.
                        tryWrapping = yPlane.allocatedDepth == 16
                                && uPlane.allocatedDepth == 16
                                && vPlane.allocatedDepth == 16
                                && yPlane.bitDepth == 10
                                && uPlane.bitDepth == 10
                                && vPlane.bitDepth == 10
                                && yPlane.rightShift == 6
                                && uPlane.rightShift == 6
                                && vPlane.rightShift == 6
                                && yPlane.rowSampling == 1 && yPlane.colSampling == 1
                                && uPlane.rowSampling == 1 && uPlane.colSampling == 2
                                && vPlane.rowSampling == 1 && vPlane.colSampling == 2
                                && yPlane.colInc == 2
                                && uPlane.colInc == 4
                                && vPlane.colInc == 4
                                && yPlane.rowInc == uPlane.rowInc
                                && yPlane.rowInc == vPlane.rowInc;
                    }
                    break;
                default: {
                    // default to fully planar format --- this will be overridden if wrapping
                    // TODO: keep interleaved format
                    int32_t colInc = divUp(mAllocatedDepth, 8u);
                    int32_t rowInc = stride * colInc / yPlane.colSampling;
                    mediaImage->mPlane[mediaImage->Y].mOffset = 0;
                    mediaImage->mPlane[mediaImage->Y].mColInc = colInc;
                    mediaImage->mPlane[mediaImage->Y].mRowInc = rowInc;
                    mediaImage->mPlane[mediaImage->Y].mHorizSubsampling = yPlane.colSampling;
                    mediaImage->mPlane[mediaImage->Y].mVertSubsampling = yPlane.rowSampling;
                    int32_t offset = rowInc * vStride / yPlane.rowSampling;

                    rowInc = stride * colInc / uPlane.colSampling;
                    mediaImage->mPlane[mediaImage->U].mOffset = offset;
                    mediaImage->mPlane[mediaImage->U].mColInc = colInc;
                    mediaImage->mPlane[mediaImage->U].mRowInc = rowInc;
                    mediaImage->mPlane[mediaImage->U].mHorizSubsampling = uPlane.colSampling;
                    mediaImage->mPlane[mediaImage->U].mVertSubsampling = uPlane.rowSampling;
                    offset += rowInc * vStride / uPlane.rowSampling;

                    rowInc = stride * colInc / vPlane.colSampling;
                    mediaImage->mPlane[mediaImage->V].mOffset = offset;
                    mediaImage->mPlane[mediaImage->V].mColInc = colInc;
                    mediaImage->mPlane[mediaImage->V].mRowInc = rowInc;
                    mediaImage->mPlane[mediaImage->V].mHorizSubsampling = vPlane.colSampling;
                    mediaImage->mPlane[mediaImage->V].mVertSubsampling = vPlane.rowSampling;
                    break;
                }
            }
            break;
        }

        case C2PlanarLayout::TYPE_YUVA:
            ALOGD("Converter: unrecognized color format "
                    "(client %d component %d) for YUVA layout",
                    mClientColorFormat, mComponentColorFormat);
            mInitCheck = NO_INIT;
            return;
        case C2PlanarLayout::TYPE_RGB:
            mediaImage->mType = MediaImage2::MEDIA_IMAGE_TYPE_RGB;
            // TODO: support MediaImage layout
            switch (mClientColorFormat) {
                case COLOR_FormatSurface:
                case COLOR_FormatRGBFlexible:
                case COLOR_Format24bitBGR888:
                case COLOR_Format24bitRGB888:
                    ALOGD("Converter: accept color format "
                            "(client %d component %d) for RGB layout",
                            mClientColorFormat, mComponentColorFormat);
                    break;
                default:
                    ALOGD("Converter: unrecognized color format "
                            "(client %d component %d) for RGB layout",
                            mClientColorFormat, mComponentColorFormat);
                    mInitCheck = BAD_VALUE;
                    return;
            }
            if (layout.numPlanes != 3) {
                ALOGD("Converter: %d planes for RGB layout", layout.numPlanes);
                mInitCheck = BAD_VALUE;
                return;
            }
            break;
        case C2PlanarLayout::TYPE_RGBA:
            mediaImage->mType = MediaImage2::MEDIA_IMAGE_TYPE_RGBA;
            // TODO: support MediaImage layout
            switch (mClientColorFormat) {
                case COLOR_FormatSurface:
                case COLOR_FormatRGBAFlexible:
                case COLOR_Format32bitABGR8888:
                case COLOR_Format32bitARGB8888:
                case COLOR_Format32bitBGRA8888:
                    ALOGD("Converter: accept color format "
                            "(client %d component %d) for RGBA layout",
                            mClientColorFormat, mComponentColorFormat);
                    break;
                default:
                    ALOGD("Converter: unrecognized color format "
                            "(client %d component %d) for RGBA layout",
                            mClientColorFormat, mComponentColorFormat);
                    mInitCheck = BAD_VALUE;
                    return;
            }
            if (layout.numPlanes != 4) {
                ALOGD("Converter: %d planes for RGBA layout", layout.numPlanes);
                mInitCheck = BAD_VALUE;
                return;
            }
            break;
        default:
            mediaImage->mType = MediaImage2::MEDIA_IMAGE_TYPE_UNKNOWN;
            if (layout.numPlanes == 1) {
                const C2PlaneInfo &plane = layout.planes[0];
                if (plane.colInc < 0 || plane.rowInc < 0) {
                    // Copy-only if we have negative colInc/rowInc
                    tryWrapping = false;
                }
                mediaImage->mPlane[0].mOffset = 0;
                mediaImage->mPlane[0].mColInc = std::abs(plane.colInc);
                mediaImage->mPlane[0].mRowInc = std::abs(plane.rowInc);
                mediaImage->mPlane[0].mHorizSubsampling = plane.colSampling;
                mediaImage->mPlane[0].mVertSubsampling = plane.rowSampling;
            } else {
                ALOGD("Converter: unrecognized layout: color format (client %d component %d)",
                        mClientColorFormat, mComponentColorFormat);
                mInitCheck = NO_INIT;
                return;
            }
            break;
    }
    if (tryWrapping) {
        // try to map directly. check if the planes are near one another
        const uint8_t *minPtr = mView.data()[0];
        const uint8_t *maxPtr = mView.data()[0];
        int32_t planeSize = 0;
        for (uint32_t i = 0; i < layout.numPlanes; ++i) {
            const C2PlaneInfo &plane = layout.planes[i];
            int64_t planeStride = std::abs(plane.rowInc / plane.colInc);
            ssize_t minOffset = plane.minOffset(
                    mWidth / plane.colSampling, mHeight / plane.rowSampling);
            ssize_t maxOffset = plane.maxOffset(
                    mWidth / plane.colSampling, mHeight / plane.rowSampling);
            if (minPtr > mView.data()[i] + minOffset) {
                minPtr = mView.data()[i] + minOffset;
            }
            if (maxPtr < mView.data()[i] + maxOffset) {
                maxPtr = mView.data()[i] + maxOffset;
            }
            planeSize += planeStride * divUp(mAllocatedDepth, 8u)
                    * align(mHeight, 64) / plane.rowSampling;
        }

        if (minPtr == mView.data()[0] && (maxPtr - minPtr) <= planeSize) {
            // FIXME: this is risky as reading/writing data out of bound results
            //        in an undefined behavior, but gralloc does assume a
            //        contiguous mapping
            for (uint32_t i = 0; i < layout.numPlanes; ++i) {
                const C2PlaneInfo &plane = layout.planes[i];
                mediaImage->mPlane[i].mOffset = mView.data()[i] - minPtr;
                mediaImage->mPlane[i].mColInc = plane.colInc;
                mediaImage->mPlane[i].mRowInc = plane.rowInc;
                mediaImage->mPlane[i].mHorizSubsampling = plane.colSampling;
                mediaImage->mPlane[i].mVertSubsampling = plane.rowSampling;
            }
            mWrapped = new ABuffer(const_cast<uint8_t *>(minPtr), maxPtr - minPtr);
            ALOGV("Converter: wrapped (capacity=%zu)", mWrapped->capacity());
        }
    }
    mediaImage->mNumPlanes = layout.numPlanes;
    mediaImage->mWidth = view.crop().width;
    mediaImage->mHeight = view.crop().height;
    mediaImage->mBitDepth = bitDepth;
    mediaImage->mBitDepthAllocated = mAllocatedDepth;

    uint32_t bufferSize = 0;
    for (uint32_t i = 0; i < layout.numPlanes; ++i) {
        const C2PlaneInfo &plane = layout.planes[i];
        if (plane.allocatedDepth < plane.bitDepth
                || plane.rightShift != plane.allocatedDepth - plane.bitDepth) {
            ALOGD("rightShift value of %u unsupported", plane.rightShift);
            mInitCheck = BAD_VALUE;
            return;
        }
        if (plane.allocatedDepth > 8 && plane.endianness != C2PlaneInfo::NATIVE) {
            ALOGD("endianness value of %u unsupported", plane.endianness);
            mInitCheck = BAD_VALUE;
            return;
        }
        if (plane.allocatedDepth != mAllocatedDepth || plane.bitDepth != bitDepth) {
            ALOGD("different allocatedDepth/bitDepth per plane unsupported");
            mInitCheck = BAD_VALUE;
            return;
        }
        // stride is in bytes
        bufferSize += stride * vStride / plane.rowSampling / plane.colSampling;
    }

    mBackBufferSize = bufferSize;
    mInitCheck = OK;
}

status_t GraphicView2MediaImageConverter::initCheck() const { return mInitCheck; }

uint32_t GraphicView2MediaImageConverter::backBufferSize() const { return mBackBufferSize; }

sp<ABuffer> GraphicView2MediaImageConverter::wrap() const {
    if (mBackBuffer == nullptr) {
        return mWrapped;
    }
    return nullptr;
}

bool GraphicView2MediaImageConverter::setBackBuffer(const sp<ABuffer> &backBuffer) {
    if (backBuffer == nullptr) {
        return false;
    }
    if (backBuffer->capacity() < mBackBufferSize) {
        return false;
    }
    backBuffer->setRange(0, mBackBufferSize);
    mBackBuffer = backBuffer;
    return true;
}

status_t GraphicView2MediaImageConverter::copyToMediaImage() {
    ATRACE_CALL();
    if (mInitCheck != OK) {
        return mInitCheck;
    }
    return ImageCopy(mBackBuffer->base(), getMediaImage(), mView);
}

const sp<ABuffer> &GraphicView2MediaImageConverter::imageData() const { return mMediaImage; }

MediaImage2 *GraphicView2MediaImageConverter::getMediaImage() {
    return (MediaImage2 *)mMediaImage->base();
}

}  // namespace android
