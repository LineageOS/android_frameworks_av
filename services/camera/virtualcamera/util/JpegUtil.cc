/*
 * Copyright (C) 2023 The Android Open Source Project
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
// #define LOG_NDEBUG 0
#define LOG_TAG "JpegUtil"
#include "JpegUtil.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "android/hardware_buffer.h"
#include "jpeglib.h"
#include "log/log.h"
#include "ui/GraphicBuffer.h"
#include "ui/GraphicBufferMapper.h"
#include "utils/Errors.h"

namespace android {
namespace companion {
namespace virtualcamera {
namespace {

class LibJpegContext {
 public:
  LibJpegContext(int width, int height, int quality, const size_t outBufferSize,
                 void* outBuffer)
      : mWidth(width),
        mHeight(height),
        mDstBufferSize(outBufferSize),
        mDstBuffer(outBuffer) {
    // Initialize error handling for libjpeg.
    // We call jpeg_std_error to initialize standard error
    // handling and then override:
    // * output_message not to print to stderr, but use ALOG instead.
    // * error_exit not to terminate the process, but failure flag instead.
    mCompressStruct.err = jpeg_std_error(&mErrorMgr);
    mCompressStruct.err->output_message = onOutputError;
    mCompressStruct.err->error_exit = onErrorExit;
    jpeg_create_compress(&mCompressStruct);

    // Configure input image parameters.
    mCompressStruct.image_width = width;
    mCompressStruct.image_height = height;
    mCompressStruct.input_components = 3;
    mCompressStruct.in_color_space = JCS_YCbCr;
    // We pass pointer to this instance as a client data so we can
    // access this object from the static callbacks invoked by
    // libjpeg.
    mCompressStruct.client_data = this;

    // Configure destination manager for libjpeg.
    mCompressStruct.dest = &mDestinationMgr;
    mDestinationMgr.init_destination = onInitDestination;
    mDestinationMgr.empty_output_buffer = onEmptyOutputBuffer;
    mDestinationMgr.term_destination = onTermDestination;
    mDestinationMgr.next_output_byte = reinterpret_cast<JOCTET*>(mDstBuffer);
    mDestinationMgr.free_in_buffer = mDstBufferSize;

    // Configure everything else based on input configuration above.
    jpeg_set_defaults(&mCompressStruct);

    // Set quality and colorspace.
    jpeg_set_quality(&mCompressStruct, quality, 1);
    jpeg_set_colorspace(&mCompressStruct, JCS_YCbCr);

    // Configure RAW input mode - this let's libjpeg know we're providing raw,
    // subsampled YCbCr data.
    mCompressStruct.raw_data_in = 1;
    mCompressStruct.dct_method = JDCT_IFAST;

    // Configure sampling factors - this states that every 2 Y
    // samples share 1 Cb & 1 Cr component vertically & horizontally (YUV420).
    mCompressStruct.comp_info[0].h_samp_factor = 2;
    mCompressStruct.comp_info[0].v_samp_factor = 2;
    mCompressStruct.comp_info[1].h_samp_factor = 1;
    mCompressStruct.comp_info[1].v_samp_factor = 1;
    mCompressStruct.comp_info[2].h_samp_factor = 1;
    mCompressStruct.comp_info[2].v_samp_factor = 1;
  }

  LibJpegContext& setApp1Data(const uint8_t* app1Data, const size_t size) {
    mApp1Data = app1Data;
    mApp1DataSize = size;
    return *this;
  }

  std::optional<size_t> compress(const android_ycbcr& ycbr) {
    // TODO(b/301023410) - Add support for compressing image sizes not aligned
    // with DCT size.
    if (mWidth % (2 * DCTSIZE) || (mHeight % (2 * DCTSIZE))) {
      ALOGE(
          "%s: Compressing YUV420 image with size %dx%d not aligned with 2 * "
          "DCTSIZE (%d) is not currently supported.",
          __func__, mWidth, mHeight, 2 * DCTSIZE);
      return std::nullopt;
    }

    // Chroma planes have 1/2 resolution of the original image.
    const int cHeight = mHeight / 2;
    const int cWidth = mWidth / 2;

    // Prepare arrays of pointers to scanlines of each plane.
    std::vector<JSAMPROW> yLines(mHeight);
    std::vector<JSAMPROW> cbLines(cHeight);
    std::vector<JSAMPROW> crLines(cHeight);

    uint8_t* y = static_cast<uint8_t*>(ycbr.y);
    uint8_t* cb = static_cast<uint8_t*>(ycbr.cb);
    uint8_t* cr = static_cast<uint8_t*>(ycbr.cr);

    // Since UV samples might be interleaved (semiplanar) we need to copy
    // them to separate planes, since libjpeg doesn't directly
    // support processing semiplanar YUV.
    const int cSamples = cWidth * cHeight;
    std::vector<uint8_t> cb_plane(cSamples);
    std::vector<uint8_t> cr_plane(cSamples);

    // TODO(b/301023410) - Use libyuv or ARM SIMD for "unzipping" the data.
    int out_idx = 0;
    for (int i = 0; i < cHeight; ++i) {
      for (int j = 0; j < cWidth; ++j) {
        cb_plane[out_idx] = cb[j * ycbr.chroma_step];
        cr_plane[out_idx] = cr[j * ycbr.chroma_step];
        out_idx++;
      }
      cb += ycbr.cstride;
      cr += ycbr.cstride;
    }

    // Collect pointers to individual scanline of each plane.
    for (int i = 0; i < mHeight; ++i) {
      yLines[i] = y + i * ycbr.ystride;
    }
    for (int i = 0; i < cHeight; ++i) {
      cbLines[i] = cb_plane.data() + i * (mWidth / 2);
      crLines[i] = cr_plane.data() + i * (mWidth / 2);
    }

    return compress(yLines, cbLines, crLines);
  }

 private:
  void setSuccess(const boolean success) {
    mSuccess = success;
  }

  void initDestination() {
    mDestinationMgr.next_output_byte = reinterpret_cast<JOCTET*>(mDstBuffer);
    mDestinationMgr.free_in_buffer = mDstBufferSize;
    ALOGV("%s:%d jpeg start: %p [%zu]", __FUNCTION__, __LINE__, mDstBuffer,
          mDstBufferSize);
  }

  void termDestination() {
    mEncodedSize = mDstBufferSize - mDestinationMgr.free_in_buffer;
    ALOGV("%s:%d Done with jpeg: %zu", __FUNCTION__, __LINE__, mEncodedSize);
  }

  // Perform actual compression.
  //
  // Takes vector of pointers to Y / Cb / Cr scanlines as an input. Length of
  // each vector needs to correspond to height of corresponding plane.
  //
  // Returns size of compressed image in bytes on success, empty optional otherwise.
  std::optional<size_t> compress(std::vector<JSAMPROW>& yLines,
                                 std::vector<JSAMPROW>& cbLines,
                                 std::vector<JSAMPROW>& crLines) {
    jpeg_start_compress(&mCompressStruct, TRUE);

    if (mApp1Data != nullptr && mApp1DataSize > 0) {
      ALOGV("%s: Writing exif, size %zu B", __func__, mApp1DataSize);
      jpeg_write_marker(&mCompressStruct, JPEG_APP0 + 1,
                        static_cast<const JOCTET*>(mApp1Data), mApp1DataSize);
    }

    while (mCompressStruct.next_scanline < mCompressStruct.image_height) {
      const uint32_t batchSize = DCTSIZE * 2;
      const uint32_t nl = mCompressStruct.next_scanline;
      JSAMPARRAY planes[3]{&yLines[nl], &cbLines[nl / 2], &crLines[nl / 2]};

      uint32_t done = jpeg_write_raw_data(&mCompressStruct, planes, batchSize);

      if (done != batchSize) {
        ALOGE("%s: compressed %u lines, expected %u (total %u/%u)",
              __FUNCTION__, done, batchSize, mCompressStruct.next_scanline,
              mCompressStruct.image_height);
        return std::nullopt;
      }
    }
    jpeg_finish_compress(&mCompressStruct);
    return mEncodedSize;
  }

  // === libjpeg callbacks below ===

  static void onOutputError(j_common_ptr cinfo) {
    char buffer[JMSG_LENGTH_MAX];
    (*cinfo->err->format_message)(cinfo, buffer);
    ALOGE("libjpeg error: %s", buffer);
  };

  static void onErrorExit(j_common_ptr cinfo) {
    static_cast<LibJpegContext*>(cinfo->client_data)->setSuccess(false);
  };

  static void onInitDestination(j_compress_ptr cinfo) {
    static_cast<LibJpegContext*>(cinfo->client_data)->initDestination();
  }

  static int onEmptyOutputBuffer(j_compress_ptr cinfo __unused) {
    ALOGV("%s:%d Out of buffer", __FUNCTION__, __LINE__);
    return 0;
  }

  static void onTermDestination(j_compress_ptr cinfo) {
    static_cast<LibJpegContext*>(cinfo->client_data)->termDestination();
  }

  jpeg_compress_struct mCompressStruct;
  jpeg_error_mgr mErrorMgr;
  jpeg_destination_mgr mDestinationMgr;

  // APP1 data.
  const uint8_t* mApp1Data = nullptr;
  size_t mApp1DataSize = 0;

  // Dimensions of the input image.
  int mWidth;
  int mHeight;

  // Destination buffer and it's capacity.
  size_t mDstBufferSize;
  void* mDstBuffer;

  // This will be set to size of encoded data
  // written to the outputBuffer when encoding finishes.
  size_t mEncodedSize;
  // Set to true/false based on whether the encoding
  // was successful.
  boolean mSuccess = true;
};

}  // namespace

std::optional<size_t> compressJpeg(const int width, const int height,
                                   const int quality, const android_ycbcr& ycbcr,
                                   const std::vector<uint8_t>& app1ExifData,
                                   size_t outBufferSize, void* outBuffer) {
  LibJpegContext context(width, height, quality, outBufferSize, outBuffer);
  if (!app1ExifData.empty()) {
    context.setApp1Data(app1ExifData.data(), app1ExifData.size());
  }
  return context.compress(ycbcr);
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
