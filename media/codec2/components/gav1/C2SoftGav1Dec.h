/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef ANDROID_C2_SOFT_GAV1_DEC_H_
#define ANDROID_C2_SOFT_GAV1_DEC_H_

#include <inttypes.h>

#include <memory>

#include <media/stagefright/foundation/ColorUtils.h>

#include <SimpleC2Component.h>
#include <C2Config.h>
#include <gav1/decoder.h>
#include <gav1/decoder_settings.h>

namespace android {

struct C2SoftGav1Dec : public SimpleC2Component {
  class IntfImpl;

  C2SoftGav1Dec(const char* name, c2_node_id_t id,
                const std::shared_ptr<IntfImpl>& intfImpl);
  ~C2SoftGav1Dec();

  // Begin SimpleC2Component overrides.
  c2_status_t onInit() override;
  c2_status_t onStop() override;
  void onReset() override;
  void onRelease() override;
  c2_status_t onFlush_sm() override;
  void process(const std::unique_ptr<C2Work>& work,
               const std::shared_ptr<C2BlockPool>& pool) override;
  c2_status_t drain(uint32_t drainMode,
                    const std::shared_ptr<C2BlockPool>& pool) override;
  // End SimpleC2Component overrides.

 private:
  std::shared_ptr<IntfImpl> mIntf;
  std::unique_ptr<libgav1::Decoder> mCodecCtx;

  // configurations used by component in process
  // (TODO: keep this in intf but make them internal only)
  std::shared_ptr<C2StreamPixelFormatInfo::output> mPixelFormatInfo;

  uint32_t mHalPixelFormat;
  uint32_t mWidth;
  uint32_t mHeight;
  bool mSignalledOutputEos;
  bool mSignalledError;
  // Used during 10-bit I444/I422 to 10-bit P010 & 8-bit I420 conversions.
  std::unique_ptr<uint16_t[]> mTmpFrameBuffer;
  size_t mTmpFrameBufferSize = 0;

  C2StreamHdrStaticMetadataInfo::output mHdrStaticMetadataInfo;
  std::unique_ptr<C2StreamHdr10PlusInfo::output> mHdr10PlusInfo = nullptr;

  // Color aspects. These are ISO values and are meant to detect changes in aspects to avoid
  // converting them to C2 values for each frame
  struct VuiColorAspects {
      uint8_t primaries;
      uint8_t transfer;
      uint8_t coeffs;
      uint8_t fullRange;

      // default color aspects
      VuiColorAspects()
          : primaries(C2Color::PRIMARIES_UNSPECIFIED),
            transfer(C2Color::TRANSFER_UNSPECIFIED),
            coeffs(C2Color::MATRIX_UNSPECIFIED),
            fullRange(C2Color::RANGE_UNSPECIFIED) { }

      bool operator==(const VuiColorAspects &o) {
          return primaries == o.primaries && transfer == o.transfer && coeffs == o.coeffs
                  && fullRange == o.fullRange;
      }
  } mBitstreamColorAspects;

  nsecs_t mTimeStart = 0;  // Time at the start of decode()
  nsecs_t mTimeEnd = 0;    // Time at the end of decode()

  bool initDecoder();
  void getHDRStaticParams(const libgav1::DecoderBuffer *buffer,
                  const std::unique_ptr<C2Work> &work);
  void getHDR10PlusInfoData(const libgav1::DecoderBuffer *buffer,
                  const std::unique_ptr<C2Work> &work);
  void getVuiParams(const libgav1::DecoderBuffer *buffer);
  void destroyDecoder();
  void finishWork(uint64_t index, const std::unique_ptr<C2Work>& work,
                  const std::shared_ptr<C2GraphicBlock>& block);
  // Sets |work->result| and mSignalledError. Returns false.
  void setError(const std::unique_ptr<C2Work> &work, c2_status_t error);
  bool allocTmpFrameBuffer(size_t size);
  bool fillMonochromeRow(int value);
  bool outputBuffer(const std::shared_ptr<C2BlockPool>& pool,
                    const std::unique_ptr<C2Work>& work);
  c2_status_t drainInternal(uint32_t drainMode,
                            const std::shared_ptr<C2BlockPool>& pool,
                            const std::unique_ptr<C2Work>& work);

  C2_DO_NOT_COPY(C2SoftGav1Dec);
};

}  // namespace android

#endif  // ANDROID_C2_SOFT_GAV1_DEC_H_
