/*
 * Copyright 2020 The Android Open Source Project
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
// Authors: corbin.souffrant@leviathansecurity.com
//          dylan.katz@leviathansecurity.com

#include <fuzzer/FuzzedDataProvider.h>
#include <media/stagefright/MediaBuffer.h>
#include <media/stagefright/SkipCutBuffer.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AMessage.h>

namespace android {
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
  size_t skip = fdp.ConsumeIntegral<size_t>();
  size_t cut = fdp.ConsumeIntegral<size_t>();
  size_t num16Channels = fdp.ConsumeIntegral<size_t>();
  sp<SkipCutBuffer> sBuffer(new SkipCutBuffer(skip, cut, num16Channels));

  while (fdp.remaining_bytes() > 0) {
    // Cap size to 1024 to limit max amount allocated.
    size_t buf_size = fdp.ConsumeIntegralInRange<size_t>(0, 1024);
    size_t range = fdp.ConsumeIntegralInRange<size_t>(0, buf_size);
    size_t length = fdp.ConsumeIntegralInRange<size_t>(0, buf_size - range);

    switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 4)) {
    case 0: {
      sp<ABuffer> a_buffer(new ABuffer(buf_size));
      sp<AMessage> format(new AMessage);
      sp<MediaCodecBuffer> s_buffer(new MediaCodecBuffer(format, a_buffer));
      s_buffer->setRange(range, length);
      sBuffer->submit(s_buffer);
      break;
    }
    case 1: {
      std::unique_ptr<MediaBufferBase> m_buffer(new MediaBuffer(buf_size));
      m_buffer->set_range(range, length);
      sBuffer->submit(reinterpret_cast<MediaBuffer *>(m_buffer.get()));
      break;
    }
    case 2: {
      sp<ABuffer> a_buffer(new ABuffer(buf_size));
      sp<AMessage> format(new AMessage);
      sp<MediaCodecBuffer> s_buffer(new MediaCodecBuffer(format, a_buffer));
      a_buffer->setRange(range, length);
      sBuffer->submit(a_buffer);
      break;
    }
    case 3: {
      sBuffer->clear();
      break;
    }
    case 4: {
      sBuffer->size();
    }
    }
  }
  return 0;
}
} // namespace android
