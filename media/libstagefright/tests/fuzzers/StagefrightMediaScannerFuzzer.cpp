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

#include <cutils/ashmem.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <media/stagefright/StagefrightMediaScanner.h>

#include <cstdio>

namespace android {
class FuzzMediaScannerClient : public MediaScannerClient {
public:
  virtual status_t scanFile(const char *, long long, long long, bool, bool) {
    return 0;
  }

  virtual status_t handleStringTag(const char *, const char *) { return 0; }

  virtual status_t setMimeType(const char *) { return 0; }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
  StagefrightMediaScanner mScanner = StagefrightMediaScanner();
  // Without this, the fuzzer crashes for some reason.
  mScanner.setLocale("");

  size_t data_size = fdp.ConsumeIntegralInRange<size_t>(0, size);
  int fd =
      ashmem_create_region("stagefrightmediascanner_fuzz_region", data_size);
  if (fd < 0)
    return 0;

  uint8_t *sh_data = static_cast<uint8_t *>(
      mmap(NULL, data_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
  if (sh_data == MAP_FAILED)
    return 0;

  while (fdp.remaining_bytes() > 8) {
    switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 1)) {
    case 0: {
      std::string path = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
      std::string mimeType =
          fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
      std::shared_ptr<MediaScannerClient> client(new FuzzMediaScannerClient());
      mScanner.processFile(path.c_str(), mimeType.c_str(), *client);
      break;
    }
    case 1: {
      size_t to_copy = fdp.ConsumeIntegralInRange<size_t>(1, data_size);
      std::vector<uint8_t> rand_buf = fdp.ConsumeBytes<uint8_t>(to_copy);

      // If fdp doesn't have enough bytes left it will just make a shorter
      // vector.
      to_copy = std::min(rand_buf.size(), data_size);

      std::copy(sh_data, sh_data + to_copy, rand_buf.begin());
      mScanner.extractAlbumArt(fd);
    }
    }
  }

  munmap(sh_data, data_size);
  close(fd);
  return 0;
}
} // namespace android
