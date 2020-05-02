/******************************************************************************
 *
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */

#include "ExtractorFuzzerBase.h"

#include "AMRExtractor.h"

using namespace android;

class AmrExtractor : public ExtractorFuzzerBase {
 public:
  AmrExtractor() = default;
  ~AmrExtractor() = default;

  bool createExtractor();
};

bool AmrExtractor::createExtractor() {
  mExtractor = new AMRExtractor(new DataSourceHelper(mDataSource->wrap()));
  if (!mExtractor) {
    return false;
  }
  mExtractor->name();
  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if ((!data) || (size == 0)) {
    return 0;
  }
  AmrExtractor* extractor = new AmrExtractor();
  if (!extractor) {
    return 0;
  }
  if (extractor->setDataSource(data, size)) {
    if (extractor->createExtractor()) {
      extractor->getExtractorDef();
      extractor->getMetadata();
      extractor->extractTracks();
      extractor->getTracksMetadata();
    }
  }
  delete extractor;
  return 0;
}
