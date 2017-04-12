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

#ifndef AAUDIO_AAUDIO_SERVICE_STREAM_EXCLUSIVE_H
#define AAUDIO_AAUDIO_SERVICE_STREAM_EXCLUSIVE_H

#include "AAudioServiceStreamMMAP.h"

namespace aaudio {

/**
 * Exclusive mode stream in the AAudio service.
 *
 * This is currently a stub.
 * We may move code from AAudioServiceStreamMMAP into this class.
 * If not, then it will be removed.
 */
class AAudioServiceStreamExclusive : public AAudioServiceStreamMMAP {

public:
    AAudioServiceStreamExclusive() {};
    virtual ~AAudioServiceStreamExclusive() = default;
};

} /* namespace aaudio */

#endif //AAUDIO_AAUDIO_SERVICE_STREAM_EXCLUSIVE_H
