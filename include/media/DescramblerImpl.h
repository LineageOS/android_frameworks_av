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

#ifndef DESCRAMBLER_IMPL_H_
#define DESCRAMBLER_IMPL_H_

#include <media/stagefright/foundation/ABase.h>
#include <android/media/BnDescrambler.h>

namespace android {
using namespace media;
using namespace MediaDescrambler;
using binder::Status;
class DescramblerPlugin;
class SharedLibrary;

class DescramblerImpl : public BnDescrambler {
public:
    DescramblerImpl(const sp<SharedLibrary>& library, DescramblerPlugin *plugin);
    virtual ~DescramblerImpl();

    virtual Status setMediaCasSession(
            const CasSessionId& sessionId) override;

    virtual Status requiresSecureDecoderComponent(
            const String16& mime, bool *result) override;

    virtual Status descramble(
            const DescrambleInfo& descrambleInfo, int32_t *result) override;

    virtual Status release() override;

private:
    sp<SharedLibrary> mLibrary;
    DescramblerPlugin *mPlugin;

    DISALLOW_EVIL_CONSTRUCTORS(DescramblerImpl);
};

} // namespace android

#endif // DESCRAMBLER_IMPL_H_
