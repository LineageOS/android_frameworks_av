/*
 * Copyright (C) 2020 The Android Open Source Project
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

#ifndef STAGEFRIGHT_CODEC2_ALLOCATION_ION_H_
#define STAGEFRIGHT_CODEC2_ALLOCATION_ION_H_

#include <C2Buffer.h>

namespace android {

struct C2HandleIon : public C2Handle {
    // ion handle owns ionFd(!) and bufferFd
    C2HandleIon(int bufferFd, size_t size)
        : C2Handle(cHeader),
          mFds{ bufferFd },
          mInts{ int(size & 0xFFFFFFFF), int((uint64_t(size) >> 32) & 0xFFFFFFFF), kMagic } { }

    static bool isValid(const C2Handle * const o);

    int bufferFd() const { return mFds.mBuffer; }
    size_t size() const {
        return size_t(unsigned(mInts.mSizeLo))
                | size_t(uint64_t(unsigned(mInts.mSizeHi)) << 32);
    }

protected:
    struct {
        int mBuffer; // shared ion buffer
    } mFds;
    struct {
        int mSizeLo; // low 32-bits of size
        int mSizeHi; // high 32-bits of size
        int mMagic;
    } mInts;

private:
    typedef C2HandleIon _type;
    enum {
        kMagic = '\xc2io\x00',
        numFds = sizeof(mFds) / sizeof(int),
        numInts = sizeof(mInts) / sizeof(int),
        version = sizeof(C2Handle)
    };
    //constexpr static C2Handle cHeader = { version, numFds, numInts, {} };
    const static C2Handle cHeader;
};
} // namespace android

#endif // STAGEFRIGHT_CODEC2_ALLOCATION_ION_H_
