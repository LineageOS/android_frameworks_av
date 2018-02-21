/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef ANDROID_STAGEFRIGHT_C2PARAM_INTERNAL_H_
#define ANDROID_STAGEFRIGHT_C2PARAM_INTERNAL_H_

#include <C2Param.h>

struct C2_HIDE _C2ParamInspector {
    inline static uint32_t GetOffset(const C2FieldDescriptor &fd) {
        return fd._mFieldId._mOffset;
    }

    inline static uint32_t GetSize(const C2FieldDescriptor &fd) {
        return fd._mFieldId._mSize;
    }

    inline static uint32_t GetIndex(const C2ParamField &pf) {
        return pf._mIndex;
    }

    inline static uint32_t GetOffset(const C2ParamField &pf) {
        return pf._mFieldId._mOffset;
    }

    inline static uint32_t GetSize(const C2ParamField &pf) {
        return pf._mFieldId._mSize;
    }

    inline static uint32_t GetAttrib(const C2ParamDescriptor &pd) {
        return pd._mAttrib;
    }

    inline static
    C2ParamField CreateParamField(C2Param::Index index, uint32_t offset, uint32_t size) {
        return C2ParamField(index, offset, size);
    }

    inline static
    C2ParamField CreateParamField(C2Param::Index index, _C2FieldId field) {
        return C2ParamField(index, field._mOffset, field._mSize);
    }

    // expose attributes
    typedef C2ParamDescriptor::attrib_t attrib_t;
};

#endif // ANDROID_STAGEFRIGHT_C2PARAM_INTERNAL_H_

