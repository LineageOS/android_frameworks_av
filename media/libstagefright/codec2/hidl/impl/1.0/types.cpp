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

//#define LOG_NDEBUG 0
#define LOG_TAG "Codec2-types"
#include <log/log.h>

#include <codec2/hidl/1.0/types.h>

#include <C2AllocatorIon.h>
#include <C2AllocatorGralloc.h>
#include <C2PlatformSupport.h>
#include <C2BlockInternal.h>
#include <C2ParamInternal.h>
#include <C2Param.h>
#include <C2Buffer.h>
#include <C2Work.h>
#include <C2Component.h>
#include <util/C2ParamUtils.h>

#include <algorithm>

namespace vendor {
namespace google {
namespace media {
namespace c2 {
namespace V1_0 {
namespace implementation {

using namespace ::android;

namespace /* unnamed */ {

template <typename Common, typename DstVector, typename SrcVector>
void copyVector(DstVector* d, const SrcVector& s) {
    static_assert(sizeof(Common) == sizeof(decltype((*d)[0])),
            "DstVector's component size does not match Common");
    static_assert(sizeof(Common) == sizeof(decltype(s[0])),
            "SrcVector's component size does not match Common");
    d->resize(s.size());
    std::copy(
            reinterpret_cast<const Common*>(&s[0]),
            reinterpret_cast<const Common*>(&s[0] + s.size()),
            reinterpret_cast<Common*>(&(*d)[0]));
}

// C2ParamField -> ParamField
void objcpy(ParamField *d, const C2ParamField &s) {
    d->index = static_cast<ParamIndex>(_C2ParamInspector::GetIndex(s));
    d->fieldId.offset = static_cast<uint32_t>(_C2ParamInspector::GetOffset(s));
    d->fieldId.size = static_cast<uint32_t>(_C2ParamInspector::GetSize(s));
}

struct C2ParamFieldBuilder : public C2ParamField {
    C2ParamFieldBuilder() : C2ParamField(
            static_cast<C2Param::Index>(static_cast<uint32_t>(0)), 0, 0) {
    }
    // ParamField -> C2ParamField
    C2ParamFieldBuilder(const ParamField& s) : C2ParamField(
            static_cast<C2Param::Index>(static_cast<uint32_t>(s.index)),
            static_cast<uint32_t>(s.fieldId.offset),
            static_cast<uint32_t>(s.fieldId.size)) {
    }
};

// C2WorkOrdinalStruct -> WorkOrdinal
void objcpy(WorkOrdinal *d, const C2WorkOrdinalStruct &s) {
    d->frameIndex = static_cast<uint64_t>(s.frameIndex.peeku());
    d->timestampUs = static_cast<uint64_t>(s.timestamp.peeku());
    d->customOrdinal = static_cast<uint64_t>(s.customOrdinal.peeku());
}

// WorkOrdinal -> C2WorkOrdinalStruct
void objcpy(C2WorkOrdinalStruct *d, const WorkOrdinal &s) {
    d->frameIndex = c2_cntr64_t(s.frameIndex);
    d->timestamp = c2_cntr64_t(s.timestampUs);
    d->customOrdinal = c2_cntr64_t(s.customOrdinal);
}

// C2FieldSupportedValues::range's type -> FieldSupportedValues::Range
void objcpy(
        FieldSupportedValues::Range* d,
        const decltype(C2FieldSupportedValues::range)& s) {
    d->min = static_cast<PrimitiveValue>(s.min.u64);
    d->max = static_cast<PrimitiveValue>(s.max.u64);
    d->step = static_cast<PrimitiveValue>(s.step.u64);
    d->num = static_cast<PrimitiveValue>(s.num.u64);
    d->denom = static_cast<PrimitiveValue>(s.denom.u64);
}

// C2FieldSupportedValues -> FieldSupportedValues
Status objcpy(FieldSupportedValues *d, const C2FieldSupportedValues &s) {
    d->typeOther = static_cast<int32_t>(s.type);
    switch (s.type) {
    case C2FieldSupportedValues::EMPTY:
        d->type = FieldSupportedValues::Type::EMPTY;
        d->values.resize(0);
        return Status::OK;
    case C2FieldSupportedValues::RANGE:
        d->type = FieldSupportedValues::Type::RANGE;
        objcpy(&d->range, s.range);
        d->values.resize(0);
        return Status::OK;
    default:
        switch (s.type) {
        case C2FieldSupportedValues::VALUES:
            d->type = FieldSupportedValues::Type::VALUES;
            break;
        case C2FieldSupportedValues::FLAGS:
            d->type = FieldSupportedValues::Type::FLAGS;
            break;
        default:
            d->type = FieldSupportedValues::Type::OTHER;
            // Copy all fields in this case
            objcpy(&d->range, s.range);
        }
        d->values.resize(s.values.size());
        copyVector<uint64_t>(&d->values, s.values);
        return Status::OK;
    }
}

// FieldSupportedValues::Range -> C2FieldSupportedValues::range's type
void objcpy(
        decltype(C2FieldSupportedValues::range)* d,
        const FieldSupportedValues::Range& s) {
    d->min.u64 = static_cast<uint64_t>(s.min);
    d->max.u64 = static_cast<uint64_t>(s.max);
    d->step.u64 = static_cast<uint64_t>(s.step);
    d->num.u64 = static_cast<uint64_t>(s.num);
    d->denom.u64 = static_cast<uint64_t>(s.denom);
}

// FieldSupportedValues -> C2FieldSupportedValues
c2_status_t objcpy(C2FieldSupportedValues *d, const FieldSupportedValues &s) {
    switch (s.type) {
    case FieldSupportedValues::Type::EMPTY:
        d->type = C2FieldSupportedValues::EMPTY;
        return C2_OK;
    case FieldSupportedValues::Type::RANGE:
        d->type = C2FieldSupportedValues::RANGE;
        objcpy(&d->range, s.range);
        d->values.resize(0);
        return C2_OK;
    default:
        switch (s.type) {
        case FieldSupportedValues::Type::VALUES:
            d->type = C2FieldSupportedValues::VALUES;
            break;
        case FieldSupportedValues::Type::FLAGS:
            d->type = C2FieldSupportedValues::FLAGS;
            break;
        default:
            d->type = static_cast<C2FieldSupportedValues::type_t>(s.typeOther);
            // Copy all fields in this case
            objcpy(&d->range, s.range);
        }
        copyVector<uint64_t>(&d->values, s.values);
        return C2_OK;
    }
}

} // unnamed namespace

// C2FieldSupportedValuesQuery -> FieldSupportedValuesQuery
Status objcpy(
        FieldSupportedValuesQuery* d,
        const C2FieldSupportedValuesQuery& s) {
    objcpy(&d->field, s.field());
    switch (s.type()) {
    case C2FieldSupportedValuesQuery::POSSIBLE:
        d->type = FieldSupportedValuesQuery::Type::POSSIBLE;
        break;
    case C2FieldSupportedValuesQuery::CURRENT:
        d->type = FieldSupportedValuesQuery::Type::CURRENT;
        break;
    default:
        ALOGE("Unknown type of C2FieldSupportedValuesQuery: %u",
                static_cast<unsigned>(s.type()));
        return Status::BAD_VALUE;
    }
    return Status::OK;
}

// FieldSupportedValuesQuery -> C2FieldSupportedValuesQuery
c2_status_t objcpy(
        C2FieldSupportedValuesQuery* d,
        const FieldSupportedValuesQuery& s) {
    C2FieldSupportedValuesQuery::type_t dType;
    switch (s.type) {
    case FieldSupportedValuesQuery::Type::POSSIBLE:
        dType = C2FieldSupportedValuesQuery::POSSIBLE;
        break;
    case FieldSupportedValuesQuery::Type::CURRENT:
        dType = C2FieldSupportedValuesQuery::CURRENT;
        break;
    default:
        ALOGE("Unknown type of FieldSupportedValuesQuery: %u",
                static_cast<unsigned>(s.type));
        return C2_BAD_VALUE;
    }
    *d = C2FieldSupportedValuesQuery(C2ParamFieldBuilder(s.field), dType);
    return C2_OK;
}

// C2FieldSupportedValuesQuery -> FieldSupportedValuesQueryResult
Status objcpy(
        FieldSupportedValuesQueryResult* d,
        const C2FieldSupportedValuesQuery& s) {
    d->status = static_cast<Status>(s.status);
    return objcpy(&d->values, s.values);
}

// FieldSupportedValuesQuery, FieldSupportedValuesQueryResult ->
// C2FieldSupportedValuesQuery
c2_status_t objcpy(
        C2FieldSupportedValuesQuery* d,
        const FieldSupportedValuesQuery& sq,
        const FieldSupportedValuesQueryResult& sr) {
    c2_status_t status = objcpy(d, sq);
    if (status != C2_OK) {
        return status;
    }
    d->status = static_cast<c2_status_t>(sr.status);
    return objcpy(&d->values, sr.values);
}

// C2Component::Traits -> IComponentStore::ComponentTraits
Status objcpy(
        IComponentStore::ComponentTraits *d,
        const C2Component::Traits &s) {
    d->name = s.name;

    // TODO: Currently, we do not have any domain values defined in Codec2.0.
    d->domain = IComponentStore::ComponentTraits::Domain::OTHER;
    d->domainOther = static_cast<uint32_t>(s.domain);

    // TODO: Currently, we do not have any kind values defined in Codec2.0.
    d->kind = IComponentStore::ComponentTraits::Kind::OTHER;
    d->kindOther = static_cast<uint32_t>(s.kind);

    d->rank = static_cast<uint32_t>(s.rank);

    d->mediaType = s.mediaType;

    d->aliases.resize(s.aliases.size());
    for (size_t ix = s.aliases.size(); ix > 0; ) {
        --ix;
        d->aliases[ix] = s.aliases[ix];
    }
    return Status::OK;
}

// ComponentTraits -> C2Component::Traits
c2_status_t objcpy(
        C2Component::Traits* d,
        const IComponentStore::ComponentTraits& s) {
    d->name = s.name;

    // TODO: Currently, we do not have any domain values defined in Codec2.0.
    d->domain = static_cast<C2Component::domain_t>(s.domainOther);

    // TODO: Currently, we do not have any kind values defined in Codec2.0.
    d->kind = static_cast<C2Component::kind_t>(s.kindOther);

    d->rank = static_cast<C2Component::rank_t>(s.rank);

    d->mediaType = s.mediaType.c_str();

    // TODO: Currently, aliases are pointers to static strings. This is not
    // supported by HIDL.
    d->aliases.clear();
    return C2_OK;
}

namespace /* unnamed */ {

// C2ParamFieldValues -> ParamFieldValues
Status objcpy(ParamFieldValues *d, const C2ParamFieldValues &s) {
    objcpy(&d->paramOrField, s.paramOrField);
    if (s.values) {
        d->values.resize(1);
        return objcpy(&d->values[0], *s.values);
    }
    d->values.resize(0);
    return Status::OK;
}

// ParamFieldValues -> C2ParamFieldValues
c2_status_t objcpy(C2ParamFieldValues *d, const ParamFieldValues &s) {
    d->paramOrField = C2ParamFieldBuilder(s.paramOrField);
    if (s.values.size() == 1) {
        d->values = std::make_unique<C2FieldSupportedValues>();
        return objcpy(d->values.get(), s.values[0]);
    } else if (s.values.size() == 0) {
        d->values.reset();
        return C2_OK;
    }
    ALOGE("Multiple FieldSupportedValues objects. "
            "(Only one is allowed.)");
    return C2_BAD_VALUE;
}

} // unnamed namespace

// C2SettingResult -> SettingResult
Status objcpy(SettingResult *d, const C2SettingResult &s) {
    d->failureOther = static_cast<uint32_t>(s.failure);
    switch (s.failure) {
    case C2SettingResult::READ_ONLY:
        d->failure = SettingResult::Failure::READ_ONLY;
        break;
    case C2SettingResult::MISMATCH:
        d->failure = SettingResult::Failure::MISMATCH;
        break;
    case C2SettingResult::BAD_VALUE:
        d->failure = SettingResult::Failure::BAD_VALUE;
        break;
    case C2SettingResult::BAD_TYPE:
        d->failure = SettingResult::Failure::BAD_TYPE;
        break;
    case C2SettingResult::BAD_PORT:
        d->failure = SettingResult::Failure::BAD_PORT;
        break;
    case C2SettingResult::BAD_INDEX:
        d->failure = SettingResult::Failure::BAD_INDEX;
        break;
    case C2SettingResult::CONFLICT:
        d->failure = SettingResult::Failure::CONFLICT;
        break;
    case C2SettingResult::UNSUPPORTED:
        d->failure = SettingResult::Failure::UNSUPPORTED;
        break;
    case C2SettingResult::INFO_CONFLICT:
        d->failure = SettingResult::Failure::INFO_CONFLICT;
        break;
    default:
        d->failure = SettingResult::Failure::OTHER;
    }
    Status status = objcpy(&d->field, s.field);
    if (status != Status::OK) {
        return status;
    }
    d->conflicts.resize(s.conflicts.size());
    size_t i = 0;
    for (const C2ParamFieldValues& sConflict : s.conflicts) {
        ParamFieldValues &dConflict = d->conflicts[i++];
        status = objcpy(&dConflict, sConflict);
        if (status != Status::OK) {
            return status;
        }
    }
    return Status::OK;
}

// SettingResult -> C2SettingResult
c2_status_t objcpy(C2SettingResult *d, const SettingResult &s) {
    switch (s.failure) {
    case SettingResult::Failure::READ_ONLY:
        d->failure = C2SettingResult::READ_ONLY;
        break;
    case SettingResult::Failure::MISMATCH:
        d->failure = C2SettingResult::MISMATCH;
        break;
    case SettingResult::Failure::BAD_VALUE:
        d->failure = C2SettingResult::BAD_VALUE;
        break;
    case SettingResult::Failure::BAD_TYPE:
        d->failure = C2SettingResult::BAD_TYPE;
        break;
    case SettingResult::Failure::BAD_PORT:
        d->failure = C2SettingResult::BAD_PORT;
        break;
    case SettingResult::Failure::BAD_INDEX:
        d->failure = C2SettingResult::BAD_INDEX;
        break;
    case SettingResult::Failure::CONFLICT:
        d->failure = C2SettingResult::CONFLICT;
        break;
    case SettingResult::Failure::UNSUPPORTED:
        d->failure = C2SettingResult::UNSUPPORTED;
        break;
    case SettingResult::Failure::INFO_CONFLICT:
        d->failure = C2SettingResult::INFO_CONFLICT;
        break;
    default:
        d->failure = static_cast<C2SettingResult::Failure>(s.failureOther);
    }
    c2_status_t status = objcpy(&d->field, s.field);
    if (status != C2_OK) {
        return status;
    }
    d->conflicts.clear();
    for (const ParamFieldValues& sConflict : s.conflicts) {
        d->conflicts.emplace_back(
                C2ParamFieldValues{ C2ParamFieldBuilder(), nullptr });
        status = objcpy(&d->conflicts.back(), sConflict);
        if (status != C2_OK) {
            return status;
        }
    }
    return C2_OK;
}

// C2ParamDescriptor -> ParamDescriptor
Status objcpy(ParamDescriptor *d, const C2ParamDescriptor &s) {
    d->index = static_cast<ParamIndex>(s.index());
    d->attrib = static_cast<hidl_bitfield<ParamDescriptor::Attrib>>(
            _C2ParamInspector::GetAttrib(s));
    d->name = s.name();
    copyVector<uint32_t>(&d->dependencies, s.dependencies());
    return Status::OK;
}

// ParamDescriptor -> C2ParamDescriptor
c2_status_t objcpy(std::unique_ptr<C2ParamDescriptor> *d, const ParamDescriptor &s) {
    std::vector<C2Param::Index> dDependencies;
    dDependencies.reserve(s.dependencies.size());
    for (const ParamIndex& sDependency : s.dependencies) {
        dDependencies.emplace_back(static_cast<uint32_t>(sDependency));
    }
    *d = std::make_unique<C2ParamDescriptor>(
            C2Param::Index(static_cast<uint32_t>(s.index)),
            static_cast<C2ParamDescriptor::attrib_t>(s.attrib),
            C2String(s.name.c_str()),
            std::move(dDependencies));
    return C2_OK;
}

// C2StructDescriptor -> StructDescriptor
Status objcpy(StructDescriptor *d, const C2StructDescriptor &s) {
    d->type = static_cast<ParamIndex>(s.coreIndex().coreIndex());
    d->fields.resize(s.numFields());
    size_t i = 0;
    for (const auto& sField : s) {
        FieldDescriptor& dField = d->fields[i++];
        dField.fieldId.offset = static_cast<uint32_t>(
                _C2ParamInspector::GetOffset(sField));
        dField.fieldId.size = static_cast<uint32_t>(
                _C2ParamInspector::GetSize(sField));
        dField.type = static_cast<hidl_bitfield<FieldDescriptor::Type>>(
                sField.type());
        dField.length = static_cast<uint32_t>(sField.extent());
        dField.name = static_cast<hidl_string>(sField.name());
        const auto& sNamedValues = sField.namedValues();
        dField.namedValues.resize(sNamedValues.size());
        size_t j = 0;
        for (const auto& sNamedValue : sNamedValues) {
            FieldDescriptor::NamedValue& dNamedValue = dField.namedValues[j++];
            dNamedValue.name = static_cast<hidl_string>(sNamedValue.first);
            dNamedValue.value = static_cast<PrimitiveValue>(
                    sNamedValue.second.u64);
        }
    }
    return Status::OK;
}

// StructDescriptor -> C2StructDescriptor
c2_status_t objcpy(C2StructDescriptor *d, const StructDescriptor &s) {
    // TODO: Implement this when C2StructDescriptor can be dynamically
    // constructed.
    (void)d;
    (void)s;
    ALOGE("Conversion StructDescriptor -> C2StructDescriptor "
            "not implemented.");
    return C2_OMITTED;
}

// Finds or adds a hidl BaseBlock object from a given C2Handle* to a list and an
// associated map.
// Note: Native handles are not duplicated. The original handles must not be
// closed before the transaction is complete.
namespace /* unnamed */ {

Status addBaseBlock(uint32_t* index, const C2Handle* handle,
        std::vector<BaseBlock>* baseBlocks,
        std::map<const C2Handle*, uint32_t>* baseBlockIndices) {
    if (handle == nullptr) {
        return Status::BAD_VALUE;
    }
    auto it = baseBlockIndices->find(handle);
    if (it != baseBlockIndices->end()) {
        *index = it->second;
    } else {
        *index = baseBlocks->size();
        BaseBlock dBaseBlock;
        // TODO: Use BufferPool.
        dBaseBlock.type = BaseBlock::Type::NATIVE;
        // This does not clone the handle.
        dBaseBlock.nativeBlock =
                reinterpret_cast<const native_handle_t*>(handle);
        baseBlocks->push_back(dBaseBlock);
        baseBlockIndices->emplace(handle, *index);
    }
    return Status::OK;
}

// C2Fence -> hidl_handle
// Note: File descriptors are not duplicated. The original file descriptor must
// not be closed before the transaction is complete.
Status objcpy(hidl_handle* d, const C2Fence& s) {
    (void)s; // TODO: implement s.fd()
    int fenceFd = -1;
    d->setTo(nullptr);
    if (fenceFd >= 0) {
        native_handle_t *handle = native_handle_create(1, 0);
        if (!handle) {
            return Status::NO_MEMORY;
        }
        handle->data[0] = fenceFd;
        d->setTo(handle, true /* owns */);
    }
    return Status::OK;
}

// C2ConstLinearBlock -> Block
// Note: Native handles are not duplicated. The original handles must not be
// closed before the transaction is complete.
Status objcpy(Block* d, const C2ConstLinearBlock& s,
        std::vector<BaseBlock>* baseBlocks,
        std::map<const C2Handle*, uint32_t>* baseBlockIndices) {
    // Find the BaseBlock index.
    // TODO: Use BufferPool.
    Status status = addBaseBlock(
            &d->index, s.handle(), baseBlocks, baseBlockIndices);
    if (status != Status::OK) {
        return status;
    }

    // Create the metadata.
    C2Hidl_RangeInfo dRangeInfo;
    dRangeInfo.offset = static_cast<uint32_t>(s.offset());
    dRangeInfo.length = static_cast<uint32_t>(s.size());
    status = createParamsBlob(&d->meta,
            std::vector<C2Param*>{ &dRangeInfo });
    if (status != Status::OK) {
        return Status::BAD_VALUE;
    }

    // Copy the fence
    return objcpy(&d->fence, s.fence());
}

// C2ConstGraphicBlock -> Block
// Note: Native handles are not duplicated. The original handles must not be
// closed before the transaction is complete.
Status objcpy(Block* d, const C2ConstGraphicBlock& s,
        std::vector<BaseBlock>* baseBlocks,
        std::map<const C2Handle*, uint32_t>* baseBlockIndices) {
    // Find the BaseBlock index.
    // TODO: Use BufferPool.
    Status status = addBaseBlock(
            &d->index, s.handle(), baseBlocks, baseBlockIndices);
    if (status != Status::OK) {
        return status;
    }

    // Create the metadata.
    C2Hidl_RectInfo dRectInfo;
    C2Rect sRect = s.crop();
    dRectInfo.left = static_cast<uint32_t>(sRect.left);
    dRectInfo.top = static_cast<uint32_t>(sRect.top);
    dRectInfo.width = static_cast<uint32_t>(sRect.width);
    dRectInfo.height = static_cast<uint32_t>(sRect.height);
    status = createParamsBlob(&d->meta,
            std::vector<C2Param*>{ &dRectInfo });
    if (status != Status::OK) {
        return Status::BAD_VALUE;
    }

    // Copy the fence
    return objcpy(&d->fence, s.fence());
}

// C2BufferData -> Buffer
// This function only fills in d->blocks.
Status objcpy(Buffer* d, const C2BufferData& s,
        std::vector<BaseBlock>* baseBlocks,
        std::map<const C2Handle*, uint32_t>* baseBlockIndices) {
    Status status;
    d->blocks.resize(
            s.linearBlocks().size() +
            s.graphicBlocks().size());
    size_t i = 0;
    for (const C2ConstLinearBlock& linearBlock : s.linearBlocks()) {
        Block& dBlock = d->blocks[i++];
        status = objcpy(
                &dBlock, linearBlock, baseBlocks, baseBlockIndices);
        if (status != Status::OK) {
            return status;
        }
    }
    for (const C2ConstGraphicBlock& graphicBlock : s.graphicBlocks()) {
        Block& dBlock = d->blocks[i++];
        status = objcpy(
                &dBlock, graphicBlock, baseBlocks, baseBlockIndices);
        if (status != Status::OK) {
            return status;
        }
    }
    return Status::OK;
}

// C2Buffer -> Buffer
Status objcpy(Buffer* d, const C2Buffer& s,
        std::vector<BaseBlock>* baseBlocks,
        std::map<const C2Handle*, uint32_t>* baseBlockIndices) {
    Status status = createParamsBlob(&d->info, s.info());
    if (status != Status::OK) {
        return status;
    }
    return objcpy(d, s.data(), baseBlocks, baseBlockIndices);
}

// C2InfoBuffer -> InfoBuffer
Status objcpy(InfoBuffer* d, const C2InfoBuffer& s,
        std::vector<BaseBlock>* baseBlocks,
        std::map<const C2Handle*, uint32_t>* baseBlockIndices) {
    // TODO: C2InfoBuffer is not implemented.
    (void)d;
    (void)s;
    (void)baseBlocks;
    (void)baseBlockIndices;
    return Status::OK;
    /*
    // Stub implementation that may work in the future.
    d->index = static_cast<uint32_t>(s.index());
    d->buffer.info.resize(0);
    return objcpy(&d->buffer, s.data(), baseBlocks, baseBlockIndices);
    */
}

// C2FrameData -> FrameData
Status objcpy(FrameData* d, const C2FrameData& s,
        std::vector<BaseBlock>* baseBlocks,
        std::map<const C2Handle*, uint32_t>* baseBlockIndices) {
    d->flags = static_cast<hidl_bitfield<FrameData::Flags>>(s.flags);
    objcpy(&d->ordinal, s.ordinal);

    Status status;
    d->buffers.resize(s.buffers.size());
    size_t i = 0;
    for (const std::shared_ptr<C2Buffer>& sBuffer : s.buffers) {
        Buffer& dBuffer = d->buffers[i++];
        if (!sBuffer) {
            ALOGE("Null C2Buffer");
            return Status::BAD_VALUE;
        }
        status = objcpy(&dBuffer, *sBuffer, baseBlocks, baseBlockIndices);
        if (status != Status::OK) {
            return status;
        }
    }

    status = createParamsBlob(&d->configUpdate, s.configUpdate);
    if (status != Status::OK) {
        return status;
    }

    d->infoBuffers.resize(s.infoBuffers.size());
    i = 0;
    for (const std::shared_ptr<C2InfoBuffer>& sInfoBuffer : s.infoBuffers) {
        InfoBuffer& dInfoBuffer = d->infoBuffers[i++];
        if (!sInfoBuffer) {
            ALOGE("Null C2InfoBuffer");
            return Status::BAD_VALUE;
        }
        status = objcpy(&dInfoBuffer, *sInfoBuffer, baseBlocks, baseBlockIndices);
        if (status != Status::OK) {
            return status;
        }
    }

    return status;
}

} // unnamed namespace

// std::list<std::unique_ptr<C2Work>> -> WorkBundle
// TODO: Connect with Bufferpool
Status objcpy(WorkBundle* d, const std::list<std::unique_ptr<C2Work>>& s) {
    Status status = Status::OK;

    std::vector<BaseBlock> baseBlocks;
    std::map<const C2Handle*, uint32_t> baseBlockIndices;
    d->works.resize(s.size());
    size_t i = 0;
    for (const std::unique_ptr<C2Work>& sWork : s) {
        Work &dWork = d->works[i++];
        if (!sWork) {
            ALOGW("Null C2Work encountered.");
            continue;
        }
        status = objcpy(&dWork.input, sWork->input,
                &baseBlocks, &baseBlockIndices);
        if (status != Status::OK) {
            return status;
        }
        if (sWork->worklets.size() == 0) {
            ALOGW("Work with no worklets.");
        } else {
            if (sWork->worklets.size() > 1) {
                ALOGW("Work with multiple worklets. "
                        "Only the first worklet will be marshalled.");
            }
            if (!sWork->worklets.front()) {
                ALOGE("Null worklet encountered.");
                return Status::BAD_VALUE;
            }

            // Parcel the first worklet.
            const C2Worklet &sWorklet = *sWork->worklets.front();
            Worklet &dWorklet = dWork.worklet;

            dWorklet.tunings.resize(sWorklet.tunings.size());
            size_t j = 0;
            for (const std::unique_ptr<C2Tuning>& sTuning : sWorklet.tunings) {
                status = createParamsBlob(
                        &dWorklet.tunings[j++],
                        std::vector<C2Param*>
                        { reinterpret_cast<C2Param*>(sTuning.get()) });
                if (status != Status::OK) {
                    return status;
                }
            }

            dWorklet.failures.resize(sWorklet.failures.size());
            j = 0;
            for (const std::unique_ptr<C2SettingResult>& sFailure :
                    sWorklet.failures) {
                if (!sFailure) {
                    ALOGE("Null C2SettingResult");
                    return Status::BAD_VALUE;
                }
                status = objcpy(&dWorklet.failures[j++], *sFailure);
                if (status != Status::OK) {
                    return status;
                }
            }

            status = objcpy(&dWorklet.output, sWorklet.output,
                    &baseBlocks, &baseBlockIndices);
            if (status != Status::OK) {
                return status;
            }
        }
        dWork.workletProcessed = sWork->workletsProcessed > 0;
        dWork.result = static_cast<Status>(sWork->result);
    }

    d->baseBlocks = baseBlocks;

    return Status::OK;
}

namespace /* unnamed */ {

// hidl_handle -> C2Fence
// Note: File descriptors are not duplicated. The original file descriptor must
// not be closed before the transaction is complete.
c2_status_t objcpy(C2Fence* d, const hidl_handle& s) {
    // TODO: Implement.
    (void)s;
    *d = C2Fence();
    return C2_OK;
}

// Buffer -> C2Buffer
// Note: The native handles will be cloned.
c2_status_t objcpy(std::shared_ptr<C2Buffer>* d, const Buffer& s,
        const hidl_vec<BaseBlock>& baseBlocks) {
    c2_status_t status;

    // First, construct C2Buffer with blocks from s.blocks.
    *d = nullptr;

    // TODO: Only buffers with 1 block are supported.
    if (s.blocks.size() == 1) {
        // Obtain the BaseBlock.
        const Block &sBlock = s.blocks[0];
        if (sBlock.index >= baseBlocks.size()) {
            ALOGE("Index into baseBlocks is out of range.");
            return C2_BAD_VALUE;
        }
        const BaseBlock &sBaseBlock = baseBlocks[sBlock.index];

        // Parse meta.
        std::vector<C2Param*> sBlockMeta;
        status = parseParamsBlob(&sBlockMeta, sBlock.meta);
        if (status != C2_OK) {
            ALOGE("Invalid block params blob.");
            return C2_BAD_VALUE;
        }

        // Copy fence.
        C2Fence dFence;
        status = objcpy(&dFence, sBlock.fence);

        // Construct a block.
        switch (sBaseBlock.type) {
        case BaseBlock::Type::NATIVE: {
            const native_handle_t* sHandle = sBaseBlock.nativeBlock;
            if (sHandle == nullptr) {
                ALOGE("Null native handle in a block.");
                return C2_BAD_VALUE;
            }
            sHandle = native_handle_clone(sHandle);
            if (sHandle == nullptr) {
                ALOGE("Cannot clone native handle.");
                return C2_NO_MEMORY;
            }
            const C2Handle *sC2Handle =
                    reinterpret_cast<const C2Handle*>(sHandle);

            // Currently, there are only 2 types of C2Allocation: ion and
            // gralloc.
            if (C2AllocatorIon::isValid(sC2Handle)) {
                // Check the block meta. It should have exactly 1 C2Info:
                // C2Hidl_RangeInfo.
                if ((sBlockMeta.size() != 1) || !sBlockMeta[0]) {
                    ALOGE("Invalid block metadata for ion block.");
                    return C2_BAD_VALUE;
                }
                if (sBlockMeta[0]->size() != sizeof(C2Hidl_RangeInfo)) {
                    ALOGE("Invalid block metadata for ion block: range.");
                    return C2_BAD_VALUE;
                }
                C2Hidl_RangeInfo *rangeInfo =
                        reinterpret_cast<C2Hidl_RangeInfo*>(sBlockMeta[0]);

                std::shared_ptr<C2Allocator> allocator;
                c2_status_t status = GetCodec2PlatformAllocatorStore(
                        )->fetchAllocator(
                        C2PlatformAllocatorStore::ION,
                        &allocator);
                if (status != C2_OK) {
                    ALOGE("Cannot fetch platform linear allocator.");
                    return status;
                }
                std::shared_ptr<C2LinearAllocation> allocation;
                status = allocator->priorLinearAllocation(
                        sC2Handle, &allocation);
                if (status != C2_OK) {
                    ALOGE("Error constructing linear allocation.");
                    return status;
                } else if (!allocation) {
                    ALOGE("Null linear allocation.");
                    return C2_BAD_VALUE;
                }
                std::shared_ptr<C2LinearBlock> block =
                        _C2BlockFactory::CreateLinearBlock(allocation);
                if (!block) {
                    ALOGE("Cannot create a block.");
                    return C2_BAD_VALUE;
                }
                *d = C2Buffer::CreateLinearBuffer(block->share(
                        rangeInfo->offset, rangeInfo->length, dFence));
                if (!(*d)) {
                    ALOGE("Cannot create a linear buffer.");
                    return C2_BAD_VALUE;
                }
            } else if (C2AllocatorGralloc::isValid(sC2Handle)) {
                // Check the block meta. It should have exactly 1 C2Info:
                // C2Hidl_RectInfo.
                if ((sBlockMeta.size() != 1) || !sBlockMeta[0]) {
                    ALOGE("Invalid block metadata for graphic block.");
                    return C2_BAD_VALUE;
                }
                if (sBlockMeta[0]->size() != sizeof(C2Hidl_RectInfo)) {
                    ALOGE("Invalid block metadata for graphic block: crop rect.");
                    return C2_BAD_VALUE;
                }
                C2Hidl_RectInfo *rectInfo =
                        reinterpret_cast<C2Hidl_RectInfo*>(sBlockMeta[0]);

                std::shared_ptr<C2Allocator> allocator;
                c2_status_t status = GetCodec2PlatformAllocatorStore(
                        )->fetchAllocator(
                        C2PlatformAllocatorStore::GRALLOC,
                        &allocator);
                if (status != C2_OK) {
                    ALOGE("Cannot fetch platform graphic allocator.");
                    return status;
                }

                std::shared_ptr<C2GraphicAllocation> allocation;
                status = allocator->priorGraphicAllocation(
                        sC2Handle, &allocation);
                if (status != C2_OK) {
                    ALOGE("Error constructing graphic allocation.");
                    return status;
                } else if (!allocation) {
                    ALOGE("Null graphic allocation.");
                    return C2_BAD_VALUE;
                }
                std::shared_ptr<C2GraphicBlock> block =
                        _C2BlockFactory::CreateGraphicBlock(allocation);
                if (!block) {
                    ALOGE("Cannot create a block.");
                    return C2_BAD_VALUE;
                }
                *d = C2Buffer::CreateGraphicBuffer(block->share(
                        C2Rect(rectInfo->width, rectInfo->height,
                               rectInfo->left, rectInfo->top),
                        dFence));
                if (!(*d)) {
                    ALOGE("Cannot create a graphic buffer.");
                    return C2_BAD_VALUE;
                }
            } else {
                ALOGE("Unknown handle type.");
                return C2_BAD_VALUE;
            }
            break;
        }
        case BaseBlock::Type::POOLED: {
            // TODO: Implement. Use BufferPool.
            return C2_OMITTED;
        }
        default:
            ALOGE("Invalid BaseBlock type.");
            return C2_BAD_VALUE;
        }
    } else {
        ALOGE("Currently a buffer must contain exactly 1 block.");
        return C2_BAD_VALUE;
    }

    // Parse info
    std::vector<C2Param*> params;
    status = parseParamsBlob(&params, s.info);
    if (status != C2_OK) {
        ALOGE("Invalid buffer params blob.");
        return status;
    }
    for (C2Param* param : params) {
        if (param == nullptr) {
            ALOGE("Null buffer param encountered.");
            return C2_BAD_VALUE;
        }
        std::shared_ptr<C2Param> c2param(
                C2Param::Copy(*param).release());
        if (!c2param) {
            ALOGE("Invalid buffer param inside a blob.");
            return C2_BAD_VALUE;
        }
        status = (*d)->setInfo(std::static_pointer_cast<C2Info>(c2param));
        if (status != C2_OK) {
            ALOGE("C2Buffer::setInfo failed().");
            return C2_BAD_VALUE;
        }
    }

    return C2_OK;
}

// FrameData -> C2FrameData
c2_status_t objcpy(C2FrameData* d, const FrameData& s,
        const hidl_vec<BaseBlock>& baseBlocks) {
    c2_status_t status;
    d->flags = static_cast<C2FrameData::flags_t>(s.flags);
    objcpy(&d->ordinal, s.ordinal);
    d->buffers.clear();
    d->buffers.reserve(s.buffers.size());
    for (const Buffer& sBuffer : s.buffers) {
        std::shared_ptr<C2Buffer> dBuffer;
        status = objcpy(&dBuffer, sBuffer, baseBlocks);
        if (status != C2_OK) {
            return status;
        }
        d->buffers.emplace_back(dBuffer);
    }

    std::vector<C2Param*> params;
    status = parseParamsBlob(&params, s.configUpdate);
    if (status != C2_OK) {
        ALOGE("Failed to parse frame data params.");
        return status;
    }
    d->configUpdate.clear();
    for (C2Param* param : params) {
        d->configUpdate.emplace_back(C2Param::Copy(*param));
        if (!d->configUpdate.back()) {
            ALOGE("Unexpected error while parsing frame data params.");
            return C2_BAD_VALUE;
        }
    }

    // TODO: Implement this once C2InfoBuffer has constructors.
    d->infoBuffers.clear();
    return C2_OK;
}

} // unnamed namespace

// WorkBundle -> std::list<std::unique_ptr<C2Work>>
// TODO: Connect with Bufferpool
c2_status_t objcpy(std::list<std::unique_ptr<C2Work>>* d, const WorkBundle& s) {
    c2_status_t status;
    d->clear();
    for (const Work& sWork : s.works) {
        d->emplace_back(std::make_unique<C2Work>());
        C2Work& dWork = *d->back();

        // input
        status = objcpy(&dWork.input, sWork.input, s.baseBlocks);
        if (status != C2_OK) {
            ALOGE("Error constructing C2Work's input.");
            return C2_BAD_VALUE;
        }

        // worklet(s)
        // TODO: Currently, tunneling is not supported.
        if (sWork.workletProcessed) {
            dWork.worklets.clear();
            dWork.workletsProcessed = 1;

            const Worklet &sWorklet = sWork.worklet;
            std::unique_ptr<C2Worklet> dWorklet = std::make_unique<C2Worklet>();

            // tunings
            dWorklet->tunings.clear();
            dWorklet->tunings.reserve(sWorklet.tunings.size());
            for (const Params& sTuning : sWorklet.tunings) {
                std::vector<C2Param*> dParams;
                status = parseParamsBlob(&dParams, sTuning);
                if (status != C2_OK) {
                    ALOGE("Failed to parse C2Tuning in C2Worklet.");
                    return C2_BAD_VALUE;
                }
                for (C2Param* param : dParams) {
                    std::unique_ptr<C2Param> dParam = C2Param::Copy(*param);
                    if (!dParam) {
                        ALOGE("Null C2Tuning encountered while "
                                "parsing C2Worklet.");
                        return C2_BAD_VALUE;
                    }
                    dWorklet->tunings.emplace_back(
                            std::unique_ptr<C2Tuning>(
                            reinterpret_cast<C2Tuning*>(
                            dParam.release())));
                }
            }
            // failures
            dWorklet->failures.clear();
            dWorklet->failures.reserve(sWorklet.failures.size());
            for (const SettingResult& sFailure : sWorklet.failures) {
                std::unique_ptr<C2SettingResult> dFailure(
                        new C2SettingResult { .field = C2ParamFieldValues {
                        C2ParamFieldBuilder(), nullptr } });
                status = objcpy(dFailure.get(), sFailure);
                if (status != C2_OK) {
                    ALOGE("Failed to create C2SettingResult in C2Worklet.");
                    return C2_BAD_VALUE;
                }
                dWorklet->failures.emplace_back(std::move(dFailure));
            }
            // output
            status = objcpy(&dWorklet->output, sWorklet.output, s.baseBlocks);
            if (status != C2_OK) {
                ALOGE("Failed to create output C2FrameData.");
                return C2_BAD_VALUE;
            }
            dWork.worklets.emplace_back(std::move(dWorklet));
        } else {
            dWork.worklets.clear();
            dWork.workletsProcessed = 0;
        }

        // result
        dWork.result = static_cast<c2_status_t>(sWork.result);
    }

    return C2_OK;
}

// Params -> std::vector<C2Param*>
c2_status_t parseParamsBlob(std::vector<C2Param*> *params, const hidl_vec<uint8_t> &blob) {
    // assuming blob is const here
    size_t size = blob.size();
    const uint8_t *data = blob.data();
    C2Param *p = nullptr;

    do {
        p = C2ParamUtils::ParseFirst(data, size);
        if (p) {
            params->emplace_back(p);
            size -= p->size();
            data += p->size();
        }
    } while (p);

    return size == 0 ? C2_OK : C2_BAD_VALUE;
}

namespace /* unnamed */ {

/**
 * Concatenates a list of C2Params into a params blob.
 * \param[out] blob target blob
 * \param[in] params parameters to concatenate
 * \retval C2_OK if the blob was successfully created
 * \retval C2_BAD_VALUE if the blob was not successful (this only happens if the parameters were
 *         not const)
 */
template<typename T>
Status _createParamsBlob(hidl_vec<uint8_t> *blob, const T &params) {
    // assuming the parameter values are const
    size_t size = 0;
    for (const auto &p : params) {
        size += p->size();
    }
    blob->resize(size);
    size_t ix = 0;
    for (const auto &p : params) {
        // NEVER overwrite even if param values (e.g. size) changed
        size_t paramSize = std::min(p->size(), size - ix);
//        memcpy(&blob[ix], &*p, paramSize);
        std::copy(
                reinterpret_cast<const uint8_t*>(&*p),
                reinterpret_cast<const uint8_t*>(&*p) + paramSize,
                &blob[ix]);
        ix += paramSize;
    }
    blob->resize(ix);
    return ix == size ? Status::OK : Status::CORRUPTED;
}

} // unnamed namespace

// std::vector<const C2Param*> -> Params
Status createParamsBlob(
        hidl_vec<uint8_t> *blob,
        const std::vector<const C2Param*> &params) {
    return _createParamsBlob(blob, params);
}

// std::vector<C2Param*> -> Params
Status createParamsBlob(
        hidl_vec<uint8_t> *blob,
        const std::vector<C2Param*> &params) {
    return _createParamsBlob(blob, params);
}

// std::vector<std::unique_ptr<C2Param>> -> Params
Status createParamsBlob(
        hidl_vec<uint8_t> *blob,
        const std::vector<std::unique_ptr<C2Param>> &params) {
    return _createParamsBlob(blob, params);
}

// std::vector<std::unique_ptr<C2Tuning>> -> Params
Status createParamsBlob(
        hidl_vec<uint8_t> *blob,
        const std::vector<std::unique_ptr<C2Tuning>> &params) {
    return _createParamsBlob(blob, params);
}

// std::vector<std::shared_ptr<const C2Info>> -> Params
Status createParamsBlob(
        hidl_vec<uint8_t> *blob,
        const std::vector<std::shared_ptr<const C2Info>> &params) {
    return _createParamsBlob(blob, params);
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android

