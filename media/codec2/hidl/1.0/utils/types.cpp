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

#include <media/stagefright/bqhelper/WGraphicBufferProducer.h>

#include <C2AllocatorIon.h>
#include <C2AllocatorGralloc.h>
#include <C2BlockInternal.h>
#include <C2Buffer.h>
#include <C2Component.h>
#include <C2Param.h>
#include <C2ParamInternal.h>
#include <C2PlatformSupport.h>
#include <C2Work.h>
#include <util/C2ParamUtils.h>

#include <algorithm>
#include <functional>
#include <unordered_map>

#include <media/stagefright/foundation/AUtils.h>

namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {

using namespace ::android;
using ::android::hardware::Return;
using ::android::hardware::media::bufferpool::BufferPoolData;
using ::android::hardware::media::bufferpool::V1_0::BufferStatusMessage;
using ::android::hardware::media::bufferpool::V1_0::ResultStatus;
using ::android::hardware::media::bufferpool::V1_0::implementation::
        ClientManager;
using ::android::hardware::media::bufferpool::V1_0::implementation::
        TransactionId;
using ::android::TWGraphicBufferProducer;

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

    switch (s.domain) {
    case C2Component::DOMAIN_VIDEO:
        d->domain = IComponentStore::ComponentTraits::Domain::VIDEO;
        break;
    case C2Component::DOMAIN_AUDIO:
        d->domain = IComponentStore::ComponentTraits::Domain::AUDIO;
        break;
    default:
        d->domain = IComponentStore::ComponentTraits::Domain::OTHER;
    }
    d->domainOther = static_cast<uint32_t>(s.domain);

    switch (s.kind) {
    case C2Component::KIND_DECODER:
        d->kind = IComponentStore::ComponentTraits::Kind::DECODER;
        break;
    case C2Component::KIND_ENCODER:
        d->kind = IComponentStore::ComponentTraits::Kind::ENCODER;
        break;
    default:
        d->kind = IComponentStore::ComponentTraits::Kind::OTHER;
    }
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

// ComponentTraits -> C2Component::Traits, std::unique_ptr<std::vector<std::string>>
c2_status_t objcpy(
        C2Component::Traits* d,
        std::unique_ptr<std::vector<std::string>>* aliasesBuffer,
        const IComponentStore::ComponentTraits& s) {
    d->name = s.name.c_str();

    switch (s.domain) {
    case IComponentStore::ComponentTraits::Domain::VIDEO:
        d->domain = C2Component::DOMAIN_VIDEO;
        break;
    case IComponentStore::ComponentTraits::Domain::AUDIO:
        d->domain = C2Component::DOMAIN_AUDIO;
        break;
    default:
        d->domain = static_cast<C2Component::domain_t>(s.domainOther);
    }

    switch (s.kind) {
    case IComponentStore::ComponentTraits::Kind::DECODER:
        d->kind = C2Component::KIND_DECODER;
        break;
    case IComponentStore::ComponentTraits::Kind::ENCODER:
        d->kind = C2Component::KIND_ENCODER;
        break;
    default:
        d->kind = static_cast<C2Component::kind_t>(s.kindOther);
    }

    d->rank = static_cast<C2Component::rank_t>(s.rank);
    d->mediaType = s.mediaType.c_str();

    // aliasesBuffer must not be resized after this.
    *aliasesBuffer = std::make_unique<std::vector<std::string>>(
            s.aliases.size());
    (*aliasesBuffer)->resize(s.aliases.size());
    std::vector<C2StringLiteral> dAliases(s.aliases.size());
    for (size_t i = 0; i < s.aliases.size(); ++i) {
        (**aliasesBuffer)[i] = s.aliases[i].c_str();
        d->aliases[i] = (**aliasesBuffer)[i].c_str();
    }
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

// SettingResult -> std::unique_ptr<C2SettingResult>
c2_status_t objcpy(std::unique_ptr<C2SettingResult> *d, const SettingResult &s) {
    *d = std::unique_ptr<C2SettingResult>(new C2SettingResult {
            .field = C2ParamFieldValues(C2ParamFieldBuilder()) });
    if (!*d) {
        return C2_NO_MEMORY;
    }

    // failure
    switch (s.failure) {
    case SettingResult::Failure::READ_ONLY:
        (*d)->failure = C2SettingResult::READ_ONLY;
        break;
    case SettingResult::Failure::MISMATCH:
        (*d)->failure = C2SettingResult::MISMATCH;
        break;
    case SettingResult::Failure::BAD_VALUE:
        (*d)->failure = C2SettingResult::BAD_VALUE;
        break;
    case SettingResult::Failure::BAD_TYPE:
        (*d)->failure = C2SettingResult::BAD_TYPE;
        break;
    case SettingResult::Failure::BAD_PORT:
        (*d)->failure = C2SettingResult::BAD_PORT;
        break;
    case SettingResult::Failure::BAD_INDEX:
        (*d)->failure = C2SettingResult::BAD_INDEX;
        break;
    case SettingResult::Failure::CONFLICT:
        (*d)->failure = C2SettingResult::CONFLICT;
        break;
    case SettingResult::Failure::UNSUPPORTED:
        (*d)->failure = C2SettingResult::UNSUPPORTED;
        break;
    case SettingResult::Failure::INFO_CONFLICT:
        (*d)->failure = C2SettingResult::INFO_CONFLICT;
        break;
    default:
        (*d)->failure = static_cast<C2SettingResult::Failure>(s.failureOther);
    }

    // field
    c2_status_t status = objcpy(&(*d)->field, s.field);
    if (status != C2_OK) {
        return status;
    }

    // conflicts
    (*d)->conflicts.clear();
    (*d)->conflicts.reserve(s.conflicts.size());
    for (const ParamFieldValues& sConflict : s.conflicts) {
        (*d)->conflicts.emplace_back(
                C2ParamFieldValues{ C2ParamFieldBuilder(), nullptr });
        status = objcpy(&(*d)->conflicts.back(), sConflict);
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
c2_status_t objcpy(std::shared_ptr<C2ParamDescriptor> *d, const ParamDescriptor &s) {
    std::vector<C2Param::Index> dDependencies;
    dDependencies.reserve(s.dependencies.size());
    for (const ParamIndex& sDependency : s.dependencies) {
        dDependencies.emplace_back(static_cast<uint32_t>(sDependency));
    }
    *d = std::make_shared<C2ParamDescriptor>(
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
c2_status_t objcpy(std::unique_ptr<C2StructDescriptor> *d, const StructDescriptor &s) {
    C2Param::CoreIndex dIndex = C2Param::CoreIndex(static_cast<uint32_t>(s.type));
    std::vector<C2FieldDescriptor> dFields;
    dFields.reserve(s.fields.size());
    for (const auto &sField : s.fields) {
        C2FieldDescriptor dField = {
            static_cast<uint32_t>(sField.type),
            sField.length,
            sField.name,
            sField.fieldId.offset,
            sField.fieldId.size };
        C2FieldDescriptor::NamedValuesType namedValues;
        namedValues.reserve(sField.namedValues.size());
        for (const auto& sNamedValue : sField.namedValues) {
            namedValues.emplace_back(
                sNamedValue.name,
                C2Value::Primitive(static_cast<uint64_t>(sNamedValue.value)));
        }
        _C2ParamInspector::AddNamedValues(dField, std::move(namedValues));
        dFields.emplace_back(dField);
    }
    *d = std::make_unique<C2StructDescriptor>(
            _C2ParamInspector::CreateStructDescriptor(dIndex, std::move(dFields)));
    return C2_OK;
}

namespace /* unnamed */ {

// Find or add a hidl BaseBlock object from a given C2Handle* to a list and an
// associated map.
// Note: The handle is not cloned.
Status _addBaseBlock(
        uint32_t* index,
        const C2Handle* handle,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    if (!handle) {
        ALOGE("addBaseBlock called on a null C2Handle.");
        return Status::BAD_VALUE;
    }
    auto it = baseBlockIndices->find(handle);
    if (it != baseBlockIndices->end()) {
        *index = it->second;
    } else {
        *index = baseBlocks->size();
        baseBlockIndices->emplace(handle, *index);
        baseBlocks->emplace_back();

        BaseBlock &dBaseBlock = baseBlocks->back();
        dBaseBlock.type = BaseBlock::Type::NATIVE;
        // This does not clone the handle.
        dBaseBlock.nativeBlock =
                reinterpret_cast<const native_handle_t*>(handle);

    }
    return Status::OK;
}

// Find or add a hidl BaseBlock object from a given BufferPoolData to a list and
// an associated map.
Status _addBaseBlock(
        uint32_t* index,
        const std::shared_ptr<BufferPoolData> bpData,
        BufferPoolSender* bufferPoolSender,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    if (!bpData) {
        ALOGE("addBaseBlock called on a null BufferPoolData.");
        return Status::BAD_VALUE;
    }
    auto it = baseBlockIndices->find(bpData.get());
    if (it != baseBlockIndices->end()) {
        *index = it->second;
    } else {
        *index = baseBlocks->size();
        baseBlockIndices->emplace(bpData.get(), *index);
        baseBlocks->emplace_back();

        BaseBlock &dBaseBlock = baseBlocks->back();
        dBaseBlock.type = BaseBlock::Type::POOLED;

        if (bufferPoolSender) {
            ResultStatus bpStatus = bufferPoolSender->send(
                    bpData,
                    &dBaseBlock.pooledBlock);

            if (bpStatus != ResultStatus::OK) {
                ALOGE("Failed to send buffer with BufferPool. Error: %d.",
                        static_cast<int>(bpStatus));
                return Status::BAD_VALUE;
            }
        }
    }
    return Status::OK;
}

Status addBaseBlock(
        uint32_t* index,
        const C2Handle* handle,
        const std::shared_ptr<const _C2BlockPoolData>& blockPoolData,
        BufferPoolSender* bufferPoolSender,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    if (!blockPoolData) {
        // No BufferPoolData ==> NATIVE block.
        return _addBaseBlock(
                index, handle,
                baseBlocks, baseBlockIndices);
    }
    switch (blockPoolData->getType()) {
    case _C2BlockPoolData::TYPE_BUFFERPOOL: {
            // BufferPoolData
            std::shared_ptr<BufferPoolData> bpData;
            if (!_C2BlockFactory::GetBufferPoolData(blockPoolData, &bpData)
                    || !bpData) {
                ALOGE("BufferPoolData unavailable in a block.");
                return Status::BAD_VALUE;
            }
            return _addBaseBlock(
                    index, bpData,
                    bufferPoolSender, baseBlocks, baseBlockIndices);
        }
    case _C2BlockPoolData::TYPE_BUFFERQUEUE:
        // Do the same thing as a NATIVE block.
        return _addBaseBlock(
                index, handle,
                baseBlocks, baseBlockIndices);
    default:
        ALOGE("Unknown C2BlockPoolData type.");
        return Status::BAD_VALUE;
    }
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
        BufferPoolSender* bufferPoolSender,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    std::shared_ptr<const _C2BlockPoolData> bpData =
            _C2BlockFactory::GetLinearBlockPoolData(s);
    Status status = addBaseBlock(&d->index, s.handle(), bpData,
            bufferPoolSender, baseBlocks, baseBlockIndices);
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
        BufferPoolSender* bufferPoolSender,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    std::shared_ptr<const _C2BlockPoolData> bpData =
            _C2BlockFactory::GetGraphicBlockPoolData(s);
    Status status = addBaseBlock(&d->index, s.handle(), bpData,
            bufferPoolSender, baseBlocks, baseBlockIndices);

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
        BufferPoolSender* bufferPoolSender,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    Status status;
    d->blocks.resize(
            s.linearBlocks().size() +
            s.graphicBlocks().size());
    size_t i = 0;
    for (const C2ConstLinearBlock& linearBlock : s.linearBlocks()) {
        Block& dBlock = d->blocks[i++];
        status = objcpy(
                &dBlock, linearBlock,
                bufferPoolSender, baseBlocks, baseBlockIndices);
        if (status != Status::OK) {
            return status;
        }
    }
    for (const C2ConstGraphicBlock& graphicBlock : s.graphicBlocks()) {
        Block& dBlock = d->blocks[i++];
        status = objcpy(
                &dBlock, graphicBlock,
                bufferPoolSender, baseBlocks, baseBlockIndices);
        if (status != Status::OK) {
            return status;
        }
    }
    return Status::OK;
}

// C2Buffer -> Buffer
Status objcpy(Buffer* d, const C2Buffer& s,
        BufferPoolSender* bufferPoolSender,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    Status status = createParamsBlob(&d->info, s.info());
    if (status != Status::OK) {
        return status;
    }
    return objcpy(d, s.data(), bufferPoolSender, baseBlocks, baseBlockIndices);
}

// C2InfoBuffer -> InfoBuffer
Status objcpy(InfoBuffer* d, const C2InfoBuffer& s,
        BufferPoolSender* bufferPoolSender,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    // TODO: C2InfoBuffer is not implemented.
    (void)d;
    (void)s;
    (void)bufferPoolSender;
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
        BufferPoolSender* bufferPoolSender,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    d->flags = static_cast<hidl_bitfield<FrameData::Flags>>(s.flags);
    objcpy(&d->ordinal, s.ordinal);

    Status status;
    d->buffers.resize(s.buffers.size());
    size_t i = 0;
    for (const std::shared_ptr<C2Buffer>& sBuffer : s.buffers) {
        Buffer& dBuffer = d->buffers[i++];
        if (!sBuffer) {
            // A null (pointer to) C2Buffer corresponds to a Buffer with empty
            // info and blocks.
            dBuffer.info.resize(0);
            dBuffer.blocks.resize(0);
            continue;
        }
        status = objcpy(
                &dBuffer, *sBuffer,
                bufferPoolSender, baseBlocks, baseBlockIndices);
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
        status = objcpy(&dInfoBuffer, *sInfoBuffer,
                bufferPoolSender, baseBlocks, baseBlockIndices);
        if (status != Status::OK) {
            return status;
        }
    }

    return status;
}

} // unnamed namespace

// DefaultBufferPoolSender's implementation

DefaultBufferPoolSender::DefaultBufferPoolSender(
        const sp<IClientManager>& receiverManager,
        std::chrono::steady_clock::duration refreshInterval)
    : mReceiverManager(receiverManager),
      mSourceConnectionId(0),
      mLastSent(std::chrono::steady_clock::now()),
      mRefreshInterval(refreshInterval) {
}

void DefaultBufferPoolSender::setReceiver(
        const sp<IClientManager>& receiverManager,
        std::chrono::steady_clock::duration refreshInterval) {
    std::lock_guard<std::mutex> lock(mMutex);
    if (mReceiverManager != receiverManager) {
        mReceiverManager = receiverManager;
    }
    mRefreshInterval = refreshInterval;
}

ResultStatus DefaultBufferPoolSender::send(
        const std::shared_ptr<BufferPoolData>& bpData,
        BufferStatusMessage* bpMessage) {
    if (!mReceiverManager) {
        ALOGE("No access to receiver's BufferPool.");
        return ResultStatus::NOT_FOUND;
    }
    ResultStatus rs;
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mSenderManager) {
        mSenderManager = ClientManager::getInstance();
        if (!mSenderManager) {
            ALOGE("Failed to retrieve local BufferPool ClientManager.");
            return ResultStatus::CRITICAL_ERROR;
        }
    }
    int64_t connectionId = bpData->mConnectionId;
    std::chrono::steady_clock::time_point now =
            std::chrono::steady_clock::now();
    std::chrono::steady_clock::duration interval = now - mLastSent;
    if (mSourceConnectionId == 0 ||
            mSourceConnectionId != connectionId ||
            interval > mRefreshInterval) {
        // Initialize the bufferpool connection.
        mSourceConnectionId = connectionId;
        if (mSourceConnectionId == 0) {
            return ResultStatus::CRITICAL_ERROR;
        }

        int64_t receiverConnectionId;
        rs = mSenderManager->registerSender(mReceiverManager,
                                            connectionId,
                                            &receiverConnectionId);
        if ((rs != ResultStatus::OK) && (rs != ResultStatus::ALREADY_EXISTS)) {
            ALOGW("registerSender -- returned error: %d.",
                    static_cast<int>(rs));
            return rs;
        } else {
            ALOGV("registerSender -- succeeded.");
            mReceiverConnectionId = receiverConnectionId;
        }
    }

    uint64_t transactionId;
    int64_t timestampUs;
    rs = mSenderManager->postSend(
            mReceiverConnectionId, bpData, &transactionId, &timestampUs);
    if (rs != ResultStatus::OK) {
        ALOGE("ClientManager::postSend -- returned error: %d.",
                static_cast<int>(rs));
        return rs;
    }
    if (!bpMessage) {
        ALOGE("Null output parameter for BufferStatusMessage.");
        return ResultStatus::CRITICAL_ERROR;
    }
    bpMessage->connectionId = mReceiverConnectionId;
    bpMessage->bufferId = bpData->mId;
    bpMessage->transactionId = transactionId;
    bpMessage->timestampUs = timestampUs;
    mLastSent = now;
    return rs;
}

// std::list<std::unique_ptr<C2Work>> -> WorkBundle
Status objcpy(
        WorkBundle* d,
        const std::list<std::unique_ptr<C2Work>>& s,
        BufferPoolSender* bufferPoolSender) {
    Status status = Status::OK;

    // baseBlocks holds a list of BaseBlock objects that Blocks can refer to.
    std::list<BaseBlock> baseBlocks;

    // baseBlockIndices maps a raw pointer to native_handle_t or BufferPoolData
    // inside baseBlocks to the corresponding index into baseBlocks. The keys
    // (pointers) are used to identify blocks that have the same "base block" in
    // s, a list of C2Work objects. Because baseBlocks will be copied into a
    // hidl_vec eventually, the values of baseBlockIndices are zero-based
    // integer indices instead of list iterators.
    //
    // Note that the pointers can be raw because baseBlockIndices has a shorter
    // lifespan than all of base blocks.
    std::map<const void*, uint32_t> baseBlockIndices;

    d->works.resize(s.size());
    size_t i = 0;
    for (const std::unique_ptr<C2Work>& sWork : s) {
        Work &dWork = d->works[i++];
        if (!sWork) {
            ALOGW("Null C2Work encountered.");
            continue;
        }
        status = objcpy(&dWork.input, sWork->input,
                bufferPoolSender, &baseBlocks, &baseBlockIndices);
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
                    bufferPoolSender, &baseBlocks, &baseBlockIndices);
            if (status != Status::OK) {
                return status;
            }
        }
        dWork.workletProcessed = sWork->workletsProcessed > 0;
        dWork.result = static_cast<Status>(sWork->result);
    }

    // Copy std::list<BaseBlock> to hidl_vec<BaseBlock>.
    {
        d->baseBlocks.resize(baseBlocks.size());
        size_t i = 0;
        for (const BaseBlock& baseBlock : baseBlocks) {
            d->baseBlocks[i++] = baseBlock;
        }
    }

    return Status::OK;
}

namespace /* unnamed */ {

struct C2BaseBlock {
    enum type_t {
        LINEAR,
        GRAPHIC,
    };
    type_t type;
    std::shared_ptr<C2LinearBlock> linear;
    std::shared_ptr<C2GraphicBlock> graphic;
};

// hidl_handle -> C2Fence
// Note: File descriptors are not duplicated. The original file descriptor must
// not be closed before the transaction is complete.
c2_status_t objcpy(C2Fence* d, const hidl_handle& s) {
    // TODO: Implement.
    (void)s;
    *d = C2Fence();
    return C2_OK;
}

// C2LinearBlock, vector<C2Param*>, C2Fence -> C2Buffer
c2_status_t createLinearBuffer(
        std::shared_ptr<C2Buffer>* buffer,
        const std::shared_ptr<C2LinearBlock>& block,
        const std::vector<C2Param*>& meta,
        const C2Fence& fence) {
    // Check the block meta. It should have exactly 1 C2Info:
    // C2Hidl_RangeInfo.
    if ((meta.size() != 1) || !meta[0]) {
        ALOGE("Invalid block metadata for ion block.");
        return C2_BAD_VALUE;
    }
    if (meta[0]->size() != sizeof(C2Hidl_RangeInfo)) {
        ALOGE("Invalid block metadata for ion block: range.");
        return C2_BAD_VALUE;
    }
    C2Hidl_RangeInfo *rangeInfo =
            reinterpret_cast<C2Hidl_RangeInfo*>(meta[0]);

    // Create C2Buffer from C2LinearBlock.
    *buffer = C2Buffer::CreateLinearBuffer(block->share(
            rangeInfo->offset, rangeInfo->length,
            fence));
    if (!(*buffer)) {
        ALOGE("Cannot create a linear buffer.");
        return C2_BAD_VALUE;
    }
    return C2_OK;
}

// C2GraphicBlock, vector<C2Param*>, C2Fence -> C2Buffer
c2_status_t createGraphicBuffer(
        std::shared_ptr<C2Buffer>* buffer,
        const std::shared_ptr<C2GraphicBlock>& block,
        const std::vector<C2Param*>& meta,
        const C2Fence& fence) {
    // Check the block meta. It should have exactly 1 C2Info:
    // C2Hidl_RectInfo.
    if ((meta.size() != 1) || !meta[0]) {
        ALOGE("Invalid block metadata for graphic block.");
        return C2_BAD_VALUE;
    }
    if (meta[0]->size() != sizeof(C2Hidl_RectInfo)) {
        ALOGE("Invalid block metadata for graphic block: crop rect.");
        return C2_BAD_VALUE;
    }
    C2Hidl_RectInfo *rectInfo =
            reinterpret_cast<C2Hidl_RectInfo*>(meta[0]);

    // Create C2Buffer from C2GraphicBlock.
    *buffer = C2Buffer::CreateGraphicBuffer(block->share(
            C2Rect(rectInfo->width, rectInfo->height).
            at(rectInfo->left, rectInfo->top),
            fence));
    if (!(*buffer)) {
        ALOGE("Cannot create a graphic buffer.");
        return C2_BAD_VALUE;
    }
    return C2_OK;
}

// Buffer -> C2Buffer
// Note: The native handles will be cloned.
c2_status_t objcpy(std::shared_ptr<C2Buffer>* d, const Buffer& s,
        const std::vector<C2BaseBlock>& baseBlocks) {
    c2_status_t status;
    *d = nullptr;

    // Currently, a non-null C2Buffer must contain exactly 1 block.
    if (s.blocks.size() == 0) {
        return C2_OK;
    } else if (s.blocks.size() != 1) {
        ALOGE("Currently, a C2Buffer must contain exactly 1 block.");
        return C2_BAD_VALUE;
    }

    const Block &sBlock = s.blocks[0];
    if (sBlock.index >= baseBlocks.size()) {
        ALOGE("Index into baseBlocks is out of range.");
        return C2_BAD_VALUE;
    }
    const C2BaseBlock &baseBlock = baseBlocks[sBlock.index];

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
    switch (baseBlock.type) {
    case C2BaseBlock::LINEAR:
        status = createLinearBuffer(d, baseBlock.linear, sBlockMeta, dFence);
        break;
    case C2BaseBlock::GRAPHIC:
        status = createGraphicBuffer(d, baseBlock.graphic, sBlockMeta, dFence);
        break;
    default:
        ALOGE("Invalid BaseBlock type.");
        return C2_BAD_VALUE;
    }
    if (status != C2_OK) {
        return status;
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
        const std::vector<C2BaseBlock>& baseBlocks) {
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

// BaseBlock -> C2BaseBlock
c2_status_t objcpy(C2BaseBlock* d, const BaseBlock& s) {
    switch (s.type) {
    case BaseBlock::Type::NATIVE: {
            native_handle_t* sHandle =
                    native_handle_clone(s.nativeBlock);
            if (sHandle == nullptr) {
                ALOGE("Null native handle in a block.");
                return C2_BAD_VALUE;
            }
            const C2Handle *sC2Handle =
                    reinterpret_cast<const C2Handle*>(sHandle);

            d->linear = _C2BlockFactory::CreateLinearBlock(sC2Handle);
            if (d->linear) {
                d->type = C2BaseBlock::LINEAR;
                return C2_OK;
            }

            d->graphic = _C2BlockFactory::CreateGraphicBlock(sC2Handle);
            if (d->graphic) {
                d->type = C2BaseBlock::GRAPHIC;
                return C2_OK;
            }

            ALOGE("Unknown handle type in native BaseBlock.");
            if (sHandle) {
                native_handle_close(sHandle);
                native_handle_delete(sHandle);
            }
            return C2_BAD_VALUE;
        }
    case BaseBlock::Type::POOLED: {
            const BufferStatusMessage &bpMessage =
                    s.pooledBlock;
            sp<ClientManager> bp = ClientManager::getInstance();
            std::shared_ptr<BufferPoolData> bpData;
            native_handle_t *cHandle;
            ResultStatus bpStatus = bp->receive(
                    bpMessage.connectionId,
                    bpMessage.transactionId,
                    bpMessage.bufferId,
                    bpMessage.timestampUs,
                    &cHandle,
                    &bpData);
            if (bpStatus != ResultStatus::OK) {
                ALOGE("Failed to receive buffer from bufferpool -- "
                        "resultStatus = %d",
                        static_cast<int>(bpStatus));
                return toC2Status(bpStatus);
            } else if (!bpData) {
                ALOGE("No data in bufferpool transaction.");
                return C2_BAD_VALUE;
            }

            d->linear = _C2BlockFactory::CreateLinearBlock(cHandle, bpData);
            if (d->linear) {
                d->type = C2BaseBlock::LINEAR;
                return C2_OK;
            }

            d->graphic = _C2BlockFactory::CreateGraphicBlock(cHandle, bpData);
            if (d->graphic) {
                d->type = C2BaseBlock::GRAPHIC;
                return C2_OK;
            }

            ALOGE("Unknown handle type in pooled BaseBlock.");
            return C2_BAD_VALUE;
        }
    default:
        ALOGE("Corrupted BaseBlock type: %d", static_cast<int>(s.type));
        return C2_BAD_VALUE;
    }
}

} // unnamed namespace

// WorkBundle -> std::list<std::unique_ptr<C2Work>>
c2_status_t objcpy(std::list<std::unique_ptr<C2Work>>* d, const WorkBundle& s) {
    c2_status_t status;

    // Convert BaseBlocks to C2BaseBlocks.
    std::vector<C2BaseBlock> dBaseBlocks(s.baseBlocks.size());
    for (size_t i = 0; i < s.baseBlocks.size(); ++i) {
        status = objcpy(&dBaseBlocks[i], s.baseBlocks[i]);
        if (status != C2_OK) {
            return status;
        }
    }

    d->clear();
    for (const Work& sWork : s.works) {
        d->emplace_back(std::make_unique<C2Work>());
        C2Work& dWork = *d->back();

        // input
        status = objcpy(&dWork.input, sWork.input, dBaseBlocks);
        if (status != C2_OK) {
            ALOGE("Error constructing C2Work's input.");
            return C2_BAD_VALUE;
        }

        // worklet(s)
        dWork.worklets.clear();
        // TODO: Currently, tunneling is not supported.
        if (sWork.workletProcessed) {
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
                std::unique_ptr<C2SettingResult> dFailure;
                status = objcpy(&dFailure, sFailure);
                if (status != C2_OK) {
                    ALOGE("Failed to create C2SettingResult in C2Worklet.");
                    return C2_BAD_VALUE;
                }
                dWorklet->failures.emplace_back(std::move(dFailure));
            }
            // output
            status = objcpy(&dWorklet->output, sWorklet.output, dBaseBlocks);
            if (status != C2_OK) {
                ALOGE("Failed to create output C2FrameData.");
                return C2_BAD_VALUE;
            }
            dWork.worklets.emplace_back(std::move(dWorklet));
        } else {
            dWork.worklets.emplace_back(std::make_unique<C2Worklet>());
            dWork.workletsProcessed = 0;
        }

        // result
        dWork.result = static_cast<c2_status_t>(sWork.result);
    }

    return C2_OK;
}

constexpr size_t PARAMS_ALIGNMENT = 8;  // 64-bit alignment
static_assert(PARAMS_ALIGNMENT % alignof(C2Param) == 0, "C2Param alignment mismatch");
static_assert(PARAMS_ALIGNMENT % alignof(C2Info) == 0, "C2Param alignment mismatch");
static_assert(PARAMS_ALIGNMENT % alignof(C2Tuning) == 0, "C2Param alignment mismatch");

// Params -> std::vector<C2Param*>
c2_status_t parseParamsBlob(std::vector<C2Param*> *params, const hidl_vec<uint8_t> &blob) {
    // assuming blob is const here
    size_t size = blob.size();
    size_t ix = 0;
    const uint8_t *data = blob.data();
    C2Param *p = nullptr;

    do {
        p = C2ParamUtils::ParseFirst(data + ix, size - ix);
        if (p) {
            params->emplace_back(p);
            ix += p->size();
            ix = align(ix, PARAMS_ALIGNMENT);
        }
    } while (p);

    return ix == size ? C2_OK : C2_BAD_VALUE;
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
        if (!p) {
            continue;
        }
        size += p->size();
        size = align(size, PARAMS_ALIGNMENT);
    }
    blob->resize(size);
    size_t ix = 0;
    for (const auto &p : params) {
        if (!p) {
            continue;
        }
        // NEVER overwrite even if param values (e.g. size) changed
        size_t paramSize = std::min(p->size(), size - ix);
        std::copy(
                reinterpret_cast<const uint8_t*>(&*p),
                reinterpret_cast<const uint8_t*>(&*p) + paramSize,
                &(*blob)[ix]);
        ix += paramSize;
        ix = align(ix, PARAMS_ALIGNMENT);
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

// Params -> std::vector<std::unique_ptr<C2Param>>
c2_status_t copyParamsFromBlob(
        std::vector<std::unique_ptr<C2Param>>* params,
        Params blob) {
    std::vector<C2Param*> paramPointers;
    c2_status_t status = parseParamsBlob(&paramPointers, blob);
    if (status != C2_OK) {
        ALOGE("copyParamsFromBlob -- blob parsing failed.");
        return status;
    }
    params->resize(paramPointers.size());
    size_t i = 0;
    for (C2Param* const& paramPointer : paramPointers) {
        if (!paramPointer) {
            ALOGE("copyParamsFromBlob -- corrupted params blob.");
            return C2_BAD_VALUE;
        }
        (*params)[i++] = C2Param::Copy(*paramPointer);
    }
    return C2_OK;
}

// Params -> update std::vector<std::unique_ptr<C2Param>>
c2_status_t updateParamsFromBlob(
        const std::vector<C2Param*>& params,
        const Params& blob) {
    std::unordered_map<uint32_t, C2Param*> index2param;
    for (C2Param* const& param : params) {
        if (!param) {
            ALOGE("updateParamsFromBlob -- corrupted input params.");
            return C2_BAD_VALUE;
        }
        if (index2param.find(param->index()) == index2param.end()) {
            index2param.emplace(param->index(), param);
        }
    }

    std::vector<C2Param*> paramPointers;
    c2_status_t status = parseParamsBlob(&paramPointers, blob);
    if (status != C2_OK) {
        ALOGE("updateParamsFromBlob -- blob parsing failed.");
        return status;
    }

    for (C2Param* const& paramPointer : paramPointers) {
        if (!paramPointer) {
            ALOGE("updateParamsFromBlob -- corrupted param in blob.");
            return C2_BAD_VALUE;
        }
        decltype(index2param)::iterator i = index2param.find(
                paramPointer->index());
        if (i == index2param.end()) {
            ALOGW("updateParamsFromBlob -- unseen param index.");
            continue;
        }
        if (!i->second->updateFrom(*paramPointer)) {
            ALOGE("updateParamsFromBlob -- mismatching sizes: "
                    "%u vs %u (index = %u).",
                    static_cast<unsigned>(params.size()),
                    static_cast<unsigned>(paramPointer->size()),
                    static_cast<unsigned>(i->first));
            return C2_BAD_VALUE;
        }
    }
    return C2_OK;
}

// Convert BufferPool ResultStatus to c2_status_t.
c2_status_t toC2Status(ResultStatus rs) {
    switch (rs) {
    case ResultStatus::OK:
        return C2_OK;
    case ResultStatus::NO_MEMORY:
        return C2_NO_MEMORY;
    case ResultStatus::ALREADY_EXISTS:
        return C2_DUPLICATE;
    case ResultStatus::NOT_FOUND:
        return C2_NOT_FOUND;
    case ResultStatus::CRITICAL_ERROR:
        return C2_CORRUPTED;
    default:
        ALOGW("Unrecognized BufferPool ResultStatus: %d", static_cast<int>(rs));
        return C2_CORRUPTED;
    }
}

namespace /* unnamed */ {

// Create a GraphicBuffer object from a graphic block.
sp<GraphicBuffer> createGraphicBuffer(const C2ConstGraphicBlock& block) {
    uint32_t width;
    uint32_t height;
    uint32_t format;
    uint64_t usage;
    uint32_t stride;
    uint32_t generation;
    uint64_t bqId;
    int32_t bqSlot;
    _UnwrapNativeCodec2GrallocMetadata(
            block.handle(), &width, &height, &format, &usage,
            &stride, &generation, &bqId, reinterpret_cast<uint32_t*>(&bqSlot));
    native_handle_t *grallocHandle =
            UnwrapNativeCodec2GrallocHandle(block.handle());
    sp<GraphicBuffer> graphicBuffer =
            new GraphicBuffer(grallocHandle,
                              GraphicBuffer::CLONE_HANDLE,
                              width, height, format,
                              1, usage, stride);
    native_handle_delete(grallocHandle);
    return graphicBuffer;
}

template <typename BlockProcessor>
void forEachBlock(C2FrameData& frameData,
                  BlockProcessor process) {
    for (const std::shared_ptr<C2Buffer>& buffer : frameData.buffers) {
        if (buffer) {
            for (const C2ConstGraphicBlock& block :
                    buffer->data().graphicBlocks()) {
                process(block);
            }
        }
    }
}

template <typename BlockProcessor>
void forEachBlock(const std::list<std::unique_ptr<C2Work>>& workList,
                  BlockProcessor process,
                  bool processInput, bool processOutput) {
    for (const std::unique_ptr<C2Work>& work : workList) {
        if (!work) {
            continue;
        }
        if (processInput) {
            forEachBlock(work->input, process);
        }
        if (processOutput) {
            for (const std::unique_ptr<C2Worklet>& worklet : work->worklets) {
                if (worklet) {
                    forEachBlock(worklet->output,
                                 process);
                }
            }
        }
    }
}

sp<HGraphicBufferProducer> getHgbp(const sp<IGraphicBufferProducer>& igbp) {
    sp<HGraphicBufferProducer> hgbp = igbp->getHalInterface();
    return hgbp ? hgbp :
            new TWGraphicBufferProducer<HGraphicBufferProducer>(igbp);
}

} // unnamed namespace

status_t attachToBufferQueue(const C2ConstGraphicBlock& block,
                             const sp<IGraphicBufferProducer>& igbp,
                             uint32_t generation,
                             int32_t* bqSlot) {
    if (!igbp) {
        ALOGW("attachToBufferQueue -- null producer.");
        return NO_INIT;
    }

    sp<GraphicBuffer> graphicBuffer = createGraphicBuffer(block);
    graphicBuffer->setGenerationNumber(generation);

    ALOGV("attachToBufferQueue -- attaching buffer: "
            "block dimension %ux%u, "
            "graphicBuffer dimension %ux%u, "
            "format %#x, usage %#llx, stride %u, generation %u.",
            static_cast<unsigned>(block.width()),
            static_cast<unsigned>(block.height()),
            static_cast<unsigned>(graphicBuffer->getWidth()),
            static_cast<unsigned>(graphicBuffer->getHeight()),
            static_cast<unsigned>(graphicBuffer->getPixelFormat()),
            static_cast<unsigned long long>(graphicBuffer->getUsage()),
            static_cast<unsigned>(graphicBuffer->getStride()),
            static_cast<unsigned>(graphicBuffer->getGenerationNumber()));

    status_t result = igbp->attachBuffer(bqSlot, graphicBuffer);
    if (result != OK) {
        ALOGW("attachToBufferQueue -- attachBuffer failed. Error code = %d",
                static_cast<int>(result));
        return false;
    }
    ALOGV("attachToBufferQueue -- attachBuffer returned slot %d",
            static_cast<int>(*bqSlot));
    return true;
}

bool getBufferQueueAssignment(const C2ConstGraphicBlock& block,
                              uint32_t* generation,
                              uint64_t* bqId,
                              int32_t* bqSlot) {
    return _C2BlockFactory::GetBufferQueueData(
            _C2BlockFactory::GetGraphicBlockPoolData(block),
            generation, bqId, bqSlot);
}

bool yieldBufferQueueBlock(const C2ConstGraphicBlock& block) {
    std::shared_ptr<_C2BlockPoolData> data =
            _C2BlockFactory::GetGraphicBlockPoolData(block);
    if (data && _C2BlockFactory::GetBufferQueueData(data)) {
        _C2BlockFactory::YieldBlockToBufferQueue(data);
        return true;
    }
    return false;
}

void yieldBufferQueueBlocks(
        const std::list<std::unique_ptr<C2Work>>& workList,
        bool processInput, bool processOutput) {
    forEachBlock(workList, yieldBufferQueueBlock, processInput, processOutput);
}

bool holdBufferQueueBlock(const C2ConstGraphicBlock& block,
                            const sp<IGraphicBufferProducer>& igbp,
                            uint64_t bqId,
                            uint32_t generation) {
    std::shared_ptr<_C2BlockPoolData> data =
            _C2BlockFactory::GetGraphicBlockPoolData(block);
    if (!data) {
        return false;
    }

    uint32_t oldGeneration;
    uint64_t oldId;
    int32_t oldSlot;
    // If the block is not bufferqueue-based, do nothing.
    if (!_C2BlockFactory::GetBufferQueueData(
            data, &oldGeneration, &oldId, &oldSlot) ||
            (oldId == 0)) {
        return false;
    }

    // If the block's bqId is the same as the desired bqId, just hold.
    if ((oldId == bqId) && (oldGeneration == generation)) {
        ALOGV("holdBufferQueueBlock -- import without attaching: "
                "bqId %llu, bqSlot %d, generation %u.",
                static_cast<long long unsigned>(oldId),
                static_cast<int>(oldSlot),
                static_cast<unsigned>(generation));
        _C2BlockFactory::HoldBlockFromBufferQueue(data, getHgbp(igbp));
        return true;
    }

    // Otherwise, attach to the given igbp, which must not be null.
    if (!igbp) {
        return false;
    }

    int32_t bqSlot;
    status_t result = attachToBufferQueue(block, igbp, generation, &bqSlot);

    if (result != OK) {
        ALOGE("holdBufferQueueBlock -- fail to attach: "
                "target bqId %llu, generation %u.",
                static_cast<long long unsigned>(bqId),
                static_cast<unsigned>(generation));

        return false;
    }

    ALOGV("holdBufferQueueBlock -- attached: "
            "bqId %llu, bqSlot %d, generation %u.",
            static_cast<long long unsigned>(bqId),
            static_cast<int>(bqSlot),
            static_cast<unsigned>(generation));
    _C2BlockFactory::AssignBlockToBufferQueue(
            data, getHgbp(igbp), bqId, bqSlot, true);
    return true;
}

void holdBufferQueueBlocks(const std::list<std::unique_ptr<C2Work>>& workList,
                           const sp<IGraphicBufferProducer>& igbp,
                           uint64_t bqId,
                           uint32_t generation,
                           bool forInput) {
    forEachBlock(workList,
                 std::bind(holdBufferQueueBlock,
                           std::placeholders::_1, igbp, bqId, generation),
                 forInput, !forInput);
}

}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android

