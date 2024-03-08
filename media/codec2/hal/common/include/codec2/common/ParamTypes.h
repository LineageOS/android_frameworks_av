/*
 * Copyright 2018 The Android Open Source Project
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

#ifndef CODEC2_COMMON_PARAM_TYPES_H
#define CODEC2_COMMON_PARAM_TYPES_H

#ifndef LOG_TAG
#define LOG_TAG "Codec2-ParamTypes"
#endif
#include <android-base/logging.h>

#include <log/log_safetynet.h>
#include <media/stagefright/foundation/AUtils.h>

#include <C2Component.h>
#include <C2Param.h>
#include <C2ParamInternal.h>
#include <util/C2ParamUtils.h>

#include <algorithm>
#include <unordered_map>

namespace android {

template <typename EnumClass>
typename std::underlying_type<EnumClass>::type underlying_value(EnumClass x) {
    return static_cast<typename std::underlying_type<EnumClass>::type>(x);
}

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

// {offset, size} -> FieldId
template <typename FieldId>
void SetFieldId(FieldId *d, uint32_t offset, uint32_t size) {
    d->offset = offset;
    d->size = size;
}

// FieldId -> offset
template <typename FieldId>
uint32_t GetOffsetFromFieldId(const FieldId &s) {
    return s.offset;
}

// FieldId -> size
template <typename FieldId>
uint32_t GetSizeFromFieldId(const FieldId &s) {
    return s.size;
}

// C2ParamField -> ParamField
template <typename ParamField>
bool objcpy(ParamField *d, const C2ParamField &s) {
    d->index = static_cast<decltype(d->index)>(_C2ParamInspector::GetIndex(s));
    SetFieldId(
            &d->fieldId,
            static_cast<uint32_t>(_C2ParamInspector::GetOffset(s)),
            static_cast<uint32_t>(_C2ParamInspector::GetSize(s)));
    return true;
}

template <typename ParamField>
struct C2ParamFieldBuilder : public C2ParamField {
    C2ParamFieldBuilder() : C2ParamField(
            static_cast<C2Param::Index>(static_cast<uint32_t>(0)), 0, 0) {
    }
    // ParamField -> C2ParamField
    C2ParamFieldBuilder(const ParamField& s) : C2ParamField(
            static_cast<C2Param::Index>(static_cast<uint32_t>(s.index)),
            static_cast<uint32_t>(GetOffsetFromFieldId(s.fieldId)),
            static_cast<uint32_t>(GetSizeFromFieldId(s.fieldId))) {
    }
};

// C2WorkOrdinalStruct -> WorkOrdinal
template <typename WorkOrdinal>
bool objcpy(WorkOrdinal *d, const C2WorkOrdinalStruct &s) {
    d->frameIndex = static_cast<uint64_t>(s.frameIndex.peeku());
    d->timestampUs = static_cast<uint64_t>(s.timestamp.peeku());
    d->customOrdinal = static_cast<uint64_t>(s.customOrdinal.peeku());
    return true;
}

// WorkOrdinal -> C2WorkOrdinalStruct
template <typename WorkOrdinal>
bool objcpy(C2WorkOrdinalStruct *d, const WorkOrdinal &s) {
    d->frameIndex = c2_cntr64_t(s.frameIndex);
    d->timestamp = c2_cntr64_t(s.timestampUs);
    d->customOrdinal = c2_cntr64_t(s.customOrdinal);
    return true;
}

// C2FieldSupportedValues::range's type -> ValueRange
template <typename ValueRange>
bool objcpy(
        ValueRange* d,
        const decltype(C2FieldSupportedValues::range)& s) {
    d->min    = static_cast<decltype(d->min)>(s.min.u64);
    d->max    = static_cast<decltype(d->max)>(s.max.u64);
    d->step   = static_cast<decltype(d->step)>(s.step.u64);
    d->num    = static_cast<decltype(d->num)>(s.num.u64);
    d->denom  = static_cast<decltype(d->denom)>(s.denom.u64);
    return true;
}

// ValueRange -> C2FieldSupportedValues::range's type
template <typename ValueRange>
bool objcpy(
        decltype(C2FieldSupportedValues::range)* d,
        const ValueRange& s) {
    d->min.u64  = static_cast<uint64_t>(s.min);
    d->max.u64  = static_cast<uint64_t>(s.max);
    d->step.u64 = static_cast<uint64_t>(s.step);
    d->num.u64  = static_cast<uint64_t>(s.num);
    d->denom.u64  = static_cast<uint64_t>(s.denom);
    return true;
}

template <typename Status>
void SetStatus(Status *dst, c2_status_t src) {
    *dst = static_cast<Status>(src);
}

template <typename Status>
c2_status_t GetStatus(const Status &status) {
    return static_cast<c2_status_t>(status);
}

// C2FieldSupportedValues -> FieldSupportedValues
template <typename FieldSupportedValues>
bool objcpy(FieldSupportedValues *d, const C2FieldSupportedValues &s);

// FieldSupportedValues -> C2FieldSupportedValues
template <typename FieldSupportedValues>
bool objcpy(C2FieldSupportedValues *d, const FieldSupportedValues &s);

// C2FieldSupportedValuesQuery -> FieldSupportedValuesQuery, FieldSupportedValuesQueryResult
template <typename FieldSupportedValuesQueryPtr>
bool objcpy(
        FieldSupportedValuesQueryPtr dq,
        nullptr_t,
        const C2FieldSupportedValuesQuery& s) {
    static_assert(!std::is_null_pointer_v<FieldSupportedValuesQueryPtr>);
    static_assert(std::is_pointer_v<FieldSupportedValuesQueryPtr>);
    typedef std::remove_pointer_t<FieldSupportedValuesQueryPtr> FieldSupportedValuesQuery;
    if (!dq) {
        return false;
    }
    if (!objcpy(&dq->field, s.field())) {
        LOG(ERROR) << "Invalid C2FieldSupportedValuesQuery::field.";
        return false;
    }
    switch (s.type()) {
    case C2FieldSupportedValuesQuery::POSSIBLE:
        dq->type = FieldSupportedValuesQuery::Type::POSSIBLE;
        break;
    case C2FieldSupportedValuesQuery::CURRENT:
        dq->type = FieldSupportedValuesQuery::Type::CURRENT;
        break;
    default:
        LOG(DEBUG) << "Unrecognized C2FieldSupportedValuesQuery::type_t "
                   << "with underlying value " << underlying_value(s.type())
                   << ".";
        dq->type = static_cast<decltype(dq->type)>(s.type());
    }
    return true;
}

template <typename FieldSupportedValuesQueryResultPtr>
bool objcpy(
        nullptr_t,
        FieldSupportedValuesQueryResultPtr dr,
        const C2FieldSupportedValuesQuery& s) {
    static_assert(!std::is_null_pointer_v<FieldSupportedValuesQueryResultPtr>);
    static_assert(std::is_pointer_v<FieldSupportedValuesQueryResultPtr>);
    if (!dr) {
        return false;
    }
    SetStatus(&dr->status, s.status);
    return objcpy(&dr->values, s.values);
}

template <typename FieldSupportedValuesQueryPtr, typename FieldSupportedValuesQueryResultPtr>
bool objcpy(
        FieldSupportedValuesQueryPtr dq,
        FieldSupportedValuesQueryResultPtr dr,
        const C2FieldSupportedValuesQuery& s) {
    if (!objcpy(dq, nullptr, s)) {
        return false;
    }
    return objcpy(nullptr, dr, s);
}

// FieldSupportedValuesQuery -> C2FieldSupportedValuesQuery
template <typename FieldSupportedValuesQuery>
bool objcpy(
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
        LOG(DEBUG) << "Unrecognized FieldSupportedValuesQuery::Type "
                   << "with underlying value " << underlying_value(s.type)
                   << ".";
        dType = static_cast<C2FieldSupportedValuesQuery::type_t>(s.type);
    }
    *d = C2FieldSupportedValuesQuery(C2ParamFieldBuilder(s.field), dType);
    return true;
}

// FieldSupportedValuesQuery, FieldSupportedValuesQueryResult ->
// C2FieldSupportedValuesQuery
template <typename FieldSupportedValuesQuery,
          typename FieldSupportedValuesQueryResult>
bool objcpy(
        C2FieldSupportedValuesQuery* d,
        const FieldSupportedValuesQuery& sq,
        const FieldSupportedValuesQueryResult& sr) {
    if (!objcpy(d, sq)) {
        LOG(ERROR) << "Invalid FieldSupportedValuesQuery.";
        return false;
    }
    d->status = GetStatus(sr.status);
    if (!objcpy(&d->values, sr.values)) {
        LOG(ERROR) << "Invalid FieldSupportedValuesQueryResult::values.";
        return false;
    }
    return true;
}

// C2Component::Traits -> IComponentStore::ComponentTraits
template <typename ComponentTraits>
bool objcpy(
        ComponentTraits *d,
        const C2Component::Traits &s) {
    d->name = s.name;

    switch (s.domain) {
    case C2Component::DOMAIN_VIDEO:
        d->domain = ComponentTraits::Domain::VIDEO;
        break;
    case C2Component::DOMAIN_AUDIO:
        d->domain = ComponentTraits::Domain::AUDIO;
        break;
    case C2Component::DOMAIN_IMAGE:
        d->domain = ComponentTraits::Domain::IMAGE;
        break;
    case C2Component::DOMAIN_OTHER:
        d->domain = ComponentTraits::Domain::OTHER;
        break;
    default:
        LOG(DEBUG) << "Unrecognized C2Component::domain_t "
                   << "with underlying value " << underlying_value(s.domain)
                   << ".";
        d->domain = static_cast<decltype(d->domain)>(s.domain);
    }

    switch (s.kind) {
    case C2Component::KIND_DECODER:
        d->kind = ComponentTraits::Kind::DECODER;
        break;
    case C2Component::KIND_ENCODER:
        d->kind = ComponentTraits::Kind::ENCODER;
        break;
    case C2Component::KIND_OTHER:
        d->kind = ComponentTraits::Kind::OTHER;
        break;
    default:
        LOG(DEBUG) << "Unrecognized C2Component::kind_t "
                   << "with underlying value " << underlying_value(s.kind)
                   << ".";
        d->kind = static_cast<decltype(d->kind)>(s.kind);
    }

    d->rank = static_cast<uint32_t>(s.rank);

    d->mediaType = s.mediaType;

    d->aliases.resize(s.aliases.size());
    for (size_t ix = s.aliases.size(); ix > 0; ) {
        --ix;
        d->aliases[ix] = s.aliases[ix];
    }
    return true;
}

// ComponentTraits -> C2Component::Traits, std::unique_ptr<std::vector<std::string>>
template <typename ComponentTraits>
bool objcpy(
        C2Component::Traits* d,
        const ComponentTraits& s) {
    d->name = s.name.c_str();

    switch (s.domain) {
    case ComponentTraits::Domain::VIDEO:
        d->domain = C2Component::DOMAIN_VIDEO;
        break;
    case ComponentTraits::Domain::AUDIO:
        d->domain = C2Component::DOMAIN_AUDIO;
        break;
    case ComponentTraits::Domain::IMAGE:
        d->domain = C2Component::DOMAIN_IMAGE;
        break;
    case ComponentTraits::Domain::OTHER:
        d->domain = C2Component::DOMAIN_OTHER;
        break;
    default:
        LOG(DEBUG) << "Unrecognized ComponentTraits::Domain "
                   << "with underlying value " << underlying_value(s.domain)
                   << ".";
        d->domain = static_cast<C2Component::domain_t>(s.domain);
    }

    switch (s.kind) {
    case ComponentTraits::Kind::DECODER:
        d->kind = C2Component::KIND_DECODER;
        break;
    case ComponentTraits::Kind::ENCODER:
        d->kind = C2Component::KIND_ENCODER;
        break;
    case ComponentTraits::Kind::OTHER:
        d->kind = C2Component::KIND_OTHER;
        break;
    default:
        LOG(DEBUG) << "Unrecognized ComponentTraits::Kind "
                   << "with underlying value " << underlying_value(s.kind)
                   << ".";
        d->kind = static_cast<C2Component::kind_t>(s.kind);
    }

    d->rank = static_cast<C2Component::rank_t>(s.rank);
    d->mediaType = s.mediaType.c_str();
    d->aliases.resize(s.aliases.size());
    for (size_t i = 0; i < s.aliases.size(); ++i) {
        d->aliases[i] = s.aliases[i];
    }
    return true;
}

// C2ParamFieldValues -> ParamFieldValues
template <typename ParamFieldValues>
bool objcpy(
        ParamFieldValues *d,
        const C2ParamFieldValues &s) {
    if (!objcpy(&d->paramOrField, s.paramOrField)) {
        LOG(ERROR) << "Invalid C2ParamFieldValues::paramOrField.";
        return false;
    }
    if (s.values) {
        d->values.resize(1);
        if (!objcpy(&d->values[0], *s.values)) {
            LOG(ERROR) << "Invalid C2ParamFieldValues::values.";
            return false;
        }
        return true;
    }
    d->values.resize(0);
    return true;
}

// ParamFieldValues -> C2ParamFieldValues
template <typename ParamFieldValues>
bool objcpy(
        C2ParamFieldValues *d,
        const ParamFieldValues &s) {
    d->paramOrField = C2ParamFieldBuilder(s.paramOrField);
    if (s.values.size() == 1) {
        d->values = std::make_unique<C2FieldSupportedValues>();
        if (!objcpy(d->values.get(), s.values[0])) {
            LOG(ERROR) << "Invalid ParamFieldValues::values.";
            return false;
        }
        return true;
    } else if (s.values.size() == 0) {
        d->values.reset();
        return true;
    }
    LOG(ERROR) << "Invalid ParamFieldValues: "
                  "Two or more FieldSupportedValues objects exist in "
                  "ParamFieldValues. "
                  "Only zero or one is allowed.";
    return false;
}

// C2SettingResult -> SettingResult
template <typename SettingResult>
bool objcpy(
        SettingResult *d,
        const C2SettingResult &s) {
    switch (s.failure) {
    case C2SettingResult::BAD_TYPE:
        d->failure = SettingResult::Failure::BAD_TYPE;
        break;
    case C2SettingResult::BAD_PORT:
        d->failure = SettingResult::Failure::BAD_PORT;
        break;
    case C2SettingResult::BAD_INDEX:
        d->failure = SettingResult::Failure::BAD_INDEX;
        break;
    case C2SettingResult::READ_ONLY:
        d->failure = SettingResult::Failure::READ_ONLY;
        break;
    case C2SettingResult::MISMATCH:
        d->failure = SettingResult::Failure::MISMATCH;
        break;
    case C2SettingResult::BAD_VALUE:
        d->failure = SettingResult::Failure::BAD_VALUE;
        break;
    case C2SettingResult::CONFLICT:
        d->failure = SettingResult::Failure::CONFLICT;
        break;
    case C2SettingResult::UNSUPPORTED:
        d->failure = SettingResult::Failure::UNSUPPORTED;
        break;
    case C2SettingResult::INFO_BAD_VALUE:
        d->failure = SettingResult::Failure::INFO_BAD_VALUE;
        break;
    case C2SettingResult::INFO_CONFLICT:
        d->failure = SettingResult::Failure::INFO_CONFLICT;
        break;
    default:
        LOG(DEBUG) << "Unrecognized C2SettingResult::Failure "
                   << "with underlying value " << underlying_value(s.failure)
                   << ".";
        d->failure = static_cast<decltype(d->failure)>(s.failure);
    }
    if (!objcpy(&d->field, s.field)) {
        LOG(ERROR) << "Invalid C2SettingResult::field.";
        return false;
    }
    d->conflicts.resize(s.conflicts.size());
    size_t i = 0;
    for (const C2ParamFieldValues& sConflict : s.conflicts) {
        auto &dConflict = d->conflicts[i++];
        if (!objcpy(&dConflict, sConflict)) {
            LOG(ERROR) << "Invalid C2SettingResult::conflicts["
                       << i - 1 << "].";
            return false;
        }
    }
    return true;
}

// SettingResult -> std::unique_ptr<C2SettingResult>
template <typename SettingResult>
bool objcpy(
        std::unique_ptr<C2SettingResult> *d,
        const SettingResult &s) {
    typedef decltype((*d)->field) ParamField;
    *d = std::unique_ptr<C2SettingResult>(new C2SettingResult {
            .field = C2ParamFieldValues(C2ParamFieldBuilder<ParamField>()) });
    if (!*d) {
        LOG(ERROR) << "No memory for C2SettingResult.";
        return false;
    }

    // failure
    switch (s.failure) {
    case SettingResult::Failure::BAD_TYPE:
        (*d)->failure = C2SettingResult::BAD_TYPE;
        break;
    case SettingResult::Failure::BAD_PORT:
        (*d)->failure = C2SettingResult::BAD_PORT;
        break;
    case SettingResult::Failure::BAD_INDEX:
        (*d)->failure = C2SettingResult::BAD_INDEX;
        break;
    case SettingResult::Failure::READ_ONLY:
        (*d)->failure = C2SettingResult::READ_ONLY;
        break;
    case SettingResult::Failure::MISMATCH:
        (*d)->failure = C2SettingResult::MISMATCH;
        break;
    case SettingResult::Failure::BAD_VALUE:
        (*d)->failure = C2SettingResult::BAD_VALUE;
        break;
    case SettingResult::Failure::CONFLICT:
        (*d)->failure = C2SettingResult::CONFLICT;
        break;
    case SettingResult::Failure::UNSUPPORTED:
        (*d)->failure = C2SettingResult::UNSUPPORTED;
        break;
    case SettingResult::Failure::INFO_BAD_VALUE:
        (*d)->failure = C2SettingResult::INFO_BAD_VALUE;
        break;
    case SettingResult::Failure::INFO_CONFLICT:
        (*d)->failure = C2SettingResult::INFO_CONFLICT;
        break;
    default:
        LOG(DEBUG) << "Unrecognized SettingResult::Failure "
                   << "with underlying value " << underlying_value(s.failure)
                   << ".";
        (*d)->failure = static_cast<C2SettingResult::Failure>(s.failure);
    }

    // field
    if (!objcpy(&(*d)->field, s.field)) {
        LOG(ERROR) << "Invalid SettingResult::field.";
        return false;
    }

    // conflicts
    (*d)->conflicts.clear();
    (*d)->conflicts.reserve(s.conflicts.size());
    for (const auto& sConflict : s.conflicts) {
        (*d)->conflicts.emplace_back(
                C2ParamFieldValues{ C2ParamFieldBuilder<ParamField>(), nullptr });
        if (!objcpy(&(*d)->conflicts.back(), sConflict)) {
            LOG(ERROR) << "Invalid SettingResult::conflicts.";
            return false;
        }
    }
    return true;
}

// C2ParamDescriptor -> ParamDescriptor
template <typename ParamDescriptor>
bool objcpy(ParamDescriptor *d, const C2ParamDescriptor &s) {
    d->index = static_cast<decltype(d->index)>(s.index());
    d->attrib = static_cast<decltype(d->attrib)>(
            _C2ParamInspector::GetAttrib(s));
    d->name = s.name();
    copyVector<uint32_t>(&d->dependencies, s.dependencies());
    return true;
}

// ParamDescriptor -> C2ParamDescriptor
template <typename ParamDescriptor>
bool objcpy(std::shared_ptr<C2ParamDescriptor> *d, const ParamDescriptor &s) {
    std::vector<C2Param::Index> dDependencies;
    dDependencies.reserve(s.dependencies.size());
    for (const auto& sDependency : s.dependencies) {
        dDependencies.emplace_back(static_cast<uint32_t>(sDependency));
    }
    *d = std::make_shared<C2ParamDescriptor>(
            C2Param::Index(static_cast<uint32_t>(s.index)),
            static_cast<C2ParamDescriptor::attrib_t>(s.attrib),
            C2String(s.name.c_str()),
            std::move(dDependencies));
    return true;
}

// C2StructDescriptor -> StructDescriptor
template <typename StructDescriptor>
bool objcpy(StructDescriptor *d, const C2StructDescriptor &s) {
    d->type = static_cast<decltype(d->type)>(s.coreIndex().coreIndex());
    d->fields.resize(s.numFields());
    size_t i = 0;
    for (const C2FieldDescriptor& sField : s) {
        auto& dField = d->fields[i++];
        SetFieldId(
                &dField.fieldId,
                _C2ParamInspector::GetOffset(sField),
                _C2ParamInspector::GetSize(sField));
        dField.type = static_cast<decltype(dField.type)>(sField.type());
        dField.extent = static_cast<uint32_t>(sField.extent());
        dField.name = static_cast<decltype(dField.name)>(sField.name());
        const auto& sNamedValues = sField.namedValues();
        dField.namedValues.resize(sNamedValues.size());
        size_t j = 0;
        for (const auto& sNamedValue : sNamedValues) {
            auto& dNamedValue = dField.namedValues[j++];
            dNamedValue.name = static_cast<decltype(dNamedValue.name)>(sNamedValue.first);
            dNamedValue.value = static_cast<decltype(dNamedValue.value)>(
                    sNamedValue.second.u64);
        }
    }
    return true;
}

// StructDescriptor -> C2StructDescriptor
template <typename StructDescriptor>
bool objcpy(std::unique_ptr<C2StructDescriptor> *d, const StructDescriptor &s) {
    C2Param::CoreIndex dIndex = C2Param::CoreIndex(static_cast<uint32_t>(s.type));
    std::vector<C2FieldDescriptor> dFields;
    dFields.reserve(s.fields.size());
    for (const auto &sField : s.fields) {
        C2FieldDescriptor dField = {
            static_cast<uint32_t>(sField.type),
            static_cast<uint32_t>(sField.extent),
            sField.name,
            GetOffsetFromFieldId(sField.fieldId),
            GetSizeFromFieldId(sField.fieldId) };
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
    return true;
}

constexpr size_t PARAMS_ALIGNMENT = 8;  // 64-bit alignment
static_assert(PARAMS_ALIGNMENT % alignof(C2Param) == 0, "C2Param alignment mismatch");
static_assert(PARAMS_ALIGNMENT % alignof(C2Info) == 0, "C2Param alignment mismatch");
static_assert(PARAMS_ALIGNMENT % alignof(C2Tuning) == 0, "C2Param alignment mismatch");

template <typename Params>
struct _ParamsBlobHelper { typedef Params BlobType; };

template <typename Params>
using ParamsBlobType = typename _ParamsBlobHelper<Params>::BlobType;

template <typename Params>
const ParamsBlobType<Params> &GetBlob(const Params &params) {
    return params;
}

template <typename Params>
ParamsBlobType<Params> *GetBlob(Params *params) {
    return params;
}

// Params -> std::vector<C2Param*>
template <typename Params>
bool parseParamsBlob(std::vector<C2Param*> *params, const Params &paramsBlob) {
    // assuming blob is const here
    const ParamsBlobType<Params> &blob = GetBlob(paramsBlob);
    size_t size = blob.size();
    size_t ix = 0;
    size_t old_ix = 0;
    const uint8_t *data = blob.data();
    C2Param *p = nullptr;

    do {
        p = C2ParamUtils::ParseFirst(data + ix, size - ix);
        if (p) {
            params->emplace_back(p);
            old_ix = ix;
            ix += p->size();
            ix = align(ix, PARAMS_ALIGNMENT);
            if (ix <= old_ix || ix > size) {
                android_errorWriteLog(0x534e4554, "238083570");
                break;
            }
        }
    } while (p);

    if (ix != size) {
        LOG(ERROR) << "parseParamsBlob -- inconsistent sizes.";
        return false;
    }
    return true;
}

/**
 * Concatenates a list of C2Params into a params blob. T is a container type
 * whose member type is compatible with C2Param*.
 *
 * \param[out] blob target blob
 * \param[in] params parameters to concatenate
 * \retval C2_OK if the blob was successfully created
 * \retval C2_BAD_VALUE if the blob was not successful created (this only
 *         happens if the parameters were not const)
 */
template <typename Params, typename T>
bool _createParamsBlob(Params *paramsBlob, const T &params) {
    // assuming the parameter values are const
    size_t size = 0;
    for (const auto &p : params) {
        if (!p) {
            continue;
        }
        size += p->size();
        size = align(size, PARAMS_ALIGNMENT);
    }
    ParamsBlobType<Params> *blob = GetBlob(paramsBlob);
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
    if (ix != size) {
        LOG(ERROR) << "createParamsBlob -- inconsistent sizes.";
        return false;
    }
    return true;
}

/**
 * Parses a params blob and create a vector of new T objects that contain copies
 * of the params in the blob. T is C2Param or its compatible derived class.
 *
 * \param[out] params the resulting vector
 * \param[in] blob parameter blob to parse
 * \retval C2_OK if the full blob was parsed and params was constructed
 * \retval C2_BAD_VALUE otherwise
 */
template <typename Params, typename T>
bool _copyParamsFromBlob(
        std::vector<std::unique_ptr<T>>* params,
        const Params &paramsBlob) {
    const ParamsBlobType<Params> &blob = GetBlob(paramsBlob);
    std::vector<C2Param*> paramPointers;
    if (!parseParamsBlob(&paramPointers, blob)) {
        LOG(ERROR) << "copyParamsFromBlob -- failed to parse.";
        return false;
    }

    params->resize(paramPointers.size());
    size_t i = 0;
    for (C2Param* const& paramPointer : paramPointers) {
        if (!paramPointer) {
            LOG(ERROR) << "copyParamsFromBlob -- null paramPointer.";
            return false;
        }
        (*params)[i++].reset(reinterpret_cast<T*>(
                C2Param::Copy(*paramPointer).release()));
    }
    return true;
}

// Params -> update std::vector<std::unique_ptr<C2Param>>
template <typename Params>
bool updateParamsFromBlob(
        const std::vector<C2Param*>& params,
        const Params& paramsBlob) {
    const ParamsBlobType<Params> &blob = GetBlob(paramsBlob);
    std::unordered_map<uint32_t, C2Param*> index2param;
    for (C2Param* const& param : params) {
        if (!param) {
            LOG(ERROR) << "updateParamsFromBlob -- null output param.";
            return false;
        }
        if (index2param.find(param->index()) == index2param.end()) {
            index2param.emplace(param->index(), param);
        }
    }

    std::vector<C2Param*> paramPointers;
    if (!parseParamsBlob(&paramPointers, blob)) {
        LOG(ERROR) << "updateParamsFromBlob -- failed to parse.";
        return false;
    }

    for (C2Param* const& paramPointer : paramPointers) {
        if (!paramPointer) {
            LOG(ERROR) << "updateParamsFromBlob -- null input param.";
            return false;
        }
        decltype(index2param)::iterator i = index2param.find(
                paramPointer->index());
        if (i == index2param.end()) {
            LOG(DEBUG) << "updateParamsFromBlob -- index "
                       << paramPointer->index() << " not found. Skipping...";
            continue;
        }
        if (!i->second->updateFrom(*paramPointer)) {
            LOG(ERROR) << "updateParamsFromBlob -- size mismatch: "
                       << params.size() << " vs " << paramPointer->size()
                       << " (index = " << i->first << ").";
            return false;
        }
    }
    return true;
}

}  // namespace android

#endif  // CODEC2_COMMON_PARAM_TYPES_H
