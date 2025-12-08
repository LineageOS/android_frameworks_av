/*
 * Copyright (C) 2024 The Android Open Source Project
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

#define LOG_TAG "ApexCodecs"
//#define LOG_NDEBUG 0
#include <android-base/logging.h>

#include <new>
#include <map>
#include <vector>

#include <C2Param.h>
#include <C2ParamInternal.h>
#include <C2Work.h>
#include <android_media_swcodec_flags.h>
#include <media/stagefright/foundation/AUtils.h>

#include <android-base/no_destructor.h>
#include <apex/ApexCodecs.h>
#include <apex/ApexCodecsImpl.h>
#include <apex/ApexCodecsParam.h>

using ::android::apexcodecs::ApexComponentIntf;
using ::android::apexcodecs::ApexComponentStoreIntf;
using ::android::apexcodecs::ApexConfigurableIntf;
using ::android::base::ERROR;

// 64-bit alignment
constexpr size_t PARAMS_ALIGNMENT = 8;

struct ApexCodec_Configurable {
    ApexCodec_Configurable(
            std::unique_ptr<ApexConfigurableIntf> &&configurable,
            const std::shared_ptr<C2ParamReflector> &reflector)
        : mConfigurable(std::move(configurable)),
          mReflector(reflector) {
    }

    ApexCodec_Status config(
            ApexCodec_LinearBuffer *params,
            ApexCodec_SettingResults **results);

    ApexCodec_Status query(
            uint32_t indices[],
            size_t numIndices,
            ApexCodec_LinearBuffer *config,
            size_t *writtenOrRequired);

    ApexCodec_Status querySupportedParams(
            ApexCodec_ParamDescriptors **descriptors);

    ApexCodec_Status querySupportedValues(
            ApexCodec_SupportedValuesQuery *queries,
            size_t numQueries);

private:
    std::unique_ptr<ApexConfigurableIntf> mConfigurable;
    std::shared_ptr<C2ParamReflector> mReflector;

    uint32_t findSize(C2Param::Index index, uint32_t offset) {
        // NOTE: we probably could cache the (index, offset) -> size mapping
        if (mReflector == nullptr) {
            return 0;
        }
        std::shared_ptr<C2StructDescriptor> structDesc = mReflector->describe(index);
        if (structDesc == nullptr) {
            return 0;
        }
        for (const C2FieldDescriptor &fieldDesc : *structDesc) {
            if (_C2ParamInspector::GetOffset(fieldDesc) == offset) {
                return _C2ParamInspector::GetSize(fieldDesc);
            }
        }
        return 0;
    }
};

struct ApexCodec_ParamDescriptors {
public:
    explicit ApexCodec_ParamDescriptors(
            const std::vector<std::shared_ptr<C2ParamDescriptor>> &paramDescriptors);

    ~ApexCodec_ParamDescriptors() = default;

    ApexCodec_Status getIndices(uint32_t **indices, size_t *numIndices);

    ApexCodec_Status getDescriptor(
            uint32_t index,
            ApexCodec_ParamAttribute *attr,
            const char **name,
            uint32_t **dependencies,
            size_t *numDependencies);

private:
    struct Entry {
        uint32_t index;
        ApexCodec_ParamAttribute attr;
        C2String name;
        std::vector<uint32_t> dependencies;
    };
    std::map<uint32_t, Entry> mDescriptors;
    std::vector<uint32_t> mIndices;
};

struct ApexCodec_Component {
    ApexCodec_Component(
            std::unique_ptr<ApexComponentIntf> &&comp,
            const std::shared_ptr<C2ParamReflector> &reflector)
        : mComponent(std::move(comp)) {
        mConfigurable.reset(new ApexCodec_Configurable(
                mComponent->getConfigurable(), reflector));
    }

    ApexCodec_Status start() {
        return mComponent->start();
    }

    ApexCodec_Status flush() {
        return mComponent->flush();
    }

    ApexCodec_Status reset() {
        return mComponent->reset();
    }

    ApexCodec_Configurable *getConfigurable() {
        return mConfigurable.get();
    }

    ApexCodec_Status process(
            const ApexCodec_Buffer *input,
            ApexCodec_Buffer *output,
            size_t *consumed,
            size_t *produced) {
        if (input == nullptr || output == nullptr || consumed == nullptr || produced == nullptr) {
            return APEXCODEC_STATUS_BAD_VALUE;
        }
        return mComponent->process(input, output, consumed, produced);
    }


private:
    std::unique_ptr<ApexComponentIntf> mComponent;
    std::unique_ptr<ApexCodec_Configurable> mConfigurable;
};

struct ApexCodec_ComponentStore {
    ApexCodec_ComponentStore() : mStore((ApexComponentStoreIntf *)GetApexComponentStore()) {
        if (mStore == nullptr) {
            return;
        }
        mC2Traits = mStore->listComponents();
        mTraits.reserve(mC2Traits.size());
        for (const std::shared_ptr<const C2Component::Traits> &trait : mC2Traits) {
            mTraits.push_back(ApexCodec_ComponentTraits{
                trait->name.c_str(),                // name
                trait->mediaType.c_str(),           // mediaType
                (ApexCodec_Kind)trait->kind,        // kind
                (ApexCodec_Domain)trait->domain,    // domain
            });
        }
    }

    ApexCodec_ComponentTraits *getTraits(size_t index) {
        if (mStore == nullptr) {
            return nullptr;
        }
        if (index < mTraits.size()) {
            return mTraits.data() + index;
        } else {
            return nullptr;
        }
    }

    std::unique_ptr<ApexComponentIntf> createComponent(const char *name) {
        if (mStore == nullptr) {
            return nullptr;
        }
        return mStore->createComponent(name);
    }

    std::shared_ptr<C2ParamReflector> getParamReflector() const {
        if (mStore == nullptr) {
            return nullptr;
        }
        return mStore->getParamReflector();
    }

private:
    ApexComponentStoreIntf *mStore;
    std::vector<std::shared_ptr<const C2Component::Traits>> mC2Traits;
    std::vector<ApexCodec_ComponentTraits> mTraits;
};

ApexCodec_ComponentStore *ApexCodec_GetComponentStore() {
    static ::android::base::NoDestructor<ApexCodec_ComponentStore> store;
    return store.get();
}

ApexCodec_ComponentTraits *ApexCodec_Traits_get(
        ApexCodec_ComponentStore *store, size_t index) {
    if (!android::media::swcodec::flags::apexcodecs_base()) {
        return nullptr;
    }
    return store->getTraits(index);
}

ApexCodec_Status ApexCodec_Component_create(
        ApexCodec_ComponentStore *store, const char *name, ApexCodec_Component **comp) {
    if (!android::media::swcodec::flags::apexcodecs_base()) {
        return APEXCODEC_STATUS_NOT_FOUND;
    }
    if (store == nullptr) {
        LOG(ERROR) << "ApexCodec_Component_create: store is nullptr";
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    if (name == nullptr) {
        LOG(ERROR) << "ApexCodec_Component_create: name is nullptr";
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    if (comp == nullptr) {
        LOG(ERROR) << "ApexCodec_Component_create: comp is nullptr";
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    *comp = nullptr;
    std::unique_ptr<ApexComponentIntf> compIntf = store->createComponent(name);
    if (compIntf == nullptr) {
        return APEXCODEC_STATUS_NOT_FOUND;
    }
    *comp = new ApexCodec_Component(std::move(compIntf), store->getParamReflector());
    return APEXCODEC_STATUS_OK;
}

void ApexCodec_Component_destroy(ApexCodec_Component *comp) {
    delete comp;
}

ApexCodec_Status ApexCodec_Component_start(ApexCodec_Component *comp) {
    if (comp == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return comp->start();
}

ApexCodec_Status ApexCodec_Component_flush(ApexCodec_Component *comp) {
    if (comp == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return comp->flush();
}

ApexCodec_Status ApexCodec_Component_reset(ApexCodec_Component *comp) {
    if (comp == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return comp->reset();
}

ApexCodec_Configurable *ApexCodec_Component_getConfigurable(
        ApexCodec_Component *comp) {
    if (comp == nullptr) {
        return nullptr;
    }
    return comp->getConfigurable();
}

ApexCodec_Buffer::ApexCodec_Buffer()
        : mType(APEXCODEC_BUFFER_TYPE_EMPTY) {
}

ApexCodec_Buffer::~ApexCodec_Buffer() {
}

void ApexCodec_Buffer::clear() {
    mType = APEXCODEC_BUFFER_TYPE_EMPTY;
    mBufferInfo.reset();
    mLinearBuffer = {};
    mGraphicBuffer = nullptr;
    mConfigUpdates.reset();
    mOwnedConfigUpdates.reset();
}

ApexCodec_BufferType ApexCodec_Buffer::getType() const {
    return mType;
}

void ApexCodec_Buffer::setBufferInfo(
        ApexCodec_BufferFlags flags, uint64_t frameIndex, uint64_t timestampUs) {
    mBufferInfo.emplace(BufferInfo{flags, frameIndex, timestampUs});
}

ApexCodec_Status ApexCodec_Buffer::setLinearBuffer(const ApexCodec_LinearBuffer *linearBuffer) {
    if (mType != APEXCODEC_BUFFER_TYPE_EMPTY) {
        return APEXCODEC_STATUS_BAD_STATE;
    }
    mType = APEXCODEC_BUFFER_TYPE_LINEAR;
    if (linearBuffer == nullptr) {
        mLinearBuffer.data = nullptr;
        mLinearBuffer.size = 0;
    } else {
        mLinearBuffer = *linearBuffer;
    }
    return APEXCODEC_STATUS_OK;
}

ApexCodec_Status ApexCodec_Buffer::setGraphicBuffer(AHardwareBuffer *graphicBuffer) {
    if (mType != APEXCODEC_BUFFER_TYPE_EMPTY) {
        return APEXCODEC_STATUS_BAD_STATE;
    }
    mType = APEXCODEC_BUFFER_TYPE_GRAPHIC;
    mGraphicBuffer = graphicBuffer;
    return APEXCODEC_STATUS_OK;
}

ApexCodec_Status ApexCodec_Buffer::setConfigUpdates(const ApexCodec_LinearBuffer *configUpdates) {
    if (configUpdates == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    if (mConfigUpdates.has_value()) {
        return APEXCODEC_STATUS_BAD_STATE;
    }
    mOwnedConfigUpdates.reset();
    mConfigUpdates.emplace(*configUpdates);
    return APEXCODEC_STATUS_OK;
}

ApexCodec_Status ApexCodec_Buffer::getBufferInfo(
        ApexCodec_BufferFlags *outFlags,
        uint64_t *outFrameIndex,
        uint64_t *outTimestampUs) const {
    if (!mBufferInfo.has_value()) {
        return APEXCODEC_STATUS_BAD_STATE;
    }
    *outFlags = mBufferInfo->flags;
    *outFrameIndex = mBufferInfo->frameIndex;
    *outTimestampUs = mBufferInfo->timestampUs;
    return APEXCODEC_STATUS_OK;
}

ApexCodec_Status ApexCodec_Buffer::getLinearBuffer(ApexCodec_LinearBuffer *outLinearBuffer) const {
    if (mType != APEXCODEC_BUFFER_TYPE_LINEAR) {
        return APEXCODEC_STATUS_BAD_STATE;
    }
    *outLinearBuffer = mLinearBuffer;
    return APEXCODEC_STATUS_OK;
}

ApexCodec_Status ApexCodec_Buffer::getGraphicBuffer(AHardwareBuffer **outGraphicBuffer) const {
    if (mType != APEXCODEC_BUFFER_TYPE_GRAPHIC) {
        return APEXCODEC_STATUS_BAD_STATE;
    }
    *outGraphicBuffer = mGraphicBuffer;
    return APEXCODEC_STATUS_OK;
}

ApexCodec_Status ApexCodec_Buffer::getConfigUpdates(
        ApexCodec_LinearBuffer *outConfigUpdates,
        bool *outOwnedByClient) const {
    if (!mConfigUpdates.has_value()) {
        return APEXCODEC_STATUS_NOT_FOUND;
    }
    *outConfigUpdates = mConfigUpdates.value();
    *outOwnedByClient = !mOwnedConfigUpdates.has_value();
    return APEXCODEC_STATUS_OK;
}

void ApexCodec_Buffer::setOwnedConfigUpdates(std::vector<uint8_t> &&configUpdates) {
    mConfigUpdates.emplace(
            ApexCodec_LinearBuffer{ configUpdates.data(), configUpdates.size() });
    mOwnedConfigUpdates = std::move(configUpdates);
}

ApexCodec_Buffer *ApexCodec_Buffer_create() {
    return new ApexCodec_Buffer;
}

void ApexCodec_Buffer_destroy(ApexCodec_Buffer *buffer) {
    delete buffer;
}

void ApexCodec_Buffer_clear(ApexCodec_Buffer *buffer) {
    if (buffer == nullptr) {
        return;
    }
    buffer->clear();
}

ApexCodec_BufferType ApexCodec_Buffer_getType(ApexCodec_Buffer *buffer) {
    if (buffer == nullptr) {
        return APEXCODEC_BUFFER_TYPE_EMPTY;
    }
    return buffer->getType();
}

void ApexCodec_Buffer_setBufferInfo(
        ApexCodec_Buffer *buffer,
        ApexCodec_BufferFlags flags,
        uint64_t frameIndex,
        uint64_t timestampUs) {
    if (buffer == nullptr) {
        return;
    }
    buffer->setBufferInfo(flags, frameIndex, timestampUs);
}

ApexCodec_Status ApexCodec_Buffer_setLinearBuffer(
        ApexCodec_Buffer *buffer,
        const ApexCodec_LinearBuffer *linearBuffer) {
    if (buffer == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return buffer->setLinearBuffer(linearBuffer);
}

ApexCodec_Status ApexCodec_Buffer_setGraphicBuffer(
        ApexCodec_Buffer *buffer,
        AHardwareBuffer *graphicBuffer) {
    if (buffer == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return buffer->setGraphicBuffer(graphicBuffer);
}

ApexCodec_Status ApexCodec_Buffer_setConfigUpdates(
        ApexCodec_Buffer *buffer,
        const ApexCodec_LinearBuffer *configUpdates) {
    if (buffer == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return buffer->setConfigUpdates(configUpdates);
}

ApexCodec_Status ApexCodec_Buffer_getBufferInfo(
        ApexCodec_Buffer *buffer,
        ApexCodec_BufferFlags *outFlags,
        uint64_t *outFrameIndex,
        uint64_t *outTimestampUs) {
    if (buffer == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return buffer->getBufferInfo(outFlags, outFrameIndex, outTimestampUs);
}

ApexCodec_Status ApexCodec_Buffer_getLinearBuffer(
        ApexCodec_Buffer *buffer,
        ApexCodec_LinearBuffer *outLinearBuffer) {
    if (buffer == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return buffer->getLinearBuffer(outLinearBuffer);
}

ApexCodec_Status ApexCodec_Buffer_getGraphicBuffer(
        ApexCodec_Buffer *buffer,
        AHardwareBuffer **outGraphicBuffer) {
    if (buffer == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return buffer->getGraphicBuffer(outGraphicBuffer);
}

ApexCodec_Status ApexCodec_Buffer_getConfigUpdates(
        ApexCodec_Buffer *buffer,
        ApexCodec_LinearBuffer *outConfigUpdates,
        bool *outOwnedByClient) {
    if (buffer == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return buffer->getConfigUpdates(outConfigUpdates, outOwnedByClient);
}

struct ApexCodec_SupportedValues {
public:
    ApexCodec_SupportedValues(
            const C2FieldSupportedValues &supportedValues,
            const C2Value::type_t &numberType) {
        mType = (ApexCodec_SupportedValuesType)supportedValues.type;
        mNumberType = (ApexCodec_SupportedValuesNumberType)numberType;
        switch (supportedValues.type) {
            case C2FieldSupportedValues::RANGE: {
                mValues.insert(mValues.end(), 5, ApexCodec_Value{});
                ToApexCodecValue(supportedValues.range.min,   numberType, &mValues[0]);
                ToApexCodecValue(supportedValues.range.max,   numberType, &mValues[1]);
                ToApexCodecValue(supportedValues.range.step,  numberType, &mValues[2]);
                ToApexCodecValue(supportedValues.range.num,   numberType, &mValues[3]);
                ToApexCodecValue(supportedValues.range.denom, numberType, &mValues[4]);
                break;
            }
            case C2FieldSupportedValues::VALUES:
            case C2FieldSupportedValues::FLAGS: {
                for (size_t i = 0; i < supportedValues.values.size(); ++i) {
                    mValues.emplace_back();
                    ToApexCodecValue(supportedValues.values[i], numberType, &mValues[i]);
                }
                break;
            }
            default:
                // Unrecognized type; initialize as empty.
                mType = APEXCODEC_SUPPORTED_VALUES_EMPTY;
                break;
        }
    }

    ~ApexCodec_SupportedValues() {
    }

    ApexCodec_Status getTypeAndValues(
            ApexCodec_SupportedValuesType *type,
            ApexCodec_SupportedValuesNumberType *numberType,
            ApexCodec_Value **values,
            uint32_t *numValues) {
        if (type == nullptr) {
            return APEXCODEC_STATUS_BAD_VALUE;
        }
        if (numberType == nullptr) {
            return APEXCODEC_STATUS_BAD_VALUE;
        }
        if (values == nullptr) {
            return APEXCODEC_STATUS_BAD_VALUE;
        }
        if (numValues == nullptr) {
            return APEXCODEC_STATUS_BAD_VALUE;
        }
        *type = mType;
        *numberType = mNumberType;
        switch (mType) {
            case APEXCODEC_SUPPORTED_VALUES_EMPTY: {
                *values = nullptr;
                *numValues = 0;
                break;
            }
            case APEXCODEC_SUPPORTED_VALUES_RANGE:
            case APEXCODEC_SUPPORTED_VALUES_VALUES:
            case APEXCODEC_SUPPORTED_VALUES_FLAGS: {
                if (mValues.empty()) {
                    return APEXCODEC_STATUS_BAD_STATE;
                }
                *values = mValues.data();
                *numValues = mValues.size();
                break;
            }
            default:
                return APEXCODEC_STATUS_BAD_STATE;
        }
        return APEXCODEC_STATUS_OK;
    }

    static bool ToApexCodecValue(
            const C2Value::Primitive &value,
            const C2Value::type_t &type,
            ApexCodec_Value *outValue) {
        switch (type) {
            case C2Value::NO_INIT:
                return false;
            case C2Value::INT32:
                outValue->i32 = value.i32;
                return true;
            case C2Value::UINT32:
                outValue->u32 = value.u32;
                return true;
            case C2Value::INT64:
                outValue->i64 = value.i64;
                return true;
            case C2Value::UINT64:
                outValue->u64 = value.u64;
                return true;
            case C2Value::FLOAT:
                outValue->f = value.fp;
                return true;
            default:
                return false;
        }
    }

    static C2Value::type_t GetFieldType(
            const std::shared_ptr<C2ParamReflector> &reflector,
            const C2ParamField& field) {
        std::unique_ptr<C2StructDescriptor> desc = reflector->describe(
                _C2ParamInspector::GetIndex(field));
        if (!desc) {
            return C2Value::NO_INIT;
        }

        for (const C2FieldDescriptor &fieldDesc : *desc) {
            if (_C2ParamInspector::GetOffset(fieldDesc) == _C2ParamInspector::GetOffset(field)) {
                if (_C2ParamInspector::GetSize(fieldDesc) != _C2ParamInspector::GetSize(field)) {
                    // Size doesn't match.
                    return C2Value::NO_INIT;
                }
                switch (fieldDesc.type()) {
                    case C2FieldDescriptor::INT32:
                    case C2FieldDescriptor::UINT32:
                    case C2FieldDescriptor::INT64:
                    case C2FieldDescriptor::UINT64:
                    case C2FieldDescriptor::FLOAT:
                        return (C2Value::type_t)fieldDesc.type();
                    default:
                        // Unrecognized type.
                        return C2Value::NO_INIT;
                }
            }
        }
        return C2Value::NO_INIT;
    }

private:
    ApexCodec_SupportedValuesType mType;
    ApexCodec_SupportedValuesNumberType mNumberType;
    std::vector<ApexCodec_Value> mValues;
};

ApexCodec_Status ApexCodec_SupportedValues_getTypeAndValues(
        ApexCodec_SupportedValues *supportedValues,
        ApexCodec_SupportedValuesType *type,
        ApexCodec_SupportedValuesNumberType *numberType,
        ApexCodec_Value **values,
        uint32_t *numValues) {
    if (supportedValues == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return supportedValues->getTypeAndValues(type, numberType, values, numValues);
}

void ApexCodec_SupportedValues_destroy(ApexCodec_SupportedValues *values) {
    delete values;
}

struct ApexCodec_SettingResults {
public:
    explicit ApexCodec_SettingResults(
            const std::shared_ptr<C2ParamReflector> &reflector,
            const std::vector<std::unique_ptr<C2SettingResult>> &results) : mReflector(reflector) {
        for (const std::unique_ptr<C2SettingResult> &c2Result : results) {
            mResults.emplace_back();
            Entry &entry = mResults.back();
            entry.failure = (ApexCodec_SettingResultFailure)c2Result->failure;
            entry.field.index = _C2ParamInspector::GetIndex(c2Result->field.paramOrField);
            entry.field.offset = _C2ParamInspector::GetOffset(c2Result->field.paramOrField);
            entry.field.size = _C2ParamInspector::GetSize(c2Result->field.paramOrField);
            if (c2Result->field.values) {
                entry.fieldValues = std::make_unique<ApexCodec_SupportedValues>(
                        *c2Result->field.values,
                        ApexCodec_SupportedValues::GetFieldType(mReflector,
                                                                c2Result->field.paramOrField));
                entry.field.values = entry.fieldValues.get();
            } else {
                entry.field.values = nullptr;
            }
            for (const C2ParamFieldValues &c2Conflict : c2Result->conflicts) {
                entry.conflicts.emplace_back();
                ApexCodec_ParamFieldValues &conflict = entry.conflicts.back();
                conflict.index = _C2ParamInspector::GetIndex(c2Conflict.paramOrField);
                conflict.offset = _C2ParamInspector::GetOffset(c2Conflict.paramOrField);
                conflict.size = _C2ParamInspector::GetSize(c2Conflict.paramOrField);
                if (c2Conflict.values) {
                    entry.conflictValues.emplace_back(std::make_unique<ApexCodec_SupportedValues>(
                            *c2Conflict.values,
                            ApexCodec_SupportedValues::GetFieldType(mReflector,
                                                                    c2Conflict.paramOrField)));
                    conflict.values = entry.conflictValues.back().get();
                } else {
                    conflict.values = nullptr;
                }
            }
        }
    }

    ~ApexCodec_SettingResults() {
    }

    ApexCodec_Status getResultAtIndex(
            size_t index,
            ApexCodec_SettingResultFailure *failure,
            ApexCodec_ParamFieldValues *field,
            ApexCodec_ParamFieldValues **conflicts,
            size_t *numConflicts) {
        if (failure == nullptr) {
            return APEXCODEC_STATUS_BAD_VALUE;
        }
        if (field == nullptr) {
            return APEXCODEC_STATUS_BAD_VALUE;
        }
        if (conflicts == nullptr) {
            return APEXCODEC_STATUS_BAD_VALUE;
        }
        if (numConflicts == nullptr) {
            return APEXCODEC_STATUS_BAD_VALUE;
        }
        if (index >= mResults.size()) {
            return APEXCODEC_STATUS_NOT_FOUND;
        }
        *failure = mResults[index].failure;
        *field = mResults[index].field;
        *conflicts = mResults[index].conflicts.data();
        *numConflicts = mResults[index].conflicts.size();
        return APEXCODEC_STATUS_OK;
    }
private:
    std::shared_ptr<C2ParamReflector> mReflector;
    struct Entry {
        ApexCodec_SettingResultFailure failure;
        ApexCodec_ParamFieldValues field;
        std::vector<ApexCodec_ParamFieldValues> conflicts;
        std::unique_ptr<ApexCodec_SupportedValues> fieldValues;
        std::vector<std::unique_ptr<ApexCodec_SupportedValues>> conflictValues;
    };
    std::vector<Entry> mResults;
};

ApexCodec_Status ApexCodec_SettingResults_getResultAtIndex(
        ApexCodec_SettingResults *results,
        size_t index,
        ApexCodec_SettingResultFailure *failure,
        ApexCodec_ParamFieldValues *field,
        ApexCodec_ParamFieldValues **conflicts,
        size_t *numConflicts) {
    if (results == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return results->getResultAtIndex(index, failure, field, conflicts, numConflicts);
}

void ApexCodec_SettingResults_destroy(ApexCodec_SettingResults *results) {
    delete results;
}

ApexCodec_Status ApexCodec_Component_process(
        ApexCodec_Component *comp,
        const ApexCodec_Buffer *input,
        ApexCodec_Buffer *output,
        size_t *consumed,
        size_t *produced) {
    if (comp == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return comp->process(input, output, consumed, produced);
}

ApexCodec_Status ApexCodec_Configurable::config(
        ApexCodec_LinearBuffer *params,
        ApexCodec_SettingResults **results) {
    if (results == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    *results = nullptr;
    std::vector<C2Param *> c2Params;
    uint8_t *data = params->data;
    size_t size = params->size;
    while (size > 0) {
        size_t paramSize = ((C2Param *)data)->size();
        if (paramSize > size || paramSize == 0) {
            return APEXCODEC_STATUS_BAD_VALUE;
        }
        c2Params.emplace_back(C2Param::From(data, paramSize));
        data += align(paramSize, PARAMS_ALIGNMENT);
        size -= align(paramSize, PARAMS_ALIGNMENT);
    }
    std::vector<std::unique_ptr<C2SettingResult>> c2Results;
    ApexCodec_Status status = mConfigurable->config(c2Params, &c2Results);
    if (status != APEXCODEC_STATUS_OK) {
        return status;
    }
    *results = new ApexCodec_SettingResults(mReflector, c2Results);
    return APEXCODEC_STATUS_OK;
}

ApexCodec_Status ApexCodec_Configurable::query(
        uint32_t indices[],
        size_t numIndices,
        ApexCodec_LinearBuffer *config,
        size_t *writtenOrRequired) {
    if (config == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    if (writtenOrRequired == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    *writtenOrRequired = 0;
    std::vector<C2Param::Index> heapParamIndices;
    for (size_t i = 0; i < numIndices; ++i) {
        LOG(VERBOSE) << "query: input index=0x"
                     << std::hex << indices[i] << std::dec << " aka " << indices[i];
        heapParamIndices.push_back(indices[i]);
    }
    std::vector<std::unique_ptr<C2Param>> params;
    ApexCodec_Status status = mConfigurable->query(heapParamIndices, &params);
    if (status != APEXCODEC_STATUS_OK && status != APEXCODEC_STATUS_BAD_INDEX) {
        return status;
    }
    LOG(VERBOSE) << "query: " << params.size() << " params";
    for (const std::unique_ptr<C2Param> &param : params) {
        if (!param || !(*param)) {
            continue;
        }
        LOG(VERBOSE) << "query: output index=0x"
                     << std::hex << param->index() << std::dec << " aka " << param->index();
        *writtenOrRequired += align(param->size(), PARAMS_ALIGNMENT);
    }
    LOG(VERBOSE) << "query: *writtenOrRequired: " << *writtenOrRequired;
    if (*writtenOrRequired > config->size) {
        return APEXCODEC_STATUS_NO_MEMORY;
    }
    size_t offset = 0;
    for (const std::unique_ptr<C2Param> &param : params) {
        if (!param || !(*param)) {
            continue;
        }
        memcpy(config->data + offset, param.get(), param->size());
        offset = align(offset + param->size(), PARAMS_ALIGNMENT);
    }
    return status;
}

ApexCodec_Status ApexCodec_Configurable::querySupportedParams(
        ApexCodec_ParamDescriptors **descriptors) {
    if (descriptors == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    *descriptors = nullptr;
    std::vector<std::shared_ptr<C2ParamDescriptor>> c2Descs;
    mConfigurable->querySupportedParams(&c2Descs);
    *descriptors = new ApexCodec_ParamDescriptors(c2Descs);
    return APEXCODEC_STATUS_OK;
}

ApexCodec_Status ApexCodec_Configurable::querySupportedValues(
        ApexCodec_SupportedValuesQuery *queries,
        size_t numQueries) {
    if (queries == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    if (mReflector == nullptr) {
        return APEXCODEC_STATUS_BAD_STATE;
    }
    std::vector<C2FieldSupportedValuesQuery> c2Queries;
    std::vector<C2ParamField> c2Fields;
    c2Queries.reserve(numQueries);
    for (size_t i = 0; i < numQueries; ++i) {
        C2Param::Index index = queries[i].index;
        uint32_t offset = queries[i].offset;
        uint32_t size = findSize(index, offset);
        c2Fields.push_back(_C2ParamInspector::CreateParamField(index, offset, size));
        c2Queries.emplace_back(c2Fields.back(),
                               (C2FieldSupportedValuesQuery::type_t)queries[i].type);
    }
    mConfigurable->querySupportedValues(c2Queries);
    for (size_t i = 0; i < numQueries; ++i) {
        queries[i].status = (ApexCodec_Status)c2Queries[i].status;
        queries[i].values = new ApexCodec_SupportedValues(
                c2Queries[i].values,
                ApexCodec_SupportedValues::GetFieldType(mReflector, c2Fields[i]));
    }
    return APEXCODEC_STATUS_OK;
}

ApexCodec_Status ApexCodec_Configurable_config(
        ApexCodec_Configurable *comp,
        ApexCodec_LinearBuffer *params,
        ApexCodec_SettingResults **results) {
    if (comp == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return comp->config(params, results);
}

ApexCodec_Status ApexCodec_Configurable_query(
        ApexCodec_Configurable *comp,
        uint32_t indices[],
        size_t numIndices,
        ApexCodec_LinearBuffer *config,
        size_t *writtenOrRequired) {
    if (comp == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return comp->query(indices, numIndices, config, writtenOrRequired);
}

ApexCodec_ParamDescriptors::ApexCodec_ParamDescriptors(
        const std::vector<std::shared_ptr<C2ParamDescriptor>> &paramDescriptors) {
    for (const std::shared_ptr<C2ParamDescriptor> &c2Descriptor : paramDescriptors) {
        if (!c2Descriptor) {
            continue;
        }
        uint32_t index = c2Descriptor->index();
        Entry &entry = mDescriptors[index];
        entry.index = index;
        entry.attr = (ApexCodec_ParamAttribute)_C2ParamInspector::GetAttrib(*c2Descriptor);
        entry.name = c2Descriptor->name();
        for (const C2Param::Index &dependency : c2Descriptor->dependencies()) {
            entry.dependencies.emplace_back((uint32_t)dependency);
        }
        mIndices.push_back(entry.index);
    }
}

ApexCodec_Status ApexCodec_ParamDescriptors::getIndices(uint32_t **indices, size_t *numIndices) {
    if (indices == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    if (numIndices == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    *indices = mIndices.data();
    *numIndices = mIndices.size();
    return APEXCODEC_STATUS_OK;
}

ApexCodec_Status ApexCodec_ParamDescriptors::getDescriptor(
        uint32_t index,
        ApexCodec_ParamAttribute *attr,
        const char **name,
        uint32_t **dependencies,
        size_t *numDependencies) {
    if (attr == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    if (name == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    if (dependencies == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    if (numDependencies == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    auto it = mDescriptors.find(index);
    if (it == mDescriptors.end()) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    const Entry &entry = it->second;
    *attr = entry.attr;
    *name = entry.name.c_str();
    *dependencies = const_cast<uint32_t *>(entry.dependencies.data());
    *numDependencies = entry.dependencies.size();
    return APEXCODEC_STATUS_OK;
}

ApexCodec_Status ApexCodec_ParamDescriptors_getIndices(
        ApexCodec_ParamDescriptors *descriptors,
        uint32_t **indices,
        size_t *numIndices) {
    if (descriptors == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return descriptors->getIndices(indices, numIndices);
}

ApexCodec_Status ApexCodec_ParamDescriptors_getDescriptor(
        ApexCodec_ParamDescriptors *descriptors,
        uint32_t index,
        ApexCodec_ParamAttribute *attr,
        const char **name,
        uint32_t **dependencies,
        size_t *numDependencies) {
    if (descriptors == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return descriptors->getDescriptor(index, attr, name, dependencies, numDependencies);
}

void ApexCodec_ParamDescriptors_destroy(ApexCodec_ParamDescriptors *descriptors) {
    delete descriptors;
}

ApexCodec_Status ApexCodec_Configurable_querySupportedParams(
        ApexCodec_Configurable *comp,
        ApexCodec_ParamDescriptors **descriptors) {
    if (comp == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return comp->querySupportedParams(descriptors);
}

ApexCodec_Status ApexCodec_Configurable_querySupportedValues(
        ApexCodec_Configurable *comp,
        ApexCodec_SupportedValuesQuery *queries,
        size_t numQueries) {
    if (comp == nullptr) {
        return APEXCODEC_STATUS_BAD_VALUE;
    }
    return comp->querySupportedValues(queries, numQueries);
}
