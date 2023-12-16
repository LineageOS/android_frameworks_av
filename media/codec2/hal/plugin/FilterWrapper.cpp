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

//#define LOG_NDEBUG 0
#define LOG_TAG "Codec2-FilterWrapper"
#include <android-base/logging.h>

#include <set>

#include <dlfcn.h>

#include <C2Config.h>
#include <C2Debug.h>
#include <C2ParamInternal.h>

#include <codec2/hidl/plugin/FilterPlugin.h>

#include <FilterWrapper.h>

namespace android {

namespace {

// Indices that the last filter in the chain should consume.
static constexpr uint32_t kTypesForLastFilter[] = {
    // In case we have an output surface, we want to use the block pool
    // backed by the output surface for the output buffer going to the client.
    C2PortBlockPoolsTuning::output::PARAM_TYPE,
};

class WrappedDecoderInterface : public C2ComponentInterface {
public:
    WrappedDecoderInterface(
            std::shared_ptr<C2ComponentInterface> intf,
            std::vector<FilterWrapper::Component> &&filters,
            std::weak_ptr<FilterWrapper> filterWrapper)
        : mIntf(intf), mFilterWrapper(filterWrapper) {
        takeFilters(std::move(filters));
        for (size_t i = 0; i < mFilters.size(); ++i) {
            mControlParamTypes.insert(
                    mFilters[i].desc.controlParams.begin(),
                    mFilters[i].desc.controlParams.end());
        }
    }

    ~WrappedDecoderInterface() override = default;

    void takeFilters(std::vector<FilterWrapper::Component> &&filters) {
        std::unique_lock lock(mMutex);
        std::vector<std::unique_ptr<C2Param>> lastFilterParams;
        if (!mFilters.empty()) {
            std::vector<C2Param::Index> indices;
            std::vector<std::shared_ptr<C2ParamDescriptor>> paramDescs;
            c2_status_t err = mFilters.back().intf->querySupportedParams_nb(&paramDescs);
            if (err != C2_OK) {
                LOG(WARNING) << "WrappedDecoderInterface: " << mFilters.back().traits.name
                        << " returned error for querySupportedParams_nb; err=" << err;
                paramDescs.clear();
            }
            for (const std::shared_ptr<C2ParamDescriptor> &paramDesc : paramDescs) {
                C2Param::Index index = paramDesc->index();
                if (std::count(
                            std::begin(kTypesForLastFilter),
                            std::end(kTypesForLastFilter),
                            index.type()) != 0) {
                    if (index.forStream()) {
                        // querySupportedParams does not return per-stream params.
                        // We only support stream-0 for now.
                        index = index.withStream(0u);
                    }
                    indices.push_back(index);
                }
            }
            if (!indices.empty()) {
                mFilters.back().intf->query_vb({}, indices, C2_MAY_BLOCK, &lastFilterParams);
            }
        }

        // TODO: documentation
        mFilters = std::move(filters);
        mTypeToIndexForQuery.clear();
        mTypeToIndexForConfig.clear();
        for (size_t i = 0; i < mFilters.size(); ++i) {
            if (i == 0) {
                transferParams_l(mIntf, mFilters[0].intf, C2_MAY_BLOCK);
            } else {
                transferParams_l(mFilters[i - 1].intf, mFilters[i].intf, C2_MAY_BLOCK);
            }
            for (C2Param::Type type : mFilters[i].desc.controlParams) {
                mTypeToIndexForQuery[type.type()] = i;
                mTypeToIndexForConfig[type.type() & ~C2Param::CoreIndex::IS_REQUEST_FLAG] = i;
            }
            for (C2Param::Type type : mFilters[i].desc.affectedParams) {
                mTypeToIndexForQuery[type.type()] = i;
            }
        }
        for (size_t i = mFilters.size(); i > 0; --i) {
            if (i == 1) {
                backPropagateParams_l(mIntf, mFilters[0].intf, C2_MAY_BLOCK);
            } else {
                backPropagateParams_l(mFilters[i - 2].intf, mFilters[i - 1].intf, C2_MAY_BLOCK);
            }
        }
        if (!mFilters.empty()) {
            for (uint32_t type : kTypesForLastFilter) {
                mTypeToIndexForQuery[type] = mFilters.size() - 1;
                mTypeToIndexForConfig[type & ~C2Param::CoreIndex::IS_REQUEST_FLAG] =
                    mFilters.size() - 1;
            }
            if (!lastFilterParams.empty()) {
                std::vector<C2Param *> paramPtrs(lastFilterParams.size());
                std::transform(
                        lastFilterParams.begin(),
                        lastFilterParams.end(),
                        paramPtrs.begin(),
                        [](const std::unique_ptr<C2Param> &param) {
                            return param.get();
                        });
                std::vector<std::unique_ptr<C2SettingResult>> failures;
                mFilters.back().intf->config_vb(paramPtrs, C2_MAY_BLOCK, &failures);
            }
        }
    }

    C2String getName() const override { return mIntf->getName(); }

    c2_node_id_t getId() const override { return mIntf->getId(); }

    c2_status_t query_vb(
            const std::vector<C2Param *> &stackParams,
            const std::vector<C2Param::Index> &heapParamIndices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const heapParams) const override {
        std::unique_lock lock(mMutex);
        std::list<C2Param *> stackParamsList(stackParams.size());
        std::copy_n(stackParams.begin(), stackParams.size(), stackParamsList.begin());
        heapParams->clear();
        c2_status_t result = C2_OK;
        // TODO: loop optimization
        for (size_t i = 0; i < mFilters.size(); ++i) {
            // Filter stack params according to mTypeToIndexForQuery
            std::vector<C2Param *> stackParamsForFilter;
            for (auto it = stackParamsList.begin(); it != stackParamsList.end(); ) {
                C2Param *param = *it;
                uint32_t type = param->type().type();
                auto it2 = mTypeToIndexForQuery.find(type);
                if (it2 == mTypeToIndexForQuery.end() || it2->second != i) {
                    ++it;
                    continue;
                }
                stackParamsForFilter.push_back(param);
                it = stackParamsList.erase(it);
            }
            // Filter heap params according to mTypeToIndexForQuery
            std::vector<C2Param::Index> heapParamIndicesForFilter;
            for (size_t j = 0; j < heapParamIndices.size(); ++j) {
                uint32_t type = heapParamIndices[j].type();
                auto it = mTypeToIndexForQuery.find(type);
                if (it == mTypeToIndexForQuery.end() || it->second != i) {
                    continue;
                }
                heapParamIndicesForFilter.push_back(heapParamIndices[j]);
            }
            std::vector<std::unique_ptr<C2Param>> heapParamsForFilter;
            const std::shared_ptr<C2ComponentInterface> &filter = mFilters[i].intf;
            c2_status_t err = filter->query_vb(
                    stackParamsForFilter, heapParamIndicesForFilter, mayBlock,
                    &heapParamsForFilter);
            if (err != C2_OK && err != C2_BAD_INDEX) {
                LOG(WARNING) << "WrappedDecoderInterface: " << filter->getName()
                        << " returned error for query_vb; err=" << err;
                result = err;
                continue;
            }
            heapParams->insert(
                    heapParams->end(),
                    std::make_move_iterator(heapParamsForFilter.begin()),
                    std::make_move_iterator(heapParamsForFilter.end()));
        }

        std::vector<C2Param *> stackParamsForIntf;
        for (C2Param *param : stackParamsList) {
            if (mControlParamTypes.count(param->type()) != 0) {
                continue;
            }
            stackParamsForIntf.push_back(param);
        }

        // Gather heap params that did not get queried from the filter interfaces above.
        // These need to be queried from the decoder interface.
        std::vector<C2Param::Index> heapParamIndicesForIntf;
        for (size_t j = 0; j < heapParamIndices.size(); ++j) {
            uint32_t type = heapParamIndices[j].type();
            if (mTypeToIndexForQuery.find(type) != mTypeToIndexForQuery.end()) {
                continue;
            }
            if (mControlParamTypes.count(type) != 0) {
                continue;
            }
            heapParamIndicesForIntf.push_back(heapParamIndices[j]);
        }

        std::vector<std::unique_ptr<C2Param>> heapParamsForIntf;
        c2_status_t err = mIntf->query_vb(
                stackParamsForIntf, heapParamIndicesForIntf, mayBlock, &heapParamsForIntf);
        if (err != C2_OK) {
            LOG(err == C2_BAD_INDEX ? VERBOSE : WARNING)
                    << "WrappedDecoderInterface: " << mIntf->getName()
                    << " returned error for query_vb; err=" << err;
            result = err;
        }

        // TODO: params needs to preserve the order
        heapParams->insert(
                heapParams->end(),
                std::make_move_iterator(heapParamsForIntf.begin()),
                std::make_move_iterator(heapParamsForIntf.end()));

        return result;
    }

    c2_status_t config_vb(
            const std::vector<C2Param *> &params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures) override {
        std::unique_lock lock(mMutex);
        c2_status_t result = C2_OK;
        std::vector<C2Param *> paramsForIntf;
        for (C2Param* param : params) {
            auto it = mTypeToIndexForConfig.find(param->type().type());
            if (it != mTypeToIndexForConfig.end()) {
                continue;
            }
            paramsForIntf.push_back(param);
        }
        c2_status_t err = mIntf->config_vb(paramsForIntf, mayBlock, failures);
        if (err != C2_OK) {
            LOG(err == C2_BAD_INDEX ? VERBOSE : WARNING)
                    << "WrappedDecoderInterface: " << mIntf->getName()
                    << " returned error for config_vb; err=" << err;
            result = err;
        }
        for (size_t i = 0; i < mFilters.size(); ++i) {
            if (i == 0) {
                transferParams_l(mIntf, mFilters[0].intf, mayBlock);
            } else {
                transferParams_l(mFilters[i - 1].intf, mFilters[i].intf, mayBlock);
            }
            const std::shared_ptr<C2ComponentInterface> &filter = mFilters[i].intf;
            std::vector<std::unique_ptr<C2SettingResult>> filterFailures;
            std::vector<C2Param *> paramsForFilter;
            for (C2Param* param : params) {
                auto it = mTypeToIndexForConfig.find(param->type().type());
                if (it == mTypeToIndexForConfig.end() || it->second != i) {
                    continue;
                }
                paramsForFilter.push_back(param);
            }
            if (paramsForFilter.empty()) {
                continue;
            }
            c2_status_t err = filter->config_vb(paramsForFilter, mayBlock, &filterFailures);
            if (err != C2_OK) {
                LOG(err == C2_BAD_INDEX ? VERBOSE : WARNING)
                        << "WrappedDecoderInterface: " << filter->getName()
                        << " returned error for config_vb; err=" << err;
                result = err;
            }
        }
        for (size_t i = mFilters.size(); i > 0; --i) {
            if (i == 1) {
                backPropagateParams_l(mIntf, mFilters[0].intf, mayBlock);
            } else {
                backPropagateParams_l(mFilters[i - 2].intf, mFilters[i - 1].intf, mayBlock);
            }
        }

        return result;
    }

    c2_status_t createTunnel_sm(c2_node_id_t) override { return C2_OMITTED; }
    c2_status_t releaseTunnel_sm(c2_node_id_t) override { return C2_OMITTED; }

    c2_status_t querySupportedParams_nb(
            std::vector<std::shared_ptr<C2ParamDescriptor>> * const params) const override {
        std::unique_lock lock(mMutex);
        c2_status_t result = mIntf->querySupportedParams_nb(params);
        if (result != C2_OK) {
            LOG(WARNING) << "WrappedDecoderInterface: " << mIntf->getName()
                    << " returned error for querySupportedParams_nb; err=" << result;
            return result;
        }
        // TODO: optimization idea --- pre-compute at takeFilter().
        for (const FilterWrapper::Component &filter : mFilters) {
            std::vector<std::shared_ptr<C2ParamDescriptor>> filterParams;
            c2_status_t err = filter.intf->querySupportedParams_nb(&filterParams);
            if (err != C2_OK) {
                LOG(WARNING) << "WrappedDecoderInterface: " << filter.intf->getName()
                        << " returned error for querySupportedParams_nb; err=" << result;
                result = err;
                continue;
            }
            for (const std::shared_ptr<C2ParamDescriptor> &paramDesc : filterParams) {
                if (std::count(
                        filter.desc.controlParams.begin(),
                        filter.desc.controlParams.end(),
                        paramDesc->index().type()) == 0) {
                    continue;
                }
                params->push_back(paramDesc);
            }
        }
        return result;
    }

    c2_status_t querySupportedValues_vb(
            std::vector<C2FieldSupportedValuesQuery> &fields,
            c2_blocking_t mayBlock) const override {
        std::unique_lock lock(mMutex);
        c2_status_t result = mIntf->querySupportedValues_vb(fields, mayBlock);
        if (result != C2_OK && result != C2_BAD_INDEX) {
            LOG(WARNING) << "WrappedDecoderInterface: " << mIntf->getName()
                    << " returned error for querySupportedParams_nb; err=" << result;
            return result;
        }
        for (const FilterWrapper::Component &filter : mFilters) {
            std::vector<C2FieldSupportedValuesQuery> filterFields;
            std::vector<size_t> indices;
            for (size_t i = 0; i < fields.size(); ++i) {
                const C2FieldSupportedValuesQuery &field = fields[i];
                uint32_t type = C2Param::Index(_C2ParamInspector::GetIndex(field.field())).type();
                if (std::count(
                        filter.desc.controlParams.begin(),
                        filter.desc.controlParams.end(),
                        type) == 0) {
                    continue;
                }
                filterFields.push_back(field);
                indices.push_back(i);
            }
            c2_status_t err = filter.intf->querySupportedValues_vb(filterFields, mayBlock);
            if (err != C2_OK && err != C2_BAD_INDEX) {
                LOG(WARNING) << "WrappedDecoderInterface: " << filter.intf->getName()
                        << " returned error for querySupportedParams_nb; err=" << result;
                result = err;
                continue;
            }
            for (size_t i = 0; i < filterFields.size(); ++i) {
                fields[indices[i]] = filterFields[i];
            }
        }
        return result;
    }

private:
    mutable std::mutex mMutex;
    std::shared_ptr<C2ComponentInterface> mIntf;
    std::vector<FilterWrapper::Component> mFilters;
    std::weak_ptr<FilterWrapper> mFilterWrapper;
    std::map<uint32_t, size_t> mTypeToIndexForQuery;
    std::map<uint32_t, size_t> mTypeToIndexForConfig;
    std::set<C2Param::Type> mControlParamTypes;

    c2_status_t transferParams_l(
            const std::shared_ptr<C2ComponentInterface> &curr,
            const std::shared_ptr<C2ComponentInterface> &next,
            c2_blocking_t mayBlock) {
        // NOTE: this implementation is preliminary --- it could change once
        // we define what parameters needs to be propagated in component chaining.
        std::vector<std::shared_ptr<C2ParamDescriptor>> paramDescs;
        c2_status_t err = next->querySupportedParams_nb(&paramDescs);
        if (err != C2_OK) {
            LOG(DEBUG) << "WrappedDecoderInterface: " << next->getName()
                    << " returned error for querySupportedParams_nb; err=" << err;
            return err;
        }
        // Find supported input params from the next interface and flip direction
        // so they become output params.
        std::vector<C2Param::Index> indices;
        for (const std::shared_ptr<C2ParamDescriptor> &paramDesc : paramDescs) {
            C2Param::Index index = paramDesc->index();
            if (!index.forInput() || paramDesc->isReadOnly()) {
                continue;
            }
            if (index.forStream()) {
                uint32_t stream = index.stream();
                index = index.withPort(true /* output */).withStream(stream);
            } else {
                index = index.withPort(true /* output */);
            }
            indices.push_back(index);
        }
        // Query those output params from the current interface
        std::vector<std::unique_ptr<C2Param>> heapParams;
        err = curr->query_vb({}, indices, mayBlock, &heapParams);
        if (err != C2_OK && err != C2_BAD_INDEX) {
            LOG(DEBUG) << "WrappedDecoderInterface: " << curr->getName()
                    << " returned error for query_vb; err=" << err;
            return err;
        }
        // Flip the direction of the queried params, so they become input parameters.
        // Configure the next interface with the params.
        std::vector<C2Param *> configParams;
        for (size_t i = 0; i < heapParams.size(); ++i) {
            if (!heapParams[i]) {
                continue;
            }
            if (heapParams[i]->forStream()) {
                heapParams[i] = C2Param::CopyAsStream(
                        *heapParams[i], false /* output */, heapParams[i]->stream());
            } else {
                heapParams[i] = C2Param::CopyAsPort(*heapParams[i], false /* output */);
            }
            configParams.push_back(heapParams[i].get());
        }
        std::vector<std::unique_ptr<C2SettingResult>> failures;
        err = next->config_vb(configParams, mayBlock, &failures);
        if (err != C2_OK && err != C2_BAD_INDEX) {
            LOG(DEBUG) << "WrappedDecoderInterface: " << next->getName()
                    << " returned error for config_vb; err=" << err;
            return err;
        }
        return C2_OK;
    }

    c2_status_t backPropagateParams_l(
            const std::shared_ptr<C2ComponentInterface> &curr,
            const std::shared_ptr<C2ComponentInterface> &next,
            c2_blocking_t mayBlock) {
        // NOTE: this implementation is preliminary --- it could change once
        // we define what parameters needs to be propagated in component chaining.
        std::shared_ptr<FilterWrapper> filterWrapper = mFilterWrapper.lock();
        if (!filterWrapper) {
            LOG(DEBUG) << "WrappedDecoderInterface: FilterWrapper not found";
            return C2_OK;
        }
        if (!filterWrapper->isFilteringEnabled(next)) {
            LOG(VERBOSE) << "WrappedDecoderInterface: filtering not enabled";
            return C2_OK;
        }
        std::vector<std::unique_ptr<C2Param>> params;
        c2_status_t err = filterWrapper->queryParamsForPreviousComponent(next, &params);
        if (err != C2_OK) {
            LOG(DEBUG) << "WrappedDecoderInterface: FilterWrapper returned error for "
                << "queryParamsForPreviousComponent; intf=" << next->getName() << " err=" << err;
            return C2_OK;
        }
        std::vector<C2Param *> configParams;
        for (size_t i = 0; i < params.size(); ++i) {
            if (!params[i]) {
                continue;
            }
            configParams.push_back(params[i].get());
        }
        std::vector<std::unique_ptr<C2SettingResult>> failures;
        curr->config_vb(configParams, mayBlock, &failures);
        if (err != C2_OK && err != C2_BAD_INDEX) {
            LOG(DEBUG) << "WrappedDecoderInterface: " << next->getName()
                    << " returned error for config_vb; err=" << err;
            return err;
        }
        return C2_OK;
    }
};

class WrappedDecoder : public C2Component, public std::enable_shared_from_this<WrappedDecoder> {
public:
    WrappedDecoder(
            std::shared_ptr<C2Component> comp,
            std::vector<FilterWrapper::Component> &&filters,
            std::weak_ptr<FilterWrapper> filterWrapper)
        : mComp(comp), mFilters(std::move(filters)), mFilterWrapper(filterWrapper) {
        std::vector<FilterWrapper::Component> filtersDup(mFilters);
        mIntf = std::make_shared<WrappedDecoderInterface>(
                comp->intf(), std::move(filtersDup), filterWrapper);
    }

    ~WrappedDecoder() override = default;

    std::shared_ptr<C2ComponentInterface> intf() override { return mIntf; }

    c2_status_t setListener_vb(
            const std::shared_ptr<Listener> &listener, c2_blocking_t mayBlock) override {
        if (listener) {
            setListenerInternal(mFilters, listener, mayBlock);
        } else {
            mComp->setListener_vb(nullptr, mayBlock);
            for (FilterWrapper::Component &filter : mFilters) {
                filter.comp->setListener_vb(nullptr, mayBlock);
            }
        }
        mListener = listener;
        return C2_OK;
    }

    c2_status_t queue_nb(std::list<std::unique_ptr<C2Work>>* const items) override {
        return mComp->queue_nb(items);
    }

    c2_status_t announce_nb(const std::vector<C2WorkOutline> &) override {
        return C2_OMITTED;
    }

    c2_status_t flush_sm(
            flush_mode_t mode, std::list<std::unique_ptr<C2Work>>* const flushedWork) override {
        c2_status_t result = mComp->flush_sm(mode, flushedWork);
        std::list<std::unique_ptr<C2Work>> filterFlushedWork;
        for (FilterWrapper::Component filter : mRunningFilters) {
            c2_status_t err = filter.comp->flush_sm(mode, &filterFlushedWork);
            if (err != C2_OK) {
                result = err;
            }
            flushedWork->splice(flushedWork->end(), filterFlushedWork);
        }
        return result;
    }

    c2_status_t drain_nb(drain_mode_t mode) override {
        // TODO: simplify using comp->drain_nb(mode)
        switch (mode) {
        case DRAIN_COMPONENT_WITH_EOS: {
            std::unique_ptr<C2Work> eosWork{new C2Work};
            eosWork->input.flags = C2FrameData::FLAG_END_OF_STREAM;
            eosWork->worklets.push_back(std::make_unique<C2Worklet>());
            std::list<std::unique_ptr<C2Work>> items;
            items.push_back(std::move(eosWork));
            mComp->queue_nb(&items);
            return C2_OK;
        }
        case DRAIN_COMPONENT_NO_EOS:
        case DRAIN_CHAIN:
        default:
            return C2_BAD_VALUE;
        }
    }

    c2_status_t start() override {
        std::vector<FilterWrapper::Component> filters;
        if (std::shared_ptr<FilterWrapper> filterWrapper = mFilterWrapper.lock()) {
            // Let's check if we have filters that we can skip
            for (FilterWrapper::Component &filter : mFilters) {
                if (!filterWrapper->isFilteringEnabled(filter.intf)) {
                    LOG(VERBOSE) << "filtering disabled for " << filter.traits.name;
                    continue;
                }
                LOG(VERBOSE) << "filtering enabled for " << filter.traits.name;
                filters.push_back(filter);
            }
            if (filters.size() < mFilters.size()) {
                LOG(VERBOSE) << (mFilters.size() - filters.size()) << " filter(s) skipped";
                setListenerInternal(filters, mListener, C2_MAY_BLOCK);
                std::vector filtersCopy(filters);
                mIntf->takeFilters(std::move(filtersCopy));
            }
        }

        c2_status_t err = mComp->start();
        if (err != C2_OK) {
            return err;
        }
        for (FilterWrapper::Component &filter : filters) {
            c2_status_t err = filter.comp->start();
            if (err != C2_OK) {
                // Previous components are already started successfully;
                // we ended up in an incoherent state.
                return C2_CORRUPTED;
            }
        }
        mRunningFilters = std::move(filters);
        return C2_OK;
    }

    c2_status_t stop() override {
        c2_status_t err = mComp->stop();
        if (err != C2_OK) {
            return err;
        }
        for (FilterWrapper::Component filter : mRunningFilters) {
            c2_status_t err = filter.comp->stop();
            if (err != C2_OK) {
                // Previous components are already stopped successfully;
                // we ended up in an incoherent state.
                return C2_CORRUPTED;
            }
        }
        mRunningFilters.clear();
        return C2_OK;
    }

    c2_status_t reset() override {
        c2_status_t result = mComp->reset();
        if (result != C2_OK) {
            result = C2_CORRUPTED;
        }
        for (FilterWrapper::Component filter : mFilters) {
            c2_status_t err = filter.comp->reset();
            if (err != C2_OK) {
                // Previous components are already reset successfully;
                // we ended up in an incoherent state.
                result = C2_CORRUPTED;
                // continue for the rest of the chain
            }
        }
        mRunningFilters.clear();
        std::vector<FilterWrapper::Component> filters(mFilters);
        mIntf->takeFilters(std::move(filters));
        return result;
    }

    c2_status_t release() override {
        c2_status_t result = mComp->release();
        if (result != C2_OK) {
            result = C2_CORRUPTED;
        }
        for (FilterWrapper::Component filter : mFilters) {
            c2_status_t err = filter.comp->release();
            if (err != C2_OK) {
                // Previous components are already released successfully;
                // we ended up in an incoherent state.
                result = C2_CORRUPTED;
                // continue for the rest of the chain
            }
        }
        mRunningFilters.clear();
        return result;
    }

private:
    class PassingListener : public Listener {
    public:
        PassingListener(
                std::shared_ptr<C2Component> wrappedComponent,
                const std::shared_ptr<Listener> &wrappedComponentListener,
                std::shared_ptr<C2Component> nextComponent)
            : mWrappedComponent(wrappedComponent),
              mWrappedComponentListener(wrappedComponentListener),
              mNextComponent(nextComponent) {
        }

        void onWorkDone_nb(
                std::weak_ptr<C2Component>,
                std::list<std::unique_ptr<C2Work>> workItems) override {
            std::shared_ptr<C2Component> nextComponent = mNextComponent.lock();
            std::list<std::unique_ptr<C2Work>> failedWorkItems;
            if (!nextComponent) {
                for (std::unique_ptr<C2Work> &work : workItems) {
                    // Next component unexpectedly released while the work is
                    // in-flight. Report C2_CORRUPTED to the client.
                    work->result = C2_CORRUPTED;
                    failedWorkItems.push_back(std::move(work));
                }
                workItems.clear();
            } else {
                for (auto it = workItems.begin(); it != workItems.end(); ) {
                    const std::unique_ptr<C2Work> &work = *it;
                    if (work->result != C2_OK
                            || work->worklets.size() != 1) {
                        failedWorkItems.push_back(std::move(*it));
                        it = workItems.erase(it);
                        continue;
                    }
                    C2FrameData &output = work->worklets.front()->output;
                    c2_cntr64_t customOrdinal = work->input.ordinal.customOrdinal;
                    work->input = std::move(output);
                    work->input.ordinal.customOrdinal = customOrdinal;
                    output.flags = C2FrameData::flags_t(0);
                    output.buffers.clear();
                    output.configUpdate.clear();
                    output.infoBuffers.clear();
                    ++it;
                }
            }
            if (!failedWorkItems.empty()) {
                for (const std::unique_ptr<C2Work> &work : failedWorkItems) {
                    LOG(VERBOSE) << "work #" << work->input.ordinal.frameIndex.peek()
                            << " failed: err=" << work->result
                            << " worklets.size()=" << work->worklets.size();
                }
                if (std::shared_ptr<Listener> wrappedComponentListener =
                        mWrappedComponentListener.lock()) {
                    wrappedComponentListener->onWorkDone_nb(
                            mWrappedComponent, std::move(failedWorkItems));
                }
            }
            if (!workItems.empty()) {
                nextComponent->queue_nb(&workItems);
            }
        }

        void onTripped_nb(
                std::weak_ptr<C2Component>,
                std::vector<std::shared_ptr<C2SettingResult>>) override {
            // Trip not supported
        }

        void onError_nb(std::weak_ptr<C2Component>, uint32_t errorCode) {
            if (std::shared_ptr<Listener> wrappedComponentListener =
                    mWrappedComponentListener.lock()) {
                wrappedComponentListener->onError_nb(mWrappedComponent, errorCode);
            }
        }

    private:
        std::weak_ptr<C2Component> mWrappedComponent;
        std::weak_ptr<Listener> mWrappedComponentListener;
        std::weak_ptr<C2Component> mNextComponent;
    };

    class LastListener : public Listener {
    public:
        LastListener(
                std::shared_ptr<C2Component> wrappedComponent,
                const std::shared_ptr<Listener> &wrappedComponentListener)
            : mWrappedComponent(wrappedComponent),
              mWrappedComponentListener(wrappedComponentListener) {
        }

        void onWorkDone_nb(
                std::weak_ptr<C2Component>,
                std::list<std::unique_ptr<C2Work>> workItems) override {
            if (mWrappedComponent.expired()) {
                return;
            }
            if (std::shared_ptr<Listener> wrappedComponentListener =
                    mWrappedComponentListener.lock()) {
                wrappedComponentListener->onWorkDone_nb(
                        mWrappedComponent, std::move(workItems));
            }
        }

        void onTripped_nb(
                std::weak_ptr<C2Component>,
                std::vector<std::shared_ptr<C2SettingResult>>) override {
            // Trip not supported
        }

        void onError_nb(std::weak_ptr<C2Component>, uint32_t errorCode) {
            if (mWrappedComponent.expired()) {
                return;
            }
            if (std::shared_ptr<Listener> wrappedComponentListener =
                    mWrappedComponentListener.lock()) {
                wrappedComponentListener->onError_nb(mWrappedComponent, errorCode);
            }
        }

    private:
        std::weak_ptr<C2Component> mWrappedComponent;
        std::weak_ptr<Listener> mWrappedComponentListener;
    };

    std::shared_ptr<C2Component> mComp;
    std::shared_ptr<WrappedDecoderInterface> mIntf;
    std::vector<FilterWrapper::Component> mFilters;
    std::vector<FilterWrapper::Component> mRunningFilters;
    std::weak_ptr<FilterWrapper> mFilterWrapper;
    std::shared_ptr<Listener> mListener;
#if defined(LOG_NDEBUG) && !LOG_NDEBUG
    base::ScopedLogSeverity mScopedLogSeverity{base::VERBOSE};
#endif

    c2_status_t setListenerInternal(
            const std::vector<FilterWrapper::Component> &filters,
            const std::shared_ptr<Listener> &listener,
            c2_blocking_t mayBlock) {
        if (filters.empty()) {
            return mComp->setListener_vb(listener, mayBlock);
        }
        std::shared_ptr passingListener = std::make_shared<PassingListener>(
                shared_from_this(),
                listener,
                filters.front().comp);
        mComp->setListener_vb(passingListener, mayBlock);
        for (size_t i = 0; i < filters.size() - 1; ++i) {
            filters[i].comp->setListener_vb(
                    std::make_shared<PassingListener>(
                            shared_from_this(),
                            listener,
                            filters[i + 1].comp),
                    mayBlock);
        }
        filters.back().comp->setListener_vb(
                std::make_shared<LastListener>(shared_from_this(), listener), mayBlock);
        return C2_OK;
    }
};

}  // anonymous namespace

FilterWrapper::FilterWrapper(std::unique_ptr<Plugin> &&plugin)
    : mInit(NO_INIT),
      mPlugin(std::move(plugin)) {
    if (mPlugin->status() != OK) {
        LOG(ERROR) << "plugin not OK: " << mPlugin->status();
        mPlugin.reset();
        return;
    }
    mStore = mPlugin->getStore();
    if (!mStore) {
        LOG(ERROR) << "no store";
        mPlugin.reset();
        return;
    }
    std::vector<std::shared_ptr<const C2Component::Traits>> traits =
        mStore->listComponents();
    std::sort(
            traits.begin(),
            traits.end(),
            [](std::shared_ptr<const C2Component::Traits> &a,
                    std::shared_ptr<const C2Component::Traits> &b) {
                return a->rank < b->rank;
            });
    for (size_t i = 0; i < traits.size(); ++i) {
        const std::shared_ptr<const C2Component::Traits> &trait = traits[i];
        if (trait->domain == C2Component::DOMAIN_OTHER
                || trait->domain == C2Component::DOMAIN_AUDIO
                || trait->kind != C2Component::KIND_OTHER) {
            LOG(DEBUG) << trait->name << " is ignored because of domain/kind: "
                << trait->domain << "/" << trait->kind;
            continue;
        }
        Descriptor desc;
        if (!mPlugin->describe(trait->name, &desc)) {
            LOG(DEBUG) << trait->name << " is ignored because describe() failed";
            continue;
        }
        mComponents.push_back({nullptr, nullptr, *trait, desc});
    }
    if (mComponents.empty()) {
        LOG(DEBUG) << "FilterWrapper: no filter component found";
        mPlugin.reset();
        return;
    }
    mInit = OK;
}

FilterWrapper::~FilterWrapper() {
}

std::vector<FilterWrapper::Component> FilterWrapper::createFilters() {
    std::vector<FilterWrapper::Component> filters;
    for (const FilterWrapper::Component &filter : mComponents) {
        std::shared_ptr<C2Component> comp;
        std::shared_ptr<C2ComponentInterface> intf;
        if (C2_OK != mStore->createComponent(filter.traits.name, &comp)) {
            return {};
        }
        filters.push_back({comp, comp->intf(), filter.traits, filter.desc});
    }
    return filters;
}

C2Component::Traits FilterWrapper::getTraits(
        const std::shared_ptr<C2ComponentInterface> &intf) {
    {
        std::unique_lock lock(mCacheMutex);
        if (mCachedTraits.count(intf->getName())) {
            return mCachedTraits.at(intf->getName());
        }
    }
    C2ComponentDomainSetting domain;
    C2ComponentKindSetting kind;
    c2_status_t err = intf->query_vb({&domain, &kind}, {}, C2_MAY_BLOCK, nullptr);
    C2Component::Traits traits = {
        "query failed",  // name
        C2Component::DOMAIN_OTHER,
        C2Component::KIND_OTHER,
        0,   // rank, unused
        "",  // media type, unused
        "",  // owner, unused
        {},  // aliases, unused
    };
    if (err == C2_OK) {
        traits = {
            intf->getName(),
            domain.value,
            kind.value,
            0,   // rank, unused
            "",  // media type, unused
            "",  // owner, unused
            {},  // aliases, unused
        };
        std::unique_lock lock(mCacheMutex);
        mCachedTraits[traits.name] = traits;
    }
    return traits;
}

std::shared_ptr<C2ComponentInterface> FilterWrapper::maybeWrapInterface(
        const std::shared_ptr<C2ComponentInterface> intf) {
    if (mInit != OK) {
        LOG(VERBOSE) << "maybeWrapInterface: Wrapper not initialized: "
                << intf->getName() << " is not wrapped.";
        return intf;
    }
    C2Component::Traits traits = getTraits(intf);
    if (traits.name != intf->getName()) {
        LOG(INFO) << "maybeWrapInterface: Querying traits from " << intf->getName()
                << " failed; not wrapping the interface";
        return intf;
    }
    if ((traits.domain != C2Component::DOMAIN_VIDEO && traits.domain != C2Component::DOMAIN_IMAGE)
            || traits.kind != C2Component::KIND_DECODER) {
        LOG(VERBOSE) << "maybeWrapInterface: " << traits.name
                << " is not video/image decoder; not wrapping the interface";
        return intf;
    }
    return std::make_shared<WrappedDecoderInterface>(
            intf, createFilters(), weak_from_this());
}

std::shared_ptr<C2Component> FilterWrapper::maybeWrapComponent(
        const std::shared_ptr<C2Component> comp) {
    if (mInit != OK) {
        LOG(VERBOSE) << "maybeWrapComponent: Wrapper not initialized: "
                << comp->intf()->getName() << " is not wrapped.";
        return comp;
    }
    C2Component::Traits traits = getTraits(comp->intf());
    if (traits.name != comp->intf()->getName()) {
        LOG(INFO) << "maybeWrapComponent: Querying traits from " << comp->intf()->getName()
                << " failed; not wrapping the component";
        return comp;
    }
    if ((traits.domain != C2Component::DOMAIN_VIDEO && traits.domain != C2Component::DOMAIN_IMAGE)
            || traits.kind != C2Component::KIND_DECODER) {
        LOG(VERBOSE) << "maybeWrapComponent: " << traits.name
                << " is not video/image decoder; not wrapping the component";
        return comp;
    }
    std::vector<Component> filters = createFilters();
    std::shared_ptr wrapped = std::make_shared<WrappedDecoder>(
            comp, std::vector(filters), weak_from_this());
    {
        std::unique_lock lock(mWrappedComponentsMutex);
        std::vector<std::weak_ptr<const C2Component>> &components =
            mWrappedComponents.emplace_back();
        components.push_back(wrapped);
        components.push_back(comp);
        for (const Component &filter : filters) {
            components.push_back(filter.comp);
        }
    }
    return wrapped;
}

bool FilterWrapper::isFilteringEnabled(const std::shared_ptr<C2ComponentInterface> &intf) {
    if (mInit != OK) {
        LOG(WARNING) << "isFilteringEnabled: Wrapper not initialized: ";
        return false;
    }
    return mPlugin->isFilteringEnabled(intf);
}

c2_status_t FilterWrapper::createBlockPool(
        C2PlatformAllocatorStore::id_t allocatorId,
        std::shared_ptr<const C2Component> component,
        std::shared_ptr<C2BlockPool> *pool) {
    C2PlatformAllocatorDesc allocatorParam;
    allocatorParam.allocatorId = allocatorId;
    return createBlockPool(allocatorParam, component, pool);
}

c2_status_t FilterWrapper::createBlockPool(
        C2PlatformAllocatorDesc &allocatorParam,
        std::shared_ptr<const C2Component> component,
        std::shared_ptr<C2BlockPool> *pool) {
    std::unique_lock lock(mWrappedComponentsMutex);
    for (auto it = mWrappedComponents.begin(); it != mWrappedComponents.end(); ) {
        std::shared_ptr<const C2Component> comp = it->front().lock();
        if (!comp) {
            it = mWrappedComponents.erase(it);
            continue;
        }
        if (component == comp) {
            std::vector<std::shared_ptr<const C2Component>> components(it->size());
            std::transform(
                    it->begin(), it->end(), components.begin(),
                    [](const std::weak_ptr<const C2Component> &el) {
                        return el.lock();
                    });
            if (C2_OK == CreateCodec2BlockPool(allocatorParam, components, pool)) {
                return C2_OK;
            }
        }
        ++it;
    }
    return CreateCodec2BlockPool(allocatorParam, component, pool);
}

c2_status_t FilterWrapper::queryParamsForPreviousComponent(
        const std::shared_ptr<C2ComponentInterface> &intf,
        std::vector<std::unique_ptr<C2Param>> *params) {
    if (mInit != OK) {
        LOG(WARNING) << "queryParamsForPreviousComponent: Wrapper not initialized: ";
        return C2_NO_INIT;
    }
    return mPlugin->queryParamsForPreviousComponent(intf, params);
}

}  // namespace android
