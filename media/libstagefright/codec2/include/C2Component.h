/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef C2COMPONENT_H_

#define C2COMPONENT_H_

#include <stdbool.h>
#include <stdint.h>

#include <list>
#include <memory>
#include <vector>
#include <functional>

#include <C2Param.h>
#include <C2Work.h>

namespace android {

/// \defgroup components Components
/// @{

class C2Component;

struct C2FieldSupportedValuesQuery {
    enum Type : uint32_t {
        POSSIBLE, ///< query all possible values regardless of other settings
        CURRENT,  ///< query currently possible values given dependent settings
    };

    const C2ParamField field;
    const Type type;
    c2_status_t status;
    C2FieldSupportedValues values;

    C2FieldSupportedValuesQuery(const C2ParamField &field_, Type type_)
        : field(field_), type(type_), status(C2_NO_INIT) { }

    static C2FieldSupportedValuesQuery&&
    Current(const C2ParamField &field_) {
        return std::move(C2FieldSupportedValuesQuery(field_, CURRENT));
    }

    static C2FieldSupportedValuesQuery&&
    Possible(const C2ParamField &field_) {
        return std::move(C2FieldSupportedValuesQuery(field_, POSSIBLE));
    }
};

/**
 * Component interface object. This object contains all of the configuration of a potential or
 * actual component. It can be created and used independently of an actual C2Component instance to
 * query support and parameters for various component settings and configurations for a potential
 * component. Actual components also expose this interface.
 */

class C2ComponentInterface {
public:
    // ALWAYS AVAILABLE METHODS
    // =============================================================================================

    /**
     * Returns the name of this component or component interface object.
     * This is a unique name for this component or component interface 'class'; however, multiple
     * instances of this component SHALL have the same name.
     *
     * This method MUST be supported in any state. This call does not change the state nor the
     * internal states of the component.
     *
     * This method MUST be "non-blocking" and return within 1ms.
     *
     * \return the name of this component or component interface object.
     * \retval an empty string if there was not enough memory to allocate the actual name.
     */
    virtual C2String getName() const = 0;

    /**
     * Returns a unique ID for this component or interface object.
     * This ID is used as work targets, unique work IDs, and when configuring tunneling.
     *
     * This method MUST be supported in any state. This call does not change the state nor the
     * internal states of the component.
     *
     * This method MUST be "non-blocking" and return within 1ms.
     *
     * \return a unique node ID for this component or component interface instance.
     */
    virtual c2_node_id_t getId() const = 0;

    /**
     * Queries a set of parameters from the component or interface object.
     * Querying is performed at best effort: the component SHALL query all supported parameters and
     * skip unsupported ones, or heap allocated parameters that could not be allocated. Any errors
     * are communicated in the return value. Additionally, preallocated (e.g. stack) parameters that
     * could not be queried are invalidated. Parameters to be allocated on the heap are omitted from
     * the result.
     *
     * \note Parameter values do not depend on the order of query.
     *
     * \todo This method cannot be used to query info-buffers. Is that a problem?
     *
     * This method MUST be supported in any state. This call does not change the state nor the
     * internal states of the component.
     *
     * This method MUST be "non-blocking" and return within 1ms.
     *
     * \param[in,out] stackParams   a list of params queried. These are initialized specific to each
     *                      setting; e.g. size and index are set and rest of the members are
     *                      cleared.
     *                      \note Flexible settings that are of incorrect size will be invalidated.
     * \param[in] heapParamIndices a vector of param indices for params to be queried and returned on the
     *                      heap. These parameters will be returned in heapParams. Unsupported param
     *                      indices will be ignored.
     * \param[out] heapParams    a list of params where to which the supported heap parameters will be
     *                      appended in the order they appear in heapParamIndices.
     *
     * \retval C2_OK        all parameters could be queried
     * \retval C2_BAD_INDEX all supported parameters could be queried, but some parameters were not
     *                      supported
     * \retval C2_NO_MEMORY could not allocate memory for a supported parameter
     * \retval C2_CORRUPTED some unknown error prevented the querying of the parameters
     *                      (unexpected)
     */
    virtual c2_status_t query_nb(
        const std::vector<C2Param* const> &stackParams,
        const std::vector<C2Param::Index> &heapParamIndices,
        std::vector<std::unique_ptr<C2Param>>* const heapParams) const = 0;

    /**
     * Sets a set of parameters for the component or interface object.
     * Tuning is performed at best effort: the component SHALL update all supported configuration at
     * best effort (unless configured otherwise) and skip unsupported ones. Any errors are
     * communicated in the return value and in |failures|.
     *
     * \note Parameter tuning DOES depend on the order of the tuning parameters. E.g. some parameter
     * update may allow some subsequent parameter update.
     *
     * This method MUST be supported in any state.
     *
     * This method MUST be "non-blocking" and return within 1ms.
     *
     * \param[in,out] params          a list of parameter updates. These will be updated to the actual
     *                      parameter values after the updates (this is because tuning is performed
     *                      at best effort).
     *                      \todo params that could not be updated are not marked here, so are
     *                      confusing - are they "existing" values or intended to be configured
     *                      values?
     * \param[out] failures        a list of parameter failures
     *
     * \retval C2_OK        all parameters could be updated successfully
     * \retval C2_BAD_INDEX all supported parameters could be updated successfully, but some
     *                      parameters were not supported
     * \retval C2_BAD_VALUE some supported parameters could not be updated successfully because
     *                      they contained unsupported values. These are returned in |failures|.
     * \retval C2_NO_MEMORY some supported parameters could not be updated successfully because
     *                      they contained unsupported values, but could not allocate a failure
     *                      object for them.
     * \retval C2_CORRUPTED some unknown error prevented the update of the parameters
     *                      (unexpected)
     */
    virtual c2_status_t config_nb(
            const std::vector<C2Param* const> &params,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures) = 0;

    /**
     * Atomically sets a set of parameters for the component or interface object.
     *
     * \note This method is used mainly for reserving resources for a component.
     *
     * The component SHALL update all supported configuration at
     * best effort(TBD) (unless configured otherwise) and skip unsupported ones. Any errors are
     * communicated in the return value and in |failures|.
     *
     * \note Parameter tuning DOES depend on the order of the tuning parameters. E.g. some parameter
     * update may allow some subsequent parameter update.
     *
     * This method MUST be supported in any state.
     *
     * This method may be momentarily blocking, but MUST return within 5ms.
     *
     * \param params[in,out]          a list of parameter updates. These will be updated to the actual
     *                      parameter values after the updates (this is because tuning is performed
     *                      at best effort).
     *                      \todo params that could not be updated are not marked here, so are
     *                      confusing - are they "existing" values or intended to be configured
     *                      values?
     * \param failures[out]        a list of parameter failures
     *
     * \retval C2_OK        all parameters could be updated successfully
     * \retval C2_BAD_INDEX all supported parameters could be updated successfully, but some
     *                      parameters were not supported
     * \retval C2_BAD_VALUE some supported parameters could not be updated successfully because
     *                      they contained unsupported values. These are returned in |failures|.
     * \retval C2_NO_MEMORY some supported parameters could not be updated successfully because
     *                      they contained unsupported values, but could not allocate a failure
     *                      object for them.
     * \retval C2_CORRUPTED some unknown error prevented the update of the parameters
     *                      (unexpected)
     */
    virtual c2_status_t commit_sm(
            const std::vector<C2Param* const> &params,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures) = 0;

    // TUNNELING
    // =============================================================================================

    /**
     * Creates a tunnel from this component to the target component.
     *
     * If the component is successfully created, subsequent work items queued may include a
     * tunneled path between these components.
     *
     * This method MUST be supported in any state.
     *
     * This method may be momentarily blocking, but MUST return within 5ms.
     *
     * \retval C2_OK        the tunnel was successfully created
     * \retval C2_BAD_INDEX the target component does not exist
     * \retval C2_DUPLICATE the tunnel already exists
     * \retval C2_OMITTED   tunneling is not supported by this component
     * \retval C2_CANNOT_DO the specific tunnel is not supported
     *
     * \retval C2_TIMED_OUT could not create the tunnel within the time limit (unexpected)
     * \retval C2_CORRUPTED some unknown error prevented the creation of the tunnel (unexpected)
     */
    virtual c2_status_t createTunnel_sm(c2_node_id_t targetComponent) = 0;

    /**
     * Releases a tunnel from this component to the target component.
     *
     * The release of a tunnel is delayed while there are pending work items for the tunnel.
     * After releasing a tunnel, subsequent work items queued MUST NOT include a tunneled
     * path between these components.
     *
     * This method MUST be supported in any state.
     *
     * This method may be momentarily blocking, but MUST return within 5ms.
     *
     * \retval C2_OK        the tunnel was marked for release successfully
     * \retval C2_BAD_INDEX the target component does not exist
     * \retval C2_NOT_FOUND the tunnel does not exist
     * \retval C2_OMITTED   tunneling is not supported by this component
     *
     * \retval C2_TIMED_OUT could not mark the tunnel for release within the time limit (unexpected)
     * \retval C2_CORRUPTED some unknown error prevented the release of the tunnel (unexpected)
     */
    virtual c2_status_t releaseTunnel_sm(c2_node_id_t targetComponent) = 0;

    // REFLECTION MECHANISM (USED FOR EXTENSION)
    // =============================================================================================

    /**
     * Returns the set of supported parameters.
     *
     * This method MUST be "non-blocking" and return within 1ms.
     *
     * \param[out] params a vector of supported parameters will be appended to this vector.
     *
     * \retval C2_OK        the operation completed successfully.
     * \retval C2_NO_MEMORY not enough memory to complete this method.
     */
    virtual c2_status_t querySupportedParams_nb(
            std::vector<std::shared_ptr<C2ParamDescriptor>> * const params) const = 0;

    /**
     * Retrieves the supported values for the queried fields.
     *
     * Client SHALL set the parameter-field specifier and the type of supported values query (e.g.
     * currently supported values, or potential supported values) in fields.
     * Upon return the component SHALL fill in the supported values for the fields listed as well
     * as a status for each field. Component shall process all fields queried even if some queries
     * fail.
     *
     * This method MUST be "non-blocking" and return within 1ms.
     *
     * \param[in out] fields a vector of fields descriptor structures.
     *
     * \retval C2_OK        the operation completed successfully.
     * \retval C2_BAD_INDEX at least one field was not recognized as a component field
     */
    virtual c2_status_t querySupportedValues_nb(
            std::vector<C2FieldSupportedValuesQuery> &fields) const = 0;

    virtual ~C2ComponentInterface() = default;
};

class C2Component {
public:
    class Listener {
    public:
        virtual void onWorkDone_nb(std::weak_ptr<C2Component> component,
                                std::vector<std::unique_ptr<C2Work>> workItems) = 0;

        virtual void onTripped_nb(std::weak_ptr<C2Component> component,
                               std::vector<std::shared_ptr<C2SettingResult>> settingResult) = 0;

        virtual void onError_nb(std::weak_ptr<C2Component> component,
                             uint32_t errorCode) = 0;

        // virtual void onTunnelReleased(<from>, <to>) = 0;

        // virtual void onComponentReleased(<id>) = 0;

    protected:
        virtual ~Listener() = default;
    };

    /**
     * Sets the listener for this component
     *
     * This method MUST be supported in all states. The listener can only be set to non-null value
     * in non-running state (that does not include tripped or error). It can be set to nullptr in
     * any state. Components only use the listener in running state.
     *
     * If listener is nullptr, the component SHALL guarantee that no more listener callbacks are
     * done to the original listener once this method returns. (Any pending listener callbacks will
     * need to be completed during this call - hence this call may be temporarily blocking.)
     *
     * This method may be momentarily blocking, but must return within 5ms.
     *
     * Component SHALL handle listener notifications from the same thread (the thread used is
     * at the component's discretion.)
     *
     * \note This could also be accomplished by passing a weak_ptr to a component-specific listener
     * here and requiring the client to always promote the weak_ptr before any callback. This would
     * put the burden on the client to clear the listener - wait for its deletion - at which point
     * it is guaranteed that no more listener callbacks will occur.
     *
     * \todo TBD is this needed? or move it to createComponent()
     *
     * \param listener the component listener object
     *
     * \retval C2_BAD_STATE attempting to change the listener in the running state (user error)
     * \retval C2_OK        listener was updated successfully.
     */
    virtual c2_status_t setListener_sm(const std::shared_ptr<Listener> &listener) = 0;

    /**
     * Information about a component.
     */
    struct Traits {
    // public:
    // TBD
    #if 0
        C2String name;             ///< name of the component
        C2DomainKind domain;       ///< component domain (e.g. audio or video)
        C2ComponentKind type;      ///< component type (e.g. encoder, decoder or filter)
        C2StringLiteral mediaType; ///< media type supported by the component
        C2ComponentPriority priority; ///< priority used to determine component ordering

        /**
         * name alias(es) for backward compatibility.
         * \note Multiple components can have the same alias as long as their media-type differs.
         */
        std::vector<C2StringLiteral> aliases; ///< name aliases for backward compatibility
    #endif
    };

    // METHODS AVAILABLE WHEN RUNNING
    // =============================================================================================

    /**
     * Queues up work for the component.
     *
     * This method MUST be supported in running (including tripped) states.
     *
     * This method MUST be "non-blocking" and return within 1ms
     *
     * It is acceptable for this method to return OK and return an error value using the
     * onWorkDone() callback.
     *
     * \retval C2_OK        the work was successfully queued
     * \retval C2_BAD_INDEX some component(s) in the work do(es) not exist
     * \retval C2_CANNOT_DO the components are not tunneled
     *
     * \retval C2_NO_MEMORY not enough memory to queue the work
     * \retval C2_CORRUPTED some unknown error prevented queuing the work (unexpected)
     */
    virtual c2_status_t queue_nb(std::list<std::unique_ptr<C2Work>>* const items) = 0;

    /**
     * Announces a work to be queued later for the component. This reserves a slot for the queue
     * to ensure correct work ordering even if the work is queued later.
     *
     * This method MUST be supported in running (including tripped) states.
     *
     * This method MUST be "non-blocking" and return within 1 ms
     *
     * \retval C2_OK        the work announcement has been successfully recorded
     * \retval C2_BAD_INDEX some component(s) in the work outline do(es) not exist
     * \retval C2_CANNOT_DO the componentes are not tunneled
     *
     * \retval C2_NO_MEMORY not enough memory to record the work announcement
     * \retval C2_CORRUPTED some unknown error prevented recording the announcement (unexpected)
     *
     * \todo Can this be rolled into queue_nb?
     * \todo Expose next work item for each component to detect stalls
     */
    virtual c2_status_t announce_nb(const std::vector<C2WorkOutline> &items) = 0;

    enum flush_mode_t : uint32_t {
        /// flush work from this component only
        FLUSH_COMPONENT,
        /// flush work from this component and all components connected downstream from it via
        /// tunneling
        FLUSH_CHAIN,
    };

    /**
     * Discards and abandons any pending work for the component, and optionally any component
     * downstream.
     *
     * \todo define this: we could flush all work before last item queued for component across all
     *                    components linked to this; flush only work items that are queued to this
     *                    component
     * \todo return work # of last flushed item; or all flushed (but not returned items)
     * \todo we could make flush take a work item and flush all work before/after that item to allow
     *       TBD (slicing/seek?)
     * \todo we could simply take a list of numbers and flush those... this is bad for decoders
     *       also, what would happen to fine grade references?
     *
     * This method MUST be supported in running (including tripped) states.
     *
     * This method may be momentarily blocking, but must return within 5ms.
     *
     * Work that could be immediately abandoned/discarded SHALL be returned in |flushedWork|; this
     * can be done in an arbitrary order.
     *
     * Work that could not be abandoned or discarded immediately SHALL be marked to be
     * discarded at the earliest opportunity, and SHALL be returned via the onWorkDone() callback.
     * This shall be completed within 500ms.
     *
     * \param mode flush mode
     *
     * \retval C2_OK        the component has been successfully flushed
     * \retval C2_TIMED_OUT the flush could not be completed within the time limit (unexpected)
     * \retval C2_CORRUPTED some unknown error prevented flushing from completion (unexpected)
     */
    virtual c2_status_t flush_sm(flush_mode_t mode, std::list<std::unique_ptr<C2Work>>* const flushedWork) = 0;

    enum drain_mode_t : uint32_t {
        /// drain component only
        DRAIN_COMPONENT,
        /// marks the last work item with a persistent "end-of-stream" marker that will drain
        /// downstream components
        /// \todo this may confuse work-ordering downstream
        DRAIN_CHAIN,
        /**
         * \todo define this; we could place EOS to all upstream components, just this component, or
         *       all upstream and downstream component.
         * \todo should EOS carry over to downstream components?
         */
    };

    /**
     * Drains the component, and optionally downstream components. This is a signalling method;
     * as such it does not wait for any work completion.
     *
     * Marks last work item as "end-of-stream", so component is notified not to wait for further
     * work before it processes work already queued. This method is called to set the end-of-stream
     * flag after work has been queued. Client can continue to queue further work immediately after
     * this method returns.
     *
     * This method MUST be supported in running (including tripped) states.
     *
     * This method MUST be "non-blocking" and return within 1ms.
     *
     * Work that is completed SHALL be returned via the onWorkDone() callback.
     *
     * \param mode drain mode
     *
     * \retval C2_OK        the drain request has been successfully recorded
     * \retval C2_TIMED_OUT the flush could not be completed within the time limit (unexpected)
     * \retval C2_CORRUPTED some unknown error prevented flushing from completion (unexpected)
     */
    virtual c2_status_t drain_nb(drain_mode_t mode) = 0;

    // STATE CHANGE METHODS
    // =============================================================================================

    /**
     * Starts the component.
     *
     * This method MUST be supported in stopped state.
     *
     * \todo This method MUST return within 500ms. Seems this should be able to return quickly, as
     * there are no immediate guarantees. Though there are guarantees for responsiveness immediately
     * after start returns.
     *
     * \retval C2_OK        the component has started successfully
     * \retval C2_NO_MEMORY not enough memory to start the component
     * \retval C2_TIMED_OUT the component could not be started within the time limit (unexpected)
     * \retval C2_CORRUPTED some unknown error prevented starting the component (unexpected)
     */
    virtual c2_status_t start() = 0;

    /**
     * Stops the component.
     *
     * This method MUST be supported in running (including tripped) state.
     *
     * This method MUST return withing 500ms.
     *
     * Upon this call, all pending work SHALL be abandoned.
     *
     * \todo should this return completed work, since client will just free it? Perhaps just to
     * verify accounting.
     *
     * This does not alter any settings and tunings that may have resulted in a tripped state.
     * (Is this material given the definition? Perhaps in case we want to start again.)
     */
    virtual c2_status_t stop() = 0;

    /**
     * Resets the component.
     *
     * This method MUST be supported in all (including tripped) state.
     *
     * This method MUST be supported during any other blocking call.
     *
     * This method MUST return withing 500ms.
     *
     * After this call returns all work is/must be abandoned, all references should be released.
     *
     * \todo should this return completed work, since client will just free it? Also, if it unblocks
     * a stop, where should completed work be returned?
     *
     * This brings settings back to their default - "guaranteeing" no tripped space.
     *
     * \todo reclaim support - it seems that since ownership is passed, this will allow reclaiming stuff.
     *
     * \retval C2_OK        the component has been reset
     * \retval C2_TIMED_OUT the component could not be reset within the time limit (unexpected)
     * \retval C2_CORRUPTED some unknown error prevented resetting the component (unexpected)
     */
    virtual void reset() = 0;

    /**
     * Releases the component.
     *
     * This method MUST be supported in stopped state.
     *
     * This method MUST return withing 500ms. Upon return all references shall be abandoned.
     *
     * \retval C2_OK        the component has been released
     * \retval C2_BAD_STATE the component is running
     * \retval C2_TIMED_OUT the component could not be released within the time limit (unexpected)
     * \retval C2_CORRUPTED some unknown error prevented releasing the component (unexpected)
     */
    virtual void release() = 0;

    /**
     * Returns the interface for this component.
     *
     * \return the component interface
     */
    virtual std::shared_ptr<C2ComponentInterface> intf() = 0;

    virtual ~C2Component() = default;
};

class C2FrameInfoParser {
public:
    /**
     * \return the content type supported by this info parser.
     *
     * \todo this may be redundant
     */
    virtual C2StringLiteral getType() const = 0;

    /**
     * \return a vector of supported parameter indices parsed by this info parser.
     *
     * This method MUST be "non-blocking" and return within 1ms.
     *
     * \todo sticky vs. non-sticky params? this may be communicated by param-reflector.
     */
    virtual const std::vector<C2Param::Index> getParsedParams() const = 0;

    /**
     * Resets this info parser. This brings this parser to its initial state after creation.
     *
     * This method SHALL return within 5ms.
     *
     * \retval C2_OK        the info parser was reset
     * \retval C2_TIMED_OUT could not reset the parser within the time limit (unexpected)
     * \retval C2_CORRUPTED some unknown error prevented the resetting of the parser (unexpected)
     */
    virtual c2_status_t reset() { return C2_OK; }

    virtual c2_status_t parseFrame(C2BufferPack &frame);

    virtual ~C2FrameInfoParser() = default;
};

class C2AllocatorStore {
public:
    typedef C2Allocator::id_t id_t;

    enum : C2Allocator::id_t {
        DEFAULT_LINEAR,     ///< basic linear allocator type
        DEFAULT_GRAPHIC,    ///< basic graphic allocator type
        PLATFORM_START = 0x10,
        VENDOR_START   = 0x100,
    };

    /**
     * Returns the unique name of this allocator store.
     *
     * This method MUST be "non-blocking" and return within 1ms.
     *
     * \return the name of this allocator store.
     * \retval an empty string if there was not enough memory to allocate the actual name.
     */
    virtual C2String getName() const = 0;

    /**
     * Returns the set of allocators supported by this allocator store.
     *
     * This method MUST be "non-blocking" and return within 1ms.
     *
     * \retval vector of allocator information (as shared pointers)
     * \retval an empty vector if there was not enough memory to allocate the whole vector.
     */
    virtual std::vector<std::shared_ptr<const C2Allocator::Traits>> listAllocators_nb() const = 0;

    /**
     * Retrieves/creates a shared allocator object.
     *
     * This method MUST be return within 5ms.
     *
     * The allocator is created on first use, and the same allocator is returned on subsequent
     * concurrent uses in the same process. The allocator is freed when it is no longer referenced.
     *
     * \param id      the ID of the allocator to create. This is defined by the store, but
     *                the ID of the default linear and graphic allocators is formalized.
     * \param allocator shared pointer where the created allocator is stored. Cleared on failure
     *                  and updated on success.
     *
     * \retval C2_OK        the allocator was created successfully
     * \retval C2_TIMED_OUT could not create the allocator within the time limit (unexpected)
     * \retval C2_CORRUPTED some unknown error prevented the creation of the allocator (unexpected)
     *
     * \retval C2_NOT_FOUND no such allocator
     * \retval C2_NO_MEMORY not enough memory to create the allocator
     */
    virtual c2_status_t fetchAllocator(id_t id, std::shared_ptr<C2Allocator>* const allocator) = 0;

    virtual ~C2AllocatorStore() = default;
};

class C2ComponentStore {
public:
    /**
     * Returns the name of this component or component interface object.
     * This is a unique name for this component or component interface 'class'; however, multiple
     * instances of this component SHALL have the same name.
     *
     * This method MUST be supported in any state. This call does not change the state nor the
     * internal states of the component.
     *
     * This method MUST be "non-blocking" and return within 1ms.
     *
     * \return the name of this component or component interface object.
     * \retval an empty string if there was not enough memory to allocate the actual name.
     */
    virtual C2String getName() const = 0;

    /**
     * Creates a component.
     *
     * This method SHALL return within 100ms.
     *
     * \param name          name of the component to create
     * \param component     shared pointer where the created component is stored. Cleared on
     *                      failure and updated on success.
     *
     * \retval C2_OK        the component was created successfully
     * \retval C2_TIMED_OUT could not create the component within the time limit (unexpected)
     * \retval C2_CORRUPTED some unknown error prevented the creation of the component (unexpected)
     *
     * \retval C2_NOT_FOUND no such component
     * \retval C2_NO_MEMORY not enough memory to create the component
     */
    virtual c2_status_t createComponent(
            C2String name, std::shared_ptr<C2Component>* const component) = 0;

    /**
     * Creates a component interface.
     *
     * This method SHALL return within 100ms.
     *
     * \param name          name of the component interface to create
     * \param interface     shared pointer where the created interface is stored
     *
     * \retval C2_OK        the component interface was created successfully
     * \retval C2_TIMED_OUT could not create the component interface within the time limit
     *                      (unexpected)
     * \retval C2_CORRUPTED some unknown error prevented the creation of the component interface
     *                      (unexpected)
     *
     * \retval C2_NOT_FOUND no such component interface
     * \retval C2_NO_MEMORY not enough memory to create the component interface
     *
     * \todo Do we need an interface, or could this just be a component that is never started?
     */
    virtual c2_status_t createInterface(
            C2String name, std::shared_ptr<C2ComponentInterface>* const interface) = 0;

    /**
     * Returns the list of components supported by this component store.
     *
     * This method MUST return within 500ms.
     *
     * \retval vector of component information.
     */
    virtual std::vector<std::shared_ptr<const C2Component::Traits>> listComponents() = 0;

    // -------------------------------------- UTILITY METHODS --------------------------------------

    // on-demand buffer layout conversion (swizzling)
    //
    virtual c2_status_t copyBuffer(
            std::shared_ptr<C2GraphicBuffer> src, std::shared_ptr<C2GraphicBuffer> dst) = 0;

    // -------------------------------------- CONFIGURATION API -----------------------------------
    // e.g. for global settings (system-wide stride, etc.)

    /**
     * Queries a set of system-wide parameters.
     * Querying is performed at best effort: the store SHALL query all supported parameters and
     * skip unsupported ones, or heap allocated parameters that could not be allocated. Any errors
     * are communicated in the return value. Additionally, preallocated (e.g. stack) parameters that
     * could not be queried are invalidated. Parameters to be allocated on the heap are omitted from
     * the result.
     *
     * \note Parameter values do not depend on the order of query.
     *
     * This method may be momentarily blocking, but MUST return within 5ms.
     *
     * \param stackParams   a list of params queried. These are initialized specific to each
     *                      setting; e.g. size and index are set and rest of the members are
     *                      cleared.
     *                      NOTE: Flexible settings that are of incorrect size will be invalidated.
     * \param heapParamIndices a vector of param indices for params to be queried and returned on the
     *                      heap. These parameters will be returned in heapParams. Unsupported param
     *                      indices will be ignored.
     * \param heapParams    a list of params where to which the supported heap parameters will be
     *                      appended in the order they appear in heapParamIndices.
     *
     * \retval C2_OK        all parameters could be queried
     * \retval C2_BAD_INDEX all supported parameters could be queried, but some parameters were not
     *                      supported
     * \retval C2_NO_MEMORY could not allocate memory for a supported parameter
     * \retval C2_CORRUPTED some unknown error prevented the querying of the parameters
     *                      (unexpected)
     */
    virtual c2_status_t query_sm(
        const std::vector<C2Param* const> &stackParams,
        const std::vector<C2Param::Index> &heapParamIndices,
        std::vector<std::unique_ptr<C2Param>>* const heapParams) const = 0;

    /**
     * Sets a set of system-wide parameters.
     *
     * \note There are no settable system-wide parameters defined thus far, but may be added in the
     * future.
     *
     * Tuning is performed at best effort: the store SHALL update all supported configuration at
     * best effort (unless configured otherwise) and skip unsupported ones. Any errors are
     * communicated in the return value and in |failures|.
     *
     * \note Parameter tuning DOES depend on the order of the tuning parameters. E.g. some parameter
     * update may allow some subsequent parameter update.
     *
     * This method may be momentarily blocking, but MUST return within 5ms.
     *
     * \param params        a list of parameter updates. These will be updated to the actual
     *                      parameter values after the updates (this is because tuning is performed
     *                      at best effort).
     *                      \todo params that could not be updated are not marked here, so are
     *                      confusing - are they "existing" values or intended to be configured
     *                      values?
     * \param failures      a list of parameter failures
     *
     * \retval C2_OK        all parameters could be updated successfully
     * \retval C2_BAD_INDEX all supported parameters could be updated successfully, but some
     *                      parameters were not supported
     * \retval C2_BAD_VALUE some supported parameters could not be updated successfully because
     *                      they contained unsupported values. These are returned in |failures|.
     * \retval C2_NO_MEMORY some supported parameters could not be updated successfully because
     *                      they contained unsupported values, but could not allocate a failure
     *                      object for them.
     * \retval C2_CORRUPTED some unknown error prevented the update of the parameters
     *                      (unexpected)
     */
    virtual c2_status_t config_sm(
            const std::vector<C2Param* const> &params,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures) = 0;

    /**
     * Atomically sets a set of system-wide parameters.
     *
     * \note There are no settable system-wide parameters defined thus far, but may be added in the
     * future.
     *
     * The component store SHALL update all supported configuration at best effort(TBD)
     * (unless configured otherwise) and skip unsupported ones. If any errors are encountered
     * (other than unsupported parameters), the configuration SHALL be aborted as if it did not
     * happen.
     *
     * \note Parameter tuning DOES depend on the order of the tuning parameters. E.g. some parameter
     * update may allow some subsequent parameter update.
     *
     * This method may be momentarily blocking, but MUST return within 5ms.
     *
     * \param params[in,out] a list of parameter updates. These will be updated to the actual
     *                       parameter values after the updates (this is because tuning is performed
     *                       at best effort).
     *                       \todo params that could not be updated are not marked here, so are
     *                       confusing - are they "existing" values or intended to be configured
     *                       values?
     * \param failures[out]  a list of parameter failures
     *
     * \retval C2_OK        all parameters could be updated successfully
     * \retval C2_BAD_INDEX all supported parameters could be updated successfully, but some
     *                      parameters were not supported
     * \retval C2_BAD_VALUE some supported parameters could not be updated successfully because
     *                      they contained unsupported values. These are returned in |failures|.
     * \retval C2_NO_MEMORY some supported parameters could not be updated successfully because
     *                      they contained unsupported values, but could not allocate a failure
     *                      object for them.
     * \retval C2_CORRUPTED some unknown error prevented the update of the parameters
     *                      (unexpected)
     */
    virtual c2_status_t commit_sm(
            const std::vector<C2Param* const> &params,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures) = 0;

    // REFLECTION MECHANISM (USED FOR EXTENSION)
    // =============================================================================================

    /**
     * Returns the parameter reflector.
     *
     * This is used to describe parameter fields. This is shared for all components created by
     * this component store.
     *
     * This method MUST be "non-blocking" and return within 1ms.
     *
     * \return a shared parameter reflector object.
     */
    virtual std::shared_ptr<C2ParamReflector> getParamReflector() const = 0;

    /**
     * Returns the set of supported parameters.
     *
     * This method MUST be "non-blocking" and return within 1ms.
     *
     * \param[out] params a vector of supported parameters will be appended to this vector.
     *
     * \retval C2_OK        the operation completed successfully.
     * \retval C2_NO_MEMORY not enough memory to complete this method.
     */
    virtual c2_status_t querySupportedParams_nb(
            std::vector<std::shared_ptr<C2ParamDescriptor>> * const params) const = 0;

    /**
     * Retrieves the supported values for the queried fields.
     *
     * Client SHALL set the parameter-field specifier and the type of supported values query (e.g.
     * currently supported values, or potential supported values) in fields.
     * Upon return the store SHALL fill in the supported values for the fields listed as well
     * as a status for each field. Store shall process all fields queried even if some queries
     * fail.
     *
     * This method MUST be "non-blocking" and return within 1ms.
     *
     * \param[in out] fields a vector of fields descriptor structures.
     *
     * \retval C2_OK        the operation completed successfully.
     * \retval C2_BAD_INDEX at least one field was not recognized as a component store field
     */
    virtual c2_status_t querySupportedValues_nb(
            std::vector<C2FieldSupportedValuesQuery> &fields) const = 0;

    virtual ~C2ComponentStore() = default;
};

// ================================================================================================

/// @}

}  // namespace android

#endif  // C2COMPONENT_H_
