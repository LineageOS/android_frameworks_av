/*
 * Copyright (C) 2023 The Android Open Source Project
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

package android.media.audio;

import android.hardware.audio.core.VendorParameter;

/**
 * This interface is used by the HAL adapter of the Audio Server. Implementation
 * is optional. Vendors may provide an implementation on the system_ext
 * partition. The default instance of this interface, if provided, must be
 * registered prior to the moment when the audio server connects to HAL modules.
 * Vendors need to set the system property `ro.audio.ihaladaptervendorextension_enabled`
 * to `true` for the framework to bind to this service.
 *
 * {@hide}
 */
interface IHalAdapterVendorExtension {
    enum ParameterScope {
        MODULE = 0,
        STREAM = 1,
    }

    /**
     * Parse raw parameter keys into vendor parameter ids.
     *
     * This method prepares arguments for a call to the 'getVendorParameters'
     * method of an 'IModule' or an 'IStreamCommon' interface instance,
     * depending on the provided scope.
     *
     * The client calls this method in order to prepare arguments for a call to
     * the particular Core HAL interface. The result returned by the HAL is then
     * processed using the 'processVendorParameters' method. It is not required
     * to maintain a 1:1 correspondence between the provided raw keys and the
     * elements of the parsed result. If the returned list is empty, the call of
     * 'getVendorParameters' is skipped. The implementation can either ignore
     * keys which it does not recognize, or throw an error. The latter is
     * preferred as it can help in discovering malformed key names.
     *
     * @param scope The scope of all raw parameter keys.
     * @param rawKeys Raw parameter keys, joined into a string using a semicolon
     *                (';') as the delimiter.
     * @return A list of vendor parameter IDs, see android.hardware.audio.core.VendorParameter.
     * @throws EX_ILLEGAL_ARGUMENT If the implementation can not parse the raw keys
     *                             and prefers to signal an error.
     */
    @utf8InCpp String[] parseVendorParameterIds(
            ParameterScope scope, in @utf8InCpp String rawKeys);

    /**
     * Parse raw parameter key-value pairs into vendor parameters.
     *
     * This method prepares arguments for a call to the 'setVendorParameters'
     * method of an 'IModule' or an 'IStreamCommon' interface instance,
     * depending on the provided scope.
     *
     * The vendor parameters returned using 'syncParameters' argument is then
     * used to call the 'setVendorParameters' method with 'async = false', and
     * 'asyncParameters' is used in a subsequent call to the same method, but
     * with 'async = true'. It is not required to maintain a 1:1 correspondence
     * between the provided key-value pairs and the elements of parsed
     * results. If any of the returned lists of vendor parameters is empty, then
     * the corresponding call is skipped. The implementation can either ignore
     * keys which it does not recognize, and invalid values, or throw an
     * error. The latter is preferred as it can help in discovering malformed
     * key names and values.
     *
     * @param scope The scope of all raw key-value pairs.
     * @param rawKeys Raw key-value pairs, separated by the "equals" sign ('='),
     *                joined into a string using a semicolon (';') as the delimiter.
     * @param syncParameters A list of vendor parameters to be set synchronously.
     * @param asyncParameters A list of vendor parameters to be set asynchronously.
     * @throws EX_ILLEGAL_ARGUMENT If the implementation can not parse raw key-value
     *                             pairs and prefers to signal an error.
     */
    void parseVendorParameters(
            ParameterScope scope, in @utf8InCpp String rawKeysAndValues,
            out VendorParameter[] syncParameters, out VendorParameter[] asyncParameters);

    /**
     * Parse raw value of the parameter for BT A2DP reconfiguration.
     *
     * This method may return any number of vendor parameters (including zero)
     * which will be passed to the 'IBluetoothA2dp.reconfigureOffload' method.
     *
     * @param rawValue An unparsed value of the legacy parameter.
     * @return A list of vendor parameters.
     * @throws EX_ILLEGAL_ARGUMENT If the implementation can not parse the raw value.
     */
    VendorParameter[] parseBluetoothA2dpReconfigureOffload(in @utf8InCpp String rawValue);

    /**
     * Parse raw value of the parameter for BT LE reconfiguration.
     *
     * This method may return any number of vendor parameters (including zero)
     * which will be passed to the 'IBluetoothLe.reconfigureOffload' method.
     *
     * @param rawValue An unparsed value of the legacy parameter.
     * @return A list of vendor parameters.
     * @throws EX_ILLEGAL_ARGUMENT If the implementation can not parse the raw value.
     */
    VendorParameter[] parseBluetoothLeReconfigureOffload(in @utf8InCpp String rawValue);

    /**
     * Process vendor parameters returned by the Audio Core HAL.
     *
     * This processes the result returned from a call to the
     * 'getVendorParameters' method of an 'IModule' or an 'IStreamCommon'
     * interface instance, depending on the provided scope.
     *
     * See 'parseVendorParameterIds' method for the flow description.  It is not
     * required to maintain a 1:1 correspondence between the elements of the
     * provided list and the emitted key-value pairs. The returned string with
     * raw key-value pairs is passed back to the framework.
     *
     * @param scope The scope of vendor parameters.
     * @param parameters Vendor parameters, see android.hardware.audio.core.VendorParameter.
     * @return Key-value pairs, separated by the "equals" sign ('='),
     *         joined into a string using a semicolon (';') as the delimiter.
     * @throws EX_ILLEGAL_ARGUMENT If the implementation can not emit raw key-value
     *                             pairs and prefers to signal an error.
     */
    @utf8InCpp String processVendorParameters(
            ParameterScope scope, in VendorParameter[] parameters);
}
