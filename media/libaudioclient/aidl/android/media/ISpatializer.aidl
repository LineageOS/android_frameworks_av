/*
 * Copyright 2021 The Android Open Source Project
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

package android.media;

import android.media.ISpatializerHeadTrackingCallback;
import android.media.SpatializationLevel;
import android.media.SpatializationMode;
import android.media.SpatializerHeadTrackingMode;


/**
 * The ISpatializer interface is used to control the native audio service implementation
 * of the spatializer stage with headtracking when present on a platform.
 * It is intended for exclusive use by the java AudioService running in system_server.
 * It provides APIs to discover the feature availability and options as well as control and report
 * the active state and modes of the spatializer and head tracking effect.
 * {@hide}
 */
interface ISpatializer {
    /** Releases a ISpatializer interface previously acquired. */
    void release();

    /** Reports the list of supported spatialization levels (see SpatializationLevel.aidl).
     * The list should never be empty if an ISpatializer interface was successfully
     * retrieved with IAudioPolicyService.getSpatializer().
     */
    SpatializationLevel[] getSupportedLevels();

    /** Selects the desired spatialization level (see SpatializationLevel.aidl). Selecting a level
     * different from SpatializationLevel.NONE with create the specialized multichannel output
     * mixer, create and enable the spatializer effect and let the audio policy attach eligible
     * AudioTrack to this output stream.
     */
    void setLevel(SpatializationLevel level);

    /** Gets the selected spatialization level (see SpatializationLevel.aidl) */
    SpatializationLevel getLevel();

    /** Reports if the spatializer engine supports head tracking or not.
     * This is a pre condition independent of the fact that a head tracking sensor is
     * registered or not.
     */
    boolean isHeadTrackingSupported();

    /** Reports the list of supported head tracking modes (see SpatializerHeadTrackingMode.aidl).
     * The list always contains SpatializerHeadTrackingMode.DISABLED and can include other modes
     * if the spatializer effect implementation supports head tracking.
     * The result does not depend on currently connected sensors but reflects the capabilities
     * when sensors are available.
     */
    SpatializerHeadTrackingMode[] getSupportedHeadTrackingModes();

    /** Selects the desired head tracking mode (see SpatializerHeadTrackingMode.aidl) */
    void setDesiredHeadTrackingMode(SpatializerHeadTrackingMode mode);

    /** Gets the actual head tracking mode. Can be different from the desired mode if conditions to
     * enable the desired mode are not met (e.g if the head tracking device was removed)
     */
    SpatializerHeadTrackingMode getActualHeadTrackingMode();

    /** Reset the head tracking algorithm to consider current head pose as neutral */
    void recenterHeadTracker();

    /** Set the screen to stage transform to use by the head tracking algorithm
     * The screen to stage transform is conveyed as a vector of 6 elements,
     * where the first three are a translation vector and
     * the last three are a rotation vector.
     */
    void setGlobalTransform(in float[] screenToStage);

    /**
     * Set the sensor that is to be used for head-tracking.
     * -1 can be used to disable head-tracking.
     */
    void setHeadSensor(int sensorHandle);

    /**
     * Set the sensor that is to be used for screen-tracking.
     * -1 can be used to disable screen-tracking.
     */
    void setScreenSensor(int sensorHandle);

    /**
     * Sets the display orientation.
     *
     * This is the rotation of the displayed content relative to its natural orientation.
     *
     * Orientation is expressed in the angle of rotation from the physical "up" side of the screen
     * to the logical "up" side of the content displayed the screen. Counterclockwise angles, as
     * viewed while facing the screen are positive.
     *
     * Note: DisplayManager currently only returns this in increments of 90 degrees,
     * so the values will be 0, PI/2, PI, 3PI/2.
     */
    void setDisplayOrientation(float physicalToLogicalAngle);

    /**
     * Sets the hinge angle for foldable devices.
     *
     * Per the hinge angle sensor, this returns a value from 0 to 2PI.
     * The value of 0 is considered closed, and PI is considered flat open.
     */
    void setHingeAngle(float hingeAngle);

    /**
     * Sets whether a foldable is considered "folded" or not.
     *
     * The fold state may affect which physical screen is active for display.
     */
    void setFoldState(boolean folded);

    /** Reports the list of supported spatialization modess (see SpatializationMode.aidl).
     * The list should never be empty if an ISpatializer interface was successfully
     * retrieved with IAudioPolicyService.getSpatializer().
     */
    SpatializationMode[] getSupportedModes();

    /**
     * Registers a callback to monitor head tracking functions.
     * Only one callback can be registered on a Spatializer.
     * The last callback registered wins and passing a nullptr unregisters
     * last registered callback.
     */
    void registerHeadTrackingCallback(@nullable ISpatializerHeadTrackingCallback callback);

    /**
     * Sets a parameter to the spatializer engine. Used by effect implementor for vendor
     * specific configuration.
     */
     void setParameter(int key, in byte[] value);

    /**
     * Gets a parameter from the spatializer engine. Used by effect implementor for vendor
     * specific configuration.
     */
     void getParameter(int key, inout byte[] value);

    /**
     * Gets the io handle of the output stream the spatializer is connected to.
     */
     int getOutput();
}
