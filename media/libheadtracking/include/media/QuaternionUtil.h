/*
 * Copyright (C) 2021 The Android Open Source Project
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
#pragma once

#include <android-base/stringprintf.h>
#include <Eigen/Geometry>
#include <media/Pose.h>

namespace android {
namespace media {

/**
 * Converts a rotation vector to an equivalent quaternion.
 * The rotation vector is given as a 3-vector whose direction represents the rotation axis and its
 * magnitude the rotation angle (in radians) around that axis.
 */
Eigen::Quaternionf rotationVectorToQuaternion(const Eigen::Vector3f& rotationVector);

/**
 * Converts a quaternion to an equivalent rotation vector.
 * The rotation vector is given as a 3-vector whose direction represents the rotation axis and its
 * magnitude the rotation angle (in radians) around that axis.
 */
Eigen::Vector3f quaternionToRotationVector(const Eigen::Quaternionf& quaternion);

/**
 * Returns a quaternion representing a rotation around the X-axis with the given amount (in
 * radians).
 */
Eigen::Quaternionf rotateX(float angle);

/**
 * Returns a quaternion representing a rotation around the Y-axis with the given amount (in
 * radians).
 */
Eigen::Quaternionf rotateY(float angle);

/**
 * Returns a quaternion representing a rotation around the Z-axis with the given amount (in
 * radians).
 */
Eigen::Quaternionf rotateZ(float angle);

/**
 * Compute separate roll, pitch, and yaw angles from a quaternion
 *
 * The roll, pitch, and yaw follow standard 3DOF virtual reality definitions
 * with angles increasing counter-clockwise by the right hand rule.
 *
 * https://en.wikipedia.org/wiki/Six_degrees_of_freedom
 *
 * The roll, pitch, and yaw angles are calculated separately from the device frame
 * rotation from the world frame.  This is not to be confused with the
 * intrinsic Euler xyz roll, pitch, yaw 'nautical' angles.
 *
 * The input quarternion is the active rotation that transforms the
 * World/Stage frame to the Head/Screen frame.
 *
 * The input quaternion may come from two principal sensors: DEVICE and HEADSET
 * and are interpreted as below.
 *
 * DEVICE SENSOR
 *
 * Android sensor stack assumes device coordinates along the x/y axis.
 *
 * https://developer.android.com/reference/android/hardware/SensorEvent#sensor.type_rotation_vector:
 *
 * Looking down from the clouds. Android Device coordinate system (not used)
 *        DEVICE --> X (Y goes through top speaker towards the observer)
 *           | Z
 *           V
 *         USER
 *
 * Internally within this library, we transform the device sensor coordinate
 * system by rotating the coordinate system around the X axis by -M_PI/2.
 * This aligns the device coordinate system to match that of the
 * Head Tracking sensor (see below), should the user be facing the device in
 * natural (phone == portrait, tablet == ?) orientation.
 *
 * Looking down from the clouds. Spatializer device frame.
 *           Y
 *           ^
 *           |
 *        DEVICE --> X (Z goes through top of the DEVICE towards the observer)
 *
 *         USER
 *
 * The reference world frame is the device in vertical
 * natural (phone == portrait) orientation with the top pointing straight
 * up from the ground and the front-to-back direction facing north.
 * The world frame is presumed locally fixed by magnetic and gravitational reference.
 *
 * HEADSET SENSOR
 * https://developer.android.com/reference/android/hardware/SensorEvent#sensor.type_head_tracker:
 *
 * Looking down from the clouds. Headset frame.
 *           Y
 *           ^
 *           |
 *         USER ---> X
 *         (Z goes through the top of the USER head towards the observer)
 *
 * The Z axis goes from the neck to the top of the head, the X axis goes
 * from the left ear to the right ear, the Y axis goes from the back of the
 * head through the nose.
 *
 * Typically for a headset sensor, the X and Y axes have some arbitrary fixed
 * reference.
 *
 * ROLL
 * Roll is the counter-clockwise L/R motion around the Y axis (hence ZX plane).
 * The right hand convention means the plane is ZX not XZ.
 * This can be considered the azimuth angle in spherical coordinates
 * with Pitch being the elevation angle.
 *
 * Roll has a range of -M_PI to M_PI radians.
 *
 * Rolling a device changes between portrait and landscape
 * modes, and for L/R speakers will limit the amount of crosstalk cancellation.
 * Roll increases as the device (if vertical like a coin) rolls from left to right.
 *
 * By this definition, Roll is less accurate when the device is flat
 * on a table rather than standing on edge.
 * When perfectly flat on the table, roll may report as 0, M_PI, or -M_PI
 * due ambiguity / degeneracy of atan(0, 0) in this case (the device Y axis aligns with
 * the world Z axis), but exactly flat rarely occurs.
 *
 * Roll for a headset is the angle the head is inclined to the right side
 * (like sleeping).
 *
 * PITCH
 * Pitch is the Surface normal Y deviation (along the Z axis away from the earth).
 * This can be considered the elevation angle in spherical coordinates using
 * Roll as the azimuth angle.
 *
 * Pitch for a device determines whether the device is "upright" or lying
 * flat on the table (i.e. surface normal).  Pitch is 0 when upright, decreases
 * as the device top moves away from the user to -M_PI/2 when lying down face up.
 * Pitch increases from 0 to M_PI/2 when the device tilts towards the user, and is
 * M_PI/2 degrees when face down.
 *
 * Pitch for a headset is the user tilting the head/chin up or down,
 * like nodding.
 *
 * Pitch has a range of -M_PI/2, M_PI/2 radians.
 *
 * YAW
 * Yaw is the rotational component along the earth's XY tangential plane,
 * where the Z axis points radially away from the earth.
 *
 * Yaw has a range of -M_PI to M_PI radians.  If used for azimuth angle in
 * spherical coordinates, the elevation angle may be derived from the Z axis.
 *
 * A positive increase means the phone is rotating from right to left
 * when considered flat on the table.
 * (headset: the user is rotating their head to look left).
 * If left speaker or right earbud is pointing straight up or down,
 * this value is imprecise and Pitch or Roll is a more useful measure.
 *
 * Yaw for a device is like spinning a vertical device along the axis of
 * gravity, like spinning a coin.  Yaw increases as the coin / device
 * spins from right to left, rotating around the Z axis.
 *
 * Yaw for a headset is the user turning the head to look left or right
 * like shaking the head for no. Yaw is the primary angle for a binaural
 * head tracking device.
 *
 * @param q input active rotation Eigen quaternion.
 * @param pitch output set to pitch if not nullptr
 * @param roll output set to roll if not nullptr
 * @param yaw output set to yaw if not nullptr
 * @return (DEBUG==true) a debug string with intermediate transformation matrix
 *                       interpreted as the unit basis vectors.
 */

// DEBUG returns a debug string for analysis.
// We save unneeded rotation matrix computation by keeping the DEBUG option constexpr.
template <bool DEBUG = false>
auto quaternionToAngles(const Eigen::Quaternionf& q, float *pitch, float *roll, float *yaw) {
    /*
     * The quaternion here is the active rotation that transforms from the world frame
     * to the device frame: the observer remains in the world frame,
     * and the device (frame) moves.
     *
     * We use this to map device coordinates to world coordinates.
     *
     * Device:  We transform the device right speaker (X == 1), top speaker (Z == 1),
     * and surface inwards normal (Y == 1) positions to the world frame.
     *
     * Headset: We transform the headset right bud (X == 1), top (Z == 1) and
     * nose normal (Y == 1) positions to the world frame.
     *
     * This is the same as the world frame coordinates of the
     *  unit device vector in the X dimension (ux),
     *  unit device vector in the Y dimension (uy),
     *  unit device vector in the Z dimension (uz).
     *
     * Rather than doing the rotation on unit vectors individually,
     * one can simply use the columns of the rotation matrix of
     * the world-to-body quaternion, so the computation is exceptionally fast.
     *
     * Furthermore, Eigen inlines the "toRotationMatrix" method
     * and we rely on unused expression removal for efficiency
     * and any elements not used should not be computed.
     *
     * Side note: For applying a rotation to several points,
     * it is more computationally efficient to extract and
     * use the rotation matrix form than the quaternion.
     * So use of the rotation matrix is good for many reasons.
     */
    const auto rotation = q.toRotationMatrix();

    /*
     * World location of unit vector right speaker assuming the phone is situated
     * natural (phone == portrait) mode.
     * (headset: right bud).
     *
     * auto ux = q.rotation() * Eigen::Vector3f{1.f, 0.f, 0.f};
     *         = rotation.col(0);
     */
    [[maybe_unused]] const auto ux_0 = rotation.coeff(0, 0);
    [[maybe_unused]] const auto ux_1 = rotation.coeff(1, 0);
    [[maybe_unused]] const auto ux_2 = rotation.coeff(2, 0);

    [[maybe_unused]] std::string coordinates;
    if constexpr (DEBUG) {
        base::StringAppendF(&coordinates, "ux: %f %f %f", ux_0, ux_1, ux_2);
    }

    /*
     * World location of screen-inwards normal assuming the phone is situated
     * in natural (phone == portrait) mode.
     * (headset: user nose).
     *
     * auto uy = q.rotation() * Eigen::Vector3f{0.f, 1.f, 0.f};
     *         = rotation.col(1);
     */
    [[maybe_unused]] const auto uy_0 = rotation.coeff(0, 1);
    [[maybe_unused]] const auto uy_1 = rotation.coeff(1, 1);
    [[maybe_unused]] const auto uy_2 = rotation.coeff(2, 1);
    if constexpr (DEBUG) {
        base::StringAppendF(&coordinates, "uy: %f %f %f", uy_0, uy_1, uy_2);
    }

    /*
     * World location of unit vector top speaker.
     * (headset: top of head).
     * auto uz = q.rotation() * Eigen::Vector3f{0.f, 0.f, 1.f};
     *         = rotation.col(2);
     */
    [[maybe_unused]] const auto uz_0 = rotation.coeff(0, 2);
    [[maybe_unused]] const auto uz_1 = rotation.coeff(1, 2);
    [[maybe_unused]] const auto uz_2 = rotation.coeff(2, 2);
    if constexpr (DEBUG) {
        base::StringAppendF(&coordinates, "uz: %f %f %f", uz_0, uz_1, uz_2);
    }

    // pitch computed from nose world Z coordinate;
    // hence independent of rotation around world Z.
    if (pitch != nullptr) {
        *pitch = asin(std::clamp(uy_2, -1.f, 1.f));
    }

    // roll computed from head/right world Z coordinate;
    // hence independent of rotation around world Z.
    if (roll != nullptr) {
        // atan2 takes care of implicit scale normalization of Z, X.
        *roll = -atan2(ux_2, uz_2);
    }

    // yaw computed from right ear angle projected onto world XY plane
    // where world Z == 0.  This is the rotation around world Z.
    if (yaw != nullptr) {
        // atan2 takes care of implicit scale normalization of X, Y.
        *yaw =  atan2(ux_1, ux_0);
    }

    if constexpr (DEBUG) {
        return coordinates;
    }
}

}  // namespace media
}  // namespace android
