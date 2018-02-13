/*
 * Copyright 2018, The Android Open Source Project
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

#ifndef INPUT_SURFACE_WRAPPER_H_

#define INPUT_SURFACE_WRAPPER_H_

namespace android {

/**
 * Wrapper interface around InputSurface.
 */
class InputSurfaceWrapper {
public:
    virtual ~InputSurfaceWrapper() = default;

    /**
     * Connect the surface with |comp| and start pushing buffers. A surface can
     * connect to at most one component at a time.
     *
     * \return OK               successfully connected to |comp|
     * \return ALREADY_EXISTS   already connected to another component.
     */
    virtual status_t connect(const std::shared_ptr<C2Component> &comp) = 0;

    /**
     * Disconnect the surface from the component if any.
     */
    virtual void disconnect() = 0;

    // TODO: intf()
};

}  // namespace android

#endif  // INPUT_SURFACE_WRAPPER_H_
