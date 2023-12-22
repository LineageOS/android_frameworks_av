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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_EGLPROGRAM_H
#define ANDROID_COMPANION_VIRTUALCAMERA_EGLPROGRAM_H

#include <array>

#include "GLES/gl.h"

namespace android {
namespace companion {
namespace virtualcamera {

// Base class for EGL Shader programs representation.
class EglProgram {
 public:
  virtual ~EglProgram();

  // Returns whether the EGL Program was successfully compiled and linked.
  bool isInitialized() const;

 protected:
  // Compile & link program from the vertex & fragment shader source.
  bool initialize(const char* vertexShaderSrc, const char* fragmentShaderSrc);
  GLuint mProgram;
  // Whether the EGL Program was successfully compiled and linked.
  bool mIsInitialized = false;
};

// Shader program to draw Julia Set test pattern.
class EglTestPatternProgram : public EglProgram {
 public:
  EglTestPatternProgram();

  bool draw(int width, int height, int frameNumber);
};

// Shader program to  draw texture.
//
// Shader stretches the texture over the viewport (if the texture is not same
// aspect ratio as viewport, it will be deformed).
//
// TODO(b/301023410) Add support for translation / cropping.
class EglTextureProgram : public EglProgram {
 public:
  enum class TextureFormat { RGBA, YUV };

  EglTextureProgram(TextureFormat textureFormat = TextureFormat::YUV);
  virtual ~EglTextureProgram();

  // Draw texture over whole viewport, applying transformMatrix to texture
  // coordinates.
  //
  // Transform matrix is 4x4 matrix represented in column-major order and is
  // applied to texture coordinates in (s,t,0,1), s,t from <0,1> range prior to
  // sampling:
  //
  // textureCoord = transformMatrix * vec4(s,t,0,1).xy
  bool draw(GLuint textureId, const std::array<float, 16>& transformMatrix);

 private:
  int mPositionHandle = -1;
  int mTextureCoordHandle = -1;
  int mTransformMatrixHandle = -1;
  int mTextureHandle = -1;
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_EGLPROGRAM_H
