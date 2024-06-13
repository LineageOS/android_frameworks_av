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

// #define LOG_NDEBUG 0
#define LOG_TAG "EglProgram"
#include "EglProgram.h"

#include <array>
#include <complex>

#include "EglUtil.h"
#include "GLES/gl.h"
#include "GLES2/gl2.h"
#include "GLES2/gl2ext.h"
#include "log/log.h"

namespace android {
namespace companion {
namespace virtualcamera {

namespace {

constexpr char kGlExtYuvTarget[] = "GL_EXT_YUV_target";

constexpr char kJuliaFractalVertexShader[] = R"(#version 300 es
    in vec4 aPosition;
    in vec2 aTextureCoord;
    out vec2 vFractalCoord;
    out vec2 vUVCoord;
    void main() {
      gl_Position = aPosition;
      vUVCoord = aTextureCoord;
      vFractalCoord = vec2(aTextureCoord.x - 0.5, aTextureCoord.y - 0.5) * 4.0;
    })";

constexpr char kJuliaFractalFragmentShader[] = R"(#version 300 es
    #extension GL_EXT_YUV_target : require
    precision mediump float;

    const float kIter = 64.0;

    in vec2 vFractalCoord;
    in vec2 vUVCoord;
    out vec4 fragColor;
    uniform vec2 uC;

    vec2 imSq(vec2 n){
      return vec2(pow(n.x,2.0)-pow(n.y,2.0), 2.0*n.x*n.y);
    }

    float julia(vec2 n, vec2 c) {
      vec2 z = n;
      for (float i=0.0;i<kIter; i+=1.0) {
        z = imSq(z) + c;
        if (length(z) > 2.0) return i/kIter;
      }
      return kIter;
    }

    void main() {
      float juliaVal = julia(vFractalCoord, uC);
      fragColor = vec4(yuv_2_rgb(vec3(juliaVal, vUVCoord.x, vUVCoord.y), itu_601_full_range), 0.0);
    })";

constexpr char kExternalTextureVertexShader[] = R"(#version 300 es
  uniform mat4 aTextureTransformMatrix; // Transform matrix given by surface texture.
  in vec4 aPosition;
  in vec2 aTextureCoord;
  out vec2 vTextureCoord;
  void main() {
    gl_Position = aPosition;
    vTextureCoord = (aTextureTransformMatrix * vec4(aTextureCoord, 0.0, 1.0)).xy;
  })";

constexpr char kExternalYuvTextureFragmentShader[] = R"(#version 300 es
    #extension GL_OES_EGL_image_external_essl3 : require
    #extension GL_EXT_YUV_target : require
    precision mediump float;
    in vec2 vTextureCoord;
    layout (yuv) out vec4 fragColor;
    uniform __samplerExternal2DY2YEXT uTexture;
    void main() {
      fragColor = texture(uTexture, vTextureCoord);
    })";

constexpr char kExternalRgbaTextureFragmentShader[] = R"(#version 300 es
    #extension GL_OES_EGL_image_external_essl3 : require
    #extension GL_EXT_YUV_target : require
    precision mediump float;
    in vec2 vTextureCoord;
    layout (yuv) out vec4 fragColor;
    uniform samplerExternalOES uTexture;
    void main() {
      vec4 rgbaColor = texture(uTexture, vTextureCoord);
      fragColor = vec4(rgb_2_yuv(rgbaColor.xyz, itu_601_full_range), 0.0);
    })";

constexpr int kCoordsPerVertex = 3;

constexpr std::array<float, 12> kSquareCoords{
    -1.f, -1.0f, 0.0f,   // top left
    -1.f, 1.f,   0.0f,   // bottom left
    1.0f, 1.f,   0.0f,   // bottom right
    1.0f, -1.0f, 0.0f};  // top right

constexpr std::array<float, 8> kTextureCoords{0.0f, 1.0f,   // top left
                                              0.0f, 0.0f,   // bottom left
                                              1.0f, 0.0f,   // bottom right
                                              1.0f, 1.0f};  // top right

constexpr std::array<uint8_t, 6> kDrawOrder{0, 1, 2, 0, 2, 3};

GLuint compileShader(GLenum shaderType, const char* src) {
  GLuint shader = glCreateShader(shaderType);
  if (shader == 0) {
    ALOGE("glCreateShader(shaderType=%x) error: %#x",
          static_cast<unsigned int>(shaderType), glGetError());
    return 0;
  }

  glShaderSource(shader, 1, &src, NULL);
  glCompileShader(shader);

  GLint compiled = 0;
  glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
  if (!compiled) {
    ALOGE("Compile of shader type %d failed", shaderType);
    GLint infoLen = 0;
    glGetShaderiv(shader, GL_INFO_LOG_LENGTH, &infoLen);
    if (infoLen) {
      char* buf = new char[infoLen];
      if (buf) {
        glGetShaderInfoLog(shader, infoLen, NULL, buf);
        ALOGE("Compile log: %s", buf);
        delete[] buf;
      }
    }
    glDeleteShader(shader);
    return 0;
  }
  return shader;
}

}  // namespace

EglProgram::~EglProgram() {
  if (mProgram) {
    glDeleteProgram(mProgram);
  }
}

bool EglProgram::initialize(const char* vertexShaderSrc,
                            const char* fragmentShaderSrc) {
  GLuint vertexShaderId = compileShader(GL_VERTEX_SHADER, vertexShaderSrc);
  if (checkEglError("compileShader(vertex)")) {
    return false;
  }
  GLuint fragmentShaderId = compileShader(GL_FRAGMENT_SHADER, fragmentShaderSrc);
  if (checkEglError("compileShader(fragment)")) {
    return false;
  }

  GLuint programId = glCreateProgram();

  glAttachShader(programId, vertexShaderId);
  glAttachShader(programId, fragmentShaderId);
  glLinkProgram(programId);

  GLint linkStatus = GL_FALSE;
  glGetProgramiv(programId, GL_LINK_STATUS, &linkStatus);
  if (linkStatus != GL_TRUE) {
    ALOGE("glLinkProgram failed");
    GLint bufLength = 0;
    glGetProgramiv(programId, GL_INFO_LOG_LENGTH, &bufLength);
    if (bufLength) {
      char* buf = new char[bufLength];
      if (buf) {
        glGetProgramInfoLog(programId, bufLength, NULL, buf);
        ALOGE("Link log: %s", buf);
        delete[] buf;
      }
    }
    glDeleteProgram(programId);
    return false;
  }

  mProgram = programId;

  mIsInitialized = true;
  return mIsInitialized;
}

bool EglProgram::isInitialized() const {
  return mIsInitialized;
}

EglTestPatternProgram::EglTestPatternProgram() {
  if (initialize(kJuliaFractalVertexShader, kJuliaFractalFragmentShader)) {
    ALOGV("Successfully initialized EGL shaders for test pattern program.");
  } else {
    ALOGE("Test pattern EGL shader program initialization failed.");
  }

  mCHandle = glGetUniformLocation(mProgram, "uC");
  mPositionHandle = glGetAttribLocation(mProgram, "aPosition");
  mTextureCoordHandle = glGetAttribLocation(mProgram, "aTextureCoord");

  // Pass vertex array to draw.
  glEnableVertexAttribArray(mPositionHandle);
  // Prepare the triangle coordinate data.
  glVertexAttribPointer(mPositionHandle, kCoordsPerVertex, GL_FLOAT, false,
                        kSquareCoords.size(), kSquareCoords.data());

  glEnableVertexAttribArray(mTextureCoordHandle);
  glVertexAttribPointer(mTextureCoordHandle, 2, GL_FLOAT, false,
                        kTextureCoords.size(), kTextureCoords.data());
}

EglTestPatternProgram::~EglTestPatternProgram() {
  if (mPositionHandle != -1) {
    glDisableVertexAttribArray(mPositionHandle);
  }
  if (mTextureCoordHandle != -1) {
    glDisableVertexAttribArray(mTextureCoordHandle);
  }
}

bool EglTestPatternProgram::draw(const std::chrono::nanoseconds timestamp) {
  // Load compiled shader.
  glUseProgram(mProgram);
  checkEglError("glUseProgram");

  float time = float(timestamp.count() / 1e9) / 10;
  const std::complex<float> c(std::sin(time) * 0.78f, std::cos(time) * 0.78f);

  // Pass "C" constant value determining the Julia set to the shader.
  glUniform2f(mCHandle, c.imag(), c.real());

  // Draw triangle strip forming a square filling the viewport.
  glDrawElements(GL_TRIANGLES, kDrawOrder.size(), GL_UNSIGNED_BYTE,
                 kDrawOrder.data());
  if (checkEglError("glDrawElements")) {
    return false;
  }

  return true;
}

EglTextureProgram::EglTextureProgram(const TextureFormat textureFormat) {
  if (!isGlExtensionSupported(kGlExtYuvTarget)) {
    ALOGE(
        "Cannot initialize external texture program due to missing "
        "GL_EXT_YUV_target extension");
    return;
  }

  const char* fragmentShaderSrc = textureFormat == TextureFormat::YUV
                                      ? kExternalYuvTextureFragmentShader
                                      : kExternalRgbaTextureFragmentShader;
  if (initialize(kExternalTextureVertexShader, fragmentShaderSrc)) {
    ALOGV("Successfully initialized EGL shaders for external texture program.");
  } else {
    ALOGE("External texture EGL shader program initialization failed.");
  }

  // Lookup and cache handles to uniforms & attributes.
  mPositionHandle = glGetAttribLocation(mProgram, "aPosition");
  mTextureCoordHandle = glGetAttribLocation(mProgram, "aTextureCoord");
  mTransformMatrixHandle =
      glGetUniformLocation(mProgram, "aTextureTransformMatrix");
  mTextureHandle = glGetUniformLocation(mProgram, "uTexture");

  // Pass vertex array to the shader.
  glEnableVertexAttribArray(mPositionHandle);
  glVertexAttribPointer(mPositionHandle, kCoordsPerVertex, GL_FLOAT, false,
                        kSquareCoords.size(), kSquareCoords.data());

  // Pass texture coordinates corresponding to vertex array to the shader.
  glEnableVertexAttribArray(mTextureCoordHandle);
  glVertexAttribPointer(mTextureCoordHandle, 2, GL_FLOAT, false,
                        kTextureCoords.size(), kTextureCoords.data());
}

EglTextureProgram::~EglTextureProgram() {
  if (mPositionHandle != -1) {
    glDisableVertexAttribArray(mPositionHandle);
  }
  if (mTextureCoordHandle != -1) {
    glDisableVertexAttribArray(mTextureCoordHandle);
  }
}

bool EglTextureProgram::draw(GLuint textureId,
                             const std::array<float, 16>& transformMatrix) {
  // Load compiled shader.
  glUseProgram(mProgram);
  if (checkEglError("glUseProgram")) {
    return false;
  }

  // Pass transformation matrix for the texture coordinates.
  glUniformMatrix4fv(mTransformMatrixHandle, 1, /*transpose=*/GL_FALSE,
                     transformMatrix.data());

  // Configure texture for the shader.
  glActiveTexture(GL_TEXTURE0);
  glBindTexture(GL_TEXTURE_EXTERNAL_OES, textureId);
  glUniform1i(mTextureHandle, 0);

  // Draw triangle strip forming a square filling the viewport.
  glDrawElements(GL_TRIANGLES, kDrawOrder.size(), GL_UNSIGNED_BYTE,
                 kDrawOrder.data());
  if (checkEglError("glDrawElements")) {
    return false;
  }

  return true;
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
