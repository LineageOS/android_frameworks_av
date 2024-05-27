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

#include <cstdint>
#include "android/hardware_buffer.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "system/graphics.h"
#include "ui/GraphicBuffer.h"
#include "util/EglDisplayContext.h"
#include "util/EglProgram.h"
#include "util/EglSurfaceTexture.h"
#include "util/EglUtil.h"
#include "utils/Errors.h"

namespace android {
namespace companion {
namespace virtualcamera {
namespace {

using ::testing::IsNull;

constexpr int kWidth = 64;
constexpr int kHeight = 64;
constexpr char kGlExtYuvTarget[] = "GL_EXT_YUV_target";

TEST(EglDisplayContextTest, SuccessfulInitialization) {
  EglDisplayContext displayContext;

  EXPECT_TRUE(displayContext.isInitialized());
}

class EglTest : public ::testing::Test {
public:
  void SetUp() override {
      ASSERT_TRUE(mEglDisplayContext.isInitialized());
      ASSERT_TRUE(mEglDisplayContext.makeCurrent());
  }

private:
  EglDisplayContext mEglDisplayContext;
};

TEST_F(EglTest, EglTestPatternProgramSuccessfulInit) {
  if (!isGlExtensionSupported(kGlExtYuvTarget)) {
    GTEST_SKIP() << "Skipping test because of missing required GL extension "
                 << kGlExtYuvTarget;
  }

  EglTestPatternProgram eglTestPatternProgram;

  // Verify the shaders compiled and linked successfully.
  EXPECT_TRUE(eglTestPatternProgram.isInitialized());
}

TEST_F(EglTest, EglTextureProgramYuvSuccessfulInit) {
  if (!isGlExtensionSupported(kGlExtYuvTarget)) {
      GTEST_SKIP() << "Skipping test because of missing required GL extension " << kGlExtYuvTarget;
  }

  EglTextureProgram eglTextureProgram(EglTextureProgram::TextureFormat::YUV);

  // Verify the shaders compiled and linked successfully.
  EXPECT_TRUE(eglTextureProgram.isInitialized());
}

TEST_F(EglTest, EglTextureProgramRgbaSuccessfulInit) {
  if (!isGlExtensionSupported(kGlExtYuvTarget)) {
      GTEST_SKIP() << "Skipping test because of missing required GL extension "
                   << kGlExtYuvTarget;
  }

  EglTextureProgram eglTextureProgram(EglTextureProgram::TextureFormat::RGBA);

  // Verify the shaders compiled and linked successfully.
  EXPECT_TRUE(eglTextureProgram.isInitialized());
}

TEST_F(EglTest, EglSurfaceCurrentBufferNullAfterInit) {
  if (!isGlExtensionSupported(kGlExtYuvTarget)) {
      GTEST_SKIP() << "Skipping test because of missing required GL extension " << kGlExtYuvTarget;
  }

  EglSurfaceTexture surfaceTexture(kWidth, kHeight);
  surfaceTexture.updateTexture();
  sp<GraphicBuffer> buffer = surfaceTexture.getCurrentBuffer();

  EXPECT_THAT(buffer, IsNull());
}

}  // namespace
}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
