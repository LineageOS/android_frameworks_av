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

#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <gtest/gtest.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/IMediaPlayer.h>
#include <media/IMediaPlayerService.h>
#include <media/mediaplayer.h>

namespace android {

constexpr uint8_t kMockByteArray[16] = {};

 class IMediaPlayerTest : public testing::Test {
  protected:
   static constexpr uint32_t PREPARE_DRM = IMediaPlayer::PREPARE_DRM;

   void SetUp() override {
    mediaPlayer_ = sp<MediaPlayer>::make();
    sp<IServiceManager> serviceManager = defaultServiceManager();
    sp<IBinder> mediaPlayerService = serviceManager->getService(String16("media.player"));
    sp<IMediaPlayerService> iMediaPlayerService =
            IMediaPlayerService::asInterface(mediaPlayerService);
    iMediaPlayer_ = iMediaPlayerService->create(mediaPlayer_);
   }

   sp<MediaPlayer> mediaPlayer_;
   sp<IMediaPlayer> iMediaPlayer_;
 };

TEST_F(IMediaPlayerTest, PrepareDrmInvalidTransaction) {
    Parcel data, reply;
    data.writeInterfaceToken(iMediaPlayer_->getInterfaceDescriptor());
    data.write(kMockByteArray, 16);

    // We write a length greater than the following session id array. Should be discarded.
    data.writeUint32(2);
    data.writeUnpadded(kMockByteArray, 1);

    status_t result = IMediaPlayer::asBinder(iMediaPlayer_)
            ->transact(PREPARE_DRM, data, &reply);
    ASSERT_EQ(result, BAD_VALUE);
}

TEST_F(IMediaPlayerTest, PrepareDrmValidTransaction) {
    Parcel data, reply;
    data.writeInterfaceToken(iMediaPlayer_->getInterfaceDescriptor());
    data.write(kMockByteArray, 16);

    // We write a length equal to the length of the following data. The transaction should be valid.
    data.writeUint32(1);
    data.write(kMockByteArray, 1);

    status_t result = IMediaPlayer::asBinder(iMediaPlayer_)
            ->transact(PREPARE_DRM, data, &reply);
    ASSERT_EQ(result, OK);
}
}  // namespace android
