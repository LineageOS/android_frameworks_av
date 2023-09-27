/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <MtpDevHandle.h>
#include <MtpPacket.h>
#include <MtpPacketFuzzerUtils.h>
#include <functional>
#include <fuzzer/FuzzedDataProvider.h>
#include <mtp.h>

using namespace android;

class MtpPacketFuzzer : MtpPacketFuzzerUtils {
  public:
    MtpPacketFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {
        mUsbDevFsUrb = (struct usbdevfs_urb*)malloc(sizeof(struct usbdevfs_urb) +
                                                   sizeof(struct usbdevfs_iso_packet_desc));
    };
    ~MtpPacketFuzzer() { free(mUsbDevFsUrb); };
    void process();

  private:
    FuzzedDataProvider mFdp;
};

void MtpPacketFuzzer::process() {
    MtpPacket mtpPacket(mFdp.ConsumeIntegralInRange<size_t>(MTP_CONTAINER_HEADER_SIZE,
                                                            kMaxSize)); /*bufferSize*/
    while (mFdp.remaining_bytes() > 0) {
        auto mtpPacketAPI = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() {
                    mtpPacket.allocate(mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize));
                },
                [&]() { mtpPacket.reset(); },
                [&]() { mtpPacket.getContainerType(); },
                [&]() { mtpPacket.getContainerCode(); },
                [&]() { mtpPacket.dump(); },
                [&]() { mtpPacket.getTransactionID(); },
                [&]() {
                    mtpPacket.setContainerCode(
                            mFdp.ConsumeIntegralInRange<int32_t>(kMinSize, kMaxSize));
                },
                [&]() {
                    mtpPacket.setTransactionID(
                            mFdp.ConsumeIntegralInRange<int32_t>(kMinSize, kMaxSize));
                },
                [&]() {
                    mtpPacket.getParameter(
                            mFdp.ConsumeIntegralInRange<int32_t>(kMinSize, kMaxSize));
                },
                [&]() {
                    mtpPacket.setParameter(
                            mFdp.ConsumeIntegralInRange<int32_t>(kMinSize, kMaxSize),
                            mFdp.ConsumeIntegralInRange<int32_t>(kMinSize, kMaxSize));
                },
                [&]() {
                    MtpPacket testMtpPacket(
                            mFdp.ConsumeIntegralInRange<int32_t>(kMinSize, kMaxSize));
                    testMtpPacket.copyFrom(mtpPacket);
                },
                [&]() {
                    fillFilePath(&mFdp);
                    int32_t fd = memfd_create(mPath.c_str(), MFD_ALLOW_SEALING);
                    fillUsbRequest(fd, &mFdp);
                    mUsbRequest.dev = usb_device_new(mPath.c_str(), fd);
                    mtpPacket.transfer(&mUsbRequest);
                    usb_device_close(mUsbRequest.dev);
                },
        });
        mtpPacketAPI();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    MtpPacketFuzzer mtpPacketFuzzer(data, size);
    mtpPacketFuzzer.process();
    return 0;
}
